//! Multi-instance config-file integration test.
//! Boots the multi-instance serve loop from the canonical
//! `examples/mainnet-6-instance.toml` shape and verifies status output
//! plus encoder-default `active_k_concurrency` resolution.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::manual_contains,
    clippy::panic,
    clippy::unwrap_used
)]

use raven_railgun_cli::serve_production_multi::{load_options_from_toml, run_with_listener};
use raven_railgun_engine::orchestrator::{
    default_k_for, DataSourceFilter, InstanceConfig, VerificationMode,
};
use raven_railgun_engine::persistence::SnapshotPolicy;
use raven_railgun_engine::pir_table::EncoderKind;
use raven_railgun_engine::InstanceRole;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::Path;
use tokio::sync::oneshot;

const BEARER_TOKEN: &str = "config-file-test-token-padded-long";

/// Every `[[instance]]` the example declares, with its encoder-default k:
/// per-node 16, per-list-status 4, per-list-path10 16.
const EXAMPLE_INSTANCES: [(&str, u32); 11] = [
    ("commit-tree-0", 16),
    ("commit-tree-1", 16),
    ("commit-tree-2", 16),
    ("commit-tree-3", 16),
    ("ppoi-status-ofac", 4),
    ("ppoi-paths-ofac-0", 16),
    ("ppoi-paths-ofac-1", 16),
    ("ppoi-paths-ofac-2", 16),
    ("ppoi-paths-ofac-3", 16),
    ("ppoi-paths-ofac-4", 16),
    ("ppoi-paths-ofac-5", 16),
];

#[derive(Debug, Deserialize)]
struct StatusJson {
    instances: Vec<InstanceJson>,
}

#[derive(Debug, Deserialize)]
struct InstanceJson {
    id: String,
    #[serde(default)]
    #[allow(dead_code)]
    epoch: u64,
    active_k_concurrency: u32,
}

fn rewrite_to_tempdir(src: &Path, tmp: &Path, bind: SocketAddr, token: &str) -> std::path::PathBuf {
    let body = std::fs::read_to_string(src).expect("read example toml");
    let mut out = body;
    out = out.replace("/var/lib/raven-railgun/", &format!("{}/", tmp.display()));
    out = out.replace("0.0.0.0:8080", &bind.to_string());
    out = out.replace("REPLACE_ME", token);
    let path = tmp.join("config.toml");
    std::fs::write(&path, out).expect("write rewritten config");
    restrict_to_owner(&path);
    path
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "~7 s per PIR instance stood up, ~99% of it PackParams::try_new (the deterministic \
            d=2048 packing table) built twice per setup_state; the keygen proper is ~60 ms. \
            Trigger: changing multi-instance config-file boot or the status listing."]
async fn six_instance_config_file_boots_and_status_lists_all() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let example_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/mainnet-6-instance.toml");
    let config_path = rewrite_to_tempdir(&example_path, tmp.path(), bind, BEARER_TOKEN);

    let mut opts = load_options_from_toml(&config_path).expect("parse config");
    opts.bind = bind;
    opts.skip_chain_workers = true;
    opts.skip_mirror_workers = true;
    opts.entries = 256;
    for inst in &mut opts.instances {
        inst.use_flock = false;
    }

    assert_eq!(
        opts.instances.len(),
        EXAMPLE_INSTANCES.len(),
        "config should describe every example instance"
    );

    let listener = tokio::net::TcpListener::bind(bind).await.expect("bind");
    let local_addr = listener.local_addr().expect("local addr");
    let (tx, rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let _ = run_with_listener(opts, listener, async move {
            let _ = rx.await;
        })
        .await;
    });

    let url = format!("http://{local_addr}/v1/status");
    let client = reqwest::Client::new();
    let mut last_err: Option<String> = None;
    let mut status_body: Option<StatusJson> = None;
    for _ in 0..240u32 {
        match client.get(&url).bearer_auth(BEARER_TOKEN).send().await {
            Ok(resp) if resp.status().is_success() => {
                let parsed: StatusJson = resp.json().await.expect("parse status json");
                status_body = Some(parsed);
                break;
            }
            Ok(resp) => last_err = Some(format!("HTTP {}", resp.status())),
            Err(e) => last_err = Some(e.to_string()),
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    let body = status_body.unwrap_or_else(|| {
        panic!("status never returned 2xx; last_err = {last_err:?}");
    });

    assert_eq!(
        body.instances.len(),
        EXAMPLE_INSTANCES.len(),
        "every declared instance must be visible"
    );
    let by_id: std::collections::HashMap<&str, u32> = body
        .instances
        .iter()
        .map(|i| (i.id.as_str(), i.active_k_concurrency))
        .collect();
    for (id, k) in EXAMPLE_INSTANCES {
        let served = by_id
            .get(id)
            .unwrap_or_else(|| panic!("missing {id} in {:?}", by_id.keys()));
        assert_eq!(*served, k, "{id} active_k_concurrency");
    }

    let _ = tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), server).await;
}

#[test]
fn default_k_for_per_node_is_sixteen() {
    assert_eq!(default_k_for(EncoderKind::PerNode { tree_number: 0 }), 16);
    assert_eq!(
        default_k_for(EncoderKind::PerListPath {
            list_key: [0u8; 32]
        }),
        16
    );
    assert_eq!(
        default_k_for(EncoderKind::PerListNode {
            list_key: [0u8; 32]
        }),
        16
    );
    assert_eq!(
        default_k_for(EncoderKind::PerLeafPath { tree_number: 0 }),
        8
    );
    assert_eq!(default_k_for(EncoderKind::PerLeafBc { tree_number: 0 }), 4);
    assert_eq!(
        default_k_for(EncoderKind::PerListStatus {
            list_key: [0u8; 32]
        }),
        4
    );
}

#[test]
fn explicit_k_override_replaces_encoder_default() {
    let cfg = InstanceConfig {
        instance_id: raven_railgun_core::InstanceId::new("override-test"),
        role: InstanceRole::Live,
        data_dir: std::path::PathBuf::from("/tmp/raven-not-used"),
        encoder: EncoderKind::PerNode { tree_number: 0 },
        record_size: 32,
        entries_per_shard: 256,
        verification_mode: VerificationMode::ChainRootHistory,
        data_source: DataSourceFilter::ChainTreeNumber(0),
        use_flock: false,
        snapshot_policy: SnapshotPolicy::default(),
        scheme_tag: "test".to_owned(),
        channel_capacity: 64,
        max_concurrent_queries: Some(2),
        verification_cadence_n: 0,
        chain_source: None,
    };
    assert_eq!(
        cfg.resolved_max_concurrent_queries(),
        2,
        "explicit Some(2) must override per-encoder default of 16"
    );
    let no_override = InstanceConfig {
        max_concurrent_queries: None,
        ..cfg
    };
    assert_eq!(
        no_override.resolved_max_concurrent_queries(),
        16,
        "fallback to default_k_for(PerNode) = 16"
    );
}

/// The parser refuses a group- or world-readable config carrying an inline token.
fn restrict_to_owner(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("fixture config must be owner-only");
    }
    #[cfg(not(unix))]
    let _ = path;
}
