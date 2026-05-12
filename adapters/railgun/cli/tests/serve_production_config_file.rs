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
    path
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow: cold-start PIR keygen; run with --ignored"]
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
        6,
        "config should describe 6 instances"
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

    assert_eq!(body.instances.len(), 6, "all 6 instances must be visible");
    let ids: Vec<&str> = body.instances.iter().map(|i| i.id.as_str()).collect();
    for expect in [
        "commit-tree-0",
        "commit-tree-1",
        "commit-tree-2",
        "commit-tree-3",
        "ppoi-status-ofac",
        "ppoi-paths-ofac",
    ] {
        assert!(
            ids.iter().any(|id| *id == expect),
            "missing {expect} in {ids:?}"
        );
    }

    // Per Workstream N: active_k_concurrency must default per-encoder.
    // commit-tree-* are PerNode -> 16.
    // ppoi-status-ofac is PerListStatus -> 4.
    // ppoi-paths-ofac is PerListNode -> 16.
    let by_id: std::collections::HashMap<&str, u32> = body
        .instances
        .iter()
        .map(|i| (i.id.as_str(), i.active_k_concurrency))
        .collect();
    assert_eq!(by_id["commit-tree-0"], 16);
    assert_eq!(by_id["commit-tree-1"], 16);
    assert_eq!(by_id["commit-tree-2"], 16);
    assert_eq!(by_id["commit-tree-3"], 16);
    assert_eq!(by_id["ppoi-status-ofac"], 4);
    assert_eq!(by_id["ppoi-paths-ofac"], 16);

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
    assert_eq!(default_k_for(EncoderKind::PerLeafBc), 4);
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
