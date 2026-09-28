//! Multi-instance config-file integration test.
//! Boots the multi-instance serve loop from the chain-and-list
//! `examples/mainnet-6-instance.toml` shape and verifies status output
//! plus encoder-default `active_k_concurrency` resolution, and that a wallet-shim route
//! is answered from the stores that config declares.
//!
//! Nothing here constructs an `AppState`: the shim routes were certified by a hand-wired
//! one while the deployment served 503, so the only wiring these tests can observe is the
//! one `serve-production --config` builds.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::manual_contains,
    clippy::panic,
    clippy::unwrap_used
)]

use raven_railgun_cli::serve_production_multi::{
    load_options_from_toml, run_with_listener, MultiServeOptions,
};
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
/// per-node 16, per-list-path10 16.
const EXAMPLE_INSTANCES: [(&str, u32); 10] = [
    ("commit-tree-0", 16),
    ("commit-tree-1", 16),
    ("commit-tree-2", 16),
    ("commit-tree-3", 16),
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

/// Incremented only when a coverage proof refuses. It is the only thing separating "the
/// proof ran and refused" from "no store was ever wired": both answer 503.
const COVERAGE_REFUSALS_TOTAL: &str = "raven_railgun_shim_coverage_refusals_total";

const COMMIT_TREE_ROUTE: &str = "commit-tree-merkle-proof";

/// The shim list routes that are mounted unconditionally, so the exact refusal counts
/// below do not move with whichever index channel is compiled in.
const LIST_ROUTES: [&str; 1] = ["merkle-proofs"];

fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn refusals_for(scrape: &str, route: &str) -> u64 {
    let label = format!("route=\"{route}\"");
    scrape
        .lines()
        .find(|line| {
            line.starts_with(COVERAGE_REFUSALS_TOTAL)
                && line.contains(&label)
                && !line.starts_with('#')
        })
        .and_then(|line| line.rsplit(' ').next()?.parse().ok())
        .unwrap_or(0)
}

async fn ask_commit_tree(addr: SocketAddr, tree_number: u32) -> reqwest::StatusCode {
    reqwest::Client::new()
        .post(format!(
            "http://{addr}/v1/commit-tree/{tree_number}/merkle-proof"
        ))
        .json(&serde_json::json!({ "leafIndex": 0 }))
        .send()
        .await
        .expect("commit-tree merkle proof")
        .status()
}

/// The commit trees and the single PPOI list the config declares, read out of the parsed
/// options rather than pinned here, so the probes follow the example file instead of a copy
/// of it that can drift.
fn declared_domains(opts: &MultiServeOptions) -> (Vec<u32>, [u8; 32]) {
    let mut trees: Vec<u32> = opts
        .instances
        .iter()
        .filter_map(|inst| match inst.data_source {
            DataSourceFilter::ChainTreeNumber(tree) => Some(tree),
            DataSourceFilter::PpoiListBlock { .. } => None,
        })
        .collect();
    trees.sort_unstable();
    let mut list_key = None;
    let mut blocks: Vec<u32> = Vec::new();
    for inst in &opts.instances {
        if let DataSourceFilter::PpoiListBlock {
            list_key: key,
            block,
        } = inst.data_source
        {
            assert!(
                list_key.is_none_or(|seen| seen == key),
                "the example declares path blocks for more than one list key"
            );
            list_key = Some(key);
            blocks.push(block);
        }
    }
    let list_key = list_key.expect("the example declares no path block");
    assert!(
        trees.len() >= 2 && blocks.len() >= 2,
        "fewer than two trees and two blocks cannot tell a declared store from any store"
    );
    (trees, list_key)
}

/// One request per route, in `LIST_ROUTES` order, so a per-route refusal count of one is an
/// exact figure rather than a floor.
async fn ask_list_routes(
    addr: SocketAddr,
    list_key: &str,
) -> Vec<(&'static str, reqwest::StatusCode)> {
    let client = reqwest::Client::new();
    let probe = hex32(&raven_railgun_testkit::canonical(0x71));
    let base = format!("http://{addr}");
    vec![(
        "merkle-proofs",
        client
            .post(format!("{base}/v1/poi/merkle-proofs"))
            .json(&serde_json::json!({ "listKey": list_key, "blindedCommitments": [probe] }))
            .send()
            .await
            .expect("merkle-proofs")
            .status(),
    )]
}

/// Every commit tree the config declares reaches its own store; one it does not declare is
/// refused by the coverage proof; and the list it declares six blocks of is refused too,
/// because six empty blocks are no sealed prefix of a 358,320-row list.
///
/// The load-bearing assertion is the exact refusal count on the commit-tree route. It is
/// one, raised by the single undeclared tree, while four declared trees answered from a
/// store. Take the registry assignment out of the boot path and all five answer 503 with
/// that counter at zero, so a bare status-code assertion would pass through the defect.
///
/// No `Authorization` header goes to a shim route: the read path is public and a wallet
/// holds no credential. Only the `/metrics` scrape is authenticated.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stands up the same 10 PIR instances as the boot test above, ~7 s each. \
            Trigger: changing shim-route store resolution, or the example config's \
            declared trees and list blocks."]
async fn shim_routes_answer_only_from_the_stores_the_example_config_declares() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let example_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/mainnet-6-instance.toml");
    let config_path = rewrite_to_tempdir(&example_path, tmp.path(), bind, BEARER_TOKEN);

    let mut opts = load_options_from_toml(&config_path).expect("parse config");

    let (trees, list_key) = declared_domains(&opts);
    let undeclared_tree = trees.last().copied().expect("a declared tree") + 1;

    // The only deviations from the shipped file, all about reaching the network or the
    // filesystem rather than about which store answers a route.
    opts.skip_chain_workers = true;
    opts.skip_mirror_workers = true;
    for inst in &mut opts.instances {
        inst.use_flock = false;
    }

    let listener = tokio::net::TcpListener::bind(bind).await.expect("bind");
    let local_addr = listener.local_addr().expect("local addr");
    let (tx, rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let _ = run_with_listener(opts, listener, async move {
            let _ = rx.await;
        })
        .await;
    });

    // The registry is installed before the listener is served, so a 2xx here means wired.
    let client = reqwest::Client::new();
    let status_url = format!("http://{local_addr}/v1/status");
    let mut ready = false;
    for _ in 0..1200u32 {
        if client
            .get(&status_url)
            .send()
            .await
            .is_ok_and(|resp| resp.status().is_success())
        {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    assert!(ready, "the example config never answered /v1/status");

    let mut declared = Vec::with_capacity(trees.len());
    for tree in &trees {
        declared.push((*tree, ask_commit_tree(local_addr, *tree).await));
    }
    let undeclared = ask_commit_tree(local_addr, undeclared_tree).await;
    let list_statuses = ask_list_routes(local_addr, &hex32(&list_key)).await;
    let scrape = client
        .get(format!("http://{local_addr}/metrics"))
        .bearer_auth(BEARER_TOKEN)
        .send()
        .await
        .expect("scrape")
        .text()
        .await
        .expect("metrics body");

    for (tree, status) in &declared {
        assert_eq!(
            *status,
            reqwest::StatusCode::NOT_FOUND,
            "commit tree {tree} is declared, so the request must reach its store and miss \
             there rather than find no store at all"
        );
    }
    assert_eq!(
        undeclared,
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "commit tree {undeclared_tree} is held by nobody and must not be answered from a \
         declared tree's store"
    );
    assert_eq!(
        refusals_for(&scrape, COMMIT_TREE_ROUTE),
        1,
        "exactly one commit-tree request refused through the proof, the undeclared one; zero \
         means no registry was installed and every 503 is the absent-store 503: {scrape}"
    );
    for (route, status) in &list_statuses {
        assert_eq!(
            *status,
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            "{route} answered {status} over a list whose declared blocks hold no sealed prefix"
        );
    }
    for route in LIST_ROUTES {
        assert_eq!(
            refusals_for(&scrape, route),
            1,
            "{route} was asked once and must have refused through the coverage proof: {scrape}"
        );
    }

    let _ = tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(30), server).await;
}

#[test]
fn default_k_for_per_node_is_sixteen() {
    assert_eq!(default_k_for(EncoderKind::PerNode { tree_number: 0 }), 16);
    assert_eq!(
        default_k_for(EncoderKind::PerLeafPath { tree_number: 0 }),
        8
    );
    assert_eq!(default_k_for(EncoderKind::PerLeafBc { tree_number: 0 }), 4);
    assert_eq!(
        default_k_for(EncoderKind::PerListPath10 {
            list_key: [0u8; 32]
        }),
        16
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
