//! The shipped Sepolia example: it loads with declared keys only, names Sepolia and the OFAC
//! list's first two blocks and nothing else of mainnet's changes, and boots a node whose mirror
//! asks upstream for Sepolia, one request a second at most, under the mirror's `User-Agent`.
//! Beside it, no shipped example lowers the request spacing a live endpoint is read at.
//!
//! Every endpoint here is an in-process listener on loopback.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

#[path = "support/progress.rs"]
mod progress;
#[path = "support/signed_list.rs"]
mod signed_list;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use progress::until_done_or_stalled;
use raven_railgun_cli::serve_production_multi::{
    load_options_from_toml, run_with_listener, BootstrapObserver, BootstrapView, MultiServeOptions,
};
use raven_railgun_engine::imt::Imt;
use raven_railgun_engine::orchestrator::DataSourceFilter;
use raven_railgun_http::status::MirrorFeedState;
use raven_railgun_http::HealthReadyResponse;
use raven_railgun_ppoi_mirror::USER_AGENT;
use serde_json::{json, Value};
use signed_list::{rekeyed, signed_row, SHIPPED_LIST_HEX};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const BEARER_TOKEN: &str = "sepolia-example-test-token-padded-long";
const SEPOLIA_CHAIN_ID: u64 = 11_155_111;
const SHIPPED_ENDPOINT: &str = "https://ppoi.fdi.network";

/// Where a stub times a request, a loopback hop behind where the mirror starts it.
const HOP: Duration = Duration::from_millis(100);

fn example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../examples")
        .join(name)
}

fn read_example(name: &str) -> String {
    std::fs::read_to_string(example(name)).expect("read the shipped example")
}

/// `body` loaded the way an operator's file is, its token made real.
fn load(body: &str) -> MultiServeOptions {
    let mut file = tempfile::NamedTempFile::new().expect("tempfile");
    std::io::Write::write_all(
        &mut file,
        body.replace("REPLACE_ME", BEARER_TOKEN).as_bytes(),
    )
    .expect("write config");
    load_options_from_toml(file.path()).expect("the shipped example loads")
}

/// The `[global]` table's settings, comments and blank lines left out.
fn global_settings(body: &str) -> Vec<String> {
    let start = body.find("[global]\n").expect("a [global] table");
    let end = body.find("[[instance]]").expect("an instance");
    body[start..end]
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_sepolia_example_is_mainnets_global_table_on_sepolia_with_blocks_0_and_1_of_the_list() {
    let sepolia = read_example("sepolia-ppoi.toml");
    let mainnet = read_example("mainnet-ppoi.toml");
    let expected: Vec<String> = global_settings(&mainnet)
        .into_iter()
        .map(|line| {
            if line == "chain_id = 1" {
                format!("chain_id = {SEPOLIA_CHAIN_ID}")
            } else {
                line
            }
        })
        .collect();
    assert_eq!(global_settings(&sepolia), expected);

    let opts = load(&sepolia);
    assert_eq!(opts.chain_id, SEPOLIA_CHAIN_ID);
    assert_eq!(opts.mirror_endpoint, SHIPPED_ENDPOINT);
    let list_key = hex::decode(SHIPPED_LIST_HEX).expect("hex");
    let declared: Vec<(String, u32)> = opts
        .instances
        .iter()
        .map(|instance| match instance.data_source {
            DataSourceFilter::PpoiListBlock {
                list_key: key,
                block,
            } => {
                assert_eq!(key.to_vec(), list_key, "{}", instance.instance_id.as_str());
                (instance.instance_id.as_str().to_owned(), block)
            }
            DataSourceFilter::ChainTreeNumber(tree) => panic!("a commit tree, {tree}"),
        })
        .collect();
    assert_eq!(
        declared,
        [
            ("ppoi-paths-ofac-0".to_owned(), 0),
            ("ppoi-paths-ofac-1".to_owned(), 1)
        ]
    );
}

/// A live endpoint is read one request a second at most unless a config lowers the spacing, and
/// only a local replay may.
#[test]
fn no_shipped_example_lowers_the_request_spacing() {
    for name in [
        "mainnet-ppoi.toml",
        "mainnet-6-instance.toml",
        "sepolia-ppoi.toml",
    ] {
        let opts = load(&read_example(name));
        assert!(
            opts.mirror_backfill_interval_secs
                .is_none_or(|secs| secs >= 1),
            "{name}: {:?}",
            opts.mirror_backfill_interval_secs
        );
    }
}

type Requests = Arc<parking_lot::Mutex<Vec<(Instant, Option<String>, Value)>>>;

/// Distinct in the bytes the index publishes too, or a renumbered index would still match.
fn leaf_at(index: u64) -> [u8; 32] {
    let mut leaf = [0u8; 32];
    let row = (index + 1).to_be_bytes();
    leaf[24..].copy_from_slice(&row);
    leaf[2..6].copy_from_slice(row.last_chunk::<4>().expect("four bytes"));
    leaf
}

/// Holds rows `0..rows` of the test list in block 0, with the root upstream publishes after each,
/// and records when each request landed and its `User-Agent`.
async fn upstream_holding(rows: u64) -> (String, Requests) {
    let mut tree = Imt::new().expect("imt");
    let roots: Vec<[u8; 32]> = (0..rows)
        .map(|index| {
            tree.insert_leaves(usize::try_from(index).expect("index"), &[leaf_at(index)])
                .expect("append");
            tree.root()
        })
        .collect();
    let roots = Arc::new(roots);
    let requests = Requests::default();
    let seen = Arc::clone(&requests);
    let app = Router::new().route(
        "/",
        post(move |headers: HeaderMap, Json(request): Json<Value>| {
            let seen = Arc::clone(&seen);
            let roots = Arc::clone(&roots);
            async move {
                let landed = Instant::now();
                let bound = |name: &str| request["params"][name].as_u64().expect("page bound");
                let (start, end) = (bound("startIndex"), bound("endIndex"));
                let result: Vec<Value> = (start..=end)
                    .map_while(|index| {
                        let root = roots.get(usize::try_from(index).ok()?)?;
                        Some(signed_row(
                            index,
                            &hex::encode(leaf_at(index)),
                            &hex::encode(root),
                        ))
                    })
                    .collect();
                let agent = headers
                    .get("user-agent")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                seen.lock().push((landed, agent, request));
                Json(json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (url, requests)
}

struct Booting {
    addr: SocketAddr,
    server: JoinHandle<anyhow::Result<()>>,
    stop: oneshot::Sender<()>,
}

/// The shipped example rewritten at its data root, token, list key and endpoint only.
fn shipped_sepolia_options(
    data_root: &Path,
    endpoint: &str,
) -> (MultiServeOptions, BootstrapObserver) {
    let body = read_example("sepolia-ppoi.toml")
        .replace("/srv/raven/data/", &format!("{}/", data_root.display()))
        .replace(SHIPPED_ENDPOINT, endpoint);
    let mut opts = load(&rekeyed(&body));
    opts.bind = "127.0.0.1:0".parse().expect("addr");
    opts.skip_chain_workers = true;
    opts.entries = 256;
    for instance in &mut opts.instances {
        instance.use_flock = false;
    }
    let observer = BootstrapObserver::default();
    opts.bootstrap_observer = Some(Arc::clone(&observer));
    (opts, observer)
}

async fn boot(opts: MultiServeOptions, observer: &BootstrapObserver) -> (Booting, BootstrapView) {
    let listener = tokio::net::TcpListener::bind(opts.bind)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let (stop, stopped) = oneshot::channel::<()>();
    let mut server = tokio::spawn(run_with_listener(opts, listener, async move {
        let _ = stopped.await;
    }));
    // 300 s: the allowance the six-instance suite gives cold PIR bootstraps under CI contention.
    for _ in 0..1200u32 {
        if let Some(view) = observer.lock().clone() {
            return (Booting { addr, server, stop }, view);
        }
        if server.is_finished() {
            let ended = (&mut server).await.expect("boot task panicked");
            panic!("boot ended before its instances came up: {ended:?}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("instances never finished bootstrapping");
}

async fn readiness(addr: SocketAddr) -> Option<HealthReadyResponse> {
    let response = reqwest::Client::new()
        .get(format!("http://{addr}/v1/health/ready"))
        .send()
        .await
        .ok()?;
    response.json().await.ok()
}

async fn shut_down(booting: Booting) {
    let _ = booting.stop.send(());
    tokio::time::timeout(progress::STALL, booting.server)
        .await
        .expect("shutdown stalled")
        .expect("server task panicked")
        .expect("graceful shutdown");
}

/// A cold sync of 1,010 rows on the example as shipped: the preflight and three pages, each
/// asking for Sepolia under the mirror's `User-Agent`, each starting at least a second after the
/// one before, and every row lands in block 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_sepolia_example_boots_and_syncs_from_upstream_a_request_a_second_at_most() {
    const ROWS: u64 = 1_010;
    let data_root = tempfile::tempdir().expect("tempdir");
    let (endpoint, requests) = upstream_holding(ROWS).await;
    let (opts, observer) = shipped_sepolia_options(data_root.path(), &endpoint);
    assert_eq!(opts.mirror_backfill_interval_secs, None);
    let (booting, _view) = boot(opts, &observer).await;
    drop(observer);

    let feed = until_done_or_stalled("the feed catches up", async || {
        let feed = readiness(booting.addr)
            .await
            .and_then(|body| body.mirror_feeds.into_iter().next());
        let progress = feed.as_ref().map(|feed| (feed.rows_held, feed.next_index));
        let done = feed.filter(|feed| feed.state == MirrorFeedState::CaughtUp);
        ((progress, requests.lock().len()), done)
    })
    .await;
    assert_eq!((feed.rows_held, feed.upstream_rows), (ROWS, Some(ROWS)));
    shut_down(booting).await;

    let requests = requests.lock().clone();
    let starts: Vec<u64> = requests
        .iter()
        .map(|(_, _, request)| request["params"]["startIndex"].as_u64().expect("start"))
        .collect();
    assert_eq!(
        starts[..4],
        [0, 0, 501, 1_002],
        "the preflight, then the pages"
    );
    for (_, agent, request) in &requests {
        assert_eq!(request["params"]["chainID"], SEPOLIA_CHAIN_ID.to_string());
        assert_eq!(agent.as_deref(), Some(USER_AGENT));
    }
    for pair in requests.windows(2) {
        let gap = pair[1].0.duration_since(pair[0].0);
        assert!(
            gap + HOP >= Duration::from_secs(1),
            "requests {gap:?} apart"
        );
    }
}
