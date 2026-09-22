//! A single-instance node answers a shim route only over a domain it declared.
//!
//! One store cannot bound a PPOI list: its only boundary is its own frontier under the
//! 65,536-row per-IMT wall, so "whole list" and "however far this node has got" would be the
//! same predicate. The routes over that domain answer ABSENCE, so this path declares no list
//! and refuses them - and the refusal has to come from the coverage proof, not from a store
//! that was never wired, which is why every assertion here reads the refusal counter.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_cli::serve_production::{
    run_with_listener, ProductionServeOptions, MIRROR_PREFLIGHT_FAILED_TOTAL,
};
use raven_railgun_engine::inspire::setup_state;
use raven_railgun_engine::orchestrator::{bootstrap_railgun_engine, OrchestratorConfig};
use raven_railgun_engine::persistence::ConsumerEvent;
use raven_railgun_engine::pir_table::EncoderKind;
use raven_railgun_engine::InstanceRole;
use raven_railgun_persistence::{PpoiEventType, WalEntryPayload};
use serde_json::{json, Value};
use tokio::sync::{oneshot, Notify};

const BEARER_TOKEN: &str = "single-instance-shim-coverage-token";
const OFAC_LIST_HEX: &str = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";
const INSTANCE_ID: &str = "single";
const ENTRIES: usize = 65_536;
const ENTRY_BYTES: usize = 32;
const SEEDED_ROWS: u32 = 3;

/// Incremented only by the shim's coverage refusal, so it separates "the proof refused" from
/// "no store was ever wired", which answer the same 503.
const COVERAGE_REFUSALS_TOTAL: &str = "raven_railgun_shim_coverage_refusals_total";

/// A route an unreachable upstream cannot disable, so its 503 is about coverage alone.
const LIST_ROUTES: [&str; 4] = [
    "pois-per-list",
    "merkle-proofs",
    "bc-to-idx-map",
    "status-header",
];

fn ofac_list() -> [u8; 32] {
    let mut key = [0u8; 32];
    for (byte, pair) in key.iter_mut().zip(OFAC_LIST_HEX.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).expect("ascii hex");
        *byte = u8::from_str_radix(pair, 16).expect("hex byte");
    }
    key
}

fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn single_options(
    data_dir: &Path,
    encoder: EncoderKind,
    rpc_url: String,
    mirror_endpoint: String,
) -> ProductionServeOptions {
    ProductionServeOptions {
        bind: "127.0.0.1:0".parse().expect("addr"),
        token: BEARER_TOKEN.to_owned(),
        rpc_url,
        railgun_proxy: "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9".to_owned(),
        chain_id: 1,
        start_block: 0,
        mirror_endpoint,
        list_key: OFAC_LIST_HEX.to_owned(),
        data_dir: data_dir.to_path_buf(),
        instance_id: INSTANCE_ID.to_owned(),
        max_concurrent_queries: 4,
        respond_timeout_secs: 30,
        entries: ENTRIES,
        entry_bytes: ENTRY_BYTES,
        encoder,
        session_eviction_interval_secs: 0,
        metrics_public: false,
        enable_fanout: false,
        max_fanout_shards: 16,
    }
}

/// The cell the serve path builds, so the snapshot left behind is the one it would leave.
fn production_cell(params: &InspireParams) -> raven_railgun_engine::inspire::InspireServerState {
    let initial_db: Vec<u8> = (0..ENTRIES)
        .flat_map(|i| (0..ENTRY_BYTES).map(move |j| u8::try_from((i + j) % 251).unwrap_or(0)))
        .collect();
    setup_state(params, &initial_db, ENTRY_BYTES, InspireVariant::TwoPacking)
        .expect("setup_state")
        .0
}

/// Leave `SEEDED_ROWS` PPOI rows in `data_dir` through the engine alone, so the serving boot
/// recovers a store that genuinely holds part of the list.
///
/// No server: a serving boot installs the process-global metrics recorder, and one left by a
/// seeding boot would hide the counts the real boot is asked for. `use_flock` is off because
/// `open_with_lock` refuses a second holder in the same process, this one included.
async fn leave_list_rows_on_disk(data_dir: &Path, encoder: EncoderKind) {
    let params = InspireParams::secure_128_d2048();
    let mut config = OrchestratorConfig::demo(data_dir.to_path_buf(), INSTANCE_ID);
    config.role = InstanceRole::Live;
    config.encoder = encoder;
    config.record_size = ENTRY_BYTES;
    config.entries_per_shard = u32::try_from(ENTRIES.min(params.ring_dim)).expect("rows per shard");
    config.use_flock = false;

    let handle = bootstrap_railgun_engine(config, params.clone(), || Ok(production_cell(&params)))
        .expect("engine bootstrap");
    for index in 0..SEEDED_ROWS {
        handle
            .sender
            .send(ConsumerEvent::Ppoi(
                WalEntryPayload::PpoiListLeafAdded {
                    list_key: ofac_list(),
                    list_index: index,
                    blinded_commitment: raven_railgun_testkit::canonical(
                        u8::try_from(index).expect("row fits a seed byte") + 0x71,
                    ),
                    status: 0,
                    event_type: PpoiEventType::Shield,
                    signature: vec![0; 64],
                    validated_merkleroot: [0; 32],
                },
                u64::from(index),
            ))
            .await
            .expect("consumer open");
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while rows_held(&handle) < SEEDED_ROWS as usize {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the seeded list rows were never applied"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    handle
        .sender
        .send(ConsumerEvent::Shutdown)
        .await
        .expect("consumer open");
    tokio::time::timeout(Duration::from_secs(60), handle.consumer)
        .await
        .expect("consumer drained")
        .expect("consumer joined")
        .expect("consumer exited clean");
    handle.indexer_bridge.abort();
    handle.mirror_bridge.abort();
}

fn rows_held(handle: &raven_railgun_engine::orchestrator::OrchestratorHandle) -> usize {
    handle
        .logical_store
        .lock()
        .ppoi_imt(&ofac_list())
        .map_or(0, raven_railgun_engine::imt::Imt::leaf_count)
}

struct Serving {
    addr: SocketAddr,
    server: tokio::task::JoinHandle<anyhow::Result<()>>,
    stop: oneshot::Sender<()>,
}

async fn boot(opts: ProductionServeOptions, head_asked: &Notify) -> Serving {
    let listener = tokio::net::TcpListener::bind(opts.bind)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(run_with_listener(opts, listener, async move {
        let _ = stopped.await;
    }));
    tokio::time::timeout(Duration::from_secs(300), head_asked.notified())
        .await
        .expect("the single-instance path never asked the chain RPC for its head");
    let ready = Serving { addr, server, stop };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        if reqwest::Client::new()
            .get(format!("http://{addr}/v1/status"))
            .bearer_auth(BEARER_TOKEN)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            return ready;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the single-instance server never answered /v1/status"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn shut_down(serving: Serving) {
    let _ = serving.stop.send(());
    let _ = tokio::time::timeout(Duration::from_secs(25), serving.server).await;
}

async fn scrape(addr: SocketAddr) -> String {
    reqwest::Client::new()
        .get(format!("http://{addr}/metrics"))
        .bearer_auth(BEARER_TOKEN)
        .send()
        .await
        .expect("scrape")
        .text()
        .await
        .expect("metrics body")
}

fn counter(scrape: &str, name: &str) -> u64 {
    scrape
        .lines()
        .find(|line| line.starts_with(name) && !line.starts_with('#'))
        .and_then(|line| line.rsplit(' ').next()?.parse().ok())
        .unwrap_or(0)
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

async fn ask_list_routes(addr: SocketAddr) -> Vec<(&'static str, StatusCode)> {
    let client = reqwest::Client::new();
    let list_key_hex = OFAC_LIST_HEX;
    let probe = hex32(&raven_railgun_testkit::canonical(0x71));
    let base = format!("http://{addr}");
    let mut out = Vec::with_capacity(LIST_ROUTES.len());
    out.push((
        "pois-per-list",
        client
            .post(format!("{base}/v1/poi/pois-per-list"))
            .bearer_auth(BEARER_TOKEN)
            .json(&json!({
                "listKeys": [list_key_hex],
                "blindedCommitmentDatas": [{ "blindedCommitment": probe }],
            }))
            .send()
            .await
            .expect("pois-per-list")
            .status(),
    ));
    out.push((
        "merkle-proofs",
        client
            .post(format!("{base}/v1/poi/merkle-proofs"))
            .bearer_auth(BEARER_TOKEN)
            .json(&json!({ "listKey": list_key_hex, "blindedCommitments": [probe] }))
            .send()
            .await
            .expect("merkle-proofs")
            .status(),
    ));
    out.push((
        "bc-to-idx-map",
        client
            .get(format!("{base}/v1/poi/{list_key_hex}/bc-to-idx-map"))
            .bearer_auth(BEARER_TOKEN)
            .send()
            .await
            .expect("bc-to-idx-map")
            .status(),
    ));
    out.push((
        "status-header",
        client
            .get(format!("{base}/v1/poi/{list_key_hex}/status-header"))
            .bearer_auth(BEARER_TOKEN)
            .send()
            .await
            .expect("status-header")
            .status(),
    ));
    out
}

async fn ask_commit_tree(addr: SocketAddr, tree_number: u32) -> StatusCode {
    reqwest::Client::new()
        .post(format!(
            "http://{addr}/v1/commit-tree/{tree_number}/merkle-proof"
        ))
        .bearer_auth(BEARER_TOKEN)
        .json(&json!({ "leafIndex": 0 }))
        .send()
        .await
        .expect("commit-tree merkle proof")
        .status()
}

/// The store holds part of the list and the node still refuses every route over it.
///
/// The preflight counter is the witness that the rows are there: a list instance with no
/// local rows refuses to boot against an unreachable upstream, so a node that booted past one
/// and counted it is a node holding rows. Serving them would be a 200 over the 65,533 rows it
/// does not have.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_single_list_instance_holding_rows_still_refuses_every_list_route() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    let encoder = EncoderKind::PerListStatus {
        list_key: ofac_list(),
    };
    leave_list_rows_on_disk(data_dir.path(), encoder).await;

    let (rpc_url, head_asked) = chain_rpc_with_a_finalized_block().await;
    let serving = boot(
        single_options(
            data_dir.path(),
            encoder,
            rpc_url,
            // Refused at connect, so the preflight fails inside its bound.
            "http://127.0.0.1:1".to_owned(),
        ),
        &head_asked,
    )
    .await;

    let statuses = ask_list_routes(serving.addr).await;
    let body = scrape(serving.addr).await;
    assert_eq!(
        counter(&body, MIRROR_PREFLIGHT_FAILED_TOTAL),
        1,
        "this node booted past a dead upstream, which a list instance can only do when it \
         holds rows; without that the refusals below prove nothing"
    );
    for (route, status) in &statuses {
        assert_eq!(
            *status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{route} answered {status} over a list one store cannot bound"
        );
    }
    for route in LIST_ROUTES {
        assert!(
            refusals_for(&body, route) >= 1,
            "{route} must refuse through the coverage proof, not because nothing was wired: \
             {body}"
        );
    }
    shut_down(serving).await;
}

/// The chain half of the same declaration: the tree the encoder is pinned to reaches the
/// store, every other tree is refused by the proof, and no list is declared at all.
///
/// 404, not 200, because this node has indexed no leaf yet - but it is the store answering,
/// which is the distinction a 503 erases.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_single_chain_instance_declares_its_tree_and_nothing_else() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    let (rpc_url, head_asked) = chain_rpc_with_a_finalized_block().await;
    let serving = boot(
        single_options(
            data_dir.path(),
            EncoderKind::PerLeafBc { tree_number: 0 },
            rpc_url,
            "http://127.0.0.1:1".to_owned(),
        ),
        &head_asked,
    )
    .await;

    let declared = ask_commit_tree(serving.addr, 0).await;
    let undeclared = ask_commit_tree(serving.addr, 7).await;
    let list_statuses = ask_list_routes(serving.addr).await;
    let body = scrape(serving.addr).await;

    assert_eq!(
        declared,
        StatusCode::NOT_FOUND,
        "tree 0 is this encoder's own tree: the request must reach the store"
    );
    assert_eq!(
        undeclared,
        StatusCode::SERVICE_UNAVAILABLE,
        "tree 7 is held by nobody here and must not be answered from tree 0's store"
    );
    assert_eq!(
        refusals_for(&body, "commit-tree-merkle-proof"),
        1,
        "exactly the undeclared tree is refused through the proof: {body}"
    );
    for (route, status) in &list_statuses {
        assert_eq!(
            *status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{route} answered {status} on a node that declares no list"
        );
        assert!(
            refusals_for(&body, route) >= 1,
            "{route} must refuse through the coverage proof: {body}"
        );
    }
    shut_down(serving).await;
}

/// Answers the two calls the single-instance path makes before it builds the mirror, and
/// signals the second: that is the end of its instance bootstrap.
async fn chain_rpc_with_a_finalized_block() -> (String, Arc<Notify>) {
    let head_asked = Arc::new(Notify::new());
    let signal = Arc::clone(&head_asked);
    let app = Router::new().route(
        "/",
        post(move |Json(request): Json<Value>| {
            let signal = Arc::clone(&signal);
            async move {
                let id = request.get("id").cloned().unwrap_or(Value::Null);
                let result = match request.get("method").and_then(Value::as_str) {
                    Some("eth_chainId") => json!("0x1"),
                    Some("eth_getBlockByNumber") => {
                        signal.notify_one();
                        finalized_block()
                    }
                    _ => {
                        return (
                            StatusCode::OK,
                            Json(json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "error": { "code": -32601, "message": "unsupported in fixture" }
                            })),
                        );
                    }
                };
                (
                    StatusCode::OK,
                    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })),
                )
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
    (url, head_asked)
}

fn finalized_block() -> Value {
    let zero_hash = format!("0x{}", "0".repeat(64));
    json!({
        "number": "0x10",
        "hash": format!("0x{}", "1".repeat(64)),
        "parentHash": zero_hash,
        "sha3Uncles": zero_hash,
        "logsBloom": format!("0x{}", "0".repeat(512)),
        "transactionsRoot": zero_hash,
        "stateRoot": zero_hash,
        "receiptsRoot": zero_hash,
        "miner": format!("0x{}", "0".repeat(40)),
        "difficulty": "0x0",
        "totalDifficulty": "0x0",
        "mixHash": zero_hash,
        "nonce": "0x0000000000000000",
        "extraData": "0x",
        "size": "0x0",
        "gasLimit": "0x0",
        "gasUsed": "0x0",
        "timestamp": "0x0",
        "transactions": [],
        "uncles": [],
        "baseFeePerGas": "0x0",
    })
}
