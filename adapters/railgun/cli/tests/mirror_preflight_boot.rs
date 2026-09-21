//! Boot against an upstream PPOI endpoint that cannot feed the mirror.
//!
//! The mirror worker warns and retries forever, so boot is the only place a dead endpoint can
//! be refused. Two failures sit either side of that refusal: a node holding nothing that boots
//! clean and serves nothing, and a node holding rows that an upstream outage keeps down.
//!
//! Every endpoint here is an in-process listener on loopback.

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
    ProductionServeOptions, MIRROR_PREFLIGHT_FAILED_TOTAL, MIRROR_PREFLIGHT_TIMEOUT,
};
use raven_railgun_cli::serve_production_multi::{
    load_options_from_toml, run_with_listener, BootstrapObserver, BootstrapView, MultiServeOptions,
};
use raven_railgun_engine::inspire::{setup_state_with_inspiring_seed, LogicalLeafStore};
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine_multi, DataSourceFilter, InstanceConfig,
};
use raven_railgun_engine::persistence::ConsumerEvent;
use raven_railgun_engine::pir_table::EncoderKind;
use raven_railgun_engine::InstanceRole;
use raven_railgun_persistence::{PpoiEventType, WalEntryPayload};
use raven_railgun_ppoi_mirror::PreflightFailure;
use serde_json::{json, Value};
use tokio::sync::{oneshot, Notify};
use tokio::task::JoinHandle;

const BEARER_TOKEN: &str = "mirror-preflight-boot-token-padded";
const OFAC_LIST_HEX: &str = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";
const STATUS: &str = "ppoi-status-ofac";
const PATHS_BLOCK_0: &str = "ppoi-paths-ofac-0";
const PATHS_BLOCK_1: &str = "ppoi-paths-ofac-1";

/// Counted from the end of instance bootstrap, because PIR setup is machine speed and the
/// preflight is not. Twice the bound, so a second sequential wait on one list key overruns it.
fn boot_guard() -> Duration {
    MIRROR_PREFLIGHT_TIMEOUT * 2
}

/// Accepts and holds every connection open in silence.
async fn upstream_that_never_answers() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    url
}

type Requests = Arc<parking_lot::Mutex<Vec<Value>>>;

async fn upstream_with_an_empty_list() -> (String, Requests) {
    let requests = Requests::default();
    let seen = Arc::clone(&requests);
    let app = Router::new().route(
        "/",
        post(move |Json(request): Json<Value>| {
            let seen = Arc::clone(&seen);
            async move {
                seen.lock().push(request);
                Json(json!({ "jsonrpc": "2.0", "id": 1, "result": [] }))
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

fn ofac_list() -> [u8; 32] {
    let mut key = [0u8; 32];
    for (byte, pair) in key.iter_mut().zip(OFAC_LIST_HEX.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).expect("ascii hex");
        *byte = u8::from_str_radix(pair, 16).expect("hex byte");
    }
    key
}

/// The shipped example narrowed to `instance_ids`, mirror workers left ENABLED as the loader
/// leaves them, chain workers off. `mirror_endpoint` is the only address a mirror worker dials.
fn shipped_ppoi_options(
    data_root: &Path,
    instance_ids: &[&str],
    mirror_endpoint: &str,
) -> (MultiServeOptions, BootstrapObserver) {
    assert!(
        mirror_endpoint.starts_with("http://127.0.0.1:"),
        "mirror workers are enabled; the endpoint must be an in-process listener: {mirror_endpoint}"
    );
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/mainnet-6-instance.toml");
    let body = std::fs::read_to_string(example)
        .expect("read the shipped example")
        .replace(
            "/var/lib/raven-railgun/",
            &format!("{}/", data_root.display()),
        )
        .replace("REPLACE_ME", BEARER_TOKEN);
    let config = data_root.join("config.toml");
    std::fs::write(&config, body).expect("write config");
    restrict_to_owner(&config);

    let mut opts = load_options_from_toml(&config).expect("parse the shipped example");
    opts.instances
        .retain(|instance| instance_ids.contains(&instance.instance_id.as_str()));
    assert_eq!(
        opts.instances.len(),
        instance_ids.len(),
        "the shipped example no longer declares every one of {instance_ids:?}"
    );
    opts.bind = "127.0.0.1:0".parse().expect("addr");
    opts.skip_chain_workers = true;
    mirror_endpoint.clone_into(&mut opts.mirror_endpoint);
    opts.entries = 256;
    for instance in &mut opts.instances {
        instance.use_flock = false;
    }
    let observer = BootstrapObserver::default();
    opts.bootstrap_observer = Some(Arc::clone(&observer));
    (opts, observer)
}

/// The parser refuses a group- or world-readable config carrying an inline token.
fn restrict_to_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("fixture config must be owner-only");
    }
    #[cfg(not(unix))]
    let _ = path;
}

struct Booting {
    addr: SocketAddr,
    server: JoinHandle<anyhow::Result<()>>,
    stop: oneshot::Sender<()>,
}

async fn boot_multi(opts: MultiServeOptions) -> Booting {
    let listener = tokio::net::TcpListener::bind(opts.bind)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(run_with_listener(opts, listener, async move {
        let _ = stopped.await;
    }));
    Booting { addr, server, stop }
}

/// `None` when boot ended before its instances came up; a refused boot is only legitimate
/// here once bootstrap is over, so the error is surfaced rather than swallowed.
async fn bootstrapped(
    observer: &BootstrapObserver,
    booting: &mut Booting,
) -> Option<BootstrapView> {
    // 300 s: the allowance the six-instance suite gives cold PIR bootstraps under CI contention.
    for _ in 0..1200u32 {
        if let Some(view) = observer.lock().clone() {
            return Some(view);
        }
        if booting.server.is_finished() {
            let ended = (&mut booting.server).await.expect("boot task panicked");
            let refusal = ended.expect_err("the serve loop returned Ok with no shutdown signal");
            panic!("boot ended before its instances came up: {refusal:#}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("instances never finished bootstrapping");
}

enum Boot {
    Refused(String),
    Serving,
}

async fn status_answers(addr: SocketAddr) {
    let client = reqwest::Client::new();
    loop {
        let answered = client
            .get(format!("http://{addr}/v1/status"))
            .bearer_auth(BEARER_TOKEN)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success());
        if answered {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Call once bootstrap is over; see [`boot_guard`].
async fn boot_verdict(booting: &mut Booting) -> Boot {
    let verdict = async {
        tokio::select! {
            joined = &mut booting.server => match joined.expect("boot task panicked") {
                Err(refusal) => Boot::Refused(format!("{refusal:#}")),
                Ok(()) => panic!("the serve loop returned Ok with no shutdown signal"),
            },
            () = status_answers(booting.addr) => Boot::Serving,
        }
    };
    tokio::time::timeout(boot_guard(), verdict)
        .await
        .expect("boot neither refused nor served inside twice the preflight bound")
}

async fn shut_down(booting: Booting) {
    let _ = booting.stop.send(());
    tokio::time::timeout(Duration::from_secs(20), booting.server)
        .await
        .expect("shutdown timed out")
        .expect("server task panicked")
        .expect("graceful shutdown");
}

/// The single-instance path drains its indexer and mirror workers in turn on a graceful
/// shutdown, up to 14 s each; nothing here is asserted after the verdict, so abort instead.
async fn abort(booting: Booting) {
    booting.server.abort();
    let _ = tokio::time::timeout(Duration::from_secs(20), booting.server).await;
}

fn assert_refusal_names_the_dead_endpoint(refusal: &str, endpoint: &str, setting: &str) {
    assert!(
        refusal.contains(endpoint),
        "refusal must name the endpoint {endpoint}: {refusal}"
    );
    let class = PreflightFailure::Timeout(MIRROR_PREFLIGHT_TIMEOUT).to_string();
    assert!(
        refusal.contains(&class),
        "refusal must name the failure class {class:?}: {refusal}"
    );
    assert!(
        refusal.contains(setting),
        "refusal must name the setting to fix, {setting}: {refusal}"
    );
}

async fn served_through_failures(addr: SocketAddr) -> u64 {
    let scrape = reqwest::Client::new()
        .get(format!("http://{addr}/metrics"))
        .bearer_auth(BEARER_TOKEN)
        .send()
        .await
        .expect("scrape")
        .text()
        .await
        .expect("metrics body");
    scrape
        .lines()
        .find_map(|line| {
            line.strip_prefix(MIRROR_PREFLIGHT_FAILED_TOTAL)?
                .trim()
                .parse()
                .ok()
        })
        .unwrap_or(0)
}

fn rows_in(store: &parking_lot::Mutex<LogicalLeafStore>, list_key: &[u8; 32]) -> usize {
    store
        .lock()
        .ppoi_imt(list_key)
        .map_or(0, raven_railgun_engine::imt::Imt::leaf_count)
}

fn local_rows(
    instance: &raven_railgun_cli::serve_production_multi::BootstrapInstanceView,
    list_key: &[u8; 32],
) -> usize {
    rows_in(&instance.logical_store, list_key)
}

/// Boots `instance_ids` through the engine alone, delivers one upstream row the way the mirror
/// worker does, and shuts the consumers down cleanly. No server: a serving boot installs the
/// process-global metrics recorder, and one left behind by a seeding boot would hide a count
/// made before the real boot installs its own.
async fn leave_one_row_on_disk(data_root: &Path, instance_ids: &[&str]) {
    let (opts, _) = shipped_ppoi_options(data_root, instance_ids, "http://127.0.0.1:1");
    let params = InspireParams::secure_128_d2048();
    // The cell the serve path builds, so the snapshot left behind is the one it would leave.
    let factory = |config: &InstanceConfig| {
        let entry_size = config.record_size.max(32);
        let entries = *opts
            .instance_entries
            .get(&config.instance_id)
            .expect("every instance the factory sees was given a row count");
        let initial_db: Vec<u8> = (0..entries)
            .flat_map(|i| (0..entry_size).map(move |j| u8::try_from((i + j) % 251).unwrap_or(0)))
            .collect();
        setup_state_with_inspiring_seed(
            &params,
            &initial_db,
            entry_size,
            InspireVariant::TwoPacking,
            None,
        )
        .map(|(state, _)| state)
    };
    let mut engine =
        bootstrap_railgun_engine_multi(opts.instances.clone(), params.clone(), factory)
            .expect("engine bootstrap");

    engine
        .channels
        .mirror_tx
        .send((
            WalEntryPayload::PpoiListLeafAdded {
                list_key: ofac_list(),
                list_index: 0,
                blinded_commitment: raven_railgun_testkit::canonical(0x71),
                status: 0,
                event_type: PpoiEventType::Shield,
                signature: vec![0; 64],
                validated_merkleroot: [0; 32],
            },
            0,
        ))
        .await
        .expect("mirror channel open");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !engine
        .instances
        .iter()
        .all(|instance| rows_in(&instance.logical_store, &ofac_list()) == 1)
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the row was never applied"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    for instance in &mut engine.instances {
        instance
            .sender
            .send(ConsumerEvent::Shutdown)
            .await
            .expect("consumer open");
        tokio::time::timeout(Duration::from_secs(60), &mut instance.consumer)
            .await
            .expect("consumer drained")
            .expect("consumer joined")
            .expect("consumer exited clean");
    }
    engine.router.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_holding_no_rows_refuses_to_boot_against_an_upstream_that_never_answers() {
    let data_root = tempfile::tempdir().expect("tempdir");
    let endpoint = upstream_that_never_answers().await;
    let (opts, observer) = shipped_ppoi_options(data_root.path(), &[STATUS], &endpoint);
    let mut booting = boot_multi(opts).await;
    bootstrapped(&observer, &mut booting).await;

    match boot_verdict(&mut booting).await {
        Boot::Refused(refusal) => {
            assert_refusal_names_the_dead_endpoint(&refusal, &endpoint, "mirror_endpoint");
        }
        Boot::Serving => panic!(
            "a node holding no rows for the list booted and is serving, against an upstream \
             that never answers: it serves nothing and nothing says so"
        ),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_holding_rows_boots_past_an_upstream_that_never_answers_and_counts_it() {
    let data_root = tempfile::tempdir().expect("tempdir");
    leave_one_row_on_disk(data_root.path(), &[STATUS]).await;

    let endpoint = upstream_that_never_answers().await;
    let (opts, observer) = shipped_ppoi_options(data_root.path(), &[STATUS], &endpoint);
    let mut booting = boot_multi(opts).await;
    let view = bootstrapped(&observer, &mut booting)
        .await
        .expect("restart bootstraps");
    assert_eq!(
        local_rows(
            view.instances
                .first()
                .expect("the restart brought an instance up"),
            &ofac_list()
        ),
        1,
        "the restart must recover the row, or this test is not about a populated node"
    );

    match boot_verdict(&mut booting).await {
        Boot::Serving => {}
        Boot::Refused(refusal) => {
            panic!("an upstream outage kept a node holding rows from restarting: {refusal}")
        }
    }
    assert!(
        served_through_failures(booting.addr).await >= 1,
        "serving past a dead upstream must be counted on /metrics"
    );
    shut_down(booting).await;
}

/// The worker runs on the status instance; the rows here live under a path block only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rows_held_only_by_a_block_instance_still_keep_the_node_up() {
    let data_root = tempfile::tempdir().expect("tempdir");
    leave_one_row_on_disk(data_root.path(), &[PATHS_BLOCK_0]).await;

    let endpoint = upstream_that_never_answers().await;
    let (opts, observer) =
        shipped_ppoi_options(data_root.path(), &[STATUS, PATHS_BLOCK_0], &endpoint);
    let mut booting = boot_multi(opts).await;
    let view = bootstrapped(&observer, &mut booting)
        .await
        .expect("restart bootstraps");
    let rows_under = |id: &str| {
        let instance = view
            .instances
            .iter()
            .find(|instance| instance.instance_id.as_str() == id)
            .expect("instance booted");
        local_rows(instance, &ofac_list())
    };
    assert_eq!(
        (rows_under(STATUS), rows_under(PATHS_BLOCK_0)),
        (0, 1),
        "fixture: the list's only row must sit under the block instance"
    );

    match boot_verdict(&mut booting).await {
        Boot::Serving => {}
        Boot::Refused(refusal) => panic!(
            "the list has a served row under {PATHS_BLOCK_0}, yet boot was refused: {refusal}"
        ),
    }
    assert!(
        served_through_failures(booting.addr).await >= 1,
        "serving past a dead upstream must be counted on /metrics"
    );
    shut_down(booting).await;
}

/// Two `PpoiList` instances on one key, so two mirror workers: the shipped topology has one
/// and could not tell a per-key preflight from a per-worker one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answering_upstream_is_asked_once_per_list_key_however_many_instances_share_it() {
    let data_root = tempfile::tempdir().expect("tempdir");
    let (endpoint, requests) = upstream_with_an_empty_list().await;
    let (mut opts, observer) = shipped_ppoi_options(
        data_root.path(),
        &[STATUS, PATHS_BLOCK_0, PATHS_BLOCK_1],
        &endpoint,
    );
    for instance in &mut opts.instances {
        if let DataSourceFilter::PpoiListBlock { list_key, block: 0 } = instance.data_source {
            instance.data_source = DataSourceFilter::PpoiList(list_key);
            instance.role = InstanceRole::Live;
        }
    }
    let mut booting = boot_multi(opts).await;
    bootstrapped(&observer, &mut booting).await;

    match boot_verdict(&mut booting).await {
        Boot::Serving => {}
        Boot::Refused(refusal) => panic!("an answering upstream was refused: {refusal}"),
    }

    // A worker page spans `max_rows_per_fetch` indices; only the preflight asks for index 0 alone.
    let preflights: Vec<Value> = requests
        .lock()
        .iter()
        .filter(|request| request.pointer("/params/endIndex") == Some(&json!(0)))
        .cloned()
        .collect();
    assert_eq!(
        preflights.len(),
        1,
        "boot must cost upstream one preflight per list key: {preflights:?}"
    );
    assert_eq!(
        preflights
            .first()
            .expect("exactly one preflight was recorded")
            .pointer("/params/listKey"),
        Some(&json!(OFAC_LIST_HEX))
    );
    shut_down(booting).await;
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

fn single_instance_options(
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
        instance_id: "single".to_owned(),
        max_concurrent_queries: 4,
        respond_timeout_secs: 30,
        entries: 65_536,
        entry_bytes: 32,
        encoder,
        session_eviction_interval_secs: 0,
        metrics_public: false,
        enable_fanout: false,
        max_fanout_shards: 16,
    }
}

async fn boot_single(opts: ProductionServeOptions, head_asked: &Notify) -> Booting {
    let listener = tokio::net::TcpListener::bind(opts.bind)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(raven_railgun_cli::serve_production::run_with_listener(
        opts,
        listener,
        async move {
            let _ = stopped.await;
        },
    ));
    tokio::time::timeout(Duration::from_secs(300), head_asked.notified())
        .await
        .expect("the single-instance path never asked the chain RPC for its head");
    Booting { addr, server, stop }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_single_list_instance_holding_no_rows_refuses_an_upstream_that_never_answers() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    let (rpc_url, head_asked) = chain_rpc_with_a_finalized_block().await;
    let endpoint = upstream_that_never_answers().await;
    let opts = single_instance_options(
        data_dir.path(),
        EncoderKind::PerListStatus {
            list_key: ofac_list(),
        },
        rpc_url,
        endpoint.clone(),
    );
    let mut booting = boot_single(opts, &head_asked).await;

    match boot_verdict(&mut booting).await {
        Boot::Refused(refusal) => {
            assert_refusal_names_the_dead_endpoint(&refusal, &endpoint, "--mirror-endpoint");
        }
        Boot::Serving => panic!(
            "a list instance holding no rows booted and is serving, against an upstream that \
             never answers"
        ),
    }
}

/// The single-instance path runs a mirror beside every encoder, the default chain cell
/// included. That cell serves chain rows, so the list upstream being down is not its outage.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_single_chain_instance_boots_past_an_upstream_that_never_answers_and_counts_it() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    let (rpc_url, head_asked) = chain_rpc_with_a_finalized_block().await;
    let endpoint = upstream_that_never_answers().await;
    let opts = single_instance_options(
        data_dir.path(),
        EncoderKind::PerLeafBc { tree_number: 0 },
        rpc_url,
        endpoint,
    );
    let mut booting = boot_single(opts, &head_asked).await;

    match boot_verdict(&mut booting).await {
        Boot::Serving => {}
        Boot::Refused(refusal) => panic!(
            "a chain instance was kept down by the list upstream it does not serve from: {refusal}"
        ),
    }
    assert!(
        served_through_failures(booting.addr).await >= 1,
        "serving past a dead upstream must be counted on /metrics"
    );
    abort(booting).await;
}
