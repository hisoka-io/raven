//! Boot against an upstream PPOI endpoint that cannot feed the mirror.
//!
//! The mirror worker warns and retries forever, so boot is the only place a dead endpoint can
//! be refused. Two failures sit either side of that refusal: a node holding nothing that boots
//! clean and serves nothing, and a node holding rows that an upstream outage keeps down.
//!
//! Also here: the pace of the feed a boot starts, since only a boot reads it from the config;
//! where it resumes, which only a boot reads off the stores; and what readiness says of it.
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
use raven_railgun_cli::serve_production_multi::{
    load_options_from_toml, run_with_listener, BootstrapObserver, BootstrapView, MultiServeOptions,
    MIRROR_PREFLIGHT_FAILED_TOTAL, MIRROR_PREFLIGHT_TIMEOUT,
};
use raven_railgun_engine::imt::Imt;
use raven_railgun_engine::inspire::{
    apply_wal_entry, re_encode_shard, setup_state_with_inspiring_seed, LogicalLeafStore,
};
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine_multi, DataSourceFilter, InstanceConfig, LEAVES_PER_PPOI_BLOCK,
};
use raven_railgun_engine::persistence::{ConsumerEvent, InspirePersistence};
use raven_railgun_engine::pir_table::PirTableEncoder;
use raven_railgun_engine::session_pool::BoundedSessionStore;
use raven_railgun_engine::InstanceRole;
use raven_railgun_http::status::{MirrorFeedState, MirrorFeedView};
use raven_railgun_http::HealthReadyResponse;
use raven_railgun_persistence::{PpoiEventType, StoreLayout, WalEntryPayload};
use raven_railgun_ppoi_mirror::{MirrorCursor, MirrorKind, PreflightFailure};
use serde_json::{json, Value};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const BEARER_TOKEN: &str = "mirror-preflight-boot-token-padded";
const OFAC_LIST_HEX: &str = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";
const STATUS: &str = "ppoi-status-ofac";
const PATHS_BLOCK_0: &str = "ppoi-paths-ofac-0";
const PATHS_BLOCK_1: &str = "ppoi-paths-ofac-1";
const SHIPPED_ENDPOINT: &str = "mirror_endpoint = \"https://ppoi.fdi.network\"";

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
    shipped_ppoi_options_with(data_root, instance_ids, mirror_endpoint, "")
}

/// [`shipped_ppoi_options`] with `global_line` added to the example's `[global]` table, so a
/// setting under test travels the loader an operator's file does.
fn shipped_ppoi_options_with(
    data_root: &Path,
    instance_ids: &[&str],
    mirror_endpoint: &str,
    global_line: &str,
) -> (MultiServeOptions, BootstrapObserver) {
    assert!(
        mirror_endpoint.starts_with("http://127.0.0.1:"),
        "mirror workers are enabled; the endpoint must be an in-process listener: {mirror_endpoint}"
    );
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/mainnet-6-instance.toml");
    let body = std::fs::read_to_string(example).expect("read the shipped example");
    assert_eq!(
        body.matches(SHIPPED_ENDPOINT).count(),
        1,
        "fixture: the shipped [global] table no longer carries {SHIPPED_ENDPOINT}"
    );
    let body = body
        .replace(
            SHIPPED_ENDPOINT,
            &format!("{SHIPPED_ENDPOINT}\n{global_line}"),
        )
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
    shut_down_within(booting, Duration::from_secs(20)).await;
}

/// A graceful stop commits each instance's snapshot, and a production cell holding a full block
/// re-encodes and writes one, which a loaded box stretches well past [`shut_down`]'s bound.
async fn shut_down_within(booting: Booting, within: Duration) {
    let _ = booting.stop.send(());
    tokio::time::timeout(within, booting.server)
        .await
        .expect("shutdown timed out")
        .expect("server task panicked")
        .expect("graceful shutdown");
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
    rows_in_store(&store.lock(), list_key)
}

fn local_rows(
    instance: &raven_railgun_cli::serve_production_multi::BootstrapInstanceView,
    list_key: &[u8; 32],
) -> usize {
    rows_in(&instance.logical_store, list_key)
}

fn rows_under(view: &BootstrapView, instance_id: &str) -> usize {
    let instance = view
        .instances
        .iter()
        .find(|instance| instance.instance_id.as_str() == instance_id)
        .expect("instance booted");
    local_rows(instance, &ofac_list())
}

/// Pages a mirror worker asked upstream for. The preflight asks for index 0 alone and a worker
/// asks for a span, so only these show a worker exists.
fn worker_pages(requests: &Requests) -> Vec<Value> {
    requests
        .lock()
        .iter()
        .filter(|request| {
            request.pointer("/params/listKey") == Some(&json!(OFAC_LIST_HEX))
                && request.pointer("/params/endIndex") != request.pointer("/params/startIndex")
        })
        .cloned()
        .collect()
}

/// A worker asks for its first page as it spawns, and the next only a poll interval later.
async fn first_worker_page(requests: &Requests) -> Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(page) = worker_pages(requests).into_iter().next() {
            return page;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no mirror worker asked upstream for a page of the list; upstream saw {:?}",
            requests.lock()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn leave_one_row_on_disk(data_root: &Path, instance_ids: &[&str]) {
    leave_rows_on_disk(data_root, instance_ids, &[0]).await;
}

/// Boots `instance_ids` through the engine alone, delivers the upstream rows at `indices` the
/// way the mirror worker does, and shuts the consumers down cleanly. Every instance must end up
/// holding all of them. No server: a serving boot installs the process-global metrics recorder,
/// and one left behind by a seeding boot would hide a count made before the real boot installs
/// its own.
async fn leave_rows_on_disk(data_root: &Path, instance_ids: &[&str], indices: &[u32]) {
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

    for (seed, &list_index) in (0x71u8..).zip(indices) {
        engine
            .channels
            .mirror_tx
            .send((
                WalEntryPayload::PpoiListLeafAdded {
                    list_key: ofac_list(),
                    list_index,
                    blinded_commitment: raven_railgun_testkit::canonical(seed),
                    status: 0,
                    event_type: PpoiEventType::Shield,
                    signature: vec![0; 64],
                    validated_merkleroot: [0; 32],
                },
                0,
            ))
            .await
            .expect("mirror channel open");
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !engine
        .instances
        .iter()
        .all(|instance| rows_in(&instance.logical_store, &ofac_list()) == indices.len())
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

/// Leaves each of `instance_ids`, all holding the list from its first row, holding rows `0..rows`
/// in one committed snapshot, every shard of its cell encoded from them, so a boot resumes past
/// them. Applied in memory: syncing to the same row costs two fsynced appends per row. Returns
/// the list's tree over those rows.
fn leave_rows_committed(data_root: &Path, instance_ids: &[&str], rows: u64) -> Imt {
    let (opts, _) = shipped_ppoi_options(data_root, instance_ids, "http://127.0.0.1:1");
    let params = InspireParams::secure_128_d2048();
    let encoders: Vec<_> = opts
        .instances
        .iter()
        .map(|config| {
            assert!(
                matches!(
                    config.data_source,
                    DataSourceFilter::PpoiList(_)
                        | DataSourceFilter::PpoiListBlock { block: 0, .. }
                ),
                "fixture seeds from the list's first row: {config:?}"
            );
            config
                .encoder
                .build(config.record_size, config.entries_per_shard)
                .expect("encoder")
        })
        .collect();
    let mut store = LogicalLeafStore::new();
    for index in 0..rows {
        let row = WalEntryPayload::PpoiListLeafAdded {
            list_key: ofac_list(),
            list_index: u32::try_from(index).expect("list index"),
            blinded_commitment: leaf_at(index),
            status: 0,
            event_type: PpoiEventType::Shield,
            signature: vec![0; 64],
            validated_merkleroot: [0; 32],
        };
        let encoder = encoders.first().expect("an instance");
        apply_wal_entry(&mut store, &row, 0, encoder.as_ref()).expect("apply");
    }
    store.clear_dirty_shards();
    std::thread::scope(|scope| {
        for (config, encoder) in opts.instances.iter().zip(&encoders) {
            let entries = *opts
                .instance_entries
                .get(&config.instance_id)
                .expect("every instance was given a row count");
            let (params, store) = (&params, &store);
            scope.spawn(move || commit_rows(config, encoder, entries, params, store.clone()));
        }
    });
    store
        .ppoi_imt(&ofac_list())
        .cloned()
        .expect("the list's tree")
}

fn commit_rows(
    config: &InstanceConfig,
    encoder: &Arc<dyn PirTableEncoder>,
    entries: usize,
    params: &InspireParams,
    mut store: LogicalLeafStore,
) {
    let layout = StoreLayout::open(&config.data_dir).expect("layout");
    let sessions = BoundedSessionStore::open(layout.root()).expect("session floor");
    let opened = InspirePersistence::open(
        layout,
        config.scheme_tag.clone(),
        config.instance_id.clone(),
        config.snapshot_policy,
        Arc::clone(encoder),
    )
    .expect("open");
    assert!(
        opened.recovered_state.is_none(),
        "fixture wants a fresh data_dir"
    );
    // The cell the serve path builds for a fresh instance.
    let entry_size = config.record_size.max(32);
    let initial_db: Vec<u8> = (0..entries)
        .flat_map(|i| (0..entry_size).map(move |j| u8::try_from((i + j) % 251).unwrap_or(0)))
        .collect();
    let (mut state, _) = setup_state_with_inspiring_seed(
        params,
        &initial_db,
        entry_size,
        InspireVariant::TwoPacking,
        None,
    )
    .expect("cell");
    state.session_store = Arc::new(sessions);
    let shards: Vec<u32> = state
        .encoded_db
        .shards
        .iter()
        .map(|shard| shard.id)
        .collect();
    for shard in shards {
        let bytes = encoder.materialize_shard(shard, &store);
        let entry_size = state.entry_size;
        re_encode_shard(
            Arc::make_mut(&mut state.encoded_db),
            params,
            shard,
            &bytes,
            entry_size,
        )
        .expect("re-encode");
    }
    store.refresh_committed_addenda(&state.encoded_db, encoder.entries_per_shard());
    opened
        .persistence
        .commit_v6(&state, &store, 0)
        .expect("commit");
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

/// The list's only row lives under a path block; the status instance beside it holds none.
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
    assert_eq!(
        (rows_under(&view, STATUS), rows_under(&view, PATHS_BLOCK_0)),
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

/// A list past one depth-16 tree can only be held by block instances, so a config that
/// declares nothing else still has to drive the feed. A spawn loop keyed on whole-list routes
/// gives it no worker: boot comes up clean, serves its rows, and never asks upstream for a
/// single row -- the outage this suite exists for, with no endpoint to blame. The preflight
/// names the list as well, so only a worker's page proves the feed runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_list_declared_only_in_blocks_still_drives_its_mirror_feed() {
    let data_root = tempfile::tempdir().expect("tempdir");
    leave_one_row_on_disk(data_root.path(), &[PATHS_BLOCK_0]).await;
    let (endpoint, requests) = upstream_with_an_empty_list().await;
    let (opts, observer) =
        shipped_ppoi_options(data_root.path(), &[PATHS_BLOCK_0, PATHS_BLOCK_1], &endpoint);
    assert!(
        opts.instances
            .iter()
            .all(|instance| matches!(instance.data_source, DataSourceFilter::PpoiListBlock { .. })),
        "fixture: no whole-list route may remain, or the old spawn loop would find one"
    );

    let mut booting = boot_multi(opts).await;
    bootstrapped(&observer, &mut booting).await;
    match boot_verdict(&mut booting).await {
        Boot::Serving => {}
        Boot::Refused(refusal) => panic!("an answering upstream was refused: {refusal}"),
    }

    let page = first_worker_page(&requests).await;
    assert_eq!(
        page.pointer("/params/startIndex"),
        Some(&json!(1)),
        "the feed must resume past the row {PATHS_BLOCK_0} holds: {page}"
    );
    shut_down(booting).await;
}

/// Instances on one list need not stand at the same row: this block was restored from an
/// older snapshot, or added after the status instance had mirrored a row and persisted its
/// cursor past it. A feed resumed from that cursor starts past the row the block lacks, and the
/// block then refuses every later row as non-contiguous, for good.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_instance_behind_the_rest_of_its_list_is_fed_from_the_row_it_lacks() {
    let data_root = tempfile::tempdir().expect("tempdir");
    leave_one_row_on_disk(data_root.path(), &[STATUS]).await;
    let (endpoint, requests) = upstream_with_an_empty_list().await;
    let (opts, observer) =
        shipped_ppoi_options(data_root.path(), &[STATUS, PATHS_BLOCK_0], &endpoint);
    let status_dir = opts
        .instances
        .iter()
        .find(|instance| instance.instance_id.as_str() == STATUS)
        .expect("the status instance is declared")
        .data_dir
        .clone();
    MirrorCursor::new(status_dir, MirrorKind::Status, 0)
        .persist(1)
        .expect("leave the cursor a worker on the status instance persists");

    let mut booting = boot_multi(opts).await;
    let view = bootstrapped(&observer, &mut booting)
        .await
        .expect("restart bootstraps");
    assert_eq!(
        (rows_under(&view, STATUS), rows_under(&view, PATHS_BLOCK_0)),
        (1, 0),
        "fixture: the block must stand behind the status instance"
    );
    match boot_verdict(&mut booting).await {
        Boot::Serving => {}
        Boot::Refused(refusal) => panic!("an answering upstream was refused: {refusal}"),
    }

    let page = first_worker_page(&requests).await;
    assert_eq!(
        page.pointer("/params/startIndex"),
        Some(&json!(0)),
        "the feed must start at the row {PATHS_BLOCK_0} lacks, not past it: {page}"
    );
    shut_down(booting).await;
}

/// Instances on one key cost upstream one preflight and one worker, however many a topology
/// puts under a list: the feed is the list's, and a second worker re-delivers every row for
/// each instance to refuse as a duplicate.
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

    first_worker_page(&requests).await;
    // Well inside `DEFAULT_POLL_INTERVAL_SECS`, so a second page can only be a second worker's.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let pages = worker_pages(&requests);
    assert_eq!(
        pages.len(),
        1,
        "boot must start one mirror worker per list key: {pages:?}"
    );
    shut_down(booting).await;
}

type TimedRequests = Arc<parking_lot::Mutex<Vec<(tokio::time::Instant, Value)>>>;

/// Holds rows `0..rows` and answers any page of them, stamping each request as it lands.
async fn upstream_holding(rows: u64) -> (String, TimedRequests) {
    let requests = TimedRequests::default();
    let seen = Arc::clone(&requests);
    let app = Router::new().route(
        "/",
        post(move |Json(request): Json<Value>| {
            let seen = Arc::clone(&seen);
            async move {
                let bound = |name: &str| {
                    request
                        .pointer(&format!("/params/{name}"))
                        .and_then(Value::as_u64)
                        .expect("page bound")
                };
                let (start, end) = (bound("startIndex"), bound("endIndex"));
                seen.lock().push((tokio::time::Instant::now(), request));
                let result: Vec<Value> = (start..=end.min(rows.saturating_sub(1)))
                    .map(|index| {
                        json!({
                            "signedPOIEvent": {
                                "index": index,
                                "blindedCommitment": format!("{index:064x}"),
                                "signature": "00".repeat(64),
                                "type": "Shield"
                            },
                            "validatedMerkleroot": format!("{:064x}", index + 1)
                        })
                    })
                    .collect();
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

/// `(landed, startIndex)` of each page a worker asked for; see [`worker_pages`].
fn timed_worker_pages(requests: &TimedRequests) -> Vec<(tokio::time::Instant, u64)> {
    requests
        .lock()
        .iter()
        .filter(|(_, request)| {
            request.pointer("/params/endIndex") != request.pointer("/params/startIndex")
        })
        .map(|(at, request)| {
            let start = request
                .pointer("/params/startIndex")
                .and_then(Value::as_u64);
            (*at, start.expect("page start"))
        })
        .collect()
}

/// A cold sync through the shipped loader: `[global].mirror_backfill_interval_secs = 0` has the
/// worker ask for each page as soon as the last full one is delivered, and the first short page
/// puts it back on the 30 s poll. At the poll alone the second page lands 30 s after the first,
/// so pages landing well inside that show the setting reached the worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_backfill_setting_pages_a_cold_sync_back_to_back_then_returns_to_the_poll() {
    let data_root = tempfile::tempdir().expect("tempdir");
    let (endpoint, requests) = upstream_holding(1_010).await;
    let (opts, observer) = shipped_ppoi_options_with(
        data_root.path(),
        &[PATHS_BLOCK_0],
        &endpoint,
        "mirror_backfill_interval_secs = 0",
    );
    assert_eq!(opts.mirror_backfill_interval_secs, Some(0));

    let mut booting = boot_multi(opts).await;
    bootstrapped(&observer, &mut booting).await;
    match boot_verdict(&mut booting).await {
        Boot::Serving => {}
        Boot::Refused(refusal) => panic!("an answering upstream was refused: {refusal}"),
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while timed_worker_pages(&requests).len() < 3 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "a cold sync of three pages did not finish: {:?}",
            timed_worker_pages(&requests)
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let pages = timed_worker_pages(&requests);
    let starts: Vec<u64> = pages.iter().map(|(_, start)| *start).collect();
    assert_eq!(
        starts,
        [0, 501, 1_002],
        "two full pages, then the short tail"
    );
    let spacing = pages
        .windows(2)
        .filter_map(|pair| match pair {
            [(earlier, _), (later, _)] => Some(later.duration_since(*earlier)),
            _ => None,
        })
        .max()
        .expect("three pages");
    assert!(
        spacing < Duration::from_secs(15),
        "full pages were {spacing:?} apart, the pace of the 30 s poll rather than the setting"
    );

    let short_page = pages.last().expect("three pages").0;
    tokio::time::sleep_until(short_page + Duration::from_secs(5)).await;
    assert_eq!(
        timed_worker_pages(&requests).len(),
        3,
        "after a short page the worker must wait the poll, not keep the backfill pace"
    );
    shut_down(booting).await;
}

/// Holds rows `0..rows` of the list with the roots upstream publishes, one depth-16 tree per
/// 65,536-row block, so every instance on the list applies what it is sent.
async fn upstream_holding_rooted(rows: u64) -> (String, Requests) {
    upstream_holding_rooted_after(rows, Duration::ZERO).await
}

/// [`upstream_holding_rooted`], answering each request `delay` after it arrives.
async fn upstream_holding_rooted_after(rows: u64, delay: Duration) -> (String, Requests) {
    let block = u64::from(raven_railgun_engine::orchestrator::LEAVES_PER_PPOI_BLOCK);
    let mut roots = Vec::new();
    let mut tree = raven_railgun_engine::imt::Imt::new().expect("imt");
    for index in 0..rows {
        if index % block == 0 {
            tree = raven_railgun_engine::imt::Imt::new().expect("imt");
        }
        let local = usize::try_from(index % block).expect("local index");
        tree.insert_leaves(local, &[leaf_at(index)])
            .expect("append");
        roots.push(tree.root());
    }
    upstream_answering(
        move |index| roots.get(usize::try_from(index).ok()?).copied(),
        delay,
    )
    .await
}

/// Answers each page with row `index`'s leaf and the root `root_at(index)` gives, `delay` after
/// the request arrives, and nothing for an index it gives none.
async fn upstream_answering(
    root_at: impl Fn(u64) -> Option<[u8; 32]> + Send + Sync + 'static,
    delay: Duration,
) -> (String, Requests) {
    let root_at = Arc::new(root_at);
    let requests = Requests::default();
    let seen = Arc::clone(&requests);
    let app = Router::new().route(
        "/",
        post(move |Json(request): Json<Value>| {
            let seen = Arc::clone(&seen);
            let root_at = Arc::clone(&root_at);
            async move {
                let bound = |name: &str| {
                    request
                        .pointer(&format!("/params/{name}"))
                        .and_then(Value::as_u64)
                        .expect("page bound")
                };
                let (start, end) = (bound("startIndex"), bound("endIndex"));
                seen.lock().push(request);
                tokio::time::sleep(delay).await;
                let result: Vec<Value> = (start..=end)
                    .filter_map(|index| {
                        let root = root_at(index)?;
                        Some(json!({
                            "signedPOIEvent": {
                                "index": index,
                                "blindedCommitment": hex::encode(leaf_at(index)),
                                "signature": "00".repeat(64),
                                "type": "Shield"
                            },
                            "validatedMerkleroot": hex::encode(root)
                        }))
                    })
                    .collect();
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

fn leaf_at(index: u64) -> [u8; 32] {
    let mut leaf = [0u8; 32];
    leaf[24..].copy_from_slice(&(index + 1).to_be_bytes());
    leaf
}

/// Answers every request HTTP 500, as upstream does for a range it will not serve.
async fn upstream_answering_500() -> String {
    let app = Router::new().route("/", post(|| async { StatusCode::INTERNAL_SERVER_ERROR }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    url
}

/// Uncredentialed, as the image's HEALTHCHECK calls it.
async fn readiness(addr: SocketAddr) -> (u16, HealthReadyResponse) {
    let response = reqwest::Client::new()
        .get(format!("http://{addr}/v1/health/ready"))
        .send()
        .await
        .expect("readiness probe");
    let code = response.status().as_u16();
    (code, response.json().await.expect("readiness body"))
}

/// Polls readiness until the list's feed satisfies `done`, and returns that answer.
async fn readiness_once(
    addr: SocketAddr,
    within: Duration,
    done: impl Fn(&MirrorFeedView) -> bool,
) -> (u16, HealthReadyResponse) {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let (code, body) = readiness(addr).await;
        if body.mirror_feeds.iter().any(&done) {
            return (code, body);
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "readiness never reached the awaited feed state: {code} {body:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn start_indices(requests: &Requests) -> Vec<u64> {
    worker_pages(requests)
        .iter()
        .map(|page| {
            page.pointer("/params/startIndex")
                .and_then(Value::as_u64)
                .expect("page start")
        })
        .collect()
}

/// The shipped PPOI instances on one list, fed cold from one upstream: each page of the list is
/// asked for once, however many instances share it, and each instance ends holding every row
/// its reach covers. Readiness is down while nothing is held and up once the feed is caught up,
/// which is the state an operator waits for before stopping the process to copy its data dirs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ppoi_only_boot_asks_for_each_page_once_and_fills_every_instance_on_the_list() {
    const ROWS: u64 = 1_010;
    let data_root = tempfile::tempdir().expect("tempdir");
    let (endpoint, requests) = upstream_holding_rooted(ROWS).await;
    let (opts, observer) = shipped_ppoi_options_with(
        data_root.path(),
        &[STATUS, PATHS_BLOCK_0, PATHS_BLOCK_1],
        &endpoint,
        "mirror_backfill_interval_secs = 0",
    );
    let mut booting = boot_multi(opts).await;
    let view = bootstrapped(&observer, &mut booting)
        .await
        .expect("boot bootstraps");
    match boot_verdict(&mut booting).await {
        Boot::Serving => {}
        Boot::Refused(refusal) => panic!("an answering upstream was refused: {refusal}"),
    }

    let (code, body) = readiness_once(booting.addr, Duration::from_secs(60), |feed| {
        feed.state == MirrorFeedState::CaughtUp
    })
    .await;
    assert_eq!(code, 200, "caught up and every row applied: {body:?}");
    let feed = body.mirror_feeds.first().expect("one list");
    assert_eq!(
        (feed.rows_held, feed.upstream_rows, feed.next_index),
        (ROWS, Some(ROWS), ROWS)
    );
    assert_eq!(
        (
            rows_under(&view, STATUS),
            rows_under(&view, PATHS_BLOCK_0),
            rows_under(&view, PATHS_BLOCK_1)
        ),
        (1_010, 1_010, 0),
        "every instance holds the rows its reach covers, and only those"
    );
    let (paging, polling): (Vec<u64>, Vec<u64>) = start_indices(&requests)
        .into_iter()
        .partition(|start| *start < ROWS);
    assert_eq!(
        paging,
        [0, 501, 1_002],
        "one request per page of the list, in order"
    );
    assert!(
        polling.iter().all(|start| *start == ROWS),
        "once caught up the feed asks only at the tip: {polling:?}"
    );
    let preflights = requests
        .lock()
        .iter()
        .filter(|request| request.pointer("/params/endIndex") == Some(&json!(0)))
        .count();
    assert_eq!(preflights, 1, "and one preflight for the list");
    shut_down(booting).await;

    // What the trigger promises: stopped once caught up, the data dirs hold every row upstream had.
    assert_eq!(
        (
            recovered_rows(data_root.path(), STATUS),
            recovered_rows(data_root.path(), PATHS_BLOCK_0),
            recovered_rows(data_root.path(), PATHS_BLOCK_1)
        ),
        (ROWS, ROWS, 0)
    );
}

/// Rows of the list `instance_id`'s data dir recovers to, reopened the way a boot reopens it.
/// Rows come back through the commit or WAL replay alike, so this pins durability across the
/// stop, not the stop's own final commit.
fn recovered_rows(data_root: &Path, instance_id: &str) -> u64 {
    let (opts, _) = shipped_ppoi_options(data_root, &[instance_id], "http://127.0.0.1:1");
    let config = opts.instances.first().expect("the instance");
    let encoder = config
        .encoder
        .build(config.record_size, config.entries_per_shard)
        .expect("encoder");
    let opened = InspirePersistence::open(
        StoreLayout::open(&config.data_dir).expect("layout"),
        config.scheme_tag.clone(),
        config.instance_id.clone(),
        config.snapshot_policy,
        encoder,
    )
    .expect("reopen after a graceful stop");
    assert!(
        opened.recovered_state.is_some(),
        "{instance_id}: nothing recoverable after the stop"
    );
    // Mirror rows carry no chain block, which is what `dump` reports for this marker.
    assert_eq!(
        opened.persistence.manifest_block_height(),
        0,
        "{instance_id}: a mirror-fed commit marker"
    );
    u64::try_from(rows_in_store(&opened.recovered_logical_store, &ofac_list())).expect("rows")
}

fn rows_in_store(store: &LogicalLeafStore, list_key: &[u8; 32]) -> usize {
    store.ppoi_imt(list_key).map_or(0, Imt::leaf_count)
}

/// The fresh box the gate is written for: booted, answering, and holding nothing. Every other
/// readiness gate passes it; the feed is the one that says why it must not serve.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_list_that_has_applied_nothing_is_not_ready_although_upstream_answers() {
    let data_root = tempfile::tempdir().expect("tempdir");
    let (endpoint, requests) = upstream_with_an_empty_list().await;
    let (opts, observer) = shipped_ppoi_options(data_root.path(), &[PATHS_BLOCK_0], &endpoint);
    let mut booting = boot_multi(opts).await;
    bootstrapped(&observer, &mut booting).await;
    match boot_verdict(&mut booting).await {
        Boot::Serving => {}
        Boot::Refused(refusal) => panic!("an answering upstream was refused: {refusal}"),
    }
    first_worker_page(&requests).await;

    let (code, body) = readiness_once(booting.addr, Duration::from_secs(20), |feed| {
        feed.upstream_rows == Some(0)
    })
    .await;
    assert_eq!(code, 503, "{body:?}");
    let feed = body.mirror_feeds.first().expect("one list");
    assert_eq!(
        (feed.state, feed.rows_held, feed.consecutive_failures),
        (MirrorFeedState::NeverFed, 0, 0),
        "upstream answered, and answered nothing"
    );
    assert!(
        body.stalled_consumer_instances.is_empty()
            && body.router_unrouted_targets.is_empty()
            && body.wal_replay_skipped_instances.is_empty()
            && body.layer2_divergent_instances.is_empty(),
        "no other gate sees a node that has applied nothing: {body:?}"
    );
    shut_down(booting).await;
}

/// Upstream failing a node that holds rows is not this node's outage: readiness stays up, and
/// says upstream is refusing and how.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_holding_rows_stays_ready_while_upstream_refuses_and_says_so() {
    let data_root = tempfile::tempdir().expect("tempdir");
    leave_one_row_on_disk(data_root.path(), &[PATHS_BLOCK_0]).await;
    let endpoint = upstream_answering_500().await;
    let (opts, observer) = shipped_ppoi_options(data_root.path(), &[PATHS_BLOCK_0], &endpoint);
    let mut booting = boot_multi(opts).await;
    bootstrapped(&observer, &mut booting).await;
    match boot_verdict(&mut booting).await {
        Boot::Serving => {}
        Boot::Refused(refusal) => panic!("rows held, yet boot was refused: {refusal}"),
    }

    let (code, body) = readiness_once(booting.addr, Duration::from_secs(20), |feed| {
        feed.consecutive_failures > 0
    })
    .await;
    assert_eq!(code, 200, "{body:?}");
    let feed = body.mirror_feeds.first().expect("one list");
    assert_eq!(
        (feed.state, feed.rows_held, feed.last_failure.as_deref()),
        (
            MirrorFeedState::UpstreamRefusing,
            1,
            Some("answered HTTP 500")
        )
    );
    assert!(
        !format!("{body:?}").contains(&endpoint),
        "an uncredentialed probe must not name the upstream endpoint: {body:?}"
    );
    shut_down(booting).await;
}

/// A block's rows are list-wide indices from its block's first, and the store alone says where
/// they end. A sidecar there -- torn, written ahead of rows that never reached the WAL, behind
/// them, or holding the block-local count -- cannot move the resume point.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_sidecar_a_block_instance_leaves_behind_moves_where_its_feed_resumes() {
    let data_root = tempfile::tempdir().expect("tempdir");
    let block_1 = raven_railgun_engine::orchestrator::LEAVES_PER_PPOI_BLOCK;
    leave_rows_on_disk(data_root.path(), &[PATHS_BLOCK_1], &[block_1, block_1 + 1]).await;
    let frontier = u64::from(block_1) + 2;

    let sidecars: [(&str, Vec<u8>); 4] = [
        ("torn", vec![0xAB; 3]),
        ("ahead", 5_000_000u64.to_le_bytes().to_vec()),
        ("behind", 0u64.to_le_bytes().to_vec()),
        ("block-local", 2u64.to_le_bytes().to_vec()),
    ];
    for (case, bytes) in sidecars {
        let (endpoint, requests) = upstream_with_an_empty_list().await;
        let (opts, observer) = shipped_ppoi_options(data_root.path(), &[PATHS_BLOCK_1], &endpoint);
        let data_dir = opts
            .instances
            .first()
            .expect("the block instance is declared")
            .data_dir
            .clone();
        for kind in [MirrorKind::Status, MirrorKind::Path] {
            std::fs::write(data_dir.join(kind.sidecar_filename()), &bytes)
                .expect("leave a sidecar behind");
        }
        let mut booting = boot_multi(opts).await;
        let view = bootstrapped(&observer, &mut booting)
            .await
            .expect("restart bootstraps");
        assert_eq!(rows_under(&view, PATHS_BLOCK_1), 2, "{case}: fixture");
        match boot_verdict(&mut booting).await {
            Boot::Serving => {}
            Boot::Refused(refusal) => panic!("{case}: rows held, yet refused: {refusal}"),
        }
        let page = first_worker_page(&requests).await;
        assert_eq!(
            page.pointer("/params/startIndex"),
            Some(&json!(frontier)),
            "{case}: the feed must resume at the list-wide row after the store's last: {page}"
        );
        shut_down(booting).await;
    }
}

/// Across a block boundary from one feed: block 0 fills to its 65,536 rows, the feed carries on
/// into block 1 at local row 0 with that block's own roots, and the whole-list status instance
/// stops at its one-tree wall. Every page is still asked for once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "cost: about 330,000 fsynced WAL appends, minutes; run by hand when the feed or router changes"]
async fn one_feed_fills_block_0_and_carries_on_into_block_1() {
    let block = u64::from(raven_railgun_engine::orchestrator::LEAVES_PER_PPOI_BLOCK);
    let rows = block + 1_010;
    let data_root = tempfile::tempdir().expect("tempdir");
    let (endpoint, requests) = upstream_holding_rooted(rows).await;
    let (opts, observer) = shipped_ppoi_options_with(
        data_root.path(),
        &[STATUS, PATHS_BLOCK_0, PATHS_BLOCK_1],
        &endpoint,
        "mirror_backfill_interval_secs = 0",
    );
    let mut booting = boot_multi(opts).await;
    let view = bootstrapped(&observer, &mut booting)
        .await
        .expect("boot bootstraps");
    match boot_verdict(&mut booting).await {
        Boot::Serving => {}
        Boot::Refused(refusal) => panic!("an answering upstream was refused: {refusal}"),
    }

    let (_, body) = readiness_once(booting.addr, Duration::from_mins(30), |feed| {
        feed.state == MirrorFeedState::CaughtUp
    })
    .await;
    let feed = body.mirror_feeds.first().expect("one list");
    assert_eq!((feed.rows_held, feed.upstream_rows), (rows, Some(rows)));
    let full = usize::try_from(block).expect("block rows");
    assert_eq!(
        (
            rows_under(&view, STATUS),
            rows_under(&view, PATHS_BLOCK_0),
            rows_under(&view, PATHS_BLOCK_1)
        ),
        (full, full, 1_010),
        "block 0 full, block 1 carrying the rest, the status instance at its wall"
    );
    let (paging, polling): (Vec<u64>, Vec<u64>) = start_indices(&requests)
        .into_iter()
        .partition(|start| *start < rows);
    let pages: Vec<u64> = (0..rows).step_by(501).collect();
    assert_eq!(paging, pages, "one request per page");
    assert!(polling.iter().all(|start| *start == rows), "{polling:?}");
    shut_down(booting).await;
}

/// Roots upstream publishes for row 0, for rows `from..` to the end of the first block's tree,
/// which holds every row below `from`, and for the first `beyond` rows of the next block.
fn roots_past(mut tree: Imt, from: u64, beyond: u64) -> std::collections::BTreeMap<u64, [u8; 32]> {
    let block = u64::from(LEAVES_PER_PPOI_BLOCK);
    let mut roots = std::collections::BTreeMap::new();
    let mut first = Imt::new().expect("imt");
    first.insert_leaves(0, &[leaf_at(0)]).expect("append");
    roots.insert(0, first.root());
    let mut next = Imt::new().expect("imt");
    for index in from..block + beyond {
        let (tree, local) = if index < block {
            (&mut tree, index)
        } else {
            (&mut next, index - block)
        };
        let local = usize::try_from(local).expect("local index");
        tree.insert_leaves(local, &[leaf_at(index)])
            .expect("append");
        roots.insert(index, tree.root());
    }
    roots
}

/// Boots `instance_ids` of the shipped example at the backfill setting 0 and waits until it
/// serves.
async fn serving(
    data_root: &Path,
    instance_ids: &[&str],
    endpoint: &str,
) -> (Booting, BootstrapView) {
    let (opts, observer) = shipped_ppoi_options_with(
        data_root,
        instance_ids,
        endpoint,
        "mirror_backfill_interval_secs = 0",
    );
    let mut booting = boot_multi(opts).await;
    let view = bootstrapped(&observer, &mut booting)
        .await
        .expect("boot bootstraps");
    match boot_verdict(&mut booting).await {
        Boot::Serving => {}
        Boot::Refused(refusal) => panic!("an answering upstream was refused: {refusal}"),
    }
    (booting, view)
}

/// `(startIndex, endIndex)` of each page a worker asked for.
fn page_bounds(requests: &Requests) -> Vec<(u64, u64)> {
    worker_pages(requests)
        .iter()
        .map(|page| {
            let bound = |name: &str| {
                page.pointer(&format!("/params/{name}"))
                    .and_then(Value::as_u64)
                    .expect("page bound")
            };
            (bound("startIndex"), bound("endIndex"))
        })
        .collect()
}

/// The stop through the production boot, on a node six rows short of the last row its blocks
/// declare: the shipped status instance and block 0, fed from an upstream holding rows past
/// block 0. The feed asks for the six and no further, and readiness names block 1. Declared and
/// restarted, block 1 is fed from its first row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_feed_stops_at_the_last_declared_row_names_the_next_block_and_feeds_it_once_declared() {
    let block = u64::from(LEAVES_PER_PPOI_BLOCK);
    let full = usize::try_from(block).expect("block rows");
    let held = block - 6;
    let beyond = 10;
    let data_root = tempfile::tempdir().expect("tempdir");
    let tree = leave_rows_committed(data_root.path(), &[STATUS, PATHS_BLOCK_0], held);
    let roots = roots_past(tree, held, beyond);
    let (endpoint, requests) =
        upstream_answering(move |index| roots.get(&index).copied(), Duration::ZERO).await;

    let (booting, view) = serving(data_root.path(), &[STATUS, PATHS_BLOCK_0], &endpoint).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let (code, body) = loop {
        let pages = page_bounds(&requests);
        assert!(
            pages.iter().all(|&(_, end)| end < block),
            "the feed asked upstream for rows no declared block holds: {pages:?}"
        );
        let (code, body) = readiness(booting.addr).await;
        let stopped = body
            .mirror_feeds
            .iter()
            .any(|feed| feed.state == MirrorFeedState::Stopped);
        let applied = rows_under(&view, STATUS) == full && rows_under(&view, PATHS_BLOCK_0) == full;
        if stopped && applied && !body.router_unrouted_targets.is_empty() {
            break (code, body);
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the feed never filled block 0, stopped and named a block: {code} {body:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(code, 503, "{body:?}");
    assert_eq!(
        body.router_unrouted_targets,
        [format!("list:{OFAC_LIST_HEX}:block:1")],
        "readiness must name the block the feed waits on"
    );
    let feed = body.mirror_feeds.first().expect("one list");
    assert_eq!(
        (feed.state, feed.rows_held, feed.next_index),
        (MirrorFeedState::Stopped, block, block)
    );
    assert_eq!(
        page_bounds(&requests),
        [(held, block - 1)],
        "one page, cut at the last row a declared block holds"
    );
    shut_down_within(booting, Duration::from_mins(2)).await;

    let asked = worker_pages(&requests).len();
    let (booting, view) = serving(
        data_root.path(),
        &[STATUS, PATHS_BLOCK_0, PATHS_BLOCK_1],
        &endpoint,
    )
    .await;
    let fed = usize::try_from(beyond).expect("rows");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while rows_under(&view, PATHS_BLOCK_1) < fed {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the declared block was never fed: {}",
            rows_under(&view, PATHS_BLOCK_1)
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        page_bounds(&requests).get(asked).map(|&(start, _)| start),
        Some(block),
        "the feed resumes at the declared block's first row"
    );
    assert_eq!(
        (
            rows_under(&view, PATHS_BLOCK_0),
            rows_under(&view, PATHS_BLOCK_1)
        ),
        (full, fed)
    );
    let (_, body) = readiness(booting.addr).await;
    assert!(
        !body
            .router_unrouted_targets
            .contains(&format!("list:{OFAC_LIST_HEX}:block:1")),
        "a delivery to the declared block clears its mark: {body:?}"
    );
    shut_down_within(booting, Duration::from_mins(2)).await;
}

/// Where a cold sync runs out of declared blocks, through the production boot: the shipped status
/// instance and block 0 fed at the backfill setting from an upstream holding rows past block 0.
/// The feed fills both instances, never asks for a row at or past 65,536, stops, and readiness
/// names block 1 until an operator declares it. The fill is also the one-block cold-sync
/// measurement, printed with each instance's commit count and the graceful stop that commits
/// the static block.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "cost: about 262,000 fsynced WAL appends, past nextest's 300 s kill; run by hand, as the test binary with --ignored, when the feed, router or commit policy changes"]
#[allow(clippy::print_stderr)]
async fn a_cold_sync_stops_where_the_declared_blocks_end_and_names_the_next() {
    let block = u64::from(raven_railgun_engine::orchestrator::LEAVES_PER_PPOI_BLOCK);
    let rows = block + 1_010;
    let data_root = tempfile::tempdir().expect("tempdir");
    let (endpoint, requests) = upstream_holding_rooted(rows).await;
    let (opts, observer) = shipped_ppoi_options_with(
        data_root.path(),
        &[STATUS, PATHS_BLOCK_0],
        &endpoint,
        "mirror_backfill_interval_secs = 0",
    );
    let mut booting = boot_multi(opts).await;
    let view = bootstrapped(&observer, &mut booting)
        .await
        .expect("boot bootstraps");
    match boot_verdict(&mut booting).await {
        Boot::Serving => {}
        Boot::Refused(refusal) => panic!("an answering upstream was refused: {refusal}"),
    }
    let began = std::time::Instant::now();
    let full = usize::try_from(block).expect("block rows");
    let furthest_asked = || {
        requests
            .lock()
            .iter()
            .filter_map(|request| request.pointer("/params/endIndex").and_then(Value::as_u64))
            .max()
            .unwrap_or(0)
    };
    let deadline = began + Duration::from_mins(30);
    let mut applied = None;
    loop {
        assert!(
            furthest_asked() < block,
            "the feed asked upstream for row {} with no block declared to hold it",
            furthest_asked()
        );
        if applied.is_none()
            && rows_under(&view, STATUS) == full
            && rows_under(&view, PATHS_BLOCK_0) == full
        {
            applied = Some(began.elapsed());
        }
        let (code, body) = readiness(booting.addr).await;
        let stopped = body
            .mirror_feeds
            .iter()
            .any(|feed| feed.state == MirrorFeedState::Stopped);
        if applied.is_some() && stopped {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "block 0 never filled, or the feed never stopped: {code} {body:?}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // The feed records its stop a moment before it marks the block.
    let (code, body) = readiness_once(booting.addr, Duration::from_secs(5), |_| {
        !raven_railgun_engine::orchestrator::router_unrouted_targets().is_empty()
    })
    .await;
    let commits: Vec<u64> = view
        .instances
        .iter()
        .map(|instance| instance.metrics.lock().commits_fired)
        .collect();
    eprintln!(
        "one-block cold sync at mirror_backfill_interval_secs = 0: {block} rows applied to \
         {STATUS} and {PATHS_BLOCK_0} in {:?}; commits {commits:?}; {} upstream requests",
        applied.expect("applied"),
        requests.lock().len()
    );

    assert_eq!(code, 503, "{body:?}");
    assert_eq!(
        body.router_unrouted_targets,
        [format!("list:{OFAC_LIST_HEX}:block:1")],
        "readiness must name the block the feed waits on"
    );
    let feed = body.mirror_feeds.first().expect("one list");
    assert_eq!(
        (feed.state, feed.rows_held),
        (MirrorFeedState::Stopped, block)
    );
    let pages: Vec<u64> = (0..block).step_by(501).collect();
    assert_eq!(start_indices(&requests), pages, "one request per page");
    assert_eq!(
        furthest_asked(),
        block - 1,
        "the last page is cut at the stop"
    );
    let stopping = std::time::Instant::now();
    shut_down(booting).await;
    eprintln!(
        "graceful stop, committing the static block: {:?}",
        stopping.elapsed()
    );
}

/// A cold sync of the whole shipped list: every PPOI instance the shipped example declares, fed at
/// the backfill setting from an upstream holding the list at its measured row count and answering
/// each page after the measured live round trip, so fetch and apply overlap as they would against
/// the real one. Prints the wall clock to caught up and the graceful stop that commits the static
/// blocks. Blocks 0-4 fill, block 5 holds the rest, and the status instance stops at its one tree.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "cost: about 2.9 million fsynced WAL appends in seven production cells, tens of minutes; run by hand, as the test binary with --ignored, when the feed, router, commit policy or list size changes"]
#[allow(clippy::print_stderr)]
async fn a_cold_sync_of_the_whole_shipped_list_at_the_live_round_trip() {
    // Upstream's row count at 2026-09-20T08:14:13Z, and its round trip for a full page.
    const ROWS: u64 = 358_344;
    const ROUND_TRIP: Duration = Duration::from_millis(1_050);
    let block = u64::from(raven_railgun_engine::orchestrator::LEAVES_PER_PPOI_BLOCK);
    let blocks: Vec<String> = (0..6)
        .map(|index| format!("ppoi-paths-ofac-{index}"))
        .collect();
    let ids: Vec<&str> = std::iter::once(STATUS)
        .chain(blocks.iter().map(String::as_str))
        .collect();
    let data_root = tempfile::tempdir().expect("tempdir");
    let (endpoint, requests) = upstream_holding_rooted_after(ROWS, ROUND_TRIP).await;
    let (opts, observer) = shipped_ppoi_options_with(
        data_root.path(),
        &ids,
        &endpoint,
        "mirror_backfill_interval_secs = 0",
    );
    let mut booting = boot_multi(opts).await;
    let view = bootstrapped(&observer, &mut booting)
        .await
        .expect("boot bootstraps");
    match boot_verdict(&mut booting).await {
        Boot::Serving => {}
        Boot::Refused(refusal) => panic!("an answering upstream was refused: {refusal}"),
    }
    let began = std::time::Instant::now();
    let (_, body) = readiness_once(booting.addr, Duration::from_hours(3), |feed| {
        feed.state == MirrorFeedState::CaughtUp
    })
    .await;
    let caught_up = began.elapsed();
    let feed = body.mirror_feeds.first().expect("one list");
    assert_eq!((feed.rows_held, feed.upstream_rows), (ROWS, Some(ROWS)));
    let full = usize::try_from(block).expect("block rows");
    let held: Vec<usize> = ids.iter().map(|id| rows_under(&view, id)).collect();
    let last = usize::try_from(ROWS - 5 * block).expect("rows");
    assert_eq!(held, [full, full, full, full, full, full, last]);
    let (paging, polling): (Vec<u64>, Vec<u64>) = start_indices(&requests)
        .into_iter()
        .partition(|start| *start < ROWS);
    let pages: Vec<u64> = (0..ROWS).step_by(501).collect();
    assert_eq!(paging, pages, "one request per page");
    assert!(polling.iter().all(|start| *start == ROWS), "{polling:?}");
    let commits: Vec<u64> = view
        .instances
        .iter()
        .map(|instance| instance.metrics.lock().commits_fired)
        .collect();
    eprintln!(
        "whole-list cold sync at mirror_backfill_interval_secs = 0 and a {ROUND_TRIP:?} round \
         trip: {ROWS} rows, {} pages, caught up in {caught_up:?}; commits {commits:?}",
        pages.len()
    );

    let stopping = std::time::Instant::now();
    let _ = booting.stop.send(());
    tokio::time::timeout(Duration::from_mins(20), booting.server)
        .await
        .expect("the graceful stop finished")
        .expect("server task panicked")
        .expect("graceful shutdown");
    eprintln!(
        "graceful stop, committing the static blocks: {:?}",
        stopping.elapsed()
    );
}
