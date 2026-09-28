//! A config describing only PPOI instances boots, serves, and starts no chain indexer; the chain
//! settings it leaves out are demanded only of a config that reads the chain. Its list routes
//! answer only once the mirror has reached upstream's tip: a cold sync part-way through holds a
//! gap-free prefix that is still not the list.
//!
//! Every endpoint here is an in-process listener on loopback.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

#[path = "support/bc_prefixes.rs"]
mod bc_prefixes;
#[path = "support/progress.rs"]
mod progress;
#[path = "support/signed_list.rs"]
mod signed_list;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::routing::post;
use axum::{Json, Router};
use bc_prefixes::{prefix_of, read_segment};
use progress::until_done_or_stalled;
use raven_railgun_cli::serve_production_multi::{
    chain_indexer_reason, load_options_from_toml, run_with_listener, BootstrapObserver,
    BootstrapView, MultiServeOptions,
};
use raven_railgun_engine::orchestrator::DataSourceFilter;
use raven_railgun_http::status::{MirrorFeedState, MirrorFeedView};
use raven_railgun_http::HealthReadyResponse;
use reqwest::StatusCode;
use serde_json::{json, Value};
use signed_list::{rekeyed, signed_row, LIST_HEX, SHIPPED_LIST_HEX};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;

const BEARER_TOKEN: &str = "ppoi-only-boot-token-padded-long";
const PATHS_BLOCK_0: &str = "ppoi-paths-ofac-0";
const PATHS_BLOCK_1: &str = "ppoi-paths-ofac-1";
const SHIPPED_ENDPOINT: &str = "mirror_endpoint = \"https://ppoi.fdi.network\"";
const CHAIN_KEYS: [&str; 3] = ["rpc_url", "railgun_proxy", "start_block"];

fn example() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/mainnet-ppoi.toml");
    std::fs::read_to_string(path).expect("read the PPOI-only example")
}

/// `body` with its data dirs under `root`, loopback bind, the test token, `endpoint` as the only
/// upstream a mirror worker may dial, and `global` appended to `[global]`. Written owner-only.
fn write_config(root: &Path, body: &str, endpoint: &str, global: &str) -> PathBuf {
    assert!(
        endpoint.starts_with("http://127.0.0.1:"),
        "the mirror endpoint must be an in-process listener: {endpoint}"
    );
    assert_eq!(
        body.matches(SHIPPED_ENDPOINT).count(),
        1,
        "fixture: the example's [global] table no longer carries {SHIPPED_ENDPOINT}"
    );
    let body = body
        .replace(
            SHIPPED_ENDPOINT,
            &format!("mirror_endpoint = \"{endpoint}\"\n{global}"),
        )
        .replace("/srv/raven/data/", &format!("{}/", root.display()))
        .replace("0.0.0.0:8080", "127.0.0.1:0")
        .replace("REPLACE_ME", BEARER_TOKEN);
    let path = root.join("config.toml");
    std::fs::write(&path, body).expect("write config");
    restrict_to_owner(&path);
    path
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

const CHAIN_SETTINGS: &str = "rpc_url = \"http://127.0.0.1:1\"\n\
    railgun_proxy = \"0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9\"\nstart_block = 0";

fn commit_tree_instance(root: &Path) -> String {
    format!(
        "\n[[instance]]\nid = \"commit-tree-0\"\nrole = \"static\"\nencoder = \"per-node\"\n\
         tree_number = 0\ndata_dir = \"{}/commit-tree-0\"\n\
         data_source = {{ kind = \"indexer\", filter = {{ tree_number = 0 }} }}\n",
        root.display()
    )
}

/// The example loaded whole and narrowed to `keep`, as an operator's file would be trimmed.
fn narrowed(config: &Path, keep: &[&str]) -> (MultiServeOptions, BootstrapObserver) {
    let mut opts = load_options_from_toml(config).expect("load the PPOI-only example");
    opts.instances
        .retain(|instance| keep.contains(&instance.instance_id.as_str()));
    assert_eq!(
        opts.instances.len(),
        keep.len(),
        "the example lost one of {keep:?}"
    );
    for instance in &mut opts.instances {
        instance.use_flock = false;
    }
    let observer = BootstrapObserver::default();
    opts.bootstrap_observer = Some(Arc::clone(&observer));
    (opts, observer)
}

/// Distinct in the bytes the index publishes too, or a renumbered index would still match.
fn leaf_at(index: u64) -> [u8; 32] {
    let mut leaf = [0u8; 32];
    let row = (index + 1).to_be_bytes();
    leaf[24..].copy_from_slice(&row);
    leaf[2..6].copy_from_slice(row.last_chunk::<4>().expect("four bytes"));
    leaf
}

/// Holds rows `0..rows` of the test list, signed, with the roots upstream publishes, and returns
/// those roots.
/// A page starting at or past `held_back_from` is not answered until `true` is sent, so a cold
/// sync can be stopped part-way with every page it has had so far come back full.
async fn upstream_holding(
    rows: u64,
    held_back_from: u64,
) -> (String, Vec<[u8; 32]>, watch::Sender<bool>) {
    let mut roots = Vec::new();
    let mut tree = raven_railgun_engine::imt::Imt::new().expect("imt");
    for index in 0..rows {
        let local = usize::try_from(index).expect("local index");
        tree.insert_leaves(local, &[leaf_at(index)])
            .expect("append");
        roots.push(tree.root());
    }
    let (release, released) = watch::channel(false);
    let served = Arc::new(roots.clone());
    let app = Router::new().route(
        "/",
        post(move |Json(request): Json<Value>| {
            let served = Arc::clone(&served);
            let mut released = released.clone();
            async move {
                let bound = |name: &str| {
                    request
                        .pointer(&format!("/params/{name}"))
                        .and_then(Value::as_u64)
                        .expect("page bound")
                };
                let (start, end) = (bound("startIndex"), bound("endIndex"));
                if start >= held_back_from {
                    let _ = released.wait_for(|open| *open).await;
                }
                let result: Vec<Value> = (start..=end)
                    .filter_map(|index| {
                        let root = served.get(usize::try_from(index).ok()?)?;
                        Some(signed_row(
                            index,
                            &hex::encode(leaf_at(index)),
                            &hex::encode(root),
                        ))
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
    (url, roots, release)
}

/// Counts every connection and closes it unanswered: a chain indexer that started would be
/// counted at its first request and refused there.
async fn chain_rpc_that_counts() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    let dialled = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&dialled);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    (url, dialled)
}

/// Answers every page empty and keeps the `(chainType, chainID)` of each request.
async fn empty_upstream_recording_chains(
) -> (String, Arc<parking_lot::Mutex<Vec<(String, String)>>>) {
    let asked = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let recorded = Arc::clone(&asked);
    let app = Router::new().route(
        "/",
        post(move |Json(request): Json<Value>| {
            let recorded = Arc::clone(&recorded);
            async move {
                let param = |name: &str| {
                    request
                        .pointer(&format!("/params/{name}"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                };
                recorded.lock().push((param("chainType"), param("chainID")));
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
    (url, asked)
}

struct Booting {
    addr: SocketAddr,
    server: JoinHandle<anyhow::Result<()>>,
    stop: oneshot::Sender<()>,
}

async fn boot(opts: MultiServeOptions) -> Booting {
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

/// Waits for `/v1/status`, and fails with the boot's own refusal if it ends first.
async fn serving(booting: &mut Booting, observer: &BootstrapObserver) -> BootstrapView {
    let client = reqwest::Client::new();
    // 300 s: the allowance the six-instance suite gives cold PIR bootstraps under CI contention.
    for _ in 0..1200u32 {
        if booting.server.is_finished() {
            let ended = (&mut booting.server).await.expect("boot task panicked");
            let refusal = ended.expect_err("the serve loop returned Ok with no shutdown signal");
            panic!("a PPOI-only config was refused at boot: {refusal:#}");
        }
        let answered = client
            .get(format!("http://{}/v1/status", booting.addr))
            .bearer_auth(BEARER_TOKEN)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success());
        if answered {
            return observer.lock().clone().expect("bootstrap view recorded");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("the PPOI-only config never answered /v1/status");
}

/// A stop commits every instance, re-encoding its whole cell, and nothing observable moves while
/// it does. A loaded full run has taken that past a minute, so the bound is the stall bound.
async fn shut_down(booting: Booting) {
    let _ = booting.stop.send(());
    tokio::time::timeout(progress::STALL, booting.server)
        .await
        .expect("shutdown stalled")
        .expect("server task panicked")
        .expect("graceful shutdown");
}

fn rows_under(view: &BootstrapView, instance_id: &str) -> usize {
    let list_key: [u8; 32] = hex::decode(LIST_HEX)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let instance = view
        .instances
        .iter()
        .find(|instance| instance.instance_id.as_str() == instance_id)
        .expect("instance booted");
    instance
        .logical_store
        .lock()
        .ppoi_imt(&list_key)
        .map_or(0, raven_railgun_engine::imt::Imt::leaf_count)
}

async fn feed(addr: SocketAddr) -> (u16, MirrorFeedView) {
    let response = reqwest::Client::new()
        .get(format!("http://{addr}/v1/health/ready"))
        .send()
        .await
        .expect("readiness probe");
    let code = response.status().as_u16();
    let body: HealthReadyResponse = response.json().await.expect("readiness body");
    let feed = body.mirror_feeds.into_iter().next().expect("one list");
    (code, feed)
}

/// How far the feed and each instance have got: what moves while a sync is under way. Failures
/// and the clock are left out, since a feed retrying a dead upstream changes both forever.
async fn sync_progress(
    addr: SocketAddr,
    view: &BootstrapView,
) -> (u64, u64, Option<u64>, Vec<usize>) {
    let (_, feed) = feed(addr).await;
    let rows = view
        .instances
        .iter()
        .map(|instance| rows_under(view, instance.instance_id.as_str()))
        .collect();
    (feed.rows_held, feed.next_index, feed.upstream_rows, rows)
}

/// Every list route, in order, asked about `bc`. No `Authorization`: the read path is public.
async fn list_routes(addr: SocketAddr, bc: &str) -> Vec<(&'static str, reqwest::Response)> {
    let client = reqwest::Client::new();
    let base = format!("http://{addr}/v1/poi");
    let get = |path: &str| client.get(format!("{base}/{LIST_HEX}/{path}")).send();
    vec![
        (
            "merkle-proofs",
            client
                .post(format!("{base}/merkle-proofs"))
                .json(&json!({ "listKey": LIST_HEX, "blindedCommitments": [bc] }))
                .send()
                .await
                .expect("merkle-proofs"),
        ),
        (
            "bc-prefixes",
            get("bc-prefixes").await.expect("bc-prefixes"),
        ),
    ]
}

async fn coverage_refusals(addr: SocketAddr, route: &str) -> u64 {
    let scrape = reqwest::Client::new()
        .get(format!("http://{addr}/metrics"))
        .bearer_auth(BEARER_TOKEN)
        .send()
        .await
        .expect("scrape")
        .text()
        .await
        .expect("metrics body");
    let label = format!("route=\"{route}\"");
    scrape
        .lines()
        .find(|line| {
            line.starts_with("raven_railgun_shim_coverage_refusals_total") && line.contains(&label)
        })
        .and_then(|line| line.rsplit(' ').next()?.parse().ok())
        .unwrap_or(0)
}

/// Each list route refuses, and through the coverage proof rather than for want of a store.
async fn assert_every_list_route_refuses(addr: SocketAddr, bc: &str) {
    for (route, response) in list_routes(addr, bc).await {
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{route} answered over part of the list"
        );
        assert_eq!(
            coverage_refusals(addr, route).await,
            1,
            "{route} must refuse through the coverage proof, not for want of a store"
        );
    }
}

/// Every route answers over the list upstream holds, one row per root in `roots`: its last row
/// with upstream's root, a row past it as absent, and every row in the index at its global
/// position. The list is shorter than a block, so one index segment is all of it.
async fn assert_list_routes_answer_the_whole_list(addr: SocketAddr, roots: &[[u8; 32]]) {
    let rows = u64::try_from(roots.len()).unwrap();
    let last = hex::encode(leaf_at(rows - 1));
    let mut routes = list_routes(addr, &last).await.into_iter();
    let (_, proof) = routes.next().expect("merkle-proofs");
    assert_eq!(
        proof.status(),
        StatusCode::OK,
        "merkle-proofs refused at the tip"
    );
    let proof: Value = proof.json().await.expect("merkle-proofs body");
    assert_eq!(
        proof[0]["root"],
        hex::encode(roots[roots.len() - 1]),
        "the proof's root is the one upstream published for that row"
    );
    let (_, index) = routes.next().expect("bc-prefixes");
    let index = read_segment(index).await;
    assert_eq!(
        index.status,
        StatusCode::OK,
        "bc-prefixes refused at the tip"
    );
    assert_eq!(
        (index.base, index.next, index.total),
        (Some(0), Some(rows), Some(rows)),
        "the whole list in one frontier segment"
    );
    let expected: Vec<_> = (0..rows).map(|row| prefix_of(&leaf_at(row))).collect();
    let misplaced = index
        .rows
        .iter()
        .zip(&expected)
        .position(|(got, want)| got != want);
    assert_eq!(
        (index.rows.len(), misplaced),
        (expected.len(), None),
        "every row sits at its global position in the index"
    );

    let past = hex::encode(leaf_at(rows + 7));
    let (_, response) = list_routes(addr, &past)
        .await
        .into_iter()
        .next()
        .expect("merkle-proofs");
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "a row past the end of a list upstream has ended is absent"
    );
}

#[test]
fn the_ppoi_only_example_names_no_chain_setting_and_loads() {
    let body = example();
    let settings: Vec<&str> = body
        .lines()
        .map(str::trim_start)
        .filter(|line| !line.starts_with('#'))
        .collect();
    for chain_only in CHAIN_KEYS
        .iter()
        .map(|key| format!("{key} ="))
        .chain(["[auto_spawn]".to_owned(), "tree_number =".to_owned()])
    {
        assert!(
            !settings.iter().any(|line| line.starts_with(&chain_only)),
            "the PPOI-only example sets {chain_only}"
        );
    }
    assert!(
        !body.contains("kind = \"indexer\""),
        "the PPOI-only example indexes the chain"
    );
    let root = tempfile::tempdir().expect("tempdir");
    let config = write_config(root.path(), &body, "http://127.0.0.1:1", "");
    let opts = load_options_from_toml(&config).expect("the PPOI-only example loads");

    assert_eq!(
        chain_indexer_reason(&opts.instances, opts.auto_spawn.as_ref()),
        None
    );
    let list_key: [u8; 32] = hex::decode(SHIPPED_LIST_HEX).unwrap().try_into().unwrap();
    let blocks: Vec<u32> = opts
        .instances
        .iter()
        .map(|instance| match instance.data_source {
            DataSourceFilter::PpoiListBlock {
                list_key: key,
                block,
            } if key == list_key => block,
            other => panic!(
                "{} is not a block of the OFAC list: {other:?}",
                instance.instance_id.as_str()
            ),
        })
        .collect();
    assert_eq!(
        blocks,
        (0..7).collect::<Vec<u32>>(),
        "seven blocks, the one the list reaches at row 393,216 included, and nothing else"
    );
}

/// A new example is covered without being named here.
#[test]
fn every_shipped_serve_config_loads_through_the_loader() {
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&examples)
        .expect("read the examples directory")
        .map(|entry| entry.expect("examples entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    paths.sort();
    let root = tempfile::tempdir().expect("tempdir");
    let config = root.path().join("config.toml");
    let mut loaded = Vec::new();
    for path in paths {
        let body = std::fs::read_to_string(&path).expect("read example");
        if !body.lines().any(|line| line.trim() == "[global]") {
            continue;
        }
        std::fs::write(&config, body.replace("REPLACE_ME", BEARER_TOKEN)).expect("write config");
        restrict_to_owner(&config);
        load_options_from_toml(&config)
            .unwrap_or_else(|e| panic!("{} does not load: {e:#}", path.display()));
        loaded.push(path.file_name().expect("file name").to_owned());
    }
    for shipped in ["mainnet-6-instance.toml", "mainnet-ppoi.toml"] {
        assert!(
            loaded.iter().any(|name| name.as_os_str() == shipped),
            "{shipped} was not loaded: {loaded:?}"
        );
    }
}

/// With nothing to read them, chain settings would be dropped; each is refused by name.
#[test]
fn a_ppoi_only_config_refuses_every_chain_setting_by_name() {
    let root = tempfile::tempdir().expect("tempdir");
    let in_global = [
        ("rpc_url = \"http://127.0.0.1:1\"", "[global].rpc_url"),
        (
            "railgun_proxy = \"0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9\"",
            "[global].railgun_proxy",
        ),
        ("start_block = 0", "[global].start_block"),
        ("ws_endpoint = \"ws://127.0.0.1:1\"", "[global].ws_endpoint"),
        (
            "reorg_window_path = \"/tmp/raven-unused/reorg.bin\"",
            "[global].reorg_window_path",
        ),
        ("tree_fill_threshold = 0.9", "[global].tree_fill_threshold"),
        ("max_instance_count = 8", "[global].max_instance_count"),
    ];
    let pooled = format!(
        "{}\n[rpc_pool]\nurls = [\"http://127.0.0.1:1\"]\n",
        example()
    );
    let cases = in_global
        .iter()
        .map(|&(line, key)| (example(), line, key))
        .chain([(pooled, "", "[rpc_pool]")]);
    let mut leaks = Vec::new();
    for (body, line, key) in cases {
        let config = write_config(root.path(), &body, "http://127.0.0.1:1", line);
        match load_options_from_toml(&config) {
            Ok(_) => leaks.push(format!("{key} was accepted")),
            Err(err) => {
                let refusal = format!("{err:#}");
                if !(refusal.contains(&format!("`{key}`"))
                    && refusal.contains("nothing reads them"))
                {
                    leaks.push(format!("{key} was refused without naming it: {refusal}"));
                }
            }
        }
    }
    assert!(leaks.is_empty(), "{}", leaks.join("\n"));
}

/// A config that reads the chain still has to name every chain setting, and the refusal says
/// which one and what reads it.
#[test]
fn a_config_that_reads_the_chain_is_refused_without_each_chain_setting() {
    let root = tempfile::tempdir().expect("tempdir");
    let with_tree = format!("{}{}", example(), commit_tree_instance(root.path()));
    let config = write_config(
        root.path(),
        &with_tree,
        "http://127.0.0.1:1",
        CHAIN_SETTINGS,
    );
    let opts = load_options_from_toml(&config).expect("every chain setting named");
    assert_eq!(opts.rpc_url, "http://127.0.0.1:1");

    for missing in CHAIN_KEYS {
        let rest: Vec<&str> = CHAIN_SETTINGS
            .lines()
            .filter(|line| !line.starts_with(missing))
            .collect();
        let config = write_config(
            root.path(),
            &with_tree,
            "http://127.0.0.1:1",
            &rest.join("\n"),
        );
        let refusal = format!("{:#}", load_options_from_toml(&config).expect_err(missing));
        for named in [format!("[global].{missing}"), "commit-tree-0".to_owned()] {
            assert!(
                refusal.contains(&named),
                "{missing}: refusal must name {named}: {refusal}"
            );
        }
    }

    let spawning = format!(
        "{}\n[auto_spawn]\nenabled = true\ndata_dir_template = \"{}/commit-tree-{{tree_number}}\"\n\
         encoder = \"per-node\"\n",
        example(),
        root.path().display()
    );
    let config = write_config(root.path(), &spawning, "http://127.0.0.1:1", "");
    let refusal = format!(
        "{:#}",
        load_options_from_toml(&config).expect_err("auto_spawn")
    );
    for named in ["[global].rpc_url", "[auto_spawn]"] {
        assert!(
            refusal.contains(named),
            "refusal must name {named}: {refusal}"
        );
    }

    let templated = format!(
        "{}\n[[instance_template]]\ntemplate_id = \"chain-trees\"\nencoder = \"per-node\"\n\
         data_dir_template = \"{}/tree-{{tree_number}}\"\n",
        example(),
        root.path().display()
    );
    let config = write_config(root.path(), &templated, "http://127.0.0.1:1", "");
    let refusal = format!(
        "{:#}",
        load_options_from_toml(&config).expect_err("instance_template")
    );
    for named in [
        "[global].rpc_url",
        "[[instance_template]]",
        "\"chain-trees\"",
    ] {
        assert!(
            refusal.contains(named),
            "refusal must name {named}: {refusal}"
        );
    }
    assert!(
        !refusal.contains("[auto_spawn]"),
        "the file has no [auto_spawn] table to blame: {refusal}"
    );
}

/// End to end: the example as shipped, no chain setting anywhere, fed cold from one upstream.
/// Had a chain indexer started it would have parsed the empty `railgun_proxy` first and refused
/// the boot, so serving at all is the proof none did.
///
/// Stopped part-way, with every page so far a full one, the stores hold a gap-free prefix and
/// upstream has not said where its list ends: each list route refuses through the coverage
/// proof. Once the feed reaches the tip every route answers, with global indices, over block 1
/// too, which the example declares ahead of the list and which holds nothing yet.
///
/// Every wait fails only once nothing moves: the apply is fsync-bound, so a loaded box slows a
/// correct run without stopping it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_ppoi_only_example_boots_and_answers_list_routes_only_at_upstreams_tip() {
    const ROWS: u64 = 1_010;
    const FIRST_PAGE: u64 = 501;
    let root = tempfile::tempdir().expect("tempdir");
    let (endpoint, roots, release) = upstream_holding(ROWS, FIRST_PAGE).await;
    let config = write_config(
        root.path(),
        &rekeyed(&example()),
        &endpoint,
        "mirror_backfill_interval_secs = 0",
    );
    let (opts, observer) = narrowed(&config, &[PATHS_BLOCK_0, PATHS_BLOCK_1]);
    assert!(opts.rpc_url.is_empty() && opts.railgun_proxy.is_empty());
    let mut booting = boot(opts).await;
    let view = serving(&mut booting, &observer).await;
    let addr = booting.addr;

    until_done_or_stalled("the first page applied", async || {
        let progress = sync_progress(addr, &view).await;
        let done = rows_under(&view, PATHS_BLOCK_0) == 501;
        (progress, done.then_some(()))
    })
    .await;
    let (_, part_way) = feed(addr).await;
    assert_eq!(
        (part_way.rows_held, part_way.upstream_rows),
        (501, None),
        "fixture: a cold sync part-way, its last page full"
    );
    assert_every_list_route_refuses(addr, &hex::encode(leaf_at(0))).await;

    release.send(true).expect("upstream listening");
    let caught_up = until_done_or_stalled("the feed at upstream's tip", async || {
        let progress = sync_progress(addr, &view).await;
        let (code, feed) = feed(addr).await;
        (
            progress,
            (feed.state == MirrorFeedState::CaughtUp).then_some((code, feed)),
        )
    })
    .await;
    assert_eq!(
        (
            caught_up.0,
            caught_up.1.rows_held,
            caught_up.1.upstream_rows
        ),
        (200, ROWS, Some(ROWS))
    );
    assert_eq!(
        rows_under(&view, PATHS_BLOCK_1),
        0,
        "fixture: block 1 is ahead of the list"
    );
    assert_list_routes_answer_the_whole_list(addr, &roots).await;

    let tree = reqwest::Client::new()
        .post(format!("http://{addr}/v1/commit-tree/0/merkle-proof"))
        .json(&json!({ "leafIndex": 0 }))
        .send()
        .await
        .expect("commit-tree merkle proof");
    assert_eq!(
        (
            tree.status(),
            coverage_refusals(addr, "commit-tree-merkle-proof").await
        ),
        (StatusCode::SERVICE_UNAVAILABLE, 1),
        "no instance declares a commit tree, so the proof refuses it"
    );
    shut_down(booting).await;
}

/// Options that name a chain RPC over instances that read nothing off the chain: the RPC is
/// never dialled, and the mirror asks upstream for the configured chain's list.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ppoi_only_boot_dials_no_chain_rpc_and_mirrors_the_configured_chain() {
    const CHAIN_ID: &str = "chain_id = 1\n";
    let root = tempfile::tempdir().expect("tempdir");
    let (rpc_url, dialled) = chain_rpc_that_counts().await;
    let (endpoint, chains_asked) = empty_upstream_recording_chains().await;
    let body = example();
    assert_eq!(
        body.matches(CHAIN_ID).count(),
        1,
        "fixture: the example no longer sets {CHAIN_ID}"
    );
    let config = write_config(
        root.path(),
        &body.replace(CHAIN_ID, "chain_id = 137\n"),
        &endpoint,
        "",
    );
    let (mut opts, observer) = narrowed(&config, &[PATHS_BLOCK_0]);
    assert_eq!(opts.chain_id, 137);
    assert!(opts.rpc_url.is_empty() && opts.railgun_proxy.is_empty());
    opts.rpc_url = rpc_url;
    opts.railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9".to_owned();
    let mut booting = boot(opts).await;
    serving(&mut booting, &observer).await;
    assert_eq!(
        dialled.load(Ordering::SeqCst),
        0,
        "the indexer starts before the listener serves, so a dial would have landed by now"
    );
    let asked = until_done_or_stalled("a page asked of upstream", async || {
        let asked = chains_asked.lock().clone();
        (asked.len(), (!asked.is_empty()).then_some(asked))
    })
    .await;
    assert!(
        asked
            .iter()
            .all(|(kind, id)| (kind.as_str(), id.as_str()) == ("0", "137")),
        "the mirror asked upstream about a chain other than [global].chain_id: {asked:?}"
    );
    shut_down(booting).await;
}

/// `--ws-endpoint` reaches the options after the loader has refused the TOML key, so the boot
/// refuses it too rather than start with a setting nothing reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ppoi_only_boot_refuses_a_websocket_endpoint_nothing_reads() {
    let root = tempfile::tempdir().expect("tempdir");
    let config = write_config(root.path(), &example(), "http://127.0.0.1:1", "");
    let (mut opts, _observer) = narrowed(&config, &[PATHS_BLOCK_0]);
    opts.skip_mirror_workers = true;
    opts.ws_endpoint = Some("ws://127.0.0.1:1".to_owned());
    let listener = tokio::net::TcpListener::bind(opts.bind)
        .await
        .expect("bind");
    let ended = tokio::time::timeout(
        Duration::from_secs(30),
        run_with_listener(opts, listener, std::future::pending::<()>()),
    )
    .await
    .expect("the boot served with a WebSocket endpoint nothing reads");
    let refusal = format!(
        "{:#}",
        ended.expect_err("the boot accepted a WebSocket endpoint nothing reads")
    );
    assert!(
        refusal.contains("`--ws-endpoint`") && refusal.contains("nothing reads it"),
        "{refusal}"
    );
}
