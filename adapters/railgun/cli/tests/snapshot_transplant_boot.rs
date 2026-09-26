//! The transplant a fresh box receives, booted: a node fed from upstream is exported the moment
//! its feed catches up, imported into another root, and started there. It answers its list
//! routes over every row it was fed and asks upstream for none of them again.
//!
//! Every endpoint here is an in-process listener on loopback.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

#[path = "support/snapshot_fixture.rs"]
mod snapshot_fixture;

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::post;
use axum::{Json, Router};
use raven_railgun_cli::serve_production_multi::{
    load_options_from_toml, run_with_listener, BootstrapObserver, MultiServeOptions,
};
use raven_railgun_http::status::{MirrorFeedState, MirrorFeedView};
use raven_railgun_http::HealthReadyResponse;
use raven_railgun_persistence::{Manifest, StoreLayout};
use reqwest::StatusCode;
use serde_json::{json, Value};
use snapshot_fixture::{export, import, keys, read_tarball};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const BEARER_TOKEN: &str = "snapshot-transplant-boot-token-padded";
const OFAC_LIST_HEX: &str = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";
const STATUS: &str = "ppoi-status-ofac";
const PATHS_BLOCK_0: &str = "ppoi-paths-ofac-0";
/// A live whole-list instance and a static block: both kinds a PPOI-only node runs.
const INSTANCES: [&str; 2] = [STATUS, PATHS_BLOCK_0];
const SHIPPED_ENDPOINT: &str = "mirror_endpoint = \"https://ppoi.fdi.network\"";
/// More than one upstream page, so the source's sync is a real multi-page one.
const ROWS: u64 = 600;

fn leaf_at(index: u64) -> [u8; 32] {
    let mut leaf = [0u8; 32];
    leaf[24..].copy_from_slice(&(index + 1).to_be_bytes());
    leaf
}

type Pages = Arc<parking_lot::Mutex<Vec<(u64, u64)>>>;

/// Holds rows `0..rows` with the roots upstream publishes, and records every page asked for.
async fn upstream_holding(rows: u64) -> (String, Vec<[u8; 32]>, Pages) {
    let mut roots = Vec::new();
    let mut tree = raven_railgun_engine::imt::Imt::new().expect("imt");
    for index in 0..rows {
        let local = usize::try_from(index).expect("local index");
        tree.insert_leaves(local, &[leaf_at(index)])
            .expect("append");
        roots.push(tree.root());
    }
    let pages = Pages::default();
    let seen = Arc::clone(&pages);
    let served = Arc::new(roots.clone());
    let app = Router::new().route(
        "/",
        post(move |Json(request): Json<Value>| {
            let served = Arc::clone(&served);
            let seen = Arc::clone(&seen);
            async move {
                let bound = |name: &str| {
                    request
                        .pointer(&format!("/params/{name}"))
                        .and_then(Value::as_u64)
                        .expect("page bound")
                };
                let (start, end) = (bound("startIndex"), bound("endIndex"));
                seen.lock().push((start, end));
                let result: Vec<Value> = (start..=end)
                    .filter_map(|index| {
                        let root = served.get(usize::try_from(index).ok()?)?;
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
    (url, roots, pages)
}

/// The shipped example narrowed to [`INSTANCES`], its data dirs under `data_root`, and
/// `endpoint` the only upstream a mirror worker may dial. The config is written outside the root,
/// so the root holds instances only.
fn options(
    data_root: &Path,
    config: &Path,
    endpoint: &str,
) -> (MultiServeOptions, BootstrapObserver) {
    assert!(
        endpoint.starts_with("http://127.0.0.1:"),
        "mirror workers are enabled; the endpoint must be an in-process listener: {endpoint}"
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
            &format!("mirror_endpoint = \"{endpoint}\"\nmirror_backfill_interval_secs = 0"),
        )
        .replace(
            "/var/lib/raven-railgun/",
            &format!("{}/", data_root.display()),
        )
        .replace("REPLACE_ME", BEARER_TOKEN);
    std::fs::write(config, body).expect("write config");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(config, std::fs::Permissions::from_mode(0o600))
            .expect("the parser refuses a readable config carrying a token");
    }

    let mut opts = load_options_from_toml(config).expect("parse the shipped example");
    opts.instances
        .retain(|instance| INSTANCES.contains(&instance.instance_id.as_str()));
    assert_eq!(
        opts.instances.len(),
        INSTANCES.len(),
        "the example lost one of {INSTANCES:?}"
    );
    opts.bind = "127.0.0.1:0".parse().expect("addr");
    opts.skip_chain_workers = true;
    assert_eq!(opts.mirror_endpoint, endpoint);
    opts.entries = 256;
    for instance in &mut opts.instances {
        instance.use_flock = false;
    }
    let observer = BootstrapObserver::default();
    opts.bootstrap_observer = Some(Arc::clone(&observer));
    (opts, observer)
}

/// Every regular file under `dir`, as `/`-joined paths relative to it.
fn files_under(dir: &Path) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next).expect("read_dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let rel = path.strip_prefix(dir).expect("under dir");
                let parts: Vec<&str> = rel
                    .components()
                    .map(|c| c.as_os_str().to_str().expect("utf8"))
                    .collect();
                found.insert(parts.join("/"));
            }
        }
    }
    found
}

struct Booting {
    addr: SocketAddr,
    server: JoinHandle<anyhow::Result<()>>,
    stop: oneshot::Sender<()>,
}

/// Boots and waits for `/v1/status`, failing with the boot's own refusal if it ends first.
async fn boot_serving(opts: MultiServeOptions) -> Booting {
    let listener = tokio::net::TcpListener::bind(opts.bind)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let (stop, stopped) = oneshot::channel::<()>();
    let mut server = tokio::spawn(run_with_listener(opts, listener, async move {
        let _ = stopped.await;
    }));
    let client = reqwest::Client::new();
    // 300 s: the allowance the six-instance suite gives cold PIR bootstraps under CI contention.
    for _ in 0..1200u32 {
        if server.is_finished() {
            let ended = (&mut server).await.expect("boot task panicked");
            let refusal = ended.expect_err("the serve loop returned Ok with no shutdown signal");
            panic!("boot refused: {refusal:#}");
        }
        let answered = client
            .get(format!("http://{addr}/v1/status"))
            .bearer_auth(BEARER_TOKEN)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success());
        if answered {
            return Booting { addr, server, stop };
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("never answered /v1/status");
}

async fn shut_down(booting: Booting) {
    let _ = booting.stop.send(());
    tokio::time::timeout(Duration::from_secs(20), booting.server)
        .await
        .expect("shutdown timed out")
        .expect("server task panicked")
        .expect("graceful shutdown");
}

/// The list's feed once it reports caught up, with the readiness code it was read under.
async fn caught_up(addr: SocketAddr) -> (u16, MirrorFeedView) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        let response = reqwest::Client::new()
            .get(format!("http://{addr}/v1/health/ready"))
            .send()
            .await
            .expect("readiness probe");
        let code = response.status().as_u16();
        let body: HealthReadyResponse = response.json().await.expect("readiness body");
        let feed = body.mirror_feeds.into_iter().next().expect("one list");
        if feed.state == MirrorFeedState::CaughtUp {
            return (code, feed);
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the feed never caught up: {feed:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Every row at its global index, and the last row's proof under the root upstream published.
async fn assert_serves_every_row(addr: SocketAddr, roots: &[[u8; 32]]) {
    let client = reqwest::Client::new();
    let base = format!("http://{addr}/v1/poi");
    let map = client
        .get(format!("{base}/{OFAC_LIST_HEX}/bc-to-idx-map"))
        .send()
        .await
        .expect("bc-to-idx-map");
    assert_eq!(map.status(), StatusCode::OK, "bc-to-idx-map refused");
    let map: Value = map.json().await.expect("bc-to-idx-map body");
    let entries = map["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), roots.len());
    for (index, entry) in (0u64..).zip(entries) {
        assert_eq!(
            (entry["idx"].as_u64(), entry["bc"].as_str()),
            (Some(index), Some(hex::encode(leaf_at(index)).as_str())),
            "row {index}"
        );
    }

    let last = hex::encode(leaf_at(u64::try_from(roots.len()).expect("rows") - 1));
    let pois = client
        .post(format!("{base}/pois-per-list"))
        .json(&json!({
            "listKeys": [OFAC_LIST_HEX],
            "blindedCommitmentDatas": [{ "blindedCommitment": last }],
        }))
        .send()
        .await
        .expect("pois-per-list");
    assert_eq!(pois.status(), StatusCode::OK, "pois-per-list refused");
    let pois: Value = pois.json().await.expect("pois-per-list body");
    assert_eq!(pois[&last][OFAC_LIST_HEX], "Valid");

    let proofs = client
        .post(format!("{base}/merkle-proofs"))
        .json(&json!({ "listKey": OFAC_LIST_HEX, "blindedCommitments": [last] }))
        .send()
        .await
        .expect("merkle-proofs");
    assert_eq!(proofs.status(), StatusCode::OK, "merkle-proofs refused");
    let proofs: Value = proofs.json().await.expect("merkle-proofs body");
    assert_eq!(
        proofs[0]["root"],
        hex::encode(roots[roots.len() - 1]),
        "the last row's proof is under the root upstream published for it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transplanted_node_serves_the_rows_it_was_fed_without_fetching_them_again() {
    let scratch = tempfile::tempdir().expect("scratch");
    let source = scratch.path().join("source");
    let (endpoint, roots, _) = upstream_holding(ROWS).await;
    let (opts, _observer) = options(&source, &scratch.path().join("source.toml"), &endpoint);
    let booting = boot_serving(opts).await;
    let (code, feed) = caught_up(booting.addr).await;
    assert_eq!(
        (code, feed.rows_held, feed.upstream_rows),
        (200, ROWS, Some(ROWS))
    );

    // Taken while the node serves, the moment its feed caught up: a static block commits nothing
    // during a sync, so every row it was fed is in its live log.
    let live_log = source.join(PATHS_BLOCK_0).join("wal/current.log");
    assert!(
        std::fs::metadata(&live_log).expect("live log").len() > 0,
        "fixture: the sync left its rows in the live log"
    );
    let keys = keys(scratch.path(), 0x5c);
    let tarball = scratch.path().join("transplant.tar.zst");
    let receipt = export(&source, &tarball, &keys);
    // Everything the node keeps in an instance dir travels, bar its lock files, the packing cache
    // the destination rebuilds from the rows, and snapshots older than the one recovery reads.
    let manifest = read_tarball(&tarball).0;
    for id in INSTANCES {
        let layout = StoreLayout::inspect(source.join(id));
        let current = Manifest::load(&layout)
            .expect("instance manifest")
            .expect("a booted instance has one")
            .current_snapshot_id;
        let current_snapshot = format!(
            "snapshots/{}/",
            layout
                .snapshot_dir(current)
                .file_name()
                .and_then(|name| name.to_str())
                .expect("snapshot dir name")
        );
        let kept: BTreeSet<String> = files_under(layout.root())
            .into_iter()
            .filter(|rel| {
                !rel.starts_with("cache/")
                    && !rel.rsplit('/').next().unwrap_or(rel).starts_with('.')
                    && (!rel.starts_with("snapshots/") || rel.starts_with(&current_snapshot))
            })
            .collect();
        let carried: BTreeSet<String> = manifest
            .instances
            .iter()
            .find(|instance| instance.id == id)
            .expect("every instance exported")
            .files
            .iter()
            .map(|f| f.rel_path.clone())
            .collect();
        assert_eq!(
            carried, kept,
            "{id}: the export carries what the node keeps"
        );
    }
    shut_down(booting).await;
    assert_eq!(receipt.instances.len(), INSTANCES.len());
    for (id, recovered) in &receipt.instances {
        assert_eq!(recovered.lists[0].leaf_count, ROWS, "{id}");
    }

    let dest = scratch.path().join("dest");
    import(&tarball, &dest, &keys, &receipt.content_hash_hex).expect("import");

    let (endpoint, _, pages) = upstream_holding(ROWS).await;
    let (opts, _observer) = options(&dest, &scratch.path().join("dest.toml"), &endpoint);
    let booting = boot_serving(opts).await;
    let (code, feed) = caught_up(booting.addr).await;
    assert_eq!(
        (code, feed.rows_held, feed.upstream_rows),
        (200, ROWS, Some(ROWS))
    );
    assert_serves_every_row(booting.addr, &roots).await;
    let refetched: Vec<(u64, u64)> = pages
        .lock()
        .iter()
        .copied()
        .filter(|&(start, end)| start < ROWS && end > 0)
        .collect();
    assert!(
        refetched.is_empty(),
        "the destination fetched rows the transplant carried: {refetched:?}"
    );
    shut_down(booting).await;
}
