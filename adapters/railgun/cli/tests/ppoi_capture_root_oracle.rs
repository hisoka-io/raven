//! Real-data root oracle: a recorded capture of an upstream PPOI list, served over loopback by
//! the replay crate and fed through the production boot's mirror feed into the shipped forest's
//! block instances. The engine holds every row to the `validatedMerkleroot` upstream published
//! with it and refuses a diverging row before the WAL, so a block stalls at the first bad root:
//! each block reaching the capture's row count, with no divergence and no unasserted row
//! counted, is every row applied with its root matched.
//!
//! By hand, with a capture folder in the replay crate's format (`events.bin`, `manifest.json`,
//! and `noncanonical.jsonl` when the list has one):
//! `PPOI_REPLAY_CAPTURE=<folder> cargo test --manifest-path adapters/railgun/Cargo.toml
//! -p raven-railgun-cli --profile ci-test --test ppoi_capture_root_oracle -- --ignored
//! --nocapture`. `cargo test`, because a whole list outlasts nextest's slow-timeout.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::too_many_lines,
    reason = "by-hand oracle; the receipt is the printed run"
)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use raven_railgun_cli::serve_production_multi::{
    load_options_from_toml, run_with_listener, BootstrapObserver, BootstrapView,
};
use raven_railgun_engine::orchestrator::{DataSourceFilter, LEAVES_PER_PPOI_BLOCK};
use raven_railgun_http::status::MirrorFeedState;
use raven_railgun_http::HealthReadyResponse;
use raven_railgun_ppoi_replay::{Capture, EventRow, Replay};

const CAPTURE_ENV: &str = "PPOI_REPLAY_CAPTURE";
const BEARER_TOKEN: &str = "ppoi-capture-root-oracle-token-pad";
const SHIPPED_ENDPOINT: &str = "mirror_endpoint = \"https://ppoi.fdi.network\"";
const DIVERGED: &str = "raven_railgun_ppoi_root_divergence_total";
const UNASSERTED: &str = "raven_railgun_ppoi_root_unasserted_total";
/// A block that applies nothing for this long is stalled, not slow: a cold page applies in
/// well under a second.
const STALL: Duration = Duration::from_mins(5);

/// Rows `block` of the list holds, and the root upstream published with its last one.
fn expected_blocks(rows: &[EventRow]) -> Vec<(usize, [u8; 32])> {
    rows.chunks(LEAVES_PER_PPOI_BLOCK as usize)
        .map(|block| (block.len(), block[block.len() - 1].validated_merkleroot))
        .collect()
}

/// The replay answers node status for its own list only; the mirror never asks for it.
fn node_status(network: &str, list_key_hex: &str) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"forNetwork\":{{\"{network}\":\
         {{\"listStatuses\":{{\"{list_key_hex}\":{{}}}}}}}},\"listKeys\":[\"{list_key_hex}\"]}}}}"
    )
}

/// The shipped PPOI example with its data dirs under `root`, loopback bind, the test token, and
/// the replay as the one upstream, paged back to back.
fn shipped_config(root: &Path, endpoint: &str) -> PathBuf {
    // Compiled in, so renaming the example breaks every build rather than only this ignored test.
    let body = include_str!("../../examples/mainnet-ppoi-7-instance.toml");
    assert_eq!(
        body.matches(SHIPPED_ENDPOINT).count(),
        1,
        "fixture: the example's [global] table no longer carries {SHIPPED_ENDPOINT}"
    );
    let body = body
        .replace(
            SHIPPED_ENDPOINT,
            &format!("mirror_endpoint = \"{endpoint}\"\nmirror_backfill_interval_secs = 0"),
        )
        .replace("/var/lib/raven-railgun/", &format!("{}/", root.display()))
        .replace("0.0.0.0:8080", "127.0.0.1:0")
        .replace("REPLACE_ME", BEARER_TOKEN);
    let path = root.join("config.toml");
    std::fs::write(&path, body).expect("write config");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("an inline token needs an owner-only config");
    }
    path
}

/// Block instances in block order, by id.
fn block_ids(view: &BootstrapView, list_key: &[u8; 32]) -> Vec<String> {
    let mut blocks: Vec<(u32, String)> = view
        .instances
        .iter()
        .filter_map(|instance| match instance.data_source {
            DataSourceFilter::PpoiListBlock {
                list_key: key,
                block,
            } if key == *list_key => Some((block, instance.instance_id.as_str().to_owned())),
            _ => None,
        })
        .collect();
    blocks.sort_unstable();
    for (position, (block, id)) in blocks.iter().enumerate() {
        assert_eq!(
            *block as usize, position,
            "the shipped blocks must be contiguous from 0; {id} is block {block}"
        );
    }
    blocks.into_iter().map(|(_, id)| id).collect()
}

/// `(rows, root)` each block instance holds now.
fn held(view: &BootstrapView, ids: &[String], list_key: &[u8; 32]) -> Vec<(usize, [u8; 32])> {
    ids.iter()
        .map(|id| {
            let instance = view
                .instances
                .iter()
                .find(|instance| instance.instance_id.as_str() == id)
                .expect("block instance booted");
            let store = instance.logical_store.lock();
            store
                .ppoi_imt(list_key)
                .map_or((0, [0; 32]), |imt| (imt.leaf_count(), imt.root()))
        })
        .collect()
}

async fn readiness(addr: SocketAddr) -> (u16, HealthReadyResponse) {
    let response = reqwest::Client::new()
        .get(format!("http://{addr}/v1/health/ready"))
        .send()
        .await
        .expect("readiness probe");
    let code = response.status().as_u16();
    (code, response.json().await.expect("readiness body"))
}

/// A counter's value. The engine describes the root counters while it bootstraps, before the
/// serving boot installs its recorder, so a counter nothing has incremented since is absent:
/// the feed starts after the recorder, so absent is zero here.
async fn counter(addr: SocketAddr, name: &str) -> u64 {
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
        .find(|line| line.split([' ', '{']).next() == Some(name))
        .map_or(0, |line| {
            line.rsplit(' ')
                .next()
                .and_then(|value| value.parse().ok())
                .unwrap_or_else(|| panic!("unreadable {name} line: {line}"))
        })
}

/// The capture at `folder`, served over loopback until the test ends.
struct Served {
    endpoint: String,
    list_key: [u8; 32],
    chain_id: u32,
    rows: usize,
    expected: Vec<(usize, [u8; 32])>,
}

async fn serve_capture(folder: &Path) -> Served {
    let (capture, scope) = Capture::load_dir(folder)
        .unwrap_or_else(|error| panic!("capture {}: {error}", folder.display()));
    let list_key = *capture.list_key();
    let rows = capture.rows().len();
    // The screen compares every root but the all-zero one, which it applies unasserted.
    if let Some(row) = capture
        .rows()
        .iter()
        .find(|row| row.validated_merkleroot == [0; 32])
    {
        panic!("capture row {} carries the all-zero root", row.index);
    }
    let expected = expected_blocks(capture.rows());
    let status = node_status(&scope.network, &hex::encode(list_key));
    let chain_id = scope.chain_id;
    let replay =
        Arc::new(Replay::new(capture, scope, status.as_bytes(), rows).expect("replay the capture"));
    let (listener, addr) =
        raven_railgun_ppoi_replay::bind("127.0.0.1:0".parse().expect("loopback"))
            .await
            .expect("bind the replay");
    tokio::spawn(raven_railgun_ppoi_replay::serve(listener, replay));
    Served {
        endpoint: format!("http://{addr}"),
        list_key,
        chain_id,
        rows,
        expected,
    }
}

/// Polls until every block holds `want`, failing on a stopped server or a stall.
async fn wait_for_blocks(
    addr: SocketAddr,
    server: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
    view: &BootstrapView,
    ids: &[String],
    list_key: &[u8; 32],
    want: &[usize],
) {
    let mut last_progress = (Instant::now(), held(view, ids, list_key));
    loop {
        let now = held(view, ids, list_key);
        let counts: Vec<usize> = now.iter().map(|(count, _)| *count).collect();
        if counts == want {
            return;
        }
        if server.is_finished() {
            let ended = server.await.expect("server task panicked");
            panic!("the server stopped at {counts:?} of {want:?}: {ended:?}");
        }
        let diverged = counter(addr, DIVERGED).await;
        assert_eq!(
            diverged, 0,
            "a row was refused for its root at {counts:?} of {want:?}"
        );
        if now != last_progress.1 {
            last_progress = (Instant::now(), now);
        } else if last_progress.0.elapsed() > STALL {
            let (code, body) = readiness(addr).await;
            panic!(
                "no block applied a row for {STALL:?} at {counts:?} of {want:?}; readiness \
                 {code} {body:?}"
            );
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "cost: a cold sync of the whole captured list into six production cells, tens of \
            minutes. Trigger: run by hand with PPOI_REPLAY_CAPTURE naming a capture folder when \
            the feed, the router, the root screen or the captured list changes"]
async fn every_captured_row_applies_through_the_mirror_feed_with_its_root_matched() {
    let folder = PathBuf::from(
        std::env::var(CAPTURE_ENV)
            .unwrap_or_else(|_| panic!("{CAPTURE_ENV} is unset; name a capture folder")),
    );
    let served = serve_capture(&folder).await;
    let list_key = served.list_key;
    let list_key_hex = hex::encode(list_key);

    let data_root = tempfile::tempdir().expect("tempdir");
    let config = shipped_config(data_root.path(), &served.endpoint);
    let mut opts = load_options_from_toml(&config).expect("load the shipped PPOI example");
    assert_eq!(
        opts.chain_id,
        u64::from(served.chain_id),
        "the capture's chain and the example's must agree"
    );
    // The whole-list status instance stops at one tree; the forest is the block instances.
    opts.instances.retain(|instance| {
        matches!(
            instance.data_source,
            DataSourceFilter::PpoiListBlock { list_key: key, .. } if key == list_key
        )
    });
    assert!(
        !opts.instances.is_empty(),
        "the shipped example declares no block of list {list_key_hex}, the capture's list"
    );
    let observer = BootstrapObserver::default();
    opts.bootstrap_observer = Some(Arc::clone(&observer));

    let listener = tokio::net::TcpListener::bind(opts.bind)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let mut server = tokio::spawn(run_with_listener(opts, listener, async move {
        let _ = stopped.await;
    }));
    let view = loop {
        if let Some(view) = observer.lock().clone() {
            break view;
        }
        if server.is_finished() {
            let ended = (&mut server).await.expect("boot task panicked");
            panic!("the boot ended before its instances came up: {ended:?}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    let ids = block_ids(&view, &list_key);
    let expected = &served.expected;
    assert!(
        ids.len() >= expected.len(),
        "the capture fills {} blocks, the shipped example declares {}",
        expected.len(),
        ids.len()
    );
    let want: Vec<usize> = (0..ids.len())
        .map(|block| expected.get(block).map_or(0, |(count, _)| *count))
        .collect();

    let began = Instant::now();
    wait_for_blocks(addr, &mut server, &view, &ids, &list_key, &want).await;
    let applied = began.elapsed();

    let now = held(&view, &ids, &list_key);
    for (block, ((count, root), (want_count, want_root))) in now.iter().zip(expected).enumerate() {
        assert_eq!(count, want_count, "block {block} row count");
        assert_eq!(
            hex::encode(root),
            hex::encode(want_root),
            "block {block} must end on the root upstream published with its last row"
        );
    }
    assert_eq!(counter(addr, DIVERGED).await, 0, "a row was refused");
    assert_eq!(
        counter(addr, UNASSERTED).await,
        0,
        "a row was applied with no root to compare"
    );
    let (code, body) = readiness(addr).await;
    let feed = body
        .mirror_feeds
        .iter()
        .find(|feed| feed.list_key == list_key_hex)
        .expect("the list's feed");
    let rows = u64::try_from(served.rows).expect("row count");
    assert_eq!(
        (feed.state, feed.rows_held, feed.upstream_rows),
        (MirrorFeedState::CaughtUp, rows, Some(rows)),
        "readiness {code}: {body:?}"
    );

    eprintln!(
        "capture root oracle: list {list_key_hex}, {rows} rows over {} blocks {want:?}, every \
         row applied with its validatedMerkleroot matched in {applied:?}",
        expected.len()
    );
    for (block, (count, root)) in now.iter().enumerate().take(expected.len()) {
        eprintln!("  block {block}: {count} rows, root {}", hex::encode(root));
    }

    let stopping = Instant::now();
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_mins(20), server)
        .await
        .expect("the graceful stop finished")
        .expect("server task panicked")
        .expect("graceful shutdown");
    eprintln!("graceful stop: {:?}", stopping.elapsed());
}
