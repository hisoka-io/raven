//! How far a node trails upstream has to be readable in every state: while it pages a cold sync,
//! while upstream serves a row it refuses, and while its consumer lags behind the feed. Each
//! answer records the count it shows, taken or not, and a page that does not show where the list
//! ends is followed by one node status request a poll for the count upstream states.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use raven_railgun_core::ListKey;
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_ppoi_mirror::test_signer::TestListSigner;
use raven_railgun_ppoi_mirror::{
    ppoi_network_name, FeedProgress, FeedStatus, MirrorConfig, MirrorError, UpstreamPpoiMirror,
};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

const PAGE: u64 = 10;

fn provider() -> TestListSigner {
    TestListSigner::new(0x5a)
}

struct Upstream {
    /// Rows `0..rows` exist.
    rows: u64,
    /// A row served under another provider's signature.
    forged: Option<u64>,
    /// Node status requests are answered HTTP 500.
    status_fails: bool,
    methods: parking_lot::Mutex<Vec<String>>,
}

impl Upstream {
    fn asked(&self, method: &str) -> usize {
        self.methods.lock().iter().filter(|m| *m == method).count()
    }
}

async fn serve(rows: u64, forged: Option<u64>, status_fails: bool) -> (String, Arc<Upstream>) {
    let upstream = Arc::new(Upstream {
        rows,
        forged,
        status_fails,
        methods: parking_lot::Mutex::new(Vec::new()),
    });
    let state = Arc::clone(&upstream);
    let app = Router::new().route(
        "/",
        post(move |Json(request): Json<Value>| {
            let upstream = Arc::clone(&state);
            async move {
                let method = request["method"].as_str().unwrap_or_default().to_owned();
                upstream.methods.lock().push(method.clone());
                let result = if method == "ppoi_node_status" {
                    if upstream.status_fails {
                        return Err(StatusCode::INTERNAL_SERVER_ERROR);
                    }
                    // Split across two types: the count is their sum.
                    let lengths = json!({ "Shield": upstream.rows - 3, "Transact": 3 });
                    json!({ "forNetwork": { "Ethereum": { "listStatuses": {
                        provider().list_key_hex(): { "poiEventLengths": lengths }
                    } } } })
                } else {
                    let bound = |name: &str| request["params"][name].as_u64().expect("bound");
                    let (start, end) = (bound("startIndex"), bound("endIndex"));
                    let rows: Vec<Value> = (start..=end.min(upstream.rows - 1))
                        .map(|index| {
                            let signer = if upstream.forged == Some(index) {
                                TestListSigner::new(0x99)
                            } else {
                                provider()
                            };
                            let digits = format!("{:064x}", index + 1);
                            signer
                                .row(index, &digits, "Shield", &digits)
                                .expect("signs")
                        })
                        .collect();
                    Value::Array(rows)
                };
                Ok(Json(json!({ "jsonrpc": "2.0", "id": 1, "result": result })))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let endpoint = format!("http://{}", listener.local_addr().expect("local addr"));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (endpoint, upstream)
}

fn mirror(endpoint: &str, poll_interval_secs: u64) -> UpstreamPpoiMirror {
    UpstreamPpoiMirror::new(MirrorConfig {
        endpoint: endpoint.to_owned(),
        poll_interval_secs,
        max_rows_per_fetch: PAGE,
        ..MirrorConfig::default()
    })
    .expect("mirror")
    .with_backfill_interval(Duration::ZERO)
}

fn spawn_feed(
    mirror: UpstreamPpoiMirror,
    status: &FeedStatus,
    tx: mpsc::Sender<(WalEntryPayload, u64)>,
) -> tokio::task::JoinHandle<Result<(), MirrorError>> {
    tokio::spawn(Arc::new(mirror).run_feed(
        ListKey(provider().list_key()),
        0,
        |cursor| cursor..u64::MAX,
        status.clone(),
        tx,
    ))
}

async fn until(status: &FeedStatus, done: impl Fn(&FeedProgress) -> bool) -> FeedProgress {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let progress = status.snapshot();
        if done(&progress) {
            return progress;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "never reached: {progress:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Upstream holds 40 rows and serves row 5 under a signature the list key does not verify: the
/// feed stands at row 5, and the count the node status states shows it 35 rows behind.
#[tokio::test]
async fn a_refused_row_leaves_the_node_trailing_the_count_upstream_states() {
    let (endpoint, upstream) = serve(40, Some(5), false).await;
    let status = FeedStatus::default();
    let (tx, _rx) = mpsc::channel(256);
    let network = ppoi_network_name("0", 1).expect("mainnet has a network name");
    let worker = spawn_feed(mirror(&endpoint, 1).with_node_status(network), &status, tx);
    let refused = until(&status, |p| {
        p.consecutive_failures > 0 && p.upstream_rows_seen == Some(40)
    })
    .await;
    worker.abort();
    assert_eq!(
        (refused.next_index, refused.upstream_rows),
        (5, None),
        "{refused:?}"
    );
    assert!(upstream.asked("ppoi_node_status") >= 1);
}

/// With no node status to ask, a page that served a row at the end of its range still shows
/// upstream holds at least that many, though the feed took none past the refused row.
#[tokio::test]
async fn without_node_status_a_refused_page_shows_the_rows_it_served() {
    let (endpoint, upstream) = serve(40, Some(5), false).await;
    let status = FeedStatus::default();
    let (tx, _rx) = mpsc::channel(256);
    let worker = spawn_feed(mirror(&endpoint, 1), &status, tx);
    let refused = until(&status, |p| p.consecutive_failures > 0).await;
    worker.abort();
    assert_eq!(
        (
            refused.next_index,
            refused.upstream_rows,
            refused.upstream_rows_seen
        ),
        (5, None, Some(PAGE))
    );
    assert_eq!(upstream.asked("ppoi_node_status"), 0);
}

/// A caught-up node that refuses row 5 of 8: the short page shows where the list ends, so no
/// status is asked for and the count is exact.
#[tokio::test]
async fn a_short_page_shows_the_count_past_a_refused_row_without_a_status_request() {
    let (endpoint, upstream) = serve(8, Some(5), false).await;
    let status = FeedStatus::default();
    let (tx, _rx) = mpsc::channel(256);
    let worker = spawn_feed(
        mirror(&endpoint, 1).with_node_status("Ethereum"),
        &status,
        tx,
    );
    let refused = until(&status, |p| p.consecutive_failures >= 2).await;
    worker.abort();
    assert_eq!(
        (
            refused.next_index,
            refused.upstream_rows,
            refused.upstream_rows_seen
        ),
        (5, None, Some(8))
    );
    assert_eq!(upstream.asked("ppoi_node_status"), 0);
}

/// A cold sync whose consumer has not taken the first page: the feed waits on its channel at row
/// 10 while the stated count shows upstream holds 45. Drained, it catches up without asking the
/// status again inside the poll.
#[tokio::test]
async fn a_cold_sync_behind_a_lagging_consumer_shows_the_count_upstream_states() {
    let (endpoint, upstream) = serve(45, None, false).await;
    let status = FeedStatus::default();
    let (tx, mut rx) = mpsc::channel(10);
    let worker = spawn_feed(
        mirror(&endpoint, 30).with_node_status("Ethereum"),
        &status,
        tx,
    );
    let lagging = until(&status, |p| p.upstream_rows_seen == Some(45)).await;
    assert_eq!((lagging.next_index, lagging.upstream_rows), (10, None));
    let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let caught_up = until(&status, |p| p.upstream_rows == Some(45)).await;
    worker.abort();
    drain.abort();
    assert_eq!(caught_up.upstream_rows_seen, Some(45));
    assert_eq!(upstream.asked("ppoi_node_status"), 1);
}

/// A node status that fails is logged and skipped: it is not a failed page, so it moves no
/// failure count, and the count falls back to what the page served.
#[tokio::test]
async fn a_failed_status_request_is_not_a_feed_failure() {
    let (endpoint, upstream) = serve(45, None, true).await;
    let status = FeedStatus::default();
    let (tx, _rx) = mpsc::channel(10);
    let worker = spawn_feed(
        mirror(&endpoint, 30).with_node_status("Ethereum"),
        &status,
        tx,
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while upstream.asked("ppoi_node_status") == 0 {
        assert!(tokio::time::Instant::now() < deadline, "no status request");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    worker.abort();
    let progress = status.snapshot();
    assert_eq!(
        (
            progress.consecutive_failures,
            progress.last_failure,
            progress.upstream_rows_seen,
            progress.next_index
        ),
        (0, None, Some(PAGE), PAGE)
    );
}
