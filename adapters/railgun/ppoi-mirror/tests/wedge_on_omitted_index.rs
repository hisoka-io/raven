//! An upstream page that leaves out a row must not move the cursor past it.
//!
//! The decoder checks that every index is inside the requested range and strictly increasing,
//! not that the page is complete. Were the cursor set from the page's last index, the missing row
//! would never be asked for again, and every later row would fail the per-list contiguity rule
//! for the rest of the run. So the feed takes a page only up to its first missing row and asks
//! for that row again, on the production feed and on the sidecar-cursor worker alike.
//!
//! The consumer here is a local stand-in, since this crate cannot depend on the engine: it
//! restates the contiguity rule, refusing any leaf that is not the next expected one.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::items_after_statements,
    clippy::indexing_slicing,
    clippy::missing_panics_doc
)]

use axum::extract::Json;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use raven_railgun_core::ListKey;
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_ppoi_mirror::{
    FeedStatus, MirrorConfig, MirrorCursor, MirrorKind, PreflightFailure, UpstreamPpoiMirror,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

const PAGE: u64 = 5;
/// Rows `0..ROWS` exist upstream.
const ROWS: u64 = 12;
/// The index upstream leaves out of its pages until it recovers.
const OMITTED: u64 = 2;
/// Requests answered without [`OMITTED`], counted from the first.
const OMITTING_FOR: usize = 3;

#[derive(Default)]
struct MockState {
    starts: parking_lot::Mutex<Vec<u64>>,
}

async fn poi_events_handler(
    axum::extract::State(state): axum::extract::State<Arc<MockState>>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let body = request.get("params").ok_or(StatusCode::BAD_REQUEST)?;
    let bound = |name: &str| {
        body.get(name)
            .and_then(serde_json::Value::as_u64)
            .ok_or(StatusCode::BAD_REQUEST)
    };
    let (start, end) = (bound("startIndex")?, bound("endIndex")?);
    let ordinal = {
        let mut starts = state.starts.lock();
        starts.push(start);
        starts.len()
    };
    let events: Vec<serde_json::Value> = (start..=end.min(ROWS - 1))
        .filter(|index| ordinal > OMITTING_FOR || *index != OMITTED)
        .map(row)
        .collect();
    Ok(Json(serde_json::json!({
        "jsonrpc": "2.0",
        "id": request["id"],
        "result": events
    })))
}

fn row(index: u64) -> serde_json::Value {
    serde_json::json!({
        "signedPOIEvent": {
            "index": index,
            "blindedCommitment": format!("0x{:064x}", index + 1),
            "signature": "00".repeat(64),
            "type": "Shield",
        },
        "validatedMerkleroot": format!("{:064x}", index + 1),
    })
}

async fn start_mock() -> (String, Arc<MockState>, tokio::task::JoinHandle<()>) {
    let state = Arc::new(MockState::default());
    let app = Router::new()
        .route("/", post(poi_events_handler))
        .with_state(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 0");
    let addr: SocketAddr = listener.local_addr().expect("local_addr");
    let url = format!("http://{addr}");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (url, state, handle)
}

fn mirror(endpoint: String) -> Arc<UpstreamPpoiMirror> {
    Arc::new(
        UpstreamPpoiMirror::new(MirrorConfig {
            endpoint,
            poll_interval_secs: 1,
            max_rows_per_fetch: PAGE,
            ..MirrorConfig::default()
        })
        .expect("mirror builds")
        .with_backfill_interval(Duration::ZERO),
    )
}

/// Restates the engine's per-list contiguity rule: a leaf whose index is not the next expected
/// one is refused.
#[derive(Default)]
struct ContiguousConsumer {
    emitted: Vec<u32>,
    applied: Vec<u32>,
}

impl ContiguousConsumer {
    fn offer(&mut self, list_index: u32) {
        self.emitted.push(list_index);
        if usize::try_from(list_index).expect("index") == self.applied.len() {
            self.applied.push(list_index);
        }
    }

    /// Feeds leaves from `rx` until every upstream row is applied, or panics at the deadline.
    async fn drain_until_complete(&mut self, rx: &mut mpsc::Receiver<(WalEntryPayload, u64)>) {
        let complete = usize::try_from(ROWS).expect("rows");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while self.applied.len() < complete {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let received = tokio::time::timeout(remaining, rx.recv())
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "the list never completed: emitted {:?}, applied {:?}",
                        self.emitted, self.applied
                    )
                });
            match received {
                Some((WalEntryPayload::PpoiListLeafAdded { list_index, .. }, _)) => {
                    self.offer(list_index);
                }
                Some(_) => {}
                None => panic!("the feed hung up; applied {:?}", self.applied),
            }
        }
    }
}

fn assert_the_omitted_row_was_asked_for_again(starts: &[u64]) {
    assert_eq!(starts[0], 0);
    assert!(
        starts[1..=OMITTING_FOR]
            .iter()
            .all(|start| *start == OMITTED),
        "every page after one missing row {OMITTED} must start at it until upstream fills it: \
         {starts:?}"
    );
}

fn all_rows() -> Vec<u32> {
    (0..u32::try_from(ROWS).expect("rows")).collect()
}

/// The production feed: every row reaches the consumer once, in order, and none is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_feed_asks_again_for_a_row_a_page_left_out_and_the_list_completes() {
    let (url, mock, server) = start_mock().await;
    let (tx, mut rx) = mpsc::channel::<(WalEntryPayload, u64)>(128);
    let status = FeedStatus::default();
    let worker = tokio::spawn(mirror(url).run_feed(
        ListKey([0x42; 32]),
        0,
        |cursor| cursor..u64::MAX,
        status.clone(),
        tx,
    ));

    let mut consumer = ContiguousConsumer::default();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while mock.starts.lock().len() < 2 {
        assert!(tokio::time::Instant::now() < deadline, "no second page");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let refused = status.snapshot();
    assert_eq!(
        (
            refused.next_index,
            refused.last_failure,
            refused.upstream_rows
        ),
        (OMITTED, Some(PreflightFailure::MissingRow(OMITTED)), None),
        "the page is taken up to the missing row, and says nothing of upstream's size"
    );
    consumer.drain_until_complete(&mut rx).await;
    worker.abort();
    server.abort();

    assert_eq!(consumer.emitted, all_rows(), "no row is sent out of order");
    assert_eq!(consumer.applied, all_rows());
    assert_the_omitted_row_was_asked_for_again(&mock.starts.lock());
}

/// The sidecar-cursor worker: the persisted cursor never passes the missing row, so a restart
/// while upstream is still leaving it out resumes at it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sidecar_cursor_stops_at_a_row_a_page_left_out_and_the_list_completes() {
    let (url, mock, server) = start_mock().await;
    let scratch = tempfile::tempdir().expect("tempdir");
    let cursor = MirrorCursor::new(scratch.path().to_path_buf(), MirrorKind::Path, 0);
    let (tx, mut rx) = mpsc::channel::<(WalEntryPayload, u64)>(128);
    let worker = tokio::spawn(mirror(url).run_worker_with_cursor(
        ListKey([0x42; 32]),
        0,
        Some(cursor.clone()),
        tx,
    ));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while mock.starts.lock().len() < 2 {
        assert!(tokio::time::Instant::now() < deadline, "no second page");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        cursor.resolve_start(),
        OMITTED,
        "the persisted cursor must stop at the row upstream left out"
    );

    let mut consumer = ContiguousConsumer::default();
    consumer.drain_until_complete(&mut rx).await;
    // The sidecar is written after a page's rows are sent, so it can trail the last leaf.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while cursor.resolve_start() != ROWS {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the persisted cursor never reached the end of the list: {}",
            cursor.resolve_start()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    worker.abort();
    server.abort();

    assert_eq!(consumer.emitted, all_rows(), "no row is sent out of order");
    assert_eq!(consumer.applied, all_rows());
    assert_the_omitted_row_was_asked_for_again(&mock.starts.lock());
}
