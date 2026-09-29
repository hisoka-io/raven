//! A row the consumer refuses must be asked for again while the feed runs.
//!
//! The feed sends a row and moves on; the consumer applies it later, or refuses it. Once one row
//! is refused, every later row fails the per-list contiguity rule, so a feed that never came back
//! for it would leave the list stopped until a restart. Upstream's own syncer avoids this by
//! reading its start from the store's event count before every page. Here the span plays that
//! part: it starts at the lowest row some consumer still lacks, and a start that stays below the
//! cursor for a poll interval sends the feed back for that row.
//!
//! While the feed asks for the row again it names it in the feed status, so readiness can say
//! which row holds the list back, and a consumer that never takes it leaves that name standing.
//!
//! The consumer is a local stand-in, since this crate cannot depend on the engine: it restates
//! the contiguity rule and refuses one row, once or every time it is offered.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use axum::extract::Json;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use raven_railgun_core::ListKey;
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_ppoi_mirror::test_signer::TestListSigner;
use raven_railgun_ppoi_mirror::{
    FeedProgress, FeedStatus, MirrorConfig, MirrorError, UpstreamPpoiMirror,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

const PAGE: u64 = 4;
/// Rows `0..ROWS` exist upstream.
const ROWS: u64 = 12;
/// The row the consumer refuses. Stands for any consumer-side refusal: a root divergence, a
/// non-canonical leaf, or a transport corruption.
const REFUSED: u32 = 5;
/// The run fails only when nothing is applied for this long, not when the whole run is slow.
const STALL: Duration = Duration::from_secs(30);

#[derive(Default)]
struct MockState {
    starts: parking_lot::Mutex<Vec<u64>>,
    /// When each request in `starts` arrived.
    arrived: parking_lot::Mutex<Vec<std::time::Instant>>,
}

async fn poi_events_handler(
    axum::extract::State(state): axum::extract::State<Arc<MockState>>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let bound = |name: &str| {
        request["params"][name]
            .as_u64()
            .ok_or(StatusCode::BAD_REQUEST)
    };
    let (start, end) = (bound("startIndex")?, bound("endIndex")?);
    state.starts.lock().push(start);
    state.arrived.lock().push(std::time::Instant::now());
    let events: Vec<serde_json::Value> = (start..=end.min(ROWS - 1)).map(row).collect();
    Ok(Json(serde_json::json!({
        "jsonrpc": "2.0",
        "id": request["id"],
        "result": events
    })))
}

fn provider() -> TestListSigner {
    TestListSigner::new(0x41)
}

fn row(index: u64) -> serde_json::Value {
    provider()
        .row(
            index,
            &format!("0x{:064x}", index + 1),
            "Shield",
            &format!("{:064x}", index + 1),
        )
        .expect("signs")
}

async fn start_mock() -> (String, Arc<MockState>) {
    let state = Arc::new(MockState::default());
    let app = Router::new()
        .route("/", post(poi_events_handler))
        .with_state(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 0");
    let url = format!("http://{}", listener.local_addr().expect("local_addr"));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (url, state)
}

/// Restates the engine's per-list contiguity rule, and refuses [`REFUSED`] the first `refusals`
/// times it is offered.
struct RefusingConsumer {
    refusals: usize,
    offered: Vec<u32>,
    applied: Vec<u32>,
    refused: usize,
}

impl RefusingConsumer {
    fn new(refusals: usize) -> Self {
        Self {
            refusals,
            offered: Vec::new(),
            applied: Vec::new(),
            refused: 0,
        }
    }

    fn offer(&mut self, list_index: u32) {
        self.offered.push(list_index);
        if list_index == REFUSED && self.refused < self.refusals {
            self.refused += 1;
            return;
        }
        if usize::try_from(list_index).expect("index") == self.applied.len() {
            self.applied.push(list_index);
        }
    }
}

type Rx = tokio::sync::mpsc::Receiver<(WalEntryPayload, u64)>;

/// A feed over the mock whose span starts at the lowest row the consumer lacks, as it stands at
/// each call.
fn feed(
    url: String,
) -> (
    tokio::task::JoinHandle<Result<(), MirrorError>>,
    Rx,
    Arc<AtomicU64>,
    FeedStatus,
) {
    let mirror = Arc::new(
        UpstreamPpoiMirror::new(MirrorConfig {
            endpoint: url,
            poll_interval_secs: 1,
            max_rows_per_fetch: PAGE,
            ..MirrorConfig::default()
        })
        .expect("mirror builds"),
    );
    let held = Arc::new(AtomicU64::new(0));
    let span = {
        let held = Arc::clone(&held);
        move |_cursor| held.load(Ordering::SeqCst)..u64::MAX
    };
    let (tx, rx) = tokio::sync::mpsc::channel::<(WalEntryPayload, u64)>(128);
    let status = FeedStatus::default();
    let worker =
        tokio::spawn(mirror.run_feed(ListKey(provider().list_key()), 0, span, status.clone(), tx));
    (worker, rx, held, status)
}

/// Offers the next row the feed sends to `consumer`, and publishes what it then holds. Returns
/// the row and the feed status as it stood before the consumer saw it.
async fn offer_next(
    rx: &mut Rx,
    consumer: &mut RefusingConsumer,
    held: &AtomicU64,
    status: &FeedStatus,
    mock: &MockState,
) -> Option<(u32, FeedProgress)> {
    let received = tokio::time::timeout(STALL, rx.recv())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "nothing arrived for {STALL:?}: offered {:?}, applied {:?}, asked {:?}",
                consumer.offered,
                consumer.applied,
                mock.starts.lock()
            )
        });
    match received {
        Some((WalEntryPayload::PpoiListLeafAdded { list_index, .. }, _)) => {
            let before = status.snapshot();
            consumer.offer(list_index);
            held.store(
                u64::try_from(consumer.applied.len()).expect("count"),
                Ordering::SeqCst,
            );
            Some((list_index, before))
        }
        Some(_) => None,
        None => panic!("the feed hung up; applied {:?}", consumer.applied),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_row_the_consumer_refuses_is_asked_for_again_and_the_list_completes() {
    let (url, mock) = start_mock().await;
    let (worker, mut rx, held, status) = feed(url);
    let mut consumer = RefusingConsumer::new(1);
    let mut named_while_asked_again = false;
    while consumer.applied.len() < usize::try_from(ROWS).expect("rows") {
        let seen_before = consumer.offered.contains(&REFUSED);
        // The feed names the row before it sends it again, and clears the name only once the
        // span has moved past it, which waits on this consumer.
        if let Some((REFUSED, before)) =
            offer_next(&mut rx, &mut consumer, &held, &status, &mock).await
        {
            if seen_before {
                assert_eq!(before.untaken_row, Some(u64::from(REFUSED)));
                named_while_asked_again = true;
            }
        }
    }
    assert!(
        named_while_asked_again,
        "fixture: the row came back: {:?}",
        consumer.offered
    );
    // The next request after the consumer took the row clears its name; allow a few.
    let answered_when_taken = status.snapshot().last_answer;
    let mut answers = 0;
    let mut last_answer = answered_when_taken;
    loop {
        let now = status.snapshot();
        if now.untaken_row.is_none() {
            break;
        }
        if now.last_answer != last_answer {
            (last_answer, answers) = (now.last_answer, answers + 1);
        }
        assert!(answers < 3, "the taken row is still named: {now:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        !worker.is_finished(),
        "the list completed on the feed that saw the refusal, with no restart"
    );
    worker.abort();

    assert_eq!(consumer.refused, 1, "fixture: the row was refused once");
    assert_eq!(consumer.applied, (0..12).collect::<Vec<u32>>());
    let starts = mock.starts.lock().clone();
    let first_past = starts
        .iter()
        .position(|start| *start > u64::from(REFUSED))
        .expect("the feed went past the refused row before coming back");
    assert!(
        starts[first_past..].contains(&u64::from(REFUSED)),
        "row {REFUSED} is asked for again after the feed had moved past it: {starts:?}"
    );
}

/// A row no consumer ever takes stays named, and the feed keeps coming back for it rather than
/// stopping or walking past it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_row_no_consumer_ever_takes_stays_named_and_is_asked_for_again_each_time() {
    let (url, mock) = start_mock().await;
    let (worker, mut rx, held, status) = feed(url);
    let mut consumer = RefusingConsumer::new(usize::MAX);
    while consumer.refused < 3 {
        offer_next(&mut rx, &mut consumer, &held, &status, &mock).await;
    }
    assert!(!worker.is_finished(), "the feed stopped on the refused row");
    worker.abort();
    assert_eq!(consumer.applied, (0..REFUSED).collect::<Vec<u32>>());
    assert_eq!(
        status.snapshot().untaken_row,
        Some(u64::from(REFUSED)),
        "the row holding the list back must be named"
    );
}

/// Coming back for a row no consumer takes costs upstream a page per poll. The pages past the row
/// would only be refused again, so they are not re-downloaded back to back each time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_row_asked_for_again_holds_the_feed_to_a_page_per_poll() {
    let (url, mock) = start_mock().await;
    let (worker, mut rx, held, status) = feed(url);
    let mut consumer = RefusingConsumer::new(usize::MAX);
    while consumer.refused < 3 {
        offer_next(&mut rx, &mut consumer, &held, &status, &mock).await;
    }
    worker.abort();
    let starts = mock.starts.lock().clone();
    let arrived = mock.arrived.lock().clone();
    let back = (1..starts.len())
        .find(|&at| {
            starts[at] == u64::from(REFUSED) && starts[..at].iter().any(|s| *s > u64::from(REFUSED))
        })
        .expect("the feed came back for the row");
    let gaps: Vec<Duration> = arrived[back..]
        .windows(2)
        .map(|pair| pair[1].duration_since(pair[0]))
        .collect();
    assert!(
        gaps.len() >= 2,
        "fixture: pages after the first return {starts:?}"
    );
    assert!(
        gaps.iter().all(|gap| *gap >= Duration::from_millis(900)),
        "pages came back to back while row {REFUSED} stood untaken: starts {starts:?}, gaps \
         {gaps:?}"
    );
}
