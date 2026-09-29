//! How fast a mirror feed asks upstream for pages, and where it stops asking.
//!
//! A cold sync of a list several hundred pages long is six hours at a page per poll interval,
//! and a node that simply polled faster would keep that rate against a third party forever.
//! So a full page is followed at once, or at the backfill setting when one is given, and every
//! other page waits the poll.
//! Separately, a row nothing downstream can hold must stop the feed, not pass under an
//! advancing cursor.
//! And a feed waiting out a poll stops as soon as the engine hangs up.
//!
//! Every wait here is bounded by progress, not by the whole run: a run slowed by a loaded host
//! passes, and only a feed that stops moving for [`STALL`] fails.

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
use raven_railgun_ppoi_mirror::{FeedStatus, MirrorConfig, MirrorError, UpstreamPpoiMirror};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

fn provider() -> TestListSigner {
    TestListSigner::new(0x51)
}

fn list() -> ListKey {
    ListKey(provider().list_key())
}

/// First row of the seventh 65,536-row block: where a six-block forest runs out.
const SEVENTH_BLOCK: u64 = 6 * 65_536;

/// Longest a feed may go without visible progress before a wait fails. Below the 30 s poll, so a
/// full page followed at the poll still fails.
const STALL: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Asked {
    start: u64,
    end: u64,
}

struct Upstream {
    /// Highest index the list holds; a page past it comes back short or empty.
    last_index: u64,
    /// 1-based ordinals of the requests answered HTTP 500.
    failing: Vec<usize>,
    log: parking_lot::Mutex<Vec<(Instant, Asked)>>,
}

impl Upstream {
    fn holding_through(last_index: u64) -> Self {
        Self {
            last_index,
            failing: Vec::new(),
            log: parking_lot::Mutex::new(Vec::new()),
        }
    }

    fn failing(mut self, ordinals: &[usize]) -> Self {
        self.failing = ordinals.to_vec();
        self
    }

    fn asked(&self) -> Vec<Asked> {
        self.log.lock().iter().map(|(_, asked)| *asked).collect()
    }

    /// Gap between request `later` and the one before it, both 1-based.
    fn gap_before(&self, later: usize) -> Duration {
        let log = self.log.lock();
        let at = |ordinal: usize| log.get(ordinal - 1).expect("request was made").0;
        at(later).duration_since(at(later - 1))
    }
}

fn row(index: u64) -> Value {
    provider()
        .row(
            index,
            &format!("{index:064x}"),
            "Shield",
            &format!("{:064x}", index + 1),
        )
        .expect("signs")
}

async fn serve(upstream: Upstream) -> (String, Arc<Upstream>) {
    let upstream = Arc::new(upstream);
    let state = Arc::clone(&upstream);
    let app = Router::new().route(
        "/",
        post(move |Json(request): Json<Value>| {
            let upstream = Arc::clone(&state);
            async move {
                let param = |name: &str| {
                    request
                        .pointer(&format!("/params/{name}"))
                        .and_then(Value::as_u64)
                        .expect("page bound")
                };
                let asked = Asked {
                    start: param("startIndex"),
                    end: param("endIndex"),
                };
                let ordinal = {
                    let mut log = upstream.log.lock();
                    log.push((Instant::now(), asked));
                    log.len()
                };
                if upstream.failing.contains(&ordinal) {
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
                let rows: Vec<Value> = (asked.start..=asked.end.min(upstream.last_index))
                    .map(row)
                    .collect();
                Ok(Json(json!({ "jsonrpc": "2.0", "id": 1, "result": rows })))
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

fn mirror(
    endpoint: &str,
    poll_interval_secs: u64,
    max_rows_per_fetch: u64,
    backfill: Option<Duration>,
) -> Arc<UpstreamPpoiMirror> {
    let mirror = UpstreamPpoiMirror::new(MirrorConfig {
        endpoint: endpoint.to_owned(),
        poll_interval_secs,
        max_rows_per_fetch,
        ..MirrorConfig::default()
    })
    .expect("mirror");
    Arc::new(match backfill {
        Some(interval) => mirror.with_backfill_interval(interval),
        None => mirror,
    })
}

type Payloads = mpsc::Receiver<(WalEntryPayload, u64)>;

fn feed_all(mirror: Arc<UpstreamPpoiMirror>, tx: mpsc::Sender<(WalEntryPayload, u64)>) -> Feed {
    tokio::spawn(mirror.run_feed(
        list(),
        0,
        |cursor| cursor..u64::MAX,
        FeedStatus::default(),
        tx,
    ))
}

type Feed = tokio::task::JoinHandle<Result<(), MirrorError>>;

/// Leaf indices received until `last` arrives, or a panic once no leaf arrives for [`STALL`].
async fn leaves_through(rx: &mut Payloads, last: u32) -> Vec<u32> {
    let mut seen = Vec::new();
    loop {
        let received = tokio::time::timeout(STALL, rx.recv())
            .await
            .unwrap_or_else(|_| panic!("no leaf for {STALL:?} before {last}; got {seen:?}"));
        match received {
            Some((WalEntryPayload::PpoiListLeafAdded { list_index, .. }, _)) => {
                seen.push(list_index);
                if list_index == last {
                    return seen;
                }
            }
            Some(_) => {}
            None => panic!("the feed hung up before sending leaf {last}"),
        }
    }
}

/// Waits for `count` requests, failing once no new request arrives for `stall`.
async fn requests_made(upstream: &Upstream, count: usize, stall: Duration) {
    let mut seen = upstream.asked().len();
    let mut since = Instant::now();
    while seen < count {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let now = upstream.asked().len();
        if now > seen {
            (seen, since) = (now, Instant::now());
        }
        assert!(
            since.elapsed() < stall,
            "no request for {stall:?} with {seen} of {count} made: {:?}",
            upstream.asked()
        );
    }
}

/// Drives `feed` to completion, failing once its status stops changing for [`STALL`].
async fn settled<T>(status: &FeedStatus, feed: impl std::future::Future<Output = T>) -> T {
    tokio::pin!(feed);
    let mut last = status.snapshot();
    let mut since = Instant::now();
    loop {
        tokio::select! {
            outcome = &mut feed => return outcome,
            () = tokio::time::sleep(Duration::from_millis(50)) => {
                let now = status.snapshot();
                if now == last {
                    assert!(since.elapsed() < STALL, "the feed made no progress for {STALL:?}: {now:?}");
                } else {
                    (last, since) = (now, Instant::now());
                }
            }
        }
    }
}

fn page(start: u64, end: u64) -> Asked {
    Asked { start, end }
}

/// At a 30 s poll a page paced by the poll comes 30 s after the one before it, so four pages
/// each inside half the poll are only reachable when a full page is followed at once, which it
/// is with no backfill setting. The short fourth page then holds the fifth for the poll.
#[tokio::test]
async fn full_pages_follow_at_once_and_a_short_page_returns_to_the_poll() {
    let (endpoint, upstream) = serve(Upstream::holding_through(34)).await;
    let (tx, mut rx) = mpsc::channel(256);
    let worker = feed_all(mirror(&endpoint, 30, 10, None), tx);

    let leaves = leaves_through(&mut rx, 34).await;
    assert_eq!(leaves, (0..=34).collect::<Vec<u32>>());
    for later in 2..=4 {
        assert!(
            upstream.gap_before(later) < STALL,
            "full page {later} came {:?} after the one before it, at the poll",
            upstream.gap_before(later)
        );
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        upstream.asked(),
        [page(0, 9), page(10, 19), page(20, 29), page(30, 39)],
        "a caught-up worker must not keep asking at the backfill rate"
    );
    worker.abort();
}

/// An operator can still slow a cold sync: a backfill setting spaces full pages by that much.
#[tokio::test]
async fn a_backfill_setting_spaces_full_pages() {
    let (endpoint, upstream) = serve(Upstream::holding_through(34)).await;
    let (tx, _rx) = mpsc::channel(256);
    let worker = feed_all(mirror(&endpoint, 30, 10, Some(Duration::from_secs(2))), tx);

    requests_made(&upstream, 2, STALL).await;
    assert_eq!(upstream.asked(), [page(0, 9), page(10, 19)]);
    assert!(
        upstream.gap_before(2) >= Duration::from_millis(1_900),
        "a full page was followed after {:?}, inside the 2 s setting",
        upstream.gap_before(2)
    );
    worker.abort();
}

/// A failed page says nothing about how much upstream holds, so an upstream that is failing is
/// not retried at the backfill rate, even in the middle of a cold sync.
#[tokio::test]
async fn a_failed_page_waits_the_poll_even_mid_backfill() {
    let (endpoint, upstream) = serve(Upstream::holding_through(34).failing(&[2])).await;
    let (tx, _rx) = mpsc::channel(256);
    let worker = feed_all(mirror(&endpoint, 3, 10, None), tx);

    requests_made(&upstream, 4, STALL).await;
    assert_eq!(
        upstream.asked()[..4],
        [page(0, 9), page(10, 19), page(10, 19), page(20, 29)]
    );
    assert!(upstream.gap_before(2) < Duration::from_millis(1_500));
    assert!(
        upstream.gap_before(3) >= Duration::from_millis(2_500),
        "a failed page was retried after {:?}, inside the 3 s poll",
        upstream.gap_before(3)
    );
    assert!(upstream.gap_before(4) < Duration::from_millis(1_500));
    worker.abort();
}

/// The steady state: once the list is caught up, every page is empty and waits the poll.
#[tokio::test]
async fn an_empty_page_waits_the_poll() {
    let (endpoint, upstream) = serve(Upstream::holding_through(19)).await;
    let (tx, _rx) = mpsc::channel(256);
    let worker = feed_all(mirror(&endpoint, 3, 10, None), tx);

    requests_made(&upstream, 4, STALL).await;
    assert_eq!(
        upstream.asked()[..4],
        [page(0, 9), page(10, 19), page(20, 29), page(20, 29)]
    );
    assert!(upstream.gap_before(3) < Duration::from_millis(1_500));
    assert!(
        upstream.gap_before(4) >= Duration::from_millis(2_500),
        "an empty page was followed after {:?}, inside the 3 s poll",
        upstream.gap_before(4)
    );
    worker.abort();
}

/// The six-block forest ends at `SEVENTH_BLOCK`. The page that would straddle it is cut at the
/// last held row, nothing at or past it is asked for or sent, and the feed's progress names the
/// row itself, so the block declared next resumes the feed there and nothing is skipped.
#[tokio::test]
async fn the_feed_stops_in_front_of_the_first_unheld_row_and_resumes_there() {
    let (endpoint, upstream) = serve(Upstream::holding_through(u64::from(u32::MAX))).await;
    // Room for a whole page, so a feed that ran past the stop is caught by what it sent.
    let (tx, mut rx) = mpsc::channel(1_024);
    let status = FeedStatus::default();
    let stopped = settled(
        &status,
        mirror(&endpoint, 1, 501, None).run_feed(
            list(),
            SEVENTH_BLOCK - 2,
            |at| at..at.max(SEVENTH_BLOCK),
            status.clone(),
            tx,
        ),
    )
    .await;
    assert!(
        matches!(stopped, Err(MirrorError::Unheld { list_index }) if list_index == SEVENTH_BLOCK),
        "{stopped:?}"
    );

    let mut sent = Vec::new();
    while let Ok((payload, _)) = rx.try_recv() {
        sent.push(payload);
    }
    let held_through = u32::try_from(SEVENTH_BLOCK - 1).expect("u32 index");
    assert!(
        matches!(
            sent[..],
            [
                WalEntryPayload::PpoiListLeafAdded { list_index: a, .. },
                WalEntryPayload::PpoiListLeafAdded { list_index: b, .. },
            ] if a == held_through - 1 && b == held_through
        ),
        "one leaf per held row, and nothing else: {sent:?}"
    );
    assert_eq!(
        upstream.asked(),
        [page(SEVENTH_BLOCK - 2, SEVENTH_BLOCK - 1)],
        "the page must end at the last held row"
    );
    let resume_at = status.snapshot().next_index;
    assert_eq!(resume_at, SEVENTH_BLOCK);

    let (tx, mut rx) = mpsc::channel(64);
    let resumed = tokio::spawn(mirror(&endpoint, 1, 501, None).run_feed(
        list(),
        resume_at,
        |at| at..at.max(SEVENTH_BLOCK + 65_536),
        FeedStatus::default(),
        tx,
    ));
    let first = leaves_through(&mut rx, u32::try_from(SEVENTH_BLOCK).expect("u32 index")).await;
    assert_eq!(
        first,
        [u32::try_from(SEVENTH_BLOCK).expect("u32 index")],
        "the declared block must receive the row the feed stopped in front of, first"
    );
    resumed.abort();
}

#[tokio::test]
async fn a_feed_starting_on_its_stop_asks_upstream_for_nothing() {
    let (endpoint, upstream) = serve(Upstream::holding_through(u64::from(u32::MAX))).await;
    let (tx, mut rx) = mpsc::channel(8);
    let status = FeedStatus::default();
    let stopped = settled(
        &status,
        mirror(&endpoint, 1, 501, None).run_feed(
            list(),
            SEVENTH_BLOCK,
            |at| at..at.max(SEVENTH_BLOCK),
            status.clone(),
            tx,
        ),
    )
    .await;
    assert!(
        matches!(stopped, Err(MirrorError::Unheld { list_index }) if list_index == SEVENTH_BLOCK),
        "{stopped:?}"
    );
    assert!(upstream.asked().is_empty(), "{:?}", upstream.asked());
    assert!(rx.try_recv().is_err());
}

/// A feed that boots above a row no consumer holds stops on that row, not on its own cursor:
/// the row is what the operator has to declare a holder for.
#[tokio::test]
async fn a_feed_booted_past_an_unheld_row_names_that_row() {
    const GAP: u64 = 65_536;
    let (endpoint, upstream) = serve(Upstream::holding_through(u64::from(u32::MAX))).await;
    let (tx, mut rx) = mpsc::channel(8);
    let status = FeedStatus::default();
    let stopped = settled(
        &status,
        mirror(&endpoint, 1, 501, None).run_feed(
            list(),
            2 * GAP + 7,
            |_| GAP..GAP,
            status.clone(),
            tx,
        ),
    )
    .await;
    assert!(
        matches!(stopped, Err(MirrorError::Unheld { list_index }) if list_index == GAP),
        "{stopped:?}"
    );
    assert!(upstream.asked().is_empty(), "{:?}", upstream.asked());
    assert!(rx.try_recv().is_err());
}

/// A feed waiting out a 30 s poll notices the engine hanging up at once, not a poll later, so
/// a graceful shutdown is not held for the rest of the interval.
#[tokio::test]
async fn a_closed_channel_ends_the_poll_wait_at_once() {
    let (endpoint, upstream) = serve(Upstream::holding_through(4)).await;
    let (tx, mut rx) = mpsc::channel(64);
    let status = FeedStatus::default();
    let worker = tokio::spawn(mirror(&endpoint, 30, 10, None).run_feed(
        list(),
        0,
        |cursor| cursor..u64::MAX,
        status.clone(),
        tx,
    ));
    leaves_through(&mut rx, 4).await;
    requests_made(&upstream, 1, STALL).await;

    drop(rx);
    let outcome = tokio::time::timeout(STALL, worker)
        .await
        .expect("the worker must stop without waiting out the poll")
        .expect("worker task");
    assert!(outcome.is_ok(), "{outcome:?}");
    assert_eq!(
        upstream.asked(),
        [page(0, 9)],
        "no request after the hang-up"
    );
    assert!(status.snapshot().stopped.is_some());
}
