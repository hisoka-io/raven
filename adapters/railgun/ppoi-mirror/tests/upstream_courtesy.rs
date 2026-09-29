//! What a mirror asks of the endpoint it reads, which is by default a third party's production
//! aggregator: one request in flight, request starts at least a second apart, a `User-Agent`
//! naming the software and its version, and a wait that lengthens while requests keep failing.
//! A local replay can lower the spacing, and nothing else changes it.
//!
//! Times are taken where the stub receives each request, a loopback hop behind where the client
//! starts it, so a lower bound allows [`HOP`] for that hop.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use raven_railgun_core::ListKey;
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_ppoi_mirror::test_signer::TestListSigner;
use raven_railgun_ppoi_mirror::{
    FeedStatus, MirrorConfig, MirrorError, UpstreamPpoiMirror, DEFAULT_REQUEST_SPACING, USER_AGENT,
};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const HOP: Duration = Duration::from_millis(100);

/// Longest a test waits for a request it expects.
const STALL: Duration = Duration::from_secs(30);

fn provider() -> TestListSigner {
    TestListSigner::new(0x2d)
}

fn list() -> ListKey {
    ListKey(provider().list_key())
}

#[derive(Debug, Clone)]
struct Received {
    at: Instant,
    user_agent: Option<String>,
    start: u64,
}

#[derive(Default)]
struct Stub {
    /// Highest index the list holds.
    last_index: u64,
    /// 1-based ordinals answered HTTP 500.
    failing: Vec<usize>,
    /// How long each answer is held.
    hold: Duration,
    log: parking_lot::Mutex<Vec<Received>>,
    in_flight: AtomicUsize,
    most_in_flight: AtomicUsize,
}

impl Stub {
    fn received(&self) -> Vec<Received> {
        self.log.lock().clone()
    }

    fn gaps(&self) -> Vec<Duration> {
        self.received()
            .windows(2)
            .map(|pair| pair[1].at.duration_since(pair[0].at))
            .collect()
    }

    async fn until_received(&self, count: usize) {
        let asked = Instant::now();
        while self.log.lock().len() < count {
            assert!(
                asked.elapsed() < STALL,
                "{} of {count} requests after {STALL:?}: {:?}",
                self.log.lock().len(),
                self.received()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

async fn serve(stub: Stub) -> (String, Arc<Stub>) {
    let stub = Arc::new(stub);
    let state = Arc::clone(&stub);
    let app = Router::new().route(
        "/",
        post(move |headers: HeaderMap, Json(request): Json<Value>| {
            let stub = Arc::clone(&state);
            async move {
                let at = Instant::now();
                let now = stub.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                stub.most_in_flight.fetch_max(now, Ordering::SeqCst);
                let bound = |name: &str| request["params"][name].as_u64().expect("page bound");
                let (start, end) = (bound("startIndex"), bound("endIndex"));
                let ordinal = {
                    let mut log = stub.log.lock();
                    log.push(Received {
                        at,
                        user_agent: headers
                            .get("user-agent")
                            .and_then(|value| value.to_str().ok())
                            .map(str::to_owned),
                        start,
                    });
                    log.len()
                };
                tokio::time::sleep(stub.hold).await;
                stub.in_flight.fetch_sub(1, Ordering::SeqCst);
                if stub.failing.contains(&ordinal) {
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
                let rows: Vec<Value> = (start..=end.min(stub.last_index))
                    .map(|index| {
                        provider()
                            .row(
                                index,
                                &format!("{:064x}", index + 1),
                                "Shield",
                                &format!("{:064x}", index + 2),
                            )
                            .expect("signs")
                    })
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
    (endpoint, stub)
}

fn config(endpoint: &str, poll_interval_secs: u64) -> MirrorConfig {
    MirrorConfig {
        endpoint: endpoint.to_owned(),
        poll_interval_secs,
        max_rows_per_fetch: 10,
        ..MirrorConfig::default()
    }
}

type Feed = tokio::task::JoinHandle<Result<(), MirrorError>>;

fn feed(mirror: &Arc<UpstreamPpoiMirror>, tx: mpsc::Sender<(WalEntryPayload, u64)>) -> Feed {
    tokio::spawn(Arc::clone(mirror).run_feed(
        list(),
        0,
        |cursor| cursor..u64::MAX,
        FeedStatus::default(),
        tx,
    ))
}

/// A boot's preflight, then a cold sync of three full pages and a short one, on the defaults:
/// every request starts at least a second after the one before, the full pages are not held to
/// the 30 s poll, and every request names the software and its version.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_the_defaults_requests_start_a_second_apart_and_name_raven_railgun_and_its_version() {
    assert_eq!(DEFAULT_REQUEST_SPACING, Duration::from_secs(1));
    let (endpoint, stub) = serve(Stub {
        last_index: 34,
        ..Stub::default()
    })
    .await;
    let mirror = Arc::new(UpstreamPpoiMirror::new(config(&endpoint, 30)).expect("mirror"));
    mirror
        .preflight(&list(), Duration::from_secs(10))
        .await
        .expect("preflight");
    let (tx, _rx) = mpsc::channel(256);
    let worker = feed(&mirror, tx);
    stub.until_received(5).await;
    worker.abort();

    let received = stub.received();
    assert_eq!(
        received.iter().map(|r| r.start).collect::<Vec<_>>(),
        [0, 0, 10, 20, 30]
    );
    for (at, gap) in stub.gaps().into_iter().enumerate() {
        assert!(
            gap + HOP >= DEFAULT_REQUEST_SPACING,
            "request {} started {gap:?} after the one before it",
            at + 2
        );
        assert!(gap < Duration::from_secs(5), "a full page waited {gap:?}");
    }
    let expected = format!("raven-railgun/{}", env!("CARGO_PKG_VERSION"));
    assert!(USER_AGENT.starts_with(&expected), "{USER_AGENT}");
    for request in &received {
        assert_eq!(request.user_agent.as_deref(), Some(USER_AGENT));
    }
}

/// Two feeds and their mirror's preflight share one queue: while one request is out, no other
/// starts, though each answer takes longer than the spacing, and each starts a second or more
/// after the one before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn feeds_sharing_a_mirror_keep_one_request_in_flight() {
    let (endpoint, stub) = serve(Stub {
        last_index: 4,
        hold: Duration::from_millis(1_500),
        ..Stub::default()
    })
    .await;
    let mirror = Arc::new(UpstreamPpoiMirror::new(config(&endpoint, 1)).expect("mirror"));
    let (tx, _rx) = mpsc::channel(256);
    let (other_tx, _other_rx) = mpsc::channel(256);
    let preflight = {
        let mirror = Arc::clone(&mirror);
        tokio::spawn(async move { mirror.preflight(&list(), Duration::from_secs(10)).await })
    };
    let workers = [feed(&mirror, tx), feed(&mirror, other_tx)];
    stub.until_received(5).await;
    for worker in &workers {
        worker.abort();
    }
    preflight.await.expect("task").expect("preflight");

    assert_eq!(stub.most_in_flight.load(Ordering::SeqCst), 1);
    for gap in stub.gaps() {
        assert!(gap + HOP >= DEFAULT_REQUEST_SPACING, "{:?}", stub.gaps());
    }
}

/// With a 1 s poll and a 4 s cap: two failures in a row wait the poll, the third 2 s, the
/// fourth 4 s and the fifth the cap. An answer resets the count, so the failure after it waits
/// the poll again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failures_in_a_row_lengthen_the_wait_up_to_the_cap_and_an_answer_resets_it() {
    let (endpoint, stub) = serve(Stub {
        last_index: 4,
        failing: vec![2, 3, 4, 5, 6, 8],
        ..Stub::default()
    })
    .await;
    let mirror = Arc::new(
        UpstreamPpoiMirror::new(MirrorConfig {
            failure_backoff_cap: Duration::from_secs(4),
            ..config(&endpoint, 1)
        })
        .expect("mirror"),
    );
    let (tx, _rx) = mpsc::channel(256);
    let worker = feed(&mirror, tx);
    stub.until_received(9).await;
    worker.abort();

    let expected = [1, 1, 1, 2, 4, 4, 1, 1].map(Duration::from_secs);
    let gaps = stub.gaps();
    for (at, (gap, wait)) in gaps.iter().zip(expected).enumerate() {
        assert!(
            *gap + HOP >= wait && *gap < wait + Duration::from_millis(900),
            "request {} came {gap:?} after the one before it, not {wait:?}: {gaps:?}",
            at + 2
        );
    }
}

/// The knob a local replay sets: a lowered spacing lets full pages follow at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lowered_spacing_lets_a_local_replay_page_at_once() {
    let (endpoint, stub) = serve(Stub {
        last_index: 34,
        ..Stub::default()
    })
    .await;
    let mirror = Arc::new(
        UpstreamPpoiMirror::new(config(&endpoint, 30))
            .expect("mirror")
            .with_backfill_interval(Duration::ZERO),
    );
    let (tx, _rx) = mpsc::channel(256);
    let worker = feed(&mirror, tx);
    stub.until_received(4).await;
    worker.abort();
    let gaps = stub.gaps();
    assert!(
        gaps.iter().all(|gap| *gap < Duration::from_millis(500)),
        "{gaps:?}"
    );
}
