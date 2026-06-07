//! Batch dispatcher timeout race.
//!
//! Verifies that a slow worker surfaces 503, releases its semaphore permit,
//! and does not block subsequent batches.

#![allow(
    dead_code,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use raven_railgun_core::{InstanceId, Result as RailgunResult};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance, PirScheme};
use raven_railgun_http::{router, AppState, HttpConfig};
use serde::{Deserialize, Serialize};

const TOKEN: &str = "batch-timeout-test-token-1234567890";
const INSTANCE: &str = "slow-instance";
const RESPOND_TIMEOUT_SECS: u64 = 1;
const SLOW_QUERY_BLOCK_MS: u64 = 2_500;

static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug)]
struct SlowScheme;

#[derive(Debug, Default)]
struct SlowState {
    respond_calls: AtomicU32,
    slow_completed: AtomicU32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct SlowQuery {
    slow: bool,
    tag: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct SlowResponse {
    tag: u32,
}

impl PirScheme for SlowScheme {
    type ServerState = SlowState;
    type Query = SlowQuery;
    type Response = SlowResponse;

    fn respond(state: &Self::ServerState, query: &Self::Query) -> RailgunResult<Self::Response> {
        state.respond_calls.fetch_add(1, Ordering::SeqCst);
        if query.slow {
            // Blocking sleep; the dispatcher's timeout must fire while this is in progress.
            std::thread::sleep(Duration::from_millis(SLOW_QUERY_BLOCK_MS));
            state.slow_completed.fetch_add(1, Ordering::SeqCst);
        }
        Ok(SlowResponse { tag: query.tag })
    }
}

async fn spawn_test_server() -> (
    SocketAddr,
    Arc<PirInstance<SlowScheme>>,
    tokio::task::JoinHandle<()>,
) {
    let instance: Arc<PirInstance<SlowScheme>> = Arc::new(PirInstance::new(
        InstanceId::new(INSTANCE),
        InstanceRole::Static,
        SlowState::default(),
    ));
    let mut engine: Engine<SlowScheme> = Engine::new();
    engine
        .register_instance(Arc::clone(&instance))
        .expect("register instance");

    let mut cfg = HttpConfig::demo(TOKEN);
    cfg.respond_timeout_secs = RESPOND_TIMEOUT_SECS;
    cfg.max_concurrent_queries = 16;
    cfg.rate_limit_rps = 10_000;
    cfg.rate_limit_burst = 10_000;

    let state = {
        let _g = APPSTATE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        AppState::new(engine, cfg).expect("appstate")
    };
    let r = router::<SlowScheme>(state).expect("router");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            r.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    tokio::task::yield_now().await;
    (addr, instance, handle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn batch_with_one_slow_query_returns_503_within_timeout_window() {
    let (addr, _instance, h) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/v1/instance/{INSTANCE}/batch");

    // K=16 queries; index 14 is slow. Dispatcher must 503 at timeout, not wait for it.
    let mut queries: Vec<SlowQuery> = (0..16)
        .map(|i| SlowQuery {
            slow: false,
            tag: i,
        })
        .collect();
    if let Some(slot) = queries.get_mut(14) {
        slot.slow = true;
    }
    let body = raven_railgun_http::write_versioned(&queries).expect("serialize batch");

    let started = Instant::now();
    let resp = client
        .post(&url)
        .bearer_auth(TOKEN)
        .body(body)
        .send()
        .await
        .expect("send");
    let elapsed = started.elapsed();

    let status = resp.status();
    assert_eq!(
        status.as_u16(),
        503,
        "batch with a timeout-class worker MUST surface 503; \
         see BatchError::status() for the typed mapping. got {status}"
    );

    // Wall-clock must be near the configured timeout (1 s), not the slow worker's full 2.5 s.
    let timeout_budget = Duration::from_secs(RESPOND_TIMEOUT_SECS);
    let upper_bound = timeout_budget + Duration::from_millis(900);
    assert!(
        elapsed < upper_bound,
        "batch must surface timeout response within ~{RESPOND_TIMEOUT_SECS} s \
         of the configured timeout; took {elapsed:?} \
         (slow worker sleeps {SLOW_QUERY_BLOCK_MS} ms)"
    );

    h.abort();
    let _ = h.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn subsequent_batch_succeeds_after_a_timeout_race() {
    let (addr, instance, h) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/v1/instance/{INSTANCE}/batch");

    let mut queries_first: Vec<SlowQuery> = (0..16)
        .map(|i| SlowQuery {
            slow: false,
            tag: i,
        })
        .collect();
    if let Some(slot) = queries_first.get_mut(14) {
        slot.slow = true;
    }
    let body_first =
        raven_railgun_http::write_versioned(&queries_first).expect("serialize first batch");

    let resp1 = client
        .post(&url)
        .bearer_auth(TOKEN)
        .body(body_first)
        .send()
        .await
        .expect("send 1");
    assert_eq!(
        resp1.status().as_u16(),
        503,
        "first batch (with slow worker) must surface 503"
    );

    // Second batch: all fast. Must succeed even though the first batch's slow worker
    // is still mid-sleep; permits must have been released on the first batch's timeout.
    let queries_second: Vec<SlowQuery> = (0..16)
        .map(|i| SlowQuery {
            slow: false,
            tag: 1_000 + i,
        })
        .collect();
    let body_second =
        raven_railgun_http::write_versioned(&queries_second).expect("serialize second batch");

    let started = Instant::now();
    let resp2 = client
        .post(&url)
        .bearer_auth(TOKEN)
        .body(body_second)
        .send()
        .await
        .expect("send 2");
    let elapsed = started.elapsed();
    let status = resp2.status();

    assert_eq!(
        status.as_u16(),
        200,
        "second batch (all fast) must succeed; if not 200, the first batch's \
         slow worker likely held its semaphore permit past the timeout \
         (regression in worker timeout-arm permit release). got {status}"
    );

    assert!(
        elapsed < Duration::from_millis(800),
        "second all-fast batch should complete quickly; took {elapsed:?}. \
         If close to {SLOW_QUERY_BLOCK_MS} ms, the first batch's slow worker \
         is still holding its semaphore permit."
    );

    let calls = instance
        .current_state()
        .respond_calls
        .load(Ordering::SeqCst);
    assert!(
        calls >= 16,
        "respond must have been called at least 16 times for the \
         second batch; observed {calls}"
    );

    let body_bytes = resp2.bytes().await.expect("body bytes");
    let responses: Vec<SlowResponse> =
        raven_railgun_http::read_batch_response_versioned(&body_bytes)
            .expect("decode batch responses");
    assert_eq!(responses.len(), 16, "second batch must return 16 responses");
    for (i, r) in responses.iter().enumerate() {
        assert_eq!(
            r.tag,
            1_000 + i as u32,
            "response {i} tag must round-trip; got {}",
            r.tag
        );
    }

    h.abort();
    let _ = h.await;
}
