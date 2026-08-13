//! `spawn_blocking` work outlives the timeout that abandoned it. Releasing the
//! permit at the deadline lets `max_concurrent_queries` admit more CPU than it
//! is meant to bound, while the permit gauge still reads healthy.

#![allow(
    dead_code,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use raven_railgun_core::{InstanceId, Result as RailgunResult};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance, PirScheme};
use raven_railgun_http::{router, AppState, HttpConfig};
use serde::{Deserialize, Serialize};

const TOKEN: &str = "detached-respond-permit-token-1234";
const INSTANCE: &str = "detached-respond-instance";
const RESPOND_TIMEOUT_SECS: u64 = 1;
const SLOW_RESPOND_MS: u64 = 2_500;
const CONCURRENCY_CAP: usize = 1;

static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug)]
struct SlowScheme;

#[derive(Debug, Default)]
struct SlowState {
    in_flight: AtomicU32,
    peak_in_flight: AtomicU32,
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
        let now = state.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        state.peak_in_flight.fetch_max(now, Ordering::SeqCst);
        if query.slow {
            std::thread::sleep(Duration::from_millis(SLOW_RESPOND_MS));
        }
        state.in_flight.fetch_sub(1, Ordering::SeqCst);
        Ok(SlowResponse { tag: query.tag })
    }
    fn state_shape(_state: &Self::ServerState) -> raven_railgun_engine::StateShape {
        raven_railgun_engine::StateShape {
            entry_size_bytes: 1,
            rows_per_shard: u64::MAX,
        }
    }
}

struct Fixture {
    addr: SocketAddr,
    instance: Arc<PirInstance<SlowScheme>>,
    serve: tokio::task::JoinHandle<()>,
}

impl Fixture {
    fn url(&self, route: &str) -> String {
        format!("http://{}/v1/instance/{INSTANCE}/{route}", self.addr)
    }

    fn metrics_url(&self) -> String {
        format!("http://{}/metrics", self.addr)
    }

    fn peak_in_flight(&self) -> u32 {
        self.instance
            .current_state()
            .peak_in_flight
            .load(Ordering::SeqCst)
    }

    async fn shutdown(self) {
        self.serve.abort();
        let _ = self.serve.await;
    }
}

async fn spawn_fixture() -> Fixture {
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
    cfg.max_concurrent_queries = CONCURRENCY_CAP;
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
    let serve = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            r.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    tokio::task::yield_now().await;
    Fixture {
        addr,
        instance,
        serve,
    }
}

fn single_body(slow: bool, tag: u32) -> Vec<u8> {
    raven_railgun_http::write_versioned(&SlowQuery { slow, tag }).expect("serialize query")
}

fn batch_body(slow: bool, tag: u32) -> Vec<u8> {
    raven_railgun_http::write_versioned(&vec![SlowQuery { slow, tag }]).expect("serialize batch")
}

async fn permits_available(client: &reqwest::Client, fixture: &Fixture) -> u64 {
    let text = client
        .get(fixture.metrics_url())
        .bearer_auth(TOKEN)
        .send()
        .await
        .expect("scrape metrics")
        .text()
        .await
        .expect("metrics body");
    text.lines()
        .find_map(|line| {
            line.strip_prefix("raven_railgun_semaphore_permits_available ")
                .and_then(|v| v.trim().parse::<f64>().ok())
        })
        .map(|v| v.max(0.0).round() as u64)
        .expect("permits gauge present in scrape")
}

/// Reproduces the `/v1/instance/:id/query` timeout arm in `query_handler`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_timed_out_single_query_keeps_its_permit_until_the_work_ends() {
    let fixture = spawn_fixture().await;
    let client = reqwest::Client::new();
    let url = fixture.url("query");

    let timed_out = client
        .post(&url)
        .bearer_auth(TOKEN)
        .body(single_body(true, 1))
        .send()
        .await
        .expect("send slow query");
    assert_eq!(
        timed_out.status().as_u16(),
        503,
        "a respond past the timeout budget must surface 503"
    );

    let free = permits_available(&client, &fixture).await;
    assert_eq!(
        free, 0,
        "the abandoned respond is still burning a blocking thread, so the \
         permit gauge must NOT report the slot free; got {free}"
    );

    let started = Instant::now();
    let next = client
        .post(&url)
        .bearer_auth(TOKEN)
        .body(single_body(false, 2))
        .send()
        .await
        .expect("send follow-up query");
    let waited = started.elapsed();
    assert_eq!(
        next.status().as_u16(),
        200,
        "the follow-up must be served once the detached respond ends"
    );
    assert!(
        waited >= Duration::from_millis(900),
        "with a cap of {CONCURRENCY_CAP} the follow-up must wait out the \
         detached respond, not run beside it; waited {waited:?}"
    );

    let peak = fixture.peak_in_flight();
    assert_eq!(
        peak, 1,
        "max_concurrent_queries={CONCURRENCY_CAP} must bound responds actually \
         running, not permits handed out; peak was {peak}"
    );

    fixture.shutdown().await;
}

/// Reproduces the batch `worker` timeout arm reached through `batch_handler`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_timed_out_batch_slot_keeps_its_permit_until_the_work_ends() {
    let fixture = spawn_fixture().await;
    let client = reqwest::Client::new();
    let url = fixture.url("batch");

    let timed_out = client
        .post(&url)
        .bearer_auth(TOKEN)
        .body(batch_body(true, 1))
        .send()
        .await
        .expect("send slow batch");
    assert_eq!(
        timed_out.status().as_u16(),
        503,
        "a batch slot past the timeout budget must surface 503"
    );

    let free = permits_available(&client, &fixture).await;
    assert_eq!(
        free, 0,
        "the abandoned batch worker is still burning a blocking thread, so the \
         permit gauge must NOT report the slot free; got {free}"
    );

    let started = Instant::now();
    let next = client
        .post(&url)
        .bearer_auth(TOKEN)
        .body(batch_body(false, 2))
        .send()
        .await
        .expect("send follow-up batch");
    let waited = started.elapsed();
    assert_eq!(
        next.status().as_u16(),
        200,
        "the follow-up batch must be served once the detached worker ends"
    );
    assert!(
        waited >= Duration::from_millis(900),
        "with a cap of {CONCURRENCY_CAP} the follow-up batch must wait out the \
         detached worker, not run beside it; waited {waited:?}"
    );

    let peak = fixture.peak_in_flight();
    assert_eq!(
        peak, 1,
        "max_concurrent_queries={CONCURRENCY_CAP} must bound responds actually \
         running, not permits handed out; peak was {peak}"
    );

    fixture.shutdown().await;
}
