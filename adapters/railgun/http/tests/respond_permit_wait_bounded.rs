//! A query that cannot get a respond permit within `respond_permit_wait_ms` is answered 503,
//! on the single-query route and on `/batch`, instead of queueing for as long as the permits
//! stay busy. There is no per-peer cap: every caller shares the one bounded wait.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use raven_railgun_core::{InstanceId, Result as RailgunResult};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance, PirScheme};
use raven_railgun_http::{router, AppState, HttpConfig};
use serde::{Deserialize, Serialize};

const TOKEN: &str = "respond-permit-wait-token-123456";
const PERMIT_WAIT_MS: u64 = 400;
/// Headroom for a loaded box; an unbounded wait overshoots it by the whole probe deadline.
const EPSILON: Duration = Duration::from_millis(1_000);
/// The client gives up here, so the pre-fix behaviour fails the test instead of hanging it.
const PROBE_DEADLINE: Duration = Duration::from_secs(5);

static APPSTATE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug)]
struct GatedScheme;

/// Responds to a `hold` query only once the test drops its [`Sender`].
#[derive(Debug)]
struct GatedState {
    gate: Mutex<Receiver<()>>,
    holding: AtomicU32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct GatedQuery {
    hold: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct GatedResponse;

impl PirScheme for GatedScheme {
    type ServerState = GatedState;
    type Query = GatedQuery;
    type Response = GatedResponse;

    fn respond(state: &Self::ServerState, query: &Self::Query) -> RailgunResult<Self::Response> {
        if query.hold {
            state.holding.fetch_add(1, Ordering::SeqCst);
            let _ = state
                .gate
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .recv();
            state.holding.fetch_sub(1, Ordering::SeqCst);
        }
        Ok(GatedResponse)
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
    instance_id: &'static str,
    instance: Arc<PirInstance<GatedScheme>>,
    serve: tokio::task::JoinHandle<()>,
}

impl Fixture {
    fn url(&self, route: &str) -> String {
        format!(
            "http://{}/v1/instance/{}/{route}",
            self.addr, self.instance_id
        )
    }

    fn holding(&self) -> u32 {
        self.instance.current_state().holding.load(Ordering::SeqCst)
    }
}

async fn spawn_fixture(instance_id: &'static str) -> (Fixture, Sender<()>) {
    let (release, gate) = channel();
    let instance = Arc::new(PirInstance::new(
        InstanceId::new(instance_id),
        InstanceRole::Static,
        GatedState {
            gate: Mutex::new(gate),
            holding: AtomicU32::new(0),
        },
    ));
    let mut engine: Engine<GatedScheme> = Engine::new();
    engine
        .register_instance(Arc::clone(&instance))
        .expect("register instance");

    let mut cfg = HttpConfig::demo(TOKEN);
    cfg.max_concurrent_queries = 1;
    cfg.respond_timeout_secs = 30;
    cfg.respond_permit_wait_ms = PERMIT_WAIT_MS;
    cfg.rate_limit_rps = 10_000;
    cfg.rate_limit_burst = 10_000;

    let state = {
        let _guard = APPSTATE_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        AppState::new(engine, cfg).expect("app state")
    };
    let app = router::<GatedScheme>(state).expect("router");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let serve = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    (
        Fixture {
            addr,
            instance_id,
            instance,
            serve,
        },
        release,
    )
}

fn single(hold: bool) -> Vec<u8> {
    raven_railgun_http::write_versioned(&GatedQuery { hold }).expect("single body")
}

fn batch(len: usize) -> Vec<u8> {
    raven_railgun_http::write_versioned(&vec![GatedQuery { hold: false }; len]).expect("batch body")
}

/// Occupy the only respond permit with a respond that blocks until `release` drops.
async fn saturate(client: &reqwest::Client, fixture: &Fixture) -> tokio::task::JoinHandle<u16> {
    let url = fixture.url("query");
    let client = client.clone();
    let held = tokio::spawn(async move {
        client
            .post(url)
            .body(single(true))
            .send()
            .await
            .expect("held query")
            .status()
            .as_u16()
    });
    let started = Instant::now();
    while fixture.holding() == 0 {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the held respond never started"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    held
}

/// Status and wall time of one request that has to queue for the permit.
async fn probe(client: &reqwest::Client, url: String, body: Vec<u8>) -> (u16, Duration) {
    let started = Instant::now();
    let response = client
        .post(url)
        .body(body)
        .timeout(PROBE_DEADLINE)
        .send()
        .await
        .unwrap_or_else(|err| {
            panic!(
                "no answer within {PROBE_DEADLINE:?}: the query is still queued for the permit \
                 ({err})"
            )
        });
    (response.status().as_u16(), started.elapsed())
}

fn assert_refused_at_the_deadline(route: &str, status: u16, waited: Duration) {
    let wait = Duration::from_millis(PERMIT_WAIT_MS);
    assert_eq!(
        status, 503,
        "{route}: a query that cannot get a permit is 503"
    );
    assert!(
        waited >= wait,
        "{route}: refused after {waited:?}, before the {wait:?} wait ran out"
    );
    assert!(
        waited < wait + EPSILON,
        "{route}: refused after {waited:?}, well past the {wait:?} wait"
    );
}

async fn refusals(client: &reqwest::Client, fixture: &Fixture, kind: &str) -> u64 {
    let text = client
        .get(format!("http://{}/metrics", fixture.addr))
        .bearer_auth(TOKEN)
        .send()
        .await
        .expect("scrape")
        .text()
        .await
        .expect("scrape body");
    let instance = format!("instance=\"{}\"", fixture.instance_id);
    let kind = format!("kind=\"{kind}\"");
    text.lines()
        .filter(|line| line.starts_with("raven_railgun_respond_permit_wait_refused_total{"))
        .filter(|line| line.contains(&instance) && line.contains(&kind))
        .filter_map(|line| line.rsplit(' ').next()?.parse::<f64>().ok())
        .map(|value| value as u64)
        .sum()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_single_query_without_a_permit_is_refused_at_the_wait_deadline() {
    let (fixture, release) = spawn_fixture("permit-wait-single").await;
    let client = reqwest::Client::new();
    let held = saturate(&client, &fixture).await;

    let (status, waited) = probe(&client, fixture.url("query"), single(false)).await;
    assert_refused_at_the_deadline("query", status, waited);
    assert_eq!(fixture.holding(), 1, "the permit must still be held");
    assert_eq!(refusals(&client, &fixture, "single").await, 1);

    drop(release);
    assert_eq!(
        held.await.expect("held task"),
        200,
        "the held respond serves"
    );
    let (status, _) = probe(&client, fixture.url("query"), single(false)).await;
    assert_eq!(status, 200, "a free permit serves at once");

    fixture.serve.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_batch_without_a_permit_is_refused_at_the_wait_deadline() {
    let (fixture, release) = spawn_fixture("permit-wait-batch").await;
    let client = reqwest::Client::new();
    let held = saturate(&client, &fixture).await;

    let (status, waited) = probe(&client, fixture.url("batch"), batch(2)).await;
    assert_refused_at_the_deadline("batch", status, waited);
    assert_eq!(fixture.holding(), 1, "the permit must still be held");
    assert_eq!(refusals(&client, &fixture, "batch").await, 1);

    drop(release);
    assert_eq!(
        held.await.expect("held task"),
        200,
        "the held respond serves"
    );
    let (status, _) = probe(&client, fixture.url("batch"), batch(2)).await;
    assert_eq!(status, 200, "a free permit serves at once");

    fixture.serve.abort();
}
