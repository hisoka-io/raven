//! `POST /v1/instance/{id}/batch` admits only fixed-size-ladder lengths: serving
//! an arbitrary `|batch|` would publish the caller's exact query count.

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

use raven_railgun_core::batch_ladder::BATCH_SIZE_LADDER;
use raven_railgun_core::{InstanceId, Result as RailgunResult};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance, PirScheme};
use raven_railgun_http::{router, AppState, HttpConfig};
use serde::{Deserialize, Serialize};

const TOKEN: &str = "batch-ladder-test-token-1234567890";
const INSTANCE: &str = "ladder-instance";

static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug)]
struct EchoScheme;

#[derive(Debug, Default)]
struct EchoState {
    respond_calls: AtomicU32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct EchoQuery {
    tag: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct EchoResponse {
    tag: u32,
}

impl PirScheme for EchoScheme {
    type ServerState = EchoState;
    type Query = EchoQuery;
    type Response = EchoResponse;

    fn respond(state: &Self::ServerState, query: &Self::Query) -> RailgunResult<Self::Response> {
        state.respond_calls.fetch_add(1, Ordering::SeqCst);
        Ok(EchoResponse { tag: query.tag })
    }
}

async fn spawn_test_server() -> (
    SocketAddr,
    Arc<PirInstance<EchoScheme>>,
    tokio::task::JoinHandle<()>,
) {
    let instance: Arc<PirInstance<EchoScheme>> = Arc::new(PirInstance::new(
        InstanceId::new(INSTANCE),
        InstanceRole::Static,
        EchoState::default(),
    ));
    let mut engine: Engine<EchoScheme> = Engine::new();
    engine
        .register_instance(Arc::clone(&instance))
        .expect("register instance");

    let mut cfg = HttpConfig::demo(TOKEN);
    cfg.max_concurrent_queries = 8;
    cfg.rate_limit_rps = 10_000;
    cfg.rate_limit_burst = 10_000;

    let state = {
        let _g = APPSTATE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        AppState::new(engine, cfg).expect("appstate")
    };
    let r = router::<EchoScheme>(state).expect("router");

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

fn batch_of(len: usize) -> Vec<u8> {
    let queries: Vec<EchoQuery> = (0..len).map(|i| EchoQuery { tag: i as u32 }).collect();
    raven_railgun_http::write_versioned(&queries).expect("serialize batch")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn off_ladder_lengths_are_refused_and_never_dispatched() {
    let (addr, instance, h) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/v1/instance/{INSTANCE}/batch");

    for len in [3usize, 5, 6, 7, 9, 15, 17, 31, 33, 64] {
        let resp = client
            .post(&url)
            .bearer_auth(TOKEN)
            .body(batch_of(len))
            .send()
            .await
            .expect("send");
        assert_eq!(
            resp.status().as_u16(),
            400,
            "batch of {len} is off the ladder {BATCH_SIZE_LADDER:?} and must be refused"
        );
    }

    assert_eq!(
        instance
            .current_state()
            .respond_calls
            .load(Ordering::SeqCst),
        0,
        "an off-ladder batch must be refused before any slot reaches respond"
    );

    h.abort();
    let _ = h.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_ladder_step_is_served_in_order() {
    let (addr, instance, h) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/v1/instance/{INSTANCE}/batch");

    let mut expected_calls = 0u32;
    for step in BATCH_SIZE_LADDER {
        let resp = client
            .post(&url)
            .bearer_auth(TOKEN)
            .body(batch_of(step))
            .send()
            .await
            .expect("send");
        assert_eq!(
            resp.status().as_u16(),
            200,
            "ladder step {step} must be served"
        );
        let bytes = resp.bytes().await.expect("body");
        let responses: Vec<EchoResponse> =
            raven_railgun_http::read_batch_response_versioned(&bytes).expect("decode batch");
        assert_eq!(
            responses.len(),
            step,
            "step {step} must return {step} slots"
        );
        for (i, r) in responses.iter().enumerate() {
            assert_eq!(
                r.tag, i as u32,
                "step {step} slot {i} must carry its own input tag; ordering is part of the contract"
            );
        }
        expected_calls += step as u32;
    }

    assert_eq!(
        instance
            .current_state()
            .respond_calls
            .load(Ordering::SeqCst),
        expected_calls,
        "every slot of a padded batch costs a real respond; skipping one would be \
         a server-side pad distinguisher"
    );

    h.abort();
    let _ = h.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_empty_batch_is_still_refused() {
    let (addr, _instance, h) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/v1/instance/{INSTANCE}/batch");

    let resp = client
        .post(&url)
        .bearer_auth(TOKEN)
        .body(batch_of(0))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 400);

    h.abort();
    let _ = h.await;
}
