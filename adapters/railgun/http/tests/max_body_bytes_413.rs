//! Regression: `HttpConfig.max_body_bytes` must be wired into `DefaultBodyLimit::max`.
//! Pre-fix the routers hardcoded 8 MiB and ignored the config field.

#![allow(
    dead_code,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::net::SocketAddr;
use std::sync::Arc;

use raven_railgun_core::{InstanceId, Result as RailgunResult};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance, PirScheme};
use raven_railgun_http::{router, AppState, HttpConfig};
use serde::{Deserialize, Serialize};

const TOKEN: &str = "max-body-test-token-padded-1234";
const INSTANCE: &str = "max-body-instance";
// 4 KiB cap, 16 KiB body: unambiguous 413.
const CONFIGURED_MAX_BODY: usize = 4 * 1024;
const POST_BODY_LEN: usize = 16 * 1024;

static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug)]
struct EchoScheme;

#[derive(Debug, Default)]
struct EchoState;

#[derive(Serialize, Deserialize, Debug)]
struct EchoQuery;

#[derive(Serialize, Deserialize, Debug)]
struct EchoResponse;

impl PirScheme for EchoScheme {
    type ServerState = EchoState;
    type Query = EchoQuery;
    type Response = EchoResponse;
    fn respond(_state: &Self::ServerState, _query: &Self::Query) -> RailgunResult<Self::Response> {
        Ok(EchoResponse)
    }
}

async fn spawn_server(max_body_bytes: usize) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let instance: Arc<PirInstance<EchoScheme>> = Arc::new(PirInstance::new(
        InstanceId::new(INSTANCE),
        InstanceRole::Static,
        EchoState,
    ));
    let mut engine: Engine<EchoScheme> = Engine::new();
    engine
        .register_instance(Arc::clone(&instance))
        .expect("register instance");

    let mut cfg = HttpConfig::demo(TOKEN);
    cfg.max_body_bytes = max_body_bytes;
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
    (addr, handle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn body_larger_than_max_body_bytes_returns_413() {
    let (addr, h) = spawn_server(CONFIGURED_MAX_BODY).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/v1/instance/{INSTANCE}/query");

    let body = vec![0u8; POST_BODY_LEN];
    let resp = client
        .post(&url)
        .bearer_auth(TOKEN)
        .body(body)
        .send()
        .await
        .expect("send");

    let status = resp.status();
    assert_eq!(
        status.as_u16(),
        413,
        "body larger than configured max_body_bytes ({CONFIGURED_MAX_BODY}) \
         must surface 413 Payload Too Large; got {status}"
    );

    h.abort();
    let _ = h.await;
}

/// Small body must still fail downstream (400), not at the body-limit layer (413).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn body_smaller_than_max_body_bytes_does_not_413() {
    let (addr, h) = spawn_server(CONFIGURED_MAX_BODY).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/v1/instance/{INSTANCE}/query");

    let body = vec![0u8; 64];
    let resp = client
        .post(&url)
        .bearer_auth(TOKEN)
        .body(body)
        .send()
        .await
        .expect("send");

    let status = resp.status();
    assert_ne!(
        status.as_u16(),
        413,
        "small body must NOT be rejected at the body-limit layer; got {status}"
    );

    h.abort();
    let _ = h.await;
}
