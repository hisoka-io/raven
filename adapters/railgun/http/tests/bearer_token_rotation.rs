//! Bearer-token hot-rotation tests.
//!
//! Verifies that token rotation takes effect immediately for new requests
//! while leaving in-flight queries (that already cleared auth) uninterrupted.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::PoisonError;
use std::time::Duration;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use raven_railgun_core::InstanceId;
use raven_railgun_engine::{Engine, InstanceRole, PirInstance, PirScheme};
use raven_railgun_http::{router, write_versioned, AppState, HttpConfig};
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

/// `PeerIpKeyExtractor` requires `ConnectInfo<SocketAddr>`; axum's `oneshot` doesn't install it.
fn inject_connect_info(req: &mut Request<Body>) {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12_345);
    req.extensions_mut().insert(ConnectInfo(addr));
}

const OLD_TOKEN: &str = "BEARER-TOKEN-OLD-padded-to-min-len-1234";
const NEW_TOKEN: &str = "BEARER-TOKEN-NEW-padded-to-min-len-5678";
const INSTANCE_ID: &str = "rotation-test-instance";

// Serialise AppState::new to avoid races on the global metrics recorder.
static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug, Default)]
struct SleepyScheme;

#[derive(Debug, Default)]
struct SleepyState {
    sleep_ms: parking_lot::Mutex<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SleepyQuery {
    nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SleepyResponse {
    echo_nonce: u64,
}

impl PirScheme for SleepyScheme {
    type ServerState = SleepyState;
    type Query = SleepyQuery;
    type Response = SleepyResponse;

    fn respond(
        state: &Self::ServerState,
        query: &Self::Query,
    ) -> raven_railgun_core::Result<Self::Response> {
        let sleep_ms = *state.sleep_ms.lock();
        if sleep_ms > 0 {
            std::thread::sleep(Duration::from_millis(sleep_ms));
        }
        Ok(SleepyResponse {
            echo_nonce: query.nonce,
        })
    }
}

fn build_state_and_router(state: Arc<SleepyState>) -> (AppState<SleepyScheme>, axum::Router) {
    let cfg = HttpConfig::demo(OLD_TOKEN);
    let mut engine: Engine<SleepyScheme> = Engine::new();
    let instance = PirInstance::new(
        InstanceId::new(INSTANCE_ID),
        InstanceRole::Static,
        SleepyState {
            sleep_ms: parking_lot::Mutex::new(*state.sleep_ms.lock()),
        },
    );
    engine.add_instance(instance).expect("register instance");

    let app_state = {
        let _g = APPSTATE_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        AppState::new(engine, cfg).expect("appstate")
    };
    let router = router::<SleepyScheme>(app_state.clone()).expect("router build");
    (app_state, router)
}

async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    resp.into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec()
}

fn build_query_request(token: &str, nonce: u64) -> Request<Body> {
    let body = write_versioned(&SleepyQuery { nonce }).expect("encode versioned body");
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/instance/{INSTANCE_ID}/query"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(body))
        .expect("build query req");
    inject_connect_info(&mut req);
    req
}

fn build_status_request(token: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/v1/status")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("build status req");
    inject_connect_info(&mut req);
    req
}

#[tokio::test]
async fn bearer_rotation_observable_on_status_route() {
    let state = Arc::new(SleepyState::default());
    let (app_state, router) = build_state_and_router(state);

    let resp_pre = router
        .clone()
        .oneshot(build_status_request(OLD_TOKEN))
        .await
        .expect("dispatch pre");
    assert_eq!(
        resp_pre.status(),
        StatusCode::OK,
        "pre-rotation OLD-token status must succeed"
    );

    app_state.set_read_token(NEW_TOKEN);

    let resp_old = router
        .clone()
        .oneshot(build_status_request(OLD_TOKEN))
        .await
        .expect("dispatch old");
    assert_eq!(
        resp_old.status(),
        StatusCode::UNAUTHORIZED,
        "post-rotation OLD-token status must be 401"
    );

    let resp_new = router
        .clone()
        .oneshot(build_status_request(NEW_TOKEN))
        .await
        .expect("dispatch new");
    assert_eq!(
        resp_new.status(),
        StatusCode::OK,
        "post-rotation NEW-token status must succeed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bearer_rotation_old_succeeds_before_and_new_succeeds_after_with_inflight_survival() {
    let state = Arc::new(SleepyState::default());
    let (app_state, router) = build_state_and_router(state);

    for nonce in 0u64..5 {
        let req = build_query_request(OLD_TOKEN, nonce);
        let resp = router.clone().oneshot(req).await.expect("dispatch");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "pre-rotation OLD-token query #{nonce} must succeed"
        );
        let bytes = body_bytes(resp).await;
        let decoded: SleepyResponse =
            raven_railgun_http::read_versioned(&bytes).expect("decode versioned response");
        assert_eq!(decoded.echo_nonce, nonce, "echo nonce must round-trip");
    }

    app_state.set_read_token(NEW_TOKEN);

    let req_old = build_query_request(OLD_TOKEN, 100);
    let resp_old = router.clone().oneshot(req_old).await.expect("dispatch old");
    assert_eq!(
        resp_old.status(),
        StatusCode::UNAUTHORIZED,
        "post-rotation OLD-token query must be 401, not {}",
        resp_old.status()
    );

    let req_new = build_query_request(NEW_TOKEN, 101);
    let resp_new = router.clone().oneshot(req_new).await.expect("dispatch new");
    assert_eq!(
        resp_new.status(),
        StatusCode::OK,
        "post-rotation NEW-token query must succeed, not {}",
        resp_new.status()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bearer_rotation_does_not_kill_inflight_query_started_under_old_token() {
    // respond sleeps 750 ms; rotate while the query is mid-sleep; it must still 200.
    let sleepy = Arc::new(SleepyState {
        sleep_ms: parking_lot::Mutex::new(750),
    });
    let (app_state, router) = build_state_and_router(Arc::clone(&sleepy));

    let router_clone = router.clone();
    let inflight = tokio::spawn(async move {
        let req = build_query_request(OLD_TOKEN, 9_001);
        router_clone.oneshot(req).await.expect("dispatch slow")
    });

    // 75 ms is well under the 750 ms sleep; query is still mid-flight when we rotate.
    tokio::time::sleep(Duration::from_millis(75)).await;

    app_state.set_read_token(NEW_TOKEN);

    let new_req = build_query_request(NEW_TOKEN, 9_002);
    let new_resp = router.clone().oneshot(new_req).await.expect("dispatch new");
    assert_eq!(
        new_resp.status(),
        StatusCode::OK,
        "NEW-token query during in-flight OLD-token query must succeed"
    );

    let old_req = build_query_request(OLD_TOKEN, 9_003);
    let old_resp = router.clone().oneshot(old_req).await.expect("dispatch old");
    assert_eq!(
        old_resp.status(),
        StatusCode::UNAUTHORIZED,
        "post-rotation OLD-token NEW-request must be 401"
    );

    let inflight_resp = inflight.await.expect("join inflight task");
    assert_eq!(
        inflight_resp.status(),
        StatusCode::OK,
        "in-flight OLD-token query must complete on its prior bearer; \
         rotation must NOT abort it mid-flight (got {})",
        inflight_resp.status()
    );
    let bytes = body_bytes(inflight_resp).await;
    let decoded: SleepyResponse =
        raven_railgun_http::read_versioned(&bytes).expect("decode in-flight response");
    assert_eq!(
        decoded.echo_nonce, 9_001,
        "in-flight echo must match the original query nonce"
    );
}
