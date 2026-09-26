//! `/metrics` is the one route the read bearer still opens, so it is where rotation is
//! observable. Rotation must bind immediately for new scrapes while leaving in-flight
//! work uninterrupted - and it must not reach the read path, which carries no credential
//! to rotate.

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

// Serialises AppState::new against the global metrics recorder.
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
    fn state_shape(_state: &Self::ServerState) -> raven_railgun_engine::StateShape {
        raven_railgun_engine::StateShape {
            entry_size_bytes: 1,
            rows_per_shard: u64::MAX,
        }
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

fn build_anonymous_query_request(nonce: u64) -> Request<Body> {
    let body = write_versioned(&SleepyQuery { nonce }).expect("encode versioned body");
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/instance/{INSTANCE_ID}/query"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(body))
        .expect("build query req");
    inject_connect_info(&mut req);
    req
}

fn build_metrics_request(token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method(Method::GET).uri("/metrics");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let mut req = builder.body(Body::empty()).expect("build metrics req");
    inject_connect_info(&mut req);
    req
}

fn build_anonymous_status_request() -> Request<Body> {
    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/v1/status")
        .body(Body::empty())
        .expect("build status req");
    inject_connect_info(&mut req);
    req
}

#[tokio::test]
async fn bearer_rotation_observable_on_the_metrics_route() {
    let state = Arc::new(SleepyState::default());
    let (app_state, router) = build_state_and_router(state);

    let resp_pre = router
        .clone()
        .oneshot(build_metrics_request(Some(OLD_TOKEN)))
        .await
        .expect("dispatch pre");
    assert_eq!(
        resp_pre.status(),
        StatusCode::OK,
        "pre-rotation OLD-token scrape must succeed"
    );

    app_state.set_read_token(NEW_TOKEN);

    let resp_old = router
        .clone()
        .oneshot(build_metrics_request(Some(OLD_TOKEN)))
        .await
        .expect("dispatch old");
    assert_eq!(
        resp_old.status(),
        StatusCode::UNAUTHORIZED,
        "post-rotation OLD-token scrape must be 401"
    );

    let resp_anon = router
        .clone()
        .oneshot(build_metrics_request(None))
        .await
        .expect("dispatch anon");
    assert_eq!(
        resp_anon.status(),
        StatusCode::UNAUTHORIZED,
        "rotating to a token nobody holds must not read as `metrics_public`"
    );

    let resp_new = router
        .clone()
        .oneshot(build_metrics_request(Some(NEW_TOKEN)))
        .await
        .expect("dispatch new");
    assert_eq!(
        resp_new.status(),
        StatusCode::OK,
        "post-rotation NEW-token scrape must succeed"
    );

    let resp_read = router
        .oneshot(build_anonymous_status_request())
        .await
        .expect("dispatch read");
    assert_eq!(
        resp_read.status(),
        StatusCode::OK,
        "rotation must not reach the credential-free read path"
    );
}

// The read path has no credential to rotate, so the question this asks is the one left:
// a rotation landing mid-request must neither abort the in-flight query nor delay the
// scrape gate. `router()` installs ONE auth_layer cloned across both route groups
// (src/lib.rs), so the `/metrics` assertions here also cover the layer the query took.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotation_mid_request_neither_aborts_the_query_nor_lags_the_metrics_gate() {
    let sleepy = Arc::new(SleepyState {
        sleep_ms: parking_lot::Mutex::new(750),
    });
    let (app_state, router) = build_state_and_router(Arc::clone(&sleepy));

    let router_clone = router.clone();
    let inflight = tokio::spawn(async move {
        let req = build_anonymous_query_request(9_001);
        router_clone.oneshot(req).await.expect("dispatch slow")
    });

    tokio::time::sleep(Duration::from_millis(75)).await;

    app_state.set_read_token(NEW_TOKEN);

    let new_resp = router
        .clone()
        .oneshot(build_metrics_request(Some(NEW_TOKEN)))
        .await
        .expect("dispatch new");
    assert_eq!(
        new_resp.status(),
        StatusCode::OK,
        "NEW-token scrape during an in-flight query must succeed"
    );

    let old_resp = router
        .clone()
        .oneshot(build_metrics_request(Some(OLD_TOKEN)))
        .await
        .expect("dispatch old");
    assert_eq!(
        old_resp.status(),
        StatusCode::UNAUTHORIZED,
        "post-rotation OLD-token scrape must be 401 without waiting on the query"
    );

    let anon_read = router
        .clone()
        .oneshot(build_anonymous_query_request(9_002))
        .await
        .expect("dispatch anon read");
    assert_eq!(
        anon_read.status(),
        StatusCode::OK,
        "a credential-free query must be served across a rotation"
    );

    let inflight_resp = inflight.await.expect("join inflight task");
    assert_eq!(
        inflight_resp.status(),
        StatusCode::OK,
        "the in-flight query must complete; rotation must NOT abort it mid-flight (got {})",
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

/// `set_read_token` takes any string, so it can install what `HttpConfig::validate` would
/// reject. An empty token must not read as "no credential required" - neither for a missing
/// header nor for `Authorization: Bearer ` with nothing after it, which a naive
/// `strip_prefix(...).unwrap_or_default()` compares equal to it.
#[tokio::test]
async fn an_empty_rotated_token_opens_nothing() {
    let state = Arc::new(SleepyState::default());
    let (app_state, router) = build_state_and_router(state);
    app_state.set_read_token("");

    for (name, request) in [
        ("a missing header", build_metrics_request(None)),
        ("an empty bearer", build_metrics_request(Some(""))),
    ] {
        let status = router
            .clone()
            .oneshot(request)
            .await
            .expect("dispatch")
            .status();
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{name} must not clear a `/metrics` gate whose token was rotated to empty"
        );
    }

    let status = router
        .oneshot(build_anonymous_status_request())
        .await
        .expect("dispatch read")
        .status();
    assert_eq!(
        status,
        StatusCode::OK,
        "the read path is unaffected; a dead router would pass the refusals above"
    );
}
