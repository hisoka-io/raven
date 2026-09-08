//! Admin route auth: the drain/undrain routes accept the admin token ONLY from
//! the Authorization header. A token smuggled as a query parameter must be
//! refused — query strings land in access logs, proxies and browser history,
//! so accepting one there silently downgrades the admin credential.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Method, Request, StatusCode},
    Router,
};
use raven_railgun_core::{InstanceId, Result as RailgunResult};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance, PirScheme};
use raven_railgun_http::{router, AppState, HttpConfig};
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

const READ_TOKEN: &str = "admin-auth-read-token-padded-123456";
const ADMIN_TOKEN: &str = "admin-auth-ADMIN-token-padded-12345";
const WRONG_TOKEN: &str = "admin-auth-WRONG-token-padded-12345";
const INSTANCE: &str = "admin-auth-instance";

static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug)]
struct EchoScheme;

#[derive(Debug, Default)]
struct EchoState;

#[derive(Serialize, Deserialize, Debug)]
struct EchoQuery {
    nonce: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct EchoResponse {
    echo_nonce: u64,
}

impl PirScheme for EchoScheme {
    type ServerState = EchoState;
    type Query = EchoQuery;
    type Response = EchoResponse;
    fn respond(_state: &Self::ServerState, query: &Self::Query) -> RailgunResult<Self::Response> {
        Ok(EchoResponse {
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

fn build_router() -> Router {
    let mut engine: Engine<EchoScheme> = Engine::new();
    engine
        .register_instance(Arc::new(PirInstance::new(
            InstanceId::new(INSTANCE),
            InstanceRole::Static,
            EchoState,
        )))
        .expect("register instance");
    let mut cfg = HttpConfig::demo(READ_TOKEN);
    cfg.admin_token = Some(ADMIN_TOKEN.to_owned());
    cfg.rate_limit_rps = 10_000;
    cfg.rate_limit_burst = 10_000;
    let state = {
        let _g = APPSTATE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        AppState::new(engine, cfg).expect("appstate")
    };
    router::<EchoScheme>(state).expect("router")
}

fn drain_request(uri: &str, auth_header: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method(Method::POST).uri(uri);
    if let Some(value) = auth_header {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    let mut req = builder.body(Body::empty()).expect("build req");
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        12_345,
    )));
    req
}

fn drain_uri() -> String {
    format!("/v1/admin/instances/drain/{INSTANCE}")
}

#[tokio::test]
async fn no_authorization_header_is_refused() {
    let router = build_router();
    let resp = router
        .oneshot(drain_request(&drain_uri(), None))
        .await
        .expect("dispatch");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn query_parameter_token_cannot_open_the_admin_routes() {
    let router = build_router();
    // The admin credential offered every way a query string can carry it, with
    // no Authorization header: all must be refused.
    for uri in [
        format!("{}?token={ADMIN_TOKEN}", drain_uri()),
        format!("{}?access_token={ADMIN_TOKEN}", drain_uri()),
        format!("{}?bearer={ADMIN_TOKEN}&token={ADMIN_TOKEN}", drain_uri()),
    ] {
        let resp = router
            .clone()
            .oneshot(drain_request(&uri, None))
            .await
            .expect("dispatch");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "a query-parameter admin token must NOT open {uri}"
        );
    }
}

#[tokio::test]
async fn wrong_bearer_token_is_refused() {
    let router = build_router();
    let resp = router
        .oneshot(drain_request(
            &drain_uri(),
            Some(&format!("Bearer {WRONG_TOKEN}")),
        ))
        .await
        .expect("dispatch");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // The READ token must not clear the admin gate either.
    let router = build_router();
    let resp = router
        .oneshot(drain_request(
            &drain_uri(),
            Some(&format!("Bearer {READ_TOKEN}")),
        ))
        .await
        .expect("dispatch");
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "the read token must not authorize admin routes"
    );
}

/// The positive case is what makes the three refusals non-vacuous: with no
/// admin token configured they would all pass against a dead route.
#[tokio::test]
async fn correct_bearer_header_drains_and_undrains() {
    let router = build_router();
    let resp = router
        .clone()
        .oneshot(drain_request(
            &drain_uri(),
            Some(&format!("Bearer {ADMIN_TOKEN}")),
        ))
        .await
        .expect("dispatch drain");
    assert_eq!(resp.status(), StatusCode::OK, "admin bearer must drain");

    let undrain = format!("/v1/admin/instances/undrain/{INSTANCE}");
    let resp = router
        .oneshot(drain_request(
            &undrain,
            Some(&format!("Bearer {ADMIN_TOKEN}")),
        ))
        .await
        .expect("dispatch undrain");
    assert_eq!(resp.status(), StatusCode::OK, "admin bearer must undrain");
}
