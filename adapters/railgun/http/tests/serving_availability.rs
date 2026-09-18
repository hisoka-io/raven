//! Missing and drained instances are different serving outcomes on every PIR route.

#![allow(clippy::expect_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use raven_inspire::params::{InspireParams, InspireVariant, SecurityLevel};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{setup_state, RavenInspireScheme};
use raven_railgun_engine::{DrainState, Engine, InstanceRole, PirInstance};
use raven_railgun_http::{inspire_router, AppState, HttpConfig};
use tower::ServiceExt;

const TOKEN: &str = "serving-accessor-test-token";
const INSTANCE: &str = "serving";

fn params() -> InspireParams {
    InspireParams {
        ring_dim: 256,
        q: 1_152_921_504_606_830_593,
        crt_moduli: vec![1_152_921_504_606_830_593],
        p: 65_537,
        sigma: 6.4,
        gadget_base: 1 << 20,
        query_gadget_len: 3,
        packing_gadget_len: 3,
        security_level: SecurityLevel::Bits128,
    }
}

fn fixture() -> (axum::Router, Arc<PirInstance<RavenInspireScheme>>) {
    let params = params();
    let db = raven_railgun_testkit::toy_db(32, 32);
    let (state, _) =
        setup_state(&params, &db, 32, InspireVariant::TwoPacking).expect("small state");
    let instance = Arc::new(PirInstance::new(
        InstanceId::new(INSTANCE),
        InstanceRole::Static,
        state,
    ));
    let engine: Engine<RavenInspireScheme> = Engine::new();
    engine
        .add_live(Arc::clone(&instance))
        .expect("register instance");
    let mut config = HttpConfig::demo(TOKEN);
    config.enable_fanout = true;
    let app = AppState::new(engine, config).expect("app state");
    (inspire_router(app).expect("router"), instance)
}

fn request(path: &str) -> Request<Body> {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::empty())
        .expect("request");
    request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        12_345,
    )));
    request
}

async fn assert_route_distinguishes_missing_from_drained(suffix: &str) {
    let (router, instance) = fixture();
    let response = router
        .clone()
        .oneshot(request(&format!("/v1/instance/missing/{suffix}")))
        .await
        .expect("missing dispatch");
    assert_eq!(response.status(), StatusCode::NOT_FOUND, "{suffix}");

    let response = router
        .clone()
        .oneshot(request(&format!("/v1/instance/{INSTANCE}/{suffix}")))
        .await
        .expect("active dispatch");
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "{suffix}: an available instance must reach body decoding"
    );

    instance.set_drain_state(DrainState::Drained);
    let response = router
        .clone()
        .oneshot(request(&format!("/v1/instance/{INSTANCE}/{suffix}")))
        .await
        .expect("drained dispatch");
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "{suffix}"
    );
}

#[tokio::test]
async fn query_route_distinguishes_missing_from_drained() {
    assert_route_distinguishes_missing_from_drained("query").await;
}

#[tokio::test]
async fn batch_route_distinguishes_missing_from_drained() {
    assert_route_distinguishes_missing_from_drained("batch").await;
}

#[tokio::test]
async fn fanout_route_distinguishes_missing_from_drained() {
    assert_route_distinguishes_missing_from_drained("fanout").await;
}
