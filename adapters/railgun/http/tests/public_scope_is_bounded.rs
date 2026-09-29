//! The uncredentialed public routes are rate-limited.
//!
//! `/v1/health/*` and `/metrics` were split into a router that bypassed the limiter entirely,
//! so that a scrape could not exhaust the burst the query path needs. With the read path opened
//! they became the only group that was both uncredentialed AND unlimited.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Method, Request, StatusCode},
};
use raven_railgun_core::{InstanceId, Result as RailgunResult};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance, PirScheme};
use raven_railgun_http::{router, AppState, HttpConfig};
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

const INSTANCE: &str = "public-scope-instance";
const TOKEN: &str = "public-scope-legacy-token-padded1234";

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

fn build(rps: u64, burst: u32) -> axum::Router {
    let mut engine: Engine<EchoScheme> = Engine::new();
    engine
        .register_instance(Arc::new(PirInstance::new(
            InstanceId::new(INSTANCE),
            InstanceRole::Static,
            EchoState,
        )))
        .expect("register instance");
    let mut cfg = HttpConfig::demo(TOKEN);
    cfg.rate_limit_rps = rps;
    cfg.rate_limit_burst = burst;
    cfg.metrics_public = true;
    let state = {
        let _g = APPSTATE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        AppState::new(engine, cfg).expect("appstate")
    };
    router::<EchoScheme>(state).expect("router")
}

/// Anonymous by construction: the whole point is the caller that holds no credential.
fn anon(uri: &str, peer: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .expect("build probe");
    assert!(
        req.headers().get(header::AUTHORIZATION).is_none(),
        "this probe must stay anonymous"
    );
    let addr: SocketAddr = peer.parse().expect("peer socket addr");
    req.extensions_mut().insert(ConnectInfo(addr));
    req
}

async fn status_of(router: &axum::Router, req: Request<Body>) -> StatusCode {
    router
        .clone()
        .oneshot(req)
        .await
        .expect("dispatch")
        .status()
}

/// One cell replenished once a second: the second request on a key inside the same second
/// is a 429. Before this the public scope had no limiter at all and both were 200.
#[tokio::test]
async fn every_uncredentialed_route_is_rate_limited() {
    for uri in ["/v1/health/live", "/v1/health/ready", "/metrics"] {
        let router = build(1, 1);
        assert_eq!(
            status_of(&router, anon(uri, "203.0.113.7:50000")).await,
            StatusCode::OK,
            "{uri}: an anonymous read must be served, and must consume the bucket"
        );
        assert_eq!(
            status_of(&router, anon(uri, "203.0.113.7:50001")).await,
            StatusCode::TOO_MANY_REQUESTS,
            "{uri} is reachable without a credential, so it must be rate-limited"
        );
        assert_eq!(
            status_of(&router, anon(uri, "198.51.100.9:50000")).await,
            StatusCode::OK,
            "{uri}: a different peer must still get its own bucket"
        );
    }
}

/// The reason the split exists at all. An independent bucket is what lets the public scope
/// be limited WITHOUT a scrape loop spending the budget a wallet's queries need; merging the
/// two routers under one limiter would pass the test above and destroy this property.
#[tokio::test]
async fn exhausting_the_public_bucket_leaves_the_query_bucket_alone() {
    let router = build(1, 1);
    let peer = "203.0.113.11:50000";

    assert_eq!(
        status_of(&router, anon("/metrics", peer)).await,
        StatusCode::OK
    );
    assert_eq!(
        status_of(&router, anon("/metrics", peer)).await,
        StatusCode::TOO_MANY_REQUESTS,
        "the public bucket must be spent before this proves anything"
    );

    assert_eq!(
        status_of(&router, anon("/v1/status", peer)).await,
        StatusCode::OK,
        "a spent scrape budget must not cost the same peer its query budget"
    );
}
