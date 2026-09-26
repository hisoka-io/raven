//! The uncredentialed routes are bounded, in both senses.
//!
//! `/v1/health/*`, `/v1/events` and `/metrics` were split into a router that bypassed the
//! limiter entirely, so that a scrape or an SSE reconnect could not exhaust the burst the
//! query path needs. With the read path opened they became the only group that was both
//! uncredentialed AND unlimited.
//!
//! Two different bounds, because a rate limit is the wrong tool for half of it. A limiter
//! bounds how fast connections ARRIVE. `/v1/events` holds a task, two timers and an
//! `AppState` clone for as long as the client stays connected, so what has to be bounded
//! there is how many are HELD. Both are asserted here; either alone reads as covered.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Method, Request, StatusCode},
    response::Response,
};
use http_body_util::BodyExt;
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

fn build(rps: u64, burst: u32, sse_cap: usize) -> axum::Router {
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
    cfg.max_sse_connections = sse_cap;
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
        let router = build(1, 1, 64);
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
    let router = build(1, 1, 64);
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

/// Every held stream here is DRIVEN to its first frame before it counts as held.
///
/// That is not tidiness. `oneshot` hands back a response whose body has never been polled, and
/// the handler's permit lives inside a lazy generator: un-polled, the generator body never runs
/// at all. A mutant that leaked the permit outright (`mem::forget` on the first line of the
/// stream) passed the first version of this test for exactly that reason -- the leak was never
/// reached. Pulling a frame runs the generator, so the permit is genuinely resident and the
/// release assertion at the end has something to detect.
async fn open_stream(router: &axum::Router, peer: &str) -> Response {
    let mut res = router
        .clone()
        .oneshot(anon("/v1/events", peer))
        .await
        .expect("dispatch");
    if res.status() == StatusCode::OK {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), res.body_mut().frame())
            .await
            .expect("the first status event must arrive promptly");
        assert!(
            frame.is_some(),
            "an accepted stream must emit its initial status event"
        );
    }
    res
}

/// A rate limit bounds arrivals; this bounds residents.
#[tokio::test]
async fn concurrent_event_streams_are_capped_and_released() {
    // Burst wide enough that the limiter cannot be what refuses; the cap must be.
    let router = build(1_000, 1_000, 2);

    let first = open_stream(&router, "203.0.113.21:50000").await;
    assert_eq!(first.status(), StatusCode::OK);

    let second = open_stream(&router, "203.0.113.22:50000").await;
    assert_eq!(second.status(), StatusCode::OK);

    let third = open_stream(&router, "203.0.113.23:50000").await;
    assert_eq!(
        third.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a third stream past a cap of two must be refused, not queued"
    );
    assert_eq!(
        third
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok()),
        Some("5"),
        "a refusal a client can act on carries when to come back"
    );

    drop(first);
    let after_release = open_stream(&router, "203.0.113.24:50000").await;
    assert_eq!(
        after_release.status(),
        StatusCode::OK,
        "a closed stream must return its permit, or the cap degrades to a lifetime quota"
    );
}
