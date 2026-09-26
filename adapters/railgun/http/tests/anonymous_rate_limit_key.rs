//! With the read path open, the per-IP limiter is the only thing standing between a
//! PIR server and an anonymous caller, so the key it buckets on is load-bearing.
//!
//! `trusted_proxy.rs` proves the extractor in isolation. This proves the extractor is the
//! one the ROUTER installs: a forged forwarding prefix, rotated per request, must not mint
//! a fresh bucket, and a genuinely different client must still get its own.

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

const INSTANCE: &str = "anon-rate-limit-instance";
const TOKEN: &str = "anon-rate-limit-legacy-token-padded1";

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

/// One cell, replenished once a second: the second request on a key inside the same
/// second is a 429, and every dispatch here is an in-process `oneshot`.
fn build_router(trusted_cidrs: &[&str]) -> axum::Router {
    build_router_at(trusted_cidrs, 1, 1)
}

fn build_router_at(trusted_cidrs: &[&str], rps: u64, burst: u32) -> axum::Router {
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
    cfg.trust_proxy_header = !trusted_cidrs.is_empty();
    cfg.trusted_proxy_cidrs = trusted_cidrs.iter().map(|c| (*c).to_owned()).collect();
    let state = {
        let _g = APPSTATE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        AppState::new(engine, cfg).expect("appstate")
    };
    router::<EchoScheme>(state).expect("router")
}

/// No `Authorization` header: the route under test is one an anonymous caller reaches.
fn probe(peer: &str, forwarded_for: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method(Method::GET).uri("/v1/status");
    if let Some(xff) = forwarded_for {
        builder = builder.header("x-forwarded-for", xff);
    }
    let mut req = builder.body(Body::empty()).expect("build probe");
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

#[tokio::test]
async fn a_rotated_forged_forwarding_prefix_cannot_mint_a_fresh_bucket() {
    let router = build_router(&["127.0.0.0/8"]);

    assert_eq!(
        status_of(
            &router,
            probe("127.0.0.1:41000", Some("1.2.3.4, 198.51.100.7"))
        )
        .await,
        StatusCode::OK,
        "an anonymous read must be served, and must consume the bucket"
    );
    assert_eq!(
        status_of(
            &router,
            probe("127.0.0.1:41000", Some("5.6.7.8, 9.9.9.9, 198.51.100.7")),
        )
        .await,
        StatusCode::TOO_MANY_REQUESTS,
        "rotating the forged prefix must land on the SAME key the proxy appended"
    );
    assert_eq!(
        status_of(
            &router,
            probe("127.0.0.1:41000", Some("1.2.3.4, 198.51.100.8"))
        )
        .await,
        StatusCode::OK,
        "a genuinely different client must still get its own bucket; otherwise the 429 \
         above only proves the limiter is globally exhausted"
    );
}

#[tokio::test]
async fn an_untrusted_peer_keys_to_its_socket_whatever_it_forwards() {
    let router = build_router(&["127.0.0.0/8"]);

    assert_eq!(
        status_of(&router, probe("203.0.113.9:41000", Some("198.51.100.200"))).await,
        StatusCode::OK
    );
    assert_eq!(
        status_of(&router, probe("203.0.113.9:41000", Some("198.51.100.201"))).await,
        StatusCode::TOO_MANY_REQUESTS,
        "an untrusted peer's forwarding header must not move its key"
    );
    assert_eq!(
        status_of(&router, probe("203.0.113.10:41000", None)).await,
        StatusCode::OK,
        "a different socket is a different key"
    );
}

/// With proxy trust off entirely the router installs `PeerIpKeyExtractor`; the same
/// forgery must still fail. Kept separate because it exercises the OTHER of the two
/// `build_governor_layer_*` branches.
#[tokio::test]
async fn with_no_declared_proxy_the_socket_is_the_key() {
    let router = build_router(&[]);

    assert_eq!(
        status_of(&router, probe("198.51.100.42:41000", Some("10.0.0.1"))).await,
        StatusCode::OK
    );
    assert_eq!(
        status_of(&router, probe("198.51.100.42:41000", Some("10.0.0.2"))).await,
        StatusCode::TOO_MANY_REQUESTS,
        "with no trusted proxy, a forwarding header must be ignored outright"
    );
}

/// `rate_limit_rps` must mean requests per second. `tower_governor`'s `per_second` takes a
/// PERIOD, so feeding it the rate read as "one request per 50 seconds" here: the burst
/// refilled 2,500x slower than configured and no test in the tree ever looked.
///
/// 50 rps is one cell per 20 ms, so 100 ms of slack is 5 replenishments; under the period
/// misreading the wait would have to be 50 s, a 500x margin in the failing direction.
#[tokio::test]
async fn the_burst_refills_at_the_configured_requests_per_second() {
    let router = build_router_at(&[], 50, 1);
    let peer = "198.51.100.77:41000";

    assert_eq!(status_of(&router, probe(peer, None)).await, StatusCode::OK);
    assert_eq!(
        status_of(&router, probe(peer, None)).await,
        StatusCode::TOO_MANY_REQUESTS,
        "burst of 1 must be spent by the first request"
    );

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    assert_eq!(
        status_of(&router, probe(peer, None)).await,
        StatusCode::OK,
        "at 50 rps the cell must be back within 100 ms; if this is a 429 the configured \
         rate is being read as a replenish period"
    );
}
