//! The u16 wire-schema prefix is the only thing standing between a future client's body
//! and a v1 decode of it. bincode accepts trailing bytes, so a body that skipped the
//! guard does not fail loudly - it decodes into whatever the old struct layout says.

#![allow(
    dead_code,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Method, Request, StatusCode},
};
use raven_railgun_core::{InstanceId, Result as RailgunResult};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance, PirScheme};
use raven_railgun_http::{
    read_batch_response_versioned, router, write_batch_response_versioned, write_versioned,
    AppState, HttpConfig, WIRE_SCHEMA_PREFIX_LEN, WIRE_SCHEMA_VERSION, X_RAVEN_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

const TOKEN: &str = "schema-version-guard-token-1234567";
const INSTANCE: &str = "schema-version-instance";

static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug)]
struct EchoScheme;

#[derive(Debug, Default)]
struct EchoState;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct EchoQuery {
    tag: u32,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct EchoResponse {
    tag: u32,
}

impl PirScheme for EchoScheme {
    type ServerState = EchoState;
    type Query = EchoQuery;
    type Response = EchoResponse;
    fn respond(_state: &Self::ServerState, query: &Self::Query) -> RailgunResult<Self::Response> {
        Ok(EchoResponse { tag: query.tag })
    }
    fn state_shape(_state: &Self::ServerState) -> raven_railgun_engine::StateShape {
        raven_railgun_engine::StateShape {
            entry_size_bytes: 1,
            rows_per_shard: u64::MAX,
        }
    }
}

fn build_router() -> axum::Router {
    let mut engine: Engine<EchoScheme> = Engine::new();
    engine
        .register_instance(Arc::new(PirInstance::new(
            InstanceId::new(INSTANCE),
            InstanceRole::Static,
            EchoState,
        )))
        .expect("register instance");
    let mut cfg = HttpConfig::demo(TOKEN);
    cfg.respond_timeout_secs = 5;
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

fn request(route: &str, body: Vec<u8>) -> Request<Body> {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/instance/{INSTANCE}/{route}"))
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(body))
        .expect("build req");
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        12_345,
    )));
    req
}

/// Everything after the prefix stays a valid v1 body, so a server that skipped the
/// version check serves 200 rather than failing to decode.
fn with_next_schema_version(mut body: Vec<u8>) -> Vec<u8> {
    let next = WIRE_SCHEMA_VERSION
        .checked_add(1)
        .expect("version headroom");
    body[..WIRE_SCHEMA_PREFIX_LEN].copy_from_slice(&next.to_be_bytes());
    body
}

async fn status_of(route: &str, body: Vec<u8>) -> StatusCode {
    build_router()
        .oneshot(request(route, body))
        .await
        .expect("dispatch")
        .status()
}

#[tokio::test]
async fn single_query_refuses_a_body_from_a_future_schema_version() {
    let body = with_next_schema_version(write_versioned(&EchoQuery { tag: 7 }).expect("encode"));
    assert_eq!(
        status_of("query", body).await,
        StatusCode::BAD_REQUEST,
        "a v{}-prefixed body must be refused, not decoded as v{WIRE_SCHEMA_VERSION}",
        WIRE_SCHEMA_VERSION + 1
    );
}

#[tokio::test]
async fn batch_refuses_a_body_from_a_future_schema_version() {
    let body =
        with_next_schema_version(write_versioned(&vec![EchoQuery { tag: 7 }]).expect("encode"));
    assert_eq!(
        status_of("batch", body).await,
        StatusCode::BAD_REQUEST,
        "the batch route decodes through the same guard and must refuse too"
    );
}

/// The premise: the same bytes at the right version ARE served. Without this the two
/// refusals above are satisfied by a route that rejects everything.
#[tokio::test]
async fn the_same_body_at_the_current_schema_version_is_served() {
    let body = write_versioned(&EchoQuery { tag: 7 }).expect("encode");
    let resp = build_router()
        .oneshot(request("query", body))
        .await
        .expect("dispatch");
    assert_eq!(resp.status(), StatusCode::OK);
    let advertised = resp
        .headers()
        .get(X_RAVEN_SCHEMA_VERSION.to_ascii_lowercase())
        .expect("responses must advertise the schema version they speak")
        .to_str()
        .expect("ascii");
    assert_eq!(advertised, WIRE_SCHEMA_VERSION.to_string());
}

#[tokio::test]
async fn a_body_shorter_than_the_version_prefix_is_refused() {
    assert_eq!(
        status_of("query", vec![WIRE_SCHEMA_VERSION.to_le_bytes()[0]]).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        status_of("query", Vec::new()).await,
        StatusCode::BAD_REQUEST
    );
}

/// The client half of the envelope. A wallet decoding a future server's batch with the
/// old element layout is the same silent-wrong defect pointed the other way.
#[test]
fn batch_response_decoder_refuses_a_future_schema_version() {
    let good = write_batch_response_versioned(&[EchoResponse { tag: 7 }]).expect("encode");
    let round_tripped: Vec<EchoResponse> =
        read_batch_response_versioned(&good).expect("current version decodes");
    assert_eq!(round_tripped, vec![EchoResponse { tag: 7 }]);

    let future = with_next_schema_version(good);
    let err = read_batch_response_versioned::<EchoResponse>(&future)
        .expect_err("a future-version batch body must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("schema version mismatch"),
        "the error must name the mismatch so a client can act on it; got: {msg}"
    );
}
