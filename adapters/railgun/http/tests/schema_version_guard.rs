//! The u16 wire-schema prefix prevents previous and future response layouts from reaching
//! the wrong decoder. Frozen v2 and current bodies prove both refusal directions.

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
use raven_inspire::math::Poly;
use raven_inspire::pir::{PackingMode, ServerResponse};
use raven_inspire::rlwe::RlweCiphertext;
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
const PREVIOUS_WIRE_SCHEMA_VERSION: u16 = 5;

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

#[derive(Serialize, Deserialize, Clone, Debug)]
struct FrozenV2ServerResponse {
    ciphertext: RlweCiphertext,
    column_ciphertexts: Vec<RlweCiphertext>,
    packing_mode: Option<PackingMode>,
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

/// Everything after the prefix stays a valid current body, isolating the version guard.
fn with_next_schema_version(mut body: Vec<u8>) -> Vec<u8> {
    let next = WIRE_SCHEMA_VERSION
        .checked_add(1)
        .expect("version headroom");
    body[..WIRE_SCHEMA_PREFIX_LEN].copy_from_slice(&next.to_be_bytes());
    body
}

fn with_schema_version(mut body: Vec<u8>, version: u16) -> Vec<u8> {
    body[..WIRE_SCHEMA_PREFIX_LEN].copy_from_slice(&version.to_be_bytes());
    body
}

fn response_layouts() -> (FrozenV2ServerResponse, ServerResponse) {
    let modulus = 65_537;
    let ciphertext = RlweCiphertext::from_parts(
        Poly::from_coeffs(vec![1, 2, 3, 4], modulus),
        Poly::from_coeffs(vec![5, 6, 7, 8], modulus),
    );
    (
        FrozenV2ServerResponse {
            ciphertext: ciphertext.clone(),
            column_ciphertexts: vec![],
            packing_mode: Some(PackingMode::Inspiring),
        },
        ServerResponse {
            ciphertext,
            column_ciphertexts: vec![],
            packing_mode: Some(PackingMode::Inspiring),
            packed_coefficients: Some(2),
        },
    )
}

fn write_at_schema<T: Serialize>(value: &T, version: u16) -> Vec<u8> {
    let mut out = version.to_be_bytes().to_vec();
    out.extend_from_slice(&bincode::serialize(value).expect("encode frozen schema body"));
    out
}

fn write_batch_at_schema<T: Serialize>(values: &[T], version: u16) -> Vec<u8> {
    let mut out = version.to_be_bytes().to_vec();
    out.extend_from_slice(
        &u64::try_from(values.len())
            .expect("batch count fits u64")
            .to_le_bytes(),
    );
    for value in values {
        let body = bincode::serialize(value).expect("encode frozen batch element");
        out.extend_from_slice(
            &u64::try_from(body.len())
                .expect("batch element length fits u64")
                .to_le_bytes(),
        );
        out.extend_from_slice(&body);
    }
    out
}

fn read_at_schema<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    expected: u16,
) -> Result<T, String> {
    let prefix = bytes
        .get(..WIRE_SCHEMA_PREFIX_LEN)
        .ok_or_else(|| "short schema prefix".to_owned())?;
    let version = u16::from_be_bytes([prefix[0], prefix[1]]);
    if version != expected {
        return Err(format!(
            "schema version mismatch: expected v{expected}, got v{version}"
        ));
    }
    bincode::deserialize(
        bytes
            .get(WIRE_SCHEMA_PREFIX_LEN..)
            .ok_or_else(|| "short schema body".to_owned())?,
    )
    .map_err(|error| error.to_string())
}

fn read_batch_at_schema<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    expected: u16,
) -> Result<Vec<T>, String> {
    let prefix = bytes
        .get(..WIRE_SCHEMA_PREFIX_LEN)
        .ok_or_else(|| "short schema prefix".to_owned())?;
    let version = u16::from_be_bytes([prefix[0], prefix[1]]);
    if version != expected {
        return Err(format!(
            "schema version mismatch: expected v{expected}, got v{version}"
        ));
    }
    let mut offset = WIRE_SCHEMA_PREFIX_LEN;
    let count_end = offset + 8;
    let count_bytes = bytes
        .get(offset..count_end)
        .ok_or_else(|| "short batch count".to_owned())?;
    let count = usize::try_from(u64::from_le_bytes(
        count_bytes.try_into().expect("eight-byte count"),
    ))
    .map_err(|_| "batch count exceeds usize".to_owned())?;
    offset = count_end;
    let mut values = Vec::with_capacity(count);
    for index in 0..count {
        let length_end = offset + 8;
        let length_bytes = bytes
            .get(offset..length_end)
            .ok_or_else(|| format!("short element {index} length"))?;
        let length = usize::try_from(u64::from_le_bytes(
            length_bytes.try_into().expect("eight-byte element length"),
        ))
        .map_err(|_| format!("element {index} length exceeds usize"))?;
        offset = length_end;
        let element_end = offset
            .checked_add(length)
            .ok_or_else(|| format!("element {index} length overflow"))?;
        let element = bytes
            .get(offset..element_end)
            .ok_or_else(|| format!("short element {index} body"))?;
        values.push(bincode::deserialize(element).map_err(|error| error.to_string())?);
        offset = element_end;
    }
    Ok(values)
}

#[test]
fn previous_and_current_single_response_layouts_refuse_each_other() {
    assert_eq!(
        WIRE_SCHEMA_VERSION, 6,
        "tight 60-bit coefficients change query and response bytes"
    );
    let (v2_response, current_response) = response_layouts();
    let old = write_at_schema(&v2_response, PREVIOUS_WIRE_SCHEMA_VERSION);
    let current = write_versioned(&current_response).expect("encode current response layout");
    assert_ne!(
        &old[WIRE_SCHEMA_PREFIX_LEN..],
        &current[WIRE_SCHEMA_PREFIX_LEN..],
        "the frozen v2 body must not be a relabeled current body"
    );

    let current_error = raven_railgun_http::read_versioned::<ServerResponse>(&old)
        .expect_err("current reader must refuse a real v2 response");
    assert!(current_error.to_string().contains("expects v6"));
    assert!(current_error.to_string().contains("sent v5"));
    let old_error =
        read_at_schema::<FrozenV2ServerResponse>(&current, PREVIOUS_WIRE_SCHEMA_VERSION)
            .expect_err("previous reader must refuse a real current response");
    assert!(old_error.contains("expected v5, got v6"));
}

#[test]
fn previous_and_current_batch_response_layouts_refuse_each_other() {
    let (v2_response, current_response) = response_layouts();
    let old = write_batch_at_schema(&[v2_response], PREVIOUS_WIRE_SCHEMA_VERSION);
    let current =
        write_batch_response_versioned(&[current_response]).expect("encode current batch");
    assert_ne!(
        &old[WIRE_SCHEMA_PREFIX_LEN + 16..],
        &current[WIRE_SCHEMA_PREFIX_LEN + 16..],
        "the frozen v2 element must not be a relabeled current element"
    );
    let current_error = read_batch_response_versioned::<ServerResponse>(&old)
        .expect_err("current batch reader must refuse a real v2 response");
    assert!(current_error.to_string().contains("expects v6"));
    assert!(current_error.to_string().contains("sent v5"));

    let old_error =
        read_batch_at_schema::<FrozenV2ServerResponse>(&current, PREVIOUS_WIRE_SCHEMA_VERSION)
            .expect_err("previous batch reader must refuse a real current response");
    assert!(old_error.contains("expected v5, got v6"));
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
async fn previous_schema_rejection_advertises_the_current_version() {
    let current = write_versioned(&EchoQuery { tag: 7 }).expect("encode current");
    let old = with_schema_version(current, PREVIOUS_WIRE_SCHEMA_VERSION);
    let response = build_router()
        .oneshot(request("query", old))
        .await
        .expect("dispatch old body");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get(X_RAVEN_SCHEMA_VERSION.to_ascii_lowercase())
            .expect("schema mismatch must advertise the accepted version"),
        "6"
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
