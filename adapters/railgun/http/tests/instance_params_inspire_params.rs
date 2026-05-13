//! Wallet self-bootstrap regression: `/v1/instance/{id}/params`
//! must ship `inspire_params_bincode` alongside `crs_bincode` and
//! `shard_config_bincode` so the WASM client can derive an RLWE
//! secret key without a side-channel param distribution.
//!
//! Three properties are pinned:
//!
//! 1. The bincode envelope decodes to an `InstanceParams` whose
//!    `inspire_params_bincode` field is non-empty.
//! 2. The bytes round-trip into a `raven_inspire::params::InspireParams`
//!    that matches what the engine was bootstrapped with.
//! 3. The wire schema version remains `1` (no envelope bump needed
//!    for this additive change at the bincode-struct end).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::PoisonError;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use raven_inspire::params::{InspireParams, InspireVariant, ShardConfig};
use raven_inspire::ServerCrs;
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{setup_state, RavenInspireScheme};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
use raven_railgun_http::{
    inspire_router, read_versioned, AppState, HttpConfig, InstanceParams, WIRE_SCHEMA_VERSION,
};
use tower::ServiceExt;

/// Token padded above `HttpConfig::MIN_TOKEN_LEN`.
const READ_TOKEN: &str = "BEARER-PARAMS-TEST-padded-min-len-aabb";
const INSTANCE_ID: &str = "params-inspire-instance";
const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_BYTES: usize = 256;

/// Serialize across tests in this file: `AppState::new` registers a
/// process-global Prometheus recorder, and the OnceLock that backs
/// it is reentrant but the per-instance state is not. Mirrors the
/// pattern in `bearer_token_rotation.rs`.
static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn inject_connect_info(req: &mut Request<Body>) {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12_345);
    req.extensions_mut().insert(ConnectInfo(addr));
}

fn build_engine_with_one_instance(params: &InspireParams) -> Engine<RavenInspireScheme> {
    let db: Vec<u8> = (0..TOY_ENTRIES)
        .flat_map(|i| {
            (0..TOY_ENTRY_BYTES).map(move |j| u8::try_from((i + j) % 251).expect("< 251"))
        })
        .collect();
    let (state, _sk) =
        setup_state(params, &db, TOY_ENTRY_BYTES, InspireVariant::TwoPacking).expect("toy state");
    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    let instance = PirInstance::new(InstanceId::new(INSTANCE_ID), InstanceRole::Live, state);
    engine.add_instance(instance).expect("register instance");
    engine
}

fn build_router_with_engine(engine: Engine<RavenInspireScheme>) -> axum::Router {
    let cfg = HttpConfig::demo(READ_TOKEN);
    let app_state = {
        let _g = APPSTATE_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        AppState::new(engine, cfg).expect("appstate")
    };
    inspire_router(app_state).expect("router build")
}

fn build_params_request(token: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method(Method::GET)
        .uri(format!("/v1/instance/{INSTANCE_ID}/params"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("build params req");
    inject_connect_info(&mut req);
    req
}

async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    resp.into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec()
}

/// Positive: the response envelope decodes to an `InstanceParams`
/// whose `inspire_params_bincode` field carries non-empty bytes and
/// whose schema version matches `WIRE_SCHEMA_VERSION`.
#[tokio::test]
async fn instance_params_response_includes_inspire_params_bincode_v2() {
    let params = InspireParams::secure_128_d2048();
    let engine = build_engine_with_one_instance(&params);
    let router = build_router_with_engine(engine);

    let resp = router
        .clone()
        .oneshot(build_params_request(READ_TOKEN))
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK, "params endpoint must 200");
    let bytes = body_bytes(resp).await;

    let decoded: InstanceParams = read_versioned(&bytes).expect("decode versioned InstanceParams");
    assert_eq!(
        decoded.wire_schema_version, WIRE_SCHEMA_VERSION,
        "wire schema must remain v{WIRE_SCHEMA_VERSION}"
    );
    assert!(
        !decoded.crs_bincode.is_empty(),
        "crs_bincode must be populated"
    );
    assert!(
        !decoded.shard_config_bincode.is_empty(),
        "shard_config_bincode must be populated"
    );
    assert!(
        !decoded.inspire_params_bincode.is_empty(),
        "inspire_params_bincode must be populated for self-bootstrap"
    );
    assert_eq!(decoded.entry_size, TOY_ENTRY_BYTES);
}

/// Round-trip: the `inspire_params_bincode` bytes decode into a
/// `raven_inspire::params::InspireParams` value byte-equal to the
/// preset the engine was bootstrapped with (`secure_128_d2048`).
#[tokio::test]
async fn instance_params_inspire_params_decodes_to_secure_128_d2048() {
    let params = InspireParams::secure_128_d2048();
    let engine = build_engine_with_one_instance(&params);
    let router = build_router_with_engine(engine);

    let resp = router
        .oneshot(build_params_request(READ_TOKEN))
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_bytes(resp).await;

    let decoded: InstanceParams = read_versioned(&bytes).expect("decode envelope");
    let recovered_params: InspireParams =
        bincode::deserialize(&decoded.inspire_params_bincode).expect("decode InspireParams");
    let expected = InspireParams::secure_128_d2048();

    // Field-by-field equality: `InspireParams` doesn't derive `Eq`,
    // but every constituent field is hashable / comparable. Spot-check
    // the load-bearing ones the WASM client reads in
    // `build_instance_params_blob` (sigma drives the sampler, ring_dim
    // drives the secret-key shape).
    assert_eq!(recovered_params.ring_dim, expected.ring_dim);
    assert_eq!(recovered_params.q, expected.q);
    assert_eq!(recovered_params.crt_moduli, expected.crt_moduli);
    assert_eq!(recovered_params.p, expected.p);
    assert!(
        (recovered_params.sigma - expected.sigma).abs() < f64::EPSILON,
        "sigma must round-trip exactly"
    );
    assert_eq!(recovered_params.gadget_base, expected.gadget_base);
    assert_eq!(recovered_params.gadget_len, expected.gadget_len);

    // Sanity: the CRS + shard-config blobs round-trip too. This is
    // the tuple the wallet hands to `build_client_session`; if any
    // of the three blobs gets corrupted, bootstrap fails.
    let _crs: ServerCrs = bincode::deserialize(&decoded.crs_bincode).expect("decode ServerCrs");
    let _shard: ShardConfig =
        bincode::deserialize(&decoded.shard_config_bincode).expect("decode ShardConfig");
}
