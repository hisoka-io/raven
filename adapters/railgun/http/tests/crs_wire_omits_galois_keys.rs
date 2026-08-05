//! `/v1/instance/{id}/params` ships a CRS without `galois_keys` - ~99.98% of the
//! serialized bytes, read only by the server's own `Tree` path.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::PoisonError;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::{
    extract_inspiring, extract_with_variant, query, query_seeded, respond_seeded_inspiring,
    respond_with_variant, PackingMode, ServerCrs,
};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{setup_state, InspireServerState, RavenInspireScheme};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
use raven_railgun_http::{inspire_router, read_versioned, AppState, HttpConfig, InstanceParams};
use tower::ServiceExt;

const READ_TOKEN: &str = "BEARER-CRS-WIRE-TEST-padded-min-len-aabb";
const INSTANCE_ID: &str = "crs-wire-instance";
const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_BYTES: usize = 32;
const TARGET_INDEX: usize = 7;

/// `AppState::new` registers a process-global Prometheus recorder; serialize across tests.
static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn toy_database() -> Vec<u8> {
    (0..TOY_ENTRIES)
        .flat_map(|i| {
            (0..TOY_ENTRY_BYTES).map(move |j| u8::try_from((i * 7 + j * 11) % 251).expect("< 251"))
        })
        .collect()
}

fn expected_entry(db: &[u8], index: usize) -> &[u8] {
    &db[index * TOY_ENTRY_BYTES..(index + 1) * TOY_ENTRY_BYTES]
}

fn build_state(params: &InspireParams) -> (InspireServerState, RlweSecretKey, Vec<u8>) {
    let db = toy_database();
    let (state, sk) =
        setup_state(params, &db, TOY_ENTRY_BYTES, InspireVariant::TwoPacking).expect("toy state");
    (state, sk, db)
}

async fn fetch_wire_crs(state: InspireServerState) -> Vec<u8> {
    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    let instance = PirInstance::new(InstanceId::new(INSTANCE_ID), InstanceRole::Live, state);
    engine.add_instance(instance).expect("register instance");

    let router = {
        let _g = APPSTATE_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        let app_state = AppState::new(engine, HttpConfig::demo(READ_TOKEN)).expect("appstate");
        inspire_router(app_state).expect("router build")
    };

    let mut req = Request::builder()
        .method(Method::GET)
        .uri(format!("/v1/instance/{INSTANCE_ID}/params"))
        .header(header::AUTHORIZATION, format!("Bearer {READ_TOKEN}"))
        .body(Body::empty())
        .expect("build params req");
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        12_345,
    )));

    let resp = router.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK, "params endpoint must 200");
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec();
    let decoded: InstanceParams = read_versioned(&bytes).expect("decode versioned InstanceParams");
    decoded.crs_bincode
}

#[tokio::test]
async fn params_crs_drops_galois_keys_and_keeps_every_serialized_field() {
    let params = InspireParams::secure_128_d2048();
    let (state, _sk, _db) = build_state(&params);
    let full = state.crs.as_ref().clone();
    let full_bytes = full.to_versioned_bytes().expect("full crs bytes");
    let full_round_tripped = ServerCrs::from_versioned_bytes(&full_bytes).expect("decode full crs");

    let wire_bytes = fetch_wire_crs(state).await;
    let wire = ServerCrs::from_versioned_bytes(&wire_bytes).expect("decode wire crs");

    assert_eq!(
        full.galois_keys.len(),
        params.ring_dim.trailing_zeros() as usize,
        "the server's own CRS keeps one galois key per packing level"
    );
    assert!(
        wire.galois_keys.is_empty(),
        "the wire CRS must carry no galois keys"
    );
    assert!(
        full_bytes.len() > 1_000_000,
        "in-memory CRS is over a megabyte at d=2048 (got {})",
        full_bytes.len()
    );
    assert!(
        wire_bytes.len() < 4_096,
        "wire CRS must be under 4 KiB (got {})",
        wire_bytes.len()
    );

    assert_eq!(wire.params.ring_dim, full.params.ring_dim);
    assert_eq!(wire.params.q, full.params.q);
    assert_eq!(wire.params.p, full.params.p);
    assert_eq!(wire.params.crt_moduli, full.params.crt_moduli);
    assert_eq!(wire.rgsw_gadget.base, full.rgsw_gadget.base);
    assert_eq!(wire.rgsw_gadget.len, full.rgsw_gadget.len);
    assert_eq!(wire.inspiring_w_seed, full.inspiring_w_seed);
    assert_eq!(wire.inspiring_v_seed, full.inspiring_v_seed);
    assert_eq!(wire.inspiring_num_columns, full.inspiring_num_columns);

    // Both are `#[serde(skip)]`, so the full CRS loses them on its own round trip.
    assert!(wire.inspiring_pack_params.is_none());
    assert!(wire.inspiring_packing_key.is_none());
    assert!(
        full_round_tripped.inspiring_pack_params.is_none()
            && full_round_tripped.inspiring_packing_key.is_none(),
        "serde(skip) fields never survive serialization, trimmed or not"
    );
}

#[tokio::test]
async fn wire_crs_drives_the_inspiring_round_trip() {
    let params = InspireParams::secure_128_d2048();
    let (state, sk, db) = build_state(&params);
    let full = state.crs.as_ref().clone();
    let encoded_db = std::sync::Arc::clone(&state.encoded_db);
    let shard_config = encoded_db.config.clone();

    let wire_bytes = fetch_wire_crs(state).await;
    let wire = ServerCrs::from_versioned_bytes(&wire_bytes).expect("decode wire crs");

    let mut sampler = GaussianSampler::new(params.sigma);
    let (client_state, client_query) =
        query_seeded(&wire, TARGET_INDEX as u64, &shard_config, &sk, &mut sampler)
            .expect("seeded query from the wire CRS");
    assert_eq!(
        client_query.packing_mode,
        PackingMode::Inspiring,
        "the wire CRS must still select the production packing mode"
    );

    let response =
        respond_seeded_inspiring(&full, &encoded_db, &client_query).expect("server respond");
    let recovered = extract_inspiring(&wire, &client_state, &response, TOY_ENTRY_BYTES)
        .expect("extract with the wire CRS");

    assert_eq!(
        recovered,
        expected_entry(&db, TARGET_INDEX),
        "wire CRS must recover the queried entry byte-for-byte"
    );
}

#[tokio::test]
async fn tree_round_trip_survives_on_the_server_crs() {
    let params = InspireParams::secure_128_d2048();
    let (state, sk, db) = build_state(&params);
    let crs = state.crs.as_ref();
    let shard_config = state.encoded_db.config.clone();

    let mut sampler = GaussianSampler::new(params.sigma);
    let (client_state, mut client_query) =
        query(crs, TARGET_INDEX as u64, &shard_config, &sk, &mut sampler).expect("query");
    client_query.packing_mode = PackingMode::Tree;

    let response = respond_with_variant(
        crs,
        &state.encoded_db,
        &client_query,
        InspireVariant::OnePacking,
    )
    .expect("tree respond");
    let recovered = extract_with_variant(
        crs,
        &client_state,
        &response,
        TOY_ENTRY_BYTES,
        InspireVariant::OnePacking,
    )
    .expect("tree extract");

    assert_eq!(
        recovered,
        expected_entry(&db, TARGET_INDEX),
        "the Tree path must still round-trip on a CRS that keeps its galois keys"
    );
}
