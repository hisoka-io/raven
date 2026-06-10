//! Byte-equality parity tests via the pure-Rust mirrors, which are kept identical
//! to the wasm-bindgen wrappers (the wrappers take `JsValue` and can't run natively).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing
)]

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, ShardConfig};
use raven_inspire::query_seeded as upstream_query_seeded;
use raven_inspire::respond_seeded_inspiring_cached_with_session;
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::{
    extract_inspiring, setup as inspire_setup, ClientSession, PackingMode, SeededClientQuery,
    ServerInspiringCache, ServerResponse, ServerSessionStore,
};

use raven_client::{build_seeded_query_rust, extract_response_rust};

/// Small params for fast CI; the byte-equality property holds at any param shape.
fn test_params() -> InspireParams {
    InspireParams {
        ring_dim: 256,
        q: 1_152_921_504_606_830_593,
        crt_moduli: vec![1_152_921_504_606_830_593],
        p: 65_537,
        sigma: 6.4,
        gadget_base: 1 << 20,
        gadget_len: 3,
        security_level: raven_inspire::params::SecurityLevel::Bits128,
    }
}

const ENTRY_BYTES: usize = 32;

fn build_test_db(params: &InspireParams) -> Vec<u8> {
    let num_entries = params.ring_dim;
    (0..(num_entries * ENTRY_BYTES))
        .map(|i| (i % 251) as u8)
        .collect()
}

#[test]
fn wasm_query_byte_equals_native_when_session_seed_is_pinned() {
    let params = test_params();
    let database = build_test_db(&params);
    let target_idx: u64 = 7;

    // Both clients share the same SK so the comparison is byte-exact.
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");

    // packing keys differ across the two sessions, but protocol output is byte-equal
    let mut sampler_native = GaussianSampler::new(params.sigma);
    let session_native =
        ClientSession::new(crs.clone(), sk.clone(), &mut sampler_native).expect("session native");

    let mut sampler_wasm_path = GaussianSampler::new(params.sigma);
    let session_wasm =
        ClientSession::new(crs.clone(), sk.clone(), &mut sampler_wasm_path).expect("session wasm");

    let (state_native, query_native) =
        build_seeded_query_rust(&session_native, &params, &encoded_db.config, target_idx)
            .expect("native query");
    let (state_wasm, query_wasm) =
        build_seeded_query_rust(&session_wasm, &params, &encoded_db.config, target_idx)
            .expect("wasm-mirror query");

    assert_eq!(query_native.shard_id, query_wasm.shard_id);
    assert_eq!(query_native.packing_mode, PackingMode::Inspiring);
    assert_eq!(query_wasm.packing_mode, PackingMode::Inspiring);
    assert_eq!(query_native.session_handle, query_wasm.session_handle);
    assert_eq!(state_native.index, target_idx);
    assert_eq!(state_wasm.index, target_idx);
    assert_eq!(state_native.local_index, state_wasm.local_index);
    assert_eq!(state_native.shard_id, state_wasm.shard_id);

    let cache = ServerInspiringCache::new(&crs, &encoded_db).expect("cache");
    let store = ServerSessionStore::new();

    let resp_native: ServerResponse = respond_seeded_inspiring_cached_with_session(
        &crs,
        &encoded_db,
        &query_native,
        &cache,
        Some(&store),
    )
    .expect("respond native");

    let resp_wasm: ServerResponse = respond_seeded_inspiring_cached_with_session(
        &crs,
        &encoded_db,
        &query_wasm,
        &cache,
        Some(&store),
    )
    .expect("respond wasm");

    let plain_native = extract_response_rust(&crs, &state_native, &resp_native, ENTRY_BYTES)
        .expect("extract native");
    let plain_wasm =
        extract_response_rust(&crs, &state_wasm, &resp_wasm, ENTRY_BYTES).expect("extract wasm");

    assert_eq!(
        plain_native, plain_wasm,
        "wasm-mirror and native client paths must recover byte-identical plaintext for the same row"
    );

    let db_row_start = (target_idx as usize) * ENTRY_BYTES;
    let db_row_end = db_row_start + ENTRY_BYTES;
    assert_eq!(
        plain_native,
        &database[db_row_start..db_row_end],
        "wasm-mirror plaintext must match database row at target_idx"
    );
}

#[test]
fn wasm_extract_byte_equals_native() {
    let params = test_params();
    let database = build_test_db(&params);
    let target_idx: u64 = 11;

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");

    let mut sampler_session = GaussianSampler::new(params.sigma);
    let session = ClientSession::new(crs.clone(), sk, &mut sampler_session).expect("session");

    let (state, query) =
        build_seeded_query_rust(&session, &params, &encoded_db.config, target_idx).expect("query");

    let cache = ServerInspiringCache::new(&crs, &encoded_db).expect("cache");
    let store = ServerSessionStore::new();
    let response = respond_seeded_inspiring_cached_with_session(
        &crs,
        &encoded_db,
        &query,
        &cache,
        Some(&store),
    )
    .expect("respond");

    let plain_via_mirror =
        extract_response_rust(&crs, &state, &response, ENTRY_BYTES).expect("mirror extract");
    let plain_via_upstream =
        extract_inspiring(&crs, &state, &response, ENTRY_BYTES).expect("upstream extract");

    assert_eq!(
        plain_via_mirror, plain_via_upstream,
        "wasm-mirror extract_response must produce byte-identical output to upstream extract_inspiring"
    );
}

#[test]
fn bincode_roundtrip_preserves_query_and_state_shapes() {
    // JS-side hold-and-restore relies on bincode round-trip being structurally lossless
    let params = test_params();
    let database = build_test_db(&params);
    let target_idx: u64 = 3;

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");

    let mut sampler_session = GaussianSampler::new(params.sigma);
    let session = ClientSession::new(crs.clone(), sk, &mut sampler_session).expect("session");

    let (state, query) =
        build_seeded_query_rust(&session, &params, &encoded_db.config, target_idx).expect("query");

    let query_bytes = bincode::serialize(&query).expect("serialize query");
    let query_rt: SeededClientQuery =
        bincode::deserialize(&query_bytes).expect("deserialize query");
    assert_eq!(query.shard_id, query_rt.shard_id);
    assert_eq!(query.packing_mode, query_rt.packing_mode);

    // keys are serde(skip); only the index metadata round-trips, which is what maps responses to queries
    let state_bytes = bincode::serialize(&state).expect("serialize state");
    let state_rt: raven_inspire::ClientState =
        bincode::deserialize(&state_bytes).expect("deserialize state");
    assert_eq!(state.index, state_rt.index);
    assert_eq!(state.shard_id, state_rt.shard_id);
    assert_eq!(state.local_index, state_rt.local_index);

    let crs_bytes = bincode::serialize(&crs).expect("serialize crs");
    let _crs_rt: raven_inspire::ServerCrs =
        bincode::deserialize(&crs_bytes).expect("deserialize crs");

    let shard_bytes = bincode::serialize(&encoded_db.config).expect("serialize shard config");
    let _shard_rt: ShardConfig =
        bincode::deserialize(&shard_bytes).expect("deserialize shard config");

    let params_bytes = bincode::serialize(&params).expect("serialize params");
    let _params_rt: InspireParams =
        bincode::deserialize(&params_bytes).expect("deserialize params");
}

/// Round-trip strips serde(skip) keys; `extract_response` must rehydrate
/// `rlwe_secret_key` from the session or `Poly::mul_ntt` panics with `Moduli must
/// match`. Exercises the trip explicitly since live-value tests never hit it.
#[test]
fn bincode_roundtrip_then_rehydrate_extracts_byte_identical_to_live_state() {
    let params = test_params();
    let database = build_test_db(&params);
    let target_idx: u64 = 13;

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");

    let mut sampler_session = GaussianSampler::new(params.sigma);
    let session = ClientSession::new(crs.clone(), sk, &mut sampler_session).expect("session");

    let (live_state, query) =
        build_seeded_query_rust(&session, &params, &encoded_db.config, target_idx).expect("query");

    let cache = ServerInspiringCache::new(&crs, &encoded_db).expect("cache");
    let store = ServerSessionStore::new();
    let response = respond_seeded_inspiring_cached_with_session(
        &crs,
        &encoded_db,
        &query,
        &cache,
        Some(&store),
    )
    .expect("respond");

    // Path A: live state, no round-trip.
    let plain_live =
        extract_response_rust(&crs, &live_state, &response, ENTRY_BYTES).expect("extract live");

    // Path B: round-trip + rehydrate, mirroring the WASM extract_response runtime path
    let state_bytes = bincode::serialize(&live_state).expect("serialize state");
    let mut state_rt: raven_inspire::ClientState =
        bincode::deserialize(&state_bytes).expect("deserialize state");
    state_rt.rlwe_secret_key = session.rlwe_secret_key().clone();

    let plain_rt =
        extract_response_rust(&crs, &state_rt, &response, ENTRY_BYTES).expect("extract round-trip");

    assert_eq!(
        plain_live, plain_rt,
        "rehydrated round-tripped state must extract byte-identical bytes to live state"
    );

    // also pin against the DB row so silent corruption fails before the parity assert
    let db_row_start = (target_idx as usize) * ENTRY_BYTES;
    let db_row_end = db_row_start + ENTRY_BYTES;
    assert_eq!(plain_live, &database[db_row_start..db_row_end]);
}

/// Negative control: round-trip without rehydration must fail. If it ever passes,
/// upstream dropped `#[serde(skip)]` and the rehydration is no longer load-bearing.
#[test]
fn bincode_roundtrip_without_rehydrate_fails_in_extract() {
    let params = test_params();
    let database = build_test_db(&params);
    let target_idx: u64 = 17;

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");

    let mut sampler_session = GaussianSampler::new(params.sigma);
    let session = ClientSession::new(crs.clone(), sk, &mut sampler_session).expect("session");

    let (live_state, query) =
        build_seeded_query_rust(&session, &params, &encoded_db.config, target_idx).expect("query");

    let cache = ServerInspiringCache::new(&crs, &encoded_db).expect("cache");
    let store = ServerSessionStore::new();
    let response = respond_seeded_inspiring_cached_with_session(
        &crs,
        &encoded_db,
        &query,
        &cache,
        Some(&store),
    )
    .expect("respond");

    let state_bytes = bincode::serialize(&live_state).expect("serialize state");
    let state_rt: raven_inspire::ClientState =
        bincode::deserialize(&state_bytes).expect("deserialize state");

    // no rehydration: expect a panic in Poly::mul_ntt ("Moduli must match"), caught here
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        extract_response_rust(&crs, &state_rt, &response, ENTRY_BYTES)
    }));
    assert!(
        outcome.is_err(),
        "bincode round-trip without rehydration must surface as a Poly::mul_ntt panic; \
         if this passes upstream changed `#[serde(skip)]` and the WASM rehydration is no \
         longer required"
    );
}

#[test]
fn rust_query_path_byte_equals_upstream_query_seeded() {
    // build_seeded_query_rust must stay a thin wrapper over upstream query_seeded + packing_mode set
    let params = test_params();
    let database = build_test_db(&params);
    let target_idx: u64 = 5;

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");

    // Path A: upstream query_seeded directly
    let mut sampler_a = GaussianSampler::new(params.sigma);
    let sk_a: RlweSecretKey = sk.clone();
    let (state_a, mut query_a) =
        upstream_query_seeded(&crs, target_idx, &encoded_db.config, &sk_a, &mut sampler_a)
            .expect("upstream query_seeded");
    query_a.packing_mode = PackingMode::Inspiring;

    // Path B: wasm-mirror via ClientSession
    let mut sampler_b = GaussianSampler::new(params.sigma);
    let session = ClientSession::new(crs.clone(), sk, &mut sampler_b).expect("session");
    let (state_b, query_b) =
        build_seeded_query_rust(&session, &params, &encoded_db.config, target_idx)
            .expect("wasm-mirror query");

    assert_eq!(state_a.index, state_b.index);
    assert_eq!(state_a.shard_id, state_b.shard_id);
    assert_eq!(state_a.local_index, state_b.local_index);
    assert_eq!(query_a.shard_id, query_b.shard_id);
    assert_eq!(query_a.packing_mode, query_b.packing_mode);
}
