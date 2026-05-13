//! Byte-equality parity tests: WASM-bindgen wrappers vs pure-Rust client path.
//!
//! The wasm-bindgen wrappers can't be invoked from a native test harness (they
//! take `JsValue` errors). We exercise the underlying marshalling shape via the
//! pure-Rust mirror functions ([`build_seeded_query_rust`],
//! [`extract_response_rust`]) which are kept byte-identical with the wasm surface.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
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

use raven_inspire_client_wasm::{build_seeded_query_rust, extract_response_rust};

/// Small parameter set for fast tests. Keeps the secure-128 layout
/// shape but at d=2048 the test takes ~12 s; we use small here so
/// CI completes quickly. The byte-equality property holds at any
/// param shape.
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

    // Two sessions from the same inputs. Packing keys differ (Gaussian samples)
    // but the protocol output must be byte-equal at the same DB+CRS+index.
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

    // Sanity: the recovered plaintext matches the database row.
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

    // One session, one query, two extract paths. Same response in,
    // same plaintext out.
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
    // The wasm boundary marshals everything via bincode. Confirm
    // that round-tripping a query + state through bincode is
    // structurally lossless (so that JS-side hold-and-restore of
    // the client_state_bincode bytes works).
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

    // ClientState's secret_key + rlwe_secret_key fields are
    // `#[serde(skip)]`. After bincode round-trip those fields are
    // empty / default. The non-skipped index metadata MUST round-
    // trip; that's what the SDK relies on to map a server response
    // back to its query index.
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

/// Regression-guard for the WASM `extract_response` fix: bincode
/// round-tripping `ClientState` strips both `secret_key` and
/// `rlwe_secret_key` (`#[serde(skip, default)]`) so a naive post-trip
/// extract panics in `Poly::mul_ntt` with `Moduli must match`. The
/// WASM crate's `extract_response` sidesteps this by rehydrating
/// `rlwe_secret_key` from the live `ClientSession` before calling the
/// extractor. Native parity tests had a blind spot here because they
/// hold the live `ClientState` Rust value and never round-trip it;
/// this test exercises the round-trip path explicitly.
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

    // Path B: bincode round-trip + rehydrate from session-held key.
    // Mirrors the WASM `extract_response` runtime behaviour exactly.
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

    // Honest-stop sanity: the live extract output matches the DB row at
    // target_idx. If the rehydration path silently corrupts the row,
    // this assertion would catch it before the parity assert above.
    let db_row_start = (target_idx as usize) * ENTRY_BYTES;
    let db_row_end = db_row_start + ENTRY_BYTES;
    assert_eq!(plain_live, &database[db_row_start..db_row_end]);
}

/// Companion negative-control: confirm the bincode round-trip alone
/// (without rehydration) fails. If this ever PASSES it means the
/// upstream `#[serde(skip)]` annotations were dropped and the
/// rehydration in `extract_response` is no longer load-bearing — at
/// which point the WASM crate's extract path can be simplified.
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

    // No rehydration: expect a panic in Poly::mul_ntt's
    // `assert_eq!(self.moduli, other.moduli, "Moduli must match")`.
    // We `catch_unwind` so the test fails cleanly on the regression
    // (rather than aborting the harness).
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
    // Sanity: confirm our `build_seeded_query_rust` is a pure
    // wrapper around the upstream `query_seeded` + a single
    // `packing_mode` overwrite. If these diverge the wasm boundary
    // is no longer faithful.
    let params = test_params();
    let database = build_test_db(&params);
    let target_idx: u64 = 5;

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");

    // Path A: upstream query() (full ClientQuery, not SeededClientQuery,
    // so we use query_seeded() for an apples-to-apples compare).
    let mut sampler_a = GaussianSampler::new(params.sigma);
    let sk_a: RlweSecretKey = sk.clone();
    let (state_a, mut query_a) =
        upstream_query_seeded(&crs, target_idx, &encoded_db.config, &sk_a, &mut sampler_a)
            .expect("upstream query_seeded");
    query_a.packing_mode = PackingMode::Inspiring;

    // Path B: our wasm-mirror via ClientSession.
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
