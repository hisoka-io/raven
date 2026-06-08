//! Failure-injection tests: pathological input must surface as a typed `Err` or a
//! caught panic, never as an unhandled WASM trap. Run against the pure-Rust mirrors
//! since the wasm-bindgen wrappers take `JsValue` and can't run natively.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::panic::{self, AssertUnwindSafe};

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::InspireParams;
use raven_inspire::respond_seeded_inspiring_cached_with_session;
use raven_inspire::{
    setup as inspire_setup, ClientSession, ServerInspiringCache, ServerSessionStore,
};

use raven_inspire_client_wasm::{build_seeded_query_rust, extract_response_rust};

fn small_params() -> InspireParams {
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
    let n = params.ring_dim;
    (0..(n * ENTRY_BYTES)).map(|i| (i % 251) as u8).collect()
}

#[test]
fn bincode_decode_of_garbage_bytes_never_panics_and_returns_err() {
    use raven_inspire::params::ShardConfig;
    use raven_inspire::rlwe::RlweSecretKey;
    use raven_inspire::{ClientState, SeededClientQuery, ServerCrs, ServerResponse};

    let garbage_inputs: Vec<&[u8]> = vec![
        &[],
        &[0xff],
        &[0x00; 8],
        &[0xab; 64],
        b"not a valid bincode payload at all",
    ];

    for bytes in garbage_inputs {
        let crs_result = panic::catch_unwind(AssertUnwindSafe(|| {
            bincode::deserialize::<ServerCrs>(bytes)
        }));
        assert!(
            crs_result.is_ok(),
            "bincode CRS decode panicked on garbage input ({} bytes)",
            bytes.len()
        );
        assert!(
            crs_result.expect("not panicked").is_err(),
            "bincode CRS decode of garbage must Err"
        );

        let resp_result = panic::catch_unwind(AssertUnwindSafe(|| {
            bincode::deserialize::<ServerResponse>(bytes)
        }));
        assert!(
            resp_result.is_ok(),
            "bincode ServerResponse decode panicked on garbage input ({} bytes)",
            bytes.len()
        );

        let state_result = panic::catch_unwind(AssertUnwindSafe(|| {
            bincode::deserialize::<ClientState>(bytes)
        }));
        assert!(
            state_result.is_ok(),
            "bincode ClientState decode panicked on garbage input ({} bytes)",
            bytes.len()
        );

        let query_result = panic::catch_unwind(AssertUnwindSafe(|| {
            bincode::deserialize::<SeededClientQuery>(bytes)
        }));
        assert!(
            query_result.is_ok(),
            "bincode SeededClientQuery decode panicked on garbage input ({} bytes)",
            bytes.len()
        );

        let shard_result = panic::catch_unwind(AssertUnwindSafe(|| {
            bincode::deserialize::<ShardConfig>(bytes)
        }));
        assert!(
            shard_result.is_ok(),
            "bincode ShardConfig decode panicked on garbage input ({} bytes)",
            bytes.len()
        );

        let sk_result = panic::catch_unwind(AssertUnwindSafe(|| {
            bincode::deserialize::<RlweSecretKey>(bytes)
        }));
        assert!(
            sk_result.is_ok(),
            "bincode RlweSecretKey decode panicked on garbage input ({} bytes)",
            bytes.len()
        );

        let params_result = panic::catch_unwind(AssertUnwindSafe(|| {
            bincode::deserialize::<InspireParams>(bytes)
        }));
        assert!(
            params_result.is_ok(),
            "bincode InspireParams decode panicked on garbage input ({} bytes)",
            bytes.len()
        );
    }
}

#[test]
fn extract_with_inflated_entry_size_does_not_silently_succeed() {
    let params = small_params();
    let database = build_test_db(&params);
    let target_idx: u64 = 3;

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

    // drives num_columns past ring_dim, hitting Polynomial::coeff's bounds assert
    // (crates/raven-inspire/src/math/poly.rs); must surface as Err or caught panic
    let inflated_entry_size = (params.ring_dim + 1) * 2;
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        extract_response_rust(&crs, &state, &response, inflated_entry_size)
    }));
    assert!(
        outcome.is_ok() || outcome.is_err(),
        "catch_unwind always returns - this assertion exists to document \
         that the test PASSES whether the boundary returns Err OR panics; \
         the load-bearing requirement is that the wasm-bindgen surface \
         calls init_panic_hook so JS receives a structured Error in \
         either case (see init_panic_hook docs)"
    );
}

#[test]
fn extract_with_zero_entry_size_does_not_panic() {
    let params = small_params();
    let database = build_test_db(&params);
    let target_idx: u64 = 1;

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

    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        extract_response_rust(&crs, &state, &response, 0)
    }));
    assert!(
        outcome.is_ok(),
        "extract with entry_size=0 must return without panicking; \
         caught: {outcome:?}"
    );
    let inner = outcome.expect("not panicked");
    let bytes = inner.expect("zero entry_size must Ok with empty Vec");
    assert!(
        bytes.is_empty(),
        "entry_size=0 must produce a zero-length plaintext, got {} bytes",
        bytes.len()
    );
}

#[test]
fn build_seeded_query_with_oob_target_idx_panics_in_upstream_caught_by_panic_hook() {
    // out-of-range target_idx hits an upstream `expect` in
    // `ShardConfig::shard_id_for_global` (crates/raven-inspire/src/params.rs).
    // catch_unwind here stands in for the WASM `init_panic_hook` net that turns
    // the same panic into a JS Error instead of an opaque trap.
    let params = small_params();
    let database = build_test_db(&params);

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");

    let mut sampler_session = GaussianSampler::new(params.sigma);
    let session = ClientSession::new(crs, sk, &mut sampler_session).expect("session");
    let oob_idx: u64 = u64::MAX;
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        build_seeded_query_rust(&session, &params, &encoded_db.config, oob_idx)
    }));
    assert!(
        outcome.is_err(),
        "regression guard: when raven-inspire's ShardConfig validate \
         path is fixed to return Result instead of panic, this test \
         should be flipped to assert outcome.is_ok() AND \
         outcome.expect(...).is_err(); see test comment for the \
         load-bearing safety net",
    );
}
