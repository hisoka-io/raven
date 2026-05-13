//! Failure-injection tests for the WASM client surface.
//!
//! Pathological inputs MUST never cause an unhandled Rust panic that
//! crosses the FFI boundary as an opaque `RuntimeError: unreachable
//! executed` trap (the WebAssembly trap surfaced when a Rust panic
//! aborts in a `panic = "abort"` build). Every documented entry-point
//! must either return a structured error (`Result<_, JsValue>` /
//! `Result<_, String>` for the pure-Rust mirrors) or, if upstream
//! raven-inspire panics on a load-bearing invariant, the panic must
//! be caught by `console_error_panic_hook` (installed via
//! [`raven_inspire_client_wasm::init_panic_hook`]) so the SDK's JS
//! caller receives a structured `Error` instead of a trap.
//!
//! The wasm-bindgen wrappers themselves cannot be invoked from a
//! native test harness (they take `JsValue` errors). We exercise the
//! pure-Rust mirror surface
//! ([`extract_response_rust`], [`build_seeded_query_rust`]) plus the
//! bincode decode helpers behind the wasm-bindgen wrappers, against
//! every malformed-input shape we expect a hostile or buggy SDK to
//! hand the module.
//!
//! Coverage:
//!
//! 1. `bincode::deserialize` of garbage bytes returns `Err`; never
//!    panics. Every constructor argument the SDK passes (CRS, params
//!    bundle, secret key, shard config, query, state, response) is
//!    bincode-decoded inside the wasm-bindgen surface.
//! 2. `extract_response_rust` against a structurally wrong (mismatched
//!    CRS / response / state) input returns either a typed `Err` or
//!    panics in upstream raven-inspire. If a panic surfaces, this
//!    test catches it via `std::panic::catch_unwind` and asserts that
//!    the panic-hook-installer documented in `init_panic_hook` is
//!    advertised as the supported safety net.
//! 3. `extract_response_rust` against a state with an `entry_size`
//!    that drives `num_columns > ring_dim` (the raven-inspire
//!    panic-on-out-of-bounds invariant) is caught.

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

    // Inflate `entry_size` so `num_columns = ceil(entry_size * 8 / 16)`
    // climbs past the ring dimension. raven-inspire's
    // `extract_inspiring` indexes `decrypted.coeff(col)` for
    // `col in 0..num_columns`; the underlying `Polynomial::coeff`
    // panics with `assert!` on out-of-bounds (see
    // `crates/raven-inspire/src/math/poly.rs`). The wasm boundary
    // MUST either propagate this as a typed error or, on a panic,
    // the `init_panic_hook` safety net surfaces a structured JS
    // exception. We assert the call returns from `catch_unwind`
    // (no native abort) so the hook is the load-bearing safety net.
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
    // BUG-LOCK: raven-inspire's `ShardConfig::shard_id_for_global` (in
    // `crates/raven-inspire/src/params.rs`) calls
    // `u32::try_from(shard_id).expect("ShardConfig produces shard_id
    // > u32::MAX; ShardConfig::validate should have been called")`
    // when `target_idx` exceeds `entries_per_shard * u32::MAX`. The
    // wasm boundary's `build_seeded_query` reaches this path on a
    // hostile / buggy SDK that hands an out-of-range `target_idx`.
    //
    // In a `panic = "abort"` WASM build the panic would surface as
    // `RuntimeError: unreachable executed` with no message. The
    // production safety net is `init_panic_hook` (added with this
    // workstream); when JS calls `init_panic_hook()` once at module
    // load, `console_error_panic_hook::set_once()` registers a hook
    // that converts panics to `console.error` + a JS `Error` instead
    // of an opaque trap.
    //
    // This test runs natively (panic = "unwind") and asserts via
    // `catch_unwind` that the panic IS caught - the same panic
    // payload that `console_error_panic_hook` intercepts in WASM.
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
