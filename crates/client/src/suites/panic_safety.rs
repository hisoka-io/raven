//! Failure-injection tests: pathological input must surface as a typed `Err` or a
//! caught panic, never as an unhandled WASM trap. Run against the pure-Rust mirrors
//! since the wasm-bindgen wrappers take `JsValue` and can't run natively.

// `catch_unwind` does not unwind on wasm32-unknown-unknown, and proptest is a
// cfg(not(wasm32)) dev-dep for the getrandom reason in Cargo.toml, so this file has no
// wasm32 form. Gated rather than left to fail the wasm32 --all-targets lane.
#![cfg(not(target_arch = "wasm32"))]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::panic::{self, AssertUnwindSafe};

use proptest::prelude::*;
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::InspireParams;
use raven_inspire::respond_seeded_inspiring_cached_with_session;
use raven_inspire::{
    setup as inspire_setup, ClientSession, ServerInspiringCache, ServerSessionStore,
};

use raven_client::{
    build_seeded_query_rust, decode_capped_for_test, deserialize_client_session_rust,
    extract_response_rust, WASM_BINCODE_DESERIALIZE_LIMIT_BYTES,
};

fn small_params() -> InspireParams {
    InspireParams {
        ring_dim: 256,
        q: 1_152_921_504_606_830_593,
        crt_moduli: vec![1_152_921_504_606_830_593],
        p: 65_537,
        sigma: 6.4,
        gadget_base: 1 << 20,
        query_gadget_len: 3,
        packing_gadget_len: 3,
        security_level: raven_inspire::params::SecurityLevel::Bits128,
    }
}

const ENTRY_BYTES: usize = 32;

fn build_test_db(params: &InspireParams) -> Vec<u8> {
    let n = params.ring_dim;
    (0..(n * ENTRY_BYTES)).map(|i| (i % 251) as u8).collect()
}

/// Mirror of the crate-private `WasmInstanceParamsBundle` (same field order; bincode
/// layout is field-ordered), so the magic-prefix arm below can reach `check_magic`
/// through the shipped `deserialize_client_session_rust` entry point.
#[derive(serde::Serialize)]
#[allow(clippy::struct_field_names)]
struct ParamsBundleMirror {
    inspire_params_bincode: Vec<u8>,
    shard_config_bincode: Vec<u8>,
    rlwe_secret_key_bincode: Vec<u8>,
}

fn valid_bundle_bytes() -> &'static [u8] {
    static BUNDLE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    BUNDLE.get_or_init(|| {
        let params = bincode::serialize(&small_params()).expect("params");
        bincode::serialize(&ParamsBundleMirror {
            inspire_params_bincode: params,
            shard_config_bincode: Vec::new(),
            rlwe_secret_key_bincode: Vec::new(),
        })
        .expect("bundle")
    })
}

/// Zero-filled deliberately: if the cap pre-check is ever removed, bincode reads a
/// zero length prefix and decodes an EMPTY `Vec<u8>` Ok, so the Err assertion below
/// fails loud instead of a huge length prefix attempting a giant allocation.
fn over_cap_bytes() -> &'static [u8] {
    static OVER: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    OVER.get_or_init(|| vec![0u8; WASM_BINCODE_DESERIALIZE_LIMIT_BYTES + 1])
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

    /// The SHIPPED decode surface, not raw `bincode::deserialize`: arbitrary bytes
    /// through the capped decode must never panic; the 64 MiB length-prefix cap must
    /// hold; and garbage in the versioned-CRS position must fail the magic check as a
    /// typed Err. The retired example this replaces called `bincode::deserialize`
    /// directly and stayed green with the cap and CRS-version paths deleted outright.
    #[test]
    fn decode_surface_never_panics_prop(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        macro_rules! no_panic_decode {
            ($t:ty, $what:literal) => {
                let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
                    decode_capped_for_test::<$t>(&bytes, $what)
                }));
                prop_assert!(outcome.is_ok(), "capped decode of {} panicked", $what);
            };
        }
        no_panic_decode!(raven_inspire::ServerCrs, "server_crs");
        no_panic_decode!(raven_inspire::ServerResponse, "server_response");
        no_panic_decode!(raven_inspire::ClientState, "client_state");
        no_panic_decode!(raven_inspire::SeededClientQuery, "seeded_client_query");
        no_panic_decode!(raven_inspire::params::ShardConfig, "shard_config");
        no_panic_decode!(raven_inspire::rlwe::RlweSecretKey, "rlwe_secret_key");
        no_panic_decode!(InspireParams, "inspire_params");

        // length-prefix path: one byte past the cap must be refused BY THE CAP
        match decode_capped_for_test::<Vec<u8>>(over_cap_bytes(), "over_cap") {
            Ok(v) => prop_assert!(false, "cap+1 bytes decoded Ok ({} elems): the 64 MiB cap is gone", v.len()),
            Err(err) => prop_assert!(err.contains("size limit reached"), "got: {err}"),
        }

        // magic-prefix path: arbitrary bytes in the CRS position surface as a typed
        // Err (Ok would need the version magic AND the 16-byte session stub to decode
        // as a valid residue) and never as a panic
        let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
            deserialize_client_session_rust(valid_bundle_bytes(), &bytes, &[0u8; 16])
        }));
        match outcome {
            Ok(inner) => prop_assert!(inner.is_err()),
            Err(_) => prop_assert!(false, "deserialize_client_session_rust panicked"),
        }
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
    // (crates/inspire/src/math/poly.rs); must surface as Err or caught panic
    let inflated_entry_size = (params.ring_dim + 1) * 2;
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        extract_response_rust(&crs, &state, &response, inflated_entry_size)
    }));
    assert!(
        !matches!(outcome, Ok(Ok(_))),
        "entry_size {inflated_entry_size} exceeds ring_dim: extraction must \
         fail closed with Err or a caught panic, never return a decoded value"
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
    assert!(
        inner.is_err(),
        "entry_size=0 is not a legal cell width and must fail closed, got {inner:?}"
    );
}

#[test]
fn build_seeded_query_with_oob_target_idx_panics_in_upstream_caught_by_panic_hook() {
    // out-of-range target_idx hits an upstream `expect` in
    // `ShardConfig::index_to_shard`. catch_unwind here stands in for the WASM
    // `init_panic_hook` net that turns the same panic into a JS Error instead
    // of an opaque trap.
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
