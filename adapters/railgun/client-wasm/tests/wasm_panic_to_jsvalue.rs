//! Invalid-input hardening: every export must surface bad input as a typed error
//! or a caught panic, never a WASM trap or native abort. Runs against the pure-Rust
//! mirrors, each wrapped in `catch_unwind`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::single_match_else,
    clippy::match_same_arms
)]

use std::panic::{self, AssertUnwindSafe};

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, ShardConfig};
use raven_inspire::respond_seeded_inspiring_cached_with_session;
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::{
    setup as inspire_setup, ClientSession, ClientState, SeededClientQuery, ServerCrs,
    ServerInspiringCache, ServerResponse, ServerSessionStore,
};

use raven_inspire_client_wasm::{
    build_seeded_query_rust, extract_response_rust, path_indices_for_leaf_rust,
    path_indices_for_per_list_leaf_rust,
};

const ENTRY_BYTES: usize = 32;
const TREE_DEPTH: u32 = 16;
const LEAVES_PER_TREE: u32 = 1u32 << TREE_DEPTH;

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

fn build_test_db(params: &InspireParams) -> Vec<u8> {
    let n = params.ring_dim;
    (0..(n * ENTRY_BYTES)).map(|i| (i % 251) as u8).collect()
}

#[test]
fn path_indices_for_leaf_overflow_returns_typed_err_no_panic() {
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        path_indices_for_leaf_rust(0, LEAVES_PER_TREE)
    }));
    let inner = outcome.expect(
        "path_indices_for_leaf_rust must NOT panic on overflow input; \
         the wasm-bindgen surface returns Result<_, JsValue> for this case",
    );
    let err = inner.expect_err("leaf_idx == 2^TREE_DEPTH must Err");
    assert!(
        err.contains(">= 2^TREE_DEPTH"),
        "error message must surface the overflow detail; got {err}"
    );
}

#[test]
fn path_indices_for_leaf_negative_via_u32_max_cast_returns_typed_err() {
    // u32::MAX models a JS negative-i32-to-u32 cast; must reject typed, never trap
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| path_indices_for_leaf_rust(0, u32::MAX)));
    let inner = outcome.expect("u32::MAX leaf_idx must NOT panic");
    let err = inner.expect_err("u32::MAX must Err");
    assert!(err.contains(">= 2^TREE_DEPTH"), "got {err}");
}

#[test]
fn path_indices_for_leaf_max_valid_leaf_succeeds_with_16_indices() {
    // last valid leaf; locks the off-by-one so a `>=`->`>` or `>=`->`<=` flip fails here
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        path_indices_for_leaf_rust(0, LEAVES_PER_TREE - 1)
    }));
    let inner = outcome.expect("max-valid leaf must NOT panic");
    let indices = inner.expect("max-valid leaf must Ok");
    assert_eq!(indices.len(), 16);
}

#[test]
fn path_indices_for_per_list_leaf_short_list_key_returns_typed_err() {
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        path_indices_for_per_list_leaf_rust(&[0u8; 31], 0)
    }));
    let inner = outcome.expect("short list_key must NOT panic");
    let err = inner.expect_err("31-byte list_key must Err");
    assert!(err.contains("list_key length 31 must be 32"), "got {err}");
}

#[test]
fn path_indices_for_per_list_leaf_long_list_key_returns_typed_err() {
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        path_indices_for_per_list_leaf_rust(&[0u8; 33], 0)
    }));
    let inner = outcome.expect("long list_key must NOT panic");
    let err = inner.expect_err("33-byte list_key must Err");
    assert!(err.contains("list_key length 33 must be 32"), "got {err}");
}

#[test]
fn path_indices_for_per_list_leaf_empty_list_key_returns_typed_err() {
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        path_indices_for_per_list_leaf_rust(&[], 0)
    }));
    let inner = outcome.expect("empty list_key must NOT panic");
    let err = inner.expect_err("0-byte list_key must Err");
    assert!(err.contains("list_key length 0 must be 32"), "got {err}");
}

#[test]
fn path_indices_for_per_list_leaf_overflow_returns_typed_err() {
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        path_indices_for_per_list_leaf_rust(&[0xA7u8; 32], LEAVES_PER_TREE)
    }));
    let inner = outcome.expect("overflow idx must NOT panic");
    let err = inner.expect_err("idx == 2^TREE_DEPTH must Err");
    assert!(err.contains(">= 2^TREE_DEPTH"), "got {err}");
}

#[test]
fn path_indices_for_per_list_leaf_negative_via_u32_max_returns_typed_err() {
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        path_indices_for_per_list_leaf_rust(&[0xA7u8; 32], u32::MAX)
    }));
    let inner = outcome.expect("u32::MAX idx must NOT panic");
    let err = inner.expect_err("u32::MAX idx must Err");
    assert!(err.contains(">= 2^TREE_DEPTH"), "got {err}");
}

#[test]
fn build_seeded_query_oob_target_idx_panics_caught_by_unwind() {
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
    // typed Err or caught panic both pass; the requirement is no native abort
    match outcome {
        Ok(Ok(_)) => {
            panic!("u64::MAX target_idx must surface as Err or caught panic, not silent Ok");
        }
        Ok(Err(_)) | Err(_) => {
            // structured Err or unwind-caught panic
        }
    }
}

#[test]
fn extract_response_inflated_entry_size_returns_or_panics_caught_no_native_abort() {
    let params = small_params();
    let database = build_test_db(&params);
    let target_idx: u64 = 5;

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

    // drives num_columns past ring_dim
    let inflated_entry_size = (params.ring_dim + 1) * 2;
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        extract_response_rust(&crs, &state, &response, inflated_entry_size)
    }));
    match outcome {
        // upstream returned a Result without panicking
        Ok(_) => {}
        // upstream panicked but the unwind was caught (init_panic_hook net)
        Err(_caught_panic) => {}
    }
}

#[test]
fn bincode_decode_garbage_bytes_per_wire_type_returns_err_never_panics() {
    let garbage_inputs: Vec<&[u8]> = vec![
        &[],
        &[0xff],
        &[0x00; 8],
        &[0xab; 64],
        b"absolutely-not-bincode-at-all",
        &[0xff; 4096],
    ];

    for bytes in garbage_inputs {
        let crs = panic::catch_unwind(AssertUnwindSafe(|| {
            bincode::deserialize::<ServerCrs>(bytes)
        }));
        assert!(crs.is_ok(), "ServerCrs decode panicked on garbage input");
        assert!(
            crs.expect("not panicked").is_err(),
            "ServerCrs decode of garbage must Err"
        );

        let resp = panic::catch_unwind(AssertUnwindSafe(|| {
            bincode::deserialize::<ServerResponse>(bytes)
        }));
        assert!(resp.is_ok(), "ServerResponse decode panicked");

        let state = panic::catch_unwind(AssertUnwindSafe(|| {
            bincode::deserialize::<ClientState>(bytes)
        }));
        assert!(state.is_ok(), "ClientState decode panicked");

        let query = panic::catch_unwind(AssertUnwindSafe(|| {
            bincode::deserialize::<SeededClientQuery>(bytes)
        }));
        assert!(query.is_ok(), "SeededClientQuery decode panicked");

        let shard = panic::catch_unwind(AssertUnwindSafe(|| {
            bincode::deserialize::<ShardConfig>(bytes)
        }));
        assert!(shard.is_ok(), "ShardConfig decode panicked");

        let sk = panic::catch_unwind(AssertUnwindSafe(|| {
            bincode::deserialize::<RlweSecretKey>(bytes)
        }));
        assert!(sk.is_ok(), "RlweSecretKey decode panicked");

        let params_dec = panic::catch_unwind(AssertUnwindSafe(|| {
            bincode::deserialize::<InspireParams>(bytes)
        }));
        assert!(params_dec.is_ok(), "InspireParams decode panicked");
    }
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
        "entry_size=0 must not panic; caught: {outcome:?}"
    );
    let bytes = outcome
        .expect("not panicked")
        .expect("zero entry_size must Ok");
    assert!(
        bytes.is_empty(),
        "entry_size=0 must produce empty plaintext, got {} bytes",
        bytes.len()
    );
}
