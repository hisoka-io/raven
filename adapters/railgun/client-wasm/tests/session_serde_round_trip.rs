//! Session-blob round-trip tests for the WASM warm-cache path.
//!
//! At the locked upstream pin `119641b`, [`raven_inspire::ClientSession`]
//! does NOT derive `Clone` / `Serialize` / `Deserialize`. The Phase 6
//! warm-cache decision (option (a), "ship-with-warm-cache-deferred")
//! means the SDK calls [`serialize_client_session`] and
//! [`deserialize_client_session`] survive at the ABI but every
//! invocation surfaces a typed `Err`. These tests lock the typed-error
//! shape so a future pin bump that lands the derives surfaces here as a
//! failure (the bodies will switch from `Err` to `Ok` and the test
//! suite must be updated in lockstep).
//!
//! Companion tests cover the pre-validation paths that DO run before
//! the deferred-symbol stop fires:
//! - CRS ring_dim drift against the params bundle's `InspireParams`.
//! - Session-blob byte-length cap (256 MiB trusted ceiling).
//! - Untrusted 64 MiB cap unchanged for HTTP-sourced bincode payloads.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::uninlined_format_args
)]

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, ShardConfig};
use raven_inspire::{setup as inspire_setup, ClientSession};

use raven_inspire_client_wasm::{
    decode_capped_for_test, decode_trusted_for_test, deserialize_client_session_rust,
    serialize_client_session_rust, WASM_BINCODE_DESERIALIZE_LIMIT_BYTES,
    WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES,
};

const ENTRY_BYTES: usize = 32;

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

fn build_test_db(params: &InspireParams) -> Vec<u8> {
    let num_entries = params.ring_dim;
    (0..(num_entries * ENTRY_BYTES))
        .map(|i| (i % 251) as u8)
        .collect()
}

/// `WasmInstanceParamsBundle` mirror used for test fixtures. The
/// upstream type is crate-private inside the WASM lib (so the SDK
/// only sees it as bincode bytes); here we reconstruct the same wire
/// shape with serde-eq fields so tests can build a bundle without a
/// private API.
#[derive(serde::Serialize)]
#[allow(clippy::struct_field_names)]
struct TestParamsBundle {
    inspire_params_bincode: Vec<u8>,
    shard_config_bincode: Vec<u8>,
    rlwe_secret_key_bincode: Vec<u8>,
}

fn make_params_bundle(
    params: &InspireParams,
    shard_config: &ShardConfig,
    sk: &raven_inspire::rlwe::RlweSecretKey,
) -> Vec<u8> {
    let bundle = TestParamsBundle {
        inspire_params_bincode: bincode::serialize(params).expect("serialize params"),
        shard_config_bincode: bincode::serialize(shard_config).expect("serialize shard"),
        rlwe_secret_key_bincode: bincode::serialize(sk).expect("serialize sk"),
    };
    bincode::serialize(&bundle).expect("serialize bundle")
}

/// At the locked upstream pin `119641b`, [`ClientSession`] does not
/// implement `Serialize`. The wasm-bindgen `serialize_client_session`
/// (and its pure-Rust mirror) ship at the ABI but surface a typed
/// `Err` carrying the Phase 6 (a) deferral wording. This test locks
/// the wording so an upstream pin bump that lands the derives flips
/// the test red — at which point the body switches from `Err` to
/// `Ok` and the round-trip closure can be re-enabled.
#[test]
fn wasm_session_serialize_returns_typed_err_until_upstream_derives_land() {
    let params = test_params();
    let database = build_test_db(&params);
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, _encoded_db, sk) =
        inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");

    let mut sampler_session = GaussianSampler::new(params.sigma);
    let session = ClientSession::new(crs, sk, &mut sampler_session).expect("session");

    let err = serialize_client_session_rust(&session)
        .expect_err("ClientSession serde unsupported at the locked submodule pin");
    assert!(
        err.contains("lacks Clone+Serialize+Deserialize derives"),
        "expected the Phase 6 (a) deferral wording, got: {err}"
    );
    assert!(
        err.contains("Phase 6 (a)"),
        "expected the explicit Phase 6 (a) tag, got: {err}"
    );
}

/// Symmetric to the serialize test: the deserialize entry point also
/// surfaces a typed `Err` with the deferral wording. This test inputs
/// valid params + CRS bytes + a small dummy session blob so the
/// CRS/params validation passes; the deferral `Err` is the final
/// return.
#[test]
fn wasm_session_deserialize_returns_typed_err_until_upstream_derives_land() {
    let params = test_params();
    let database = build_test_db(&params);
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");

    let bundle_bytes = make_params_bundle(&params, &encoded_db.config, &sk);
    let crs_bytes = bincode::serialize(&crs).expect("serialize crs");

    // 16-byte stub: under the trusted cap and under any plausible
    // bincode prefix, so the pre-checks pass and the deferred-symbol
    // stop fires.
    let session_stub = vec![0u8; 16];

    let err = deserialize_client_session_rust(&bundle_bytes, &crs_bytes, &session_stub)
        .expect_err("ClientSession serde unsupported at the locked submodule pin");
    assert!(
        err.contains("lacks Clone+Serialize+Deserialize derives"),
        "expected the Phase 6 (a) deferral wording, got: {err}"
    );
}

/// Ring-dim drift between the params bundle's `InspireParams` and the
/// supplied CRS surfaces as a typed `Err` BEFORE the deferred-symbol
/// stop fires. This validates the pre-check path the SDK relies on to
/// detect CRS rotation against a stale cached bundle.
#[test]
fn wasm_session_deserialize_validates_ring_dim_drift() {
    let params = test_params();
    let database = build_test_db(&params);
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");

    // Build a params bundle whose `InspireParams::ring_dim` differs
    // from the CRS. The honest mismatch path: clone the params,
    // bump ring_dim, re-bincode the bundle. The CRS still carries
    // the original (256) ring_dim so the pre-check must fire.
    let mut drifted_params = params.clone();
    drifted_params.ring_dim = 512;
    let drifted_bundle = TestParamsBundle {
        inspire_params_bincode: bincode::serialize(&drifted_params).expect("serialize params"),
        shard_config_bincode: bincode::serialize(&encoded_db.config).expect("serialize shard"),
        rlwe_secret_key_bincode: bincode::serialize(&sk).expect("serialize sk"),
    };
    let drifted_bundle_bytes = bincode::serialize(&drifted_bundle).expect("serialize bundle");
    let crs_bytes = bincode::serialize(&crs).expect("serialize crs");
    let session_stub = vec![0u8; 16];

    let err = deserialize_client_session_rust(&drifted_bundle_bytes, &crs_bytes, &session_stub)
        .expect_err("ring_dim mismatch must surface as typed Err");
    assert!(
        err.contains("CRS ring_dim"),
        "expected CRS ring_dim drift wording, got: {err}"
    );
    assert!(
        err.contains("InspireParams ring_dim"),
        "expected InspireParams ring_dim drift wording, got: {err}"
    );
}

/// Boundary: one byte past the trusted cap must trigger the
/// slice-length pre-check before any bincode work runs. Drop the
/// buffer immediately so it does not pin 256 MiB of RSS for the rest
/// of the test process.
#[test]
fn wasm_session_deserialize_rejects_oversize_blob_with_typed_error() {
    let params = test_params();
    let database = build_test_db(&params);
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");

    let bundle_bytes = make_params_bundle(&params, &encoded_db.config, &sk);
    let crs_bytes = bincode::serialize(&crs).expect("serialize crs");

    let err = {
        let oversize = vec![0u8; WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES + 1];
        deserialize_client_session_rust(&bundle_bytes, &crs_bytes, &oversize)
            .expect_err("oversize blob must error")
    };
    assert!(
        err.contains("size limit reached"),
        "expected size-limit error, got: {err}"
    );
}

/// Trusted cap admits payloads at the 256 MiB boundary: the
/// slice-length pre-check must NOT fire. The helper either decodes
/// or surfaces a typed bincode-decode error from the body (the
/// zero-filled buffer is not a valid `ClientSession` bincode prefix
/// — but that's a body error, not a cap error). Either outcome
/// proves cap admission.
#[test]
fn wasm_session_trusted_cap_admits_payload_at_256_mib_boundary() {
    let outcome = {
        let bytes = vec![0u8; WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES];
        decode_trusted_for_test::<Vec<u8>>(&bytes, "client_session_boundary")
    };
    if let Err(ref err) = outcome {
        assert!(
            !err.contains("size limit reached"),
            "trusted cap must admit payloads at the 256 MiB boundary; got cap rejection: {err}"
        );
        assert!(
            err.contains("bincode deserialize client_session_boundary"),
            "expected the typed Decode error wording for client_session_boundary, got: {err}"
        );
    }
}

/// Defense-in-depth: the original 64 MiB cap remains the enforcement
/// point for HTTP-sourced bincode payloads routed through
/// `decode_capped_for_test`. A regression that widens the untrusted
/// cap surfaces here.
#[test]
fn wasm_untrusted_cap_unchanged_at_64_mib_for_http_sourced_bytes() {
    let err = {
        let bytes = vec![0u8; WASM_BINCODE_DESERIALIZE_LIMIT_BYTES + 1];
        decode_capped_for_test::<Vec<u8>>(&bytes, "http_payload")
            .expect_err("64 MiB+1 payload must be rejected by the untrusted cap")
    };
    assert!(
        err.contains("size limit reached"),
        "expected the cap-rejection wording 'size limit reached', got: {err}"
    );
}
