//! Session-blob round-trip tests for the WASM warm-cache path.
//!
//! Upstream `ClientSession` lacks serde derives, so the serialize/deserialize
//! entry points surface a typed `Err`; these tests lock that wording (and the
//! pre-validation paths that run before it) so a derive-landing pin bump fails here.

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

/// Wire-shape mirror of the crate-private `WasmInstanceParamsBundle`.
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

/// Locks the deferral wording `serialize_client_session` returns until upstream
/// `ClientSession` derives `Serialize`; a derive-landing pin bump flips this red.
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
        "expected the upstream-pin deferral wording, got: {err}"
    );
    assert!(
        err.contains("upstream pin lands the derives"),
        "expected the explicit pin-bump-required tag, got: {err}"
    );
}

/// Deserialize counterpart: valid params + CRS + dummy blob pass the pre-checks,
/// then the deferral `Err` is the final return.
#[test]
fn wasm_session_deserialize_returns_typed_err_until_upstream_derives_land() {
    let params = test_params();
    let database = build_test_db(&params);
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");

    let bundle_bytes = make_params_bundle(&params, &encoded_db.config, &sk);
    let crs_bytes = bincode::serialize(&crs).expect("serialize crs");

    // small enough to clear the pre-checks so the deferral stop is what fires
    let session_stub = vec![0u8; 16];

    let err = deserialize_client_session_rust(&bundle_bytes, &crs_bytes, &session_stub)
        .expect_err("ClientSession serde unsupported at the locked submodule pin");
    assert!(
        err.contains("lacks Clone+Serialize+Deserialize derives"),
        "expected the upstream-pin deferral wording, got: {err}"
    );
}

/// ring_dim drift between bundle and CRS must error before the deferral stop:
/// the SDK relies on this to detect CRS rotation against a stale cached bundle.
#[test]
fn wasm_session_deserialize_validates_ring_dim_drift() {
    let params = test_params();
    let database = build_test_db(&params);
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");

    // bundle ring_dim bumped to 512 while the CRS keeps 256, so the pre-check fires
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

/// One byte past the trusted cap triggers the length pre-check before any bincode work.
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

/// At exactly the cap the pre-check must NOT fire; a body decode error still proves admission.
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

/// The 64 MiB cap stays the enforcement point for HTTP-sourced bytes; a widened cap fails here.
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
