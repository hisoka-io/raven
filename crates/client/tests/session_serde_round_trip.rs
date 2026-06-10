//! Session-blob round-trip tests for the WASM warm-cache path.
//!
//! `serialize_client_session` encodes the session residue (CRS + secret key +
//! packing-key body, no automorph tables); `deserialize_client_session`
//! rehydrates without rebuilding the tables. These tests prove the blob is small,
//! the rehydrated session decodes a real query e2e, and the cap/drift guards hold.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::uninlined_format_args
)]

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, ShardConfig};
use raven_inspire::{extract_inspiring, respond_inspiring, setup as inspire_setup, ClientSession};

use raven_client::{
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

/// `serialize_client_session` emits a small residue blob - the >160 MiB automorph
/// tables must not be in it.
#[test]
fn wasm_session_serialize_emits_small_residue_blob() {
    let params = test_params();
    let database = build_test_db(&params);
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, _encoded_db, sk) =
        inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");

    let mut sampler_session = GaussianSampler::new(params.sigma);
    let session = ClientSession::new(crs, sk, &mut sampler_session).expect("session");

    let blob = serialize_client_session_rust(&session).expect("serialize residue");
    assert!(!blob.is_empty(), "residue blob must be non-empty");
    assert!(
        blob.len() < 2 * 1024 * 1024,
        "residue blob is {} bytes; expected < 2 MiB (the automorph tables must not persist)",
        blob.len()
    );
}

/// Full warm-cache round-trip: serialize a session, rehydrate from the blob, and
/// prove the rehydrated session queries and decodes the planted entry - the server
/// re-derives y_all from the persisted y_body, so a warm-cache load rebuilds no
/// automorph tables.
#[test]
fn wasm_session_residue_round_trip_decodes() {
    let params = test_params();
    let database = build_test_db(&params);
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");

    let bundle_bytes = make_params_bundle(&params, &encoded_db.config, &sk);
    let crs_bytes = crs.to_versioned_bytes().expect("versioned crs");

    let mut sampler_session = GaussianSampler::new(params.sigma);
    let session = ClientSession::new(crs.clone(), sk, &mut sampler_session).expect("session");
    let blob = serialize_client_session_rust(&session).expect("serialize residue");

    let (session2, params2) =
        deserialize_client_session_rust(&bundle_bytes, &crs_bytes, &blob).expect("rehydrate");
    assert_eq!(params2.ring_dim, params.ring_dim);
    assert!(
        session2.pack_params().is_none(),
        "a rehydrated session must not rebuild pack_params"
    );

    let mut q_sampler = GaussianSampler::new(params.sigma);
    for target in [0u64, 1, 7] {
        let (state, q) = session2
            .query(target, &encoded_db.config, &mut q_sampler)
            .expect("rehydrated query");
        let response = respond_inspiring(&crs, &encoded_db, &q).expect("respond");
        let decoded = extract_inspiring(&crs, &state, &response, ENTRY_BYTES).expect("extract");
        let lo = (target as usize) * ENTRY_BYTES;
        let expected = database
            .get(lo..lo + ENTRY_BYTES)
            .expect("planted entry slice in range");
        assert_eq!(
            decoded.as_slice(),
            expected,
            "rehydrated-session decode mismatch at index {target}"
        );
    }
}

/// An unversioned (raw-bincode) CRS blob must fail loud on the version magic,
/// not bincode mis-decode silently against a new layout.
#[test]
fn wasm_session_deserialize_rejects_unversioned_crs() {
    let params = test_params();
    let database = build_test_db(&params);
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");

    let bundle_bytes = make_params_bundle(&params, &encoded_db.config, &sk);
    // raw bincode, missing the RAVEN_CRS_v01 magic prefix
    let unversioned_crs = bincode::serialize(&crs).expect("serialize crs");
    let session_stub = vec![0u8; 16];

    let err = deserialize_client_session_rust(&bundle_bytes, &unversioned_crs, &session_stub)
        .expect_err("an unversioned CRS must surface as a typed Err");
    assert!(
        err.contains("magic mismatch"),
        "expected the CRS version magic-mismatch wording, got: {err}"
    );
}

/// One byte past the trusted cap triggers the length pre-check. The CRS is versioned
/// so it passes the magic check (which now precedes the cap), isolating the cap.
#[test]
fn wasm_session_deserialize_rejects_oversize_blob_with_typed_error() {
    let params = test_params();
    let database = build_test_db(&params);
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");

    let bundle_bytes = make_params_bundle(&params, &encoded_db.config, &sk);
    let crs_bytes = crs.to_versioned_bytes().expect("versioned crs");

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

/// At exactly the cap the length pre-check must NOT fire; a deliberately-truncated
/// body then fails the decode (not the cap), so the Err arm is guaranteed - unlike
/// an all-zero blob (length 0 -> Ok), which made this assertion vacuous.
#[test]
fn wasm_session_trusted_cap_admits_payload_at_cap_boundary() {
    let cap = WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES;
    // bincode Vec<u8> = u64 length prefix + data. Claim `cap` elements but supply
    // only cap-8 data bytes, so the decode runs (cap not exceeded) then fails on
    // truncation.
    let mut bytes = (cap as u64).to_le_bytes().to_vec();
    bytes.resize(cap, 0);
    let err = decode_trusted_for_test::<Vec<u8>>(&bytes, "client_session_boundary")
        .expect_err("a cap-sized but truncated body must fail the decode, not the cap");
    assert!(
        !err.contains("size limit reached"),
        "the trusted cap must ADMIT at the boundary (reject only past it); got: {err}"
    );
    assert!(
        err.contains("client_session_boundary"),
        "expected the typed body-decode error for client_session_boundary, got: {err}"
    );
}

/// The residue-side ring_dim guard: the arg CRS is only magic-validated, then the
/// residue's own CRS ring_dim (256) is matched against the params bundle (512) and
/// must error. Confirms from_residue rehydrates from the residue CRS, not the arg.
#[test]
fn wasm_session_deserialize_validates_residue_crs_drift() {
    let params = test_params();
    let database = build_test_db(&params);
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");

    let mut sampler_session = GaussianSampler::new(params.sigma);
    let session =
        ClientSession::new(crs.clone(), sk.clone(), &mut sampler_session).expect("session");
    let blob = serialize_client_session_rust(&session).expect("serialize residue");

    let mut drifted_params = params.clone();
    drifted_params.ring_dim = 512;
    let drifted_bundle = TestParamsBundle {
        inspire_params_bincode: bincode::serialize(&drifted_params).expect("serialize params"),
        shard_config_bincode: bincode::serialize(&encoded_db.config).expect("serialize shard"),
        rlwe_secret_key_bincode: bincode::serialize(&sk).expect("serialize sk"),
    };
    let drifted_bundle_bytes = bincode::serialize(&drifted_bundle).expect("serialize bundle");
    // the arg CRS is only magic-validated (body never decoded), so its ring_dim is irrelevant
    let arg_crs_bytes = crs.to_versioned_bytes().expect("versioned crs");

    let err = deserialize_client_session_rust(&drifted_bundle_bytes, &arg_crs_bytes, &blob)
        .expect_err("residue CRS ring_dim 256 vs bundle 512 must error");
    assert!(
        err.contains("residue CRS ring_dim"),
        "expected the residue-side ring_dim guard wording, got: {err}"
    );
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
