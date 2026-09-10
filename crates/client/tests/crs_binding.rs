//! A cached session must be refused against a CRS it was not derived under.
//!
//! Packing keys depend on `(CRS, rlwe_sk, w_seed)`. The warm-session loader is the Rust layer that
//! binds the retained session CRS to the current one; bypassing it leaves a stale key set with valid
//! geometry and produces a successful response containing unrelated bytes.
//!
//! The seed needed to catch it is already on the wire: the server strips `galois_keys` from the CRS
//! it publishes but keeps `inspiring_w_seed`, so the loader can compare both values.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, ShardConfig};
use raven_inspire::{extract_inspiring, respond_inspiring, setup as inspire_setup, ClientSession};

use raven_client::{deserialize_client_session_rust, serialize_client_session_rust};

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
    (0..(params.ring_dim * ENTRY_BYTES))
        .map(|i| u8::try_from(i % 251).expect("< 251"))
        .collect()
}

/// Wire-shape mirror of the crate-private bundle type.
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

/// One setup: the CRS a client caches against, its database, and its session blob.
struct Deployment {
    crs: raven_inspire::ServerCrs,
    encoded_db: raven_inspire::EncodedDatabase,
    crs_bytes: Vec<u8>,
    bundle: Vec<u8>,
    blob: Vec<u8>,
}

fn deploy(params: &InspireParams, database: &[u8]) -> Deployment {
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(params, database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");
    let bundle = make_params_bundle(params, &encoded_db.config, &sk);
    let crs_bytes = crs.to_versioned_bytes().expect("versioned crs");
    let mut session_sampler = GaussianSampler::new(params.sigma);
    let session = ClientSession::new(crs.clone(), sk, &mut session_sampler).expect("session");
    let blob = serialize_client_session_rust(&session).expect("serialize residue");
    Deployment {
        crs,
        encoded_db,
        crs_bytes,
        bundle,
        blob,
    }
}

/// The defect this file exists for: a session cached under one CRS, loaded against another.
///
/// Every shape agrees, so nothing downstream can catch it - the refusal has to happen here, at the
/// one place holding both the residue's CRS and the live one.
#[test]
fn a_session_cached_under_a_different_crs_is_refused() {
    let params = test_params();
    let database = build_test_db(&params);
    let cached = deploy(&params, &database);
    let rotated = deploy(&params, &database);

    assert_ne!(
        cached.crs.inspiring_w_seed, rotated.crs.inspiring_w_seed,
        "premise: re-running setup draws a fresh w_seed, so the two CRSs are distinguishable"
    );

    let err = deserialize_client_session_rust(&rotated.bundle, &rotated.crs_bytes, &cached.blob)
        .expect_err("a session from a superseded CRS must not load");
    assert!(
        err.contains("w_seed"),
        "the refusal must name the CRS identity that mismatched, not a generic decode failure; \
         got: {err}"
    );
}

/// The control: a guard that refuses everything is not a guard.
#[test]
fn a_session_cached_under_the_matching_crs_still_loads() {
    let params = test_params();
    let database = build_test_db(&params);
    let live = deploy(&params, &database);

    let (session, loaded) =
        deserialize_client_session_rust(&live.bundle, &live.crs_bytes, &live.blob)
            .expect("a session from its own CRS must still load");
    assert_eq!(loaded.ring_dim, params.ring_dim);

    let mut q_sampler = GaussianSampler::new(params.sigma);
    let (state, query) = session
        .query(3, &live.encoded_db.config, &mut q_sampler)
        .expect("query");
    let response = respond_inspiring(&live.crs, &live.encoded_db, &query).expect("respond");
    let decoded = extract_inspiring(&live.crs, &state, &response, ENTRY_BYTES).expect("extract");
    let lo = 3 * ENTRY_BYTES;
    assert_eq!(
        decoded.as_slice(),
        database.get(lo..lo + ENTRY_BYTES).expect("planted entry"),
        "the matching-CRS path must still decode its own record"
    );
}

/// Why the refusal above is a CORRECTNESS guard and not hygiene.
///
/// Constructs the mismatch directly, bypassing the loader, and drives it through the full server
/// path. Every step reports success and the bytes are wrong - which is what makes this silent.
#[test]
fn a_stale_session_that_bypasses_the_loader_returns_wrong_bytes_at_ok() {
    let params = test_params();
    let database = build_test_db(&params);
    let cached = deploy(&params, &database);
    let rotated = deploy(&params, &database);

    let (stale_session, _) =
        deserialize_client_session_rust(&cached.bundle, &cached.crs_bytes, &cached.blob)
            .expect("the stale session loads against its OWN crs");

    let mut q_sampler = GaussianSampler::new(params.sigma);
    let (state, query) = stale_session
        .query(3, &rotated.encoded_db.config, &mut q_sampler)
        .expect("a stale session still builds a well-formed query");

    // The server pairs the client's keys with ITS pack params. The only geometry check compares
    // gamma and key length, which agree, so nothing refuses.
    let Ok(response) = respond_inspiring(&rotated.crs, &rotated.encoded_db, &query) else {
        return; // a typed refusal here would be a better outcome than the one this test documents
    };
    let Ok(decoded) = extract_inspiring(&rotated.crs, &state, &response, ENTRY_BYTES) else {
        return;
    };

    let lo = 3 * ENTRY_BYTES;
    let expected = database.get(lo..lo + ENTRY_BYTES).expect("planted entry");
    assert_ne!(
        decoded.as_slice(),
        expected,
        "premise of the whole file: a stale-CRS query that reports Ok end to end returns bytes \
         that are NOT the record. If this ever matches, the mismatch became harmless and the \
         loader guard can be reconsidered"
    );
}
