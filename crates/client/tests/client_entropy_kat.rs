//! Entropy KATs for the shipped client path.
//!
//! Every secret the client draws - the RLWE secret key, the packing-key noise and
//! the per-query Gaussian noise - MUST come from fresh OS entropy. A fixed PRG seed
//! anywhere here lets anyone holding the public parameters rebuild the key, decrypt
//! the query and read the queried index, collapsing the anonymity set to one.
//!
//! These drive the `#[wasm_bindgen]` entry points the SDK calls, not the test
//! mirrors, so the property is asserted on the shipped surface.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing
)]

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::InspireParams;
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::{
    respond_seeded_inspiring_cached_with_session, setup as inspire_setup, EncodedDatabase,
    SeededClientQuery, ServerCrs, ServerInspiringCache, ServerSessionStore,
};

use raven_client::{
    build_client_session, build_instance_params_blob, build_seeded_query, extract_response,
    serialize_client_session, WasmSeededQueryOutput,
};

const ENTRY_BYTES: usize = 32;
const TARGET_IDX: u64 = 7;

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
        .map(|i| (i % 251) as u8)
        .collect()
}

/// Wire-shape mirror of the crate-private `WasmInstanceParamsBundle`.
#[derive(serde::Deserialize)]
#[allow(clippy::struct_field_names)]
struct BundleView {
    inspire_params_bincode: Vec<u8>,
    #[allow(dead_code)]
    shard_config_bincode: Vec<u8>,
    rlwe_secret_key_bincode: Vec<u8>,
}

fn bundle_view(bundle_bincode: &[u8]) -> BundleView {
    bincode::deserialize(bundle_bincode).expect("decode params bundle")
}

struct Fixture {
    params: InspireParams,
    params_bincode: Vec<u8>,
    shard_config_bincode: Vec<u8>,
    crs_bincode: Vec<u8>,
    crs: ServerCrs,
    encoded_db: EncodedDatabase,
    database: Vec<u8>,
}

fn fixture() -> Fixture {
    let params = test_params();
    let database = build_test_db(&params);
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, _sk) =
        inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");
    Fixture {
        params_bincode: bincode::serialize(&params).expect("serialize params"),
        shard_config_bincode: bincode::serialize(&encoded_db.config).expect("serialize shard"),
        crs_bincode: crs.to_versioned_bytes().expect("versioned crs"),
        params,
        crs,
        encoded_db,
        database,
    }
}

/// `e + msg_term` per RGSW row, recovered as `b + a*s`. The message term is fixed by
/// the queried index, so a difference between two witnesses for the same index under
/// the same key isolates the Gaussian noise.
fn noise_witness(
    query_output_bincode: &[u8],
    sk: &RlweSecretKey,
    params: &InspireParams,
) -> Vec<Vec<u64>> {
    let output: WasmSeededQueryOutput =
        bincode::deserialize(query_output_bincode).expect("decode query output");
    let query: SeededClientQuery =
        bincode::deserialize(&output.query_bytes).expect("decode seeded query");
    let ctx = params.ntt_context();
    query
        .rgsw_ciphertext
        .rows
        .iter()
        .map(|row| {
            let full = row.expand();
            let a_s = full.a.mul_ntt(&sk.poly, &ctx);
            let witness = &full.b + &a_s;
            witness.coeffs().to_vec()
        })
        .collect()
}

#[test]
fn two_independently_built_clients_derive_different_secret_keys() {
    let f = fixture();

    let first = build_instance_params_blob(&f.params_bincode, &f.shard_config_bincode)
        .expect("first params blob");
    let second = build_instance_params_blob(&f.params_bincode, &f.shard_config_bincode)
        .expect("second params blob");

    let first_key = bundle_view(&first).rlwe_secret_key_bincode;
    let second_key = bundle_view(&second).rlwe_secret_key_bincode;

    assert_eq!(
        bundle_view(&first).inspire_params_bincode,
        bundle_view(&second).inspire_params_bincode,
        "fixture invariant: both bundles must carry the same public params"
    );
    // assert! not assert_ne!: the operands are multi-KiB and their contents are secret
    assert!(
        first_key != second_key,
        "two independently built clients derived a BYTE-IDENTICAL RLWE secret key \
         ({} bytes); anyone holding the public parameters can rebuild it and decrypt \
         every query",
        first_key.len()
    );
}

#[test]
fn two_sessions_over_one_key_carry_independent_packing_noise() {
    let f = fixture();
    let bundle = build_instance_params_blob(&f.params_bincode, &f.shard_config_bincode)
        .expect("params blob");

    let first = build_client_session(&bundle, &f.crs_bincode).expect("first session");
    let second = build_client_session(&bundle, &f.crs_bincode).expect("second session");

    let first_residue = serialize_client_session(&first).expect("first residue");
    let second_residue = serialize_client_session(&second).expect("second residue");

    assert!(
        first_residue != second_residue,
        "two sessions over the same key produced byte-identical packing keys \
         ({} bytes); the packing-key error is then known, so the server can solve \
         for the secret key",
        first_residue.len()
    );
}

#[test]
fn repeated_queries_for_one_index_carry_independent_noise() {
    let f = fixture();
    let bundle = build_instance_params_blob(&f.params_bincode, &f.shard_config_bincode)
        .expect("params blob");
    let sk: RlweSecretKey =
        bincode::deserialize(&bundle_view(&bundle).rlwe_secret_key_bincode).expect("decode sk");
    let session = build_client_session(&bundle, &f.crs_bincode).expect("session");

    let first =
        build_seeded_query(&session, &f.shard_config_bincode, TARGET_IDX).expect("first query");
    let second =
        build_seeded_query(&session, &f.shard_config_bincode, TARGET_IDX).expect("second query");

    let first_noise = noise_witness(&first, &sk, &f.params);
    let second_noise = noise_witness(&second, &sk, &f.params);

    assert_eq!(
        first_noise.len(),
        second_noise.len(),
        "fixture invariant: both queries must carry the same RGSW row count"
    );
    assert!(
        first_noise != second_noise,
        "two queries for the same index carried byte-identical Gaussian noise across \
         all {} RGSW rows; the server can re-encrypt every candidate index and match \
         the ciphertext",
        first_noise.len()
    );
}

/// Noise-budget gate on the entropy path: a fresh seed per call must still land inside
/// the decode budget, on every draw and not just the all-zero one the fixed seed gave.
#[test]
fn every_entropy_drawn_query_still_decodes_its_row() {
    const DRAWS: u64 = 8;

    let f = fixture();
    let cache = ServerInspiringCache::new(&f.crs, &f.encoded_db).expect("cache");
    let store = ServerSessionStore::new();

    for target in 0..DRAWS {
        let bundle = build_instance_params_blob(&f.params_bincode, &f.shard_config_bincode)
            .expect("params blob");
        let session = build_client_session(&bundle, &f.crs_bincode).expect("session");
        let output_bincode =
            build_seeded_query(&session, &f.shard_config_bincode, target).expect("query");
        let output: WasmSeededQueryOutput =
            bincode::deserialize(&output_bincode).expect("decode query output");
        let query: SeededClientQuery =
            bincode::deserialize(&output.query_bytes).expect("decode seeded query");

        let response = respond_seeded_inspiring_cached_with_session(
            &f.crs,
            &f.encoded_db,
            &query,
            &cache,
            Some(&store),
        )
        .expect("respond");
        let response_bytes = bincode::serialize(&response).expect("serialize response");

        let plaintext = extract_response(
            &session,
            &f.crs_bincode,
            &output.client_state_bincode,
            &response_bytes,
            ENTRY_BYTES as u32,
        )
        .expect("extract");

        let lo = (target as usize) * ENTRY_BYTES;
        assert_eq!(
            plaintext,
            &f.database[lo..lo + ENTRY_BYTES],
            "entropy-drawn query at index {target} decoded the wrong row"
        );
    }
}
