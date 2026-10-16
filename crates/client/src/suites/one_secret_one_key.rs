//! One client context is one secret and one packing key.
//!
//! Two packing keys under one secret share the CRS mask and differ only in their error,
//! so a server holding both learns the secret. Through the shipped entry points a
//! rebuilt session draws a new secret, and a handle, a retry or a restored session
//! resends the key bytes it already has.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::indexing_slicing
)]

use raven_inspire::inspiring::ClientPackingKeys;
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::InspireParams;
use raven_inspire::{setup as inspire_setup, SeededClientQuery};

use raven_client::{
    build_client_session, build_instance_params_blob, build_seeded_query,
    client_packing_keys_versioned, deserialize_client_session, serialize_client_session,
    ClientSessionHandle, WasmSeededQueryOutput,
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
        query_gadget_len: 3,
        packing_gadget_len: 3,
        approximate_packing_gadget: false,
        security_level: raven_inspire::params::SecurityLevel::Bits128,
    }
}

struct Fixture {
    params: InspireParams,
    bundle: Vec<u8>,
    params_bincode: Vec<u8>,
    shard_config_bincode: Vec<u8>,
    crs_bincode: Vec<u8>,
}

fn fixture() -> Fixture {
    let params = test_params();
    let database: Vec<u8> = (0..params.ring_dim * ENTRY_BYTES)
        .map(|i| (i % 251) as u8)
        .collect();
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, _) =
        inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");
    let params_bincode = bincode::serialize(&params).expect("serialize params");
    let shard_config_bincode = bincode::serialize(&encoded_db.config).expect("serialize shard");
    let bundle =
        build_instance_params_blob(&params_bincode, &shard_config_bincode).expect("params blob");
    Fixture {
        params,
        bundle,
        params_bincode,
        shard_config_bincode,
        crs_bincode: crs.to_versioned_bytes().expect("versioned crs"),
    }
}

fn uploaded_keys(session: &ClientSessionHandle) -> ClientPackingKeys {
    let body = client_packing_keys_versioned(session).expect("upload body");
    bincode::deserialize(&body[2..]).expect("decode packing keys")
}

/// The narrowest key row, measured by its widest centred `|a - b| mod q`.
fn smallest_row_spread(a: &ClientPackingKeys, b: &ClientPackingKeys, q: u64) -> u64 {
    assert_eq!(
        a.y_body.len(),
        b.y_body.len(),
        "fixture invariant: same key shape"
    );
    a.y_body
        .iter()
        .zip(&b.y_body)
        .map(|(ra, rb)| {
            ra.coeffs()
                .iter()
                .zip(rb.coeffs())
                .map(|(&x, &y)| {
                    let d = (x + q - y) % q;
                    d.min(q - d)
                })
                .max()
                .unwrap_or(0)
        })
        .min()
        .unwrap_or(0)
}

/// Same secret and mask leave only two Gaussian errors in the difference, tens wide;
/// a fresh secret leaves a uniform difference, about q/2 at its widest.
#[test]
fn a_second_session_on_one_bundle_builds_no_second_key_under_the_first_secret() {
    let f = fixture();
    let q = f.params.q;
    for _ in 0..4 {
        let first = build_client_session(&f.bundle, &f.crs_bincode).expect("first session");
        let second = build_client_session(&f.bundle, &f.crs_bincode).expect("second session");
        let spread = smallest_row_spread(&uploaded_keys(&first), &uploaded_keys(&second), q);
        assert!(
            spread > q / 4,
            "two sessions on one bundle published packing keys whose rows differ by at most \
             {spread}: one secret under one mask, which leaks the secret"
        );
    }
}

/// The control: two keys under one secret, built the way the shipped path no longer can.
#[test]
fn the_spread_check_sees_two_keys_under_one_secret() {
    let f = fixture();
    let session = build_client_session(&f.bundle, &f.crs_bincode).expect("session");
    let crs = session.inner.crs().clone();
    let secret = session.inner.rlwe_secret_key().clone();
    let mut sampler = GaussianSampler::new(f.params.sigma);
    let again = raven_inspire::ClientSession::new(crs, secret, &mut sampler).expect("rebuild");
    let spread = smallest_row_spread(
        &uploaded_keys(&session),
        again.packing_keys().expect("packing keys"),
        f.params.q,
    );
    assert!(spread < 1 << 12, "same secret, same mask: spread {spread}");
}

#[test]
fn a_handle_resends_the_key_bytes_it_built() {
    let f = fixture();
    let session = build_client_session(&f.bundle, &f.crs_bincode).expect("session");
    let upload = client_packing_keys_versioned(&session).expect("first upload");
    assert_eq!(
        client_packing_keys_versioned(&session).expect("retry"),
        upload,
        "a retried upload must resend the same bytes"
    );
    for index in [0u64, 0, 9] {
        let output = build_seeded_query(&session, &f.shard_config_bincode, index).expect("query");
        let output: WasmSeededQueryOutput = bincode::deserialize(&output).expect("output");
        let query: SeededClientQuery = bincode::deserialize(&output.query_bytes).expect("query");
        let inline = query
            .inspiring_packing_keys
            .expect("inline keys before a handle");
        assert_eq!(
            bincode::serialize(&inline).expect("encode inline keys"),
            upload[2..],
            "an inline-key query must carry the uploaded key, not a new one"
        );
    }
}

#[test]
fn a_restored_session_uploads_its_stored_key() {
    let f = fixture();
    let session = build_client_session(&f.bundle, &f.crs_bincode).expect("session");
    let blob = serialize_client_session(&session).expect("residue");
    let restored =
        deserialize_client_session(&f.bundle, &f.crs_bincode, &blob).expect("restored session");
    assert_eq!(
        client_packing_keys_versioned(&restored).expect("restored upload"),
        client_packing_keys_versioned(&session).expect("upload"),
    );
}

#[test]
fn the_params_bundle_holds_public_parameters_only() {
    let f = fixture();
    let public_only = bincode::serialize(&(&f.params_bincode, &f.shard_config_bincode))
        .expect("encode public parameters");
    assert_eq!(
        f.bundle, public_only,
        "the bundle carries bytes beyond the public parameters"
    );
}
