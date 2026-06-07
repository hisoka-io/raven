#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Squished and unsquished respond paths are equivalent: the packed matmul must
//! produce a byte-identical answer `c ∈ Z_q^L` to `respond`, so a caller can
//! substitute `respond_packed` with no protocol-layer change.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use raven_isimplepir::{
    extract, query, respond, respond_packed, setup, squish_db, LweParams, SEED_BYTES,
};

/// Toy params constrained so squish is valid (`p <= 2^10 = 1024`).
fn squishable_params(l: usize, m: usize) -> LweParams {
    LweParams {
        n: 128,
        log2_q: 32,
        p: 991,
        l,
        m,
        bits_per_element: 9,
    }
}

#[test]
fn squish_respond_byte_equivalent() {
    let l = 4;
    let m = 6; // aligned to compression factor 3
    let params = squishable_params(l, m);

    let db: Vec<u32> = (0..(l * m))
        .map(|i| (i as u32 * 11 + 5) % params.p)
        .collect();

    let a_seed: [u8; SEED_BYTES] = [17u8; 32];
    let out = setup(&db, params, Some(a_seed)).expect("setup");

    let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
    let target_idx = 15; // row 2, col 3
    let (_state, client_query) =
        query(&mut rng, &out.server.a_seed, &out.server.params, target_idx).expect("query");

    let c_unsquished = respond(&out.server, &client_query.query).expect("respond");

    let packed = squish_db(&out.server.db, &out.server.params).expect("squish");
    let c_squished = respond_packed(&packed, &client_query.query).expect("respond_packed");

    assert_eq!(
        c_unsquished.answer, c_squished.answer,
        "squished respond must produce byte-identical answer to unsquished",
    );
}

#[test]
fn squish_e2e_recovers_planted_value() {
    let l = 4;
    let m = 6;
    let params = squishable_params(l, m);

    let mut db = vec![0u32; l * m];
    for i in 0..l {
        for j in 0..m {
            db[i * m + j] = ((i * 19 + j * 7 + 1) as u32) % params.p;
        }
    }

    let a_seed: [u8; SEED_BYTES] = [3u8; 32];
    let out = setup(&db, params, Some(a_seed)).expect("setup");

    let target_idx = 11; // row 1, col 5
    let expected = db[target_idx];

    let mut rng = ChaCha20Rng::from_seed([21u8; 32]);
    let (state, client_query) =
        query(&mut rng, &out.server.a_seed, &out.server.params, target_idx).expect("query");

    let packed = squish_db(&out.server.db, &out.server.params).expect("squish");
    let c_squished = respond_packed(&packed, &client_query.query).expect("respond_packed");

    let recovered = extract(&out.server.params, &out.hint, &state, &c_squished).expect("extract");

    assert_eq!(
        recovered, expected,
        "squished E2E recovered {} but planted value is {} at idx {}",
        recovered, expected, target_idx
    );
}

#[test]
fn squish_unaligned_m_e2e() {
    // m = 5 forces a partial last packed column (cols 3, 4, pad).
    let l = 3;
    let m = 5;
    let params = squishable_params(l, m);

    let mut db = vec![0u32; l * m];
    for i in 0..l {
        for j in 0..m {
            db[i * m + j] = ((i * 23 + j * 11 + 7) as u32) % params.p;
        }
    }

    let a_seed: [u8; SEED_BYTES] = [45u8; 32];
    let out = setup(&db, params, Some(a_seed)).expect("setup");

    let target_idx = 7; // row 1, col 2
    let expected = db[target_idx];

    let mut rng = ChaCha20Rng::from_seed([88u8; 32]);
    let (state, client_query) =
        query(&mut rng, &out.server.a_seed, &out.server.params, target_idx).expect("query");

    let c_unsquished = respond(&out.server, &client_query.query).expect("respond");
    let packed = squish_db(&out.server.db, &out.server.params).expect("squish");
    let c_squished = respond_packed(&packed, &client_query.query).expect("respond_packed");
    assert_eq!(
        c_unsquished.answer, c_squished.answer,
        "unaligned-m: squished must byte-match unsquished"
    );

    let recovered = extract(&out.server.params, &out.hint, &state, &c_squished).expect("extract");
    assert_eq!(recovered, expected);
}
