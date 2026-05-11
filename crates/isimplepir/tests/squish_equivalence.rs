#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Equivalence of squished and unsquished respond paths.
//!
//! The squish optimization is correctness-preserving only if the
//! packed matmul produces a byte-identical answer vector `c ∈ Z_q^L`
//! to the unsquished `respond` for the same `(DB, query)` pair.
//! This test file locks that property at E2E scope:
//!
//! 1. `squish_respond_byte_equivalent`. For a fixed seeded
//!    `(db, a_seed, rng_seed, target)`, both `respond(state, query)`
//!    and `respond_packed(squish_db(state.db), query)` produce
//!    byte-identical `ServerResponse.answer` vectors.
//!
//! 2. `squish_e2e_recovers_planted_value`. Full round-trip via
//!    the squished path (`setup, query, respond_packed, extract`)
//!    recovers the planted plaintext element at the target index.
//!
//! 3. `squish_unaligned_m_e2e`. `M` not a multiple of 3 forces
//!    zero-padding of the last packed column; assert the
//!    equivalence still holds.
//!
//! Together these tests prove that a caller may substitute
//! `respond_packed` for `respond` without observable change at
//! the protocol layer (same wire bytes, same recovered plaintext).

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
    let m = 6; // M aligned to compression=3
    let params = squishable_params(l, m);

    // Deterministic DB values.
    let db: Vec<u32> = (0..(l * m))
        .map(|i| (i as u32 * 11 + 5) % params.p)
        .collect();

    let a_seed: [u8; SEED_BYTES] = [17u8; 32];
    let out = setup(&db, params, Some(a_seed)).expect("setup");

    let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
    let target_idx = 15; // row 2, col 3
    let (_state, client_query) =
        query(&mut rng, &out.server.a_seed, &out.server.params, target_idx).expect("query");

    // Unsquished respond.
    let c_unsquished = respond(&out.server, &client_query.query).expect("respond");

    // Squished respond against the same DB.
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

    // Extract is agnostic to whether the response came from the
    // squished or unsquished respond path. The wire bytes are
    // identical.
    let recovered = extract(&out.server.params, &out.hint, &state, &c_squished).expect("extract");

    assert_eq!(
        recovered, expected,
        "squished E2E recovered {} but planted value is {} at idx {}",
        recovered, expected, target_idx
    );
}

#[test]
fn squish_unaligned_m_e2e() {
    // M = 5 forces 2 packed columns: one full (cols 0, 1, 2) +
    // one partial (cols 3, 4, pad).
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

    // Byte-equivalence under unaligned m.
    let c_unsquished = respond(&out.server, &client_query.query).expect("respond");
    let packed = squish_db(&out.server.db, &out.server.params).expect("squish");
    let c_squished = respond_packed(&packed, &client_query.query).expect("respond_packed");
    assert_eq!(
        c_unsquished.answer, c_squished.answer,
        "unaligned-m: squished must byte-match unsquished"
    );

    // E2E recovery via squished path.
    let recovered = extract(&out.server.params, &out.hint, &state, &c_squished).expect("extract");
    assert_eq!(recovered, expected);
}
