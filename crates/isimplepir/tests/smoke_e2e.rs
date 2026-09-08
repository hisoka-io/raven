#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! End-to-end correctness smoke: setup, query, respond, extract recovers the
//! planted byte at known indices.

use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use raven_isimplepir::{extract, query, respond, setup, LweParams, SEED_BYTES};

fn toy_params(l: usize, m: usize) -> LweParams {
    LweParams {
        n: 256,
        log2_q: 32,
        p: 991,
        l,
        m,
        bits_per_element: 9,
    }
}

#[test]
fn smoke_e2e_recovers_planted_value_at_one_index() {
    let l = 4;
    let m = 4;
    let params = toy_params(l, m);
    let mut db = vec![0u32; l * m];
    for i in 0..l {
        for j in 0..m {
            db[i * m + j] = ((i + j) as u32 * 7 + 3) % params.p;
        }
    }

    let a_seed: [u8; SEED_BYTES] = [42u8; 32];
    let out = setup(&db, params, Some(a_seed)).expect("setup");

    let target_idx = 6usize; // (row 1, col 2)
    let expected = db[target_idx];

    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let (state, q) =
        query(&mut rng, &out.server.a_seed, &out.server.params, target_idx).expect("query");
    let response = respond(&out.server, &q.query).expect("respond");
    let recovered = extract(&out.server.params, &out.hint, &state, &response).expect("extract");

    assert_eq!(
        recovered, expected,
        "E2E smoke failed: recovered {} vs expected {} at idx {}",
        recovered, expected, target_idx,
    );
}

#[test]
fn smoke_e2e_three_indices_three_seeds() {
    let l = 8;
    let m = 8;
    let params = toy_params(l, m);
    let mut db = vec![0u32; l * m];
    for i in 0..l {
        for j in 0..m {
            db[i * m + j] = ((i * 13 + j * 5 + 1) as u32) % params.p;
        }
    }

    let a_seed: [u8; SEED_BYTES] = [11u8; 32];
    let out = setup(&db, params, Some(a_seed)).expect("setup");

    let indices = [0usize, 17, 63];
    let seeds = [[1u8; 32], [2u8; 32], [3u8; 32]];

    for &idx in &indices {
        for (seed_idx, seed) in seeds.iter().enumerate() {
            let mut rng = ChaCha20Rng::from_seed(*seed);
            let (st, q) =
                query(&mut rng, &out.server.a_seed, &out.server.params, idx).expect("query");
            let r = respond(&out.server, &q.query).expect("respond");
            let recovered = extract(&out.server.params, &out.hint, &st, &r).expect("extract");
            assert_eq!(
                recovered, db[idx],
                "smoke failed idx={} seed={}: recovered {} vs expected {}",
                idx, seed_idx, recovered, db[idx],
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Both examples above are square, and `idx / M` is indistinguishable from
    /// `idx / L` when L == M. Generated non-square shapes separate them: a
    /// mutation swapping the two left every test in this file green and was
    /// caught only, and incidentally, by the packed-path tests in
    /// `squish_equivalence`. Shape and index are generated so the plain path
    /// stands on its own.
    #[test]
    fn e2e_recovers_the_planted_value_at_any_shape_and_index(
        l in 2usize..7,
        m in 2usize..7,
        idx_pick in 0usize..64,
        rng_seed in any::<u8>(),
    ) {
        let params = toy_params(l, m);
        let db: Vec<u32> = (0..l * m).map(|i| ((i * 13 + 1) as u32) % params.p).collect();
        let out = setup(&db, params, Some([42u8; 32])).expect("setup");
        let idx = idx_pick % (l * m);

        let mut rng = ChaCha20Rng::from_seed([rng_seed; 32]);
        let (state, q) =
            query(&mut rng, &out.server.a_seed, &out.server.params, idx).expect("query");
        let response = respond(&out.server, &q.query).expect("respond");
        let recovered = extract(&out.server.params, &out.hint, &state, &response).expect("extract");

        prop_assert_eq!(
            recovered, db[idx],
            "L {} M {} idx {} (row {}, col {})", l, m, idx, idx / m, idx % m
        );
    }
}
