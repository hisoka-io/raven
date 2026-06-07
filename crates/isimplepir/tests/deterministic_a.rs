#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! A-matrix derivation determinism: same master seed yields byte-identical A,
//! letting the client regenerate A from a 32-byte seed instead of transferring it.

use raven_isimplepir::{setup, LweParams};

fn toy_params() -> LweParams {
    LweParams {
        n: 128,
        log2_q: 32,
        p: 991,
        l: 4,
        m: 4,
        bits_per_element: 9,
    }
}

#[test]
fn same_seed_yields_byte_identical_hint() {
    let params = toy_params();
    let db: Vec<u32> = (0..16u32).map(|i| i % params.p).collect();
    let out1 = setup(&db, params, Some([77u8; 32])).expect("setup 1");
    let out2 = setup(&db, params, Some([77u8; 32])).expect("setup 2");
    assert_eq!(
        out1.hint.data, out2.hint.data,
        "same master seed must produce byte-identical hint"
    );
    assert_eq!(out1.server.a_seed, out2.server.a_seed);
    assert_eq!(out1.server.db, out2.server.db);
}

#[test]
fn different_seed_yields_different_hint() {
    let params = toy_params();
    let db: Vec<u32> = (0..16u32).map(|i| i % params.p).collect();
    let out1 = setup(&db, params, Some([1u8; 32])).expect("setup 1");
    let out2 = setup(&db, params, Some([2u8; 32])).expect("setup 2");
    assert_ne!(
        out1.hint.data, out2.hint.data,
        "different master seeds must produce different hints"
    );
}

#[test]
fn deterministic_across_sessions() {
    let params = toy_params();
    let db: Vec<u32> = vec![42u32; 16];
    let hint_data_run1: Vec<u32>;
    {
        let out = setup(&db, params, Some([99u8; 32])).expect("setup 1");
        hint_data_run1 = out.hint.data.clone();
    }
    let out2 = setup(&db, params, Some([99u8; 32])).expect("setup 2");
    assert_eq!(hint_data_run1, out2.hint.data);
}
