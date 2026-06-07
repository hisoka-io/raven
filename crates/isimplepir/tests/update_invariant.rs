#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Theorem 3 exact-hint invariant: the incrementally maintained hint stays
//! byte-identical to a full `H' = D' · A` recomputation after any update sequence.
//! Paper 2026/030 §4.1 p.14 Theorem 3.

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

use raven_isimplepir::{
    db_update_batch, db_update_delete, db_update_insert, db_update_modify, db_update_row_deletions,
    db_update_row_modifications, setup, state_update_batch, state_update_entry,
    state_update_insert, state_update_row, verify_hint_matches_db, DbBatchOp, LweParams,
};

fn toy_params(l: usize, m: usize) -> LweParams {
    LweParams {
        n: 128,
        log2_q: 32,
        p: 991,
        l,
        m,
        bits_per_element: 9,
    }
}

fn random_value_below_p<R: RngCore>(rng: &mut R, p: u32) -> u32 {
    let mut buf = [0u8; 4];
    let ceil = (u32::MAX / p).saturating_mul(p);
    loop {
        rng.fill_bytes(&mut buf);
        let v = u32::from_le_bytes(buf);
        if v < ceil {
            return v % p;
        }
    }
}

fn run_k_updates(k: usize, seed: [u8; 32]) {
    let l = 4;
    let m = 4;
    let params = toy_params(l, m);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut db_init = vec![0u32; l * m];
    for slot in db_init.iter_mut() {
        *slot = random_value_below_p(&mut rng, params.p);
    }

    let a_seed = [1u8; 32];
    let out = setup(&db_init, params, Some(a_seed)).expect("setup");
    let mut hint = out.hint.clone();
    let mut state = out.server;

    for step in 0..k {
        let op = step % 3;
        match op {
            0 => {
                let total_rows = state.params.l;
                let total_cols = state.params.m;
                let row = (step * 7) % total_rows;
                let col = (step * 13) % total_cols;
                let new_v = random_value_below_p(&mut rng, state.params.p);
                let delta = db_update_modify(&mut state, row, col, new_v).expect("modify");
                state_update_entry(&mut hint, &state.a_seed, &state.params, &delta)
                    .expect("state_update modify");
            }
            1 => {
                let mut new_row = vec![0u32; state.params.m];
                for slot in new_row.iter_mut() {
                    *slot = random_value_below_p(&mut rng, state.params.p);
                }
                let delta = db_update_insert(&mut state, &new_row).expect("insert");
                state_update_insert(&mut hint, &delta).expect("state_update insert");
            }
            _ => {
                let total_rows = state.params.l;
                let total_cols = state.params.m;
                let row = (step * 11) % total_rows;
                let col = (step * 17) % total_cols;
                let delta = db_update_delete(&mut state, row, col, &mut rng).expect("delete");
                state_update_entry(&mut hint, &state.a_seed, &state.params, &delta)
                    .expect("state_update delete");
            }
        }
    }

    verify_hint_matches_db(&state, &hint)
        .unwrap_or_else(|err| panic!("Theorem 3 invariant violated after {k} updates: {err}"));
}

#[test]
fn invariant_after_1_update() {
    run_k_updates(1, [0u8; 32]);
}

#[test]
fn invariant_after_10_updates() {
    run_k_updates(10, [0u8; 32]);
}

#[test]
fn invariant_after_100_updates() {
    run_k_updates(100, [0u8; 32]);
}

#[test]
fn invariant_after_1024_updates() {
    run_k_updates(1024, [42u8; 32]);
}

#[test]
fn invariant_after_row_agg_modifications() {
    let l = 4;
    let m = 8;
    let params = toy_params(l, m);
    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
    let mut db_init = vec![0u32; l * m];
    for slot in db_init.iter_mut() {
        *slot = random_value_below_p(&mut rng, params.p);
    }

    let out = setup(&db_init, params, Some([3u8; 32])).expect("setup");
    let mut hint = out.hint.clone();
    let mut state = out.server;

    let target_row = 2;
    let edits: Vec<(usize, u32)> = (0..5)
        .map(|k| (k, random_value_below_p(&mut rng, state.params.p)))
        .collect();
    let delta =
        db_update_row_modifications(&mut state, target_row, &edits).expect("row-agg modifications");
    state_update_row(&mut hint, &delta).expect("state_update_row");

    verify_hint_matches_db(&state, &hint)
        .expect("Theorem 3 invariant failed after row-aggregated modifications");
}

#[test]
fn invariant_after_row_agg_deletions() {
    let l = 4;
    let m = 8;
    let params = toy_params(l, m);
    let mut rng = ChaCha20Rng::from_seed([55u8; 32]);
    let mut db_init = vec![0u32; l * m];
    for slot in db_init.iter_mut() {
        *slot = random_value_below_p(&mut rng, params.p);
    }

    let out = setup(&db_init, params, Some([44u8; 32])).expect("setup");
    let mut hint = out.hint.clone();
    let mut state = out.server;

    let target_row = 1;
    let cols_to_delete = vec![1usize, 3, 5];
    let delta = db_update_row_deletions(&mut state, target_row, &cols_to_delete, &mut rng)
        .expect("row-agg deletions");
    state_update_row(&mut hint, &delta).expect("state_update_row");

    verify_hint_matches_db(&state, &hint)
        .expect("Theorem 3 invariant failed after row-aggregated deletions");
}

/// Entry-level and row-aggregated paths over the same edits yield byte-identical
/// hints even though their version counters diverge (per-edit vs once).
#[test]
fn entry_vs_row_agg_byte_equality() {
    let l = 4;
    let m = 8;
    let params = toy_params(l, m);
    let mut rng = ChaCha20Rng::from_seed([77u8; 32]);
    let mut db_init = vec![0u32; l * m];
    for slot in db_init.iter_mut() {
        *slot = random_value_below_p(&mut rng, params.p);
    }
    let a_seed = [123u8; 32];

    let target_row = 0;
    let k = 6;
    let edits: Vec<(usize, u32)> = (0..k)
        .map(|idx| (idx, random_value_below_p(&mut rng, params.p)))
        .collect();

    let out_a = setup(&db_init, params, Some(a_seed)).expect("setup A");
    let mut hint_a = out_a.hint.clone();
    let mut state_a = out_a.server;
    for &(col, new_value) in &edits {
        let delta =
            db_update_modify(&mut state_a, target_row, col, new_value).expect("entry modify");
        state_update_entry(&mut hint_a, &state_a.a_seed, &state_a.params, &delta)
            .expect("state_update_entry");
    }

    let out_b = setup(&db_init, params, Some(a_seed)).expect("setup B");
    let mut hint_b = out_b.hint.clone();
    let mut state_b = out_b.server;
    let delta_row = db_update_row_modifications(&mut state_b, target_row, &edits)
        .expect("row-agg modifications");
    state_update_row(&mut hint_b, &delta_row).expect("state_update_row");

    assert_eq!(state_a.db, state_b.db, "DB should match after same edits");

    assert_eq!(
        hint_a.data, hint_b.data,
        "hint data should be byte-identical after equivalent update paths"
    );

    verify_hint_matches_db(&state_a, &hint_a).expect("Theorem 3 on entry-level path");
    verify_hint_matches_db(&state_b, &hint_b).expect("Theorem 3 on row-aggregated path");
}

#[test]
fn row_agg_version_mismatch_rejected() {
    use raven_isimplepir::IsimplePirError;

    let params = toy_params(4, 4);
    let db: Vec<u32> = (0..16u32).map(|i| i % params.p).collect();
    let out = setup(&db, params, Some([0u8; 32])).expect("setup");
    let mut hint = out.hint.clone();
    let mut state = out.server;

    let _d1 = db_update_row_modifications(&mut state, 0, &[(0, 5), (1, 6)]).expect("d1");
    let d2 = db_update_row_modifications(&mut state, 0, &[(2, 7)]).expect("d2");

    match state_update_row(&mut hint, &d2) {
        Err(IsimplePirError::VersionMismatch { .. }) => {}
        other => panic!("expected VersionMismatch, got {other:?}"),
    }
}

// paper Fig. 2 β = (β_edit, β_del, β_add)

#[test]
fn invariant_after_mixed_batch() {
    let l = 4;
    let m = 4;
    let params = toy_params(l, m);
    let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
    let mut db_init = vec![0u32; l * m];
    for slot in db_init.iter_mut() {
        *slot = random_value_below_p(&mut rng, params.p);
    }

    let a_seed = [1u8; 32];
    let out = setup(&db_init, params, Some(a_seed)).expect("setup");
    let mut state = out.server;
    let mut hint = out.hint;

    let new_row_a: Vec<u32> = (0..m).map(|i| (100 + i as u32) % params.p).collect();
    let new_row_b: Vec<u32> = (0..m).map(|i| (200 + i as u32) % params.p).collect();

    let batch = db_update_batch(
        &mut state,
        &DbBatchOp {
            modifications: &[(0, 0, 7), (1, 2, 42), (3, 3, 1)],
            deletions: &[(2, 1)],
            insertions: &[new_row_a.as_slice(), new_row_b.as_slice()],
        },
        &mut rng,
    )
    .expect("batch");

    state_update_batch(&mut hint, &a_seed, &state.params, &batch).expect("state_update_batch");
    verify_hint_matches_db(&state, &hint).expect("invariant preserved after mixed batch");

    assert_eq!(batch.version.get(), 1);
    assert_eq!(state.version.get(), 1);
    assert_eq!(hint.version.get(), 1);

    for edit in &batch.beta_edit {
        assert_eq!(edit.version, batch.version);
    }
    for del in &batch.beta_del {
        assert_eq!(del.version, batch.version);
    }
    for add in &batch.beta_add {
        assert_eq!(add.version, batch.version);
    }

    assert_eq!(state.params.l, l + 2);
    assert_eq!(hint.l, l + 2);
}

#[test]
fn batch_version_mismatch_rejected_by_state_update() {
    use raven_isimplepir::IsimplePirError;
    let l = 3;
    let m = 3;
    let params = toy_params(l, m);
    let mut rng = ChaCha20Rng::from_seed([12u8; 32]);
    let db_init: Vec<u32> = (0..l * m).map(|i| (i as u32) % params.p).collect();

    let a_seed = [2u8; 32];
    let out = setup(&db_init, params, Some(a_seed)).expect("setup");
    let mut state = out.server;
    let mut hint = out.hint;

    let _b1 = db_update_batch(
        &mut state,
        &DbBatchOp {
            modifications: &[(0, 0, 5)],
            deletions: &[],
            insertions: &[],
        },
        &mut rng,
    )
    .expect("b1");
    let b2 = db_update_batch(
        &mut state,
        &DbBatchOp {
            modifications: &[(1, 1, 9)],
            deletions: &[],
            insertions: &[],
        },
        &mut rng,
    )
    .expect("b2");

    // hint is at version 0; b2 is at version 2.
    match state_update_batch(&mut hint, &a_seed, &state.params, &b2) {
        Err(IsimplePirError::VersionMismatch { .. }) => {}
        other => panic!("expected VersionMismatch, got {other:?}"),
    }
}

#[test]
fn empty_batch_is_noop_without_version_bump() {
    let l = 3;
    let m = 3;
    let params = toy_params(l, m);
    let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
    let db_init: Vec<u32> = (0..l * m).map(|i| (i as u32) % params.p).collect();

    let a_seed = [3u8; 32];
    let out = setup(&db_init, params, Some(a_seed)).expect("setup");
    let mut state = out.server;
    let mut hint = out.hint;

    let initial_version = state.version;

    let batch = db_update_batch(
        &mut state,
        &DbBatchOp {
            modifications: &[],
            deletions: &[],
            insertions: &[],
        },
        &mut rng,
    )
    .expect("empty batch");

    assert_eq!(batch.version, initial_version);
    assert_eq!(state.version, initial_version);
    assert!(batch.beta_edit.is_empty());
    assert!(batch.beta_del.is_empty());
    assert!(batch.beta_add.is_empty());

    state_update_batch(&mut hint, &a_seed, &state.params, &batch).expect("empty apply");
    assert_eq!(hint.version, initial_version);
    verify_hint_matches_db(&state, &hint).expect("unchanged invariant");
}

#[test]
fn batch_byte_equivalent_to_sequential_with_shared_version() {
    // Batch and per-op paths reach the same final D, so hint bytes match despite
    // divergent version trails (batch +1 vs sequential +6).
    let l = 4;
    let m = 4;
    let params = toy_params(l, m);
    let mut rng = ChaCha20Rng::from_seed([14u8; 32]);
    let db_init: Vec<u32> = (0..l * m).map(|i| (i as u32) % params.p).collect();

    let a_seed = [4u8; 32];

    let out_a = setup(&db_init, params, Some(a_seed)).expect("setup a");
    let mut state_a = out_a.server;
    let mut hint_a = out_a.hint;

    let new_row: Vec<u32> = (0..m).map(|i| (5 + i as u32) % params.p).collect();
    let batch = db_update_batch(
        &mut state_a,
        &DbBatchOp {
            modifications: &[(0, 0, 11), (1, 1, 22), (2, 2, 33), (3, 3, 44), (0, 3, 7)],
            deletions: &[],
            insertions: &[new_row.as_slice()],
        },
        &mut rng,
    )
    .expect("batch");
    state_update_batch(&mut hint_a, &a_seed, &state_a.params, &batch).expect("state_batch a");

    let out_b = setup(&db_init, params, Some(a_seed)).expect("setup b");
    let mut state_b = out_b.server;
    let mut hint_b = out_b.hint;
    for &(row, col, new_value) in &[(0, 0, 11), (1, 1, 22), (2, 2, 33), (3, 3, 44), (0, 3, 7)] {
        let d = db_update_modify(&mut state_b, row, col, new_value).expect("mod");
        state_update_entry(&mut hint_b, &a_seed, &state_b.params, &d).expect("state mod");
    }
    let ins_delta = db_update_insert(&mut state_b, &new_row).expect("ins");
    state_update_insert(&mut hint_b, &ins_delta).expect("state ins");

    assert_eq!(
        hint_a.data, hint_b.data,
        "batch path and sequential path must produce byte-identical hint"
    );
    assert_eq!(hint_a.l, hint_b.l);
    assert_eq!(hint_a.n, hint_b.n);

    verify_hint_matches_db(&state_a, &hint_a).expect("theorem 3 on path A");
    verify_hint_matches_db(&state_b, &hint_b).expect("theorem 3 on path B");

    assert_eq!(hint_a.version.get(), 1);
    assert_eq!(hint_b.version.get(), 6);
}

#[test]
fn batch_rejects_invalid_input_without_mutation() {
    let l = 3;
    let m = 3;
    let params = toy_params(l, m);
    let mut rng = ChaCha20Rng::from_seed([15u8; 32]);
    let db_init: Vec<u32> = (0..l * m).map(|i| (i as u32) % params.p).collect();

    let a_seed = [5u8; 32];
    let out = setup(&db_init, params, Some(a_seed)).expect("setup");
    let mut state = out.server;

    let pre_version = state.version;
    let pre_db = state.db.clone();
    let pre_l = state.params.l;

    // col 999 out of range; reject atomically.
    let batch_result = db_update_batch(
        &mut state,
        &DbBatchOp {
            modifications: &[(0, 0, 1), (1, 999, 2)],
            deletions: &[],
            insertions: &[],
        },
        &mut rng,
    );
    assert!(batch_result.is_err());

    assert_eq!(state.version, pre_version);
    assert_eq!(state.db, pre_db);
    assert_eq!(state.params.l, pre_l);
}
