#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Wire-supplied shapes reach the kernels from an untrusted peer, so every
//! one of them must fail closed rather than compute over a short buffer.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use raven_isimplepir::{
    db_update_modify, extract, query, respond, setup, state_update_batch, state_update_entry,
    DbBatchOp, EntryUpdate, HintVersion, IsimplePirError, LweParams, ServerState, UpdateBatch,
};

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

fn planted_db(params: &LweParams) -> Vec<u32> {
    (0..(params.l * params.m))
        .map(|i| (i as u32 * 37 + 11) % params.p)
        .collect()
}

#[test]
fn extract_rejects_hint_truncated_into_the_target_row() {
    let params = toy_params();
    let db = planted_db(&params);
    let out = setup(&db, params, Some([5u8; 32])).expect("setup");
    let a_seed = out.server.a_seed;

    let target = params.l * params.m - 1;
    let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
    let (client_state, client_query) = query(&mut rng, &a_seed, &params, target).expect("query");
    let response = respond(&out.server, &client_query.query).expect("respond");

    let honest = extract(&params, &out.hint, &client_state, &response).expect("extract");
    assert_eq!(honest, db[target], "precondition: honest extract recovers");

    let mut truncated = out.hint.clone();
    truncated.data.truncate(params.l * params.n - 1);

    let result = extract(&params, &truncated, &client_state, &response);
    assert!(
        matches!(result, Err(IsimplePirError::InvalidParams { .. })),
        "hint truncated into row {} (data len {} vs L * n = {}) must fail closed, got {:?}",
        client_state.row,
        truncated.data.len(),
        params.l * params.n,
        result,
    );
}

/// A truncation past the target row still decodes that row correctly, so only
/// the declared-shape check can reject it.
#[test]
fn extract_rejects_hint_shorter_than_its_declared_shape() {
    let params = toy_params();
    let db = planted_db(&params);
    let out = setup(&db, params, Some([5u8; 32])).expect("setup");
    let a_seed = out.server.a_seed;

    let mut rng = ChaCha20Rng::from_seed([17u8; 32]);
    let (client_state, client_query) = query(&mut rng, &a_seed, &params, 0).expect("query");
    let response = respond(&out.server, &client_query.query).expect("respond");

    let mut truncated = out.hint.clone();
    truncated.data.truncate((params.l - 1) * params.n);

    let result = extract(&params, &truncated, &client_state, &response);
    assert!(
        matches!(result, Err(IsimplePirError::InvalidParams { .. })),
        "hint declaring L = {} while carrying {} words must fail closed, got {:?}",
        truncated.l,
        truncated.data.len(),
        result,
    );
}

#[test]
fn respond_rejects_short_database() {
    let params = toy_params();
    let db = planted_db(&params);
    let out = setup(&db, params, Some([5u8; 32])).expect("setup");
    let a_seed = out.server.a_seed;

    let mut rng = ChaCha20Rng::from_seed([21u8; 32]);
    let (_, client_query) = query(&mut rng, &a_seed, &params, 0).expect("query");

    let mut short = ServerState {
        db: out.server.db.clone(),
        params,
        a_seed,
        version: out.server.version,
    };
    short.db.truncate(params.l * params.m - params.m);

    let result = respond(&short, &client_query.query);
    assert!(
        matches!(result, Err(IsimplePirError::DatabaseShape { .. })),
        "short database (len {} vs L * M = {}) must fail closed, got {:?}",
        short.db.len(),
        params.l * params.m,
        result.map(|r| r.answer.len()),
    );
}

#[test]
fn state_update_entry_rejects_col_beyond_m() {
    let params = toy_params();
    let db = planted_db(&params);
    let out = setup(&db, params, Some([5u8; 32])).expect("setup");
    let a_seed = out.server.a_seed;
    let mut hint = out.hint.clone();
    let before = hint.data.clone();

    let forged = EntryUpdate {
        row: 0,
        col: params.m,
        gamma: 7,
        version: hint.version.next(),
    };

    let result = state_update_entry(&mut hint, &a_seed, &params, &forged);
    assert!(
        matches!(result, Err(IsimplePirError::DatabaseShape { .. })),
        "col {} beyond M = {} must fail closed, got {:?} (hint mutated: {})",
        forged.col,
        params.m,
        result,
        hint.data != before,
    );
    assert_eq!(
        hint.data, before,
        "rejected update must not mutate the hint"
    );
    assert_eq!(hint.version, HintVersion::INITIAL);
}

#[test]
fn state_update_batch_rejects_col_beyond_m() {
    let params = toy_params();
    let db = planted_db(&params);
    let out = setup(&db, params, Some([5u8; 32])).expect("setup");
    let a_seed = out.server.a_seed;
    let mut hint = out.hint.clone();
    let before = hint.data.clone();

    let mut server = out.server;
    let honest = db_update_modify(&mut server, 1, 1, 42).expect("modify");

    let forged = UpdateBatch {
        beta_edit: vec![EntryUpdate {
            row: 0,
            col: params.m + 3,
            gamma: honest.gamma,
            version: honest.version,
        }],
        beta_del: Vec::new(),
        beta_add: Vec::new(),
        version: honest.version,
    };

    let result = state_update_batch(&mut hint, &a_seed, &params, &forged);
    assert!(
        matches!(result, Err(IsimplePirError::DatabaseShape { .. })),
        "batch col {} beyond M = {} must fail closed, got {:?}",
        params.m + 3,
        params.m,
        result,
    );
    assert_eq!(hint.data, before, "rejected batch must not mutate the hint");
    assert_eq!(hint.version, HintVersion::INITIAL);
}

#[test]
fn honest_batch_still_applies() {
    let params = toy_params();
    let db = planted_db(&params);
    let out = setup(&db, params, Some([5u8; 32])).expect("setup");
    let a_seed = out.server.a_seed;
    let mut hint = out.hint.clone();
    let mut server = out.server;

    let insert_row: Vec<u32> = (0..params.m).map(|j| (j as u32 * 5) % params.p).collect();
    let op = DbBatchOp {
        modifications: &[(0, 1, 13), (2, 3, 77)],
        deletions: &[(1, 0)],
        insertions: &[insert_row.as_slice()],
    };
    let mut rng = ChaCha20Rng::from_seed([31u8; 32]);
    let batch = raven_isimplepir::db_update_batch(&mut server, &op, &mut rng).expect("batch");

    state_update_batch(&mut hint, &a_seed, &params, &batch).expect("state update batch");
    assert_eq!(hint.version, batch.version);
    assert_ne!(hint.version, HintVersion::INITIAL);
    raven_isimplepir::verify_hint_matches_db(&server, &hint).expect("hint tracks db");
}
