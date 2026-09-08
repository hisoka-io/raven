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

// The honest-batch accept direction (mods + deletions + insertions land and the
// hint tracks the db) lives in update_invariant.rs::invariant_after_mixed_batch,
// which additionally pins versions per delta and the grown dims.

// Row-past-L and short/long insert-row rejection, and the byte-identity of the hint
// after either, live in rejection_atomicity_prop.rs::
// a_malformed_batch_is_rejected_and_leaves_the_hint_byte_identical, which draws the
// malformed element at a generated position among generated in-range edits rather than
// at one hand-placed index, and additionally pins hint.l and the version. Proven by
// shared kill under three mutants: staged-clone removed, add_to_row's error swallowed,
// and append_row's width check narrowed from `!=` to `>`.

/// The consequence, end to end: a rejected batch must be RETRYABLE. A
/// half-applied hint is not merely stale, it is unrecoverable - re-applying the
/// corrected batch double-applies whatever already landed, and extract then
/// returns a plaintext no peer ever held, as `Ok`.
#[test]
fn a_rejected_batch_is_retryable_and_converges_on_the_server_value() {
    let params = toy_params();
    let db = planted_db(&params);
    let out = setup(&db, params, Some([5u8; 32])).expect("setup");
    let a_seed = out.server.a_seed;
    let mut hint = out.hint.clone();
    let mut server = out.server;

    // two real edits to the SAME hint row, with the malformed one BETWEEN them:
    // the first lands, the third never runs, and the server holds both - so the
    // hint row is short exactly one gamma contribution
    let (target_row, target_col, planted) = (1usize, 1usize, 42u32);
    let op = DbBatchOp {
        modifications: &[(target_row, target_col, planted), (target_row, 2, 77)],
        deletions: &[],
        insertions: &[],
    };
    let mut batch_rng = ChaCha20Rng::from_seed([31u8; 32]);
    let honest_batch =
        raven_isimplepir::db_update_batch(&mut server, &op, &mut batch_rng).expect("batch");
    assert_eq!(
        honest_batch.beta_edit.len(),
        2,
        "precondition: two real edits to splice between"
    );

    let mut beta_edit = honest_batch.beta_edit.clone();
    beta_edit.insert(
        1,
        EntryUpdate {
            row: params.l + 5,
            col: target_col,
            gamma: beta_edit[0].gamma,
            version: honest_batch.version,
        },
    );
    let forged = UpdateBatch {
        beta_edit,
        beta_del: honest_batch.beta_del.clone(),
        beta_add: honest_batch.beta_add.clone(),
        version: honest_batch.version,
    };
    let result = state_update_batch(&mut hint, &a_seed, &params, &forged);
    assert!(result.is_err(), "precondition: the batch is rejected");

    // the retry: the same batch without the spliced edit. This is the whole
    // point of failing closed - a client that rejected a malformed batch must
    // be able to apply the corrected one and converge.
    state_update_batch(&mut hint, &a_seed, &params, &honest_batch)
        .expect("the corrected batch must apply after a rejected one");
    raven_isimplepir::verify_hint_matches_db(&server, &hint)
        .expect("hint must track the db after a rejected batch is retried");

    let target = target_row * params.m + target_col;
    let mut rng = ChaCha20Rng::from_seed([29u8; 32]);
    let (client_state, client_query) = query(&mut rng, &a_seed, &params, target).expect("query");
    let response = respond(&server, &client_query.query).expect("respond");

    let recovered = extract(&params, &hint, &client_state, &response).expect("extract");
    assert_eq!(
        recovered, planted,
        "extract returned {recovered} for a cell the server holds as {planted}: the rejected \
         batch left the hint half-applied, so the retry double-applied the edit that landed"
    );
}

// Packed-shape rejection - a short buffer, and a forged `m_packed` that stays
// length-consistent - lives in rejection_atomicity_prop.rs::
// respond_packed_answers_a_forged_shape_only_if_squish_db_could_emit_it, which sweeps
// both perturbations over generated L and M against `squish_db` as the oracle and pins
// the error VARIANT (QueryShape iff the query width is wrong, DatabaseShape otherwise).
// Proven by shared kill under three mutants: the buffer-length check removed, the
// ceil(original_m / 3) relation removed, and DatabaseShape swapped for InvalidParams.
