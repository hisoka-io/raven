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
    DbBatchOp, EntryUpdate, HintVersion, InsertDelta, IsimplePirError, LweParams, ServerState,
    UpdateBatch,
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

/// `row` is not pre-validated, so a rejected batch must still leave the hint
/// byte-identical. The sibling `col` test cannot show this: `col` IS
/// pre-validated, so it rejects before the mutation loop is entered.
#[test]
fn state_update_batch_rejects_row_beyond_l_atomically() {
    let params = toy_params();
    let db = planted_db(&params);
    let out = setup(&db, params, Some([5u8; 32])).expect("setup");
    let a_seed = out.server.a_seed;
    let mut hint = out.hint.clone();
    let before = hint.data.clone();

    let mut server = out.server;
    let honest = db_update_modify(&mut server, 1, 1, 42).expect("modify");

    // the first edit is well-formed and lands; the second is out of range, so
    // a non-atomic apply leaves the first one behind
    let forged = UpdateBatch {
        beta_edit: vec![
            EntryUpdate {
                row: 0,
                col: 1,
                gamma: honest.gamma,
                version: honest.version,
            },
            EntryUpdate {
                row: params.l + 5,
                col: 1,
                gamma: honest.gamma,
                version: honest.version,
            },
        ],
        beta_del: Vec::new(),
        beta_add: Vec::new(),
        version: honest.version,
    };

    let result = state_update_batch(&mut hint, &a_seed, &params, &forged);
    assert!(
        result.is_err(),
        "batch row {} beyond L = {} must fail closed, got {:?}",
        params.l + 5,
        params.l,
        result,
    );
    assert_eq!(
        hint.data, before,
        "a rejected batch left the hint partially mutated: the first edit was applied \
         before the second was rejected"
    );
    assert_eq!(hint.version, HintVersion::INITIAL);
}

/// `w_prime.len()` is not pre-validated either, and `beta_add` runs after every
/// edit, so a malformed insert row abandons the whole edit set applied.
#[test]
fn state_update_batch_rejects_short_insert_row_atomically() {
    let params = toy_params();
    let db = planted_db(&params);
    let out = setup(&db, params, Some([5u8; 32])).expect("setup");
    let a_seed = out.server.a_seed;
    let mut hint = out.hint.clone();
    let before = hint.data.clone();
    let rows_before = hint.l;

    let mut server = out.server;
    let honest = db_update_modify(&mut server, 1, 1, 42).expect("modify");

    let forged = UpdateBatch {
        beta_edit: vec![EntryUpdate {
            row: 0,
            col: 1,
            gamma: honest.gamma,
            version: honest.version,
        }],
        beta_del: Vec::new(),
        beta_add: vec![InsertDelta {
            w_prime: vec![0u32; params.n - 1],
            version: honest.version,
        }],
        version: honest.version,
    };

    let result = state_update_batch(&mut hint, &a_seed, &params, &forged);
    assert!(
        result.is_err(),
        "insert row of length {} against n = {} must fail closed, got {:?}",
        params.n - 1,
        params.n,
        result,
    );
    assert_eq!(
        hint.data, before,
        "a rejected batch left the edit set applied before the insert was rejected"
    );
    assert_eq!(hint.l, rows_before, "rejected batch must not grow the hint");
    assert_eq!(hint.version, HintVersion::INITIAL);
}

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

/// `SquishedDatabase` has public fields and derives `Deserialize`, so a peer
/// declares `data`, `m_packed` and `original_m` independently. The packed
/// kernels read cells through `.get()`, so a short buffer reads as zeros and
/// answers `Ok` with a vector no database produces.
#[test]
fn respond_packed_rejects_short_packed_database() {
    let params = toy_params();
    let db = planted_db(&params);
    let out = setup(&db, params, Some([5u8; 32])).expect("setup");
    let a_seed = out.server.a_seed;

    let mut rng = ChaCha20Rng::from_seed([23u8; 32]);
    let (_, client_query) = query(&mut rng, &a_seed, &params, 0).expect("query");

    let honest = raven_isimplepir::squish_db(&out.server.db, &params).expect("squish");
    let packed_answer = raven_isimplepir::respond_packed(&honest, &client_query.query)
        .expect("respond_packed")
        .answer;
    let plain_answer = respond(&out.server, &client_query.query)
        .expect("respond")
        .answer;
    assert_eq!(
        packed_answer, plain_answer,
        "precondition: a well-formed packed db byte-matches respond"
    );

    let mut short = honest.clone();
    short.data.truncate(honest.data.len() - honest.m_packed);

    let result = raven_isimplepir::respond_packed(&short, &client_query.query);
    assert!(
        matches!(result, Err(IsimplePirError::DatabaseShape { .. })),
        "short packed database (len {} vs L * m_packed = {} * {} = {}) must fail closed, \
         got {:?} against the honest answer {:?}",
        short.data.len(),
        short.l,
        short.m_packed,
        short.l * short.m_packed,
        result.map(|r| r.answer),
        packed_answer,
    );
}

/// A forged `m_packed` that keeps `data.len() == l * m_packed` re-strides every
/// row while staying length-consistent, so the buffer-length check cannot be
/// what rejects it - only the `ceil(original_m / SQUISH_COMPRESSION)` relation
/// can. Both directions are covered: too few cells drops trailing columns, too
/// many reads the next row's cells as this row's.
#[test]
fn respond_packed_rejects_m_packed_inconsistent_with_original_m() {
    let params = toy_params();
    let db = planted_db(&params);
    let out = setup(&db, params, Some([5u8; 32])).expect("setup");
    let a_seed = out.server.a_seed;

    let mut rng = ChaCha20Rng::from_seed([27u8; 32]);
    let (_, client_query) = query(&mut rng, &a_seed, &params, 0).expect("query");

    let honest = raven_isimplepir::squish_db(&out.server.db, &params).expect("squish");
    assert_eq!(
        honest.m_packed, 2,
        "precondition: M = {} packs into 2 cells",
        params.m
    );

    for forged_m_packed in [1usize, 4] {
        let mut forged = honest.clone();
        forged.m_packed = forged_m_packed;
        forged.data.resize(forged.l * forged_m_packed, 0);

        let result = raven_isimplepir::respond_packed(&forged, &client_query.query);
        assert!(
            matches!(result, Err(IsimplePirError::DatabaseShape { .. })),
            "m_packed {} against original M = {} (ceil = {}) must fail closed even though \
             data len {} still equals L * m_packed = {}, got {:?}",
            forged_m_packed,
            forged.original_m,
            honest.m_packed,
            forged.data.len(),
            forged.l * forged_m_packed,
            result.map(|r| r.answer),
        );
    }
}
