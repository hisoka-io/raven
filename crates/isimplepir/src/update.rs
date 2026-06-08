//! `DBUpdate` + `StateUpdate` (eprint 2026/030 Fig. 2 Construction 1),
//! preserving Theorem 3. Deletion is weak only: a pre-deletion client
//! retaining the hint can recover deleted entries; strong deletion
//! requires re-running `Setup`.

use rand_core::RngCore;
use rand_core::TryRngCore;
use serde::{Deserialize, Serialize};

use crate::error::{IsimplePirError, Result};
use crate::hint::ClientHint;
use crate::setup::{derive_a_matrix, ServerState};
use crate::version::HintVersion;

/// Entry-level delta. `gamma = new_value - old_value mod q` (u32
/// wrapping; mod-p would break Theorem 3 on negative rolls).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryUpdate {
    pub row: usize,
    pub col: usize,
    pub gamma: u32,
    pub version: HintVersion,
}

/// Row-aggregated delta: `u'_i = Sum_j gamma_j * A[j] in Z_q^n`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowUpdate {
    pub row: usize,
    /// Length `params.n`.
    pub u_prime: Vec<u32>,
    pub version: HintVersion,
}

/// Append-only insertion delta. `w'_i = w_i * A in Z_q^n`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsertDelta {
    pub w_prime: Vec<u32>,
    pub version: HintVersion,
}

/// Crossover `t = ceil(n * log q / (log p + log sqrt(N)))`. Above
/// `t` edits to a single row, prefer a row aggregate.
pub fn row_aggregation_threshold(params: &crate::params::LweParams) -> Option<u64> {
    let n = params.n as f64;
    let log_q = f64::from(params.log2_q);
    let log_p = f64::from(params.p).log2();
    let total_elements = (params.l as f64) * (params.m as f64);
    let log_sqrt_n = total_elements.sqrt().log2();
    let denom = log_p + log_sqrt_n;
    if denom <= 0.0 {
        return None;
    }
    let raw = (n * log_q / denom).ceil();
    if raw < 0.0 || raw > f64::from(u32::MAX) * 2.0 {
        return None;
    }
    Some(raw as u64)
}

/// `DBUpdate` for an in-place mod. `new_value` must be in `[0, p)`.
pub fn db_update_modify(
    state: &mut ServerState,
    row: usize,
    col: usize,
    new_value: u32,
) -> Result<EntryUpdate> {
    if row >= state.params.l || col >= state.params.m {
        return Err(IsimplePirError::DatabaseShape {
            reason: format!(
                "update ({row}, {col}) out of range for L={}, M={}",
                state.params.l, state.params.m,
            ),
        });
    }
    if new_value >= state.params.p {
        return Err(IsimplePirError::PlaintextOutOfBound {
            value_abs: u64::from(new_value),
            half_p: u64::from(state.params.half_p()),
        });
    }
    let idx = row.saturating_mul(state.params.m).saturating_add(col);
    let Some(slot) = state.db.get_mut(idx) else {
        return Err(IsimplePirError::DatabaseShape {
            reason: format!("DB index {idx} out of range"),
        });
    };
    let old_value = *slot;
    *slot = new_value;

    let gamma = new_value.wrapping_sub(old_value);

    state.version = state.version.next();
    Ok(EntryUpdate {
        row,
        col,
        gamma,
        version: state.version,
    })
}

/// `DBUpdate` for a deletion. Replaces the entry with `r` uniform in
/// `Z_p`. `rng` MUST be OS entropy; a predictable `r` lets a client
/// subtract it from a follow-up query and recover the original.
/// Weak deletion only (eprint 2026/030 sec 2.4).
pub fn db_update_delete<R: RngCore>(
    state: &mut ServerState,
    row: usize,
    col: usize,
    rng: &mut R,
) -> Result<EntryUpdate> {
    if row >= state.params.l || col >= state.params.m {
        return Err(IsimplePirError::DatabaseShape {
            reason: format!(
                "delete ({row}, {col}) out of range for L={}, M={}",
                state.params.l, state.params.m,
            ),
        });
    }
    let p = state.params.p;
    let mut buf = [0u8; 4];
    let r = loop {
        rng.try_fill_bytes(&mut buf)
            .map_err(|e| IsimplePirError::Randomness(format!("rng fill: {e}")))?;
        let candidate = u32::from_le_bytes(buf);
        let ceil = (u32::MAX / p).saturating_mul(p);
        if candidate < ceil {
            break candidate % p;
        }
    };
    db_update_modify(state, row, col, r)
}

/// `DBUpdate` for an append-only insertion. `new_row` length `M`,
/// values in `[0, p)`.
pub fn db_update_insert(state: &mut ServerState, new_row: &[u32]) -> Result<InsertDelta> {
    let m = state.params.m;
    let n = state.params.n;
    let p = state.params.p;
    let half_p = state.params.half_p();
    let a_seed = state.a_seed;
    let params_snapshot = state.params;

    if new_row.len() != m {
        return Err(IsimplePirError::DatabaseShape {
            reason: format!("insert row length {} mismatches M = {}", new_row.len(), m),
        });
    }
    for &v in new_row.iter() {
        if v >= p {
            return Err(IsimplePirError::PlaintextOutOfBound {
                value_abs: u64::from(v),
                half_p: u64::from(half_p),
            });
        }
    }

    let a_matrix = derive_a_matrix(&a_seed, &params_snapshot)?;

    state.db.extend_from_slice(new_row);
    state.params = crate::params::LweParams {
        l: state.params.l.saturating_add(1),
        ..state.params
    };

    let mut w_prime = vec![0u32; n];
    for k in 0..m {
        let Some(&w_k) = new_row.get(k) else {
            continue;
        };
        if w_k == 0 {
            continue;
        }
        let a_row_start = k.saturating_mul(n);
        for j in 0..n {
            let a_idx = a_row_start.saturating_add(j);
            let Some(&a_kj) = a_matrix.get(a_idx) else {
                continue;
            };
            let Some(slot) = w_prime.get_mut(j) else {
                continue;
            };
            *slot = slot.wrapping_add(w_k.wrapping_mul(a_kj));
        }
    }

    state.version = state.version.next();
    Ok(InsertDelta {
        w_prime,
        version: state.version,
    })
}

/// `StateUpdate` for entry-level mod/del. Adds `gamma * A[col]`
/// to `H[row, :]`. Out-of-order updates raise `VersionMismatch`.
pub fn state_update_entry(
    hint: &mut ClientHint,
    a_seed: &[u8; crate::setup::SEED_BYTES],
    params: &crate::params::LweParams,
    delta: &EntryUpdate,
) -> Result<()> {
    let expected = hint.version.next();
    if delta.version != expected {
        return Err(IsimplePirError::VersionMismatch {
            expected: expected.get(),
            received: delta.version.get(),
        });
    }

    let a_matrix = derive_a_matrix(a_seed, params)?;
    let row_start = delta.col.saturating_mul(params.n);
    let mut x_i = vec![0u32; params.n];
    for j in 0..params.n {
        let a_idx = row_start.saturating_add(j);
        let Some(&a_cj) = a_matrix.get(a_idx) else {
            continue;
        };
        let Some(slot) = x_i.get_mut(j) else {
            continue;
        };
        *slot = delta.gamma.wrapping_mul(a_cj);
    }
    hint.add_to_row(delta.row, &x_i)?;
    hint.version = delta.version;
    Ok(())
}

pub fn state_update_insert(hint: &mut ClientHint, delta: &InsertDelta) -> Result<()> {
    let expected = hint.version.next();
    if delta.version != expected {
        return Err(IsimplePirError::VersionMismatch {
            expected: expected.get(),
            received: delta.version.get(),
        });
    }
    hint.append_row(&delta.w_prime)?;
    hint.version = delta.version;
    Ok(())
}

/// `DBUpdate` row-aggregating k mods on one row into one
/// `u'_i in Z_q^n`. Duplicate `col`s merge by summing gamma.
/// Version bumps once.
pub fn db_update_row_modifications(
    state: &mut ServerState,
    row: usize,
    edits: &[(usize, u32)],
) -> Result<RowUpdate> {
    let m = state.params.m;
    let n = state.params.n;
    let p = state.params.p;
    let half_p = state.params.half_p();
    let a_seed = state.a_seed;
    let params_snapshot = state.params;

    if row >= state.params.l {
        return Err(IsimplePirError::DatabaseShape {
            reason: format!(
                "row-agg row index {row} out of range for L = {}",
                state.params.l,
            ),
        });
    }

    for &(col, new_value) in edits {
        if col >= m {
            return Err(IsimplePirError::DatabaseShape {
                reason: format!("row-agg col index {col} out of range for M = {m}"),
            });
        }
        if new_value >= p {
            return Err(IsimplePirError::PlaintextOutOfBound {
                value_abs: u64::from(new_value),
                half_p: u64::from(half_p),
            });
        }
    }

    let row_start = row.saturating_mul(m);
    let mut gamma_by_col: Vec<(usize, u32)> = Vec::with_capacity(edits.len());
    for &(col, new_value) in edits {
        let idx = row_start.saturating_add(col);
        let Some(slot) = state.db.get_mut(idx) else {
            return Err(IsimplePirError::DatabaseShape {
                reason: format!("row-agg DB index {idx} out of range"),
            });
        };
        let old_value = *slot;
        *slot = new_value;
        let gamma = new_value.wrapping_sub(old_value);
        if let Some(existing) = gamma_by_col.iter_mut().find(|(c, _)| *c == col) {
            existing.1 = existing.1.wrapping_add(gamma);
        } else {
            gamma_by_col.push((col, gamma));
        }
    }

    let a_matrix = derive_a_matrix(&a_seed, &params_snapshot)?;
    let mut u_prime = vec![0u32; n];
    for (col, gamma) in &gamma_by_col {
        if *gamma == 0 {
            continue;
        }
        let a_row_start = col.saturating_mul(n);
        for j in 0..n {
            let a_idx = a_row_start.saturating_add(j);
            let Some(&a_cj) = a_matrix.get(a_idx) else {
                continue;
            };
            let Some(slot) = u_prime.get_mut(j) else {
                continue;
            };
            *slot = slot.wrapping_add(gamma.wrapping_mul(a_cj));
        }
    }

    state.version = state.version.next();
    Ok(RowUpdate {
        row,
        u_prime,
        version: state.version,
    })
}

/// Row-aggregated deletions. `rng` MUST be OS entropy.
pub fn db_update_row_deletions<R: RngCore>(
    state: &mut ServerState,
    row: usize,
    cols: &[usize],
    rng: &mut R,
) -> Result<RowUpdate> {
    let p = state.params.p;
    let mut edits: Vec<(usize, u32)> = Vec::with_capacity(cols.len());
    let mut buf = [0u8; 4];
    for &col in cols {
        let r = loop {
            rng.try_fill_bytes(&mut buf)
                .map_err(|e| IsimplePirError::Randomness(format!("rng fill: {e}")))?;
            let candidate = u32::from_le_bytes(buf);
            let ceil = (u32::MAX / p).saturating_mul(p);
            if candidate < ceil {
                break candidate % p;
            }
        };
        edits.push((col, r));
    }
    db_update_row_modifications(state, row, &edits)
}

pub fn state_update_row(hint: &mut ClientHint, delta: &RowUpdate) -> Result<()> {
    let expected = hint.version.next();
    if delta.version != expected {
        return Err(IsimplePirError::VersionMismatch {
            expected: expected.get(),
            received: delta.version.get(),
        });
    }
    hint.add_to_row(delta.row, &delta.u_prime)?;
    hint.version = delta.version;
    Ok(())
}

/// Mixed batch input. Insert rows must have length `M`, values in `[0, p)`.
#[derive(Clone, Debug)]
pub struct DbBatchOp<'a> {
    pub modifications: &'a [(usize, usize, u32)],
    pub deletions: &'a [(usize, usize)],
    pub insertions: &'a [&'a [u32]],
}

/// `beta = (beta_edit, beta_del, beta_add)` sharing one version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateBatch {
    pub beta_edit: Vec<EntryUpdate>,
    pub beta_del: Vec<EntryUpdate>,
    pub beta_add: Vec<InsertDelta>,
    pub version: HintVersion,
}

/// Validates all categories upfront (atomicity), then commits.
/// On success `state.version` bumps once and every inner delta
/// carries the same version. Empty batch is a legal no-op.
/// Commit-phase failures (RNG exhaustion, allocation panic) leave
/// `state` corrupted; treat the result as terminal.
pub fn db_update_batch<R: RngCore>(
    state: &mut ServerState,
    op: &DbBatchOp<'_>,
    rng: &mut R,
) -> Result<UpdateBatch> {
    let l = state.params.l;
    let m = state.params.m;
    let p = state.params.p;
    let half_p = state.params.half_p();

    for &(row, col, new_value) in op.modifications {
        if row >= l {
            return Err(IsimplePirError::DatabaseShape {
                reason: format!("batch mod row {row} out of range (L = {l})"),
            });
        }
        if col >= m {
            return Err(IsimplePirError::DatabaseShape {
                reason: format!("batch mod col {col} out of range (M = {m})"),
            });
        }
        if new_value >= p {
            return Err(IsimplePirError::PlaintextOutOfBound {
                value_abs: u64::from(new_value),
                half_p: u64::from(half_p),
            });
        }
    }
    for &(row, col) in op.deletions {
        if row >= l {
            return Err(IsimplePirError::DatabaseShape {
                reason: format!("batch del row {row} out of range (L = {l})"),
            });
        }
        if col >= m {
            return Err(IsimplePirError::DatabaseShape {
                reason: format!("batch del col {col} out of range (M = {m})"),
            });
        }
    }
    for (idx, &new_row) in op.insertions.iter().enumerate() {
        if new_row.len() != m {
            return Err(IsimplePirError::DatabaseShape {
                reason: format!(
                    "batch insert #{idx} row length {} mismatches M = {m}",
                    new_row.len(),
                ),
            });
        }
        for &v in new_row {
            if v >= p {
                return Err(IsimplePirError::PlaintextOutOfBound {
                    value_abs: u64::from(v),
                    half_p: u64::from(half_p),
                });
            }
        }
    }

    let total = op
        .modifications
        .len()
        .saturating_add(op.deletions.len())
        .saturating_add(op.insertions.len());
    if total == 0 {
        return Ok(UpdateBatch {
            beta_edit: Vec::new(),
            beta_del: Vec::new(),
            beta_add: Vec::new(),
            version: state.version,
        });
    }

    let batch_version = state.version.next();

    let mut beta_edit = Vec::with_capacity(op.modifications.len());
    for &(row, col, new_value) in op.modifications {
        let mut delta = db_update_modify(state, row, col, new_value)?;
        delta.version = batch_version;
        beta_edit.push(delta);
    }

    let mut beta_del = Vec::with_capacity(op.deletions.len());
    for &(row, col) in op.deletions {
        let mut delta = db_update_delete(state, row, col, rng)?;
        delta.version = batch_version;
        beta_del.push(delta);
    }

    let mut beta_add = Vec::with_capacity(op.insertions.len());
    for &new_row in op.insertions {
        let mut delta = db_update_insert(state, new_row)?;
        delta.version = batch_version;
        beta_add.push(delta);
    }

    state.version = batch_version;

    Ok(UpdateBatch {
        beta_edit,
        beta_del,
        beta_add,
        version: batch_version,
    })
}

/// `StateUpdate` for a batch. Applies edits, deletes, then inserts
/// under one version bump. Inlines arithmetic so `A` is derived
/// once per batch.
pub fn state_update_batch(
    hint: &mut ClientHint,
    a_seed: &[u8; crate::setup::SEED_BYTES],
    params: &crate::params::LweParams,
    delta: &UpdateBatch,
) -> Result<()> {
    if delta.beta_edit.is_empty()
        && delta.beta_del.is_empty()
        && delta.beta_add.is_empty()
        && delta.version == hint.version
    {
        return Ok(());
    }

    let expected = hint.version.next();
    if delta.version != expected {
        return Err(IsimplePirError::VersionMismatch {
            expected: expected.get(),
            received: delta.version.get(),
        });
    }

    for inner in delta.beta_edit.iter().chain(delta.beta_del.iter()) {
        if inner.version != delta.version {
            return Err(IsimplePirError::VersionMismatch {
                expected: delta.version.get(),
                received: inner.version.get(),
            });
        }
    }
    for inner in &delta.beta_add {
        if inner.version != delta.version {
            return Err(IsimplePirError::VersionMismatch {
                expected: delta.version.get(),
                received: inner.version.get(),
            });
        }
    }

    let a_matrix = derive_a_matrix(a_seed, params)?;

    for edit in delta.beta_edit.iter().chain(delta.beta_del.iter()) {
        let row_start = edit.col.saturating_mul(params.n);
        let mut x_i = vec![0u32; params.n];
        for j in 0..params.n {
            let a_idx = row_start.saturating_add(j);
            let Some(&a_cj) = a_matrix.get(a_idx) else {
                continue;
            };
            let Some(slot) = x_i.get_mut(j) else {
                continue;
            };
            *slot = edit.gamma.wrapping_mul(a_cj);
        }
        hint.add_to_row(edit.row, &x_i)?;
    }

    for insert in &delta.beta_add {
        hint.append_row(&insert.w_prime)?;
    }

    hint.version = delta.version;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::LweParams;
    use crate::setup::setup;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn toy_params() -> LweParams {
        LweParams {
            n: 8,
            log2_q: 32,
            p: 17,
            l: 4,
            m: 4,
            bits_per_element: 4,
        }
    }

    #[test]
    fn modify_updates_version_and_db() {
        let params = toy_params();
        let db: Vec<u32> = (0..16u32).map(|i| i % params.p).collect();
        let out = setup(&db, params, Some([0u8; 32])).expect("setup");
        let mut state = out.server;

        let initial_version = state.version;
        let result = db_update_modify(&mut state, 1, 2, 10).expect("modify");

        assert_eq!(state.version, initial_version.next());
        assert_eq!(state.db[params.m + 2], 10);
        assert_eq!(result.row, 1);
        assert_eq!(result.col, 2);
        assert_eq!(result.version, state.version);
    }

    #[test]
    fn modify_rejects_out_of_bound_plaintext() {
        let params = toy_params();
        let db: Vec<u32> = vec![0u32; params.l * params.m];
        let out = setup(&db, params, Some([0u8; 32])).expect("setup");
        let mut state = out.server;
        let result = db_update_modify(&mut state, 0, 0, params.p);
        assert!(matches!(
            result,
            Err(IsimplePirError::PlaintextOutOfBound { .. })
        ));
    }

    #[test]
    fn state_update_version_mismatch_rejected() {
        let params = toy_params();
        let db: Vec<u32> = vec![0u32; params.l * params.m];
        let out = setup(&db, params, Some([0u8; 32])).expect("setup");
        let mut hint = out.hint.clone();
        let a_seed = out.server.a_seed;
        let mut state = out.server;

        let _d1 = db_update_modify(&mut state, 0, 0, 1).expect("d1");
        let d2 = db_update_modify(&mut state, 0, 1, 2).expect("d2");

        let result = state_update_entry(&mut hint, &a_seed, &params, &d2);
        assert!(matches!(
            result,
            Err(IsimplePirError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn row_aggregation_threshold_positive_for_valid_params() {
        let params = toy_params();
        let t = row_aggregation_threshold(&params);
        assert!(t.is_some());
        assert!(t.unwrap() > 0);
    }

    #[test]
    fn delete_produces_entry_in_zp() {
        let params = toy_params();
        let db: Vec<u32> = (0..16u32).map(|i| i % params.p).collect();
        let out = setup(&db, params, Some([0u8; 32])).expect("setup");
        let mut state = out.server;
        let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
        let delta = db_update_delete(&mut state, 0, 0, &mut rng).expect("delete");
        let new_val = state.db[0];
        assert!(new_val < params.p, "r must be in [0, p)");
        let _ = delta.gamma;
    }
}
