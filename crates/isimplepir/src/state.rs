//! Theorem 3 oracle: recompute `D . A` and compare to the
//! incremental hint.

use crate::error::{IsimplePirError, Result};
use crate::hint::ClientHint;
use crate::setup::{compute_hint, derive_a_matrix, ServerState};

/// Mismatch is a Rust bug, not a scheme issue.
pub fn verify_hint_matches_db(state: &ServerState, hint: &ClientHint) -> Result<()> {
    if hint.l != state.params.l || hint.n != state.params.n {
        return Err(IsimplePirError::InvalidParams {
            reason: format!(
                "hint shape ({}, {}) mismatches server params (L={}, n={})",
                hint.l, hint.n, state.params.l, state.params.n,
            ),
        });
    }
    if hint.version != state.version {
        return Err(IsimplePirError::VersionMismatch {
            expected: state.version.get(),
            received: hint.version.get(),
        });
    }

    let a_matrix = derive_a_matrix(&state.a_seed, &state.params)?;
    let recomputed = compute_hint(&state.db, &a_matrix, &state.params);

    if recomputed.len() != hint.data.len() {
        return Err(IsimplePirError::InvalidParams {
            reason: format!(
                "recomputed hint length {} mismatches stored {}",
                recomputed.len(),
                hint.data.len(),
            ),
        });
    }
    for (idx, (a, b)) in recomputed.iter().zip(hint.data.iter()).enumerate() {
        if a != b {
            return Err(IsimplePirError::InvalidParams {
                reason: format!(
                    "hint mismatch at index {idx}: recomputed = {a}, stored = {b}. \
                     Theorem 3 invariant violated, implementation bug.",
                ),
            });
        }
    }
    Ok(())
}
