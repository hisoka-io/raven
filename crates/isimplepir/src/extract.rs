//! `Recover`: `result = round((ans[row] - H[row, :] . s) / delta) mod p`.
//! DB stays in `[0, p)` end-to-end (Go reference's `+p/2` recentering
//! omitted; byte-level fixtures differ).

use crate::error::{IsimplePirError, Result};
use crate::hint::ClientHint;
use crate::params::LweParams;
use crate::query::ClientState;
use crate::respond::ServerResponse;

pub fn extract(
    params: &LweParams,
    hint: &ClientHint,
    state: &ClientState,
    response: &ServerResponse,
) -> Result<u32> {
    if hint.l != params.l || hint.n != params.n {
        return Err(IsimplePirError::InvalidParams {
            reason: format!(
                "hint shape ({}, {}) mismatches params (L={}, n={})",
                hint.l, hint.n, params.l, params.n,
            ),
        });
    }
    if state.secret.len() != params.n {
        return Err(IsimplePirError::QueryShape {
            reason: format!(
                "client secret length {} does not match n = {}",
                state.secret.len(),
                params.n,
            ),
        });
    }
    if state.query_vec.len() != params.m {
        return Err(IsimplePirError::QueryShape {
            reason: format!(
                "client query vector length {} does not match M = {}",
                state.query_vec.len(),
                params.m,
            ),
        });
    }
    if response.answer.len() != params.l {
        return Err(IsimplePirError::ResponseShape {
            reason: format!(
                "response length {} does not match L = {}",
                response.answer.len(),
                params.l,
            ),
        });
    }
    if state.row >= params.l {
        return Err(IsimplePirError::QueryShape {
            reason: format!("target row {} out of range for L = {}", state.row, params.l),
        });
    }

    let row_start = state.row.saturating_mul(params.n);
    let mut interm: u32 = 0;
    for j in 0..params.n {
        let h_idx = row_start.saturating_add(j);
        let Some(&h_ij) = hint.data.get(h_idx) else {
            continue;
        };
        let Some(&s_j) = state.secret.get(j) else {
            continue;
        };
        interm = interm.wrapping_add(h_ij.wrapping_mul(s_j));
    }

    let Some(&ans_row) = response.answer.get(state.row) else {
        return Err(IsimplePirError::ResponseShape {
            reason: format!("response row {} out of bounds", state.row),
        });
    };
    let noised = ans_row.wrapping_sub(interm);

    let delta = params.delta();
    if delta == 0 {
        return Err(IsimplePirError::InvalidParams {
            reason: "delta = floor(q/p) is zero; parameters invalid".into(),
        });
    }
    let rounded = noised.wrapping_add(delta / 2) / delta;
    let plaintext = rounded % params.p;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hint::ClientHint;
    use crate::query::ClientState;
    use crate::respond::ServerResponse;
    use crate::version::HintVersion;

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
    fn extract_shape_rejection_hint() {
        let params = toy_params();
        let mut h = ClientHint {
            l: 3, // wrong
            n: params.n,
            data: vec![0u32; 3 * params.n],
            version: HintVersion::INITIAL,
        };
        let s = ClientState {
            secret: vec![0u32; params.n],
            row: 0,
            col: 0,
            query_vec: vec![0u32; params.m],
        };
        let r = ServerResponse {
            answer: vec![0u32; params.l],
        };
        let result = extract(&params, &h, &s, &r);
        assert!(matches!(result, Err(IsimplePirError::InvalidParams { .. })));

        h = ClientHint {
            l: params.l,
            n: params.n,
            data: vec![0u32; params.l * params.n],
            version: HintVersion::INITIAL,
        };
        let bad_s = ClientState {
            secret: vec![0u32; params.n + 1], // wrong
            row: 0,
            col: 0,
            query_vec: vec![0u32; params.m],
        };
        let result = extract(&params, &h, &bad_s, &r);
        assert!(matches!(result, Err(IsimplePirError::QueryShape { .. })));
    }

    #[test]
    fn extract_rejects_oor_row() {
        let params = toy_params();
        let h = ClientHint {
            l: params.l,
            n: params.n,
            data: vec![0u32; params.l * params.n],
            version: HintVersion::INITIAL,
        };
        let s = ClientState {
            secret: vec![0u32; params.n],
            row: 99,
            col: 0,
            query_vec: vec![0u32; params.m],
        };
        let r = ServerResponse {
            answer: vec![0u32; params.l],
        };
        assert!(matches!(
            extract(&params, &h, &s, &r),
            Err(IsimplePirError::QueryShape { .. })
        ));
    }
}
