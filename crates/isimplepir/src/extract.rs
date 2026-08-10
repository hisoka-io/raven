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
    let expected_hint_len = params.l.saturating_mul(params.n);
    if hint.l != params.l || hint.n != params.n || hint.data.len() != expected_hint_len {
        return Err(IsimplePirError::InvalidParams {
            reason: format!(
                "hint shape (L={}, n={}, data={}) mismatches params (L={}, n={}, data={})",
                hint.l,
                hint.n,
                hint.data.len(),
                params.l,
                params.n,
                expected_hint_len,
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
    // zip caps the row at secret.len(), checked == n above
    for (&h_ij, &s_j) in hint.data.iter().skip(row_start).zip(state.secret.iter()) {
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

    /// Every row carries a delta-scale ramp, so reading a neighbouring row - or stopping the
    /// dot product short of n - lands on a different plaintext instead of rounding back.
    #[test]
    fn extract_reads_only_the_targeted_hint_row() {
        let params = toy_params();
        let delta = params.delta();
        let data: Vec<u32> = (0..params.l * params.n)
            .map(|i| delta.wrapping_mul(i as u32 + 1))
            .collect();
        let hint = ClientHint {
            l: params.l,
            n: params.n,
            data,
            version: HintVersion::INITIAL,
        };
        let secret = vec![1u32; params.n];

        for row in 0..params.l {
            let row_sum = hint.data[row * params.n..(row + 1) * params.n]
                .iter()
                .fold(0u32, |acc, &h_ij| acc.wrapping_add(h_ij));
            let expected = row as u32 + 1;
            let mut answer = vec![0u32; params.l];
            answer[row] = row_sum.wrapping_add(delta.wrapping_mul(expected));
            let state = ClientState {
                secret: secret.clone(),
                row,
                col: 0,
                query_vec: vec![0u32; params.m],
            };
            let response = ServerResponse { answer };
            assert_eq!(
                extract(&params, &hint, &state, &response).expect("extract"),
                expected,
                "row {row} must fold exactly hint.data[{}..{}]",
                row * params.n,
                (row + 1) * params.n
            );
        }
    }

    /// The last row's span ends exactly at `data.len()`, the tightest case for the row offset.
    #[test]
    fn extract_accepts_the_final_row() {
        let params = toy_params();
        let delta = params.delta();
        let row = params.l - 1;
        let mut data = vec![0u32; params.l * params.n];
        for slot in &mut data[row * params.n..] {
            *slot = delta;
        }
        let hint = ClientHint {
            l: params.l,
            n: params.n,
            data,
            version: HintVersion::INITIAL,
        };
        let state = ClientState {
            secret: vec![1u32; params.n],
            row,
            col: 0,
            query_vec: vec![0u32; params.m],
        };
        let mut answer = vec![0u32; params.l];
        answer[row] = delta
            .wrapping_mul(params.n as u32)
            .wrapping_add(delta.wrapping_mul(3));
        let response = ServerResponse { answer };
        assert_eq!(
            extract(&params, &hint, &state, &response).expect("extract"),
            3
        );
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
