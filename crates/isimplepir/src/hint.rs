//! Client hint storage. Derivation in `setup.rs`, updates in
//! `update.rs`.

use serde::{Deserialize, Serialize};

use crate::error::{IsimplePirError, Result};
use crate::params::LweParams;
use crate::version::HintVersion;

/// `H in Z_q^{L x n}` row-major. `data[i * n + j] = H[i, j]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientHint {
    pub l: usize,
    pub n: usize,
    pub data: Vec<u32>,
    pub version: HintVersion,
}

impl ClientHint {
    pub fn zeros(params: &LweParams) -> Self {
        Self {
            l: params.l,
            n: params.n,
            data: vec![0u32; params.l.saturating_mul(params.n)],
            version: HintVersion::INITIAL,
        }
    }

    pub fn get(&self, row: usize, col: usize) -> Result<u32> {
        if row >= self.l || col >= self.n {
            return Err(IsimplePirError::QueryShape {
                reason: format!(
                    "hint index out of range: ({row}, {col}) vs L={}, n={}",
                    self.l, self.n,
                ),
            });
        }
        let idx = row.saturating_mul(self.n).saturating_add(col);
        self.data
            .get(idx)
            .copied()
            .ok_or_else(|| IsimplePirError::QueryShape {
                reason: "hint storage corrupt (length shorter than L * n)".into(),
            })
    }

    /// Add a delta vector to `H[row, :]` (StateUpdate step 2).
    pub fn add_to_row(&mut self, row: usize, delta: &[u32]) -> Result<()> {
        if row >= self.l {
            return Err(IsimplePirError::ResponseShape {
                reason: format!("row index {row} out of range (L = {})", self.l),
            });
        }
        if delta.len() != self.n {
            return Err(IsimplePirError::ResponseShape {
                reason: format!(
                    "delta length {} does not match hint n = {}",
                    delta.len(),
                    self.n,
                ),
            });
        }
        let start = row.saturating_mul(self.n);
        let end = start.saturating_add(self.n);
        if end > self.data.len() {
            return Err(IsimplePirError::QueryShape {
                reason: "hint storage corrupt (length shorter than L * n)".into(),
            });
        }
        // Safe because we checked `end <= self.data.len()`.
        #[allow(clippy::indexing_slicing)]
        for (dest, src) in self.data[start..end].iter_mut().zip(delta.iter()) {
            *dest = dest.wrapping_add(*src);
        }
        Ok(())
    }

    /// Append a row to the hint (StateUpdate step 1; append-only).
    pub fn append_row(&mut self, new_row: &[u32]) -> Result<()> {
        if new_row.len() != self.n {
            return Err(IsimplePirError::ResponseShape {
                reason: format!(
                    "new row length {} does not match hint n = {}",
                    new_row.len(),
                    self.n,
                ),
            });
        }
        self.data.extend_from_slice(new_row);
        self.l = self.l.saturating_add(1);
        Ok(())
    }

    pub fn size_bytes(&self) -> usize {
        self.data.len().saturating_mul(std::mem::size_of::<u32>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toy_params() -> LweParams {
        LweParams {
            n: crate::params::LWE_DIM,
            log2_q: crate::params::CIPHERTEXT_MODULUS_LOG2,
            p: 991,
            l: 4,
            m: 4,
            bits_per_element: 9,
        }
    }

    #[test]
    fn zero_hint_has_correct_shape() {
        let p = toy_params();
        let h = ClientHint::zeros(&p);
        assert_eq!(h.l, 4);
        assert_eq!(h.n, crate::params::LWE_DIM);
        assert_eq!(h.data.len(), 4 * crate::params::LWE_DIM);
        assert!(h.data.iter().all(|&x| x == 0));
        assert_eq!(h.version, HintVersion::INITIAL);
    }

    #[test]
    fn add_to_row_wraps_u32() {
        let p = toy_params();
        let mut h = ClientHint::zeros(&p);
        let delta = vec![u32::MAX; crate::params::LWE_DIM];
        h.add_to_row(0, &delta).expect("add delta");
        // Wrapping: 0 + u32::MAX = u32::MAX.
        assert_eq!(h.get(0, 0).expect("get"), u32::MAX);
        // Add the same delta again: u32::MAX + u32::MAX = u32::MAX - 1 (wrap).
        h.add_to_row(0, &delta).expect("add delta 2");
        assert_eq!(h.get(0, 0).expect("get 2"), u32::MAX.wrapping_add(u32::MAX));
    }

    #[test]
    fn append_row_grows_l() {
        let p = toy_params();
        let mut h = ClientHint::zeros(&p);
        assert_eq!(h.l, 4);
        let new_row = vec![1u32; crate::params::LWE_DIM];
        h.append_row(&new_row).expect("append");
        assert_eq!(h.l, 5);
        assert_eq!(h.get(4, 0).expect("get appended"), 1);
    }

    #[test]
    fn row_length_mismatch_rejected() {
        let p = toy_params();
        let mut h = ClientHint::zeros(&p);
        let bad = vec![0u32; 7]; // wrong length
        assert!(matches!(
            h.add_to_row(0, &bad),
            Err(IsimplePirError::ResponseShape { .. }),
        ));
    }
}
