//! SimplePIR parameter calibration. Table 16 from eprint 2022/949
//! sec 4.2 at `(n, q, sigma, delta) = (1024, 2^32, 6.4, 2^-40)`.

use serde::{Deserialize, Serialize};

use crate::error::{IsimplePirError, Result};

pub const LWE_DIM: usize = 1024;
pub const CIPHERTEXT_MODULUS_LOG2: u32 = 32;
pub const GAUSSIAN_SIGMA: f64 = 6.4;
pub const CORRECTNESS_DELTA_LOG2_NEG: f64 = 40.0;

/// `sqrt(2) * sigma * sqrt(ln(2/delta))` at `(6.4, 2^-40)`.
pub const EQ2_COEFFICIENT: f64 = 48.2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Table16Row {
    pub log_m: u32,
    pub p: u32,
}

/// Table 16. For cells between rows, pick the next-smaller-or-equal
/// row (smaller `p` widens the Eq. (2) margin).
pub const TABLE_16: &[Table16Row] = &[
    Table16Row { log_m: 13, p: 991 },
    Table16Row { log_m: 14, p: 833 },
    Table16Row { log_m: 15, p: 701 },
    Table16Row { log_m: 16, p: 589 },
    Table16Row { log_m: 17, p: 495 },
    Table16Row { log_m: 18, p: 416 },
    Table16Row { log_m: 19, p: 350 },
    Table16Row { log_m: 20, p: 294 },
    Table16Row { log_m: 21, p: 247 },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LweParams {
    pub n: usize,
    pub log2_q: u32,
    pub p: u32,
    pub l: usize,
    pub m: usize,
    /// `floor(log_2 p)`.
    pub bits_per_element: u32,
}

impl LweParams {
    #[inline]
    pub fn delta(&self) -> u32 {
        let q: u64 = 1u64 << self.log2_q;
        let delta = q / u64::from(self.p);
        u32::try_from(delta).unwrap_or(u32::MAX)
    }

    #[inline]
    pub fn half_p(&self) -> u32 {
        self.p / 2
    }

    /// Validate Eq. (2). f64 holds at margin > 1.001x; tighter
    /// cells need an integer nth-root.
    pub fn validate_eq2(&self) -> Result<()> {
        let n_total = (self.l as f64) * (self.m as f64);
        let lhs = (1u64 << self.log2_q) / u64::from(self.p);
        let lhs_f = lhs as f64;
        let rhs = EQ2_COEFFICIENT * f64::from(self.p) * n_total.powf(0.25);
        if lhs_f < rhs {
            return Err(IsimplePirError::InvalidParams {
                reason: format!(
                    "SimplePIR Eq. (2) violated: LHS floor(q/p) = {:.1} < RHS = {:.1} \
                     (n = {}, q = 2^{}, p = {}, sigma = {}, delta = 2^-{}, N = L*M = {:.3e}). \
                     Reduce p (eprint 2022/949 sec 4.2 Table 16) to restore margin.",
                    lhs_f,
                    rhs,
                    self.n,
                    self.log2_q,
                    self.p,
                    GAUSSIAN_SIGMA,
                    CORRECTNESS_DELTA_LOG2_NEG,
                    n_total,
                ),
            });
        }
        Ok(())
    }

    /// Sanity + Eq. (2). Use `validate_production` for strict
    /// `n = LWE_DIM`.
    pub fn validate(&self) -> Result<()> {
        if self.log2_q == 0 {
            return Err(IsimplePirError::InvalidParams {
                reason: "log2_q must be positive".into(),
            });
        }
        if self.p == 0 {
            return Err(IsimplePirError::InvalidParams {
                reason: "p must be positive".into(),
            });
        }
        if self.n == 0 {
            return Err(IsimplePirError::InvalidParams {
                reason: "n must be positive".into(),
            });
        }
        if self.l == 0 || self.m == 0 {
            return Err(IsimplePirError::InvalidParams {
                reason: "L and M must be positive".into(),
            });
        }
        self.validate_eq2()
    }

    pub fn validate_production(&self) -> Result<()> {
        self.validate()?;
        if self.n != LWE_DIM {
            return Err(IsimplePirError::InvalidParams {
                reason: format!(
                    "production n must be {}; got {} (SimplePIR Table 16 128-bit security requires n=1024)",
                    LWE_DIM, self.n,
                ),
            });
        }
        if self.log2_q != CIPHERTEXT_MODULUS_LOG2 {
            return Err(IsimplePirError::InvalidParams {
                reason: format!(
                    "production log2_q must be {}; got {}",
                    CIPHERTEXT_MODULUS_LOG2, self.log2_q,
                ),
            });
        }
        Ok(())
    }
}

/// Largest Table 16 row with `log_m <= input`. Beyond the table,
/// returns the last row; caller should re-run `lattice-estimator`.
pub fn table16_row_for_log_m(log_m: u32) -> Table16Row {
    let first = TABLE_16
        .first()
        .copied()
        .unwrap_or(Table16Row { log_m: 13, p: 991 });
    let last = TABLE_16.last().copied().unwrap_or(first);
    if log_m <= first.log_m {
        return first;
    }
    if log_m >= last.log_m {
        return last;
    }
    let mut selected = first;
    for row in TABLE_16 {
        if row.log_m <= log_m {
            selected = *row;
        } else {
            break;
        }
    }
    selected
}

/// `LweParams` for `(entries, entry_bytes)`. Square-packed matrix;
/// each Z_p element holds `floor(log_2 p)` bits.
pub fn for_cell(entries: u64, entry_bytes: usize) -> Result<LweParams> {
    if entries == 0 || entry_bytes == 0 {
        return Err(IsimplePirError::InvalidParams {
            reason: "entries and entry_bytes must both be positive".into(),
        });
    }
    let total_bits: u128 = u128::from(entries) * (entry_bytes as u128) * 8;

    let side_lower = (total_bits as f64).sqrt();
    let log_m_est = side_lower.log2().ceil() as u32;
    let row = table16_row_for_log_m(log_m_est);
    let bits_per_element = u32::from(u64::from(row.p).next_power_of_two().trailing_zeros() as u8)
        .saturating_sub(1)
        .max(1);

    let n_elements = total_bits.div_ceil(u128::from(bits_per_element));
    let side = (n_elements as f64).sqrt().ceil();
    let side_u = usize::try_from(side as u64).map_err(|_| IsimplePirError::InvalidParams {
        reason: "matrix dim overflowed usize".into(),
    })?;

    let params = LweParams {
        n: LWE_DIM,
        log2_q: CIPHERTEXT_MODULUS_LOG2,
        p: row.p,
        l: side_u,
        m: side_u,
        bits_per_element,
    };
    params.validate()?;
    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table16_row_count() {
        assert_eq!(TABLE_16.len(), 9);
        assert_eq!(TABLE_16[0].log_m, 13);
        assert_eq!(TABLE_16[0].p, 991);
        assert_eq!(TABLE_16[8].log_m, 21);
        assert_eq!(TABLE_16[8].p, 247);
    }

    #[test]
    fn table16_row_selection_conservative() {
        // Below smallest row: returns log_m = 13 row.
        let row = table16_row_for_log_m(10);
        assert_eq!(row.log_m, 13);
        assert_eq!(row.p, 991);

        // Exact match: returns that row.
        let row = table16_row_for_log_m(17);
        assert_eq!(row.log_m, 17);
        assert_eq!(row.p, 495);

        // Between rows: largest log_m row <= input, matching matrix dim.
        let row = table16_row_for_log_m(18);
        assert_eq!(row.log_m, 18);
        assert_eq!(row.p, 416);
    }

    #[test]
    fn c3_cell_passes_eq2() {
        let params = for_cell(1u64 << 28, 256).expect("c3 should build");
        params.validate().expect("c3 params should pass Eq. (2)");
        assert!(
            params.p >= 247 && params.p <= 416,
            "c3 p = {} should be between 247 and 416",
            params.p
        );
    }

    #[test]
    fn all_pse_cells_pass_eq2() {
        let entries_set = [1u64 << 20, 1u64 << 24, 1u64 << 28];
        let bytes_set = [8usize, 32, 256];
        for e in entries_set {
            for b in bytes_set {
                let params = for_cell(e, b).unwrap_or_else(|err| {
                    panic!("cell 2^{}*{}B build failed: {err}", e.ilog2(), b)
                });
                params.validate().unwrap_or_else(|err| {
                    panic!("cell 2^{}*{}B validate failed: {err}", e.ilog2(), b)
                });
            }
        }
    }

    #[test]
    fn production_validation_rejects_non_canonical_n() {
        let p = LweParams {
            n: 512, // wrong for production (correct: 1024)
            log2_q: 32,
            p: 991,
            l: 1024,
            m: 1024,
            bits_per_element: 9,
        };
        // validate() lets it through for toy/test usage.
        assert!(p.validate().is_ok());
        assert!(matches!(
            p.validate_production(),
            Err(IsimplePirError::InvalidParams { .. })
        ));
    }

    #[test]
    fn zero_params_rejected() {
        let p = LweParams {
            n: 0,
            log2_q: 32,
            p: 991,
            l: 4,
            m: 4,
            bits_per_element: 9,
        };
        assert!(matches!(
            p.validate(),
            Err(IsimplePirError::InvalidParams { .. })
        ));
    }
}
