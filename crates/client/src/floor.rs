//! Parameter floors: bounds a server-supplied parameter set must meet before the client
//! derives a key or encrypts a query under it.
//!
//! `InspireParams::validate` checks that a set is structurally usable; it runs no lattice
//! estimate, so a node could serve a smaller ring or a narrower error and the client would
//! encrypt under it. These bounds hold every served set to at least the shipped
//! `secure_128_d2048`, the preset the lattice estimate measured, and cap the sizes every client
//! allocation scales with.

use raven_inspire::math::mod_q::DEFAULT_Q;
use raven_inspire::params::InspireParams;

/// Smallest ring dimension accepted: the shipped preset's.
pub const MIN_RING_DIM: usize = 2048;

/// Largest ring dimension accepted: raven-inspire's largest preset, `secure_128_d4096`.
pub const MAX_RING_DIM: usize = 4096;

/// Largest ciphertext modulus accepted: the shipped `DEFAULT_Q = 2^60 - 2^14 + 1`. At a fixed
/// ring and error width a wider modulus is a weaker set.
pub const MAX_Q: u64 = DEFAULT_Q;

/// The one error width accepted, every shipped preset's. A narrower one is a weaker set; a wider
/// one grows each sampler's table, `2 * ceil(6 sigma) + 1` entries, without bound.
pub const SHIPPED_SIGMA: f64 = 6.4;

/// A parameter set outside the floors.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ParameterFloorError {
    /// Ring dimension outside `[MIN_RING_DIM, MAX_RING_DIM]`.
    #[error("ring_dim {ring_dim} is outside [{MIN_RING_DIM}, {MAX_RING_DIM}]")]
    RingDim {
        /// The served ring dimension.
        ring_dim: usize,
    },
    /// Ciphertext modulus above `MAX_Q`.
    #[error("q {q} exceeds the shipped modulus {MAX_Q}")]
    Modulus {
        /// The served modulus.
        q: u64,
    },
    /// Error width other than `SHIPPED_SIGMA`.
    #[error("sigma {sigma} is not the shipped width {SHIPPED_SIGMA}")]
    Sigma {
        /// The served width.
        sigma: f64,
    },
    /// A gadget with more digits than its base needs to cover `q`.
    #[error("{role} gadget has {len} digits, but base {base} covers q in {covering}")]
    GadgetWidth {
        /// Which gadget.
        role: &'static str,
        /// The served digit count.
        len: usize,
        /// The served base.
        base: u64,
        /// Digits the base needs to cover `q`, or 0 when no count up to 64 does.
        covering: usize,
    },
}

/// Refuse a parameter set outside the floors. `secure_128_d2048` and `secure_128_d4096` pass.
///
/// ```
/// use raven_client::{check_parameter_floor, ParameterFloorError};
/// use raven_inspire::params::InspireParams;
///
/// assert!(check_parameter_floor(&InspireParams::secure_128_d2048()).is_ok());
/// let small = InspireParams { ring_dim: 1024, ..InspireParams::secure_128_d2048() };
/// assert_eq!(
///     check_parameter_floor(&small),
///     Err(ParameterFloorError::RingDim { ring_dim: 1024 })
/// );
/// ```
///
/// # Errors
/// The first bound the set is outside, as a [`ParameterFloorError`].
pub fn check_parameter_floor(params: &InspireParams) -> Result<(), ParameterFloorError> {
    if !(MIN_RING_DIM..=MAX_RING_DIM).contains(&params.ring_dim) {
        return Err(ParameterFloorError::RingDim {
            ring_dim: params.ring_dim,
        });
    }
    if params.q > MAX_Q {
        return Err(ParameterFloorError::Modulus { q: params.q });
    }
    if params.sigma.to_bits() != SHIPPED_SIGMA.to_bits() {
        return Err(ParameterFloorError::Sigma {
            sigma: params.sigma,
        });
    }
    let covering = covering_digits(params.gadget_base, params.q).unwrap_or(0);
    for (role, len) in [
        ("query", params.query_gadget_len),
        ("packing", params.packing_gadget_len),
    ] {
        if covering == 0 || len > covering {
            return Err(ParameterFloorError::GadgetWidth {
                role,
                len,
                base: params.gadget_base,
                covering,
            });
        }
    }
    Ok(())
}

/// Smallest digit count with `base^len >= q`; `None` when `base < 2` or no count up to 64 does.
fn covering_digits(base: u64, q: u64) -> Option<usize> {
    if base < 2 {
        return None;
    }
    let mut covered = u128::from(base);
    for len in 1..=64usize {
        if covered >= u128::from(q) {
            return Some(len);
        }
        covered = covered.saturating_mul(u128::from(base));
    }
    None
}
