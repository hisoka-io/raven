//! Dyadic padding arithmetic for hiding exact batch lengths.
//!
//! Callers supply their own transport or deployment ceiling. The framework derives
//! the largest fitting power-of-two step and carries no scheme-specific byte limit.
//!
//! ```
//! use raven_core::batch_ladder::{largest_dyadic_step, padded_len};
//!
//! assert_eq!(largest_dyadic_step(100)?, 64);
//! assert_eq!(padded_len(33, 100)?, 64);
//! # Ok::<(), raven_core::batch_ladder::LadderViolation>(())
//! ```

use serde::{Deserialize, Serialize};

/// Rejection reason for a dyadic batch length or its caller-supplied ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LadderViolation {
    /// The caller supplied a zero slot ceiling.
    InvalidMaximum {
        /// Received ceiling.
        maximum: usize,
    },
    /// The batch contains no queries.
    Empty,
    /// No dyadic step can hold the batch beneath the supplied ceiling.
    TooLarge {
        /// Received batch length.
        len: usize,
        /// Caller-supplied slot ceiling.
        maximum: usize,
        /// Largest dyadic step at or below the ceiling.
        largest_step: usize,
    },
    /// The length lies between two steps and would reveal the exact count.
    OffStep {
        /// Received batch length.
        len: usize,
        /// Step the caller should have padded to.
        expected: usize,
    },
}

impl std::fmt::Display for LadderViolation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMaximum { maximum } => write!(
                formatter,
                "batch ladder maximum {maximum} must admit at least one slot"
            ),
            Self::Empty => write!(
                formatter,
                "batch length 0 is invalid; a batch must contain at least one query"
            ),
            Self::TooLarge {
                len,
                maximum,
                largest_step,
            } => write!(
                formatter,
                "batch length {len} has no dyadic step under slot ceiling {maximum}; \
                 largest step is {largest_step}, so split into independently padded batches"
            ),
            Self::OffStep { len, expected } => write!(
                formatter,
                "batch length {len} is off the dyadic ladder; pad to {expected} before sending, \
                 otherwise the batch length publishes the exact query count"
            ),
        }
    }
}

impl std::error::Error for LadderViolation {}

/// Largest power-of-two batch step at or below `maximum`.
///
/// # Errors
/// Returns [`LadderViolation::InvalidMaximum`] when `maximum` is zero.
pub const fn largest_dyadic_step(maximum: usize) -> Result<usize, LadderViolation> {
    if maximum == 0 {
        return Err(LadderViolation::InvalidMaximum { maximum });
    }
    let shift = usize::BITS - maximum.leading_zeros() - 1;
    Ok(1usize << shift)
}

/// Whether `len` is a non-zero dyadic step beneath the supplied ceiling.
#[must_use]
pub const fn is_on_ladder(len: usize, maximum: usize) -> bool {
    len != 0 && len <= maximum && len.is_power_of_two()
}

/// Smallest dyadic step that fits `len` beneath the supplied ceiling.
///
/// # Errors
/// Returns a typed violation for a zero ceiling, empty batch, arithmetic overflow,
/// or a batch with no fitting step.
pub fn padded_len(len: usize, maximum: usize) -> Result<usize, LadderViolation> {
    let largest_step = largest_dyadic_step(maximum)?;
    if len == 0 {
        return Err(LadderViolation::Empty);
    }
    let padded = len
        .checked_next_power_of_two()
        .filter(|step| *step <= largest_step)
        .ok_or(LadderViolation::TooLarge {
            len,
            maximum,
            largest_step,
        })?;
    Ok(padded)
}

/// Accept `len` only when it is a dyadic step beneath the supplied ceiling.
///
/// # Errors
/// Returns a typed violation naming an invalid bound or the required padding step.
pub fn check_batch_len(len: usize, maximum: usize) -> Result<(), LadderViolation> {
    let expected = padded_len(len, maximum)?;
    if expected == len {
        Ok(())
    } else {
        Err(LadderViolation::OffStep { len, expected })
    }
}
