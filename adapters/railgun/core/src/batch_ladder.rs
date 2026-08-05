//! Fixed-size ladder for batched PIR requests.
//!
//! An unpadded batch publishes `|batch|` in the clear, which is the wallet's
//! note count. Padding to a dyadic ladder replaces that with the bucket the
//! count falls in, at under 2x worst-case slot overhead.

use serde::{Deserialize, Serialize};

/// Permitted batch sizes, ascending.
///
/// Dyadic so worst-case padding overhead stays under 2x. The ladder stops at
/// 32 because a 32-slot upload is 3.16 MB at the measured 98,840 B/query,
/// which fits the 8 MiB default body cap with headroom; 64 would not.
pub const BATCH_SIZE_LADDER: [usize; 6] = [1, 2, 4, 8, 16, 32];

/// Largest batch the ladder admits.
#[must_use]
pub const fn max_batch_size() -> usize {
    32
}

/// Whether `len` is a ladder step.
#[must_use]
pub fn is_on_ladder(len: usize) -> bool {
    BATCH_SIZE_LADDER.contains(&len)
}

/// Smallest ladder step that fits `len` real queries.
///
/// `None` for an empty batch and for anything above [`max_batch_size`]; a
/// caller with more real queries than the top step must split into several
/// batches, each of which pads independently.
#[must_use]
pub fn padded_len(len: usize) -> Option<usize> {
    BATCH_SIZE_LADDER.iter().copied().find(|step| *step >= len)
}

/// Rejection reason for an off-ladder batch length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LadderViolation {
    /// Zero-length batch.
    Empty,
    /// Above [`max_batch_size`].
    TooLarge {
        /// Received length.
        len: usize,
    },
    /// Between two steps, so the true count leaks.
    OffStep {
        /// Received length.
        len: usize,
        /// Step the client should have padded to.
        expected: usize,
    },
}

impl std::fmt::Display for LadderViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(
                f,
                "batch length 0 is off the fixed-size ladder {BATCH_SIZE_LADDER:?}"
            ),
            Self::TooLarge { len } => write!(
                f,
                "batch length {len} exceeds the fixed-size ladder maximum {}; \
                 split into several batches and pad each",
                max_batch_size()
            ),
            Self::OffStep { len, expected } => write!(
                f,
                "batch length {len} is off the fixed-size ladder {BATCH_SIZE_LADDER:?}; \
                 pad to {expected} before sending, otherwise the batch length \
                 publishes the exact query count"
            ),
        }
    }
}

impl std::error::Error for LadderViolation {}

/// Accept `len` only if it is a ladder step.
///
/// # Errors
/// Returns the [`LadderViolation`] naming the step the caller should have used.
pub fn check_batch_len(len: usize) -> Result<(), LadderViolation> {
    if len == 0 {
        return Err(LadderViolation::Empty);
    }
    match padded_len(len) {
        None => Err(LadderViolation::TooLarge { len }),
        Some(step) if step == len => Ok(()),
        Some(expected) => Err(LadderViolation::OffStep { len, expected }),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        check_batch_len, is_on_ladder, max_batch_size, padded_len, LadderViolation,
        BATCH_SIZE_LADDER,
    };

    #[test]
    fn ladder_is_ascending_and_dyadic() {
        for pair in BATCH_SIZE_LADDER.windows(2) {
            let (Some(lo), Some(hi)) = (pair.first().copied(), pair.last().copied()) else {
                panic!("windows(2) always yields two elements");
            };
            assert!(hi > lo, "ladder must ascend: {lo} then {hi}");
            assert_eq!(hi, lo * 2, "ladder must be dyadic: {lo} then {hi}");
        }
        assert_eq!(
            BATCH_SIZE_LADDER.last().copied(),
            Some(max_batch_size()),
            "max_batch_size must track the top ladder step"
        );
    }

    #[test]
    fn padded_len_lands_on_a_step_and_never_shrinks() {
        for len in 1..=max_batch_size() {
            let padded = padded_len(len).expect("in range");
            assert!(
                is_on_ladder(padded),
                "padded {len} -> {padded} is off-ladder"
            );
            assert!(
                padded >= len,
                "padding must not drop queries: {len} -> {padded}"
            );
            assert!(
                padded < len * 2,
                "dyadic ladder must keep overhead under 2x: {len} -> {padded}"
            );
        }
    }

    #[test]
    fn empty_and_oversized_batches_are_rejected() {
        assert_eq!(check_batch_len(0), Err(LadderViolation::Empty));
        assert_eq!(padded_len(0), Some(1));
        assert_eq!(padded_len(max_batch_size() + 1), None);
        assert_eq!(
            check_batch_len(33),
            Err(LadderViolation::TooLarge { len: 33 })
        );
    }

    #[test]
    fn off_step_lengths_name_the_step_they_should_have_used() {
        assert_eq!(
            check_batch_len(3),
            Err(LadderViolation::OffStep {
                len: 3,
                expected: 4
            })
        );
        assert_eq!(
            check_batch_len(17),
            Err(LadderViolation::OffStep {
                len: 17,
                expected: 32
            })
        );
        for step in BATCH_SIZE_LADDER {
            check_batch_len(step).expect("every ladder step is accepted");
        }
    }

    #[test]
    fn violation_text_names_the_ladder() {
        let msg = LadderViolation::OffStep {
            len: 5,
            expected: 8,
        }
        .to_string();
        assert!(msg.contains('5') && msg.contains('8'), "{msg}");
        assert!(msg.contains("publishes the exact query count"), "{msg}");
    }
}
