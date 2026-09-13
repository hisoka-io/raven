#![allow(clippy::expect_used)]

use proptest::prelude::*;
use raven_core::batch_ladder::{
    check_batch_len, is_on_ladder, largest_dyadic_step, padded_len, LadderViolation,
};

#[test]
fn thirty_two_slot_ceiling_preserves_every_step() {
    let steps: Vec<_> = (1..=32).filter(|len| is_on_ladder(*len, 32)).collect();
    assert_eq!(steps, [1, 2, 4, 8, 16, 32]);

    for len in 1..=32 {
        let padded = padded_len(len, 32).expect("the 32-slot policy fits");
        assert!(padded >= len);
        assert!(padded < len * 2);
    }
}

#[test]
fn arbitrary_ceiling_uses_its_largest_fitting_dyadic_step() {
    assert_eq!(largest_dyadic_step(100), Ok(64));
    assert_eq!(padded_len(33, 100), Ok(64));
    assert!(is_on_ladder(64, 100));
    assert!(!is_on_ladder(100, 100));
    assert_eq!(
        padded_len(65, 100),
        Err(LadderViolation::TooLarge {
            len: 65,
            maximum: 100,
            largest_step: 64,
        })
    );
}

#[test]
fn invalid_and_empty_bounds_fail_with_typed_context() {
    assert_eq!(
        largest_dyadic_step(0),
        Err(LadderViolation::InvalidMaximum { maximum: 0 })
    );
    assert_eq!(padded_len(0, 32), Err(LadderViolation::Empty));
    assert_eq!(check_batch_len(0, 32), Err(LadderViolation::Empty));
}

#[test]
fn off_step_and_oversized_lengths_are_actionable() {
    assert_eq!(
        check_batch_len(3, 32),
        Err(LadderViolation::OffStep {
            len: 3,
            expected: 4,
        })
    );

    let message = padded_len(65, 100)
        .expect_err("65 has no dyadic step under 100")
        .to_string();
    assert!(message.contains("65"), "{message}");
    assert!(message.contains("100"), "{message}");
    assert!(message.contains("64"), "{message}");
    assert!(message.contains("split"), "{message}");
}

proptest! {
    #[test]
    fn every_returned_length_is_the_smallest_fitting_step(
        len in 1usize..1_000_000,
        maximum in 1usize..1_000_000,
    ) {
        if let Ok(padded) = padded_len(len, maximum) {
            prop_assert!(padded.is_power_of_two());
            prop_assert!(padded >= len);
            prop_assert!(padded <= maximum);
            if padded > 1 {
                prop_assert!(padded / 2 < len);
            }
        }
    }
}
