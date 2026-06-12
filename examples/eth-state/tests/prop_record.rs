//! Property + KAT coverage for the structural-tag record layout that C1 byte-identity depends
//! on: byte 0 is the presence tag, bytes 1..32 the big-endian balance. A mis-tagged or
//! mis-aligned record shifts encoder columns or breaks the present-vs-absent distinction.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic, clippy::print_stdout, clippy::print_stderr)]


use eth_state::ingest::normalize_balance_be;
use eth_state::{pad_record, unpad_record, ENTRY_SIZE, PRESENT_TAG};
use proptest::prelude::*;

proptest! {
    // pad_record: value within ENTRY_SIZE-1 -> tag at byte 0, value big-endian right-aligned,
    // the gap zero, and unpad is the identity (tag preserved).
    #[test]
    fn pad_record_tags_and_unpad_roundtrips(
        value in proptest::collection::vec(any::<u8>(), 0..ENTRY_SIZE)
    ) {
        let r = pad_record(&value).expect("within width");
        prop_assert_eq!(r.len(), ENTRY_SIZE);
        prop_assert_eq!(r[0], PRESENT_TAG);
        prop_assert_eq!(&r[ENTRY_SIZE - value.len()..], &value[..]);
        prop_assert!(r[1..ENTRY_SIZE - value.len()].iter().all(|&b| b == 0));
        prop_assert_eq!(unpad_record(&r), r.clone());
    }

    // pad_record: a value >= ENTRY_SIZE (no room for the tag) is rejected, never truncated.
    #[test]
    fn pad_record_rejects_oversize(extra in 0usize..64) {
        let value = vec![1u8; ENTRY_SIZE + extra];
        prop_assert!(pad_record(&value).is_err());
    }

    // normalize_balance_be: a u128 round-trips - tag at 0, high bytes zero, value in the low 16,
    // recoverable big-endian.
    #[test]
    fn normalize_balance_u128_roundtrips(bal in any::<u128>()) {
        let be = bal.to_be_bytes();
        let rec = normalize_balance_be(&be).expect("16 < 32");
        prop_assert_eq!(rec.len(), ENTRY_SIZE);
        prop_assert_eq!(rec[0], PRESENT_TAG);
        prop_assert!(rec[1..ENTRY_SIZE - 16].iter().all(|&b| b == 0));
        prop_assert_eq!(&rec[ENTRY_SIZE - 16..], &be[..]);
        let mut low = [0u8; 16];
        low.copy_from_slice(&rec[ENTRY_SIZE - 16..]);
        prop_assert_eq!(u128::from_be_bytes(low), bal);
    }

    // normalize_balance_be: any <= ENTRY_SIZE-1 input is tagged and right-aligned.
    #[test]
    fn normalize_tags_and_right_aligns(
        value in proptest::collection::vec(any::<u8>(), 0..ENTRY_SIZE)
    ) {
        let rec = normalize_balance_be(&value).expect("within width");
        prop_assert_eq!(rec[0], PRESENT_TAG);
        prop_assert_eq!(&rec[ENTRY_SIZE - value.len()..], &value[..]);
        prop_assert!(rec[1..ENTRY_SIZE - value.len()].iter().all(|&b| b == 0));
    }

    // normalize_balance_be: an input >= ENTRY_SIZE is rejected.
    #[test]
    fn normalize_rejects_oversize(extra in 0usize..64) {
        let value = vec![7u8; ENTRY_SIZE + extra];
        prop_assert!(normalize_balance_be(&value).is_err());
    }
}

/// KAT: the exact byte layout is frozen - byte 0 the tag, the balance big-endian in the low
/// bytes. A future widening or a dropped tag is caught here. (The present-zero-vs-absent
/// predicate is unit-tested in lib.rs where `record_present` is in scope.)
#[test]
fn presence_tag_layout_kat() {
    let rec = normalize_balance_be(&513u128.to_be_bytes()).expect("fits");
    let mut expected = [0u8; ENTRY_SIZE];
    expected[0] = PRESENT_TAG;
    expected[30] = 0x02; // 513 = 0x0201
    expected[31] = 0x01;
    assert_eq!(rec, expected, "frozen tag + big-endian layout");

    // A present zero is still tagged at byte 0; an absent slot is all-zero.
    let zero = normalize_balance_be(&0u128.to_be_bytes()).expect("fits");
    assert_eq!(zero[0], PRESENT_TAG, "present-zero carries the tag");
}
