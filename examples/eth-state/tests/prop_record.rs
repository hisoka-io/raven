//! Record layout: byte 0 is the presence tag, the rest a right-aligned big-endian balance.
//! A mis-aligned record shifts encoder columns; a dropped tag breaks present-vs-absent.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use eth_state::ingest::normalize_balance_be;
use eth_state::{pad_record, unpad_record, ENTRY_SIZE, PRESENT_TAG};
use proptest::prelude::*;

proptest! {
    // Tier A - pure byte layout, no I/O. Measured 0.01 s for the whole binary at 256 x 5, so the
    // default count is right; it is stated explicitly so the budget is visible at the call site.
    #![proptest_config(ProptestConfig::with_cases(256))]

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

    #[test]
    fn pad_record_rejects_oversize(extra in 0usize..64) {
        let value = vec![1u8; ENTRY_SIZE + extra];
        prop_assert!(pad_record(&value).is_err());
    }

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

    #[test]
    fn normalize_tags_and_right_aligns(
        value in proptest::collection::vec(any::<u8>(), 0..ENTRY_SIZE)
    ) {
        let rec = normalize_balance_be(&value).expect("within width");
        prop_assert_eq!(rec[0], PRESENT_TAG);
        prop_assert_eq!(&rec[ENTRY_SIZE - value.len()..], &value[..]);
        prop_assert!(rec[1..ENTRY_SIZE - value.len()].iter().all(|&b| b == 0));
    }

    #[test]
    fn normalize_rejects_oversize(extra in 0usize..64) {
        let value = vec![7u8; ENTRY_SIZE + extra];
        prop_assert!(normalize_balance_be(&value).is_err());
    }
}

/// Freezes the byte layout against a future widening or a dropped tag.
///
/// The two constants are pinned as LITERALS on purpose. Every property above is
/// written in terms of `PRESENT_TAG` and `ENTRY_SIZE`, so a change to either
/// value moves the assertions with it and the whole file stays green - proven by
/// mutation: `PRESENT_TAG = 0x02` left all six tests passing. Both are
/// persisted-format constants, carried in the WAL payload and in every PIR
/// corpus record, so a silent change re-reads every stored record.
#[test]
fn presence_tag_layout_kat() {
    assert_eq!(
        PRESENT_TAG, 0x01,
        "presence tag is a persisted-format constant"
    );
    assert_eq!(
        ENTRY_SIZE, 32,
        "record width is a persisted-format constant, and must stay even: \
         the encoder reads 16-bit chunks"
    );

    let rec = normalize_balance_be(&513u128.to_be_bytes()).expect("fits");
    let mut expected = [0u8; ENTRY_SIZE];
    expected[0] = PRESENT_TAG;
    expected[30] = 0x02; // 513 = 0x0201
    expected[31] = 0x01;
    assert_eq!(rec, expected, "frozen tag + big-endian layout");

    let zero = normalize_balance_be(&0u128.to_be_bytes()).expect("fits");
    assert_eq!(zero[0], PRESENT_TAG, "present-zero carries the tag");
}
