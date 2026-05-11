#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

use std::collections::HashMap;

use proptest::prelude::*;
use rand::{rngs::StdRng, Rng, SeedableRng};
use raven_bff::{BffError, BinaryFuseFilter};

fn make_random_db(n: usize, seed: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..n)
        .map(|i| {
            // Counter-stamped key to guarantee uniqueness regardless of RNG.
            let mut key = vec![0u8; 16];
            rng.fill(&mut key[..]);
            key[12..].copy_from_slice(&(i as u32).to_le_bytes());

            let mut val = vec![0u8; 4];
            rng.fill(&mut val[..]);
            (key, val)
        })
        .collect()
}

fn db_refs(owned: &[(Vec<u8>, Vec<u8>)]) -> HashMap<&[u8], &[u8]> {
    owned
        .iter()
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect()
}

#[test]
fn construct_3_wise_smoke_small() {
    let owned = make_random_db(64, 0xC0FFEE);
    let db = db_refs(&owned);
    let (filter, reverse_order, reverse_h, hash_to_key) =
        BinaryFuseFilter::construct_3_wise(&db, 8, 100).expect("construct 3-wise");
    assert_eq!(filter.arity, 3);
    assert_eq!(filter.filter_size, 64);
    assert_eq!(filter.mat_elem_bit_len, 8);
    assert_eq!(reverse_h.len(), 64);
    // db.len() + 1 (last entry is the sentinel `1`).
    assert_eq!(reverse_order.len(), 65);
    assert_eq!(hash_to_key.len(), 64);
}

#[test]
fn construct_4_wise_smoke_small() {
    let owned = make_random_db(128, 0xBADBEEF);
    let db = db_refs(&owned);
    let (filter, reverse_order, reverse_h, hash_to_key) =
        BinaryFuseFilter::construct_4_wise(&db, 12, 100).expect("construct 4-wise");
    assert_eq!(filter.arity, 4);
    assert_eq!(filter.filter_size, 128);
    assert_eq!(filter.mat_elem_bit_len, 12);
    assert_eq!(reverse_h.len(), 128);
    assert_eq!(reverse_order.len(), 129);
    assert_eq!(hash_to_key.len(), 128);
}

#[test]
fn construct_errors_on_empty_db() {
    let db: HashMap<&[u8], &[u8]> = HashMap::new();
    match BinaryFuseFilter::construct_3_wise(&db, 8, 100) {
        Err(BffError::EmptyKeyValueDatabase) => {}
        other => panic!("expected EmptyKeyValueDatabase, got {other:?}"),
    }
    match BinaryFuseFilter::construct_4_wise(&db, 8, 100) {
        Err(BffError::EmptyKeyValueDatabase) => {}
        other => panic!("expected EmptyKeyValueDatabase, got {other:?}"),
    }
}

#[test]
fn serialize_roundtrip_3_wise() {
    let owned = make_random_db(32, 0xABC123);
    let db = db_refs(&owned);
    let (filter, _, _, _) = BinaryFuseFilter::construct_3_wise(&db, 10, 50).expect("construct");
    let bytes = filter.to_bytes();
    let parsed = BinaryFuseFilter::from_bytes(&bytes).expect("from_bytes");
    assert_eq!(filter, parsed);
}

#[test]
fn serialize_roundtrip_4_wise() {
    let owned = make_random_db(48, 0xDEF456);
    let db = db_refs(&owned);
    let (filter, _, _, _) = BinaryFuseFilter::construct_4_wise(&db, 14, 50).expect("construct");
    let bytes = filter.to_bytes();
    let parsed = BinaryFuseFilter::from_bytes(&bytes).expect("from_bytes");
    assert_eq!(filter, parsed);
}

#[test]
fn from_bytes_rejects_wrong_length() {
    let buf = vec![0u8; 10];
    match BinaryFuseFilter::from_bytes(&buf) {
        Err(BffError::FailedToDeserializeFilterFromBytes) => {}
        other => panic!("expected FailedToDeserializeFilterFromBytes, got {other:?}"),
    }
}

#[test]
fn bits_per_entry_positive_for_nonempty_filter() {
    let owned = make_random_db(16, 0x42);
    let db = db_refs(&owned);
    let (filter, _, _, _) = BinaryFuseFilter::construct_3_wise(&db, 8, 50).expect("construct");
    let bpe = filter.bits_per_entry();
    assert!(bpe > 0.0, "bits_per_entry should be positive");
    assert!(bpe < 64.0, "bits_per_entry suspiciously large: {bpe}");
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        ..ProptestConfig::default()
    })]

    #[test]
    fn construct_3_wise_succeeds_on_random_distinct_keys(
        n in 2usize..512,
        seed in any::<u64>(),
        mat_bits in 4usize..17,
    ) {
        let owned = make_random_db(n, seed);
        prop_assert_eq!(owned.len(), n);
        let db = db_refs(&owned);
        prop_assume!(db.len() == n);
        let actual_db_len = db.len();
        let result = BinaryFuseFilter::construct_3_wise(&db, mat_bits, 100);
        prop_assert!(result.is_ok(), "construct failed for n={n} seed={seed:x}: {result:?}");
        let (filter, reverse_order, reverse_h, hash_to_key) = result.unwrap();
        prop_assert_eq!(
            filter.filter_size,
            actual_db_len,
            "filter_size={} actual_db_len={} n={} seed={:x}",
            filter.filter_size, actual_db_len, n, seed
        );
        prop_assert_eq!(reverse_h.len(), actual_db_len,
            "reverse_h.len()={} actual_db_len={} n={} seed={:x} filter_size={} num_fp={}",
            reverse_h.len(), actual_db_len, n, seed, filter.filter_size, filter.num_fingerprints);
        prop_assert_eq!(reverse_order.len(), actual_db_len + 1,
            "reverse_order.len()={} actual_db_len={} n={} seed={:x} filter_size={} num_fp={}",
            reverse_order.len(), actual_db_len, n, seed, filter.filter_size, filter.num_fingerprints);
        prop_assert_eq!(hash_to_key.len(), actual_db_len);
        prop_assert_eq!(filter.mat_elem_bit_len, mat_bits);
    }

    #[test]
    fn construct_4_wise_succeeds_on_random_distinct_keys(
        n in 2usize..256,
        seed in any::<u64>(),
        mat_bits in 4usize..17,
    ) {
        let owned = make_random_db(n, seed);
        let db = db_refs(&owned);
        prop_assume!(db.len() == n);
        let result = BinaryFuseFilter::construct_4_wise(&db, mat_bits, 100);
        prop_assert!(result.is_ok(), "construct failed for n={n} seed={seed:x}: {result:?}");
        let (filter, _, _, hash_to_key) = result.unwrap();
        prop_assert_eq!(filter.filter_size, n);
        prop_assert_eq!(hash_to_key.len(), n);
    }

    #[test]
    fn to_bytes_from_bytes_is_identity(
        n in 2usize..128,
        seed in any::<u64>(),
        mat_bits in 4usize..17,
    ) {
        let owned = make_random_db(n, seed);
        let db = db_refs(&owned);
        prop_assume!(db.len() == n);
        let (filter, _, _, _) =
            BinaryFuseFilter::construct_3_wise(&db, mat_bits, 100).unwrap();
        let bytes = filter.to_bytes();
        let parsed = BinaryFuseFilter::from_bytes(&bytes).unwrap();
        prop_assert_eq!(filter, parsed);
    }
}
