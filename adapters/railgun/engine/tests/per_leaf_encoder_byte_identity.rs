//! Property-based byte-identity test for PerLeafEncoder.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use proptest::prelude::*;
use raven_railgun_engine::inspire::{materialize_shard_bytes, LogicalLeafStore};
use raven_railgun_engine::pir_table::{PerLeafEncoder, PirTableEncoder};
use raven_railgun_persistence::WalEntryPayload;

const ENTRIES_PER_SHARD: u32 = 256;
const RECORD_SIZE: usize = 32;
const TOTAL_SHARDS: u32 = 4;

fn canonical(seed: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = seed.max(1);
    b
}

fn test_encoder() -> PerLeafEncoder {
    PerLeafEncoder::new(RECORD_SIZE, ENTRIES_PER_SHARD).expect("valid encoder")
}

fn append(tree: u32, leaf: u32, commitment: [u8; 32]) -> WalEntryPayload {
    WalEntryPayload::AppendLeaf {
        tree_number: tree,
        leaf_index: leaf,
        commitment,
    }
}

fn build_store_from_pattern(insert_count: usize) -> LogicalLeafStore {
    let mut store = LogicalLeafStore::new();
    for i in 0..insert_count as u32 {
        let payload = append(0, i, canonical((i % 250) as u8 + 1));
        store
            .apply(&payload, 100 + u64::from(i), &test_encoder())
            .expect("contiguous insert must succeed");
    }
    store
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 16,
        ..ProptestConfig::default()
    })]

    #[test]
    fn per_leaf_encoder_materialize_shard_matches_pre_trait_path_across_shards(
        insert_count in 0u32..(TOTAL_SHARDS * ENTRIES_PER_SHARD),
    ) {
        let store = build_store_from_pattern(insert_count as usize);
        let encoder = PerLeafEncoder::new(RECORD_SIZE, ENTRIES_PER_SHARD).expect("valid encoder");

        for shard_id in 0..TOTAL_SHARDS {
            let trait_bytes = encoder.materialize_shard(shard_id, &store);
            let direct_bytes =
                materialize_shard_bytes(&store, shard_id, ENTRIES_PER_SHARD, RECORD_SIZE);
            prop_assert_eq!(
                trait_bytes.len(),
                direct_bytes.len(),
                "length mismatch at shard {} (insert_count={})",
                shard_id,
                insert_count
            );
            prop_assert_eq!(
                &trait_bytes,
                &direct_bytes,
                "byte mismatch at shard {} (insert_count={})",
                shard_id,
                insert_count
            );
        }
    }

    #[test]
    fn per_leaf_affected_shards_matches_logical_store_dirty_marking(
        leaf_index in 0u32..(TOTAL_SHARDS * ENTRIES_PER_SHARD),
    ) {
        let mut store = LogicalLeafStore::new();
        for i in 0..=leaf_index {
            store
                .apply(&append(0, i, canonical((i % 250) as u8 + 1)), 100 + u64::from(i), &test_encoder())
                .expect("contiguous insert");
        }
        let encoder = PerLeafEncoder::new(RECORD_SIZE, ENTRIES_PER_SHARD).expect("valid encoder");
        let dirty_via_trait = encoder.affected_shards_for_leaf(0, leaf_index);

        prop_assert_eq!(
            dirty_via_trait.len(),
            1,
            "PerLeafEncoder.affected_shards_for_leaf must return exactly 1 shard"
        );
        let shard_via_trait = *dirty_via_trait.iter().next().expect("non-empty");
        prop_assert!(
            store.dirty_shards().contains(&shard_via_trait),
            "trait-reported affected shard {} not in store.dirty_shards() {:?}",
            shard_via_trait,
            store.dirty_shards()
        );
    }
}
