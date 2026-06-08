//! Validate-before-WAL property test: locks the `apply_one_leaf`
//! invariant that `validate_apply` agrees with `apply_wal_entry` and
//! that the WAL ends up containing exactly the validated events.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::items_after_statements
)]

use std::sync::Arc;

use proptest::prelude::*;
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{apply_wal_entry, validate_apply, LogicalLeafStore};
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{PerLeafCommitmentEncoder, PirTableEncoder};
use raven_railgun_persistence::{StoreLayout, WalEntryPayload};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-validate-property";
const ENTRIES_PER_SHARD: u32 = 2048;

fn test_encoder() -> PerLeafCommitmentEncoder {
    PerLeafCommitmentEncoder::new(32, ENTRIES_PER_SHARD).expect("test encoder")
}

fn test_encoder_arc() -> Arc<dyn PirTableEncoder> {
    Arc::new(test_encoder())
}

// Fr-canonical (high byte zero); last byte non-zero so the leaf is non-trivial
fn canonical_commitment(seed: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = seed.max(1);
    b
}

// fixed tree=0: long runs against one tree exercise the imt_leaf_count_for advance (cross-tree is unit-tested)
fn append_leaf_strategy() -> impl Strategy<Value = WalEntryPayload> {
    (0u32..32u32, any::<u8>()).prop_map(|(leaf_index, seed)| WalEntryPayload::AppendLeaf {
        tree_number: 0,
        leaf_index,
        commitment: canonical_commitment(seed),
    })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    #[test]
    fn validate_apply_agrees_with_apply_wal_entry(
        prefix_len in 0u32..=8u32,
        candidate in append_leaf_strategy(),
    ) {
        let mut store = LogicalLeafStore::new();
        for i in 0..prefix_len {
            let seed = u8::try_from(i).unwrap_or(255).saturating_add(1);
            let p = WalEntryPayload::AppendLeaf {
                tree_number: 0,
                leaf_index: i,
                commitment: canonical_commitment(seed),
            };
            apply_wal_entry(&mut store, &p, 100 + u64::from(i), &test_encoder())
                .expect("contiguous prefix must succeed");
        }

        let validate_outcome = validate_apply(&store, &candidate);
        let mut store_dryrun = store.clone();
        let apply_outcome =
            apply_wal_entry(&mut store_dryrun, &candidate, 200, &test_encoder());

        prop_assert_eq!(
            validate_outcome.is_ok(),
            apply_outcome.is_ok(),
            "validate_apply and apply_wal_entry disagree on candidate {:?} \
             at prefix_len={}: validate={:?}, apply={:?}",
            candidate,
            prefix_len,
            validate_outcome,
            apply_outcome,
        );
    }

    #[test]
    fn validate_then_wal_then_mutate_keeps_wal_clean(
        payloads in prop::collection::vec(append_leaf_strategy(), 1..32),
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("layout");

        let mut store = LogicalLeafStore::new();
        let mut accepted: Vec<WalEntryPayload> = Vec::new();
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("validate-property-test"),
            SnapshotPolicy::default(),
            test_encoder_arc(),
        )
        .expect("open 1");

        for (i, p) in payloads.iter().enumerate() {
            // validate, then WAL, then mutate: a rejected validate touches neither WAL nor store
            let block_height = 100 + u64::try_from(i).unwrap_or(0);
            if validate_apply(&store, p).is_ok() {
                opened
                    .persistence
                    .apply_event(p, block_height)
                    .expect("validated event must apply to WAL");
                apply_wal_entry(&mut store, p, block_height, &test_encoder())
                    .expect("validated event must mutate store");
                accepted.push(p.clone());
            }
        }

        let pre_drop_leaf_count = store.imt_leaf_count_for(0);
        drop(opened);

        // a soft-skip on the WAL-replay path would diverge recovered count from pre-drop count
        let layout2 = StoreLayout::open(dir.path()).expect("layout 2");
        let opened2 = InspirePersistence::open(
            layout2,
            SCHEME_TAG,
            InstanceId::new("validate-property-test"),
            SnapshotPolicy::default(),
            test_encoder_arc(),
        )
        .expect("open 2");
        let logical_store_after_replay = opened2.recovered_logical_store;
        let post_replay_leaf_count = logical_store_after_replay.imt_leaf_count_for(0);

        prop_assert_eq!(
            pre_drop_leaf_count,
            post_replay_leaf_count,
            "WAL replay diverged: pre-drop leaf count = {}, post-replay = {}; \
             this means validate_apply let an invalid entry through and the \
             tolerant-replay path soft-skipped it on reopen",
            pre_drop_leaf_count,
            post_replay_leaf_count,
        );

        prop_assert_eq!(
            accepted.len(),
            post_replay_leaf_count,
            "accepted-event count != recovered leaf count: accepted={}, recovered={}",
            accepted.len(),
            post_replay_leaf_count,
        );
    }
}
