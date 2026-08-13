//! `validate_apply` must agree with `apply_wal_entry`, and the WAL must contain
//! exactly the validated events.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::items_after_statements
)]

use std::sync::Arc;

use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use raven_railgun_core::InstanceId;
use raven_railgun_engine::imt::{Imt, TREE_MAX_ITEMS};
use raven_railgun_engine::inspire::{apply_wal_entry, validate_apply, LogicalLeafStore};
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{PerLeafCommitmentEncoder, PirTableEncoder};
use raven_railgun_persistence::{StoreLayout, WalEntryPayload};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-validate-property";
const ENTRIES_PER_SHARD: u32 = 2048;
const LIST_KEY: [u8; 32] = [0x42; 32];

/// BN254 scalar field modulus, big-endian; the smallest non-canonical leaf.
const BN254_FR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

fn test_encoder() -> PerLeafCommitmentEncoder {
    PerLeafCommitmentEncoder::new(32, ENTRIES_PER_SHARD, 0).expect("test encoder")
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

fn tree_capacity() -> u32 {
    u32::try_from(TREE_MAX_ITEMS).expect("depth-16 capacity fits u32")
}

// In-field leaves dominate so runs stay long; the rest generate the Fr pre-check.
fn leaf_bytes_strategy() -> impl Strategy<Value = [u8; 32]> {
    prop_oneof![
        16 => any::<u8>().prop_map(canonical_commitment),
        1 => Just(BN254_FR_MODULUS_BE),
        1 => Just([0xffu8; 32]),
    ]
}

fn slot_index_strategy() -> impl Strategy<Value = u32> {
    prop_oneof![
        16 => 0u32..32u32,
        1 => Just(tree_capacity()),
        1 => Just(u32::MAX),
    ]
}

// An absolute index almost never equals the store's next free slot, which
// starves the accept path; anchor the candidate to `expected` instead.
fn candidate_index_strategy(expected: u32) -> impl Strategy<Value = u32> {
    prop_oneof![
        8 => Just(expected),
        4 => (1u32..8u32).prop_map(move |gap| expected.saturating_add(gap)),
        2 => Just(expected.saturating_sub(1)),
        1 => Just(tree_capacity()),
        1 => Just(u32::MAX),
    ]
}

// One tree, so long runs exercise the leaf-count advance; cross-tree is unit-tested.
fn append_leaf_strategy() -> impl Strategy<Value = WalEntryPayload> {
    (slot_index_strategy(), leaf_bytes_strategy()).prop_map(|(leaf_index, commitment)| {
        WalEntryPayload::AppendLeaf {
            tree_number: 0,
            leaf_index,
            commitment,
        }
    })
}

fn ppoi_list_leaf_strategy() -> impl Strategy<Value = WalEntryPayload> {
    (slot_index_strategy(), leaf_bytes_strategy(), any::<u8>()).prop_map(
        |(list_index, blinded_commitment, status)| WalEntryPayload::PpoiListLeafAdded {
            list_key: LIST_KEY,
            list_index,
            blinded_commitment,
            status,
        },
    )
}

fn imt_backed_payload_strategy() -> impl Strategy<Value = WalEntryPayload> {
    prop_oneof![append_leaf_strategy(), ppoi_list_leaf_strategy()]
}

/// `(prefix_len, candidate)` where the candidate index is drawn around the
/// slot a prefix of that length leaves free.
fn prefix_and_candidate(ppoi_only: bool) -> impl Strategy<Value = (u32, WalEntryPayload)> {
    (0u32..=8u32).prop_flat_map(move |prefix_len| {
        let variant = if ppoi_only {
            Just(true).boxed()
        } else {
            any::<bool>().boxed()
        };
        (
            Just(prefix_len),
            candidate_index_strategy(prefix_len),
            leaf_bytes_strategy(),
            any::<u8>(),
            variant,
        )
            .prop_map(|(prefix_len, index, leaf, status, is_ppoi)| {
                let payload = if is_ppoi {
                    WalEntryPayload::PpoiListLeafAdded {
                        list_key: LIST_KEY,
                        list_index: index,
                        blinded_commitment: leaf,
                        status,
                    }
                } else {
                    WalEntryPayload::AppendLeaf {
                        tree_number: 0,
                        leaf_index: index,
                        commitment: leaf,
                    }
                };
                (prefix_len, payload)
            })
    })
}

/// Both IMT-backed variants at `index`, so a prefix advances tree 0 and the
/// PPOI list in lockstep.
fn contiguous_prefix(len: u32) -> Vec<WalEntryPayload> {
    let mut out = Vec::with_capacity(usize::try_from(len).unwrap_or(0).saturating_mul(2));
    for i in 0..len {
        let seed = u8::try_from(i).unwrap_or(255).saturating_add(1);
        out.push(WalEntryPayload::AppendLeaf {
            tree_number: 0,
            leaf_index: i,
            commitment: canonical_commitment(seed),
        });
        out.push(WalEntryPayload::PpoiListLeafAdded {
            list_key: LIST_KEY,
            list_index: i,
            blinded_commitment: canonical_commitment(seed),
            status: 1,
        });
    }
    out
}

fn ppoi_list_leaf_count(store: &LogicalLeafStore) -> usize {
    store.ppoi_imt(&LIST_KEY).map_or(0, Imt::leaf_count)
}

fn assert_validate_matches_apply(
    prefix_len: u32,
    candidate: &WalEntryPayload,
) -> Result<(), TestCaseError> {
    let mut store = LogicalLeafStore::new();
    for (i, p) in contiguous_prefix(prefix_len).iter().enumerate() {
        apply_wal_entry(
            &mut store,
            p,
            100 + u64::try_from(i).unwrap_or(0),
            &test_encoder(),
        )
        .expect("contiguous prefix must succeed");
    }

    let validate_outcome = validate_apply(&store, candidate);
    let mut store_dryrun = store.clone();
    let apply_outcome = apply_wal_entry(&mut store_dryrun, candidate, 200, &test_encoder());

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
    Ok(())
}

fn assert_wal_holds_exactly_the_validated_events(
    payloads: &[WalEntryPayload],
) -> Result<(), TestCaseError> {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");

    let mut store = LogicalLeafStore::new();
    let mut accepted_appends = 0usize;
    let mut accepted_ppoi_leaves = 0usize;
    let opened = InspirePersistence::open(
        layout,
        SCHEME_TAG,
        InstanceId::new("validate-property-test"),
        SnapshotPolicy::default(),
        test_encoder_arc(),
    )
    .expect("open 1");

    for (i, p) in payloads.iter().enumerate() {
        // Validate first: a rejection must touch neither WAL nor store.
        let block_height = 100 + u64::try_from(i).unwrap_or(0);
        if validate_apply(&store, p).is_ok() {
            opened
                .persistence
                .apply_event(p, block_height)
                .expect("validated event must apply to WAL");
            apply_wal_entry(&mut store, p, block_height, &test_encoder())
                .expect("validated event must mutate store");
            match p {
                WalEntryPayload::AppendLeaf { .. } => accepted_appends += 1,
                WalEntryPayload::PpoiListLeafAdded { .. } => accepted_ppoi_leaves += 1,
                _ => {}
            }
        }
    }

    let pre_drop_leaf_count = store.imt_leaf_count_for(0);
    let pre_drop_ppoi_count = ppoi_list_leaf_count(&store);
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
    let post_replay_ppoi_count = ppoi_list_leaf_count(&logical_store_after_replay);

    prop_assert_eq!(
        (pre_drop_leaf_count, pre_drop_ppoi_count),
        (post_replay_leaf_count, post_replay_ppoi_count),
        "WAL replay diverged: pre-drop (leaves, ppoi) = ({}, {}), post-replay = ({}, {}); \
         this means validate_apply let an invalid entry through and the \
         tolerant-replay path soft-skipped it on reopen",
        pre_drop_leaf_count,
        pre_drop_ppoi_count,
        post_replay_leaf_count,
        post_replay_ppoi_count,
    );

    prop_assert_eq!(
        (accepted_appends, accepted_ppoi_leaves),
        (post_replay_leaf_count, post_replay_ppoi_count),
        "accepted-event count != recovered leaf count: accepted=({}, {}), recovered=({}, {})",
        accepted_appends,
        accepted_ppoi_leaves,
        post_replay_leaf_count,
        post_replay_ppoi_count,
    );
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    #[test]
    fn validate_apply_agrees_with_apply_wal_entry(
        (prefix_len, candidate) in prefix_and_candidate(false),
    ) {
        assert_validate_matches_apply(prefix_len, &candidate)?;
    }

    /// PPOI-only, so the PPOI arms are covered even when the mixed generator shrinks to appends.
    #[test]
    fn ppoi_validate_apply_agrees_with_apply_wal_entry(
        (prefix_len, candidate) in prefix_and_candidate(true),
    ) {
        assert_validate_matches_apply(prefix_len, &candidate)?;
    }

    #[test]
    fn validate_then_wal_then_mutate_keeps_wal_clean(
        payloads in prop::collection::vec(imt_backed_payload_strategy(), 1..32),
    ) {
        assert_wal_holds_exactly_the_validated_events(&payloads)?;
    }

    /// PPOI-only, so a WAL-poisoning PPOI leaf cannot hide behind append traffic.
    #[test]
    fn ppoi_validate_then_wal_keeps_wal_clean(
        payloads in prop::collection::vec(ppoi_list_leaf_strategy(), 1..32),
    ) {
        assert_wal_holds_exactly_the_validated_events(&payloads)?;
    }

    /// Filling a tree to 65,536 leaves is out of reach here, so the capacity
    /// refusal is pinned on the index alone: no prefix may rescue it.
    #[test]
    fn an_index_at_or_past_capacity_is_never_accepted(
        prefix_len in 0u32..=8u32,
        index in prop_oneof![
            Just(tree_capacity()),
            Just(tree_capacity().saturating_add(1)),
            Just(u32::MAX),
        ],
        leaf in leaf_bytes_strategy(),
        status in any::<u8>(),
        is_ppoi in any::<bool>(),
    ) {
        let mut store = LogicalLeafStore::new();
        for (i, p) in contiguous_prefix(prefix_len).iter().enumerate() {
            apply_wal_entry(&mut store, p, 100 + u64::try_from(i).unwrap_or(0), &test_encoder())
                .expect("contiguous prefix must succeed");
        }
        let payload = if is_ppoi {
            WalEntryPayload::PpoiListLeafAdded {
                list_key: LIST_KEY,
                list_index: index,
                blinded_commitment: leaf,
                status,
            }
        } else {
            WalEntryPayload::AppendLeaf { tree_number: 0, leaf_index: index, commitment: leaf }
        };

        let err = validate_apply(&store, &payload)
            .expect_err("an index at or past capacity must never validate");
        let msg = format!("{err}");
        prop_assert!(
            msg.contains("capacity") && msg.contains(&TREE_MAX_ITEMS.to_string()),
            "expected a capacity refusal naming {} for index {} at prefix_len {}, got: {}",
            TREE_MAX_ITEMS,
            index,
            prefix_len,
            msg,
        );
    }
}
