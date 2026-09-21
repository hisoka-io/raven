//! What the store does TODAY when one blinded commitment arrives at two list
//! indices. Recorded, not endorsed: nothing here proposes a policy, adds a
//! refusal or adds a counter, and a passing run is not an argument that the
//! behaviour is right.
//!
//! Upstream does not enforce one index per blinded commitment on the path Raven
//! mirrors. `packages/node/src/database/databases/poi-ordered-events-database.ts:23-35`
//! keeps `(index, listKey)` unique, then drops the unique
//! `(listKey, blindedCommitment)` index and recreates it non-unique, so a
//! recurrence syncs. Raven keys both `ppoi_bc_index` and `ppoi_status` on
//! `(list_key, blinded_commitment)`, which holds one value per pair.
//!
//! If this file ever goes red, the behaviour changed; read the new behaviour
//! before deciding which side of the change is the defect.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::{PerListStatusEncoder, PirTableEncoder};
use raven_railgun_persistence::{PpoiEventType, WalEntryPayload};
use raven_railgun_testkit::canonical as bc;

const LIST_KEY: [u8; 32] = [0x3c; 32];
const RECORD: usize = 32;
const EPS: u32 = 2048;

/// Mirrors `poi_status_to_str` / `statusByteToPOIStatus`: 0 Valid, 1 ShieldBlocked.
const VALID: u8 = 0;
const SHIELD_BLOCKED: u8 = 1;

fn enc() -> PerListStatusEncoder {
    PerListStatusEncoder::new(RECORD, EPS, LIST_KEY).expect("encoder")
}

fn leaf_added(list_index: u32, blinded_commitment: [u8; 32], status: u8) -> WalEntryPayload {
    WalEntryPayload::PpoiListLeafAdded {
        list_key: LIST_KEY,
        list_index,
        blinded_commitment,
        status,
        event_type: PpoiEventType::Shield,
        signature: vec![0; 64],
        validated_merkleroot: [7; 32],
    }
}

/// Index 0 then index 1, both carrying the same commitment, with different
/// statuses so the overwrite is observable.
fn store_with_one_bc_at_two_indices() -> LogicalLeafStore {
    let mut store = LogicalLeafStore::new();
    apply_wal_entry(&mut store, &leaf_added(0, bc(11), VALID), 0, &enc())
        .expect("first occurrence applies");
    apply_wal_entry(
        &mut store,
        &leaf_added(1, bc(11), SHIELD_BLOCKED),
        0,
        &enc(),
    )
    .expect("second occurrence applies; nothing refuses a recurrence today");
    store
}

#[test]
fn a_recurring_blinded_commitment_is_accepted_at_the_next_index() {
    let mut store = LogicalLeafStore::new();
    apply_wal_entry(&mut store, &leaf_added(0, bc(11), VALID), 0, &enc()).expect("first");
    let second = apply_wal_entry(&mut store, &leaf_added(1, bc(11), VALID), 0, &enc());
    assert!(
        second.is_ok(),
        "today a recurrence applies cleanly: {second:?}"
    );
}

#[test]
fn both_indices_keep_a_leaf_while_the_bc_lookup_keeps_only_the_last() {
    let store = store_with_one_bc_at_two_indices();

    assert_eq!(store.ppoi_bc_at(&LIST_KEY, 0), Some(bc(11)));
    assert_eq!(store.ppoi_bc_at(&LIST_KEY, 1), Some(bc(11)));
    assert_eq!(
        store.ppoi_index_of(&LIST_KEY, &bc(11)),
        Some(1),
        "the reverse lookup holds one index per pair, so the later write wins"
    );
    assert_eq!(
        store
            .ppoi_imt(&LIST_KEY)
            .expect("per-list IMT exists")
            .leaf_count(),
        2,
        "the tree grew by both appends, including the duplicate leaf value"
    );
}

#[test]
fn the_leaf_count_and_the_status_count_diverge_by_one() {
    let store = store_with_one_bc_at_two_indices();

    let leaves = store.ppoi_list_leaves_iter(&LIST_KEY).count();
    assert_eq!(leaves, 2);
    assert_eq!(
        store.ppoi_count(),
        1,
        "statuses are keyed by commitment, so two leaves share one status row"
    );
    assert_ne!(
        leaves,
        store.ppoi_count(),
        "the divergence is the only local signal that a recurrence happened, and nothing reads it"
    );
}

#[test]
fn the_row_for_the_first_index_serves_the_second_occurrences_status() {
    let store = store_with_one_bc_at_two_indices();

    assert_eq!(
        store.ppoi_status_at(&LIST_KEY, 0),
        Some(SHIELD_BLOCKED),
        "index 0 arrived as Valid and now reads as the later occurrence's verdict"
    );
    assert_eq!(store.ppoi_status_at(&LIST_KEY, 1), Some(SHIELD_BLOCKED));

    let shard = enc().materialize_shard(0, &store);
    assert_eq!(
        *shard.first().expect("row 0 status byte"),
        SHIELD_BLOCKED,
        "the served bytes follow the store, so row 0 publishes the later status"
    );
    assert_eq!(
        *shard.get(RECORD).expect("row 1 status byte"),
        SHIELD_BLOCKED
    );
}

#[test]
fn per_index_metadata_stays_separate_for_each_occurrence() {
    let mut store = LogicalLeafStore::new();
    apply_wal_entry(&mut store, &leaf_added(0, bc(11), VALID), 0, &enc()).expect("first");
    let mut second = leaf_added(1, bc(11), VALID);
    if let WalEntryPayload::PpoiListLeafAdded {
        event_type,
        validated_merkleroot,
        ..
    } = &mut second
    {
        *event_type = PpoiEventType::Transact;
        *validated_merkleroot = [9; 32];
    }
    apply_wal_entry(&mut store, &second, 0, &enc()).expect("second");

    let first_meta = store
        .ppoi_event_metadata(&LIST_KEY, 0)
        .expect("metadata at 0");
    let second_meta = store
        .ppoi_event_metadata(&LIST_KEY, 1)
        .expect("metadata at 1");
    assert_eq!(first_meta.event_type, PpoiEventType::Shield);
    assert_eq!(second_meta.event_type, PpoiEventType::Transact);
    assert_eq!(first_meta.validated_merkleroot, [7; 32]);
    assert_eq!(second_meta.validated_merkleroot, [9; 32]);
}
