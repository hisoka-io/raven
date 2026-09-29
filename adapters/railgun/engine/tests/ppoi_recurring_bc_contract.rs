//! What the store owes a blinded commitment that arrives at two list indices.
//!
//! Upstream does not enforce one index per blinded commitment on the path Raven
//! mirrors. `packages/node/src/database/databases/poi-ordered-events-database.ts:23-35`
//! keeps `(index, listKey)` unique, then detects the unique
//! `(listKey, blindedCommitment)` index, drops it and recreates it non-unique, so
//! a recurrence syncs. `ppoi_bc_indices` therefore holds every occurrence rather
//! than asserting there is one.
//!
//! Each occurrence is a row of its own, and every filled row carries the Valid status byte:
//! membership is the row's presence, so two rows for one commitment publish one verdict.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_railgun_core::POIStatus;
use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::{PerListPath10Encoder, PirTableEncoder, PATH10_RECORD_BYTES};
use raven_railgun_persistence::{PpoiEventType, WalEntryPayload};
use raven_railgun_testkit::canonical as bc;

const LIST_KEY: [u8; 32] = [0x3c; 32];
const EPS: u32 = 2048;
const STATUS_OFFSET: usize = 32;

fn enc() -> PerListPath10Encoder {
    PerListPath10Encoder::new(EPS, LIST_KEY).expect("encoder")
}

fn leaf_added(list_index: u32, blinded_commitment: [u8; 32]) -> WalEntryPayload {
    WalEntryPayload::PpoiListLeafAdded {
        list_key: LIST_KEY,
        list_index,
        blinded_commitment,
        event_type: PpoiEventType::Shield,
        validated_merkleroot: [7; 32],
    }
}

/// Index 0 then index 1, both carrying the same commitment, at distinct heights so
/// a reorg can cut between them.
fn store_with_one_bc_at_two_indices() -> LogicalLeafStore {
    let mut store = LogicalLeafStore::new();
    apply_wal_entry(&mut store, &leaf_added(0, bc(11)), 100, &enc())
        .expect("first occurrence applies");
    apply_wal_entry(&mut store, &leaf_added(1, bc(11)), 200, &enc())
        .expect("second occurrence applies");
    store
}

#[test]
fn a_recurring_blinded_commitment_is_accepted_at_the_next_index() {
    let mut store = LogicalLeafStore::new();
    apply_wal_entry(&mut store, &leaf_added(0, bc(11)), 0, &enc()).expect("first");
    let second = apply_wal_entry(&mut store, &leaf_added(1, bc(11)), 0, &enc());
    assert!(
        second.is_ok(),
        "upstream permits a recurrence, so refusing one refuses valid data: {second:?}"
    );
}

#[test]
fn every_occurrence_stays_reachable_from_the_commitment() {
    let store = store_with_one_bc_at_two_indices();

    assert_eq!(store.ppoi_bc_at(&LIST_KEY, 0), Some(bc(11)));
    assert_eq!(store.ppoi_bc_at(&LIST_KEY, 1), Some(bc(11)));
    assert_eq!(
        store
            .ppoi_indices_of(&LIST_KEY, &bc(11))
            .collect::<Vec<_>>(),
        vec![0, 1],
        "both occurrences resolve, ascending"
    );
    assert_eq!(
        store.ppoi_indices_of(&LIST_KEY, &bc(11)).next(),
        Some(0),
        "the single-index lookup serves the LOWEST occurrence"
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
fn an_unindexed_commitment_resolves_to_nothing() {
    let store = store_with_one_bc_at_two_indices();

    assert_eq!(store.ppoi_indices_of(&LIST_KEY, &bc(99)).next(), None);
    assert_eq!(store.ppoi_indices_of(&LIST_KEY, &bc(99)).count(), 0);
}

#[test]
fn rolling_back_the_later_occurrence_leaves_the_earlier_indexed() {
    let mut store = store_with_one_bc_at_two_indices();

    apply_wal_entry(
        &mut store,
        &WalEntryPayload::Reorg { height: 150 },
        150,
        &enc(),
    )
    .expect("reorg unwinds everything above height 150");

    assert_eq!(
        store.ppoi_bc_at(&LIST_KEY, 1),
        None,
        "index 1 was above the reorg height"
    );
    assert_eq!(
        store
            .ppoi_indices_of(&LIST_KEY, &bc(11))
            .collect::<Vec<_>>(),
        vec![0],
        "the surviving occurrence keeps its lookup; unindexing it reports a list member as Missing"
    );
    assert_eq!(store.ppoi_indices_of(&LIST_KEY, &bc(11)).next(), Some(0));
}

#[test]
fn rolling_back_every_occurrence_unindexes_the_commitment() {
    let mut store = store_with_one_bc_at_two_indices();

    apply_wal_entry(
        &mut store,
        &WalEntryPayload::Reorg { height: 50 },
        50,
        &enc(),
    )
    .expect("reorg unwinds both occurrences");

    assert_eq!(store.ppoi_indices_of(&LIST_KEY, &bc(11)).count(), 0);
    assert_eq!(store.ppoi_indices_of(&LIST_KEY, &bc(11)).next(), None);
}

/// The client resolves an index, fetches that row and binds the row's leaf back to the
/// commitment it asked about. A recurrence must not break that bind, and every occurrence
/// publishes the one verdict.
#[test]
fn every_row_of_a_recurring_commitment_carries_it_and_the_valid_byte() {
    let store = store_with_one_bc_at_two_indices();
    let shard = enc().materialize_shard(0, &store);
    for index in store.ppoi_indices_of(&LIST_KEY, &bc(11)) {
        let row = index as usize * PATH10_RECORD_BYTES;
        assert_eq!(
            shard.get(row..row + 32).expect("leaf of the row"),
            &bc(11)[..],
            "row {index} binds to the commitment, so the client's leaf check passes"
        );
        assert_eq!(
            shard.get(row + STATUS_OFFSET).copied(),
            Some(POIStatus::Valid.wire_byte()),
            "row {index} is filled, so its status byte is Valid"
        );
    }
}

#[test]
fn per_index_metadata_stays_separate_for_each_occurrence() {
    let mut store = LogicalLeafStore::new();
    apply_wal_entry(&mut store, &leaf_added(0, bc(11)), 0, &enc()).expect("first");
    let mut second = leaf_added(1, bc(11));
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
