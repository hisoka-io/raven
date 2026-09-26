//! What the store owes a blinded commitment that arrives at two list indices.
//!
//! Upstream does not enforce one index per blinded commitment on the path Raven
//! mirrors. `packages/node/src/database/databases/poi-ordered-events-database.ts:23-35`
//! keeps `(index, listKey)` unique, then detects the unique
//! `(listKey, blindedCommitment)` index, drops it and recreates it non-unique, so
//! a recurrence syncs. `ppoi_bc_indices` therefore holds every occurrence rather
//! than asserting there is one.
//!
//! The verdict is NOT per occurrence: `poi-merkletree-manager.ts::getPOIStatus`
//! answers per `(listKey, blindedCommitment)` from merkletree membership, and the
//! mirror emits one constant membership status per event. Two rows for one
//! commitment publishing one status is that contract, not a collision.

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

/// Index 0 then index 1, both carrying the same commitment, at distinct heights so
/// a reorg can cut between them.
fn store_with_one_bc_at_two_indices() -> LogicalLeafStore {
    let mut store = LogicalLeafStore::new();
    apply_wal_entry(&mut store, &leaf_added(0, bc(11), VALID), 100, &enc())
        .expect("first occurrence applies");
    apply_wal_entry(&mut store, &leaf_added(1, bc(11), VALID), 200, &enc())
        .expect("second occurrence applies");
    store
}

#[test]
fn a_recurring_blinded_commitment_is_accepted_at_the_next_index() {
    let mut store = LogicalLeafStore::new();
    apply_wal_entry(&mut store, &leaf_added(0, bc(11), VALID), 0, &enc()).expect("first");
    let second = apply_wal_entry(&mut store, &leaf_added(1, bc(11), VALID), 0, &enc());
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
        store.ppoi_index_of(&LIST_KEY, &bc(11)),
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

    assert_eq!(store.ppoi_index_of(&LIST_KEY, &bc(99)), None);
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
    assert_eq!(store.ppoi_index_of(&LIST_KEY, &bc(11)), Some(0));
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
    assert_eq!(store.ppoi_index_of(&LIST_KEY, &bc(11)), None);
}

#[test]
fn a_status_update_dirties_the_shard_of_every_occurrence() {
    let narrow = PerListStatusEncoder::new(RECORD, 1, LIST_KEY).expect("one row per shard");
    let mut store = LogicalLeafStore::new();
    apply_wal_entry(&mut store, &leaf_added(0, bc(11), VALID), 100, &narrow).expect("first");
    apply_wal_entry(&mut store, &leaf_added(1, bc(11), VALID), 200, &narrow).expect("second");
    store.clear_dirty_shards();

    apply_wal_entry(
        &mut store,
        &WalEntryPayload::PpoiStatus {
            list_key: LIST_KEY,
            blinded_commitment: bc(11),
            status: SHIELD_BLOCKED,
        },
        300,
        &narrow,
    )
    .expect("status update");

    assert_eq!(
        store.dirty_shards().iter().copied().collect::<Vec<_>>(),
        vec![0, 1],
        "one status rewrites every row carrying that commitment, so every shard re-encodes"
    );
}

#[test]
fn one_status_covers_every_occurrence_of_a_commitment() {
    let store = store_with_one_bc_at_two_indices();

    assert_eq!(store.ppoi_list_leaves_iter(&LIST_KEY).count(), 2);
    assert_eq!(
        store.ppoi_count(),
        1,
        "upstream answers a status per commitment, so two leaves share one status row"
    );
}

#[test]
fn every_row_for_a_commitment_publishes_the_one_status() {
    let mut store = store_with_one_bc_at_two_indices();
    apply_wal_entry(
        &mut store,
        &WalEntryPayload::PpoiStatus {
            list_key: LIST_KEY,
            blinded_commitment: bc(11),
            status: SHIELD_BLOCKED,
        },
        300,
        &enc(),
    )
    .expect("status update");

    assert_eq!(store.ppoi_status_at(&LIST_KEY, 0), Some(SHIELD_BLOCKED));
    assert_eq!(store.ppoi_status_at(&LIST_KEY, 1), Some(SHIELD_BLOCKED));

    let shard = enc().materialize_shard(0, &store);
    assert_eq!(*shard.first().expect("row 0 status byte"), SHIELD_BLOCKED);
    assert_eq!(
        *shard.get(RECORD).expect("row 1 status byte"),
        SHIELD_BLOCKED
    );
}

/// The client resolves an index from the bc map, fetches that row and binds the row's
/// BC tail back to the commitment it asked about. A recurrence must not break that bind.
#[test]
fn the_row_the_lookup_resolves_carries_the_commitment_in_its_tail() {
    let store = store_with_one_bc_at_two_indices();
    let resolved = store
        .ppoi_index_of(&LIST_KEY, &bc(11))
        .expect("recurring commitment resolves");

    let shard = enc().materialize_shard(0, &store);
    let row = resolved as usize * RECORD;
    assert_eq!(
        shard
            .get(row + 1..row + RECORD)
            .expect("bc tail of the resolved row"),
        &bc(11)[..RECORD - 1],
        "the resolved row binds to the commitment, so the client's tail check passes"
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
