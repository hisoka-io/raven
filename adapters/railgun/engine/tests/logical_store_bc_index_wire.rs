//! `ppoi_bc_indices` widened from one index per commitment to a set of occurrences
//! WITHOUT moving the snapshot wire, and this is the proof.
//!
//! bincode is positional and frames nothing per element: a `BTreeMap<K, V>` and a
//! `BTreeSet<T>` are both `len: u64` then the entries back to back, a tuple is its
//! members concatenated, and `()` is zero bytes. So `(bc_key, u32)` as a map entry and
//! `(bc_key, u32)` as a set element occupy the same 68 bytes in the same order, and any
//! duplicate-free population encodes identically either way. Every snapshot ever written
//! is duplicate-free, because the map it was written from could not hold a second index.
//!
//! That is a property of the encoding, not a promise, so it is asserted here rather than
//! recorded in a comment. If it ever fails, the change needs `SNAPSHOT_V8_MAGIC` and a
//! frozen V7 shape, the way `LogicalLeafStoreV6` freezes V6.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::PerListStatusEncoder;
use raven_railgun_persistence::{decode_no_trailing, PpoiEventType, WalEntryPayload};
use std::collections::{BTreeMap, BTreeSet};

/// The store half of the shipped V7 snapshot fixture, minted by
/// `inspire::tests::mint_frozen_v7_store_fixture` from a build predating this widening:
/// one commitment leaf plus two PPOI list leaves on `FIXTURE_LIST_KEY`.
const FROZEN_V7_STORE: &[u8] = include_bytes!("fixtures/logical_store_v7.bin");
const FIXTURE_LIST_KEY: [u8; 32] = [0xab; 32];

const LIST_KEY: [u8; 32] = [0x5e; 32];
const RECORD: usize = 32;
const EPS: u32 = 2048;

/// The fixture's per-list leaves: all-zero but for a trailing ordinal.
fn fixture_bc(ordinal: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = ordinal;
    out
}

fn bc(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16] = seed;
    out[31] = 0x01;
    out
}

fn enc() -> PerListStatusEncoder {
    PerListStatusEncoder::new(RECORD, EPS, LIST_KEY).expect("encoder")
}

fn leaf_added(list_index: u32, blinded_commitment: [u8; 32]) -> WalEntryPayload {
    WalEntryPayload::PpoiListLeafAdded {
        list_key: LIST_KEY,
        list_index,
        blinded_commitment,
        status: 0,
        event_type: PpoiEventType::Shield,
        signature: vec![0; 64],
        validated_merkleroot: [7; 32],
    }
}

/// The one-index-per-commitment map every existing snapshot carries at this position.
fn superseded_map() -> BTreeMap<([u8; 32], [u8; 32]), u32> {
    let mut out = BTreeMap::new();
    out.insert((LIST_KEY, bc(1)), 0u32);
    out.insert((LIST_KEY, bc(2)), 1u32);
    out
}

fn widened_set() -> BTreeSet<([u8; 32], [u8; 32], u32)> {
    let mut out = BTreeSet::new();
    out.insert((LIST_KEY, bc(1), 0u32));
    out.insert((LIST_KEY, bc(2), 1u32));
    out
}

#[test]
fn the_widened_index_encodes_exactly_as_the_map_it_replaces() {
    let was = bincode::serialize(&superseded_map()).expect("serialize superseded map");
    let now = bincode::serialize(&widened_set()).expect("serialize widened set");

    assert_eq!(
        was, now,
        "the widening is wire-neutral only while these agree byte for byte"
    );
    assert_eq!(
        was.len(),
        8 + 2 * (32 + 32 + 4),
        "u64 length then 68 B entries"
    );
}

#[test]
fn superseded_bytes_decode_as_the_widened_set() {
    let was = bincode::serialize(&superseded_map()).expect("serialize superseded map");
    let back: BTreeSet<([u8; 32], [u8; 32], u32)> =
        decode_no_trailing(&was).expect("an existing snapshot's bytes must still read");

    assert_eq!(back, widened_set());
}

/// A snapshot written AFTER the widening, read by a build from BEFORE it. The duplicate
/// collapses -- that build's own behaviour -- and, the part that matters, the reader stays
/// byte-aligned, so no field after this one is reinterpreted.
#[test]
fn a_recurrence_read_back_through_the_superseded_shape_stays_aligned() {
    let mut recurring = widened_set();
    recurring.insert((LIST_KEY, bc(1), 7u32));
    let now = bincode::serialize(&recurring).expect("serialize widened set");

    let back: BTreeMap<([u8; 32], [u8; 32]), u32> =
        decode_no_trailing(&now).expect("no underrun and no surplus");

    assert_eq!(back.len(), 2, "the recurrence collapses, as it did before");
    assert_eq!(back.get(&(LIST_KEY, bc(1))), Some(&7u32));
}

#[test]
fn the_shipped_v7_snapshot_still_resolves_its_bc_index() {
    let store: LogicalLeafStore = decode_no_trailing(FROZEN_V7_STORE).unwrap_or_else(|e| {
        panic!(
            "LogicalLeafStore no longer reads the V7 bytes it ships with ({e}); the widening \
             moved the wire after all"
        )
    });

    assert_eq!(store.leaf(0, 0), Some(&[7u8; 32]));
    assert_eq!(store.ppoi_list_leaves_iter(&FIXTURE_LIST_KEY).count(), 2);
    assert_eq!(
        store.ppoi_index_of(&FIXTURE_LIST_KEY, &fixture_bc(1)),
        Some(0)
    );
    assert_eq!(
        store.ppoi_index_of(&FIXTURE_LIST_KEY, &fixture_bc(2)),
        Some(1)
    );
    assert_eq!(
        store
            .ppoi_indices_of(&FIXTURE_LIST_KEY, &fixture_bc(1))
            .collect::<Vec<_>>(),
        vec![0],
        "a snapshot written before the widening holds exactly one index per commitment"
    );
}

#[test]
fn a_recurrence_round_trips_through_the_live_store_encoding() {
    let mut store = LogicalLeafStore::new();
    apply_wal_entry(&mut store, &leaf_added(0, bc(1)), 100, &enc()).expect("first");
    apply_wal_entry(&mut store, &leaf_added(1, bc(1)), 200, &enc()).expect("recurrence");

    let bytes = bincode::serialize(&store).expect("serialize live store");
    let back: LogicalLeafStore = decode_no_trailing(&bytes).expect("round trip");

    assert_eq!(
        back.ppoi_indices_of(&LIST_KEY, &bc(1)).collect::<Vec<_>>(),
        vec![0, 1],
        "a snapshot must not be where the second occurrence is lost"
    );
}
