//! `ppoi_bc_indices` holds every occurrence of a commitment in a list, and the snapshot carries
//! them all: upstream permits a commitment to recur, and a snapshot must not be where the second
//! occurrence is lost.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::PerListPath10Encoder;
use raven_railgun_persistence::{decode_no_trailing, PpoiEventType, WalEntryPayload};

/// The store half of the shipped V8 snapshot fixture, minted by
/// `inspire::frozen_v8_shape_tests::mint_frozen_v8_store_fixture`: one commitment leaf plus two
/// PPOI list leaves on `FIXTURE_LIST_KEY`.
const FROZEN_V8_STORE: &[u8] = include_bytes!("fixtures/logical_store_v8.bin");
const FIXTURE_LIST_KEY: [u8; 32] = [0xab; 32];

const LIST_KEY: [u8; 32] = [0x5e; 32];
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

fn enc() -> PerListPath10Encoder {
    PerListPath10Encoder::new(EPS, LIST_KEY).expect("encoder")
}

fn leaf_added(list_index: u32, blinded_commitment: [u8; 32]) -> WalEntryPayload {
    WalEntryPayload::PpoiListLeafAdded {
        list_key: LIST_KEY,
        list_index,
        blinded_commitment,
        status: 0,
        event_type: PpoiEventType::Shield,
        signature: Vec::new(),
        validated_merkleroot: [7; 32],
    }
}

#[test]
fn the_shipped_v8_snapshot_resolves_its_bc_index() {
    let store: LogicalLeafStore = decode_no_trailing(FROZEN_V8_STORE).unwrap_or_else(|e| {
        panic!("LogicalLeafStore no longer reads the V8 bytes it ships with ({e})")
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
