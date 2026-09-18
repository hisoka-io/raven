#![allow(clippy::expect_used)]

use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::PerListStatusEncoder;
use raven_railgun_persistence::WalEntryPayload;

const LIST_KEY: [u8; 32] = [0x4d; 32];
const BLINDED_COMMITMENT: [u8; 32] = [0x2a; 32];
const ENTRIES_PER_SHARD: u32 = 8;

fn encoder() -> PerListStatusEncoder {
    PerListStatusEncoder::new(32, ENTRIES_PER_SHARD, LIST_KEY).expect("encoder")
}

fn status(status: u8) -> WalEntryPayload {
    WalEntryPayload::PpoiStatus {
        list_key: LIST_KEY,
        blinded_commitment: BLINDED_COMMITMENT,
        status,
    }
}

fn blinded_commitment(list_index: u32) -> [u8; 32] {
    if list_index == ENTRIES_PER_SHARD {
        BLINDED_COMMITMENT
    } else {
        let mut commitment = [0u8; 32];
        commitment[28..].copy_from_slice(&list_index.saturating_add(1).to_be_bytes());
        commitment
    }
}

#[test]
fn status_without_an_indexed_row_dirties_no_shard() {
    let mut store = LogicalLeafStore::new();

    apply_wal_entry(&mut store, &status(1), 100, &encoder()).expect("status update");

    assert!(store.dirty_shards().is_empty());
}

#[test]
fn status_for_an_indexed_row_reuses_the_leaf_shard_mapping() {
    let mut store = LogicalLeafStore::new();
    for list_index in 0..=ENTRIES_PER_SHARD {
        apply_wal_entry(
            &mut store,
            &WalEntryPayload::PpoiListLeafAdded {
                list_key: LIST_KEY,
                list_index,
                blinded_commitment: blinded_commitment(list_index),
                status: 0,
                event_type: raven_railgun_persistence::PpoiEventType::Shield,
                signature: vec![0; 64],
                validated_merkleroot: [0; 32],
            },
            100 + u64::from(list_index),
            &encoder(),
        )
        .expect("list leaf");
    }
    store.clear_dirty_shards();

    apply_wal_entry(&mut store, &status(2), 101, &encoder()).expect("status update");

    assert_eq!(
        store.dirty_shards().iter().copied().collect::<Vec<_>>(),
        [1]
    );
}
