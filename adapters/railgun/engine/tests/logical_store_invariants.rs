//! `LogicalLeafStore` invariant tests.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::PerLeafCommitmentEncoder;
use raven_railgun_persistence::WalEntryPayload;

const ENTRIES_PER_SHARD: u32 = 65_536;
const LIST_KEY: [u8; 32] = [0xab; 32];

fn fr_canonical(tag: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for byte in out.iter_mut().skip(16) {
        *byte = tag;
    }
    out
}

fn enc() -> PerLeafCommitmentEncoder {
    PerLeafCommitmentEncoder::new(32, ENTRIES_PER_SHARD).expect("encoder")
}

#[test]
fn append_leaf_drives_imt_root_advance() {
    let mut store = LogicalLeafStore::new();
    let e = enc();
    apply_wal_entry(
        &mut store,
        &WalEntryPayload::AppendLeaf {
            tree_number: 0,
            leaf_index: 0,
            commitment: fr_canonical(0x01),
        },
        100,
        &e,
    )
    .expect("apply 0");
    let root_after_one = store.imt_root(0).expect("root present after 1 leaf");

    apply_wal_entry(
        &mut store,
        &WalEntryPayload::AppendLeaf {
            tree_number: 0,
            leaf_index: 1,
            commitment: fr_canonical(0x02),
        },
        101,
        &e,
    )
    .expect("apply 1");
    let root_after_two = store.imt_root(0).expect("root present after 2 leaves");

    assert_ne!(
        root_after_one, root_after_two,
        "root must change after each new leaf"
    );
    assert_eq!(store.imt_leaf_count_for(0), 2);
}

#[test]
fn append_leaf_rejects_non_contiguous_insert() {
    let mut store = LogicalLeafStore::new();
    let e = enc();
    let err = apply_wal_entry(
        &mut store,
        &WalEntryPayload::AppendLeaf {
            tree_number: 0,
            leaf_index: 1,
            commitment: fr_canonical(0x01),
        },
        100,
        &e,
    )
    .expect_err("must reject leaf_index=1 with empty tree");
    assert!(format!("{err}").contains("non-contiguous"));
}

#[test]
fn reorg_truncates_leaves_above_height_and_rebuilds_imt() {
    let mut store = LogicalLeafStore::new();
    let e = enc();
    for i in 0u32..5 {
        apply_wal_entry(
            &mut store,
            &WalEntryPayload::AppendLeaf {
                tree_number: 0,
                leaf_index: i,
                commitment: fr_canonical(u8::try_from(i + 1).unwrap_or(1)),
            },
            100 + u64::from(i),
            &e,
        )
        .expect("apply");
    }
    assert_eq!(store.leaf_count(), 5);
    let root_5 = store.imt_root(0).expect("root after 5");

    apply_wal_entry(&mut store, &WalEntryPayload::Reorg { height: 102 }, 102, &e)
        .expect("apply reorg");
    assert_eq!(
        store.leaf_count(),
        3,
        "leaves at heights 103, 104 truncated"
    );
    let root_3 = store.imt_root(0).expect("root after reorg");
    assert_ne!(root_3, root_5, "root must reflect truncated tree");
    assert_eq!(store.imt_leaf_count_for(0), 3);
    assert!(store.leaf(0, 0).is_some());
    assert!(store.leaf(0, 1).is_some());
    assert!(store.leaf(0, 2).is_some());
    assert!(store.leaf(0, 3).is_none());
    assert!(store.leaf(0, 4).is_none());
}

#[test]
fn reorg_does_not_lower_last_block_height() {
    let mut store = LogicalLeafStore::new();
    let e = enc();
    apply_wal_entry(
        &mut store,
        &WalEntryPayload::AppendLeaf {
            tree_number: 0,
            leaf_index: 0,
            commitment: fr_canonical(0x01),
        },
        500,
        &e,
    )
    .expect("apply");
    assert_eq!(store.last_block_height(), 500);
    apply_wal_entry(&mut store, &WalEntryPayload::Reorg { height: 100 }, 100, &e)
        .expect("apply reorg");
    assert_eq!(
        store.last_block_height(),
        500,
        "reorg MUST NOT lower last_block_height; downstream consumers rely on monotonic-max"
    );
}

#[test]
fn ppoi_list_leaf_added_advances_per_list_imt() {
    let mut store = LogicalLeafStore::new();
    let e = enc();
    let bc = fr_canonical(0x11);
    apply_wal_entry(
        &mut store,
        &WalEntryPayload::PpoiListLeafAdded {
            list_key: LIST_KEY,
            list_index: 0,
            blinded_commitment: bc,
            status: 0,
        },
        200,
        &e,
    )
    .expect("apply ppoi");
    let r1 = store.ppoi_imt_root(&LIST_KEY).expect("root present");
    let bc2 = fr_canonical(0x22);
    apply_wal_entry(
        &mut store,
        &WalEntryPayload::PpoiListLeafAdded {
            list_key: LIST_KEY,
            list_index: 1,
            blinded_commitment: bc2,
            status: 1,
        },
        201,
        &e,
    )
    .expect("apply ppoi");
    let r2 = store.ppoi_imt_root(&LIST_KEY).expect("root present");
    assert_ne!(r1, r2);
    assert_eq!(store.ppoi_bc_at(&LIST_KEY, 0), Some(bc));
    assert_eq!(store.ppoi_bc_at(&LIST_KEY, 1), Some(bc2));
    assert_eq!(store.ppoi_index_of(&LIST_KEY, &bc), Some(0));
    assert_eq!(store.ppoi_index_of(&LIST_KEY, &bc2), Some(1));
}

#[test]
fn ppoi_status_in_place_update_does_not_affect_imt_root() {
    let mut store = LogicalLeafStore::new();
    let e = enc();
    let bc = fr_canonical(0x11);
    apply_wal_entry(
        &mut store,
        &WalEntryPayload::PpoiListLeafAdded {
            list_key: LIST_KEY,
            list_index: 0,
            blinded_commitment: bc,
            status: 0,
        },
        200,
        &e,
    )
    .expect("apply add");
    let root_before = store.ppoi_imt_root(&LIST_KEY).expect("root");
    apply_wal_entry(
        &mut store,
        &WalEntryPayload::PpoiStatus {
            list_key: LIST_KEY,
            blinded_commitment: bc,
            status: 1,
        },
        201,
        &e,
    )
    .expect("apply status update");
    let root_after = store.ppoi_imt_root(&LIST_KEY).expect("root");
    assert_eq!(
        root_before, root_after,
        "status update MUST NOT change per-list IMT root (root is over BCs, not status)"
    );
    assert_eq!(store.ppoi_status_at(&LIST_KEY, 0), Some(1));
}

#[test]
fn dirty_shards_accumulate_then_clear() {
    let mut store = LogicalLeafStore::new();
    let e = enc();
    apply_wal_entry(
        &mut store,
        &WalEntryPayload::AppendLeaf {
            tree_number: 0,
            leaf_index: 0,
            commitment: fr_canonical(0x01),
        },
        100,
        &e,
    )
    .expect("apply");
    assert!(!store.dirty_shards().is_empty());
    store.clear_dirty_shards();
    assert!(store.dirty_shards().is_empty());
}

#[test]
fn ppoi_list_count_reflects_distinct_list_keys() {
    let mut store = LogicalLeafStore::new();
    let e = enc();
    let lk_a = [0xa1u8; 32];
    let lk_b = [0xb2u8; 32];
    apply_wal_entry(
        &mut store,
        &WalEntryPayload::PpoiListLeafAdded {
            list_key: lk_a,
            list_index: 0,
            blinded_commitment: fr_canonical(0x11),
            status: 0,
        },
        200,
        &e,
    )
    .expect("apply a");
    apply_wal_entry(
        &mut store,
        &WalEntryPayload::PpoiListLeafAdded {
            list_key: lk_b,
            list_index: 0,
            blinded_commitment: fr_canonical(0x22),
            status: 0,
        },
        201,
        &e,
    )
    .expect("apply b");
    assert_eq!(store.ppoi_list_count(), 2);
}

#[test]
fn imt_tree_count_tracks_distinct_chain_trees() {
    let mut store = LogicalLeafStore::new();
    let e = enc();
    for tree in 0u32..3 {
        apply_wal_entry(
            &mut store,
            &WalEntryPayload::AppendLeaf {
                tree_number: tree,
                leaf_index: 0,
                commitment: fr_canonical(u8::try_from(tree + 1).unwrap_or(1)),
            },
            100 + u64::from(tree),
            &e,
        )
        .expect("apply");
    }
    assert_eq!(store.imt_tree_count(), 3);
}

#[test]
fn merkle_proof_round_trips_for_appended_leaf() {
    let mut store = LogicalLeafStore::new();
    let e = enc();
    for i in 0u32..3 {
        apply_wal_entry(
            &mut store,
            &WalEntryPayload::AppendLeaf {
                tree_number: 0,
                leaf_index: i,
                commitment: fr_canonical(u8::try_from(i + 1).unwrap_or(1)),
            },
            100 + u64::from(i),
            &e,
        )
        .expect("apply");
    }
    let proof = store.merkle_proof(0, 1).expect("proof");
    assert_eq!(proof.elements.len(), 16);
    assert_eq!(store.imt_root(0), Some(proof.root));
}

#[test]
fn ppoi_merkle_proof_round_trips_for_added_bc() {
    let mut store = LogicalLeafStore::new();
    let e = enc();
    let bc = fr_canonical(0x11);
    apply_wal_entry(
        &mut store,
        &WalEntryPayload::PpoiListLeafAdded {
            list_key: LIST_KEY,
            list_index: 0,
            blinded_commitment: bc,
            status: 0,
        },
        200,
        &e,
    )
    .expect("apply");
    let _ = bc;
    let proof = store.ppoi_merkle_proof(&LIST_KEY, 0).expect("proof");
    assert_eq!(proof.elements.len(), 16);
    assert_eq!(store.ppoi_imt_root(&LIST_KEY), Some(proof.root));
}

#[test]
fn heartbeat_does_not_mutate_state() {
    let mut store = LogicalLeafStore::new();
    let e = enc();
    apply_wal_entry(
        &mut store,
        &WalEntryPayload::Heartbeat {
            wallclock_unix_ms: 1_700_000_000,
        },
        100,
        &e,
    )
    .expect("apply heartbeat");
    assert_eq!(store.leaf_count(), 0);
    assert_eq!(store.ppoi_count(), 0);
    assert_eq!(store.last_block_height(), 100);
}
