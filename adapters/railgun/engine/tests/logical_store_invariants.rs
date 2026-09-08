//! `LogicalLeafStore` invariant tests.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use raven_railgun_core::MerkleProof;
use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::PerLeafCommitmentEncoder;
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_poseidon::merkle_node;

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
    PerLeafCommitmentEncoder::new(32, ENTRIES_PER_SHARD, 0).expect("encoder")
}

/// Fold the leaf up through the returned siblings. `proof.root` is copied straight
/// from the tree, so comparing it against that same tree is a tautology; only a
/// walk that consumes `elements` can tell a real path from a corrupt one.
fn reconstruct_root(leaf: [u8; 32], leaf_index: u32, proof: &MerkleProof) -> [u8; 32] {
    let mut current = leaf;
    for (level, sibling) in proof.elements.iter().enumerate() {
        current = if (leaf_index >> level) & 1 == 1 {
            merkle_node(*sibling, current)
        } else {
            merkle_node(current, *sibling)
        }
        .expect("merkle_node");
    }
    current
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
    assert_eq!(
        proof.indices, 1,
        "indices must pack the queried leaf index, or the client folds the path the \
         wrong way round"
    );
    assert_eq!(
        reconstruct_root(fr_canonical(2), 1, &proof),
        store.imt_root(0).expect("root present"),
        "the returned siblings must fold leaf 1 back to the tree root"
    );
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
    let proof = store.ppoi_merkle_proof(&LIST_KEY, 0).expect("proof");
    assert_eq!(proof.indices, 0, "list index 0 folds left at every level");
    assert_eq!(
        reconstruct_root(bc, 0, &proof),
        store.ppoi_imt_root(&LIST_KEY).expect("root present"),
        "the returned siblings must fold the blinded commitment back to the per-list root"
    );
}
