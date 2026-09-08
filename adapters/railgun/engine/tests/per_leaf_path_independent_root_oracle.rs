//! PIR-served per-leaf (commit-tree) auth-path rows checked against a tree rebuilt
//! outside `Imt`.
//!
//! The production-cell closure tests read siblings through `Imt::node` and fold with
//! `merkle_node` — an oracle that is independent of `Imt::merkle_proof` but still reads
//! the same node map, so a tree that is wrong the same way everywhere passes them.
//! The oracle here is a naive level-by-level rebuild from the raw leaf commitments,
//! sharing only the `merkle_node` primitive with production code; the pinned root
//! vector below covers that primitive drifting too. Mirror of
//! `per_list_path_independent_root_oracle.rs` for the chain-tree side.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::needless_range_loop
)]

use raven_railgun_engine::imt::TREE_DEPTH;
use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::{PerLeafPathEncoder, PirTableEncoder};
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_poseidon::{merkle_node, railgun_merkle_zero_value};

const NODE_BYTES: usize = 32;
const PATH_RECORD_BYTES: usize = TREE_DEPTH * NODE_BYTES;
const TREE_NUMBER: u32 = 3;
// Odd count, spanning two shards, so zero-sibling and cross-shard paths are exercised.
const LEAVES: u32 = 101;
const ENTRIES_PER_SHARD: u32 = 64;

/// Root of the 101-leaf tree below, computed by the naive rebuild at the time this
/// file was written. If `merkle_node`, the zero value, or the fold order drift, the
/// naive rebuild moves with them and this constant is what still fails.
const PINNED_ROOT: [u8; 32] = [
    0x18, 0xeb, 0x9c, 0x2a, 0xc7, 0x6f, 0x79, 0x06, 0xdc, 0x85, 0x54, 0xcb, 0xd0, 0x77, 0xc4, 0xe3,
    0x1c, 0x66, 0x1e, 0xee, 0xd3, 0x6b, 0xfa, 0x6d, 0x5a, 0x7b, 0x46, 0x79, 0x22, 0x93, 0x44, 0x10,
];

fn commitment_for(idx: u32) -> [u8; 32] {
    // Fr-canonical (top bytes zero), and deliberately a different byte lane than the
    // per-list oracle's fixture so the two pinned roots are independent vectors.
    let mut b = [0u8; 32];
    b[24..28].copy_from_slice(&idx.saturating_add(1).to_be_bytes());
    b
}

fn append_payload(leaf_index: u32) -> WalEntryPayload {
    WalEntryPayload::AppendLeaf {
        tree_number: TREE_NUMBER,
        leaf_index,
        commitment: commitment_for(leaf_index),
    }
}

fn zero_chain() -> [[u8; 32]; TREE_DEPTH + 1] {
    let mut z = [[0u8; 32]; TREE_DEPTH + 1];
    z[0] = railgun_merkle_zero_value();
    for level in 0..TREE_DEPTH {
        z[level + 1] = merkle_node(z[level], z[level]).expect("zero chain fold");
    }
    z
}

/// Every populated node, level by level, built bottom-up from the raw leaves.
/// Nothing incremental: no node cache, no dirty tracking, no `Imt`.
fn naive_levels(leaves: &[[u8; 32]], z: &[[u8; 32]; TREE_DEPTH + 1]) -> Vec<Vec<[u8; 32]>> {
    let mut levels = Vec::with_capacity(TREE_DEPTH + 1);
    levels.push(leaves.to_vec());
    for level in 0..TREE_DEPTH {
        let cur: &Vec<[u8; 32]> = levels.last().expect("level present");
        let mut next = Vec::with_capacity(cur.len().div_ceil(2));
        for i in 0..cur.len().div_ceil(2) {
            let left = *cur.get(2 * i).expect("left child in range");
            let right = *cur.get(2 * i + 1).unwrap_or(&z[level]);
            next.push(merkle_node(left, right).expect("naive fold"));
        }
        levels.push(next);
    }
    levels
}

fn naive_sibling(
    levels: &[Vec<[u8; 32]>],
    z: &[[u8; 32]; TREE_DEPTH + 1],
    leaf_idx: u32,
    level: usize,
) -> [u8; 32] {
    let idx = ((leaf_idx as usize) >> level) ^ 1;
    levels
        .get(level)
        .and_then(|l| l.get(idx))
        .copied()
        .unwrap_or(z[level])
}

fn build_store() -> (LogicalLeafStore, PerLeafPathEncoder) {
    let encoder = PerLeafPathEncoder::new(PATH_RECORD_BYTES, ENTRIES_PER_SHARD, TREE_NUMBER)
        .expect("per-leaf-path encoder");
    let mut store = LogicalLeafStore::new();
    for i in 0..LEAVES {
        apply_wal_entry(&mut store, &append_payload(i), 100 + u64::from(i), &encoder)
            .expect("apply chain leaf");
    }
    (store, encoder)
}

fn served_siblings(
    encoder: &PerLeafPathEncoder,
    store: &LogicalLeafStore,
    leaf_idx: u32,
) -> [[u8; 32]; TREE_DEPTH] {
    let shard_id = leaf_idx / ENTRIES_PER_SHARD;
    let row_offset = (leaf_idx % ENTRIES_PER_SHARD) as usize;
    let buf = encoder.materialize_shard(shard_id, store);
    let row_start = row_offset * PATH_RECORD_BYTES;
    let mut out = [[0u8; 32]; TREE_DEPTH];
    for (level, sib) in out.iter_mut().enumerate() {
        let s = row_start + level * NODE_BYTES;
        sib.copy_from_slice(buf.get(s..s + NODE_BYTES).expect("sibling in row"));
    }
    out
}

#[test]
fn served_rows_match_a_tree_rebuilt_outside_imt() {
    let (store, encoder) = build_store();
    let z = zero_chain();
    let leaves: Vec<[u8; 32]> = (0..LEAVES).map(commitment_for).collect();
    let levels = naive_levels(&leaves, &z);
    let naive_root = *levels
        .last()
        .and_then(|l| l.first())
        .expect("root of a non-empty tree");

    // The Imt itself against the naive rebuild: a wrong-but-self-consistent tree
    // agrees with its own `Imt::node` walk and still fails here.
    assert_eq!(
        store.imt_root(TREE_NUMBER).expect("commit-tree root"),
        naive_root,
        "Imt root diverges from the naive rebuild of the same {LEAVES} leaves"
    );

    // First, middle, both sides of the shard boundary, powers of two, last.
    for leaf_idx in [0u32, 1, 2, 31, 32, 63, 64, 65, 97, 100] {
        let served = served_siblings(&encoder, &store, leaf_idx);

        for (level, sib) in served.iter().enumerate() {
            let expected = naive_sibling(&levels, &z, leaf_idx, level);
            assert_eq!(
                *sib, expected,
                "leaf {leaf_idx} level {level}: served sibling differs from the naive tree"
            );
        }

        let mut current = commitment_for(leaf_idx);
        for (level, sib) in served.iter().enumerate() {
            current = if (leaf_idx >> level) & 1 == 1 {
                merkle_node(*sib, current).expect("fold right")
            } else {
                merkle_node(current, *sib).expect("fold left")
            };
        }
        assert_eq!(
            current, naive_root,
            "leaf {leaf_idx}: served row folds to a root the naive rebuild never produced"
        );
    }
}

#[test]
fn per_leaf_root_is_pinned_against_primitive_drift() {
    let z = zero_chain();
    let leaves: Vec<[u8; 32]> = (0..LEAVES).map(commitment_for).collect();
    let levels = naive_levels(&leaves, &z);
    let naive_root = *levels
        .last()
        .and_then(|l| l.first())
        .expect("root of a non-empty tree");
    assert_eq!(
        naive_root,
        PINNED_ROOT,
        "naive root moved off the pinned vector: merkle_node, the zero value, or the \
         fold order changed. If intentional, re-derive the pin: [{}]",
        naive_root.map(|b| format!("0x{b:02x}")).join(", ")
    );
}
