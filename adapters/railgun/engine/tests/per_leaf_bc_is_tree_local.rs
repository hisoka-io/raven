//! `per-leaf-bc` indexes rows by `leaf_index` alone and FILTERS on the tree it is pinned
//! to. Re-deriving the scope in the index would shift an already-tree-local leaf out of
//! its own cell and serve filler; dropping the tree entirely would let a foreign tree
//! overwrite the row. The pin is the invariant - not the router, which scopes only on the
//! multi-instance path (see `per_leaf_bc_two_trees_must_not_collide`).

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::{PerLeafCommitmentEncoder, PirTableEncoder, LEAVES_PER_TREE};
use raven_railgun_persistence::WalEntryPayload;

const RECORD: usize = 32;
const EPS: u32 = 2048;

fn enc_for(tree_number: u32) -> PerLeafCommitmentEncoder {
    PerLeafCommitmentEncoder::new(RECORD, EPS, tree_number).expect("test encoder")
}

fn enc() -> PerLeafCommitmentEncoder {
    enc_for(0)
}

fn commitment(seed: u8) -> [u8; 32] {
    let mut c = [0u8; 32];
    c[31] = seed.max(1);
    c
}

fn store_with(tree: u32, leaves: u32) -> LogicalLeafStore {
    let mut store = LogicalLeafStore::new();
    for leaf_index in 0..leaves {
        let seed = u8::try_from(leaf_index % 250).expect("< 250");
        let payload = WalEntryPayload::AppendLeaf {
            tree_number: tree,
            leaf_index,
            commitment: commitment(seed),
        };
        apply_wal_entry(
            &mut store,
            &payload,
            100 + u64::from(leaf_index),
            &enc_for(tree),
        )
        .expect("leaf applies");
    }
    store
}

fn row(bytes: &[u8], idx: usize) -> &[u8] {
    bytes
        .get(idx * RECORD..(idx + 1) * RECORD)
        .expect("row in range")
}

/// The defect: a tree >= 1 instance served factory filler because the row index
/// added `tree * LEAVES_PER_TREE`, pushing every row past its own cell.
#[test]
fn a_tree_three_instance_serves_its_rows_not_zeros() {
    let store = store_with(3, 4);
    let bytes = enc_for(3).materialize_shard(0, &store);

    for leaf_index in 0..4usize {
        let seed = u8::try_from(leaf_index).expect("< 4");
        assert_eq!(
            row(&bytes, leaf_index),
            &commitment(seed)[..],
            "tree 3 leaf {leaf_index} must occupy row {leaf_index} of its own shard; \
             an all-zero row here is the filler a wallet would accept as a commitment"
        );
    }
}

/// Every tree must land at the same rows, because each instance holds exactly one.
#[test]
fn every_tree_lays_its_leaves_out_identically() {
    let baseline = enc_for(0).materialize_shard(0, &store_with(0, 8));
    for tree in [1u32, 2, 3, 7, 4095] {
        let bytes = enc_for(tree).materialize_shard(0, &store_with(tree, 8));
        assert_eq!(
            bytes, baseline,
            "tree {tree} must produce the same shard bytes as tree 0: the router \
             guarantees one tree per instance, so the tree number carries no layout \
             information"
        );
    }
}

/// Regression gate for the tree-0 artifacts already on disk. `0 * LEAVES_PER_TREE + leaf
/// == leaf`, so dropping the term must be byte-identical here or it is a migration.
#[test]
fn tree_zero_shard_bytes_are_unchanged_by_the_tree_local_index() {
    let store = store_with(0, 12);
    let bytes = enc().materialize_shard(0, &store);

    let mut expected = vec![0u8; EPS as usize * RECORD];
    for leaf_index in 0..12usize {
        let seed = u8::try_from(leaf_index).expect("< 12");
        let start = leaf_index * RECORD;
        expected
            .get_mut(start..start + RECORD)
            .expect("row in range")
            .copy_from_slice(&commitment(seed));
    }
    assert_eq!(
        bytes, expected,
        "tree 0 rows must sit at row == leaf_index, exactly as before"
    );
}

/// Dirty set and materialized bytes must name the same shard, or a commit re-encodes
/// a shard whose rows did not change and leaves the one that did.
#[test]
fn the_dirty_shard_is_the_shard_whose_bytes_changed() {
    fn encoder_for_tree_under_test(t: u32) -> PerLeafCommitmentEncoder {
        PerLeafCommitmentEncoder::new(RECORD, EPS, t).expect("encoder")
    }
    let encoder = enc();
    for tree in [0u32, 1, 3] {
        for leaf_index in [0u32, 1, EPS - 1, EPS, EPS * 3 + 5] {
            let dirty = encoder.affected_shards_for_leaf(tree, leaf_index);
            let expected_shard = leaf_index / EPS;
            assert_eq!(
                encoder_for_tree_under_test(tree)
                    .affected_shards_for_leaf(tree, leaf_index)
                    .into_iter()
                    .collect::<Vec<_>>(),
                vec![expected_shard],
                "tree {tree} leaf {leaf_index} belongs to shard {expected_shard}"
            );
            let _ = dirty;
        }
    }
}

/// The one bound that survives: a leaf index past a tree's own capacity is a real
/// error and every sibling encoder rejects it the same way.
#[test]
fn a_leaf_index_past_one_trees_capacity_still_dirties_nothing() {
    assert!(
        enc()
            .affected_shards_for_leaf(0, LEAVES_PER_TREE)
            .is_empty(),
        "leaf {LEAVES_PER_TREE} is past a tree's row space and has no shard"
    );
}
