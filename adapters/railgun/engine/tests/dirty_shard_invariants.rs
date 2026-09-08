//! Indexing-math invariants for per-leaf and per-node dirty-shard computation,
//! asserted against the shipped encoders. A local re-implementation of the walk
//! would make every assertion here true of the copy and blind to the encoder.

#![allow(clippy::expect_used)]

use std::collections::BTreeSet;

use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::{
    PerLeafPathEncoder, PerNodeEncoder, PirTableEncoder, LEAVES_PER_TREE, PATH_RECORD_BYTES,
    PER_NODE_TOTAL_NODES,
};
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_testkit::canonical;

const TREE_DEPTH: u32 = 16;
const TREE: u32 = 0;
const ENTRIES_PER_SHARD: u32 = 2048;
const PER_LEAF_SHARDS: u32 = LEAVES_PER_TREE / ENTRIES_PER_SHARD;
const PER_NODE_SHARDS: u32 = PER_NODE_TOTAL_NODES.div_ceil(ENTRIES_PER_SHARD);

fn per_node_encoder() -> PerNodeEncoder {
    PerNodeEncoder::new(ENTRIES_PER_SHARD, TREE).expect("per-node encoder")
}

fn per_leaf_path_encoder() -> PerLeafPathEncoder {
    PerLeafPathEncoder::new(PATH_RECORD_BYTES, ENTRIES_PER_SHARD, TREE).expect("path encoder")
}

fn append(store: &mut LogicalLeafStore, encoder: &dyn PirTableEncoder, leaf_index: u32) {
    let payload = WalEntryPayload::AppendLeaf {
        tree_number: TREE,
        leaf_index,
        commitment: canonical(
            u8::try_from(leaf_index % 250)
                .unwrap_or(0)
                .saturating_add(1),
        ),
    };
    apply_wal_entry(store, &payload, 100 + u64::from(leaf_index), encoder).expect("leaf applies");
}

/// Concrete in the encoder so the shard count and the encoder cannot drift apart: the
/// per-leaf cell allocates half as many shards, and a `&dyn` parameter here would let a
/// caller materialize shards the per-leaf cell never allocated.
fn per_node_shard_bytes(encoder: &PerNodeEncoder, store: &LogicalLeafStore) -> Vec<Vec<u8>> {
    (0..PER_NODE_SHARDS)
        .map(|shard| encoder.materialize_shard(shard, store))
        .collect()
}

#[test]
fn per_node_flat_index_round_trip_levels() {
    assert_eq!(PerNodeEncoder::flat_index(0, 0), 0);
    assert_eq!(
        PerNodeEncoder::flat_index(0, LEAVES_PER_TREE - 1),
        LEAVES_PER_TREE - 1
    );
    assert_eq!(PerNodeEncoder::flat_index(1, 0), LEAVES_PER_TREE);
    assert_eq!(
        PerNodeEncoder::flat_index(TREE_DEPTH, 0),
        (1u32 << (TREE_DEPTH + 1)) - 2
    );
}

#[test]
fn per_node_dirty_shards_returns_at_most_tree_depth_plus_one() {
    let encoder = per_node_encoder();
    for leaf in [0u32, 1, 42, 1024, 32768, LEAVES_PER_TREE - 1] {
        let dirty = encoder.affected_shards_for_leaf(TREE, leaf);
        assert!(
            dirty.len() <= (TREE_DEPTH as usize + 1),
            "leaf={leaf} dirty.len()={} > TREE_DEPTH+1={}",
            dirty.len(),
            TREE_DEPTH + 1
        );
        assert!(
            !dirty.is_empty(),
            "leaf={leaf} dirtied nothing, so its commit re-encodes no shard"
        );
        assert!(
            dirty.iter().all(|s| *s < PER_NODE_SHARDS),
            "leaf={leaf} named a shard past the allocated cell: {dirty:?}"
        );
    }
}

/// The upper bound above is satisfied by an encoder that under-reports. Under-reporting
/// is the silent direction: the shard keeps its pre-insert bytes and every later query
/// against it returns stale nodes with no error anywhere.
#[test]
fn per_node_dirty_set_covers_every_shard_whose_bytes_changed() {
    let encoder = per_node_encoder();
    let mut store = LogicalLeafStore::new();
    for leaf in 0..8u32 {
        append(&mut store, &encoder, leaf);
    }

    let before = per_node_shard_bytes(&encoder, &store);
    append(&mut store, &encoder, 8);
    let after = per_node_shard_bytes(&encoder, &store);

    let changed: BTreeSet<u32> = before
        .iter()
        .zip(after.iter())
        .enumerate()
        .filter(|(_, (b, a))| b != a)
        .map(|(i, _)| u32::try_from(i).expect("shard id fits u32"))
        .collect();
    let dirty = encoder.affected_shards_for_leaf(TREE, 8);

    assert!(
        !changed.is_empty(),
        "premise: appending leaf 8 must change some shard's bytes"
    );
    assert!(
        changed.is_subset(&dirty),
        "shards {:?} changed bytes but were never marked dirty; a commit leaves them \
         serving pre-insert nodes",
        changed.difference(&dirty).collect::<Vec<_>>()
    );
    assert_eq!(
        dirty, changed,
        "dirty set and changed-byte set must be the same shards"
    );
}

#[test]
fn per_leaf_path_dirty_shards_returns_at_most_total_shards() {
    let encoder = per_leaf_path_encoder();
    for leaf in [0u32, 1, 42, 1024, 32768, LEAVES_PER_TREE - 1] {
        let dirty = encoder.affected_shards_for_leaf(TREE, leaf);
        assert!(
            dirty.len() <= PER_LEAF_SHARDS as usize,
            "leaf={leaf} dirty.len()={} > total shards {PER_LEAF_SHARDS}",
            dirty.len()
        );
        assert!(
            dirty.contains(&(leaf / ENTRIES_PER_SHARD)),
            "leaf={leaf} must at minimum dirty the shard holding its own row"
        );
    }
}

#[test]
fn per_leaf_path_first_insert_dirties_one_shard() {
    let dirty = per_leaf_path_encoder().affected_shards_for_leaf(TREE, 0);
    assert_eq!(
        dirty.into_iter().collect::<Vec<_>>(),
        vec![0],
        "first insert (no prior leaves) dirties exactly shard 0"
    );
}
