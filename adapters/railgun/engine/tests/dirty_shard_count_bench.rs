//! Indexing-math invariants for per-leaf and per-node dirty-shard computation.

#![allow(
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::indexing_slicing
)]

use std::collections::BTreeSet;

const TREE_DEPTH: u32 = 16;
const LEAVES_PER_TREE: u32 = 1 << TREE_DEPTH;

const PER_LEAF_ENTRIES_PER_SHARD: u32 = 2048;
const PER_LEAF_ROWS: u32 = LEAVES_PER_TREE;
const PER_LEAF_SHARDS: u32 = PER_LEAF_ROWS / PER_LEAF_ENTRIES_PER_SHARD;

const PER_NODE_ENTRIES_PER_SHARD: u32 = 2048;

fn per_leaf_shard_id(leaf_index: u32) -> u32 {
    leaf_index / PER_LEAF_ENTRIES_PER_SHARD
}

/// Flat global node index for (level, idx_at_level) in a depth-D IMT.
/// Level 0 = leaves; level D = root. Layout: leaves at [0, 2^D), level 1 at
/// [2^D, 2^D + 2^(D-1)), etc.
fn per_node_flat_index(level: u32, idx_at_level: u32) -> u32 {
    let total = 1u32 << (TREE_DEPTH + 1);
    let level_offset = total - (1u32 << (TREE_DEPTH + 1 - level));
    level_offset + idx_at_level
}

fn per_node_shard_id(level: u32, idx_at_level: u32) -> u32 {
    per_node_flat_index(level, idx_at_level) / PER_NODE_ENTRIES_PER_SHARD
}

fn per_leaf_dirty_shards(leaf_index: u32, current_leaf_count: u32) -> BTreeSet<u32> {
    let mut dirty: BTreeSet<u32> = BTreeSet::new();
    dirty.insert(per_leaf_shard_id(leaf_index));

    for k in 1..=TREE_DEPTH {
        let block_size = 1u32 << k;
        let block_start = (leaf_index / block_size) * block_size;
        if block_start >= current_leaf_count {
            continue;
        }
        let block_end = leaf_index.min(current_leaf_count);
        for affected_leaf in block_start..block_end {
            dirty.insert(per_leaf_shard_id(affected_leaf));
        }
        if dirty.len() as u32 >= PER_LEAF_SHARDS {
            break;
        }
    }
    dirty
}

fn per_node_dirty_shards(leaf_index: u32) -> BTreeSet<u32> {
    let mut dirty: BTreeSet<u32> = BTreeSet::new();
    let mut idx = leaf_index;
    for level in 0..=TREE_DEPTH {
        dirty.insert(per_node_shard_id(level, idx));
        idx >>= 1;
    }
    dirty
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_node_flat_index_round_trip_levels() {
        assert_eq!(per_node_flat_index(0, 0), 0);
        assert_eq!(
            per_node_flat_index(0, LEAVES_PER_TREE - 1),
            LEAVES_PER_TREE - 1
        );
        assert_eq!(per_node_flat_index(1, 0), LEAVES_PER_TREE);
        assert_eq!(
            per_node_flat_index(TREE_DEPTH, 0),
            (1u32 << (TREE_DEPTH + 1)) - 2
        );
    }

    #[test]
    fn per_node_dirty_shards_returns_at_most_tree_depth_plus_one() {
        for leaf in [0u32, 1, 42, 1024, 32768, LEAVES_PER_TREE - 1] {
            let dirty = per_node_dirty_shards(leaf);
            assert!(
                dirty.len() <= (TREE_DEPTH as usize + 1),
                "leaf={leaf} dirty.len()={} > TREE_DEPTH+1={}",
                dirty.len(),
                TREE_DEPTH + 1
            );
            assert!(!dirty.is_empty());
        }
    }

    #[test]
    fn per_leaf_dirty_shards_returns_at_most_total_shards() {
        for leaf in [0u32, 1, 42, 1024, 32768, LEAVES_PER_TREE - 1] {
            let dirty = per_leaf_dirty_shards(leaf, leaf);
            assert!(
                dirty.len() <= PER_LEAF_SHARDS as usize,
                "leaf={leaf} dirty.len()={} > total shards {}",
                dirty.len(),
                PER_LEAF_SHARDS
            );
        }
    }

    #[test]
    fn per_leaf_first_insert_dirties_one_shard() {
        let dirty = per_leaf_dirty_shards(0, 0);
        assert_eq!(
            dirty.len(),
            1,
            "first insert (no prior leaves) dirties exactly 1 shard"
        );
    }
}
