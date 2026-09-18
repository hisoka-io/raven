#![allow(clippy::expect_used, clippy::panic)]

const LEAVES: u32 = 65_536;
const ROWS_PER_SHARD: u32 = 2_048;
const TREE_DEPTH: u32 = 16;

fn materialize_diff_shards(inserted: u32, highest_stored_level: u32) -> u32 {
    let mut shards = 1u32 << (inserted / ROWS_PER_SHARD);
    for level in 0..=highest_stored_level {
        let subtree_size = 1u32 << level;
        let sibling_start = (((inserted >> level) ^ 1) << level).min(LEAVES);
        if sibling_start < inserted {
            let sibling_end = sibling_start
                .saturating_add(subtree_size - 1)
                .min(inserted - 1);
            for shard in sibling_start / ROWS_PER_SHARD..=sibling_end / ROWS_PER_SHARD {
                shards |= 1u32 << shard;
            }
        }
    }
    shards
}

fn interval_walk_shards(inserted: u32, highest_stored_level: u32) -> u32 {
    let mut shards = 1u32 << (inserted / ROWS_PER_SHARD);
    for shift in 1..=highest_stored_level + 1 {
        let block_size = 1u32 << shift;
        let block_start = (inserted / block_size) * block_size;
        if block_start != inserted {
            let first = block_start / ROWS_PER_SHARD;
            let last = (inserted - 1) / ROWS_PER_SHARD;
            for shard in first..=last {
                shards |= 1u32 << shard;
            }
        }
    }
    shards
}

fn planted_truncated_walk(inserted: u32, highest_stored_level: u32) -> u32 {
    let mut shards = 1u32 << (inserted / ROWS_PER_SHARD);
    for shift in 1..=highest_stored_level {
        let block_size = 1u32 << shift;
        let block_start = (inserted / block_size) * block_size;
        if block_start != inserted {
            let first = block_start / ROWS_PER_SHARD;
            let last = (inserted - 1) / ROWS_PER_SHARD;
            for shard in first..=last {
                shards |= 1u32 << shard;
            }
        }
    }
    shards
}

#[test]
fn every_insert_and_level_cut_matches_the_materialized_diff() {
    for highest_stored_level in 0..TREE_DEPTH {
        for inserted in 0..LEAVES {
            assert_eq!(
                interval_walk_shards(inserted, highest_stored_level),
                materialize_diff_shards(inserted, highest_stored_level),
                "inserted={inserted} highest_stored_level={highest_stored_level}"
            );
        }
    }
}

#[test]
fn planted_one_short_walk_is_detected_at_the_shard_boundary() {
    let inserted = ROWS_PER_SHARD;
    let highest_stored_level = 11;
    assert_ne!(
        planted_truncated_walk(inserted, highest_stored_level),
        materialize_diff_shards(inserted, highest_stored_level)
    );
}
