//! The Railgun IMT rebuilt from raw leaves, sharing only `merkle_node` with production code.
//!
//! An `Imt` that is wrong the same way everywhere agrees with its own encoders and its own
//! proofs. This rebuild is the oracle that still fails.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_range_loop
)]

use raven_railgun_engine::imt::TREE_DEPTH;
use raven_railgun_poseidon::{merkle_node, railgun_merkle_zero_value};

/// Empty-subtree hash per level, indexed `0..=TREE_DEPTH`.
pub fn zero_chain() -> [[u8; 32]; TREE_DEPTH + 1] {
    let mut z = [[0u8; 32]; TREE_DEPTH + 1];
    z[0] = railgun_merkle_zero_value();
    for level in 0..TREE_DEPTH {
        z[level + 1] = merkle_node(z[level], z[level]).expect("zero chain fold");
    }
    z
}

/// Every populated node, level by level, bottom-up. No node cache, no dirty tracking, no `Imt`.
pub fn naive_levels(leaves: &[[u8; 32]], z: &[[u8; 32]; TREE_DEPTH + 1]) -> Vec<Vec<[u8; 32]>> {
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

/// Root at level [`TREE_DEPTH`] of a rebuild produced by [`naive_levels`].
pub fn naive_root(levels: &[Vec<[u8; 32]>]) -> [u8; 32] {
    *levels
        .last()
        .and_then(|l| l.first())
        .expect("root of a non-empty rebuild")
}

/// Sibling of `leaf_idx`'s ancestor at `level`.
pub fn naive_sibling(
    levels: &[Vec<[u8; 32]>],
    z: &[[u8; 32]; TREE_DEPTH + 1],
    leaf_idx: usize,
    level: usize,
) -> [u8; 32] {
    let idx = (leaf_idx >> level) ^ 1;
    levels
        .get(level)
        .and_then(|l| l.get(idx))
        .copied()
        .unwrap_or(z[level])
}
