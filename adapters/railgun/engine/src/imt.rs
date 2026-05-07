//! Incremental Merkle tree matching Railgun's commitment-tree shape.
//! `TREE_DEPTH = 16`, Poseidon-hashed nodes, zero value = `keccak256("Railgun") mod SNARK_PRIME`.
//! Used for Layer 2 reorg detection and PIR Merkle-path table construction.

// Indexing into statically-sized [TREE_DEPTH+1] / [TREE_DEPTH] arrays is safe by construction.
#![allow(clippy::indexing_slicing, clippy::needless_range_loop)]

use std::collections::HashMap;

use raven_railgun_core::{AdapterError, MerkleProof, Result};
use raven_railgun_poseidon::{merkle_node, railgun_merkle_zero_value};

/// Tree depth in levels.
pub const TREE_DEPTH: usize = 16;

/// Maximum leaves per tree (`2 ^ TREE_DEPTH = 65,536`).
pub const TREE_MAX_ITEMS: usize = 1 << TREE_DEPTH;

#[derive(Clone, Debug)]
struct ZeroValues {
    /// `ZEROS[0..=TREE_DEPTH]`: empty-subtree hash per level.
    levels: [[u8; 32]; TREE_DEPTH + 1],
}

impl ZeroValues {
    fn new() -> Result<Self> {
        let mut levels = [[0u8; 32]; TREE_DEPTH + 1];
        levels[0] = railgun_merkle_zero_value();
        for level in 1..=TREE_DEPTH {
            let prev = levels[level - 1];
            levels[level] = merkle_node(prev, prev).map_err(|e| {
                AdapterError::Internal(format!("imt zero-value level {level}: {e}"))
            })?;
        }
        Ok(Self { levels })
    }
}

/// Sparse incremental Merkle tree backing one Railgun commitment-tree.
#[derive(Clone, Debug)]
pub struct Imt {
    leaf_count: usize,
    nodes: Vec<HashMap<usize, [u8; 32]>>,
    zeros: ZeroValues,
}

impl Imt {
    /// Build an empty tree of depth [`TREE_DEPTH`].
    ///
    /// # Errors
    /// Returns [`AdapterError::Internal`] if the zero-cache Poseidon hash fails.
    pub fn new() -> Result<Self> {
        let zeros = ZeroValues::new()?;
        let nodes = (0..=TREE_DEPTH).map(|_| HashMap::new()).collect();
        Ok(Self {
            leaf_count: 0,
            nodes,
            zeros,
        })
    }

    /// Number of leaves currently inserted.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Returns the root hash at level [`TREE_DEPTH`].
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        self.node_hash(TREE_DEPTH, 0)
    }

    fn node_hash(&self, level: usize, index: usize) -> [u8; 32] {
        debug_assert!(level <= TREE_DEPTH);
        self.nodes
            .get(level)
            .and_then(|m| m.get(&index).copied())
            .unwrap_or(self.zeros.levels[level])
    }

    /// Merkle node hash at `(level, index_at_level)`. Empty positions return the zero hash.
    #[must_use]
    pub fn node(&self, level: usize, index_at_level: usize) -> [u8; 32] {
        self.node_hash(level, index_at_level)
    }

    /// Append `leaves` starting at `start_index`. Must equal `leaf_count`.
    ///
    /// # Errors
    /// Returns [`AdapterError::InvalidQuery`] on non-contiguous insert or capacity overflow.
    pub fn insert_leaves(&mut self, start_index: usize, leaves: &[[u8; 32]]) -> Result<()> {
        if start_index != self.leaf_count {
            return Err(AdapterError::InvalidQuery(format!(
                "IMT insert_leaves: non-contiguous start_index {start_index} (expected {})",
                self.leaf_count
            )));
        }
        let end = start_index
            .checked_add(leaves.len())
            .ok_or_else(|| AdapterError::InvalidQuery("IMT insert_leaves overflow".into()))?;
        if end > TREE_MAX_ITEMS {
            return Err(AdapterError::InvalidQuery(format!(
                "IMT insert_leaves: end {end} exceeds capacity {TREE_MAX_ITEMS}"
            )));
        }

        // Clone-and-swap for atomicity: a mid-batch Poseidon failure must not corrupt self.
        let mut staged = self.clone();
        for (offset, leaf) in leaves.iter().enumerate() {
            let leaf_index = start_index + offset;
            staged.set_leaf_and_update_path(leaf_index, *leaf)?;
        }
        staged.leaf_count = end;
        *self = staged;
        Ok(())
    }

    fn set_leaf_and_update_path(&mut self, leaf_index: usize, leaf: [u8; 32]) -> Result<()> {
        self.nodes[0].insert(leaf_index, leaf);

        let mut current_index = leaf_index;
        for level in 1..=TREE_DEPTH {
            let parent_index = current_index >> 1;
            let left_index = parent_index << 1;
            let right_index = left_index + 1;
            let left = self.node_hash(level - 1, left_index);
            let right = self.node_hash(level - 1, right_index);
            let parent_hash = merkle_node(left, right).map_err(|e| {
                AdapterError::Internal(format!(
                    "imt parent hash level {level} idx {parent_index}: {e}"
                ))
            })?;
            self.nodes[level].insert(parent_index, parent_hash);
            current_index = parent_index;
        }
        Ok(())
    }

    /// Drop all leaves at `index >= new_count`. No-op if `new_count >= leaf_count`.
    pub fn truncate_to(&mut self, new_count: usize) {
        if new_count >= self.leaf_count {
            return;
        }

        for index in new_count..self.leaf_count {
            self.nodes[0].remove(&index);
        }

        for level in 1..=TREE_DEPTH {
            let level_map = &mut self.nodes[level];
            level_map.retain(|&node_index, _hash| {
                let subtree_start = node_index << level;
                subtree_start < new_count
            });
        }

        self.leaf_count = new_count;

        if new_count > 0 {
            let rightmost = new_count - 1;
            let leaf = self.node_hash(0, rightmost);
            if let Err(e) = self.set_leaf_and_update_path(rightmost, leaf) {
                tracing::error!(
                    error = %e,
                    new_count,
                    "imt truncate rehash failed; tree internal nodes may be stale until next insert"
                );
            }
        } else {
            for level in 1..=TREE_DEPTH {
                self.nodes[level].clear();
            }
        }
    }

    /// Return the 16-sibling Merkle proof for the leaf at `leaf_index`.
    ///
    /// # Errors
    /// Returns [`AdapterError::InvalidQuery`] if `leaf_index >= leaf_count`.
    pub fn merkle_proof(&self, leaf_index: usize) -> Result<MerkleProof> {
        if leaf_index >= self.leaf_count {
            return Err(AdapterError::InvalidQuery(format!(
                "IMT merkle_proof: leaf_index {leaf_index} not populated (leaf_count = {})",
                self.leaf_count
            )));
        }

        let mut elements = [[0u8; 32]; TREE_DEPTH];
        for level in 0..TREE_DEPTH {
            let sibling_index = (leaf_index >> level) ^ 1;
            elements[level] = self.node_hash(level, sibling_index);
        }

        // `indices` bit i = (leaf_index >> i) & 1; 16 bits fit in u16.
        let truncated = leaf_index & ((1 << TREE_DEPTH) - 1);
        #[allow(clippy::cast_possible_truncation)]
        let indices = truncated as u16;

        Ok(MerkleProof {
            root: self.root(),
            indices,
            elements,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn merkle_zero_value_matches_railgun_constant() {
        let v = railgun_merkle_zero_value();
        // Verified against the Railgun TS reference via circomlibjs Poseidon.
        let expected_hex = "0488f89b25bc7011eaf6a5edce71aeafb9fe706faa3c0a5cd9cbe868ae3b9ffc";
        let actual_hex = hex_encode(&v);
        assert_eq!(
            actual_hex, expected_hex,
            "MERKLE_ZERO_VALUE drift: expected {expected_hex}, got {actual_hex}"
        );
    }

    fn hex_encode(bytes: &[u8]) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    #[test]
    fn empty_tree_root_equals_zero_at_depth() {
        let tree = Imt::new().expect("imt build");
        let zeros = ZeroValues::new().expect("zeros");
        assert_eq!(tree.root(), zeros.levels[TREE_DEPTH]);
    }

    #[test]
    fn insert_then_proof_round_trips() {
        let mut tree = Imt::new().expect("imt build");
        let mut leaves = vec![];
        for i in 0..8u8 {
            leaves.push([i; 32]);
        }
        tree.insert_leaves(0, &leaves).expect("insert");
        assert_eq!(tree.leaf_count(), 8);

        let root = tree.root();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.merkle_proof(i).expect("proof");
            assert_eq!(proof.root, root, "leaf {i}");
            assert_eq!(reconstruct_root(*leaf, i, &proof), root, "leaf {i}");
            assert_eq!(usize::from(proof.indices), i);
        }
    }

    fn reconstruct_root(leaf: [u8; 32], leaf_index: usize, proof: &MerkleProof) -> [u8; 32] {
        let mut current = leaf;
        for level in 0..TREE_DEPTH {
            let bit = (leaf_index >> level) & 1;
            let sibling = proof.elements[level];
            current = if bit == 1 {
                merkle_node(sibling, current).expect("hash")
            } else {
                merkle_node(current, sibling).expect("hash")
            };
        }
        current
    }

    #[test]
    fn merkle_proof_indices_per_bit_semantic_matches_docstring() {
        let mut tree = Imt::new().expect("imt build");
        let leaves: Vec<[u8; 32]> = (0..16u8).map(|i| [i; 32]).collect();
        tree.insert_leaves(0, &leaves).expect("seed");
        for k in 0usize..16 {
            let proof = tree.merkle_proof(k).expect("proof");
            for level in 0..TREE_DEPTH {
                let expected_bit = (k >> level) & 1;
                let actual_bit = usize::from((proof.indices >> level) & 1);
                assert_eq!(
                    actual_bit, expected_bit,
                    "indices bit {level} for leaf {k}: docstring says \
                     (leaf_index >> level) & 1 = {expected_bit}, got {actual_bit}"
                );
            }
        }
    }

    #[test]
    fn truncate_to_k_equals_fresh_insert_of_first_k() {
        // Leaves are big-endian u32 zero-padded to 32 bytes — below BN254 Fr prime.
        let leaves: Vec<[u8; 32]> = (0..12u32)
            .map(|i| {
                let mut b = [0u8; 32];
                if let Some(dst) = b.get_mut(28..) {
                    dst.copy_from_slice(&(i + 1).to_be_bytes());
                }
                b
            })
            .collect();
        for k in 0..=leaves.len() {
            let mut truncated = Imt::new().expect("imt build");
            truncated.insert_leaves(0, &leaves).expect("seed L");
            truncated.truncate_to(k);

            let mut fresh = Imt::new().expect("imt build");
            if k > 0 {
                let prefix = leaves.get(..k).expect("prefix in range");
                fresh.insert_leaves(0, prefix).expect("seed K");
            }

            assert_eq!(
                truncated.leaf_count(),
                fresh.leaf_count(),
                "leaf_count mismatch at K={k}"
            );
            assert_eq!(truncated.root(), fresh.root(), "root mismatch at K={k}");
            for j in 0..k {
                let p_trunc = truncated.merkle_proof(j).expect("trunc proof");
                let p_fresh = fresh.merkle_proof(j).expect("fresh proof");
                assert_eq!(p_trunc, p_fresh, "proof mismatch at K={k}, leaf={j}");
            }
        }
    }

    /// Regression: mid-batch Poseidon failure must leave tree unchanged.
    #[test]
    fn insert_leaves_is_atomic_on_mid_batch_poseidon_failure() {
        let valid: [u8; 32] = {
            let mut b = [0u8; 32];
            b[31] = 0x07;
            b
        };
        // 0xff...ff exceeds BN254 scalar prime — Poseidon refuses.
        let invalid: [u8; 32] = [0xff; 32];

        let mut tree = Imt::new().expect("imt build");
        let pre_count = tree.leaf_count();
        let pre_root = tree.root();

        let err = tree
            .insert_leaves(0, &[valid, invalid])
            .expect_err("non-Fr-canonical input must fail Poseidon");
        match err {
            AdapterError::Internal(_) | AdapterError::InvalidQuery(_) => {}
            other => panic!("unexpected error variant: {other:?}"),
        }

        assert_eq!(tree.leaf_count(), pre_count, "leaf_count must be unchanged");
        assert_eq!(
            tree.root(),
            pre_root,
            "root must be unchanged (still empty)"
        );

        tree.insert_leaves(0, &[valid])
            .expect("clean insert after rollback");
        assert_eq!(tree.leaf_count(), 1);
    }

    #[test]
    fn insert_rejects_non_contiguous_start_index() {
        let mut tree = Imt::new().expect("imt build");
        tree.insert_leaves(0, &[[1u8; 32]]).expect("seed");
        let err = tree
            .insert_leaves(5, &[[2u8; 32]])
            .expect_err("non-contiguous must fail");
        assert!(matches!(err, AdapterError::InvalidQuery(_)), "err={err:?}");
    }

    #[test]
    #[ignore = "fills full 65,536-leaf tree; ~1M Poseidon hashes; release-only"]
    fn insert_rejects_overflow_past_capacity() {
        let mut tree = Imt::new().expect("imt build");
        let leaves: Vec<[u8; 32]> = (0..TREE_MAX_ITEMS)
            .map(|i| {
                let mut buf = [0u8; 32];
                buf[..8].copy_from_slice(&u64::try_from(i).unwrap().to_be_bytes());
                buf
            })
            .collect();
        tree.insert_leaves(0, &leaves).expect("fill");
        let err = tree
            .insert_leaves(TREE_MAX_ITEMS, &[[0u8; 32]])
            .expect_err("past cap must fail");
        assert!(matches!(err, AdapterError::InvalidQuery(_)), "err={err:?}");
    }

    #[test]
    fn truncate_drops_leaves_past_threshold() {
        let mut tree = Imt::new().expect("imt build");
        let leaves: Vec<[u8; 32]> = (0..10u8).map(|i| [i; 32]).collect();
        tree.insert_leaves(0, &leaves).expect("seed");
        let pre_root = tree.root();

        tree.truncate_to(5);
        assert_eq!(tree.leaf_count(), 5);

        // Proofs for leaves 0..5 still reconstruct the new root.
        let new_root = tree.root();
        assert_ne!(pre_root, new_root, "truncate must change root");
        for i in 0..5 {
            let proof = tree.merkle_proof(i).expect("proof");
            assert_eq!(
                reconstruct_root([u8::try_from(i).unwrap(); 32], i, &proof),
                new_root
            );
        }

        // Proof for a dropped leaf must error.
        let err = tree.merkle_proof(5).expect_err("dropped");
        assert!(matches!(err, AdapterError::InvalidQuery(_)), "err={err:?}");
    }

    #[test]
    fn truncate_to_zero_yields_empty_root() {
        let mut tree = Imt::new().expect("imt build");
        tree.insert_leaves(0, &[[7u8; 32], [8u8; 32]])
            .expect("seed");
        tree.truncate_to(0);
        assert_eq!(tree.leaf_count(), 0);
        let zeros = ZeroValues::new().expect("zeros");
        assert_eq!(tree.root(), zeros.levels[TREE_DEPTH]);
    }

    #[test]
    fn truncate_no_op_when_new_count_at_or_above_current() {
        let mut tree = Imt::new().expect("imt build");
        tree.insert_leaves(0, &[[1u8; 32], [2u8; 32]])
            .expect("seed");
        let pre_root = tree.root();
        tree.truncate_to(5);
        assert_eq!(tree.leaf_count(), 2);
        assert_eq!(tree.root(), pre_root);
    }

    #[test]
    fn proofs_after_post_truncate_insert_round_trip() {
        let mut tree = Imt::new().expect("imt build");
        tree.insert_leaves(0, &[[1u8; 32], [2u8; 32], [3u8; 32]])
            .expect("seed");
        tree.truncate_to(2);
        tree.insert_leaves(2, &[[42u8; 32]]).expect("re-insert");
        let proof = tree.merkle_proof(2).expect("proof");
        assert_eq!(reconstruct_root([42u8; 32], 2, &proof), tree.root());
    }
}
