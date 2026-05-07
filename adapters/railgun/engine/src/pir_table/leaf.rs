//! Chain-tree encoders: PerLeafCommitment, PerLeafPath, PerNode.

use std::collections::BTreeSet;

use raven_railgun_core::{AdapterError, Result};

use super::{
    labels, PirTableEncoder, LEAVES_PER_TREE, MIN_RECORD_SIZE, NODE_HASH_BYTES, PATH_RECORD_BYTES,
    PER_NODE_TOTAL_NODES,
};
use crate::imt::TREE_DEPTH;
use crate::inspire::{materialize_shard_bytes, LogicalLeafStore};

/// T1 BC-membership encoder: row = raw 32 B blinded commitment, padded
/// with zeros up to `record_size`.
#[derive(Debug, Clone)]
pub struct PerLeafCommitmentEncoder {
    record_size: usize,
    entries_per_shard: u32,
}

impl PerLeafCommitmentEncoder {
    /// Validate cell shape + return an encoder. `record_size` must be
    /// `>= 32` (BN254 commitment width); `entries_per_shard` must be
    /// non-zero.
    pub fn new(record_size: usize, entries_per_shard: u32) -> Result<Self> {
        if record_size < MIN_RECORD_SIZE {
            return Err(AdapterError::InvalidQuery(format!(
                "PerLeafCommitmentEncoder: record_size {record_size} must be >= {MIN_RECORD_SIZE}"
            )));
        }
        if entries_per_shard == 0 {
            return Err(AdapterError::InvalidQuery(
                "PerLeafCommitmentEncoder: entries_per_shard must be > 0".to_string(),
            ));
        }
        Ok(Self {
            record_size,
            entries_per_shard,
        })
    }
}

impl PirTableEncoder for PerLeafCommitmentEncoder {
    fn record_size(&self) -> usize {
        self.record_size
    }

    fn entries_per_shard(&self) -> u32 {
        self.entries_per_shard
    }

    fn materialize_shard(&self, shard_id: u32, store: &LogicalLeafStore) -> Vec<u8> {
        materialize_shard_bytes(store, shard_id, self.entries_per_shard, self.record_size)
    }

    fn affected_shards_for_leaf(&self, tree: u32, leaf_index: u32) -> BTreeSet<u32> {
        let global = u64::from(tree) * u64::from(LEAVES_PER_TREE) + u64::from(leaf_index);
        let shard = (global / u64::from(self.entries_per_shard))
            .try_into()
            .unwrap_or(u32::MAX);
        let mut out = BTreeSet::new();
        out.insert(shard);
        out
    }

    fn label(&self) -> &'static str {
        labels::PER_LEAF_BC
    }
}

/// Backward-compat alias from the prior trait surface.
pub type PerLeafEncoder = PerLeafCommitmentEncoder;

/// T2/T3 path encoder: row `idx` = 16 sibling hashes packed leaf-to-root
/// (`PATH_RECORD_BYTES = 16 × 32 = 512` bytes), one row per leaf.
///
/// Row layout matches the `bincode::serialize(&[[u8;32]; 16])` shape
/// from the locked T1/T2/T3 encoding spec — fixed-length byte array,
/// no headers, no length prefix.
///
/// Inserting leaf X invalidates the stored path of every prior leaf
/// sharing an ancestor with X; `affected_shards_for_leaf` returns the
/// full set of shard ids whose rows need re-encoding.
#[derive(Debug, Clone)]
pub struct PerLeafPathEncoder {
    record_size: usize,
    entries_per_shard: u32,
    tree_number: u32,
}

impl PerLeafPathEncoder {
    /// Build a path encoder pinned to `tree_number`. `record_size` must
    /// be exactly 512 B (16 siblings × 32 B); `entries_per_shard` must
    /// be non-zero.
    pub fn new(record_size: usize, entries_per_shard: u32, tree_number: u32) -> Result<Self> {
        if record_size != PATH_RECORD_BYTES {
            return Err(AdapterError::InvalidQuery(format!(
                "PerLeafPathEncoder: record_size {record_size} must be exactly {PATH_RECORD_BYTES}"
            )));
        }
        if entries_per_shard == 0 {
            return Err(AdapterError::InvalidQuery(
                "PerLeafPathEncoder: entries_per_shard must be > 0".to_string(),
            ));
        }
        Ok(Self {
            record_size,
            entries_per_shard,
            tree_number,
        })
    }
}

impl PirTableEncoder for PerLeafPathEncoder {
    fn record_size(&self) -> usize {
        self.record_size
    }

    fn entries_per_shard(&self) -> u32 {
        self.entries_per_shard
    }

    fn materialize_shard(&self, shard_id: u32, store: &LogicalLeafStore) -> Vec<u8> {
        let eps = self.entries_per_shard as usize;
        let mut buf = vec![0u8; eps.saturating_mul(self.record_size)];
        let Some(imt) = store.imt(self.tree_number) else {
            return buf;
        };
        let leaf_count = imt.leaf_count();
        let row_start = (shard_id as usize).saturating_mul(eps);
        for row_offset in 0..eps {
            let leaf_idx = row_start + row_offset;
            if leaf_idx >= leaf_count {
                break;
            }
            let Ok(proof) = imt.merkle_proof(leaf_idx) else {
                continue;
            };
            let row_byte_start = row_offset * self.record_size;
            for (sib_idx, sibling) in proof.elements.iter().enumerate() {
                let sib_byte_start = row_byte_start + sib_idx * NODE_HASH_BYTES;
                let sib_byte_end = sib_byte_start + NODE_HASH_BYTES;
                if let Some(dst) = buf.get_mut(sib_byte_start..sib_byte_end) {
                    dst.copy_from_slice(sibling);
                }
            }
        }
        buf
    }

    fn affected_shards_for_leaf(&self, tree: u32, leaf_index: u32) -> BTreeSet<u32> {
        let mut dirty = BTreeSet::new();
        if tree != self.tree_number {
            tracing::warn!(
                target = "raven::pir_table",
                encoder = "per-leaf-path",
                encoder_tree = self.tree_number,
                event_tree = tree,
                event_leaf = leaf_index,
                "PerLeafPathEncoder received insert for a different tree; \
                 dirty-shard set will be empty so re-encode never fires for \
                 this event. Misconfigured deployment?"
            );
            return dirty;
        }
        if leaf_index >= LEAVES_PER_TREE {
            return dirty;
        }
        dirty.insert(leaf_index / self.entries_per_shard);
        let total_shards_usize = (LEAVES_PER_TREE / self.entries_per_shard) as usize;
        for k in 1..=u32::try_from(TREE_DEPTH).unwrap_or(u32::MAX) {
            let block_size = 1u32 << k;
            let block_start = (leaf_index / block_size) * block_size;
            let mut affected = block_start;
            while affected < leaf_index {
                dirty.insert(affected / self.entries_per_shard);
                affected += 1;
            }
            if dirty.len() >= total_shards_usize {
                break;
            }
        }
        dirty
    }

    fn label(&self) -> &'static str {
        labels::PER_LEAF_PATH
    }
}

/// Per-node encoder: each row is a single Merkle node (32 B), with rows
/// laid out in flat-global-index order — leaves first (`[0, 2^TREE_DEPTH)`),
/// then level-1 nodes, then level-2 nodes, ..., up to the root.
///
/// Inserting leaf X dirties at most TREE_DEPTH+1 rows (the leaf plus its
/// ancestors), de-duplicated to ~7 shards at the locked production cell
/// shape (per the dirty-shard-count bench).
#[derive(Debug, Clone)]
pub struct PerNodeEncoder {
    entries_per_shard: u32,
    tree_number: u32,
}

impl PerNodeEncoder {
    /// Build a per-node encoder pinned to `tree_number`.
    pub fn new(entries_per_shard: u32, tree_number: u32) -> Result<Self> {
        if entries_per_shard == 0 {
            return Err(AdapterError::InvalidQuery(
                "PerNodeEncoder: entries_per_shard must be > 0".to_string(),
            ));
        }
        Ok(Self {
            entries_per_shard,
            tree_number,
        })
    }

    /// Flat global index for `(level, idx_at_level)` in a depth-D tree.
    /// Level 0 occupies `[0, 2^D)`; subsequent levels follow in order.
    pub fn flat_index(level: u32, idx_at_level: u32) -> u32 {
        let depth = u32::try_from(TREE_DEPTH).unwrap_or(u32::MAX);
        let total = 1u32 << (depth + 1);
        let level_offset = total - (1u32 << (depth + 1 - level));
        level_offset + idx_at_level
    }

    /// Inverse of [`Self::flat_index`].
    pub fn level_and_offset(flat: u32) -> (u32, u32) {
        let depth = u32::try_from(TREE_DEPTH).unwrap_or(u32::MAX);
        let total = 1u32 << (depth + 1);
        let mut cursor = 0u32;
        for level in 0..=depth {
            let span = total >> (level + 1);
            if flat < cursor.saturating_add(span.max(1)) {
                return (level, flat - cursor);
            }
            cursor = cursor.saturating_add(span.max(1));
        }
        (depth, 0)
    }
}

impl PirTableEncoder for PerNodeEncoder {
    fn record_size(&self) -> usize {
        NODE_HASH_BYTES
    }

    fn entries_per_shard(&self) -> u32 {
        self.entries_per_shard
    }

    fn materialize_shard(&self, shard_id: u32, store: &LogicalLeafStore) -> Vec<u8> {
        let eps = self.entries_per_shard as usize;
        let mut buf = vec![0u8; eps.saturating_mul(NODE_HASH_BYTES)];
        let imt = store.imt(self.tree_number);
        let row_start_global = u64::from(shard_id) * u64::from(self.entries_per_shard);
        for row_offset in 0..eps {
            let flat = row_start_global + u64::try_from(row_offset).unwrap_or(u64::MAX);
            if flat >= u64::from(PER_NODE_TOTAL_NODES) {
                break;
            }
            let flat_u32 = u32::try_from(flat).unwrap_or(u32::MAX);
            let (level, idx_at_level) = Self::level_and_offset(flat_u32);
            let hash = imt.map_or([0u8; 32], |i| i.node(level as usize, idx_at_level as usize));
            let byte_start = row_offset * NODE_HASH_BYTES;
            let byte_end = byte_start + NODE_HASH_BYTES;
            if let Some(dst) = buf.get_mut(byte_start..byte_end) {
                dst.copy_from_slice(&hash);
            }
        }
        buf
    }

    fn affected_shards_for_leaf(&self, tree: u32, leaf_index: u32) -> BTreeSet<u32> {
        let mut dirty = BTreeSet::new();
        if tree != self.tree_number {
            tracing::warn!(
                target = "raven::pir_table",
                encoder = "per-node",
                encoder_tree = self.tree_number,
                event_tree = tree,
                event_leaf = leaf_index,
                "PerNodeEncoder received insert for a different tree; \
                 dirty-shard set will be empty so re-encode never fires for \
                 this event. Misconfigured deployment?"
            );
            return dirty;
        }
        let depth = u32::try_from(TREE_DEPTH).unwrap_or(u32::MAX);
        let mut idx = leaf_index;
        for level in 0..=depth {
            let flat = Self::flat_index(level, idx);
            dirty.insert(flat / self.entries_per_shard);
            idx >>= 1;
        }
        dirty
    }

    fn label(&self) -> &'static str {
        labels::PER_NODE
    }
}
