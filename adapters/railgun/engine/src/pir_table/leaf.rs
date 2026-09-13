//! Chain-tree encoders keyed on `tree_number`.

use std::collections::BTreeSet;

use raven_railgun_core::{AdapterError, Result};

use super::{
    labels, materialize_node_shard, materialize_path_shard, node_affected_shards, PirTableEncoder,
    LEAVES_PER_TREE, MIN_RECORD_SIZE, NODE_HASH_BYTES, PATH_RECORD_BYTES,
};
use crate::imt::TREE_DEPTH;
use crate::inspire::{materialize_shard_bytes, LogicalLeafStore};

/// Membership encoder: row is the 32 B commitment, zero-padded to `record_size`.
/// Rows cover one tree's leaf range; an insert outside it dirties no shard.
#[derive(Debug, Clone)]
pub struct PerLeafCommitmentEncoder {
    record_size: usize,
    entries_per_shard: u32,
    tree_number: u32,
}

impl PerLeafCommitmentEncoder {
    /// Build after validating the cell shape; requires `record_size >= 32` and
    /// non-zero `entries_per_shard`.
    pub fn new(record_size: usize, entries_per_shard: u32, tree_number: u32) -> Result<Self> {
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
            tree_number,
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
        materialize_shard_bytes(
            store,
            shard_id,
            self.entries_per_shard,
            self.record_size,
            self.tree_number,
        )
    }

    fn affected_shards_for_leaf(&self, tree: u32, leaf_index: u32) -> BTreeSet<u32> {
        let mut dirty = BTreeSet::new();
        // The pin is the invariant, not the router: the single-instance ingest path
        // forwards every tree, and the row index is `leaf_index` alone, so an unfiltered
        // foreign leaf would overwrite this tree's row.
        if tree != self.tree_number {
            tracing::warn!(
                target = "raven::pir_table",
                encoder = "per-leaf-bc",
                pinned_tree = self.tree_number,
                event_tree = tree,
                event_leaf = leaf_index,
                "leaf from a tree this encoder is not pinned to; no shard holds it"
            );
            return dirty;
        }
        if leaf_index >= LEAVES_PER_TREE {
            tracing::warn!(
                target = "raven::pir_table",
                encoder = "per-leaf-bc",
                event_leaf = leaf_index,
                row_space = LEAVES_PER_TREE,
                "leaf index past one tree's row space; no shard holds it, so re-encode \
                 cannot fire and the row it would occupy stays zero"
            );
            return dirty;
        }
        dirty.insert(leaf_index / self.entries_per_shard);
        dirty
    }

    fn label(&self) -> &'static str {
        labels::PER_LEAF_BC
    }
}

/// Alias for [`PerLeafCommitmentEncoder`].
pub type PerLeafEncoder = PerLeafCommitmentEncoder;

/// Path encoder: one row per leaf holding its siblings packed leaf-to-root.
/// Byte layout equals `bincode::serialize(&[[u8; 32]; TREE_DEPTH])` - no header,
/// no length prefix.
#[derive(Debug, Clone)]
pub struct PerLeafPathEncoder {
    record_size: usize,
    entries_per_shard: u32,
    tree_number: u32,
}

impl PerLeafPathEncoder {
    /// Build a path encoder; requires `record_size == PATH_RECORD_BYTES` and
    /// non-zero `entries_per_shard`.
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
        materialize_path_shard(
            store.imt(self.tree_number),
            shard_id,
            self.entries_per_shard,
            self.record_size,
        )
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
        super::path_affected_shards_into(self.entries_per_shard, leaf_index, &mut dirty);
        dirty
    }

    fn label(&self) -> &'static str {
        labels::PER_LEAF_PATH
    }
}

/// Per-node encoder: one Merkle node per row in flat-global-index order,
/// leaves first then each level up to the root. A leaf insert dirties at most
/// `TREE_DEPTH + 1` rows.
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

    /// Flat global index for `(level, idx_at_level)`; level 0 occupies
    /// `[0, 2^TREE_DEPTH)` and higher levels follow in order.
    pub fn flat_index(level: u32, idx_at_level: u32) -> u32 {
        let depth = u32::try_from(TREE_DEPTH).unwrap_or(u32::MAX);
        raven_railgun_core::tree_layout::flat_index(depth, level, idx_at_level)
    }

    /// Inverse of [`Self::flat_index`].
    pub fn level_and_offset(flat: u32) -> (u32, u32) {
        let depth = u32::try_from(TREE_DEPTH).unwrap_or(u32::MAX);
        raven_railgun_core::tree_layout::level_and_offset(depth, flat)
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
        materialize_node_shard(
            store.imt(self.tree_number),
            shard_id,
            self.entries_per_shard,
        )
    }

    fn affected_shards_for_leaf(&self, tree: u32, leaf_index: u32) -> BTreeSet<u32> {
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
            return BTreeSet::new();
        }
        node_affected_shards(self.entries_per_shard, leaf_index)
    }

    fn label(&self) -> &'static str {
        labels::PER_NODE
    }
}
