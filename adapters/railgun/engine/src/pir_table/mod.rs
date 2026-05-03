//! PIR-table encoder trait + implementations.
//!
//! Encoders are pure functions over `(LogicalLeafStore, shard_id)` and are
//! reconstructible from CRS + cell shape, so the persistence layer never
//! serializes encoder state.

use crate::imt::TREE_DEPTH;
use crate::inspire::LogicalLeafStore;
use raven_railgun_core::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::Arc;

pub mod leaf;
pub mod list;

pub use leaf::{PerLeafCommitmentEncoder, PerLeafEncoder, PerLeafPathEncoder, PerNodeEncoder};
pub use list::{PerListNodeEncoder, PerListPathEncoder, PerListStatusEncoder};

/// Static label registry — every concrete encoder exports a stable
/// label string for `/v1/status` + manifest `encoder_label` matching.
pub mod labels {
    /// T1 BC-membership encoder (default).
    pub const PER_LEAF_BC: &str = "per-leaf-bc";
    /// T2/T3 path encoder.
    pub const PER_LEAF_PATH: &str = "per-leaf-path";
    /// V2 candidate per-node encoder.
    pub const PER_NODE: &str = "per-node";
    /// T1 PPOI status encoder.
    pub const PER_LIST_STATUS: &str = "per-list-status";
    /// T2 PPOI auth-path encoder.
    pub const PER_LIST_PATH: &str = "per-list-path";
    /// Per-list Merkle-node encoder; row = 32 B Merkle node from the
    /// per-list PPOI IMT. Symmetric to `per-node` but keyed on `list_key`.
    pub const PER_LIST_NODE: &str = "per-list-node";
}

/// Operator-facing encoder discriminator. Carries per-encoder config
/// (e.g. `tree_number`) needed to construct the underlying impl.
///
/// Persisted in the manifest as `encoder_label`; bootstrap rejects
/// loading a manifest whose label diverges from the configured encoder.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum EncoderKind {
    /// T1 default: row = 32 B blinded commitment, padded to record_size.
    #[default]
    PerLeafBc,
    /// T2/T3 path encoder; row = 16 siblings × 32 B = 512 B from per-tree IMT.
    PerLeafPath {
        /// Tree this encoder is pinned to.
        tree_number: u32,
    },
    /// V2 candidate per-node encoder; row = 32 B Merkle node from per-tree IMT.
    PerNode {
        /// Tree this encoder is pinned to.
        tree_number: u32,
    },
    /// T1 PPOI status encoder; row at idx = `(status_byte || blinded_commitment)`
    /// for the per-list leaf at that idx, padded to record_size.
    PerListStatus {
        /// 32-byte list_key this encoder is pinned to.
        list_key: [u8; 32],
    },
    /// T2 PPOI auth-path encoder; row at idx = 16 sibling hashes from
    /// the per-list IMT proof for leaf idx (PATH_RECORD_BYTES = 512).
    PerListPath {
        /// 32-byte list_key this encoder is pinned to.
        list_key: [u8; 32],
    },
    /// Per-list Merkle-node encoder; row = 32 B Merkle node from the
    /// per-list PPOI IMT, in the same flat-global-index layout as
    /// [`PerNode`]. Pinned to one `list_key`.
    PerListNode {
        /// 32-byte list_key this encoder is pinned to.
        list_key: [u8; 32],
    },
}

impl EncoderKind {
    /// Stable label matching the resulting encoder's `label()`.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::PerLeafBc => labels::PER_LEAF_BC,
            Self::PerLeafPath { .. } => labels::PER_LEAF_PATH,
            Self::PerNode { .. } => labels::PER_NODE,
            Self::PerListStatus { .. } => labels::PER_LIST_STATUS,
            Self::PerListPath { .. } => labels::PER_LIST_PATH,
            Self::PerListNode { .. } => labels::PER_LIST_NODE,
        }
    }

    /// Construct the underlying encoder impl for `(record_size, entries_per_shard)`.
    /// PerLeafPath is fixed at `record_size = 512` per the locked T2/T3 spec
    /// regardless of the requested record_size — caller's `record_size`
    /// hint is ignored for the path variant.
    pub fn build(
        &self,
        record_size: usize,
        entries_per_shard: u32,
    ) -> Result<Arc<dyn PirTableEncoder>> {
        match self {
            Self::PerLeafBc => {
                let enc = PerLeafCommitmentEncoder::new(record_size, entries_per_shard)?;
                Ok(Arc::new(enc))
            }
            Self::PerLeafPath { tree_number } => {
                let enc =
                    PerLeafPathEncoder::new(PATH_RECORD_BYTES, entries_per_shard, *tree_number)?;
                Ok(Arc::new(enc))
            }
            Self::PerNode { tree_number } => {
                let enc = PerNodeEncoder::new(entries_per_shard, *tree_number)?;
                Ok(Arc::new(enc))
            }
            Self::PerListStatus { list_key } => {
                let enc = PerListStatusEncoder::new(record_size, entries_per_shard, *list_key)?;
                Ok(Arc::new(enc))
            }
            Self::PerListPath { list_key } => {
                let enc = PerListPathEncoder::new(PATH_RECORD_BYTES, entries_per_shard, *list_key)?;
                Ok(Arc::new(enc))
            }
            Self::PerListNode { list_key } => {
                let enc = PerListNodeEncoder::new(entries_per_shard, *list_key)?;
                Ok(Arc::new(enc))
            }
        }
    }
}

pub(crate) const MIN_RECORD_SIZE: usize = 32;
pub(crate) const NODE_HASH_BYTES: usize = 32;
pub(crate) const PATH_RECORD_BYTES: usize = TREE_DEPTH * NODE_HASH_BYTES;
pub(crate) const LEAVES_PER_TREE: u32 = 1u32 << TREE_DEPTH;
pub(crate) const PER_NODE_TOTAL_NODES: u32 = (1u32 << (TREE_DEPTH + 1)) - 1;

/// Per-shard byte-layout encoder consumed by the consumer task at commit
/// time.
pub trait PirTableEncoder: Send + Sync + std::fmt::Debug {
    /// Bytes per row.
    fn record_size(&self) -> usize;

    /// Rows per shard. Must match `ShardConfig::entries_per_shard`.
    fn entries_per_shard(&self) -> u32;

    /// Build the byte buffer for a single shard.
    fn materialize_shard(&self, shard_id: u32, store: &LogicalLeafStore) -> Vec<u8>;

    /// Shard ids whose stored rows must be re-encoded after a leaf insert.
    fn affected_shards_for_leaf(&self, tree: u32, leaf_index: u32) -> BTreeSet<u32>;

    /// Shard ids re-encoded after a per-list PPOI leaf insert. Default
    /// no-op for chain-tree encoders; per-list encoders override.
    fn affected_shards_for_ppoi_leaf(
        &self,
        _list_key: &[u8; 32],
        _list_index: u32,
    ) -> BTreeSet<u32> {
        BTreeSet::new()
    }

    /// Shard ids re-encoded after a per-list PPOI status update. Default
    /// no-op for chain-tree encoders; T1 status encoders override.
    fn affected_shards_for_ppoi_status(
        &self,
        _list_key: &[u8; 32],
        _blinded_commitment: &[u8; 32],
    ) -> BTreeSet<u32> {
        BTreeSet::new()
    }

    /// Stable encoder discriminator surfaced via `/v1/status` + logs.
    fn label(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imt::Imt;
    use raven_railgun_core::AdapterError;
    use raven_railgun_persistence::WalEntryPayload;

    fn append(tree: u32, leaf: u32, commitment: [u8; 32]) -> WalEntryPayload {
        WalEntryPayload::AppendLeaf {
            tree_number: tree,
            leaf_index: leaf,
            commitment,
        }
    }

    fn canonical(seed: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[31] = seed.max(1);
        b
    }

    #[test]
    fn new_validates_record_size_floor() {
        let too_small = PerLeafCommitmentEncoder::new(31, 2048);
        assert!(matches!(too_small, Err(AdapterError::InvalidQuery(_))));
    }

    #[test]
    fn new_rejects_zero_entries_per_shard() {
        assert!(PerLeafCommitmentEncoder::new(32, 0).is_err());
        assert!(PerLeafPathEncoder::new(PATH_RECORD_BYTES, 0, 0).is_err());
        assert!(PerNodeEncoder::new(0, 0).is_err());
    }

    #[test]
    fn per_leaf_path_record_size_must_be_512() {
        assert!(PerLeafPathEncoder::new(256, 2048, 0).is_err());
        assert!(PerLeafPathEncoder::new(PATH_RECORD_BYTES, 2048, 0).is_ok());
    }

    #[test]
    fn record_size_and_shard_width_round_trip() {
        let bc = PerLeafCommitmentEncoder::new(512, 2048).expect("bc");
        assert_eq!(bc.label(), "per-leaf-bc");
        let path = PerLeafPathEncoder::new(PATH_RECORD_BYTES, 2048, 7).expect("path");
        assert_eq!(path.label(), "per-leaf-path");
        assert_eq!(path.record_size(), PATH_RECORD_BYTES);
        let node = PerNodeEncoder::new(2048, 7).expect("node");
        assert_eq!(node.label(), "per-node");
        assert_eq!(node.record_size(), NODE_HASH_BYTES);
    }

    #[test]
    fn per_leaf_bc_affected_shards_returns_single_shard() {
        let enc = PerLeafCommitmentEncoder::new(32, 2048).expect("valid");
        let dirty = enc.affected_shards_for_leaf(0, 4096);
        assert_eq!(dirty.len(), 1);
        assert!(dirty.contains(&2));
    }

    #[test]
    fn per_leaf_path_affected_shards_exact_counts_at_fill_levels() {
        let enc = PerLeafPathEncoder::new(PATH_RECORD_BYTES, 2048, 0).expect("valid");
        assert_eq!(enc.affected_shards_for_leaf(0, 0).len(), 1);
        assert_eq!(enc.affected_shards_for_leaf(0, 16_384).len(), 9);
        assert_eq!(enc.affected_shards_for_leaf(0, 32_768).len(), 17);
        assert_eq!(enc.affected_shards_for_leaf(0, 49_152).len(), 25);
        assert_eq!(enc.affected_shards_for_leaf(0, 65_535).len(), 32);
    }

    #[test]
    fn per_node_affected_shards_exact_count_is_seven_at_production_cell() {
        let enc = PerNodeEncoder::new(2048, 0).expect("valid");
        for leaf in [0u32, 1, 42, 1024, 32_768, LEAVES_PER_TREE - 1] {
            assert_eq!(
                enc.affected_shards_for_leaf(0, leaf).len(),
                7,
                "per-node should dirty exactly 7 shards at entries_per_shard=2048; got != 7 for leaf {leaf}"
            );
        }
    }

    #[test]
    fn per_leaf_path_ignores_other_trees() {
        let enc = PerLeafPathEncoder::new(PATH_RECORD_BYTES, 2048, 5).expect("valid");
        let dirty = enc.affected_shards_for_leaf(0, 100);
        assert!(dirty.is_empty());
    }

    #[test]
    fn per_node_affected_shards_returns_at_most_tree_depth_plus_one() {
        let enc = PerNodeEncoder::new(2048, 0).expect("valid");
        for leaf in [0u32, 1, 42, 1024, 32_768, LEAVES_PER_TREE - 1] {
            let dirty = enc.affected_shards_for_leaf(0, leaf);
            assert!(dirty.len() <= (TREE_DEPTH + 1));
            assert!(!dirty.is_empty());
        }
    }

    #[test]
    fn per_node_flat_index_round_trips() {
        let depth = u32::try_from(TREE_DEPTH).expect("depth fits u32");
        for level in 0..=depth {
            for idx in [0u32, 1, 2] {
                let level_size = 1u32 << (depth - level);
                if idx >= level_size {
                    continue;
                }
                let flat = PerNodeEncoder::flat_index(level, idx);
                let (l2, i2) = PerNodeEncoder::level_and_offset(flat);
                assert_eq!(
                    (l2, i2),
                    (level, idx),
                    "round-trip failed for ({level}, {idx})"
                );
            }
        }
    }

    #[test]
    fn per_node_materialize_shard_zero_for_empty_store() {
        let enc = PerNodeEncoder::new(2048, 0).expect("valid");
        let store = LogicalLeafStore::new();
        let buf = enc.materialize_shard(0, &store);
        assert_eq!(buf.len(), 2048 * NODE_HASH_BYTES);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn per_node_materialize_shard_emits_first_leaf_at_row_zero() {
        let enc = PerNodeEncoder::new(2048, 0).expect("valid");
        let mut store = LogicalLeafStore::new();
        let leaf = canonical(7);
        store
            .apply(&append(0, 0, leaf), 100, &enc)
            .expect("apply leaf 0");
        let buf = enc.materialize_shard(0, &store);
        let row0 = buf.get(..32).expect("row 0 present");
        assert_eq!(row0, &leaf, "row 0 must be the level-0 node = leaf 0");
    }

    #[test]
    fn per_leaf_path_materialize_shard_byte_identical_to_independent_sibling_walk() {
        let enc = PerLeafPathEncoder::new(PATH_RECORD_BYTES, 2048, 0).expect("valid");
        let mut store = LogicalLeafStore::new();
        for i in 0..32u32 {
            let seed = u8::try_from(i).unwrap_or(255).saturating_add(1);
            store
                .apply(&append(0, i, canonical(seed)), 100 + u64::from(i), &enc)
                .expect("apply");
        }
        let buf = enc.materialize_shard(0, &store);
        let imt = store.imt(0).expect("tree 0 present");
        for leaf_idx in 0usize..32 {
            let row_start = leaf_idx * PATH_RECORD_BYTES;
            let mut path_idx = leaf_idx;
            for level in 0..TREE_DEPTH {
                let sibling_idx_at_level = path_idx ^ 1;
                path_idx >>= 1;
                let expected = imt.node(level, sibling_idx_at_level);
                let s = row_start + level * 32;
                let slice = buf.get(s..s + 32).expect("sibling slice present");
                assert_eq!(
                    slice, &expected,
                    "row {leaf_idx} level {level} sibling byte mismatch"
                );
            }
        }
    }

    #[test]
    fn per_node_materialize_shard_byte_identical_across_shards_and_levels() {
        let enc = PerNodeEncoder::new(8, 0).expect("valid");
        let mut store = LogicalLeafStore::new();
        let bc_enc = PerLeafCommitmentEncoder::new(32, 8).expect("seed encoder");
        for i in 0..16u32 {
            let seed = u8::try_from(i).unwrap_or(255).saturating_add(1);
            store
                .apply(&append(0, i, canonical(seed)), 100 + u64::from(i), &bc_enc)
                .expect("apply");
        }
        let imt = store.imt(0).expect("tree 0 present");
        for shard_id in 0u32..=(PER_NODE_TOTAL_NODES / 8) {
            let buf = enc.materialize_shard(shard_id, &store);
            for row_offset in 0u32..8 {
                let flat = shard_id * 8 + row_offset;
                if flat >= PER_NODE_TOTAL_NODES {
                    let s = (row_offset as usize) * 32;
                    let slice = buf.get(s..s + 32).expect("row slice");
                    assert!(
                        slice.iter().all(|&b| b == 0),
                        "shard {shard_id} row_offset {row_offset} past total nodes must be zero"
                    );
                    continue;
                }
                let (level, idx) = PerNodeEncoder::level_and_offset(flat);
                let expected = imt.node(level as usize, idx as usize);
                let s = (row_offset as usize) * 32;
                let slice = buf.get(s..s + 32).expect("row slice present");
                assert_eq!(
                    slice, &expected,
                    "shard {shard_id} flat {flat} (level {level}, idx {idx}) byte mismatch"
                );
            }
        }
    }

    #[test]
    fn per_node_materialize_shard_byte_identical_to_imt_node_oracle() {
        let enc = PerNodeEncoder::new(2048, 0).expect("valid");
        let mut store = LogicalLeafStore::new();
        for i in 0..16u32 {
            let seed = u8::try_from(i).unwrap_or(255).saturating_add(1);
            store
                .apply(&append(0, i, canonical(seed)), 100 + u64::from(i), &enc)
                .expect("apply");
        }
        let buf = enc.materialize_shard(0, &store);
        let imt = store.imt(0).expect("tree 0 present");
        for row in 0u32..16 {
            let (level, idx_at_level) = PerNodeEncoder::level_and_offset(row);
            let expected = imt.node(level as usize, idx_at_level as usize);
            let row_usize = row as usize;
            let slice = buf
                .get(row_usize * 32..row_usize * 32 + 32)
                .expect("row slice present");
            assert_eq!(slice, &expected, "row {row} node hash mismatch");
        }
    }

    #[test]
    fn per_list_node_rejects_zero_entries_per_shard() {
        assert!(PerListNodeEncoder::new(0, [0u8; 32]).is_err());
    }

    #[test]
    fn per_list_node_materialize_shard_zero_for_empty_store() {
        let enc = PerListNodeEncoder::new(2048, [0u8; 32]).expect("valid");
        let store = LogicalLeafStore::new();
        let buf = enc.materialize_shard(0, &store);
        assert_eq!(buf.len(), 2048 * NODE_HASH_BYTES);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn imt_oracle_round_trip_for_a_few_internal_nodes() {
        let mut imt = Imt::new().expect("imt");
        let l0 = canonical(1);
        let l1 = canonical(2);
        imt.insert_leaves(0, &[l0, l1]).expect("insert");
        assert_eq!(imt.node(0, 0), l0);
        assert_eq!(imt.node(0, 1), l1);
        let parent = imt.node(1, 0);
        assert_ne!(parent, [0u8; 32], "parent of two leaves must be non-zero");
    }
}
