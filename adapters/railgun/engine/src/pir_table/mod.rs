//! PIR-table encoder trait + implementations.
//!
//! Encoders are pure functions over `(LogicalLeafStore, shard_id)` and are
//! reconstructible from CRS + cell shape, so the persistence layer never
//! serializes encoder state.

use crate::imt::TREE_DEPTH;
use crate::inspire::LogicalLeafStore;
use raven_railgun_core::{AdapterError, Result};
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

    /// Minimum `total_entries` an `EncodedDatabase` must hold for this
    /// encoder kind to be safely usable.
    ///
    /// The per-node family (PerNode / PerListNode) flat-indexes every IMT
    /// node into a single PIR table; a leaf insert at the boundary dirties
    /// shards spanning `[0, PER_NODE_TOTAL_NODES)`, so the `EncodedDatabase`
    /// must allocate at least that many entry slots or `re_encode_shard`
    /// fails on dirty-shard ids past the end.
    ///
    /// The path / leaf-keyed family (PerLeafPath / PerListPath / PerLeafBc /
    /// PerListStatus) flat-indexes by leaf, requiring `LEAVES_PER_TREE`
    /// entries.
    #[must_use]
    pub const fn min_total_entries(&self) -> u32 {
        match self {
            Self::PerNode { .. } | Self::PerListNode { .. } => PER_NODE_TOTAL_NODES,
            Self::PerLeafBc
            | Self::PerLeafPath { .. }
            | Self::PerListStatus { .. }
            | Self::PerListPath { .. } => LEAVES_PER_TREE,
        }
    }

    /// Recommended `total_entries` cell size per encoder kind.
    ///
    /// Path / leaf-keyed encoders use `LEAVES_PER_TREE = 65,536`. Per-node
    /// encoders walk the full flat `[0, PER_NODE_TOTAL_NODES)` index space;
    /// the next `entries_per_shard`-aligned ceiling of
    /// `PER_NODE_TOTAL_NODES = 131,071` rounds up to `131,072` (next
    /// 2048-multiple) so dirty-shard ids stay within the allocated
    /// `EncodedDatabase` slots.
    #[must_use]
    pub const fn default_total_entries(&self) -> usize {
        match self {
            Self::PerNode { .. } | Self::PerListNode { .. } => 131_072,
            Self::PerLeafBc
            | Self::PerLeafPath { .. }
            | Self::PerListStatus { .. }
            | Self::PerListPath { .. } => LEAVES_PER_TREE as usize,
        }
    }

    /// Per-encoder default for the operator-facing concurrency cap.
    ///
    /// - `PerNode` / `PerListNode` / `PerListPath`: 16
    /// - `PerLeafPath`: 8
    /// - `PerLeafBc` / `PerListStatus`: 4
    #[must_use]
    pub const fn default_concurrency(&self) -> usize {
        match self {
            Self::PerNode { .. } | Self::PerListNode { .. } | Self::PerListPath { .. } => 16,
            Self::PerLeafPath { .. } => 8,
            Self::PerLeafBc | Self::PerListStatus { .. } => 4,
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

/// Minimum row-record size enforced by the path-family encoders.
pub const MIN_RECORD_SIZE: usize = 32;
/// 32-byte BN254 Poseidon node / leaf / blinded-commitment hash size.
pub const NODE_HASH_BYTES: usize = 32;
/// 16 sibling hashes × 32 B = 512 B path record size for `PerLeafPath` /
/// `PerListPath` encoders.
pub const PATH_RECORD_BYTES: usize = TREE_DEPTH * NODE_HASH_BYTES;
/// 2^16 = 65,536 leaves per Railgun commitment tree.
pub const LEAVES_PER_TREE: u32 = 1u32 << TREE_DEPTH;
/// 2^17 - 1 = 131,071 total IMT nodes in the flat-global-index PIR table
/// layout used by `PerNodeEncoder` and `PerListNodeEncoder`.
pub const PER_NODE_TOTAL_NODES: u32 = (1u32 << (TREE_DEPTH + 1)) - 1;

/// Free-function alias for [`EncoderKind::default_total_entries`]. Kept as
/// a free function so call sites that read the encoder by reference (e.g.
/// the operator binary's TOML resolver) can call it directly.
#[must_use]
pub const fn default_entries_for(encoder: &EncoderKind) -> usize {
    encoder.default_total_entries()
}

/// Free-function alias for [`EncoderKind::default_concurrency`].
#[must_use]
pub const fn default_concurrency_for(encoder: &EncoderKind) -> usize {
    encoder.default_concurrency()
}

/// Validate that the supplied `total_entries` fits the encoder's minimum
/// cell-shape invariant.
///
/// This is the canonical pre-allocation check operator-binary call sites
/// run before constructing an `EncodedDatabase`: the raven-inspire engine
/// sizes its shard count from `total_entries / entries_per_shard`, so an
/// undersized cell silently allocates fewer shards than the encoder will
/// dirty, leading to `re_encode_shard: shard id N not present` runtime
/// failures.
///
/// # Errors
/// Returns [`AdapterError::InvalidQuery`] when the cell is too small for
/// the encoder kind (e.g. PerNode with
/// `total_entries < PER_NODE_TOTAL_NODES`).
pub fn validate_total_entries(encoder: &EncoderKind, total_entries: usize) -> Result<()> {
    let min = encoder.min_total_entries() as usize;
    if total_entries < min {
        return Err(AdapterError::InvalidQuery(format!(
            "encoder {label} requires total_entries >= {min} for cell shape \
             (got {total_entries}); the per-leaf insert path dirties shards \
             past the allocated EncodedDatabase otherwise",
            label = encoder.label(),
        )));
    }
    Ok(())
}

/// Shared shard-dirty walk for both [`PerLeafPathEncoder::affected_shards_for_leaf`]
/// and [`PerListPathEncoder::affected_shards_for_ppoi_leaf`]. Inserting
/// `leaf_index` invalidates the path of every prior leaf sharing an
/// ancestor with it. Each level `k` (1..=TREE_DEPTH) defines a block of
/// `2^k` consecutive leaves; the block start is `(leaf_index >> k) << k`.
/// The dirty leaves at level `k` are `[block_start, leaf_index)` — inserting
/// at `block_start..=leaf_index` changes every prior leaf's sibling at level
/// k.
///
/// We accumulate shard ids by leaf-range rather than by per-leaf walk:
/// for each level the prior-leaf range `[block_start, leaf_index)` maps
/// to the inclusive shard range
/// `[block_start / eps ..= (leaf_index - 1) / eps]`. That bounds the
/// inner work to `O(num_shards × TREE_DEPTH)` ≈ 32 × 16 = 512 inserts at
/// the production cell, instead of `O(leaf_index × TREE_DEPTH)` ≈
/// 65,535 × 16 ≈ 1 M for the prior O(N) implementation (2000× speedup
/// at the worst-case leaf).
pub(crate) fn path_affected_shards_into(
    entries_per_shard: u32,
    leaf_index: u32,
    dirty: &mut BTreeSet<u32>,
) {
    dirty.insert(leaf_index / entries_per_shard);
    let total_shards_usize = (LEAVES_PER_TREE / entries_per_shard) as usize;
    let depth = u32::try_from(TREE_DEPTH).unwrap_or(u32::MAX);
    for k in 1..=depth {
        let block_size = 1u32 << k;
        let block_start = (leaf_index / block_size) * block_size;
        if block_start == leaf_index {
            continue;
        }
        let first_shard = block_start / entries_per_shard;
        let last_shard = (leaf_index - 1) / entries_per_shard;
        for s in first_shard..=last_shard {
            dirty.insert(s);
        }
        if dirty.len() >= total_shards_usize {
            break;
        }
    }
}

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
    // ---- T-B encoder cell-shape API tests --------------------------------

    #[test]
    fn default_entries_for_returns_131072_for_per_node_family() {
        let pn = EncoderKind::PerNode { tree_number: 0 };
        let pln = EncoderKind::PerListNode { list_key: [0; 32] };
        assert_eq!(default_entries_for(&pn), 131_072);
        assert_eq!(default_entries_for(&pln), 131_072);
        assert_eq!(pn.default_total_entries(), 131_072);
        assert_eq!(pln.default_total_entries(), 131_072);
    }

    #[test]
    fn default_entries_for_returns_65536_for_leaf_keyed_family() {
        let bc = EncoderKind::PerLeafBc;
        let st = EncoderKind::PerListStatus { list_key: [0; 32] };
        let lp = EncoderKind::PerLeafPath { tree_number: 0 };
        let plp = EncoderKind::PerListPath { list_key: [0; 32] };
        assert_eq!(default_entries_for(&bc), 65_536);
        assert_eq!(default_entries_for(&st), 65_536);
        assert_eq!(default_entries_for(&lp), 65_536);
        assert_eq!(default_entries_for(&plp), 65_536);
    }

    #[test]
    fn default_concurrency_for_per_node_family_is_16() {
        let pn = EncoderKind::PerNode { tree_number: 0 };
        let pln = EncoderKind::PerListNode { list_key: [0; 32] };
        let plp = EncoderKind::PerListPath { list_key: [0; 32] };
        assert_eq!(default_concurrency_for(&pn), 16);
        assert_eq!(default_concurrency_for(&pln), 16);
        assert_eq!(default_concurrency_for(&plp), 16);
    }

    #[test]
    fn default_concurrency_for_leaf_keyed_and_path() {
        let bc = EncoderKind::PerLeafBc;
        let st = EncoderKind::PerListStatus { list_key: [0; 32] };
        let lp = EncoderKind::PerLeafPath { tree_number: 0 };
        assert_eq!(default_concurrency_for(&bc), 4);
        assert_eq!(default_concurrency_for(&st), 4);
        assert_eq!(default_concurrency_for(&lp), 8);
    }

    #[test]
    fn validate_total_entries_rejects_per_node_with_undersized_cell() {
        let pn = EncoderKind::PerNode { tree_number: 0 };
        let r = validate_total_entries(&pn, 65_536);
        assert!(
            matches!(r, Err(raven_railgun_core::AdapterError::InvalidQuery(_))),
            "PerNode with total_entries=65,536 < PER_NODE_TOTAL_NODES=131,071 must reject; got {r:?}"
        );
        if let Err(raven_railgun_core::AdapterError::InvalidQuery(msg)) = r {
            assert!(
                msg.contains("per-node"),
                "msg should name the encoder: {msg}"
            );
            assert!(msg.contains("131071"), "msg should cite the floor: {msg}");
        }
    }

    #[test]
    fn validate_total_entries_accepts_per_node_at_floor_and_ceiling() {
        let pn = EncoderKind::PerNode { tree_number: 0 };
        validate_total_entries(&pn, 131_071).expect("131,071 == PER_NODE_TOTAL_NODES floor");
        validate_total_entries(&pn, 131_072).expect("131,072 == default_total_entries");
        validate_total_entries(&pn, 262_144).expect("any larger cell is fine");
    }

    #[test]
    fn validate_total_entries_rejects_per_list_node_with_undersized_cell() {
        let pln = EncoderKind::PerListNode { list_key: [0; 32] };
        let r = validate_total_entries(&pln, 65_536);
        assert!(matches!(
            r,
            Err(raven_railgun_core::AdapterError::InvalidQuery(_))
        ));
        validate_total_entries(&pln, 131_071).expect("PerListNode at floor must validate");
    }

    #[test]
    fn validate_total_entries_accepts_path_family_at_leaves_per_tree() {
        let bc = EncoderKind::PerLeafBc;
        let lp = EncoderKind::PerLeafPath { tree_number: 0 };
        let plp = EncoderKind::PerListPath { list_key: [0; 32] };
        let st = EncoderKind::PerListStatus { list_key: [0; 32] };
        validate_total_entries(&bc, 65_536).expect("PerLeafBc at LEAVES_PER_TREE");
        validate_total_entries(&lp, 65_536).expect("PerLeafPath at LEAVES_PER_TREE");
        validate_total_entries(&plp, 65_536).expect("PerListPath at LEAVES_PER_TREE");
        validate_total_entries(&st, 65_536).expect("PerListStatus at LEAVES_PER_TREE");
    }

    #[test]
    fn per_list_node_max_shard_id_overflows_undersized_cell_regression() {
        // Regression for the bug "shard id 32 not present in EncodedDatabase
        // (have 32 shards)": at the undersized 65,536-entry cell with
        // entries_per_shard=2048, the EncodedDatabase has 32 shards
        // (ids 0..=31) but PerListNodeEncoder dirties ids up to 63.
        let entries_per_shard: u32 = 2048;
        let pln_enc = PerListNodeEncoder::new(entries_per_shard, [0; 32]).expect("encoder");
        let undersized_total: u32 = 65_536;
        let undersized_shards = undersized_total / entries_per_shard;
        let mut max_seen = 0u32;
        for leaf in 0u32..LEAVES_PER_TREE {
            for s in pln_enc.affected_shards_for_ppoi_leaf(&[0; 32], leaf) {
                max_seen = max_seen.max(s);
            }
            if max_seen >= undersized_shards {
                break;
            }
        }
        assert!(
            max_seen >= undersized_shards,
            "regression guard: PerListNodeEncoder must dirty shard >= {undersized_shards} at some leaf"
        );
    }

    #[test]
    fn path_affected_shards_byte_identity_old_vs_new_impl() {
        // Old O(N) implementation kept inline as oracle.
        fn old_impl(entries_per_shard: u32, leaf_index: u32) -> std::collections::BTreeSet<u32> {
            let mut dirty = std::collections::BTreeSet::new();
            if leaf_index >= LEAVES_PER_TREE {
                return dirty;
            }
            dirty.insert(leaf_index / entries_per_shard);
            let total_shards_usize = (LEAVES_PER_TREE / entries_per_shard) as usize;
            for k in 1..=u32::try_from(crate::imt::TREE_DEPTH).unwrap_or(u32::MAX) {
                let block_size = 1u32 << k;
                let block_start = (leaf_index / block_size) * block_size;
                let mut affected = block_start;
                while affected < leaf_index {
                    dirty.insert(affected / entries_per_shard);
                    affected += 1;
                }
                if dirty.len() >= total_shards_usize {
                    break;
                }
            }
            dirty
        }

        for &eps in &[1024u32, 2048, 4096] {
            for &leaf in &[0u32, 1, 100, 1000, 32_768, LEAVES_PER_TREE - 1] {
                let pl_enc = PerLeafPathEncoder::new(PATH_RECORD_BYTES, eps, 0).expect("encoder");
                let new = pl_enc.affected_shards_for_leaf(0, leaf);
                let old = old_impl(eps, leaf);
                assert_eq!(
                    new, old,
                    "PerLeafPath byte-identity mismatch eps={eps} leaf={leaf}: new {new:?} vs old {old:?}"
                );
                let pl_list =
                    PerListPathEncoder::new(PATH_RECORD_BYTES, eps, [0; 32]).expect("encoder");
                let new_list = pl_list.affected_shards_for_ppoi_leaf(&[0; 32], leaf);
                assert_eq!(
                    new_list, old,
                    "PerListPath byte-identity mismatch eps={eps} leaf={leaf}"
                );
            }
        }
    }
}
