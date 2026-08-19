//! PIR-table encoders. Pure functions over `(LogicalLeafStore, shard_id)` and
//! reconstructible from CRS + cell shape, so encoder state is never persisted.

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

/// Stable encoder labels, surfaced on `/v1/status` and matched against the
/// manifest's `encoder_label`.
pub mod labels {
    /// T1 BC-membership encoder (default).
    pub const PER_LEAF_BC: &str = "per-leaf-bc";
    /// T2/T3 path encoder.
    pub const PER_LEAF_PATH: &str = "per-leaf-path";
    /// Per-node encoder.
    pub const PER_NODE: &str = "per-node";
    /// T1 PPOI status encoder.
    pub const PER_LIST_STATUS: &str = "per-list-status";
    /// T2 PPOI auth-path encoder.
    pub const PER_LIST_PATH: &str = "per-list-path";
    /// Per-list Merkle-node encoder; `per-node` keyed on `list_key`.
    pub const PER_LIST_NODE: &str = "per-list-node";
}

/// Operator-facing encoder discriminator with its construction config.
/// Persisted as `encoder_label`; bootstrap rejects a diverging label.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum EncoderKind {
    /// T1 default: row = 32 B blinded commitment, padded to record_size.
    ///
    /// Carries its tree because the row index is tree-LOCAL: `leaf_index` alone. The
    /// single-instance ingest path applies no tree filter, so without the pin two trees
    /// would write the same row and the higher one would silently win.
    PerLeafBc {
        /// Tree this encoder is pinned to.
        tree_number: u32,
    },
    /// T2/T3 path encoder; row = 16 siblings x 32 B = 512 B from per-tree IMT.
    PerLeafPath {
        /// Tree this encoder is pinned to.
        tree_number: u32,
    },
    /// Per-node encoder; row = 32 B Merkle node from per-tree IMT.
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
    /// Per-list Merkle-node encoder: [`PerNode`]'s layout over the per-list
    /// IMT, pinned to one `list_key`.
    PerListNode {
        /// 32-byte list_key this encoder is pinned to.
        list_key: [u8; 32],
    },
}

impl Default for EncoderKind {
    /// `per-leaf-bc` pinned to tree 0, the historical default. Hand-written because
    /// `#[default]` does not apply to a struct variant.
    fn default() -> Self {
        Self::PerLeafBc { tree_number: 0 }
    }
}

impl EncoderKind {
    /// Chain tree this encoder is scoped to, or `None` for the per-list variants.
    ///
    /// Every chain-tree encoder now carries its tree, so an ingest path can filter on it
    /// without a separate config field. That matters because the row layouts differ in how
    /// they use it - `PerLeafBc` indexes by `leaf_index` alone and filters, the others
    /// index per-tree - but the FILTER is uniform, and a filter defined for only some
    /// variants is what let a foreign tree reach a `per-leaf-bc` store.
    #[must_use]
    pub const fn chain_tree_number(&self) -> Option<u32> {
        match self {
            Self::PerLeafBc { tree_number }
            | Self::PerLeafPath { tree_number }
            | Self::PerNode { tree_number } => Some(*tree_number),
            Self::PerListStatus { .. } | Self::PerListPath { .. } | Self::PerListNode { .. } => {
                None
            }
        }
    }

    /// Stable label matching the resulting encoder's `label()`.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::PerLeafBc { .. } => labels::PER_LEAF_BC,
            Self::PerLeafPath { .. } => labels::PER_LEAF_PATH,
            Self::PerNode { .. } => labels::PER_NODE,
            Self::PerListStatus { .. } => labels::PER_LIST_STATUS,
            Self::PerListPath { .. } => labels::PER_LIST_PATH,
            Self::PerListNode { .. } => labels::PER_LIST_NODE,
        }
    }

    /// Minimum `total_entries`: node-keyed encoders flat-index every IMT node,
    /// leaf-keyed encoders every leaf. Undersizing fails `re_encode_shard` on
    /// dirty-shard ids past the end.
    #[must_use]
    pub const fn min_total_entries(&self) -> u32 {
        match self {
            Self::PerNode { .. } | Self::PerListNode { .. } => PER_NODE_TOTAL_NODES,
            Self::PerLeafBc { .. }
            | Self::PerLeafPath { .. }
            | Self::PerListStatus { .. }
            | Self::PerListPath { .. } => LEAVES_PER_TREE,
        }
    }

    /// Recommended cell size: `LEAVES_PER_TREE` leaf-keyed, `PER_NODE_TOTAL_NODES`
    /// rounded up to a 2048-multiple node-keyed, so every dirty-shard id fits.
    #[must_use]
    pub const fn default_total_entries(&self) -> usize {
        match self {
            Self::PerNode { .. } | Self::PerListNode { .. } => 131_072,
            Self::PerLeafBc { .. }
            | Self::PerLeafPath { .. }
            | Self::PerListStatus { .. }
            | Self::PerListPath { .. } => LEAVES_PER_TREE as usize,
        }
    }

    /// Per-encoder default for the operator-facing concurrency cap.
    #[must_use]
    pub const fn default_concurrency(&self) -> usize {
        match self {
            Self::PerNode { .. } | Self::PerListNode { .. } | Self::PerListPath { .. } => 16,
            Self::PerLeafPath { .. } => 8,
            Self::PerLeafBc { .. } | Self::PerListStatus { .. } => 4,
        }
    }

    /// Row width the variant's canonical layout pins, ignoring any request.
    #[must_use]
    pub const fn fixed_record_size(&self) -> Option<usize> {
        match self {
            Self::PerLeafPath { .. } | Self::PerListPath { .. } => Some(PATH_RECORD_BYTES),
            Self::PerNode { .. } | Self::PerListNode { .. } => Some(NODE_HASH_BYTES),
            Self::PerLeafBc { .. } | Self::PerListStatus { .. } => None,
        }
    }

    /// Row width [`Self::build`] will actually use for `requested`.
    #[must_use]
    pub const fn effective_record_size(&self, requested: usize) -> usize {
        match self.fixed_record_size() {
            Some(fixed) => fixed,
            None => requested,
        }
    }

    /// Construct the encoder for `(record_size, entries_per_shard)`. Variants
    /// with a canonical row layout ignore `record_size`, so gate on
    /// [`Self::effective_record_size`] or [`validate_cell_shape`] first.
    pub fn build(
        &self,
        record_size: usize,
        entries_per_shard: u32,
    ) -> Result<Arc<dyn PirTableEncoder>> {
        match self {
            Self::PerLeafBc { tree_number } => {
                let enc =
                    PerLeafCommitmentEncoder::new(record_size, entries_per_shard, *tree_number)?;
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
/// Path record size for `PerLeafPath` / `PerListPath`: [`TREE_DEPTH`] siblings
/// x [`NODE_HASH_BYTES`].
pub const PATH_RECORD_BYTES: usize = TREE_DEPTH * NODE_HASH_BYTES;
/// 2^16 = 65,536 leaves per Railgun commitment tree.
pub const LEAVES_PER_TREE: u32 = 1u32 << TREE_DEPTH;
/// 2^17 - 1 = 131,071 total IMT nodes in the flat-global-index PIR table
/// layout used by `PerNodeEncoder` and `PerListNodeEncoder`.
pub const PER_NODE_TOTAL_NODES: u32 = (1u32 << (TREE_DEPTH + 1)) - 1;

/// By-reference free-function alias for [`EncoderKind::default_total_entries`].
#[must_use]
pub const fn default_entries_for(encoder: &EncoderKind) -> usize {
    encoder.default_total_entries()
}

/// Free-function alias for [`EncoderKind::default_concurrency`].
#[must_use]
pub const fn default_concurrency_for(encoder: &EncoderKind) -> usize {
    encoder.default_concurrency()
}

/// Validate `total_entries` before allocation: an undersized cell allocates
/// fewer shards than the encoder dirties, failing `re_encode_shard` at runtime.
///
/// # Errors
/// [`AdapterError::InvalidQuery`] when the cell is too small for the encoder.
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

/// Column count `entry_size` induces in the InspiRING packing.
#[must_use]
pub fn pir_cell_columns(entry_size: usize) -> usize {
    entry_size.div_ceil(2).max(1)
}

/// Whether `entry_size` is a legal cell width at `ring_dim`. The packing
/// generator is `2n / gamma + 1` under integer division, so an off-law column
/// count picks the wrong automorphism and silently decrypts to unrelated bytes.
/// Measured ladder: `engine/tests/pir_cell_width_law.rs`.
#[must_use]
pub fn is_legal_cell_width(entry_size: usize, ring_dim: usize) -> bool {
    let cols = pir_cell_columns(entry_size);
    entry_size > 0 && cols.is_power_of_two() && cols <= ring_dim / 2
}

/// `entry_size` rounded up to the next power-of-two ladder width, or `None`
/// past the `ring_dim` ceiling. Deliberately coarser than
/// [`is_legal_cell_width`] - which only tests the induced column count - so a
/// remedy always points at a width measured end to end.
#[must_use]
pub fn next_legal_cell_width(entry_size: usize, ring_dim: usize) -> Option<usize> {
    if entry_size == 0 {
        return None;
    }
    let cols = pir_cell_columns(entry_size).next_power_of_two();
    (cols <= ring_dim / 2).then_some(cols * 2)
}

/// Validate a record width against [`is_legal_cell_width`].
///
/// # Errors
/// [`AdapterError::InvalidQuery`] when `entry_size` is zero or induces a column
/// count that is not a power of two no larger than `ring_dim / 2`.
pub fn validate_cell_width(entry_size: usize, ring_dim: usize) -> Result<()> {
    if entry_size == 0 {
        return Err(AdapterError::InvalidQuery(
            "PIR record width must be > 0".to_string(),
        ));
    }
    if is_legal_cell_width(entry_size, ring_dim) {
        return Ok(());
    }
    let cols = pir_cell_columns(entry_size);
    let max_cols = ring_dim / 2;
    let remedy = match next_legal_cell_width(entry_size, ring_dim) {
        Some(next) => format!("configure record width {next}"),
        None => format!(
            "no legal width at or above {entry_size} exists; the widest legal record at \
             ring_dim {ring_dim} is {max_legal}",
            max_legal = max_cols * 2
        ),
    };
    Err(AdapterError::InvalidQuery(format!(
        "PIR record width {entry_size} induces num_columns = ceil({entry_size}/2) = {cols}, \
         which must be a power of two no larger than ring_dim/2 = {max_cols}. Outside that \
         law the InspiRING generator 2n/gamma+1 is inexact, every served byte is wrong, and \
         nothing on the query path returns an error. {remedy}"
    )))
}

/// Validate the operator-supplied cell shape for `encoder` at `ring_dim`.
///
/// # Errors
/// [`AdapterError::InvalidQuery`] when the cell undersizes the encoder, when
/// `record_size` would be silently substituted, or when the width breaks
/// [`is_legal_cell_width`].
pub fn validate_cell_shape(
    encoder: &EncoderKind,
    total_entries: usize,
    record_size: usize,
    ring_dim: usize,
) -> Result<()> {
    validate_total_entries(encoder, total_entries)?;
    if let Some(fixed) = encoder.fixed_record_size() {
        if record_size != fixed {
            return Err(AdapterError::InvalidQuery(format!(
                "encoder {label} pins record width {fixed} by its canonical row layout and \
                 will not honor the requested {record_size}: the encoded database would be \
                 built at {record_size} while every re-encoded shard delivers {fixed}-byte \
                 rows. Configure record width {fixed}. If a data_dir was already populated \
                 at {record_size}-byte rows it must also be re-bootstrapped, because \
                 reconfiguring the width does not convert existing shards; reopening a \
                 {record_size}-byte cell under this encoder is refused at recovery.",
                label = encoder.label(),
            )));
        }
    }
    validate_cell_width(record_size, ring_dim)
}

/// Require `entries_per_shard == ring_dim`: shards are `ring_dim * entry_size`
/// bytes, and a smaller value silently offsets the encoder's row window against
/// the shard it overwrites with no error anywhere on the re-encode or query path.
///
/// # Errors
/// [`AdapterError::InvalidQuery`] unless `entries_per_shard == ring_dim`.
pub fn validate_rows_per_shard(entries_per_shard: u32, ring_dim: usize) -> Result<()> {
    if entries_per_shard as usize == ring_dim {
        return Ok(());
    }
    Err(AdapterError::InvalidQuery(format!(
        "rows per shard {entries_per_shard} must equal ring_dim {ring_dim}: PIR setup sizes \
         every shard at ring_dim * entry_size bytes, so ShardConfig::entries_per_shard is \
         always exactly {ring_dim} rows, whatever the record width. At {entries_per_shard} the \
         encoder writes shard s from the rows starting at s * {entries_per_shard} into the \
         shard holding the rows starting at s * {ring_dim}, and neither the re-encode nor the \
         query path returns an error. Configure rows per shard {ring_dim}."
    )))
}

/// Shard-dirty walk for the path encoders. Inserting `leaf_index` invalidates
/// every prior leaf sharing an ancestor - `[(leaf_index >> k) << k, leaf_index)`
/// at level `k` - mapped per level to a shard range so the cost is
/// `O(num_shards x TREE_DEPTH)`, not `O(leaf_index x TREE_DEPTH)`.
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

/// Per-shard byte-layout encoder, driven at commit time.
pub trait PirTableEncoder: Send + Sync + std::fmt::Debug {
    /// Bytes per row.
    fn record_size(&self) -> usize;

    /// Rows per shard. Must match `ShardConfig::entries_per_shard`.
    fn entries_per_shard(&self) -> u32;

    /// Build the byte buffer for a single shard.
    fn materialize_shard(&self, shard_id: u32, store: &LogicalLeafStore) -> Vec<u8>;

    /// Shard ids whose stored rows must be re-encoded after a leaf insert. Empty
    /// when the insert is outside the encoder's row space: an id past the
    /// allocated cell is unencodable and the commit driver drops it.
    fn affected_shards_for_leaf(&self, tree: u32, leaf_index: u32) -> BTreeSet<u32>;

    /// Shard ids dirtied by a per-list leaf insert; no-op for chain-tree encoders.
    fn affected_shards_for_ppoi_leaf(
        &self,
        _list_key: &[u8; 32],
        _list_index: u32,
    ) -> BTreeSet<u32> {
        BTreeSet::new()
    }

    /// Shard ids dirtied by a per-list status update; no-op for chain-tree encoders.
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
        let too_small = PerLeafCommitmentEncoder::new(31, 2048, 0);
        assert!(matches!(too_small, Err(AdapterError::InvalidQuery(_))));
    }

    #[test]
    fn new_rejects_zero_entries_per_shard() {
        assert!(PerLeafCommitmentEncoder::new(32, 0, 0).is_err());
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
        let bc = PerLeafCommitmentEncoder::new(512, 2048, 0).expect("bc");
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
        let enc = PerLeafCommitmentEncoder::new(32, 2048, 0).expect("valid");
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

    /// Drives the same path a chain event takes: `LogicalLeafStore::apply` on an
    /// `AppendLeaf`, against the encoder `EncoderKind::build` returns at bootstrap.
    #[test]
    fn per_leaf_bc_dirty_shards_stay_inside_the_cell_it_declares() {
        // Pinned to tree 1: this test feeds a tree-1 leaf, and an encoder pinned
        // elsewhere would correctly dirty nothing, making the assertion vacuous.
        let kind = EncoderKind::PerLeafBc { tree_number: 1 };
        let entries_per_shard = 2048u32;
        let encoder = kind.build(32, entries_per_shard).expect("build");
        let cell_shards =
            u32::try_from(kind.default_total_entries()).expect("cell fits u32") / entries_per_shard;

        let mut store = LogicalLeafStore::new();
        store
            .apply(&append(1, 0, canonical(9)), 100, encoder.as_ref())
            .expect("apply tree-1 leaf 0");

        assert_eq!(
            store.dirty_shards().iter().copied().collect::<Vec<u32>>(),
            vec![0],
            "a tree-1 leaf at index 0 occupies row 0 of shard 0, exactly as tree 0 does; \
             the tree is not part of the row index because routing already scoped it"
        );
        let past_cell: Vec<u32> = store
            .dirty_shards()
            .iter()
            .copied()
            .filter(|s| *s >= cell_shards)
            .collect();
        assert!(
            past_cell.is_empty(),
            "dirty shards {past_cell:?} are past the {cell_shards} shards this encoder's \
             declared cell holds, so re-encode could not fire for them"
        );
    }

    #[test]
    fn per_leaf_bc_still_dirties_the_shard_holding_its_own_tree() {
        let encoder = EncoderKind::PerLeafBc { tree_number: 0 }
            .build(32, 8)
            .expect("build");
        let mut store = LogicalLeafStore::new();
        for leaf in 0..=8u32 {
            let seed = u8::try_from(leaf).unwrap_or(255).saturating_add(1);
            store
                .apply(&append(0, leaf, canonical(seed)), 100, encoder.as_ref())
                .expect("apply own-tree leaf");
        }
        assert_eq!(
            store.dirty_shards().iter().copied().collect::<Vec<u32>>(),
            vec![0, 1]
        );
    }

    proptest::proptest! {
        #[test]
        fn per_leaf_bc_dirty_shards_never_leave_the_declared_cell(
            tree in 0u32..8,
            leaf in 0u32..=u32::MAX,
        ) {
            let entries_per_shard = 2048u32;
            let encoder = PerLeafCommitmentEncoder::new(32, entries_per_shard, 0).expect("bc");
            // The bound is one tree's row space, not `default_total_entries` - that is a
            // documented *recommendation* and `validate_total_entries` enforces it as a
            // floor only, so using it as a ceiling asserts a limit no code applies.
            let tree_shards = LEAVES_PER_TREE / entries_per_shard;
            for shard in encoder.affected_shards_for_leaf(tree, leaf) {
                proptest::prop_assert!(
                    shard < tree_shards,
                    "tree {tree} leaf {leaf} dirtied shard {shard}, outside the \
                     {tree_shards} shards one tree's row space spans"
                );
                proptest::prop_assert_eq!(
                    shard, leaf / entries_per_shard,
                    "the row index is the leaf index alone; the tree is not part of it"
                );
            }
        }
    }

    #[test]
    fn every_chain_tree_encoder_ignores_a_foreign_tree() {
        // All three carry their tree. `per-leaf-bc` rows are indexed by `leaf_index` alone,
        // so an unfiltered foreign leaf overwrites this tree's row and the higher tree wins.
        let bc = PerLeafCommitmentEncoder::new(32, 2048, 0).expect("bc");
        let path = PerLeafPathEncoder::new(PATH_RECORD_BYTES, 2048, 0).expect("path");
        let node = PerNodeEncoder::new(2048, 0).expect("node");
        for enc in [
            &bc as &dyn PirTableEncoder,
            &path as &dyn PirTableEncoder,
            &node as &dyn PirTableEncoder,
        ] {
            assert!(
                enc.affected_shards_for_leaf(1, 0).is_empty(),
                "{} is pinned to tree 0 and must ignore tree 1",
                enc.label()
            );
        }
        // And the row index stays tree-local: the same leaf maps to the same shard under
        // a pin to any tree.
        let bc1 = PerLeafCommitmentEncoder::new(32, 2048, 1).expect("bc1");
        assert_eq!(
            bc1.affected_shards_for_leaf(1, 0),
            bc.affected_shards_for_leaf(0, 0),
            "the row index is the leaf index alone; only the filter differs"
        );
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
        let bc_enc = PerLeafCommitmentEncoder::new(32, 8, 0).expect("seed encoder");
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
        let bc = EncoderKind::PerLeafBc { tree_number: 0 };
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
        let bc = EncoderKind::PerLeafBc { tree_number: 0 };
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
        let bc = EncoderKind::PerLeafBc { tree_number: 0 };
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
        // A 65,536-entry cell gives 32 shards, but the node encoder dirties ids
        // past 31, so the cell must be sized off PER_NODE_TOTAL_NODES.
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
