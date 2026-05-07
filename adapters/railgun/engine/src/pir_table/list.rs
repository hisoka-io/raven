//! Per-list PPOI encoders: PerListStatus, PerListPath, PerListNode.

use std::collections::BTreeSet;

use raven_railgun_core::{AdapterError, Result};

use super::leaf::PerNodeEncoder;
use super::{
    labels, PirTableEncoder, LEAVES_PER_TREE, MIN_RECORD_SIZE, NODE_HASH_BYTES, PATH_RECORD_BYTES,
    PER_NODE_TOTAL_NODES,
};
use crate::imt::TREE_DEPTH;
use crate::inspire::LogicalLeafStore;

/// T1 status encoder: row at list_index = `[status_byte, blinded_commitment[0..31]]`
/// padded with zeros to `record_size`. Pinned to one `list_key`. Status
/// PIR row layout chosen so the wallet recovers BOTH the status and the
/// canonical BC bytes from a single PIR query (the BC is the on-chain-
/// witnessed identity of the queried entry; status is the PPOI verdict).
#[derive(Debug, Clone)]
pub struct PerListStatusEncoder {
    record_size: usize,
    entries_per_shard: u32,
    list_key: [u8; 32],
}

impl PerListStatusEncoder {
    /// `record_size` must be `>= 33` (1 status byte + 32 BC bytes); the
    /// production cell uses 32 (status byte only) — drop the BC tail in
    /// that case. `entries_per_shard` must be non-zero.
    pub fn new(record_size: usize, entries_per_shard: u32, list_key: [u8; 32]) -> Result<Self> {
        if record_size < MIN_RECORD_SIZE {
            return Err(AdapterError::InvalidQuery(format!(
                "PerListStatusEncoder: record_size {record_size} must be >= {MIN_RECORD_SIZE}"
            )));
        }
        if entries_per_shard == 0 {
            return Err(AdapterError::InvalidQuery(
                "PerListStatusEncoder: entries_per_shard must be > 0".to_string(),
            ));
        }
        Ok(Self {
            record_size,
            entries_per_shard,
            list_key,
        })
    }

    /// 32-byte list_key this encoder is pinned to.
    #[must_use]
    pub fn list_key(&self) -> &[u8; 32] {
        &self.list_key
    }
}

impl PirTableEncoder for PerListStatusEncoder {
    fn record_size(&self) -> usize {
        self.record_size
    }

    fn entries_per_shard(&self) -> u32 {
        self.entries_per_shard
    }

    fn materialize_shard(&self, shard_id: u32, store: &LogicalLeafStore) -> Vec<u8> {
        let eps = self.entries_per_shard as usize;
        let mut buf = vec![0u8; eps.saturating_mul(self.record_size)];
        let row_start = (shard_id as usize).saturating_mul(eps);
        for row_offset in 0..eps {
            let list_index_usize = row_start + row_offset;
            let Ok(list_index) = u32::try_from(list_index_usize) else {
                break;
            };
            let Some(bc) = store.ppoi_bc_at(&self.list_key, list_index) else {
                continue;
            };
            let status = store.ppoi_status(&self.list_key, &bc).unwrap_or(0);
            let row_byte_start = row_offset * self.record_size;
            if let Some(dst) = buf.get_mut(row_byte_start..row_byte_start + self.record_size) {
                if let Some(b) = dst.first_mut() {
                    *b = status;
                }
                let bc_tail_len = self.record_size.saturating_sub(1).min(32);
                if bc_tail_len > 0 {
                    if let Some(slice) = dst.get_mut(1..1 + bc_tail_len) {
                        if let Some(bc_slice) = bc.get(..bc_tail_len) {
                            slice.copy_from_slice(bc_slice);
                        }
                    }
                }
            }
        }
        buf
    }

    fn affected_shards_for_leaf(&self, _tree: u32, _leaf_index: u32) -> BTreeSet<u32> {
        BTreeSet::new()
    }

    fn affected_shards_for_ppoi_leaf(&self, list_key: &[u8; 32], list_index: u32) -> BTreeSet<u32> {
        let mut dirty = BTreeSet::new();
        if list_key != &self.list_key {
            tracing::warn!(
                target = "raven::pir_table",
                encoder = "per-list-status",
                "PerListStatusEncoder received insert for a different list_key; dropped"
            );
            return dirty;
        }
        if list_index >= LEAVES_PER_TREE {
            return dirty;
        }
        dirty.insert(list_index / self.entries_per_shard);
        dirty
    }

    fn affected_shards_for_ppoi_status(
        &self,
        list_key: &[u8; 32],
        blinded_commitment: &[u8; 32],
    ) -> BTreeSet<u32> {
        let _ = blinded_commitment;
        if list_key != &self.list_key {
            return BTreeSet::new();
        }
        // Trait has no store handle; the apply path resolves BC -> idx
        // and calls `affected_shards_for_ppoi_leaf` directly, so we
        // return empty here without losing dirty marking.
        BTreeSet::new()
    }

    fn label(&self) -> &'static str {
        labels::PER_LIST_STATUS
    }
}

/// T2 path encoder: row at list_index = 16 sibling hashes from the
/// per-list IMT proof for that leaf, packed leaf-to-root
/// (`PATH_RECORD_BYTES = 512` bytes). Pinned to one `list_key`.
///
/// Same cascading dirty-shard semantics as [`PerLeafPathEncoder`] —
/// inserting list_index X invalidates every prior leaf sharing an
/// ancestor with X.
#[derive(Debug, Clone)]
pub struct PerListPathEncoder {
    record_size: usize,
    entries_per_shard: u32,
    list_key: [u8; 32],
}

impl PerListPathEncoder {
    /// `record_size` must be exactly 512 B (16 siblings × 32 B);
    /// `entries_per_shard` must be non-zero.
    pub fn new(record_size: usize, entries_per_shard: u32, list_key: [u8; 32]) -> Result<Self> {
        if record_size != PATH_RECORD_BYTES {
            return Err(AdapterError::InvalidQuery(format!(
                "PerListPathEncoder: record_size {record_size} must be exactly {PATH_RECORD_BYTES}"
            )));
        }
        if entries_per_shard == 0 {
            return Err(AdapterError::InvalidQuery(
                "PerListPathEncoder: entries_per_shard must be > 0".to_string(),
            ));
        }
        Ok(Self {
            record_size,
            entries_per_shard,
            list_key,
        })
    }

    /// 32-byte list_key this encoder is pinned to.
    #[must_use]
    pub fn list_key(&self) -> &[u8; 32] {
        &self.list_key
    }
}

impl PirTableEncoder for PerListPathEncoder {
    fn record_size(&self) -> usize {
        self.record_size
    }

    fn entries_per_shard(&self) -> u32 {
        self.entries_per_shard
    }

    fn materialize_shard(&self, shard_id: u32, store: &LogicalLeafStore) -> Vec<u8> {
        let eps = self.entries_per_shard as usize;
        let mut buf = vec![0u8; eps.saturating_mul(self.record_size)];
        let Some(imt) = store.ppoi_imt(&self.list_key) else {
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

    fn affected_shards_for_leaf(&self, _tree: u32, _leaf_index: u32) -> BTreeSet<u32> {
        BTreeSet::new()
    }

    fn affected_shards_for_ppoi_leaf(&self, list_key: &[u8; 32], list_index: u32) -> BTreeSet<u32> {
        let mut dirty = BTreeSet::new();
        if list_key != &self.list_key {
            tracing::warn!(
                target = "raven::pir_table",
                encoder = "per-list-path",
                "PerListPathEncoder received insert for a different list_key; dropped"
            );
            return dirty;
        }
        if list_index >= LEAVES_PER_TREE {
            return dirty;
        }
        dirty.insert(list_index / self.entries_per_shard);
        let total_shards_usize = (LEAVES_PER_TREE / self.entries_per_shard) as usize;
        for k in 1..=u32::try_from(TREE_DEPTH).unwrap_or(u32::MAX) {
            let block_size = 1u32 << k;
            let block_start = (list_index / block_size) * block_size;
            let mut affected = block_start;
            while affected < list_index {
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
        labels::PER_LIST_PATH
    }
}

/// Per-list Merkle-node encoder: each row is a single Merkle node (32 B)
/// from the per-list PPOI IMT, laid out in the same flat-global-index order
/// as [`PerNodeEncoder`] — leaves first (`[0, 2^TREE_DEPTH)`), then
/// level-1 nodes, ..., up to the root. Pinned to one `list_key`.
///
/// Inserting list_index X dirties at most TREE_DEPTH+1 rows (the leaf
/// plus its ancestors), de-duplicated per the per-node dirty-shard walk.
#[derive(Debug, Clone)]
pub struct PerListNodeEncoder {
    entries_per_shard: u32,
    list_key: [u8; 32],
}

impl PerListNodeEncoder {
    /// Build a per-list-node encoder pinned to `list_key`.
    /// `entries_per_shard` must be non-zero.
    pub fn new(entries_per_shard: u32, list_key: [u8; 32]) -> Result<Self> {
        if entries_per_shard == 0 {
            return Err(AdapterError::InvalidQuery(
                "PerListNodeEncoder: entries_per_shard must be > 0".to_string(),
            ));
        }
        Ok(Self {
            entries_per_shard,
            list_key,
        })
    }

    /// 32-byte list_key this encoder is pinned to.
    #[must_use]
    pub fn list_key(&self) -> &[u8; 32] {
        &self.list_key
    }
}

impl PirTableEncoder for PerListNodeEncoder {
    fn record_size(&self) -> usize {
        NODE_HASH_BYTES
    }

    fn entries_per_shard(&self) -> u32 {
        self.entries_per_shard
    }

    fn materialize_shard(&self, shard_id: u32, store: &LogicalLeafStore) -> Vec<u8> {
        let eps = self.entries_per_shard as usize;
        let mut buf = vec![0u8; eps.saturating_mul(NODE_HASH_BYTES)];
        let imt = store.ppoi_imt(&self.list_key);
        let row_start_global = u64::from(shard_id) * u64::from(self.entries_per_shard);
        for row_offset in 0..eps {
            let flat = row_start_global + u64::try_from(row_offset).unwrap_or(u64::MAX);
            if flat >= u64::from(PER_NODE_TOTAL_NODES) {
                break;
            }
            let flat_u32 = u32::try_from(flat).unwrap_or(u32::MAX);
            let (level, idx_at_level) = PerNodeEncoder::level_and_offset(flat_u32);
            let hash = imt.map_or([0u8; 32], |i| i.node(level as usize, idx_at_level as usize));
            let byte_start = row_offset * NODE_HASH_BYTES;
            let byte_end = byte_start + NODE_HASH_BYTES;
            if let Some(dst) = buf.get_mut(byte_start..byte_end) {
                dst.copy_from_slice(&hash);
            }
        }
        buf
    }

    fn affected_shards_for_leaf(&self, _tree: u32, _leaf_index: u32) -> BTreeSet<u32> {
        BTreeSet::new()
    }

    fn affected_shards_for_ppoi_leaf(&self, list_key: &[u8; 32], list_index: u32) -> BTreeSet<u32> {
        let mut dirty = BTreeSet::new();
        if list_key != &self.list_key {
            tracing::warn!(
                target = "raven::pir_table",
                encoder = "per-list-node",
                "PerListNodeEncoder received insert for a different list_key; dropped"
            );
            return dirty;
        }
        let depth = u32::try_from(TREE_DEPTH).unwrap_or(u32::MAX);
        let mut idx = list_index;
        for level in 0..=depth {
            let flat = PerNodeEncoder::flat_index(level, idx);
            dirty.insert(flat / self.entries_per_shard);
            idx >>= 1;
        }
        dirty
    }

    fn label(&self) -> &'static str {
        labels::PER_LIST_NODE
    }
}
