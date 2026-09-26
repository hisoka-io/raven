//! Per-list encoders keyed on `list_key`.

use std::collections::BTreeSet;

use raven_railgun_core::{AdapterError, POIStatus, Result};

use super::{
    labels, materialize_node_shard, materialize_path_shard, node_affected_shards, PirTableEncoder,
    LEAVES_PER_TREE, MIN_RECORD_SIZE, NODE_HASH_BYTES, PATH_RECORD_BYTES,
};
use crate::imt::Imt;
use crate::inspire::LogicalLeafStore;
use crate::orchestrator::hex_lower_32;

/// Status byte of every row that carries no verdict.
///
/// Must not be 0: 0 is `Valid`, the verdict that authorizes a spend, so defaulting to
/// it fails open. Matches what the plaintext shim returns for the same state
/// (`poi_shim.rs` maps `None` to `Missing`).
pub const ABSENT_STATUS_BYTE: u8 = POIStatus::Missing.wire_byte();
/// PPOI v2 row width.
pub const PATH10_RECORD_BYTES: usize = 512;
/// Number of lower siblings retained in a PPOI v2 row.
pub const PATH10_LEVELS: usize = 11;
/// Marks a filled PPOI v2 row. An unfilled row carries no marker, and
/// [`ABSENT_STATUS_BYTE`] at the status offset.
pub const PATH10_MAGIC: [u8; 4] = *b"RVP2";
const PATH10_STATUS_OFFSET: usize = 32;

/// Rows encoded ABSENT for an index the list holds, once per shard materialization.
///
/// The list frontier is its leaf count. A row below it has a record upstream, so encoding it
/// ABSENT is a store inconsistency and is counted, again on every re-encode of its shard while
/// it persists. A row at or past it is padding for an index the list has not reached; every
/// shard past the tail is made of them, so they are not.
const UNFILLED_ROWS_TOTAL: &str = "raven_railgun_pir_unfilled_rows_total";

fn record_unfilled_row(
    encoder: &'static str,
    list_key: &[u8; 32],
    list_index: u32,
    missing: &'static str,
) {
    metrics::describe_counter!(
        UNFILLED_ROWS_TOTAL,
        metrics::Unit::Count,
        "Per-list PIR rows below the list frontier encoded ABSENT because the store lacks \
         the part the `missing` label names, counted once per shard materialization: a row \
         that stays unfilled adds one on every re-encode of its shard, so this counts \
         emissions, not distinct rows. Rows at or past the frontier are padding and are never \
         counted. Any increase means the node publishes no verdict for an index the list \
         holds. The warn log names the list_key and list_index."
    );
    metrics::counter!(UNFILLED_ROWS_TOTAL, "encoder" => encoder, "missing" => missing).increment(1);
    tracing::warn!(
        target = "raven::pir_table",
        encoder,
        list_key = %hex_lower_32(list_key),
        list_index,
        missing,
        "row below the list frontier served ABSENT"
    );
}

/// Status encoder: row at `list_index` is `[status_byte, bc[0..31]]` padded to
/// `record_size`. The BC tail lets one query recover verdict and canonical bytes.
/// Every row without a verdict encodes [`ABSENT_STATUS_BYTE`], never `Valid`.
#[derive(Debug, Clone)]
pub struct PerListStatusEncoder {
    record_size: usize,
    entries_per_shard: u32,
    list_key: [u8; 32],
}

impl PerListStatusEncoder {
    /// Requires `record_size >= 32` and non-zero `entries_per_shard`.
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
        for row in buf.chunks_exact_mut(self.record_size) {
            if let Some(b) = row.first_mut() {
                *b = ABSENT_STATUS_BYTE;
            }
        }
        let frontier = store.ppoi_imt(&self.list_key).map_or(0, Imt::leaf_count);
        let unfilled = |list_index, missing| {
            record_unfilled_row(labels::PER_LIST_STATUS, &self.list_key, list_index, missing);
        };
        let row_start = (shard_id as usize).saturating_mul(eps);
        for row_offset in 0..eps {
            let list_index_usize = row_start.saturating_add(row_offset);
            let Ok(list_index) = u32::try_from(list_index_usize) else {
                break;
            };
            let below_frontier = list_index_usize < frontier;
            let Some(bc) = store.ppoi_bc_at(&self.list_key, list_index) else {
                if below_frontier {
                    unfilled(list_index, "leaf");
                }
                continue;
            };
            // A reorg between a leaf and its later status update clears `ppoi_status` while
            // `ppoi_index_bc` survives, so this default is reachable.
            let status = store.ppoi_status(&self.list_key, &bc).unwrap_or_else(|| {
                if below_frontier {
                    unfilled(list_index, "status");
                }
                ABSENT_STATUS_BYTE
            });
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

    fn label(&self) -> &'static str {
        labels::PER_LIST_STATUS
    }
}

/// Path encoder: row at `list_index` is the per-list IMT proof packed
/// leaf-to-root. Same cascading dirty-shard semantics as [`PerLeafPathEncoder`].
#[derive(Debug, Clone)]
pub struct PerListPathEncoder {
    record_size: usize,
    entries_per_shard: u32,
    list_key: [u8; 32],
}

impl PerListPathEncoder {
    /// Requires `record_size == PATH_RECORD_BYTES` and non-zero `entries_per_shard`.
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
        materialize_path_shard(
            store.ppoi_imt(&self.list_key),
            shard_id,
            self.entries_per_shard,
            self.record_size,
        )
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
        super::path_affected_shards_into(self.entries_per_shard, list_index, &mut dirty);
        dirty
    }

    fn label(&self) -> &'static str {
        labels::PER_LIST_PATH
    }
}

/// PPOI v2 row encoder: leaf, status, type, magic and levels 0 through 10.
#[derive(Debug, Clone)]
pub struct PerListPath10Encoder {
    entries_per_shard: u32,
    list_key: [u8; 32],
}

impl PerListPath10Encoder {
    /// Construct a block-local encoder.
    pub fn new(entries_per_shard: u32, list_key: [u8; 32]) -> Result<Self> {
        if entries_per_shard == 0 {
            return Err(AdapterError::InvalidQuery(
                "PerListPath10Encoder: entries_per_shard must be > 0".to_owned(),
            ));
        }
        Ok(Self {
            entries_per_shard,
            list_key,
        })
    }
}

impl PirTableEncoder for PerListPath10Encoder {
    fn record_size(&self) -> usize {
        PATH10_RECORD_BYTES
    }

    fn entries_per_shard(&self) -> u32 {
        self.entries_per_shard
    }

    fn materialize_shard(&self, shard_id: u32, store: &LogicalLeafStore) -> Vec<u8> {
        let rows = self.entries_per_shard as usize;
        let mut out = vec![0u8; rows.saturating_mul(PATH10_RECORD_BYTES)];
        // The marker is what the client checks; the status byte is for a reader that does not.
        for row in out.as_chunks_mut::<PATH10_RECORD_BYTES>().0 {
            if let Some(status) = row.get_mut(PATH10_STATUS_OFFSET) {
                *status = ABSENT_STATUS_BYTE;
            }
        }
        let Some(imt) = store.ppoi_imt(&self.list_key) else {
            return out;
        };
        let unfilled = |list_index, missing| {
            record_unfilled_row(labels::PER_LIST_PATH10, &self.list_key, list_index, missing);
        };
        let row_start = (shard_id as usize).saturating_mul(rows);
        for row_offset in 0..rows {
            let list_index = row_start.saturating_add(row_offset);
            if list_index >= imt.leaf_count() {
                break;
            }
            let Ok(list_index_u32) = u32::try_from(list_index) else {
                break;
            };
            let Some(leaf) = store.ppoi_bc_at(&self.list_key, list_index_u32) else {
                unfilled(list_index_u32, "leaf");
                continue;
            };
            let Some(metadata) = store.ppoi_event_metadata(&self.list_key, list_index_u32) else {
                unfilled(list_index_u32, "metadata");
                continue;
            };
            let Ok(proof) = imt.merkle_proof(list_index) else {
                unfilled(list_index_u32, "proof");
                continue;
            };
            let start = row_offset * PATH10_RECORD_BYTES;
            let Some(row) = out.get_mut(start..start + PATH10_RECORD_BYTES) else {
                continue;
            };
            if let Some(dst) = row.get_mut(..32) {
                dst.copy_from_slice(&leaf);
            }
            if let Some(status) = row.get_mut(PATH10_STATUS_OFFSET) {
                *status = store
                    .ppoi_status_at(&self.list_key, list_index_u32)
                    .unwrap_or_else(|| {
                        unfilled(list_index_u32, "status");
                        ABSENT_STATUS_BYTE
                    });
            }
            let event_type = match metadata.event_type {
                raven_railgun_persistence::PpoiEventType::Shield => 0,
                raven_railgun_persistence::PpoiEventType::Transact => 1,
                raven_railgun_persistence::PpoiEventType::Unshield => 2,
                raven_railgun_persistence::PpoiEventType::LegacyTransact => 3,
            };
            if let Some(dst) = row.get_mut(33) {
                *dst = event_type;
            }
            if let Some(dst) = row.get_mut(34..38) {
                dst.copy_from_slice(&PATH10_MAGIC);
            }
            for (level, sibling) in proof.elements.iter().take(PATH10_LEVELS).enumerate() {
                let sibling_start = 38 + level * NODE_HASH_BYTES;
                if let Some(dst) = row.get_mut(sibling_start..sibling_start + NODE_HASH_BYTES) {
                    dst.copy_from_slice(sibling);
                }
            }
        }
        out
    }

    fn affected_shards_for_leaf(&self, _tree: u32, _leaf_index: u32) -> BTreeSet<u32> {
        BTreeSet::new()
    }

    fn affected_shards_for_ppoi_leaf(&self, list_key: &[u8; 32], list_index: u32) -> BTreeSet<u32> {
        let mut dirty = BTreeSet::new();
        if list_key != &self.list_key || list_index >= LEAVES_PER_TREE {
            return dirty;
        }
        // Levels 0..=PATH10_LEVELS-1 are stored IN the row, so an insert restales every
        // shard holding a leaf whose stored path moved -- the same walk the per-list path
        // encoder uses, and the one the exhaustive dirty-set property guards. The singleton this
        // replaces was correct only when a shard was exactly one 2^PATH10_LEVELS subtree,
        // while `new()` accepts any non-zero width: at 512 rows, inserting leaf 512 left
        // shard 0 stale with no error and no counter.
        let highest_stored_level =
            u32::try_from(PATH10_LEVELS.saturating_sub(1)).unwrap_or(u32::MAX);
        super::path_affected_shards_for_level_into(
            self.entries_per_shard,
            list_index,
            highest_stored_level,
            &mut dirty,
        );
        dirty
    }

    fn label(&self) -> &'static str {
        labels::PER_LIST_PATH10
    }
}

/// Per-list node encoder using flat-global-index layout over the per-list IMT.
/// A leaf insert dirties at most `TREE_DEPTH + 1` rows.
#[derive(Debug, Clone)]
pub struct PerListNodeEncoder {
    entries_per_shard: u32,
    list_key: [u8; 32],
}

impl PerListNodeEncoder {
    /// Build a per-list-node encoder; `entries_per_shard` must be non-zero.
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
        materialize_node_shard(
            store.ppoi_imt(&self.list_key),
            shard_id,
            self.entries_per_shard,
        )
    }

    fn affected_shards_for_leaf(&self, _tree: u32, _leaf_index: u32) -> BTreeSet<u32> {
        BTreeSet::new()
    }

    fn affected_shards_for_ppoi_leaf(&self, list_key: &[u8; 32], list_index: u32) -> BTreeSet<u32> {
        if list_key != &self.list_key {
            tracing::warn!(
                target = "raven::pir_table",
                encoder = "per-list-node",
                "PerListNodeEncoder received insert for a different list_key; dropped"
            );
            return BTreeSet::new();
        }
        node_affected_shards(self.entries_per_shard, list_index)
    }

    fn label(&self) -> &'static str {
        labels::PER_LIST_NODE
    }
}
