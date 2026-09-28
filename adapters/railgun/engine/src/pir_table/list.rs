//! The per-list encoder keyed on `list_key`.

use std::collections::BTreeSet;

use raven_railgun_core::{AdapterError, POIStatus, Result};

use super::{labels, PirTableEncoder, LEAVES_PER_TREE, NODE_HASH_BYTES};
use crate::inspire::LogicalLeafStore;
use crate::orchestrator::hex_lower_32;

/// Status byte of every row that carries no verdict.
///
/// Must not be 0: 0 is `Valid`, the verdict that authorizes a spend, so defaulting to
/// it fails open.
pub const ABSENT_STATUS_BYTE: u8 = POIStatus::Missing.wire_byte();
/// Status byte of every filled row. The byte is kept so the row layout stays as shipped, and
/// derived from presence: a row the list holds is a member of it.
pub const FILLED_STATUS_BYTE: u8 = POIStatus::Valid.wire_byte();
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
                *status = FILLED_STATUS_BYTE;
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
