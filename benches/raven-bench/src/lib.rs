//! Cross-scheme bench harness. All schemes report against the
//! same 3x3 grid `(entries, record_size)`.

#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]
#![allow(missing_docs)]

pub mod frame;
pub mod harness;
pub mod noise;
pub mod pir_eng_notes;
pub mod timing;

use serde::{Deserialize, Serialize};

pub const GRID_ENTRY_LOG2: [u8; 3] = [20, 24, 28];
pub const GRID_RECORD_BYTES: [u32; 3] = [8, 32, 256];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GridCell {
    pub entries_log2: u8,
    pub record_bytes: u32,
}

impl GridCell {
    #[inline]
    pub const fn entries(self) -> u64 {
        1u64 << self.entries_log2
    }

    #[inline]
    pub const fn raw_db_bytes(self) -> u128 {
        (self.entries() as u128) * (self.record_bytes as u128)
    }
}

pub fn grid_cells() -> impl Iterator<Item = GridCell> {
    GRID_ENTRY_LOG2.into_iter().flat_map(|e| {
        GRID_RECORD_BYTES.into_iter().map(move |r| GridCell {
            entries_log2: e,
            record_bytes: r,
        })
    })
}

/// Bench result for one cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchReport {
    pub scheme: String,
    pub cell: GridCell,
    /// End-to-end setup, ms.
    pub setup_ms: f64,
    /// Client hint shipped once per scheme instance; 0 for hintless.
    pub hint_bytes: u64,
    pub query_bytes: u64,
    pub response_bytes: u64,
    /// Median end-to-end query latency, ms.
    pub query_ms_median: f64,
    /// Median server-side compute, ms. `None` when the harness can't
    /// separate server from client.
    pub server_ms_median: Option<f64>,
    /// Median client query-gen + decode, ms.
    pub client_ms_median: Option<f64>,
    /// Sustained throughput, queries/sec/core.
    pub throughput_qps_per_core: f64,
    pub measured_queries: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grid_has_exactly_nine_cells() {
        assert_eq!(grid_cells().count(), 9);
    }

    #[test]
    fn grid_starts_at_smallest_and_ends_at_largest_cell() {
        let first = grid_cells().next().expect("grid not empty");
        assert_eq!(first.entries_log2, 20);
        assert_eq!(first.record_bytes, 8);

        let last = grid_cells().last().expect("grid not empty");
        assert_eq!(last.entries_log2, 28);
        assert_eq!(last.record_bytes, 256);
        assert_eq!(last.entries(), 1u64 << 28);
    }

    #[test]
    fn raw_db_bytes_matches_entries_times_record_bytes() {
        let cell = GridCell {
            entries_log2: 20,
            record_bytes: 256,
        };
        assert_eq!(cell.raw_db_bytes(), (1u128 << 20) * 256);
    }
}
