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

    /// Stable key for this cell, matching the `cell-2e<log2>x<bytes>` file naming the
    /// bench binaries already use. A regression gate keys results by name, so two cells
    /// sharing one key would be diffed against each other silently.
    #[must_use]
    pub fn label(self) -> String {
        format!("2e{}x{}", self.entries_log2, self.record_bytes)
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

/// Per-trial timings in microseconds, in trial order.
///
/// A median alone cannot say whether two runs differ or the machine was noisy, so the
/// differ needs the distribution behind it. Empty when the producer did not record it,
/// in which case the differ reports no p-value rather than inventing one.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BenchSamples {
    #[serde(default)]
    pub query_us: Vec<u64>,
    #[serde(default)]
    pub server_us: Vec<u64>,
    #[serde(default)]
    pub client_us: Vec<u64>,
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
    /// Per-trial timings behind the medians above. Defaulted so files written before
    /// the differ needed a distribution still parse.
    #[serde(default)]
    pub samples: BenchSamples,
}

/// The canonical on-disk bench file. Defined here, in the library the benches use,
/// so the producer and `tools/bench-compare` cannot drift: two hand-maintained copies
/// of a cross-boundary schema is the defect a shared definition exists to prevent.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BenchFile {
    #[serde(default)]
    pub hardware: String,
    #[serde(default)]
    pub captured_at: String,
    pub results: Vec<BenchResult>,
}

/// What a measurement counts, and therefore which direction is an improvement.
///
/// The direction is the load-bearing half. A differ that assumes lower-is-better reports
/// every genuine throughput gain as a regression, so a unit-less schema cannot carry a
/// qps metric at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    /// Duration. Lower is better. The default, so pre-`unit` files still parse as ns.
    #[default]
    Nanoseconds,
    /// A size on the wire or on disk. Lower is better.
    Bytes,
    /// Sustained queries per second. **Higher** is better.
    QueriesPerSecond,
}

impl Unit {
    /// Whether a smaller value is the better outcome.
    #[must_use]
    pub const fn lower_is_better(self) -> bool {
        match self {
            Self::Nanoseconds | Self::Bytes => true,
            Self::QueriesPerSecond => false,
        }
    }

    /// Short suffix for human output.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Nanoseconds => "ns",
            Self::Bytes => "B",
            Self::QueriesPerSecond => "qps",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BenchResult {
    pub bench: String,
    /// The measurement. `median_ns` is accepted as an alias so files written before the
    /// unit field carried a name that asserted their unit.
    #[serde(alias = "median_ns")]
    pub value: f64,
    /// Defaults to nanoseconds, which is what every pre-`unit` file meant.
    #[serde(default)]
    pub unit: Unit,
    #[serde(default, alias = "samples_ns")]
    pub samples: Vec<f64>,
}

impl BenchReport {
    /// Flatten into the canonical `BenchResult` list `tools/bench-compare` consumes.
    ///
    /// Each measurement carries its own unit, because the unit decides the sign of a
    /// regression verdict: a rise in `throughput_qps_per_core` is the improvement, while a
    /// rise in a latency or a byte count is the regression. Names are prefixed with the
    /// cell so two cells in one file cannot collide on a key and be diffed against each
    /// other.
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        reason = "byte counts here are wire and hint sizes, orders below f64's 2^53 exact range"
    )]
    pub fn to_results(&self) -> Vec<BenchResult> {
        let key = |metric: &str| format!("{}/{}/{metric}", self.scheme, self.cell.label());
        let ms_to_ns = |ms: f64| ms * 1e6;
        let us_to_ns = |xs: &[u64]| xs.iter().map(|&us| us as f64 * 1e3).collect::<Vec<f64>>();
        let mut out = vec![
            BenchResult {
                bench: key("setup"),
                value: ms_to_ns(self.setup_ms),
                unit: Unit::Nanoseconds,
                samples: Vec::new(),
            },
            BenchResult {
                bench: key("hint_bytes"),
                value: self.hint_bytes as f64,
                unit: Unit::Bytes,
                samples: Vec::new(),
            },
            BenchResult {
                bench: key("query_bytes"),
                value: self.query_bytes as f64,
                unit: Unit::Bytes,
                samples: Vec::new(),
            },
            BenchResult {
                bench: key("response_bytes"),
                value: self.response_bytes as f64,
                unit: Unit::Bytes,
                samples: Vec::new(),
            },
            BenchResult {
                bench: key("query_median"),
                value: ms_to_ns(self.query_ms_median),
                unit: Unit::Nanoseconds,
                samples: us_to_ns(&self.samples.query_us),
            },
            BenchResult {
                bench: key("throughput"),
                value: self.throughput_qps_per_core,
                unit: Unit::QueriesPerSecond,
                samples: Vec::new(),
            },
        ];
        // Absent phases are omitted rather than emitted as zero: a zero would diff as a
        // 100% improvement against a run that did measure them.
        if let Some(ms) = self.server_ms_median {
            out.push(BenchResult {
                bench: key("server_median"),
                value: ms_to_ns(ms),
                unit: Unit::Nanoseconds,
                samples: us_to_ns(&self.samples.server_us),
            });
        }
        if let Some(ms) = self.client_ms_median {
            out.push(BenchResult {
                bench: key("client_median"),
                value: ms_to_ns(ms),
                unit: Unit::Nanoseconds,
                samples: us_to_ns(&self.samples.client_us),
            });
        }
        out
    }
}

impl From<BenchReport> for BenchFile {
    fn from(report: BenchReport) -> Self {
        Self {
            hardware: String::new(),
            captured_at: String::new(),
            results: report.to_results(),
        }
    }
}

impl BenchFile {
    /// Parse either the canonical file or the single-cell report the benches wrote
    /// before the schema was unified.
    ///
    /// Both shapes are on disk and the legacy ones are the only baselines that exist,
    /// so a reader that accepts only the canonical shape has nothing to diff against.
    /// The `results` key decides which shape the file claims to be, so a malformed file
    /// reports the error for the shape it was actually written as.
    ///
    /// # Errors
    /// The `serde_json` error for whichever shape the file claims to be.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        let probe: serde_json::Value = serde_json::from_slice(bytes)?;
        if probe.get("results").is_some() {
            serde_json::from_slice::<Self>(bytes)
        } else {
            serde_json::from_slice::<BenchReport>(bytes).map(Self::from)
        }
    }
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
