//! [`BenchReport`] exporter for the PIR-Eng-Notes v2 reporting schema.
//!
//! Upstream's `*_kb` / `*_mb` fields are binary prefixes: KiB = 1024, MiB = 1024^2.
//! `throughput_gbps` and `rate` are omitted - both need plaintext-space arithmetic the
//! scheme crate owns.

use serde::{Deserialize, Serialize};

use crate::{BenchReport, GridCell};

/// One entry in the upstream `configs` array; mirrors `schema_v2.jsonc`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PirEngNotesConfig {
    /// Entry count and size combined, e.g. `"2^20x256B"`.
    pub config_id: String,
    /// Entry count.
    pub num_entries: u64,
    /// Entry-count label, e.g. `"2^20"`.
    pub num_entries_label: String,
    /// Per-row size in bytes.
    pub entry_size_bytes: u64,
    /// Record-size label, e.g. `"256 B"`.
    pub entry_size_label: String,
}

impl From<GridCell> for PirEngNotesConfig {
    fn from(cell: GridCell) -> Self {
        Self {
            config_id: format_config_id(cell),
            num_entries: cell.entries(),
            num_entries_label: format_entries_label(cell),
            entry_size_bytes: u64::from(cell.record_bytes),
            entry_size_label: format_record_label(cell),
        }
    }
}

/// One row in the upstream `benchmarks` array; unobservable metrics ship as `None`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PirEngNotesBenchmark {
    /// Scheme variant.
    pub variant: String,
    /// Key into the configs array.
    pub config_id: String,
    /// Provenance of the row.
    pub source_ref: String,
    /// One of `"single"`, `"multi"`, `"gpu"`.
    pub threading: String,
    /// Metrics sub-object.
    pub metrics: PirEngNotesMetrics,
}

/// Upstream `metrics` sub-object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PirEngNotesMetrics {
    /// Per-query request size, KiB.
    pub query_size_kb: f64,
    /// Per-query response size, KiB.
    pub response_size_kb: f64,
    /// Median end-to-end query time, milliseconds.
    pub query_time_ms: f64,
    /// Median server compute time, milliseconds; `None` when inseparable from client work.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_time_ms: Option<f64>,
    /// Median client encode plus decode time, milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_time_ms: Option<f64>,
    /// Hint size in MiB.
    pub client_storage_mb: f64,
    /// Server preprocessing time in milliseconds.
    pub client_preprocessing_time_ms: f64,
    /// Sustained throughput, queries per second per core.
    pub throughput_qps_per_core: f64,
}

impl BenchReport {
    /// The upstream-shaped config and benchmark pair for this report.
    #[must_use]
    pub fn to_pir_eng_notes(&self) -> (PirEngNotesConfig, PirEngNotesBenchmark) {
        let config = PirEngNotesConfig::from(self.cell);
        let metrics = PirEngNotesMetrics {
            query_size_kb: bytes_to_kib(self.query_bytes),
            response_size_kb: bytes_to_kib(self.response_bytes),
            query_time_ms: self.query_ms_median,
            server_time_ms: self.server_ms_median,
            client_time_ms: self.client_ms_median,
            client_storage_mb: bytes_to_mib(self.hint_bytes),
            client_preprocessing_time_ms: self.setup_ms,
            throughput_qps_per_core: self.throughput_qps_per_core,
        };
        let benchmark = PirEngNotesBenchmark {
            variant: self.scheme.clone(),
            config_id: config.config_id.clone(),
            source_ref: "raven-bench internal".to_owned(),
            threading: "single".to_owned(),
            metrics,
        };
        (config, benchmark)
    }
}

fn format_config_id(cell: GridCell) -> String {
    format!("2^{}x{}B", cell.entries_log2, cell.record_bytes)
}

fn format_entries_label(cell: GridCell) -> String {
    format!("2^{}", cell.entries_log2)
}

fn format_record_label(cell: GridCell) -> String {
    format!("{} B", cell.record_bytes)
}

#[allow(clippy::cast_precision_loss)]
fn bytes_to_kib(bytes: u64) -> f64 {
    bytes as f64 / 1024.0
}

#[allow(clippy::cast_precision_loss)]
fn bytes_to_mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> BenchReport {
        BenchReport {
            scheme: "example-v0.1".to_owned(),
            cell: GridCell {
                entries_log2: 20,
                record_bytes: 256,
            },
            setup_ms: 1260.0,
            hint_bytes: 3 * 1024 * 1024 + 900 * 1024, // ~3.88 MiB
            query_bytes: 4096,
            response_bytes: 2048,
            query_ms_median: 1.26,
            server_ms_median: None,
            client_ms_median: None,
            throughput_qps_per_core: 793.65,
            measured_queries: 256,
        }
    }

    #[test]
    fn config_from_2_20_x_256_matches_upstream_labels() {
        let cell = GridCell {
            entries_log2: 20,
            record_bytes: 256,
        };
        let cfg = PirEngNotesConfig::from(cell);
        assert_eq!(cfg.config_id, "2^20x256B");
        assert_eq!(cfg.num_entries, 1 << 20);
        assert_eq!(cfg.num_entries_label, "2^20");
        assert_eq!(cfg.entry_size_bytes, 256);
        assert_eq!(cfg.entry_size_label, "256 B");
    }

    #[test]
    fn config_from_2_24_x_8_matches_upstream_labels() {
        let cell = GridCell {
            entries_log2: 24,
            record_bytes: 8,
        };
        let cfg = PirEngNotesConfig::from(cell);
        assert_eq!(cfg.config_id, "2^24x8B");
        assert_eq!(cfg.num_entries, 1 << 24);
        assert_eq!(cfg.num_entries_label, "2^24");
        assert_eq!(cfg.entry_size_bytes, 8);
        assert_eq!(cfg.entry_size_label, "8 B");
    }

    #[test]
    fn report_to_pir_eng_notes_converts_units() {
        let report = sample_report();
        let (config, benchmark) = report.to_pir_eng_notes();

        assert_eq!(config.config_id, "2^20x256B");
        assert_eq!(benchmark.variant, "example-v0.1");
        assert_eq!(benchmark.config_id, "2^20x256B");
        assert_eq!(benchmark.source_ref, "raven-bench internal");
        assert_eq!(benchmark.threading, "single");

        let m = &benchmark.metrics;
        assert!((m.query_size_kb - 4.0).abs() < 1e-9);
        assert!((m.response_size_kb - 2.0).abs() < 1e-9);
        assert!((m.query_time_ms - 1.26).abs() < 1e-9);
        assert!(m.server_time_ms.is_none());
        assert!(m.client_time_ms.is_none());
        assert!((m.client_storage_mb - 3.878_906_25).abs() < 1e-9);
        assert!((m.client_preprocessing_time_ms - 1260.0).abs() < 1e-9);
    }

    #[test]
    fn missing_timings_serialize_as_absent_not_null() {
        let report = sample_report();
        let (_cfg, bench) = report.to_pir_eng_notes();
        let json = serde_json::to_string(&bench).expect("serialize");
        assert!(
            !json.contains("server_time_ms"),
            "absent optional fields must be omitted, not emitted as null: {json}"
        );
        assert!(!json.contains("client_time_ms"));
    }

    #[test]
    fn populated_timings_appear_in_json() {
        let mut report = sample_report();
        report.server_ms_median = Some(1.0);
        report.client_ms_median = Some(0.2);
        let (_cfg, bench) = report.to_pir_eng_notes();
        let json = serde_json::to_string(&bench).expect("serialize");
        assert!(json.contains("\"server_time_ms\":1.0"));
        assert!(json.contains("\"client_time_ms\":0.2"));
    }

    // Fails if upstream renames or drops a field these types depend on.
    #[test]
    fn deserialize_upstream_shaped_config_fragment() {
        let json = r#"{
            "config_id": "2^20x256B",
            "num_entries": 1048576,
            "num_entries_label": "2^20",
            "entry_size_bytes": 256,
            "entry_size_label": "256 B"
        }"#;
        let cfg: PirEngNotesConfig = serde_json::from_str(json).expect("deserialize config");
        assert_eq!(cfg.config_id, "2^20x256B");
        assert_eq!(cfg.num_entries, 1 << 20);
        assert_eq!(cfg.num_entries_label, "2^20");
        assert_eq!(cfg.entry_size_bytes, 256);
        assert_eq!(cfg.entry_size_label, "256 B");
    }

    #[test]
    fn deserialize_upstream_shaped_benchmark_fragment_without_optional_timings() {
        let json = r#"{
            "variant": "Example",
            "config_id": "2^20x256B",
            "source_ref": "upstream fixture",
            "threading": "single",
            "metrics": {
                "query_size_kb": 4.0,
                "response_size_kb": 2.0,
                "query_time_ms": 1.26,
                "client_storage_mb": 3.88,
                "client_preprocessing_time_ms": 1260.0,
                "throughput_qps_per_core": 793.65
            }
        }"#;
        let b: PirEngNotesBenchmark = serde_json::from_str(json).expect("deserialize benchmark");
        assert_eq!(b.variant, "Example");
        assert_eq!(b.config_id, "2^20x256B");
        assert_eq!(b.threading, "single");
        assert!(b.metrics.server_time_ms.is_none());
        assert!(b.metrics.client_time_ms.is_none());
        assert!((b.metrics.query_size_kb - 4.0).abs() < 1e-9);
    }

    #[test]
    fn roundtrip_benchmark_through_json_preserves_values() {
        let report = sample_report();
        let (_cfg, benchmark) = report.to_pir_eng_notes();
        let as_json = serde_json::to_string(&benchmark).expect("serialize");
        let back: PirEngNotesBenchmark = serde_json::from_str(&as_json).expect("deserialize");
        assert_eq!(benchmark, back);
    }
}
