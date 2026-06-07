//! Scheme-agnostic bench driver. Server-only (uses
//! `std::time::Instant`); the `lib` target compiles to wasm32
//! but the harness itself is not exercised there.

use std::time::{Duration, Instant};

use crate::timing::PhaseTimings;
use crate::{BenchReport, GridCell};

/// A scheme plugged into the bench harness.
pub trait BenchScheme {
    fn name(&self) -> &str;

    /// Hint bytes shipped once per scheme instance; 0 for hintless.
    fn hint_bytes(&self) -> u64;

    /// One round-trip; returns `(query_bytes, response_bytes)`.
    fn query(&self, index: u64) -> QuerySizes;
}

#[derive(Debug, Clone, Copy)]
pub struct QuerySizes {
    pub query_bytes: u64,
    pub response_bytes: u64,
}

/// Index pattern for measured queries.
#[derive(Debug, Clone, Copy)]
pub enum IndexPattern {
    Sequential,
    Stride {
        /// Should be coprime to `entries` for uniform coverage.
        stride: u64,
    },
    /// SplitMix64-derived (Vigna, BigCrush-passing).
    Randomised {
        seed: u64,
    },
}

impl Default for IndexPattern {
    fn default() -> Self {
        Self::Randomised { seed: 0 }
    }
}

impl IndexPattern {
    #[must_use]
    pub fn index_for(&self, trial_idx: u64, entries: u64) -> u64 {
        let n = entries.max(1);
        match *self {
            Self::Sequential => trial_idx % n,
            Self::Stride { stride } => trial_idx.wrapping_mul(stride) % n,
            Self::Randomised { seed } => {
                let mut h = seed.wrapping_add(trial_idx);
                h = (h ^ (h >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                h = (h ^ (h >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                h ^= h >> 31;
                h % n
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HarnessConfig {
    pub warmup_queries: u32,
    pub measured_queries: u32,
    /// Wall-clock budget; harness stops at `measured_queries` or
    /// `budget`, whichever first.
    pub budget: Duration,
    pub index_pattern: IndexPattern,
}

impl Default for HarnessConfig {
    fn default() -> Self {
        Self {
            warmup_queries: 16,
            measured_queries: 256,
            budget: Duration::from_secs(60),
            index_pattern: IndexPattern::default(),
        }
    }
}

/// Drive `scheme` through warmup + measured queries against `cell`,
/// summarize into a `BenchReport`. `setup_time` is supplied by the
/// caller; harness only times queries.
pub fn run_cell<S: BenchScheme>(
    scheme: &S,
    cell: GridCell,
    setup_time: Duration,
    config: HarnessConfig,
) -> BenchReport {
    let mut timings = PhaseTimings::new();
    let mut last_query_bytes: u64 = 0;
    let mut last_response_bytes: u64 = 0;
    let entries = cell.entries();

    for i in 0..config.warmup_queries {
        let idx = config.index_pattern.index_for(u64::from(i), entries);
        let _ = scheme.query(idx);
    }

    let measured_start = Instant::now();
    let mut completed: u64 = 0;
    // Past the warmup-trial range so measured queries hit fresh indices.
    let measured_start_trial = u64::from(config.warmup_queries);
    for i in 0..config.measured_queries {
        if measured_start.elapsed() >= config.budget {
            break;
        }
        let trial_idx = measured_start_trial.wrapping_add(u64::from(i));
        let idx = config.index_pattern.index_for(trial_idx, entries);
        let query_start = Instant::now();
        let sizes = scheme.query(idx);
        let query_time = query_start.elapsed();
        timings.record("query", query_time);
        last_query_bytes = sizes.query_bytes;
        last_response_bytes = sizes.response_bytes;
        completed += 1;
    }
    let measured_elapsed = measured_start.elapsed();

    let query_samples = timings.get("query");
    #[allow(clippy::cast_precision_loss)]
    let query_ms_median = query_samples
        .and_then(crate::timing::PhaseSamples::median)
        .map_or(0.0, |us| us as f64 / 1000.0);

    // Sustained throughput: completed queries / wall time (not 1/median).
    #[allow(clippy::cast_precision_loss)]
    let throughput = if measured_elapsed.as_secs_f64() > 0.0 {
        completed as f64 / measured_elapsed.as_secs_f64()
    } else {
        0.0
    };

    BenchReport {
        scheme: scheme.name().to_owned(),
        cell,
        setup_ms: duration_to_ms(setup_time),
        hint_bytes: scheme.hint_bytes(),
        query_bytes: last_query_bytes,
        response_bytes: last_response_bytes,
        query_ms_median,
        // The single-process harness can't separate phases.
        server_ms_median: None,
        client_ms_median: None,
        throughput_qps_per_core: throughput,
        measured_queries: completed,
    }
}

#[allow(clippy::cast_precision_loss)]
fn duration_to_ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeScheme {
        query_delay: Duration,
        qb: u64,
        rb: u64,
    }

    impl BenchScheme for FakeScheme {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn hint_bytes(&self) -> u64 {
            42
        }
        fn query(&self, _index: u64) -> QuerySizes {
            // Busy-wait rather than sleep so OS scheduling jitter can't flake the median.
            let start = Instant::now();
            while start.elapsed() < self.query_delay {
                std::hint::spin_loop();
            }
            QuerySizes {
                query_bytes: self.qb,
                response_bytes: self.rb,
            }
        }
    }

    #[test]
    fn harness_records_bytes_and_query_count() {
        let scheme = FakeScheme {
            query_delay: Duration::from_micros(50),
            qb: 100,
            rb: 2048,
        };
        let cell = GridCell {
            entries_log2: 20,
            record_bytes: 256,
        };
        let report = run_cell(
            &scheme,
            cell,
            Duration::from_millis(123),
            HarnessConfig {
                warmup_queries: 2,
                measured_queries: 10,
                budget: Duration::from_secs(5),
                index_pattern: IndexPattern::Sequential,
            },
        );
        assert_eq!(report.scheme, "fake");
        assert_eq!(report.hint_bytes, 42);
        assert_eq!(report.query_bytes, 100);
        assert_eq!(report.response_bytes, 2048);
        assert_eq!(report.measured_queries, 10);
        assert!((report.setup_ms - 123.0).abs() < 1.0);
        assert!(report.query_ms_median > 0.0);
        assert!(report.server_ms_median.is_none());
        assert!(report.client_ms_median.is_none());
        assert!(report.throughput_qps_per_core > 0.0);
    }

    #[test]
    fn harness_respects_wall_clock_budget() {
        let scheme = FakeScheme {
            query_delay: Duration::from_millis(5),
            qb: 1,
            rb: 1,
        };
        let cell = GridCell {
            entries_log2: 20,
            record_bytes: 8,
        };
        let report = run_cell(
            &scheme,
            cell,
            Duration::ZERO,
            HarnessConfig {
                warmup_queries: 0,
                measured_queries: 1000,
                budget: Duration::from_millis(60),
                index_pattern: IndexPattern::default(),
            },
        );
        assert!(
            report.measured_queries < 1000,
            "budget should stop us before 1000 queries; got {}",
            report.measured_queries
        );
        assert!(report.measured_queries > 0);
    }

    #[test]
    fn index_pattern_sequential_is_monotone_mod_n() {
        let p = IndexPattern::Sequential;
        for i in 0u64..10 {
            assert_eq!(p.index_for(i, 7), i % 7);
        }
    }

    #[test]
    fn index_pattern_stride_covers_db_when_coprime() {
        let p = IndexPattern::Stride { stride: 7 };
        let n = 16u64;
        let covered: std::collections::BTreeSet<u64> = (0..n).map(|i| p.index_for(i, n)).collect();
        assert_eq!(
            covered.len() as u64,
            n,
            "coprime stride should cover every index"
        );
    }

    #[test]
    fn index_pattern_randomised_is_deterministic_in_seed() {
        let p1 = IndexPattern::Randomised { seed: 42 };
        let p2 = IndexPattern::Randomised { seed: 42 };
        let p3 = IndexPattern::Randomised { seed: 43 };
        for i in 0u64..16 {
            assert_eq!(p1.index_for(i, 1_000_000), p2.index_for(i, 1_000_000));
        }
        // Different seeds should produce different sequences (with
        // overwhelming probability at this sample size).
        let diffs = (0u64..16)
            .filter(|&i| p1.index_for(i, 1_000_000) != p3.index_for(i, 1_000_000))
            .count();
        assert!(diffs > 8);
    }

    struct RecordingScheme {
        indices: std::cell::RefCell<Vec<u64>>,
    }

    impl RecordingScheme {
        fn new() -> Self {
            Self {
                indices: std::cell::RefCell::new(Vec::new()),
            }
        }
    }

    impl BenchScheme for RecordingScheme {
        fn name(&self) -> &'static str {
            "recorder"
        }
        fn hint_bytes(&self) -> u64 {
            0
        }
        fn query(&self, index: u64) -> QuerySizes {
            self.indices.borrow_mut().push(index);
            QuerySizes {
                query_bytes: 1,
                response_bytes: 1,
            }
        }
    }

    #[test]
    fn warmup_and_measured_indices_are_disjoint_under_sequential_pattern() {
        // Worst case: trial_idx i -> DB index i, so a measured loop restarting at 0 would re-prime warmup caches.
        let scheme = RecordingScheme::new();
        let cell = GridCell {
            entries_log2: 20,
            record_bytes: 8,
        };
        let warmup = 16u32;
        let measured = 64u32;
        let _report = run_cell(
            &scheme,
            cell,
            Duration::ZERO,
            HarnessConfig {
                warmup_queries: warmup,
                measured_queries: measured,
                budget: Duration::from_secs(5),
                index_pattern: IndexPattern::Sequential,
            },
        );

        let indices = scheme.indices.borrow().clone();
        assert_eq!(indices.len(), (warmup + measured) as usize);
        let warmup_set: std::collections::BTreeSet<u64> =
            indices[..warmup as usize].iter().copied().collect();
        let measured_set: std::collections::BTreeSet<u64> =
            indices[warmup as usize..].iter().copied().collect();
        let overlap: Vec<u64> = warmup_set.intersection(&measured_set).copied().collect();
        assert!(
            overlap.is_empty(),
            "warmup ({warmup_set:?}) and measured ({measured_set:?}) index sets must not overlap; \
             overlap = {overlap:?}"
        );
    }

    #[test]
    fn warmup_and_measured_indices_are_disjoint_under_randomised_pattern() {
        // Mapping keys on trial_idx, so shifting the measured start by warmup_queries yields a disjoint prefix at this scale.
        let scheme = RecordingScheme::new();
        let cell = GridCell {
            entries_log2: 20,
            record_bytes: 8,
        };
        let _report = run_cell(
            &scheme,
            cell,
            Duration::ZERO,
            HarnessConfig {
                warmup_queries: 8,
                measured_queries: 32,
                budget: Duration::from_secs(5),
                index_pattern: IndexPattern::Randomised { seed: 0xBEEF },
            },
        );
        let indices = scheme.indices.borrow().clone();
        let warmup_set: std::collections::BTreeSet<u64> = indices[..8].iter().copied().collect();
        let measured_set: std::collections::BTreeSet<u64> = indices[8..].iter().copied().collect();
        let overlap: Vec<u64> = warmup_set.intersection(&measured_set).copied().collect();
        assert!(
            overlap.is_empty(),
            "randomised warmup/measured overlap = {overlap:?}"
        );
    }

    #[test]
    fn harness_default_index_pattern_is_randomised() {
        // Guards against the default reverting to the sequential 0,1,2,... artefact.
        let cfg = HarnessConfig::default();
        match cfg.index_pattern {
            IndexPattern::Randomised { .. } => {}
            other => panic!("default index pattern regressed to {other:?}"),
        }
    }
}
