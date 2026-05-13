//! Percentile-aware per-phase timing: min / median / p95 / p99 / mean.
//!
//! Samples are held unsorted in a `Vec<u64>` (microseconds); percentile
//! queries sort a clone. `record` is O(1); percentile queries are O(n log n).

use std::collections::BTreeMap;

/// One phase's worth of timing samples, in microseconds.
#[derive(Debug, Clone, Default)]
pub struct PhaseSamples {
    samples_us: Vec<u64>,
}

impl PhaseSamples {
    /// Record one sample, in microseconds.
    #[inline]
    pub fn record_us(&mut self, micros: u64) {
        self.samples_us.push(micros);
    }

    /// Record one sample from a `std::time::Duration`.
    #[inline]
    pub fn record(&mut self, d: std::time::Duration) {
        // Saturate rather than overflow. A bench that runs for 500_000+ years
        // per sample has bigger problems than a rollover here.
        let micros = u64::try_from(d.as_micros()).unwrap_or(u64::MAX);
        self.record_us(micros);
    }

    /// Number of samples recorded.
    #[inline]
    pub fn count(&self) -> usize {
        self.samples_us.len()
    }

    /// Minimum sample, or `None` if no samples recorded.
    pub fn min(&self) -> Option<u64> {
        self.samples_us.iter().copied().min()
    }

    /// Maximum sample, or `None` if no samples recorded.
    pub fn max(&self) -> Option<u64> {
        self.samples_us.iter().copied().max()
    }

    /// Arithmetic mean, or `None` if no samples recorded.
    pub fn mean(&self) -> Option<f64> {
        if self.samples_us.is_empty() {
            return None;
        }
        let sum: u128 = self.samples_us.iter().map(|&x| u128::from(x)).sum();
        // f64 conversion is lossless for counts up to 2^53 and sums up to ~1.8e19
        // microseconds, which is ~600_000 years. Both are fine for bench use.
        #[allow(clippy::cast_precision_loss)]
        Some(sum as f64 / self.samples_us.len() as f64)
    }

    /// Return the `q`-th percentile (`q ∈ [0.0, 1.0]`) using nearest-rank
    /// selection on a sorted copy of the samples.
    ///
    /// Returns `None` if no samples recorded; panics only if `q` is NaN, which
    /// the `q.is_finite()` guard protects against by returning `None`.
    pub fn percentile(&self, q: f64) -> Option<u64> {
        if !q.is_finite() || !(0.0..=1.0).contains(&q) || self.samples_us.is_empty() {
            return None;
        }
        let mut sorted = self.samples_us.clone();
        sorted.sort_unstable();
        // nearest-rank: rank = ceil(q * n), 1-indexed. Sample counts we care
        // about are well under 2^52, so usize -> f64 precision loss is not a
        // real hazard here.
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let rank = (q * sorted.len() as f64).ceil() as usize;
        let idx = rank.saturating_sub(1).min(sorted.len().saturating_sub(1));
        sorted.get(idx).copied()
    }

    /// Convenience accessor. 50th percentile.
    pub fn median(&self) -> Option<u64> {
        self.percentile(0.50)
    }

    /// Convenience accessor. 95th percentile.
    pub fn p95(&self) -> Option<u64> {
        self.percentile(0.95)
    }

    /// Convenience accessor. 99th percentile.
    pub fn p99(&self) -> Option<u64> {
        self.percentile(0.99)
    }
}

/// A set of named [`PhaseSamples`] buckets.
#[derive(Debug, Default)]
pub struct PhaseTimings {
    phases: BTreeMap<String, PhaseSamples>,
}

impl PhaseTimings {
    /// Create an empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a sample for the named phase, in microseconds.
    pub fn record_us(&mut self, phase: &str, micros: u64) {
        self.phases
            .entry(phase.to_owned())
            .or_default()
            .record_us(micros);
    }

    /// Record a sample from a [`std::time::Duration`].
    pub fn record(&mut self, phase: &str, d: std::time::Duration) {
        self.phases.entry(phase.to_owned()).or_default().record(d);
    }

    /// Borrow the samples for one phase.
    pub fn get(&self, phase: &str) -> Option<&PhaseSamples> {
        self.phases.get(phase)
    }

    /// Iterate phases in lexicographic order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &PhaseSamples)> {
        self.phases.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Number of distinct phases recorded.
    pub fn len(&self) -> usize {
        self.phases.len()
    }

    /// Returns whether no phases have been recorded.
    pub fn is_empty(&self) -> bool {
        self.phases.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_samples_have_no_statistics() {
        let s = PhaseSamples::default();
        assert_eq!(s.count(), 0);
        assert!(s.min().is_none());
        assert!(s.max().is_none());
        assert!(s.mean().is_none());
        assert!(s.median().is_none());
        assert!(s.p95().is_none());
        assert!(s.p99().is_none());
    }

    #[test]
    fn single_sample_populates_every_statistic() {
        let mut s = PhaseSamples::default();
        s.record_us(42);
        assert_eq!(s.count(), 1);
        assert_eq!(s.min(), Some(42));
        assert_eq!(s.max(), Some(42));
        assert_eq!(s.median(), Some(42));
        assert_eq!(s.mean(), Some(42.0));
    }

    #[test]
    fn percentiles_match_nearest_rank_definition() {
        let mut s = PhaseSamples::default();
        // Samples 1..=100 inclusive.
        for i in 1u64..=100 {
            s.record_us(i);
        }
        // Nearest-rank: p50 = sample at rank ceil(0.5*100)=50 (value 50).
        assert_eq!(s.median(), Some(50));
        // p95 = rank 95 = value 95
        assert_eq!(s.p95(), Some(95));
        // p99 = rank 99 = value 99
        assert_eq!(s.p99(), Some(99));
        // min/max are deterministic
        assert_eq!(s.min(), Some(1));
        assert_eq!(s.max(), Some(100));
    }

    #[test]
    fn percentile_with_q_out_of_range_returns_none() {
        let mut s = PhaseSamples::default();
        s.record_us(10);
        assert!(s.percentile(-0.1).is_none());
        assert!(s.percentile(1.5).is_none());
        assert!(s.percentile(f64::NAN).is_none());
    }

    #[test]
    fn phase_timings_separate_named_buckets() {
        let mut t = PhaseTimings::new();
        t.record_us("setup", 100);
        t.record_us("setup", 200);
        t.record_us("query", 10);
        assert_eq!(t.len(), 2);
        assert_eq!(t.get("setup").expect("setup present").count(), 2);
        assert_eq!(t.get("query").expect("query present").count(), 1);
        assert!(t.get("missing").is_none());
    }

    #[test]
    fn phase_iter_is_lexicographic() {
        let mut t = PhaseTimings::new();
        t.record_us("zebra", 1);
        t.record_us("alpha", 1);
        t.record_us("middle", 1);
        let names: Vec<&str> = t.iter().map(|(k, _)| k).collect();
        assert_eq!(names, vec!["alpha", "middle", "zebra"]);
    }
}
