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
        // Saturate; a per-sample duration that overflows u64 micros is not a real bench.
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
        // f64 is lossless below 2^53; sample counts and microsecond sums stay well under it.
        #[allow(clippy::cast_precision_loss)]
        Some(sum as f64 / self.samples_us.len() as f64)
    }

    /// `q`-th percentile (`q` in `[0.0, 1.0]`) by nearest-rank on a sorted copy.
    ///
    /// `None` for no samples or non-finite/out-of-range `q`.
    pub fn percentile(&self, q: f64) -> Option<u64> {
        if !q.is_finite() || !(0.0..=1.0).contains(&q) || self.samples_us.is_empty() {
            return None;
        }
        let mut sorted = self.samples_us.clone();
        sorted.sort_unstable();
        // nearest-rank: rank = ceil(q * n), 1-indexed.
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
        for i in 1u64..=100 {
            s.record_us(i);
        }
        // Nearest-rank over 1..=100: pN = value N.
        assert_eq!(s.median(), Some(50));
        assert_eq!(s.p95(), Some(95));
        assert_eq!(s.p99(), Some(99));
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
