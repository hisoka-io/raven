//! Empirical noise-validation for lattice-based PIR.
//!
//! SimplePIR-family schemes can fail silently: a query whose accumulated
//! noise exceeds the budget decodes to the wrong plaintext with no error.
//! Paper-derived bounds aren't always tight in practice. Schemes implement
//! [`NoiseValidatable`], the harness runs `N` trials, and
//! [`NoiseBenchReport`] reports the observed silent-failure rate with a
//! Wilson upper bound.

use serde::{Deserialize, Serialize};

use crate::GridCell;

/// Per-trial outcome reported by a [`NoiseValidatable`] implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrialOutcome {
    /// The decoded value matched the reference.
    Correct,
    /// The decoded value differed from the reference. The scheme did not
    /// detect this. That is precisely the silent-failure mode we measure.
    SilentMismatch,
    /// The scheme surfaced an explicit error (query failed, decode rejected,
    /// etc.). Counted separately because it is NOT a silent failure.
    ExplicitError,
}

/// Inputs passed to each trial. The scheme uses these to derive any internal
/// randomness deterministically so failing trials can be reproduced.
#[derive(Debug, Clone, Copy)]
pub struct TrialInput {
    /// Monotonic trial index in `[0, config.trials)`.
    pub trial_idx: u64,
    /// Caller-supplied seed for this trial. Schemes should derive all internal
    /// randomness from this seed (e.g. `ChaCha20Rng::seed_from_u64(seed)`) so
    /// that reproducing a failing trial requires only the seed.
    pub seed: u64,
    /// Index the client queries on this trial.
    pub index: u64,
}

/// A PIR scheme under noise-validation bench.
///
/// The scheme is set up once (hint, parameters) and then queried
/// `config.trials` times. The harness never inspects the scheme's internal
/// noise accounting. It only cares whether each trial returned the correct
/// plaintext.
pub trait NoiseValidatable {
    /// Execute one trial end-to-end (query generation, server response,
    /// client decode, comparison against the reference oracle).
    ///
    /// Implementations MUST be deterministic in `TrialInput::seed` so the
    /// harness can reproduce mismatches by seed alone.
    fn run_trial(&self, input: TrialInput) -> TrialOutcome;
}

/// Caller-supplied configuration for a noise-validation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoiseBenchConfig {
    /// Grid cell under measurement (db shape).
    pub cell: GridCell,
    /// Number of trials to run. Higher is more statistical power but more
    /// wall time. A typical default is `1_000_000` per cell.
    pub trials: u64,
    /// Base seed. Trial `i` uses seed `base_seed ^ (i as u64).rotate_left(32)`
    /// so seeds are independent but reproducible.
    pub base_seed: u64,
    /// Index stride pattern: if `Some(k)`, trial `i` queries index `(i * k) mod n`.
    /// If `None`, the harness picks uniformly random indices derived from `base_seed`.
    /// Deterministic stride is preferred when reproducing specific failures.
    pub index_stride: Option<u64>,
}

impl NoiseBenchConfig {
    /// Derive the seed to pass into trial `i`.
    #[inline]
    #[must_use]
    pub fn seed_for(&self, trial_idx: u64) -> u64 {
        self.base_seed ^ trial_idx.rotate_left(32)
    }

    /// Derive the DB index to query on trial `i`.
    #[inline]
    #[must_use]
    pub fn index_for(&self, trial_idx: u64) -> u64 {
        let n = self.cell.entries();
        match self.index_stride {
            Some(stride) if stride != 0 => trial_idx.wrapping_mul(stride) % n.max(1),
            _ => {
                // SplitMix-style stride from the base seed; avoids needing an
                // extra RNG when the caller just wants "something reproducible".
                let mut h = self.base_seed ^ trial_idx;
                h = h.wrapping_mul(0x9E37_79B9_7F4A_7C15);
                h ^= h >> 32;
                h % n.max(1)
            }
        }
    }
}

/// Result of a noise-validation run.
///
/// Reports raw counts plus a Wilson-interval upper bound on the silent-mismatch
/// rate, which is what drives the risk-register cap. Wilson is used rather
/// than normal-approximation because the observed failure count can be zero
/// and Wilson degrades gracefully.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoiseBenchReport {
    /// Configuration the run used.
    pub config: NoiseBenchConfig,
    /// Trials completed.
    pub trials: u64,
    /// Number of silent mismatches (`TrialOutcome::SilentMismatch`).
    pub silent_mismatches: u64,
    /// Number of explicit errors (`TrialOutcome::ExplicitError`).
    pub explicit_errors: u64,
    /// Point estimate of silent-failure rate: `silent_mismatches / trials`.
    pub silent_failure_rate: f64,
    /// Wilson upper confidence bound on the silent-failure rate at z = 1.96
    /// (i.e. A one-sided upper 97.5% confidence, equivalently the upper end
    /// of a two-sided 95% interval). The more conservative choice of z keeps
    /// the cap safer when observed failure counts are small.
    pub silent_failure_wilson_upper_97_5: f64,
}

impl NoiseBenchReport {
    /// Build a report from raw counts + the supplied configuration.
    ///
    /// `trials` MUST be positive; callers are responsible for not producing
    /// empty runs.
    #[must_use]
    pub fn summarize(config: NoiseBenchConfig, trials: u64, silent: u64, explicit: u64) -> Self {
        // Guard: the harness must never submit zero trials.
        let trials = trials.max(1);
        let silent = silent.min(trials);
        #[allow(clippy::cast_precision_loss)]
        let rate = silent as f64 / trials as f64;
        let wilson = wilson_upper_95(silent, trials);
        Self {
            config,
            trials,
            silent_mismatches: silent,
            explicit_errors: explicit,
            silent_failure_rate: rate,
            silent_failure_wilson_upper_97_5: wilson,
        }
    }
}

/// Standard normal quantile for a two-sided 95% confidence interval.
const WILSON_Z_95: f64 = 1.96;

/// Wilson score interval, upper bound at 95% confidence.
///
/// Defined as (p + z²/(2n) + z·sqrt(p(1-p)/n + z²/(4n²))) / (1 + z²/n)
/// with z = 1.96. See <https://en.wikipedia.org/wiki/Binomial_proportion_confidence_interval#Wilson_score_interval>.
#[allow(clippy::cast_precision_loss)]
fn wilson_upper_95(successes: u64, trials: u64) -> f64 {
    if trials == 0 {
        return 1.0;
    }
    let z = WILSON_Z_95;
    let n = trials as f64;
    let p = successes as f64 / n;
    let denom = 1.0 + (z * z) / n;
    let centre = p + (z * z) / (2.0 * n);
    let radicand = (p * (1.0 - p) / n) + (z * z) / (4.0 * n * n);
    let spread = z * radicand.sqrt();
    ((centre + spread) / denom).clamp(0.0, 1.0)
}

/// Drive a noise-validation bench end-to-end against any [`NoiseValidatable`]
/// scheme. Returns a [`NoiseBenchReport`].
pub fn run_noise_bench<S: NoiseValidatable>(
    scheme: &S,
    config: NoiseBenchConfig,
) -> NoiseBenchReport {
    let mut silent = 0u64;
    let mut explicit = 0u64;
    let trials = config.trials;
    for i in 0..trials {
        let outcome = scheme.run_trial(TrialInput {
            trial_idx: i,
            seed: config.seed_for(i),
            index: config.index_for(i),
        });
        match outcome {
            TrialOutcome::Correct => {}
            TrialOutcome::SilentMismatch => silent += 1,
            TrialOutcome::ExplicitError => explicit += 1,
        }
    }
    NoiseBenchReport::summarize(config, trials, silent, explicit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell_2_20_x_256() -> GridCell {
        GridCell {
            entries_log2: 20,
            record_bytes: 256,
        }
    }

    #[test]
    fn config_seed_is_deterministic_per_trial() {
        let cfg = NoiseBenchConfig {
            cell: cell_2_20_x_256(),
            trials: 10,
            base_seed: 0xDEAD_BEEF,
            index_stride: Some(1),
        };
        assert_eq!(cfg.seed_for(0), cfg.seed_for(0));
        assert_ne!(cfg.seed_for(0), cfg.seed_for(1));
    }

    #[test]
    fn deterministic_stride_walks_indices_modulo_n() {
        let cfg = NoiseBenchConfig {
            cell: cell_2_20_x_256(),
            trials: 4,
            base_seed: 0,
            index_stride: Some(7),
        };
        let n = cfg.cell.entries();
        for i in 0..4u64 {
            assert_eq!(cfg.index_for(i), (i * 7) % n);
        }
    }

    #[test]
    fn random_stride_is_deterministic_in_base_seed() {
        let cfg_a = NoiseBenchConfig {
            cell: cell_2_20_x_256(),
            trials: 4,
            base_seed: 42,
            index_stride: None,
        };
        let cfg_b = cfg_a.clone();
        for i in 0..4 {
            assert_eq!(cfg_a.index_for(i), cfg_b.index_for(i));
        }
    }

    #[test]
    fn wilson_upper_bound_is_1_for_all_failures() {
        // When every trial fails, the upper bound hits the unit boundary.
        let w = wilson_upper_95(100, 100);
        assert!(w > 0.95);
        assert!(w <= 1.0);
    }

    #[test]
    fn wilson_upper_bound_is_strictly_positive_for_zero_failures() {
        // Zero observed failures does NOT mean zero failure rate; Wilson
        // gives a positive upper bound that shrinks with n.
        let w_small = wilson_upper_95(0, 100);
        let w_large = wilson_upper_95(0, 100_000);
        assert!(w_small > 0.0);
        assert!(w_large > 0.0);
        assert!(w_large < w_small);
    }

    #[test]
    fn summary_clamps_silent_to_trials() {
        let cfg = NoiseBenchConfig {
            cell: cell_2_20_x_256(),
            trials: 10,
            base_seed: 0,
            index_stride: Some(1),
        };
        // Intentionally misuse. Silent > trials
        let r = NoiseBenchReport::summarize(cfg, 10, 999, 0);
        assert_eq!(r.silent_mismatches, 10);
        assert!((r.silent_failure_rate - 1.0).abs() < 1e-9);
    }

    // A scheme that reports `Correct` on every trial; used to sanity-check
    // the harness loop without any real crypto.
    struct AlwaysCorrect;
    impl NoiseValidatable for AlwaysCorrect {
        fn run_trial(&self, _: TrialInput) -> TrialOutcome {
            TrialOutcome::Correct
        }
    }

    // A scheme that fails silently every Nth trial (deterministic by trial_idx).
    struct EveryNthSilentMismatch {
        n: u64,
    }
    impl NoiseValidatable for EveryNthSilentMismatch {
        fn run_trial(&self, input: TrialInput) -> TrialOutcome {
            if self.n > 0 && input.trial_idx % self.n == 0 {
                TrialOutcome::SilentMismatch
            } else {
                TrialOutcome::Correct
            }
        }
    }

    #[test]
    fn zero_failure_run_reports_zero() {
        let cfg = NoiseBenchConfig {
            cell: cell_2_20_x_256(),
            trials: 1000,
            base_seed: 1,
            index_stride: Some(1),
        };
        let r = run_noise_bench(&AlwaysCorrect, cfg);
        assert_eq!(r.silent_mismatches, 0);
        assert_eq!(r.explicit_errors, 0);
        assert!((r.silent_failure_rate - 0.0).abs() < 1e-12);
        assert!(r.silent_failure_wilson_upper_97_5 > 0.0);
    }

    #[test]
    fn deterministic_failure_rate_matches_observation() {
        let cfg = NoiseBenchConfig {
            cell: cell_2_20_x_256(),
            trials: 1000,
            base_seed: 1,
            index_stride: Some(1),
        };
        // Fails every 10th trial: 100 silent mismatches in 1000 trials.
        let r = run_noise_bench(&EveryNthSilentMismatch { n: 10 }, cfg);
        assert_eq!(r.silent_mismatches, 100);
        assert!((r.silent_failure_rate - 0.1).abs() < 1e-12);
        // Wilson upper bound is > observed rate.
        assert!(r.silent_failure_wilson_upper_97_5 > 0.1);
    }
}
