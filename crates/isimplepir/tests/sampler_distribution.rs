#![allow(clippy::indexing_slicing)]
//! Chi-square coverage for the sigma = 6.4 discrete Gaussian sampler. The seed
//! is fixed: a statistical gate that can flake is worse than no gate.
//! Magnitudes past `RESOLVED_MAGNITUDE` are pooled into two tail bins, so the
//! far-tail table entries carry no measurable mass and are not constrained.

use std::sync::OnceLock;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use raven_isimplepir::query::{gauss_sample_sigma_6_4, CDF_TABLE_SIGMA_6_4};

const DRAWS: usize = 400_000;
const SEED: [u8; 32] = [0x5a; 32];
// Largest magnitude whose signed bin still expects >= 5 draws at DRAWS.
const RESOLVED_MAGNITUDE: i64 = 26;
const BINS: usize = 2 * RESOLVED_MAGNITUDE as usize + 3;
const NEGATIVE_TAIL: usize = 0;
const POSITIVE_TAIL: usize = BINS - 1;
const DISTRIBUTION_DF: usize = BINS - 1;
const SIGN_DF: i64 = RESOLVED_MAGNITUDE;
const SIGMA: f64 = 6.4;
// Chi-square upper tail 1e-6 at df 54 and df 26.
const DISTRIBUTION_CRITICAL: f64 = 118.45;
const SIGN_CRITICAL: f64 = 75.55;
const PERTURBED_MAGNITUDE: usize = 3;

fn bin_of(value: i64) -> usize {
    if value < -RESOLVED_MAGNITUDE {
        NEGATIVE_TAIL
    } else if value > RESOLVED_MAGNITUDE {
        POSITIVE_TAIL
    } else {
        (value + RESOLVED_MAGNITUDE + 1) as usize
    }
}

/// Table entry 0 is pre-halved so the sign fold does not emit zero twice; the
/// remaining entries split evenly across the two signs.
fn expected_bin_probabilities(magnitude_weight: &[f64]) -> Vec<f64> {
    let normaliser: f64 = magnitude_weight.iter().sum();
    let mut expected = vec![0.0f64; BINS];
    for (magnitude, &weight) in magnitude_weight.iter().enumerate() {
        let magnitude = magnitude as i64;
        if magnitude == 0 {
            expected[bin_of(0)] += weight / normaliser;
        } else {
            let per_sign = weight / (2.0 * normaliser);
            expected[bin_of(magnitude)] += per_sign;
            expected[bin_of(-magnitude)] += per_sign;
        }
    }
    expected
}

fn closed_form_weights() -> Vec<f64> {
    (0..CDF_TABLE_SIGMA_6_4.len())
        .map(|magnitude| {
            let x = magnitude as f64;
            let weight = (-(x * x) / (2.0 * SIGMA * SIGMA)).exp();
            if magnitude == 0 {
                weight / 2.0
            } else {
                weight
            }
        })
        .collect()
}

fn histogram() -> &'static [u64] {
    static COUNTS: OnceLock<Vec<u64>> = OnceLock::new();
    COUNTS.get_or_init(|| {
        let mut rng = ChaCha20Rng::from_seed(SEED);
        let mut counts = vec![0u64; BINS];
        for _ in 0..DRAWS {
            counts[bin_of(gauss_sample_sigma_6_4(&mut rng))] += 1;
        }
        counts
    })
}

fn chi_square(counts: &[u64], expected_probability: &[f64]) -> f64 {
    counts
        .iter()
        .zip(expected_probability)
        .map(|(&observed, &probability)| {
            let expected = probability * DRAWS as f64;
            let deviation = observed as f64 - expected;
            deviation * deviation / expected
        })
        .sum()
}

fn sign_chi_square(counts: &[u64]) -> f64 {
    let mut statistic = 0.0f64;
    for magnitude in 1..=RESOLVED_MAGNITUDE {
        let positive = counts[bin_of(magnitude)] as f64;
        let negative = counts[bin_of(-magnitude)] as f64;
        let balanced = f64::midpoint(positive, negative);
        let deviation = positive - balanced;
        statistic += 2.0 * deviation * deviation / balanced;
    }
    statistic
}

fn fold_onto_positive(counts: &[u64]) -> Vec<u64> {
    let mut folded = vec![0u64; BINS];
    folded[bin_of(0)] = counts[bin_of(0)];
    for magnitude in 1..=RESOLVED_MAGNITUDE {
        folded[bin_of(magnitude)] = counts[bin_of(magnitude)] + counts[bin_of(-magnitude)];
    }
    folded[POSITIVE_TAIL] = counts[NEGATIVE_TAIL] + counts[POSITIVE_TAIL];
    folded
}

/// Covers the rejection loop, the uniform candidate draw and the sign fold. It
/// cannot see a corrupted table entry, because the reference law moves with it.
#[test]
fn draws_match_the_table_derived_law() {
    let statistic = chi_square(
        histogram(),
        &expected_bin_probabilities(CDF_TABLE_SIGMA_6_4),
    );
    assert!(
        statistic.is_finite() && statistic <= DISTRIBUTION_CRITICAL,
        "chi-square {statistic:.2} against the CDF_TABLE_SIGMA_6_4 law exceeds \
         {DISTRIBUTION_CRITICAL} (df {DISTRIBUTION_DF}, {DRAWS} draws, upper tail 1e-6)"
    );
}

/// Independent oracle: the table entries are exp(-k^2 / 2 sigma^2), so a
/// corrupted entry shows up here even though the table-derived law hides it.
#[test]
fn draws_match_the_closed_form_discrete_gaussian() {
    let statistic = chi_square(
        histogram(),
        &expected_bin_probabilities(&closed_form_weights()),
    );
    assert!(
        statistic.is_finite() && statistic <= DISTRIBUTION_CRITICAL,
        "chi-square {statistic:.2} against the closed-form sigma = {SIGMA} law exceeds \
         {DISTRIBUTION_CRITICAL} (df {DISTRIBUTION_DF}, {DRAWS} draws, upper tail 1e-6)"
    );
}

#[test]
fn sign_fold_is_two_sided_at_every_resolved_magnitude() {
    let statistic = sign_chi_square(histogram());
    assert!(
        statistic.is_finite() && statistic <= SIGN_CRITICAL,
        "sign-balance chi-square {statistic:.2} exceeds {SIGN_CRITICAL} \
         (df {SIGN_DF}, {DRAWS} draws, upper tail 1e-6)"
    );
}

#[test]
fn the_law_gate_rejects_a_one_sided_sign_fold() {
    let folded = fold_onto_positive(histogram());
    let statistic = chi_square(&folded, &expected_bin_probabilities(CDF_TABLE_SIGMA_6_4));
    assert!(
        statistic > DISTRIBUTION_CRITICAL,
        "chi-square {statistic:.2} failed to reject an all-positive fold at \
         {DISTRIBUTION_CRITICAL} (df {DISTRIBUTION_DF}, {DRAWS} draws)"
    );
}

#[test]
fn the_sign_gate_rejects_a_one_sided_sign_fold() {
    let statistic = sign_chi_square(&fold_onto_positive(histogram()));
    assert!(
        statistic > SIGN_CRITICAL,
        "sign-balance chi-square {statistic:.2} failed to reject an all-positive \
         fold at {SIGN_CRITICAL} (df {SIGN_DF}, {DRAWS} draws)"
    );
}

#[test]
fn the_law_gate_rejects_a_ten_percent_shift_in_one_table_weight() {
    let mut weights = CDF_TABLE_SIGMA_6_4.to_vec();
    weights[PERTURBED_MAGNITUDE] *= 0.9;
    let statistic = chi_square(histogram(), &expected_bin_probabilities(&weights));
    assert!(
        statistic > DISTRIBUTION_CRITICAL,
        "chi-square {statistic:.2} failed to reject a 10% shift at magnitude \
         {PERTURBED_MAGNITUDE} at {DISTRIBUTION_CRITICAL} (df {DISTRIBUTION_DF}, {DRAWS} draws)"
    );
}
