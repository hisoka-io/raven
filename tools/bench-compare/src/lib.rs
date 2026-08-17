//! Per-bench comparison of two bench-result JSON files. The threshold drives the verdict; a
//! Welch t with Welch-Satterthwaite df supplies a p-value that stays valid at small n.

pub use raven_bench::{BenchFile, BenchResult, Unit};
use serde::Serialize;
use std::collections::BTreeMap;
use std::{fmt, fs, io, path::Path};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Verdict {
    Identical,
    WithinThreshold,
    Improvement,
    Regression,
    /// Past the threshold in the worse direction, but the shift could not be separated
    /// from run-to-run noise: no samples, or `p >= alpha`. Reported loudly, never blocking.
    RegressionUnconfirmed,
    /// The two runs measured this name in different units, so no comparison is meaningful.
    UnitMismatch,
    BaselineMissing,
    CurrentMissing,
}

/// What blocks the build, as distinct from what gets reported.
///
/// A shared runner's noise floor exceeds 15% on some configs, so a threshold alone cannot
/// separate a real regression from a noisy one. Timing verdicts therefore need BOTH a
/// threshold breach and a significant Welch p; byte counts need neither, because they are
/// structurally deterministic and any movement is real.
#[derive(Debug, Clone)]
pub struct GatePolicy {
    /// Fractional threshold for timing metrics, e.g. 0.15.
    pub timing_threshold: f64,
    /// Significance a timing regression must clear to block.
    pub alpha: f64,
    /// Bench-name substrings that are measured and reported but never block.
    pub non_blocking: Vec<String>,
}

impl Default for GatePolicy {
    fn default() -> Self {
        Self {
            timing_threshold: 0.15,
            alpha: 0.05,
            non_blocking: Vec::new(),
        }
    }
}

impl GatePolicy {
    /// Whether a row may block, before its verdict is considered.
    ///
    /// Throughput never blocks: it is `1/mean(query_latency)` over the same vector
    /// `query_median` already reports, so gating both counts one measurement twice.
    #[must_use]
    pub fn row_may_block(&self, bench: &str, unit: Unit) -> bool {
        if unit == Unit::QueriesPerSecond {
            return false;
        }
        !self
            .non_blocking
            .iter()
            .any(|pat| bench.contains(pat.as_str()))
    }
}

impl Verdict {
    /// Whether this row alone is enough to fail the gate.
    ///
    /// `CurrentMissing` fails: a bench the baseline measured and this run did not is a
    /// measurement that was never made, and reporting success for it is how a silently
    /// broken run passes. `BaselineMissing` does not fail, because a newly added bench
    /// legitimately has nothing to compare against yet.
    #[must_use]
    pub const fn fails_gate(&self) -> bool {
        match *self {
            Self::Regression | Self::UnitMismatch | Self::CurrentMissing => true,
            Self::RegressionUnconfirmed
            | Self::Identical
            | Self::WithinThreshold
            | Self::Improvement
            | Self::BaselineMissing => false,
        }
    }

    /// Whether this verdict is about the measurement being ABSENT or incomparable, rather
    /// than about its value moving.
    ///
    /// Policy exemptions suppress value movements, never these: excusing a config from the
    /// performance gate must not also excuse it from producing the measurement at all.
    #[must_use]
    pub const fn is_structural(&self) -> bool {
        matches!(*self, Self::UnitMismatch | Self::CurrentMissing)
    }

    /// Why this row failed the gate, for the operator-facing summary.
    #[must_use]
    pub const fn failure_reason(&self) -> &'static str {
        match *self {
            Self::Regression => "regressed",
            Self::UnitMismatch => "changed units",
            Self::CurrentMissing => "missing from this run",
            Self::RegressionUnconfirmed
            | Self::Identical
            | Self::WithinThreshold
            | Self::Improvement
            | Self::BaselineMissing => "",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Comparison {
    pub bench: String,
    pub baseline: Option<f64>,
    pub current: Option<f64>,
    /// Unit both sides were measured in; a mismatch is refused rather than compared.
    pub unit: Unit,
    pub delta_pct: Option<f64>,
    pub p_value: Option<f64>,
    pub verdict: Verdict,
}

#[derive(Debug)]
pub enum CompareError {
    Io {
        path: String,
        source: io::Error,
    },
    Parse {
        path: String,
        source: serde_json::Error,
    },
}

impl fmt::Display for CompareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "io error reading {path}: {source}"),
            Self::Parse { path, source } => write!(f, "json parse error in {path}: {source}"),
        }
    }
}

impl std::error::Error for CompareError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
        }
    }
}

pub fn load(path: &Path) -> Result<BenchFile, CompareError> {
    let p = || path.display().to_string();
    let bytes = fs::read(path).map_err(|e| CompareError::Io {
        path: p(),
        source: e,
    })?;
    BenchFile::from_json_slice(&bytes).map_err(|e| CompareError::Parse {
        path: p(),
        source: e,
    })
}

/// Produce comparisons sorted by bench name.
pub fn compare(baseline: &BenchFile, current: &BenchFile, threshold: f64) -> Vec<Comparison> {
    compare_with_alpha(baseline, current, threshold, GatePolicy::default().alpha)
}

/// Produce comparisons sorted by bench name, with an explicit significance level.
#[must_use]
pub fn compare_with_alpha(
    baseline: &BenchFile,
    current: &BenchFile,
    threshold: f64,
    alpha: f64,
) -> Vec<Comparison> {
    let mut by_name: BTreeMap<&str, (Option<&BenchResult>, Option<&BenchResult>)> = BTreeMap::new();
    for r in &baseline.results {
        by_name.entry(&r.bench).or_default().0 = Some(r);
    }
    for r in &current.results {
        by_name.entry(&r.bench).or_default().1 = Some(r);
    }
    by_name
        .into_iter()
        .map(|(n, (b, c))| compare_one(n, b, c, threshold, alpha))
        .collect()
}

fn compare_one(
    name: &str,
    b: Option<&BenchResult>,
    c: Option<&BenchResult>,
    threshold: f64,
    alpha: f64,
) -> Comparison {
    let baseline = b.map(|x| x.value);
    let current = c.map(|x| x.value);
    let (Some(b), Some(c)) = (b, c) else {
        let verdict = if baseline.is_none() {
            Verdict::BaselineMissing
        } else {
            Verdict::CurrentMissing
        };
        return Comparison {
            bench: name.into(),
            baseline,
            current,
            unit: b.or(c).map_or(Unit::default(), |r| r.unit),
            delta_pct: None,
            p_value: None,
            verdict,
        };
    };
    // Two runs measuring one name in different units are not comparable at all: the
    // percentage would be arithmetic over unrelated quantities and would read as a
    // verdict. Refuse rather than compare.
    if b.unit != c.unit {
        return Comparison {
            bench: name.into(),
            baseline,
            current,
            unit: c.unit,
            delta_pct: None,
            p_value: None,
            verdict: Verdict::UnitMismatch,
        };
    }
    let delta_pct = if b.value == 0.0 {
        0.0
    } else {
        (c.value - b.value) / b.value
    };
    // The unit decides the sign. For a duration or a size a rise is a regression; for
    // throughput a rise is the improvement, and treating it as a regression would fail
    // the build on exactly the result the work was trying to produce.
    let worse = if c.unit.lower_is_better() {
        delta_pct > 0.0
    } else {
        delta_pct < 0.0
    };
    let p_value = welch_p(&b.samples, &c.samples);
    // Bytes are structurally deterministic: measured 0.000% spread across 13 configs x 3
    // seeds and 8 same-producer seeds. Any movement is a real change, so no threshold and
    // no significance test applies. Timings get both.
    let exact = c.unit == Unit::Bytes;
    let verdict = if b.value == c.value {
        Verdict::Identical
    } else if exact {
        if worse {
            Verdict::Regression
        } else {
            Verdict::Improvement
        }
    } else if delta_pct.abs() <= threshold {
        Verdict::WithinThreshold
    } else if !worse {
        Verdict::Improvement
    } else if p_value.is_some_and(|p| p < alpha) {
        Verdict::Regression
    } else {
        // Over threshold, but indistinguishable from noise. A metric with no samples at
        // all lands here permanently, which is what keeps `setup` out of the gate: it is
        // captured once outside the seed loop, so it is n=1 compared against n=1.
        Verdict::RegressionUnconfirmed
    };
    Comparison {
        bench: name.into(),
        baseline,
        current,
        unit: c.unit,
        delta_pct: Some(delta_pct),
        p_value,
        verdict,
    }
}

/// Welch t with Welch-Satterthwaite df. `None` below 2 samples; at zero combined SE, 1.0 for
/// equal means and 0.0 otherwise.
fn welch_p(b: &[f64], c: &[f64]) -> Option<f64> {
    let (mb, vb) = mean_var(b)?;
    let (mc, vc) = mean_var(c)?;
    let (nb, nc) = (b.len() as f64, c.len() as f64);
    let se2 = vb / nb + vc / nc;
    if !se2.is_finite() {
        return None;
    }
    if se2 == 0.0 {
        return Some(if (mb - mc).abs() == 0.0 { 1.0 } else { 0.0 });
    }
    let t = (mb - mc) / se2.sqrt();
    let num = se2 * se2;
    let den = (vb * vb) / (nb * nb * (nb - 1.0)) + (vc * vc) / (nc * nc * (nc - 1.0));
    if !den.is_finite() || den <= 0.0 {
        return None;
    }
    let df = num / den;
    Some(student_t_two_sided_p(t, df))
}

fn mean_var(xs: &[f64]) -> Option<(f64, f64)> {
    if xs.len() < 2 {
        return None;
    }
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
    Some((mean, var))
}

/// `P(|T_df| >= |t|)` via `I(df/(df + t^2); df/2, 1/2)`.
fn student_t_two_sided_p(t: f64, df: f64) -> f64 {
    if !t.is_finite() || !df.is_finite() || df <= 0.0 {
        return f64::NAN;
    }
    let x = df / (df + t * t);
    reg_incomplete_beta(x, 0.5 * df, 0.5).clamp(0.0, 1.0)
}

/// Regularized incomplete beta `I(x; a, b)` via Lentz CF (Numerical Recipes 6.4) with
/// symmetric branch swap at `x > (a + 1) / (a + b + 2)` for tail stability.
fn reg_incomplete_beta(x: f64, a: f64, b: f64) -> f64 {
    if !(x.is_finite() && a.is_finite() && b.is_finite()) || a <= 0.0 || b <= 0.0 {
        return f64::NAN;
    }
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }
    // ln front factor: x^a * (1-x)^b / (a * B(a,b))
    let log_front = a * x.ln() + b * (1.0 - x).ln() - (ln_gamma(a) + ln_gamma(b) - ln_gamma(a + b));
    let symmetry_pivot = (a + 1.0) / (a + b + 2.0);
    if x < symmetry_pivot {
        let cf = beta_cf(x, a, b);
        (log_front.exp() * cf / a).clamp(0.0, 1.0)
    } else {
        let cf = beta_cf(1.0 - x, b, a);
        (1.0 - (log_front.exp() * cf / b)).clamp(0.0, 1.0)
    }
}

/// Modified Lentz CF for the incomplete beta (Numerical Recipes 6.4). Iteration cap +
/// tiny-floor keep the loop finite for pathological inputs.
fn beta_cf(x: f64, a: f64, b: f64) -> f64 {
    const MAX_ITER: u32 = 200;
    const EPS: f64 = 3.0e-16;
    const TINY: f64 = 1.0e-300;
    let floor = |v: f64| if v.abs() < TINY { TINY } else { v };
    let (qab, qap, qam) = (a + b, a + 1.0, a - 1.0);
    let mut c = 1.0_f64;
    let mut d = 1.0 / floor(1.0 - qab * x / qap);
    let mut h = d;
    for m in 1..=MAX_ITER {
        let mf = f64::from(m);
        let m2 = 2.0 * mf;
        let aa = mf * (b - mf) * x / ((qam + m2) * (a + m2));
        d = 1.0 / floor(1.0 + aa * d);
        c = floor(1.0 + aa / c);
        h *= d * c;
        let aa = -(a + mf) * (qab + mf) * x / ((a + m2) * (qap + m2));
        d = 1.0 / floor(1.0 + aa * d);
        c = floor(1.0 + aa / c);
        let delta = d * c;
        h *= delta;
        if (delta - 1.0).abs() < EPS {
            return h;
        }
    }
    h
}

/// Lanczos ln Gamma(z), g=7 / 9-coef; |err| < 1e-13 for z > 0.5.
fn ln_gamma(z: f64) -> f64 {
    const G: f64 = 7.0;
    const COEF: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_2,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_1,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    if z < 0.5 {
        // Reflection: ln Gamma(z) = ln(pi / sin(pi z)) - ln Gamma(1 - z).
        let pi = std::f64::consts::PI;
        return (pi / (pi * z).sin()).ln() - ln_gamma(1.0 - z);
    }
    let z = z - 1.0;
    let mut x = COEF[0];
    for (i, &c) in COEF.iter().enumerate().skip(1) {
        x += c / (z + i as f64);
    }
    let t = z + G + 0.5;
    0.5 * (2.0 * std::f64::consts::PI).ln() + (z + 0.5) * t.ln() - t + x.ln()
}

pub fn render_human(
    baseline_path: &str,
    current_path: &str,
    threshold: f64,
    rows: &[Comparison],
) -> String {
    render_human_with_policy(
        baseline_path,
        current_path,
        threshold,
        rows,
        &GatePolicy::default(),
    )
}

/// Render the human table, deriving the summary from the same policy the exit code uses.
#[must_use]
#[allow(
    clippy::too_many_arguments,
    reason = "one render call; splitting it would hide the shared policy"
)]
pub fn render_human_with_policy(
    baseline_path: &str,
    current_path: &str,
    threshold: f64,
    rows: &[Comparison],
    policy: &GatePolicy,
) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Bench-compare: baseline={baseline_path} vs current={current_path}"
    );
    let _ = writeln!(out, "Regression threshold: {:.1}%", threshold * 100.0);
    let _ = writeln!(
        out,
        "p-value: Welch t / Welch-Satterthwaite df / Student-t two-sided CDF\n",
    );
    out.push_str("| Bench                              | Baseline       | Current        | Delta%   | p-value | Verdict        |\n");
    out.push_str("|------------------------------------|---------------:|---------------:|---------:|---------|----------------|\n");
    let na = || "n/a".to_string();
    for r in rows {
        let baseline = r
            .baseline
            .map(|v| format_value(v, r.unit))
            .unwrap_or_else(na);
        let current = r
            .current
            .map(|v| format_value(v, r.unit))
            .unwrap_or_else(na);
        let delta = r
            .delta_pct
            .map(|d| format!("{:+.1}%", d * 100.0))
            .unwrap_or_else(na);
        let sig = r.p_value.map(|p| format!("{p:.3}")).unwrap_or_else(na);
        let verdict = match r.verdict {
            Verdict::UnitMismatch => "UNIT MISMATCH",
            Verdict::Identical => "identical",
            Verdict::WithinThreshold => "within thresh",
            Verdict::Improvement => "IMPROVEMENT",
            Verdict::Regression => "REGRESSION",
            Verdict::BaselineMissing => "BASELINE MISSING",
            Verdict::CurrentMissing => "CURRENT MISSING",
            Verdict::RegressionUnconfirmed => "noise? (unconfirmed)",
        };
        let _ = writeln!(
            out,
            "| {:<34} | {:>14} | {:>14} | {:>8} | {:<7} | {:<14} |",
            truncate(&r.bench, 34),
            baseline,
            current,
            delta,
            sig,
            verdict,
        );
    }
    // Derived from the same predicate the exit code uses: a summary computed from a
    // narrower rule prints "Exit code: 0" on a run that exits 1.
    let failing: Vec<String> = rows
        .iter()
        .filter(|r| {
            r.verdict.fails_gate()
                && (r.verdict.is_structural() || policy.row_may_block(&r.bench, r.unit))
        })
        .map(|r| format!("{} ({})", r.bench, r.verdict.failure_reason()))
        .collect();
    let unconfirmed = rows
        .iter()
        .filter(|r| r.verdict == Verdict::RegressionUnconfirmed)
        .count();
    out.push('\n');
    if unconfirmed > 0 {
        let _ = writeln!(
            out,
            "Note: {unconfirmed} bench(es) moved past the threshold but could not be \
             separated from noise (no samples, or p >= alpha). Reported, not blocking."
        );
    }
    if failing.is_empty() {
        out.push_str("Verdict: no benches regressed past threshold. Exit code: 0.\n");
    } else {
        let _ = writeln!(
            out,
            "Verdict: {} bench(es) FAILED the {:.1}% gate ({}). Exit code: 1.",
            failing.len(),
            threshold * 100.0,
            failing.join(", "),
        );
    }
    out
}

/// Render a measurement in its own unit. Rendering bytes through the duration ladder
/// prints `2048` as `2.048 us`, which reads as a plausible timing.
fn format_value(v: f64, unit: Unit) -> String {
    match unit {
        Unit::Nanoseconds => format_ns(v),
        Unit::Bytes => {
            if v >= 1_048_576.0 {
                format!("{:.2} MiB", v / 1_048_576.0)
            } else if v >= 1024.0 {
                format!("{:.2} KiB", v / 1024.0)
            } else {
                format!("{v:.0} B")
            }
        }
        Unit::QueriesPerSecond => format!("{v:.1} qps"),
    }
}

fn format_ns(ns: f64) -> String {
    if ns >= 1e9 {
        format!("{:.2} s", ns / 1e9)
    } else if ns >= 1e6 {
        format!("{:.2} ms", ns / 1e6)
    } else if ns >= 1e3 {
        format!("{:.3} us", ns / 1e3)
    } else {
        format!("{ns:.0} ns")
    }
}

fn truncate(s: &str, width: usize) -> String {
    if s.len() <= width {
        s.to_string()
    } else {
        let mut t = s[..width.saturating_sub(1)].to_string();
        t.push('~');
        t
    }
}

pub fn has_regression(rows: &[Comparison]) -> bool {
    has_regression_with_policy(rows, &GatePolicy::default())
}

/// Whether any row blocks the build under `policy`.
///
/// A row blocks only if its verdict fails the gate AND the policy lets that row block.
/// Rows the policy exempts are still compared and still printed; they simply cannot turn
/// the build red.
#[must_use]
pub fn has_regression_with_policy(rows: &[Comparison], policy: &GatePolicy) -> bool {
    rows.iter().any(|r| {
        r.verdict.fails_gate()
            && (r.verdict.is_structural() || policy.row_may_block(&r.bench, r.unit))
    })
}

#[cfg(test)]
mod welch_tests {
    use super::*;

    // n=3 vs n=3, mean diff = 1 sample-sigma. df=4, t=sqrt(3/2).
    // R: `2*pt(-sqrt(1.5), 4)` returns 0.2879933.
    #[test]
    fn t_cdf_n3_one_sigma_diff_returns_p_around_0_29() {
        let baseline = vec![-1.0, 0.0, 1.0]; // sample var = 1
        let current = vec![0.0, 1.0, 2.0];
        let p = welch_p(&baseline, &current).expect("p exists");
        assert!(
            (p - 0.287_993_3).abs() < 0.01,
            "expected p ~= 0.288, got {p}"
        );
    }

    // n=10 each, mean shift ~0.94 sample-sigma: df=18, |t| ~= 2.10, two-sided p ~ 0.05.
    #[test]
    fn t_cdf_n10_two_sigma_diff_returns_p_around_0_05() {
        let raw: Vec<f64> = (0..10).map(|i| (i as f64) - 4.5).collect();
        let scale = (82.5_f64 / 9.0).sqrt(); // unit sample variance
        let baseline: Vec<f64> = raw.iter().map(|x| x / scale).collect();
        let current: Vec<f64> = baseline.iter().map(|x| x + 0.939_5).collect();
        let p = welch_p(&baseline, &current).expect("p exists");
        assert!((p - 0.05).abs() < 0.01, "expected p ~= 0.05, got {p}");
    }

    // Small-n t has fatter tails, so p_t > the 0.2207 two-sided normal p at |t|=sqrt(1.5).
    #[test]
    fn t_cdf_diverges_from_normal_at_small_n() {
        let baseline = vec![-1.0, 0.0, 1.0];
        let current = vec![0.0, 1.0, 2.0];
        let p_t = welch_p(&baseline, &current).expect("p exists");
        let p_normal_reference = 0.2207_f64;
        assert!(
            p_t > p_normal_reference + 0.05,
            "p_t {p_t} not > p_normal {p_normal_reference}"
        );
    }

    // Zero variance both sides: equal means -> p=1.0, distinct means -> p=0.0.
    #[test]
    fn t_cdf_handles_zero_variance_edge_case() {
        let a = vec![1000.0, 1000.0, 1000.0];
        let b = vec![1500.0, 1500.0, 1500.0];
        let p_equal = welch_p(&a, &a).expect("p exists");
        assert!(
            (p_equal - 1.0).abs() < 1e-12,
            "equal-means p {p_equal} != 1.0"
        );
        let p_distinct = welch_p(&a, &b).expect("p exists");
        assert!(
            p_distinct.abs() < 1e-12,
            "distinct-means p {p_distinct} != 0.0"
        );
    }
}

#[cfg(test)]
mod unit_direction_tests {
    use super::*;

    fn result(bench: &str, value: f64, unit: Unit) -> BenchResult {
        BenchResult {
            bench: bench.to_owned(),
            value,
            unit,
            samples: Vec::new(),
        }
    }

    fn file(results: Vec<BenchResult>) -> BenchFile {
        BenchFile {
            hardware: "test".to_owned(),
            captured_at: String::new(),
            results,
        }
    }

    /// Tight, well-separated distributions, so a threshold breach is also significant.
    fn sampled(bench: &str, value: f64, unit: Unit, samples: &[f64]) -> BenchResult {
        BenchResult {
            bench: bench.to_owned(),
            value,
            unit,
            samples: samples.to_vec(),
        }
    }

    /// A rise in throughput is the outcome the work was trying to produce. Scoring it as a
    /// regression fails the build on success, which is worse than not gating at all.
    #[test]
    fn a_throughput_increase_is_an_improvement_not_a_regression() {
        let base = file(vec![result("qps", 1000.0, Unit::QueriesPerSecond)]);
        let cur = file(vec![result("qps", 1500.0, Unit::QueriesPerSecond)]);
        let rows = compare(&base, &cur, 0.20);
        assert_eq!(rows[0].verdict, Verdict::Improvement, "got {:?}", rows[0]);
        assert!(!has_regression(&rows), "a speedup must not fail the gate");
    }

    /// And the other direction must still be caught, so the fix cannot be "never regress".
    /// Throughput reports the regression but does not block: it is `1/mean(latency)` over
    /// the vector `query_median` already gates, so blocking both counts one measurement twice.
    #[test]
    fn a_throughput_drop_is_reported_as_a_regression_but_does_not_block() {
        let base = file(vec![sampled(
            "qps",
            1000.0,
            Unit::QueriesPerSecond,
            &[1000.0, 1002.0, 998.0, 1001.0, 999.0],
        )]);
        let cur = file(vec![sampled(
            "qps",
            500.0,
            Unit::QueriesPerSecond,
            &[500.0, 502.0, 498.0, 501.0, 499.0],
        )]);
        let rows = compare(&base, &cur, 0.20);
        assert_eq!(rows[0].verdict, Verdict::Regression, "got {:?}", rows[0]);
        assert!(
            !has_regression(&rows),
            "throughput is informative, not blocking"
        );
    }

    /// Durations keep the original polarity, and a significant breach blocks.
    #[test]
    fn a_significant_latency_increase_is_a_blocking_regression() {
        let base = file(vec![sampled(
            "lat",
            1000.0,
            Unit::Nanoseconds,
            &[1000.0, 1010.0, 990.0, 1005.0, 995.0],
        )]);
        let cur = file(vec![sampled(
            "lat",
            1500.0,
            Unit::Nanoseconds,
            &[1500.0, 1510.0, 1490.0, 1505.0, 1495.0],
        )]);
        let rows = compare(&base, &cur, 0.20);
        assert_eq!(rows[0].verdict, Verdict::Regression);
        assert!(has_regression(&rows), "a significant breach must block");
    }

    /// The shared-runner case: past the threshold, but no distribution to judge it by.
    /// This is what keeps `setup` out of the gate - it is captured once outside the seed
    /// loop, so it is permanently n=1 against n=1.
    #[test]
    fn a_timing_breach_without_samples_is_unconfirmed_and_does_not_block() {
        let base = file(vec![result("setup", 1000.0, Unit::Nanoseconds)]);
        let cur = file(vec![result("setup", 1500.0, Unit::Nanoseconds)]);
        let rows = compare(&base, &cur, 0.20);
        assert_eq!(rows[0].verdict, Verdict::RegressionUnconfirmed);
        assert_eq!(rows[0].p_value, None);
        assert!(!has_regression(&rows), "noise must not fail the build");
    }

    /// Overlapping distributions breach the threshold on the medians yet are not separable.
    #[test]
    fn a_timing_breach_that_is_not_significant_is_unconfirmed() {
        let base = file(vec![sampled(
            "lat",
            1000.0,
            Unit::Nanoseconds,
            &[400.0, 1600.0, 500.0, 1500.0],
        )]);
        let cur = file(vec![sampled(
            "lat",
            1500.0,
            Unit::Nanoseconds,
            &[420.0, 1650.0, 520.0, 1560.0],
        )]);
        let rows = compare(&base, &cur, 0.20);
        assert_eq!(rows[0].verdict, Verdict::RegressionUnconfirmed);
        assert!(
            rows[0].p_value.is_some_and(|p| p >= 0.05),
            "overlapping spreads must not be significant, got {:?}",
            rows[0].p_value
        );
        assert!(!has_regression(&rows));
    }

    /// Bytes are structurally deterministic, so they block on any movement with no
    /// significance test at all. Measured 0.000% spread across every seed group on disk.
    #[test]
    fn a_byte_change_blocks_without_needing_significance() {
        let base = file(vec![result("q_bytes", 1024.0, Unit::Bytes)]);
        let cur = file(vec![result("q_bytes", 1025.0, Unit::Bytes)]);
        let rows = compare(&base, &cur, 0.20);
        assert_eq!(rows[0].verdict, Verdict::Regression);
        assert_eq!(rows[0].p_value, None, "bytes need no distribution");
        assert!(
            has_regression(&rows),
            "a one-byte structural change must block even below any threshold"
        );
    }

    /// The k4 concurrent config: measured and printed, never able to turn the build red.
    #[test]
    fn a_non_blocking_pattern_is_reported_but_never_blocks() {
        let base = file(vec![sampled(
            "inspire/2e16x512-k4/query_median",
            1000.0,
            Unit::Nanoseconds,
            &[1000.0, 1010.0, 990.0, 1005.0],
        )]);
        let cur = file(vec![sampled(
            "inspire/2e16x512-k4/query_median",
            2000.0,
            Unit::Nanoseconds,
            &[2000.0, 2010.0, 1990.0, 2005.0],
        )]);
        let rows = compare(&base, &cur, 0.20);
        assert_eq!(
            rows[0].verdict,
            Verdict::Regression,
            "it must still be measured and reported as a regression"
        );
        let policy = GatePolicy {
            non_blocking: vec!["-k4/".to_owned()],
            ..GatePolicy::default()
        };
        assert!(
            !has_regression_with_policy(&rows, &policy),
            "an excluded config must never block"
        );
        assert!(
            has_regression_with_policy(&rows, &GatePolicy::default()),
            "and without the exclusion it would have blocked, so the test is not vacuous"
        );
    }

    /// Bytes are lower-is-better, and must not be rendered through the duration ladder.
    #[test]
    fn a_byte_size_growth_is_a_regression_and_renders_as_bytes() {
        let base = file(vec![result("q_bytes", 1024.0, Unit::Bytes)]);
        let cur = file(vec![result("q_bytes", 4096.0, Unit::Bytes)]);
        let rows = compare(&base, &cur, 0.20);
        assert_eq!(rows[0].verdict, Verdict::Regression);
        assert_eq!(format_value(4096.0, Unit::Bytes), "4.00 KiB");
    }

    /// Excusing a config from the performance gate must not excuse it from existing.
    /// A vanished bench is a measurement that never happened, whatever the policy says
    /// about its value moving.
    #[test]
    fn an_excluded_config_still_blocks_when_its_bench_vanishes() {
        let base = file(vec![
            result(
                "inspire/2e16x512-k4/query_median",
                1000.0,
                Unit::Nanoseconds,
            ),
            result(
                "inspire/2e16x512-k4/throughput",
                900.0,
                Unit::QueriesPerSecond,
            ),
        ]);
        let cur = file(vec![result(
            "inspire/2e16x512-k4/query_median",
            1000.0,
            Unit::Nanoseconds,
        )]);
        let rows = compare(&base, &cur, 0.20);

        let gone = rows
            .iter()
            .find(|r| r.bench.ends_with("/throughput"))
            .expect("throughput row");
        assert_eq!(gone.verdict, Verdict::CurrentMissing);

        let policy = GatePolicy {
            non_blocking: vec!["-k4/".to_owned()],
            ..GatePolicy::default()
        };
        assert!(
            has_regression_with_policy(&rows, &policy),
            "an excluded config must still block when its measurement disappears"
        );
    }

    /// Comparing one name measured in two units is arithmetic over unrelated quantities.
    #[test]
    fn two_runs_measuring_one_name_in_different_units_are_refused() {
        let base = file(vec![result("x", 1000.0, Unit::Nanoseconds)]);
        let cur = file(vec![result("x", 1000.0, Unit::Bytes)]);
        let rows = compare(&base, &cur, 0.20);
        assert_eq!(rows[0].verdict, Verdict::UnitMismatch);
        assert!(
            rows[0].delta_pct.is_none(),
            "an incomparable pair must not carry a percentage"
        );
        assert!(
            has_regression(&rows),
            "an unmeasurable pair must fail the gate"
        );
    }

    /// A file written before the unit field existed must still parse, as nanoseconds.
    #[test]
    fn a_pre_unit_file_parses_as_nanoseconds() {
        let json = r#"{"hardware":"h","captured_at":"t",
            "results":[{"bench":"a","median_ns":1234.0,"samples_ns":[1.0,2.0]}]}"#;
        let f: BenchFile = serde_json::from_str(json).expect("legacy shape must parse");
        assert_eq!(f.results[0].value, 1234.0);
        assert_eq!(f.results[0].unit, Unit::Nanoseconds);
        assert_eq!(f.results[0].samples, vec![1.0, 2.0]);
    }
}
