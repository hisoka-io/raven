//! Pure comparison logic for `bench-compare`.
//!
//! Loads two bench-result JSON files and produces per-bench
//! comparison records. Threshold drives the regression/improvement
//! verdict; Welch t-statistic with Welch-Satterthwaite df + Student's
//! t-distribution two-sided p-value via regularized incomplete beta +
//! Lanczos lnGamma gives a supplementary p-value valid at small n.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::{fmt, fs, io, path::Path};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BenchFile {
    #[serde(default)]
    pub hardware: String,
    #[serde(default)]
    pub captured_at: String,
    pub results: Vec<BenchResult>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BenchResult {
    pub bench: String,
    pub median_ns: f64,
    #[serde(default)]
    pub samples_ns: Vec<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Verdict {
    Identical,
    WithinThreshold,
    Improvement,
    Regression,
    BaselineMissing,
    CurrentMissing,
}

#[derive(Debug, Clone, Serialize)]
pub struct Comparison {
    pub bench: String,
    pub baseline_ns: Option<f64>,
    pub current_ns: Option<f64>,
    pub delta_pct: Option<f64>,
    pub p_value: Option<f64>,
    pub verdict: Verdict,
}

#[derive(Debug)]
pub enum CompareError {
    Io { path: String, source: io::Error },
    Parse { path: String, source: serde_json::Error },
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
    let bytes = fs::read(path).map_err(|e| CompareError::Io { path: p(), source: e })?;
    serde_json::from_slice(&bytes).map_err(|e| CompareError::Parse { path: p(), source: e })
}

/// Produce comparisons sorted by bench name.
pub fn compare(baseline: &BenchFile, current: &BenchFile, threshold: f64) -> Vec<Comparison> {
    let mut by_name: BTreeMap<&str, (Option<&BenchResult>, Option<&BenchResult>)> = BTreeMap::new();
    for r in &baseline.results {
        by_name.entry(&r.bench).or_default().0 = Some(r);
    }
    for r in &current.results {
        by_name.entry(&r.bench).or_default().1 = Some(r);
    }
    by_name.into_iter().map(|(n, (b, c))| compare_one(n, b, c, threshold)).collect()
}

fn compare_one(name: &str, b: Option<&BenchResult>, c: Option<&BenchResult>, threshold: f64) -> Comparison {
    let baseline_ns = b.map(|x| x.median_ns);
    let current_ns = c.map(|x| x.median_ns);
    let (Some(b), Some(c)) = (b, c) else {
        let verdict = if baseline_ns.is_none() { Verdict::BaselineMissing } else { Verdict::CurrentMissing };
        return Comparison { bench: name.into(), baseline_ns, current_ns, delta_pct: None, p_value: None, verdict };
    };
    let delta_pct = if b.median_ns == 0.0 { 0.0 } else { (c.median_ns - b.median_ns) / b.median_ns };
    let verdict = if b.median_ns == c.median_ns {
        Verdict::Identical
    } else if delta_pct.abs() <= threshold {
        Verdict::WithinThreshold
    } else if delta_pct > 0.0 {
        Verdict::Regression
    } else {
        Verdict::Improvement
    };
    Comparison {
        bench: name.into(),
        baseline_ns,
        current_ns,
        delta_pct: Some(delta_pct),
        p_value: welch_p(&b.samples_ns, &c.samples_ns),
        verdict,
    }
}

/// Welch t with Welch-Satterthwaite df; two-sided p via Student's t.
/// `None` when either sample has < 2 entries. With zero combined SE:
/// `Some(1.0)` if means match, `Some(0.0)` otherwise.
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

/// Regularized incomplete beta `I(x; a, b)` via Lentz CF (NR §6.4) with
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
    let log_front =
        a * x.ln() + b * (1.0 - x).ln() - (ln_gamma(a) + ln_gamma(b) - ln_gamma(a + b));
    let symmetry_pivot = (a + 1.0) / (a + b + 2.0);
    if x < symmetry_pivot {
        let cf = beta_cf(x, a, b);
        (log_front.exp() * cf / a).clamp(0.0, 1.0)
    } else {
        let cf = beta_cf(1.0 - x, b, a);
        (1.0 - (log_front.exp() * cf / b)).clamp(0.0, 1.0)
    }
}

/// Modified Lentz CF for the incomplete beta (NR §6.4). Iteration cap +
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
        // Even step.
        let aa = mf * (b - mf) * x / ((qam + m2) * (a + m2));
        d = 1.0 / floor(1.0 + aa * d);
        c = floor(1.0 + aa / c);
        h *= d * c;
        // Odd step.
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

/// Lanczos ln Γ(z), g=7 / 9-coef; |err| < 1e-13 for z > 0.5.
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
        // Reflection: ln Γ(z) = ln(π / sin(π z)) - ln Γ(1 - z).
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

pub fn render_human(baseline_path: &str, current_path: &str, threshold: f64, rows: &[Comparison]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "Bench-compare: baseline={baseline_path} vs current={current_path}");
    let _ = writeln!(out, "Regression threshold: {:.1}%", threshold * 100.0);
    let _ = writeln!(
        out,
        "p-value: Welch t / Welch-Satterthwaite df / Student-t two-sided CDF\n",
    );
    out.push_str("| Bench                              | Baseline       | Current        | Delta%   | p-value | Verdict        |\n");
    out.push_str("|------------------------------------|---------------:|---------------:|---------:|---------|----------------|\n");
    let na = || "n/a".to_string();
    for r in rows {
        let baseline = r.baseline_ns.map(format_ns).unwrap_or_else(na);
        let current = r.current_ns.map(format_ns).unwrap_or_else(na);
        let delta = r.delta_pct.map(|d| format!("{:+.1}%", d * 100.0)).unwrap_or_else(na);
        let sig = r.p_value.map(|p| format!("{p:.3}")).unwrap_or_else(na);
        let verdict = match r.verdict {
            Verdict::Identical => "identical",
            Verdict::WithinThreshold => "within thresh",
            Verdict::Improvement => "IMPROVEMENT",
            Verdict::Regression => "REGRESSION",
            Verdict::BaselineMissing => "BASELINE MISSING",
            Verdict::CurrentMissing => "CURRENT MISSING",
        };
        let _ = writeln!(
            out, "| {:<34} | {:>14} | {:>14} | {:>8} | {:<7} | {:<14} |",
            truncate(&r.bench, 34), baseline, current, delta, sig, verdict,
        );
    }
    let regressed: Vec<&str> = rows.iter().filter(|r| r.verdict == Verdict::Regression).map(|r| r.bench.as_str()).collect();
    out.push('\n');
    if regressed.is_empty() {
        out.push_str("Verdict: no benches regressed past threshold. Exit code: 0.\n");
    } else {
        let _ = writeln!(
            out, "Verdict: {} bench(es) REGRESSED past {:.1}% threshold ({}). Exit code: 1.",
            regressed.len(), threshold * 100.0, regressed.join(", "),
        );
    }
    out
}

fn format_ns(ns: f64) -> String {
    if ns >= 1e9 { format!("{:.2} s", ns / 1e9) }
    else if ns >= 1e6 { format!("{:.2} ms", ns / 1e6) }
    else if ns >= 1e3 { format!("{:.3} us", ns / 1e3) }
    else { format!("{ns:.0} ns") }
}

fn truncate(s: &str, width: usize) -> String {
    if s.len() <= width { s.to_string() }
    else { let mut t = s[..width.saturating_sub(1)].to_string(); t.push('~'); t }
}

pub fn has_regression(rows: &[Comparison]) -> bool {
    rows.iter().any(|r| r.verdict == Verdict::Regression)
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
        assert!((p - 0.287_993_3).abs() < 0.01, "expected p ~= 0.288, got {p}");
    }

    // n=10 vs n=10, mean shift ~ 0.94 sample-sigma. df=18, |t| ~= 2.10
    // -> two-sided p ~ 0.05.
    #[test]
    fn t_cdf_n10_two_sigma_diff_returns_p_around_0_05() {
        let raw: Vec<f64> = (0..10).map(|i| (i as f64) - 4.5).collect();
        let scale = (82.5_f64 / 9.0).sqrt(); // unit sample variance
        let baseline: Vec<f64> = raw.iter().map(|x| x / scale).collect();
        let current: Vec<f64> = baseline.iter().map(|x| x + 0.939_5).collect();
        let p = welch_p(&baseline, &current).expect("p exists");
        assert!((p - 0.05).abs() < 0.01, "expected p ~= 0.05, got {p}");
    }

    // Small-n t has fatter tails than the normal, so p_t > p_normal.
    // Two-sided normal-CDF p for |t|=sqrt(1.5) ~= 0.2207.
    #[test]
    fn t_cdf_diverges_from_normal_at_small_n() {
        let baseline = vec![-1.0, 0.0, 1.0];
        let current = vec![0.0, 1.0, 2.0];
        let p_t = welch_p(&baseline, &current).expect("p exists");
        let p_normal_reference = 0.2207_f64;
        assert!(p_t > p_normal_reference + 0.05, "p_t {p_t} not > p_normal {p_normal_reference}");
    }

    // Zero variance both sides: equal means -> p=1.0, distinct means -> p=0.0.
    #[test]
    fn t_cdf_handles_zero_variance_edge_case() {
        let a = vec![1000.0, 1000.0, 1000.0];
        let b = vec![1500.0, 1500.0, 1500.0];
        let p_equal = welch_p(&a, &a).expect("p exists");
        assert!((p_equal - 1.0).abs() < 1e-12, "equal-means p {p_equal} != 1.0");
        let p_distinct = welch_p(&a, &b).expect("p exists");
        assert!(p_distinct.abs() < 1e-12, "distinct-means p {p_distinct} != 0.0");
    }
}
