//! CLI entry point for `bench-compare`.

use bench_compare::{
    compare_with_alpha, has_regression_with_policy, load, render_human_with_policy, Comparison,
    GatePolicy,
};
use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Format {
    Human,
    Json,
}

#[derive(Parser, Debug)]
#[command(
    name = "bench-compare",
    about = "Compare two raven bench JSON outputs and flag regressions. \
             A timing regression must breach the threshold AND be significant; \
             byte counts are exact and need neither. Supplementary p-value uses \
             Welch t with Welch-Satterthwaite df and Student's t two-sided CDF \
             (regularized incomplete beta + Lanczos lnGamma); valid at small n.",
    version
)]
struct Args {
    /// Baseline bench JSON file.
    baseline: PathBuf,
    /// Current bench JSON file.
    current: PathBuf,
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Human)]
    format: Format,
    /// Fractional regression threshold for timing metrics (0.15 == +15%).
    #[arg(long, default_value_t = 0.15)]
    regression_threshold: f64,
    /// Significance a timing regression must clear to block the build.
    #[arg(long, default_value_t = 0.05)]
    alpha: f64,
    /// Bench-name substring that is measured and reported but never blocks. Repeatable.
    #[arg(long = "non-blocking")]
    non_blocking: Vec<String>,
    /// Print the comparison but always exit 0 on a regression. A parse or IO failure
    /// still exits 2, so a broken run is never mistaken for a clean one.
    #[arg(long)]
    report_only: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("bench-compare: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &Args) -> Result<ExitCode, Box<dyn std::error::Error>> {
    if !args.regression_threshold.is_finite() || args.regression_threshold < 0.0 {
        return Err(format!(
            "--regression-threshold must be a non-negative finite number; got {}",
            args.regression_threshold
        )
        .into());
    }
    if !args.alpha.is_finite() || args.alpha <= 0.0 || args.alpha >= 1.0 {
        return Err(format!(
            "--alpha must be a finite number strictly between 0 and 1; got {}",
            args.alpha
        )
        .into());
    }
    let policy = GatePolicy {
        timing_threshold: args.regression_threshold,
        alpha: args.alpha,
        non_blocking: args.non_blocking.clone(),
    };
    let baseline = load(&args.baseline)?;
    let current = load(&args.current)?;
    let rows = compare_with_alpha(&baseline, &current, policy.timing_threshold, policy.alpha);
    emit(args, &policy, &rows)?;

    let blocked = has_regression_with_policy(&rows, &policy);
    if blocked && args.report_only {
        eprintln!(
            "bench-compare: regression detected, but --report-only is set so the build is not \
             failed. Remove --report-only once the runner's noise floor has been measured."
        );
    }
    Ok(if blocked && !args.report_only {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn emit(
    args: &Args,
    policy: &GatePolicy,
    rows: &[Comparison],
) -> Result<(), Box<dyn std::error::Error>> {
    match args.format {
        Format::Human => {
            print!(
                "{}",
                render_human_with_policy(
                    &args.baseline.display().to_string(),
                    &args.current.display().to_string(),
                    policy.timing_threshold,
                    rows,
                    policy,
                )
            );
        }
        Format::Json => {
            let s = serde_json::to_string_pretty(rows)?;
            println!("{s}");
        }
    }
    Ok(())
}
