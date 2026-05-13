//! CLI entry point for `bench-compare`.

use bench_compare::{compare, has_regression, load, render_human, Comparison};
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
             Supplementary p-value uses Welch t with Welch-Satterthwaite df \
             and Student's t two-sided CDF (regularized incomplete beta + \
             Lanczos lnGamma); valid at small n.",
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
    /// Fractional regression threshold (0.20 == +20%).
    #[arg(long, default_value_t = 0.20)]
    regression_threshold: f64,
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
    let baseline = load(&args.baseline)?;
    let current = load(&args.current)?;
    let rows = compare(&baseline, &current, args.regression_threshold);
    emit(args, &rows)?;
    Ok(if has_regression(&rows) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn emit(args: &Args, rows: &[Comparison]) -> Result<(), Box<dyn std::error::Error>> {
    match args.format {
        Format::Human => {
            print!(
                "{}",
                render_human(
                    &args.baseline.display().to_string(),
                    &args.current.display().to_string(),
                    args.regression_threshold,
                    rows,
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
