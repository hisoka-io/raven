//! The committed baseline, checked against itself.
//!
//! The gate compares a fresh run to this file. Nothing compared the file to anything, so it
//! sat six times above the real figure for three weeks while every run scored IMPROVEMENT
//! and exited 0. These cases give the pin a reader: it must parse, it must be self-
//! consistent, and every byte count in it must be accompanied by the closed form that
//! produced it - so a re-pin to a number nobody can derive fails here rather than shipping.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "a test asserts by failing; the message is the diagnostic"
)]

use bench_compare::{compare, has_regression, BenchFile, Unit, DERIVED_SUFFIX};
use std::path::PathBuf;

/// `hint_bytes` is `0` by construction: InsPIRe is hintless, and emitting a computed value
/// for it is a recorded protection in `AGENTS.md`. It is the one byte row with no shape to
/// derive from.
const UNDERIVED_METRICS: [&str; 1] = ["hint_bytes"];

fn baselines_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("benches");
    p.push("baselines");
    p
}

fn tracked_baselines() -> Vec<(PathBuf, BenchFile)> {
    let dir = baselines_dir();
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("baselines directory must exist") {
        let path = entry.expect("readable directory entry").path();
        if path.extension().is_some_and(|e| e == "json") {
            let loaded = bench_compare::load(&path)
                .unwrap_or_else(|e| panic!("{} must load: {e}", path.display()));
            out.push((path, loaded));
        }
    }
    assert!(
        !out.is_empty(),
        "no baseline in {} - the armed gate would silently degrade to 'nothing to compare'",
        dir.display()
    );
    out
}

/// Every pinned byte count carries the prediction it was produced from. This is what makes
/// the JSON the only copy: a re-pin that edits the measurement alone reds here, and a re-pin
/// that edits both has to state a shape somebody can check.
#[test]
fn every_pinned_byte_count_in_the_tracked_baseline_is_derivable() {
    for (path, file) in tracked_baselines() {
        for row in &file.results {
            if row.unit != Unit::Bytes || row.bench.ends_with(DERIVED_SUFFIX) {
                continue;
            }
            let metric = row.bench.rsplit('/').next().unwrap_or(&row.bench);
            if UNDERIVED_METRICS.contains(&metric) {
                continue;
            }
            let derived_name = format!("{}{DERIVED_SUFFIX}", row.bench);
            let derived = file
                .results
                .iter()
                .find(|r| r.bench == derived_name)
                .unwrap_or_else(|| {
                    panic!(
                        "{}: {} is pinned at {} B with no {derived_name} beside it. Re-pin from \
                         a producer run rather than by hand; a figure nobody can re-derive is a \
                         copy, not a pin.",
                        path.display(),
                        row.bench,
                        row.value
                    )
                });
            assert_eq!(
                row.value,
                derived.value,
                "{}: {} pins {} B but its own closed form says {} B",
                path.display(),
                row.bench,
                row.value,
                derived.value
            );
        }
    }
}

/// A baseline that cannot pass the gate against itself is not usable as a pin, whatever it
/// says. This is the cheapest statement of that, and it is the one the gate's own exit code
/// depends on.
#[test]
fn the_tracked_baseline_passes_the_gate_against_itself() {
    for (path, file) in tracked_baselines() {
        let rows = compare(&file, &file, 0.15);
        assert!(
            !has_regression(&rows),
            "{} fails the gate when diffed against itself",
            path.display()
        );
    }
}

/// The instrument, fed a case it must reject. Without this the two cases above pass on an
/// empty rule set as readily as on a correct one.
#[test]
fn the_derivation_check_rejects_a_pin_that_walked_away_from_its_shape() {
    let (_, mut file) = tracked_baselines()
        .into_iter()
        .next()
        .expect("at least one baseline");
    let derived_name = file
        .results
        .iter()
        .find(|r| r.bench.ends_with(DERIVED_SUFFIX))
        .map(|r| r.bench.clone())
        .expect("the tracked baseline must carry at least one closed form");
    let measured_name = derived_name
        .strip_suffix(DERIVED_SUFFIX)
        .expect("suffix present")
        .to_owned();

    for row in &mut file.results {
        if row.bench == measured_name {
            row.value -= 1.0;
        }
    }
    let rows = compare(&file, &file, 0.15);
    assert!(
        has_regression(&rows),
        "a pin one byte off its own closed form must fail, or these cases prove nothing"
    );
}
