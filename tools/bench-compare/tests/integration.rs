//! Integration tests for the `bench-compare` CLI.

use assert_cmd::Command;
use predicates::str::contains;
use std::fs;
use tempfile::tempdir;

fn write_json(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    fs::write(&p, body).expect("write fixture");
    p
}

const BASELINE_1000: &str = r#"{
  "hardware": "test-host",
  "captured_at": "2026-05-01T00:00:00Z",
  "results": [
    { "bench": "bench_a", "median_ns": 1000.0, "samples_ns": [995.0, 1000.0, 1005.0] }
  ]
}"#;

const CURRENT_1500: &str = r#"{
  "hardware": "test-host",
  "captured_at": "2026-05-02T00:00:00Z",
  "results": [
    { "bench": "bench_a", "median_ns": 1500.0, "samples_ns": [1490.0, 1500.0, 1510.0] }
  ]
}"#;

const CURRENT_500: &str = r#"{
  "hardware": "test-host",
  "captured_at": "2026-05-02T00:00:00Z",
  "results": [
    { "bench": "bench_a", "median_ns": 500.0, "samples_ns": [495.0, 500.0, 505.0] }
  ]
}"#;

#[test]
fn identity_comparison_zero_diff() {
    let dir = tempdir().expect("tmp");
    let baseline = write_json(dir.path(), "baseline.json", BASELINE_1000);

    let mut cmd = Command::cargo_bin("bench-compare").expect("binary");
    cmd.arg(&baseline).arg(&baseline);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8");
    assert!(stdout.contains("identical"), "expected 'identical' verdict, got:\n{stdout}");
    assert!(stdout.contains("+0.0%"), "expected zero delta, got:\n{stdout}");
    assert!(stdout.contains("Exit code: 0"), "expected zero-exit summary, got:\n{stdout}");
}

#[test]
fn significant_regression_detected() {
    let dir = tempdir().expect("tmp");
    let baseline = write_json(dir.path(), "baseline.json", BASELINE_1000);
    let current = write_json(dir.path(), "current.json", CURRENT_1500);

    let mut cmd = Command::cargo_bin("bench-compare").expect("binary");
    cmd.arg(&baseline).arg(&current).arg("--regression-threshold").arg("0.20");
    cmd.assert()
        .failure()
        .code(1)
        .stdout(contains("REGRESSION"))
        .stdout(contains("+50.0%"));
}

#[test]
fn significant_improvement_acknowledged() {
    let dir = tempdir().expect("tmp");
    let baseline = write_json(dir.path(), "baseline.json", BASELINE_1000);
    let current = write_json(dir.path(), "current.json", CURRENT_500);

    let mut cmd = Command::cargo_bin("bench-compare").expect("binary");
    cmd.arg(&baseline).arg(&current).arg("--regression-threshold").arg("0.20");
    cmd.assert()
        .success()
        .stdout(contains("IMPROVEMENT"))
        .stdout(contains("-50.0%"));
}

#[test]
fn json_format_emits_array() {
    let dir = tempdir().expect("tmp");
    let baseline = write_json(dir.path(), "baseline.json", BASELINE_1000);
    let current = write_json(dir.path(), "current.json", CURRENT_1500);

    let mut cmd = Command::cargo_bin("bench-compare").expect("binary");
    cmd.arg(&baseline).arg(&current).arg("--format").arg("json");
    let assert = cmd.assert().failure().code(1);
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8");
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    let arr = parsed.as_array().expect("array");
    assert_eq!(arr.len(), 1, "one bench expected");
    assert_eq!(arr[0]["verdict"], "Regression");
    assert_eq!(arr[0]["bench"], "bench_a");
}
