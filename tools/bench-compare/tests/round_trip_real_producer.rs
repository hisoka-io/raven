//! The differ must consume what a bench actually emits.
//!
//! `bench-compare` shipped with a hand-authored fixture matching its own reader, so the
//! one thing it never proved was that any producer could generate that shape. A rename on
//! either side would have kept every test green.

use bench_compare::{compare, has_regression, Unit, Verdict};
use raven_bench::{BenchFile, BenchReport, GridCell};

fn report(throughput: f64, query_ms: f64) -> BenchReport {
    report_sampled(throughput, query_ms, raven_bench::BenchSamples::default())
}

fn report_sampled(
    throughput: f64,
    query_ms: f64,
    samples: raven_bench::BenchSamples,
) -> BenchReport {
    BenchReport {
        scheme: "inspire".to_owned(),
        cell: GridCell {
            entries_log2: 20,
            record_bytes: 256,
        },
        setup_ms: 1_000.0,
        hint_bytes: 0,
        query_bytes: 148_156,
        response_bytes: 2_048,
        query_ms_median: query_ms,
        server_ms_median: None,
        client_ms_median: None,
        throughput_qps_per_core: throughput,
        measured_queries: 64,
        samples,
    }
}

fn file(r: &BenchReport) -> BenchFile {
    BenchFile {
        hardware: "test-host".to_owned(),
        captured_at: "2026-08-14T00:00:00Z".to_owned(),
        results: r.to_results(),
    }
}

/// The whole point: a real `BenchReport` serializes to JSON the differ parses, with no shim.
#[test]
fn a_real_bench_report_round_trips_through_the_differ() {
    let f = file(&report(800.0, 12.0));
    let json = serde_json::to_string(&f).expect("serialize");
    let parsed: BenchFile =
        serde_json::from_str(&json).expect("the differ must parse a real emission");
    assert_eq!(parsed.results.len(), f.results.len());
    assert!(
        parsed
            .results
            .iter()
            .any(|r| r.bench == "inspire/2e20x256/throughput"),
        "keys must carry scheme and cell; got {:?}",
        parsed.results.iter().map(|r| &r.bench).collect::<Vec<_>>()
    );
}

/// Units survive the wire, and throughput keeps its higher-is-better polarity end to end.
#[test]
fn a_faster_run_diffs_as_an_improvement_not_a_regression() {
    let base = file(&report(800.0, 12.0));
    let cur = file(&report(1_200.0, 6.0));
    let rows = compare(&base, &cur, 0.20);

    let tput = rows
        .iter()
        .find(|r| r.bench.ends_with("/throughput"))
        .expect("throughput row");
    assert_eq!(tput.unit, Unit::QueriesPerSecond);
    assert_eq!(
        tput.verdict,
        Verdict::Improvement,
        "a 50% throughput gain must not read as a regression"
    );

    let lat = rows
        .iter()
        .find(|r| r.bench.ends_with("/query_median"))
        .expect("latency row");
    assert_eq!(lat.unit, Unit::Nanoseconds);
    assert_eq!(
        lat.verdict,
        Verdict::Improvement,
        "halved latency is an improvement"
    );

    assert!(
        !has_regression(&rows),
        "an all-round faster run must pass the gate"
    );
}

/// Absent phases are omitted, not zeroed: a zero would diff as a 100% improvement.
#[test]
fn an_unmeasured_phase_is_omitted_rather_than_reported_as_zero() {
    let r = report(800.0, 12.0);
    assert!(r.server_ms_median.is_none());
    let keys: Vec<String> = r.to_results().into_iter().map(|x| x.bench).collect();
    assert!(
        !keys.iter().any(|k| k.ends_with("/server_median")),
        "an unmeasured phase must not appear at all; got {keys:?}"
    );
}

/// The legacy single-cell shape is what every artifact on disk actually is, and those are
/// the only baselines that exist. Asserted through `load` and the value it yields, because
/// the operator's observable is the loaded file, not an intermediate.
#[test]
fn a_legacy_single_cell_artifact_loads_without_a_shim() {
    const LEGACY: &str = r#"{
      "scheme": "inspire-default",
      "cell": { "entries_log2": 16, "record_bytes": 32 },
      "setup_ms": 4109.573482,
      "hint_bytes": 0,
      "query_bytes": 98840,
      "response_bytes": 32879,
      "query_ms_median": 7.451,
      "server_ms_median": 4.889,
      "client_ms_median": 2.495,
      "throughput_qps_per_core": 131.20238788345947,
      "measured_queries": 16
    }"#;

    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("legacy_single_cell.json");
    std::fs::write(&path, LEGACY).expect("write fixture");

    let loaded = bench_compare::load(&path).expect("a legacy artifact must load");

    let tput = loaded
        .results
        .iter()
        .find(|r| r.bench == "inspire-default/2e16x32/throughput")
        .expect("throughput row keyed by scheme and cell");
    assert_eq!(tput.unit, Unit::QueriesPerSecond);
    assert!(
        (tput.value - 131.202_387_883_459_47).abs() < 1e-9,
        "throughput must survive the legacy decode, got {}",
        tput.value
    );

    let query_bytes = loaded
        .results
        .iter()
        .find(|r| r.bench == "inspire-default/2e16x32/query_bytes")
        .expect("query_bytes row");
    assert_eq!(query_bytes.unit, Unit::Bytes);
    assert!((query_bytes.value - 98_840.0).abs() < f64::EPSILON);
}

/// A file that claims the canonical shape reports the canonical shape's error, so a
/// malformed new-style file is never misdiagnosed as a legacy one.
#[test]
fn a_malformed_canonical_file_names_the_canonical_field() {
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("broken_canonical.json");
    std::fs::write(&path, r#"{ "results": [ { "bench": "x" } ] }"#).expect("write fixture");

    let err = bench_compare::load(&path).expect_err("a canonical file missing `value` must fail");
    let text = err.to_string();
    assert!(
        text.contains("value"),
        "the error must name the missing canonical field, got: {text}"
    );
}

fn one_result(bench: &str, value: f64, unit: Unit) -> raven_bench::BenchResult {
    raven_bench::BenchResult {
        bench: bench.to_owned(),
        value,
        unit,
        samples: Vec::new(),
    }
}

fn file_of(results: Vec<raven_bench::BenchResult>) -> BenchFile {
    BenchFile {
        hardware: "test-host".to_owned(),
        captured_at: "2026-08-15T00:00:00Z".to_owned(),
        results,
    }
}

/// A bench the baseline measured and this run did not is a measurement that never
/// happened. Exiting 0 on it is how a silently broken bench run passes the gate.
#[test]
fn a_bench_missing_from_the_current_run_fails_the_gate() {
    let base = file_of(vec![
        one_result("inspire/2e20x256/query_median", 12.0, Unit::Nanoseconds),
        one_result("inspire/2e20x256/throughput", 800.0, Unit::QueriesPerSecond),
    ]);
    let cur = file_of(vec![one_result(
        "inspire/2e20x256/query_median",
        12.0,
        Unit::Nanoseconds,
    )]);

    let rows = compare(&base, &cur, 0.20);
    let missing = rows
        .iter()
        .find(|r| r.bench.ends_with("/throughput"))
        .expect("throughput row");
    assert_eq!(missing.verdict, Verdict::CurrentMissing);
    assert!(
        has_regression(&rows),
        "a bench that vanished from this run must fail the gate"
    );
}

/// The inverse must stay passing: adding a new bench has nothing to compare against.
#[test]
fn a_newly_added_bench_passes_the_gate() {
    let base = file_of(vec![one_result(
        "inspire/2e20x256/query_median",
        12.0,
        Unit::Nanoseconds,
    )]);
    let cur = file_of(vec![
        one_result("inspire/2e20x256/query_median", 12.0, Unit::Nanoseconds),
        one_result("inspire/2e20x256/setup", 900.0, Unit::Nanoseconds),
    ]);

    let rows = compare(&base, &cur, 0.20);
    let added = rows
        .iter()
        .find(|r| r.bench.ends_with("/setup"))
        .expect("setup row");
    assert_eq!(added.verdict, Verdict::BaselineMissing);
    assert!(
        !has_regression(&rows),
        "a newly added bench must not fail the gate"
    );
}

/// The printed summary and the process exit code are derived from one predicate. They
/// disagreed: the summary counted only `Regression`, so a unit change printed
/// "Exit code: 0" on a run that exits 1.
#[test]
fn the_printed_summary_agrees_with_the_exit_code() {
    let base = file_of(vec![one_result(
        "inspire/2e20x256/throughput",
        800.0,
        Unit::QueriesPerSecond,
    )]);
    let cur = file_of(vec![one_result(
        "inspire/2e20x256/throughput",
        800.0,
        Unit::Nanoseconds,
    )]);

    let rows = compare(&base, &cur, 0.20);
    assert_eq!(rows[0].verdict, Verdict::UnitMismatch);
    assert!(has_regression(&rows), "a unit change must fail the gate");

    let rendered = bench_compare::render_human("base.json", "cur.json", 0.20, &rows);
    assert!(
        rendered.contains("Exit code: 1"),
        "the summary must announce the code the process actually returns; got:\n{rendered}"
    );
    assert!(
        rendered.contains("changed units"),
        "the summary must name why the gate failed; got:\n{rendered}"
    );
}

/// `welch_p` had no data: `to_results` hardcoded `Vec::new()` at every site, so every
/// p-value in every real comparison was `n/a` while the Welch machinery and its tests
/// stayed green. This asserts the significance half is actually reachable end to end.
#[test]
fn a_sampled_run_produces_a_p_value_through_the_differ() {
    let base_samples = raven_bench::BenchSamples {
        query_us: vec![1_000, 1_010, 990, 1_005, 995],
        server_us: vec![400, 402, 398, 401, 399],
        client_us: vec![600, 608, 592, 604, 596],
    };
    let cur_samples = raven_bench::BenchSamples {
        query_us: vec![2_000, 2_010, 1_990, 2_005, 1_995],
        server_us: vec![800, 802, 798, 801, 799],
        client_us: vec![1_200, 1_208, 1_192, 1_204, 1_196],
    };

    let base = file(&report_sampled(800.0, 1.0, base_samples));
    let cur = file(&report_sampled(800.0, 2.0, cur_samples));
    let rows = compare(&base, &cur, 0.20);

    let q = rows
        .iter()
        .find(|r| r.bench.ends_with("/query_median"))
        .expect("query_median row");
    let p = q
        .p_value
        .expect("a sampled comparison must yield a p-value, not n/a");
    assert!(
        p < 0.01,
        "two clearly separated distributions must be significant, got p={p}"
    );
    assert_eq!(
        q.verdict,
        Verdict::Regression,
        "doubled latency is a regression"
    );
}

/// And the honest inverse: with no samples the differ must say `n/a` rather than
/// manufacture significance.
#[test]
fn an_unsampled_run_reports_no_p_value() {
    let base = file(&report(800.0, 12.0));
    let cur = file(&report(800.0, 12.5));
    let rows = compare(&base, &cur, 0.20);
    let q = rows
        .iter()
        .find(|r| r.bench.ends_with("/query_median"))
        .expect("query_median row");
    assert_eq!(q.p_value, None, "no samples means no p-value");
}
