//! C1/C2/C5 gate: WRITE firehose + concurrent verified READs (Tier-A synthetic, deterministic).
//!
//! C1: every private read is byte-identical to the independent ground-truth ledger (zero
//! tolerance). C2: the freshness guard refuses any answer with lag > N. C5: the served-state
//! lag stays bounded under sustained load and the serving-QPS is reported honestly as JSON.
//! `head_ahead` runs the chain ahead of raven's marker so the lag the gates assert is real.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic, clippy::print_stdout, clippy::print_stderr)]


use eth_state::harness::Demo;
use eth_state::EthStateError;
use serial_test::serial;

#[test]
#[serial]
fn stress_c1_c2_c5() {
    let dir = tempfile::tempdir().expect("tempdir");
    // N > 2048 across multiple shards; large seed balance so no transfer drives a balance to
    // exactly 0 (the presence-predicate ambiguity).
    let mut demo = Demo::new(3000, 1_000_000, dir.path(), 0x0000_C5C5).expect("demo");
    // 20 rounds, fold every 5, 1 random read/round on top of the touched reads, N=2, the chain
    // running 1 block ahead of the marker (a real bounded lag, not the old vacuous 0).
    let res = demo.run_stress(20, 5, 1, 2, 1, 0x0000_C5C5).expect("stress");

    assert_eq!(
        res.c1_failures, 0,
        "C1: every read byte-identical to the ledger; got {} failures",
        res.c1_failures
    );
    // C2/C5: the lag is the injected head_ahead (1), genuinely measured, bounded under N=2.
    assert_eq!(res.max_lag, 1, "C2/C5: lag is the real injected head_ahead, got {}", res.max_lag);
    assert!(res.reads >= 40, "served a meaningful read load, got {}", res.reads);
    assert!(res.sidecar_hits > 0, "the sidecar answered fresh reads, got {}", res.sidecar_hits);
    assert!(res.qps_per_core > 0.0, "QPS measured");
    assert!(res.fold_count >= 3, "folds ran under load, got {}", res.fold_count);

    // C5 honest serving-QPS curve (machine-measured) as structured JSON.
    eprintln!(
        "{{\"bench\":\"eth_state_stress\",\"reads\":{},\"folds\":{},\"sidecar_hits\":{},\"mean_read_ms\":{:.3},\"qps_per_core\":{:.1},\"max_lag\":{}}}",
        res.reads, res.fold_count, res.sidecar_hits, res.mean_read_ms, res.qps_per_core, res.max_lag
    );
}

/// C2 guard efficacy: it stays clear at the inclusive bound (lag == N) and provably fires one
/// block past it (lag == N+1), with the exact message and numeric lag.
#[test]
#[serial]
fn c2_freshness_guard_boundary_and_fire() {
    // BOUNDARY: head_ahead == N -> lag == N, the guard does NOT fire; the read loop runs and C1
    // holds (a lag exactly at the bound is trusted).
    let dir = tempfile::tempdir().expect("tempdir");
    let mut demo = Demo::new(2048, 1_000_000, dir.path(), 0x0000_B0DE).expect("demo");
    let res = demo.run_stress(4, 4, 1, 2, 2, 0x0000_B0DE).expect("boundary lag == N is trusted");
    assert_eq!(res.max_lag, 2, "lag pinned at the inclusive bound N");
    assert!(res.reads > 0, "the read loop actually ran at the bound");
    assert_eq!(res.c1_failures, 0, "C1 holds at the freshness bound");

    // FIRE: head_ahead == N+1 -> lag == N+1 > N, the guard fires on the first trusted read.
    let dir2 = tempfile::tempdir().expect("tempdir");
    let mut demo2 = Demo::new(2048, 1_000_000, dir2.path(), 0x0000_F12E).expect("demo");
    match demo2.run_stress(4, 4, 1, 2, 3, 0x0000_F12E) {
        Err(EthStateError::Query(msg)) => assert!(
            msg.contains("freshness violated: lag 3 > N 2"),
            "exact freshness message + numeric lag N+1; got: {msg}"
        ),
        other => panic!("expected the freshness guard to fire (Query err); got {other:?}"),
    }
}
