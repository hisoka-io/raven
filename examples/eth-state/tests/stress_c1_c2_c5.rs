//! Write firehose with concurrent verified reads. `head_ahead` runs the chain ahead of the
//! applied marker so the freshness lag the gates assert is a real non-zero value.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use eth_state::harness::Demo;
use eth_state::EthStateError;
use serial_test::serial;

#[test]
#[serial]
fn stress_c1_c2_c5() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Seed balance large enough that no transfer drives an account to exactly 0.
    let mut demo = Demo::new(3000, 1_000_000, dir.path(), 0x0000_C5C5).expect("demo");
    let res = demo
        .run_stress(20, 5, 1, 2, 1, 0x0000_C5C5)
        .expect("stress");

    assert_eq!(
        res.c1_failures, 0,
        "C1: every read byte-identical to the ledger; got {} failures",
        res.c1_failures
    );
    assert_eq!(
        res.max_lag, 1,
        "C2/C5: lag is the real injected head_ahead, got {}",
        res.max_lag
    );
    assert!(
        res.reads >= 40,
        "served a meaningful read load, got {}",
        res.reads
    );
    assert!(
        res.sidecar_hits > 0,
        "the sidecar answered fresh reads, got {}",
        res.sidecar_hits
    );
    assert!(res.qps_per_core > 0.0, "QPS measured");
    assert!(
        res.fold_count >= 3,
        "folds ran under load, got {}",
        res.fold_count
    );

    eprintln!(
        "{{\"bench\":\"eth_state_stress\",\"reads\":{},\"folds\":{},\"sidecar_hits\":{},\"mean_read_ms\":{:.3},\"qps_per_core\":{:.1},\"max_lag\":{}}}",
        res.reads, res.fold_count, res.sidecar_hits, res.mean_read_ms, res.qps_per_core, res.max_lag
    );
}

/// The bound is inclusive: clear at lag == N, fires at N+1.
#[test]
#[serial]
fn c2_freshness_guard_boundary_and_fire() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut demo = Demo::new(2048, 1_000_000, dir.path(), 0x0000_B0DE).expect("demo");
    let res = demo
        .run_stress(4, 4, 1, 2, 2, 0x0000_B0DE)
        .expect("boundary lag == N is trusted");
    assert_eq!(res.max_lag, 2, "lag pinned at the inclusive bound N");
    assert!(res.reads > 0, "the read loop actually ran at the bound");
    assert_eq!(res.c1_failures, 0, "C1 holds at the freshness bound");

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
