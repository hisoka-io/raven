//! Resilience scenarios (local, no chain): kill-mid-fold recovery, append past a
//! shard boundary, and fold-while-serving. Each is its own asserting test.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic, clippy::print_stdout, clippy::print_stderr)]


use eth_state::fold::MainSidecar;
use eth_state::harness::Demo;
use eth_state::ingest::normalize_balance_be;
use eth_state::{build_session, AnsweringEngine, ENTRY_SIZE};
use raven_client::{build_seeded_query_rust, extract_response_rust};
use raven_inspire::params::InspireParams;
use serial_test::serial;

/// Read one leaf directly from a recovered main engine (single-engine, post-crash check).
fn read_recovered_main(ms: &MainSidecar, sk: raven_inspire::rlwe::RlweSecretKey, leaf: u64) -> Vec<u8> {
    let params = InspireParams::secure_128_d2048();
    let crs = ms.main.current_snapshot().state.crs.clone();
    let shard_cfg = ms.main.current_snapshot().state.encoded_db.config.clone();
    let session = build_session(&crs, sk, params.sigma, 1).expect("session");
    let (state, q) = build_seeded_query_rust(&session, &params, &shard_cfg, leaf).expect("query");
    let (_e, resp) = ms.main.query(&q).expect("respond");
    extract_response_rust(&crs, &state, &resp, ENTRY_SIZE).expect("extract")
}

/// A balance update is durable in the WAL before a fold; a crash + recover replays it, so the
/// served state is unchanged. (commit-then-clear + reset-LAST means a crash mid-fold never
/// loses a recently-updated balance.)
#[test]
#[serial]
fn kill_mid_fold_recover() {
    let dir = tempfile::tempdir().expect("tempdir");
    let seed = 0x0000_1701u64;

    {
        let mut demo = Demo::new(3000, 1_000_000, dir.path(), seed).expect("demo");
        // apply a balance update at block 5 (WAL append, no fold yet), then "crash" (drop).
        let addr = demo.accounts[77];
        demo.apply_block(5, &[(addr, 424_242)]).expect("apply");
    }

    // recover from the V6 snapshot + WAL replay; the recovered main answers the updated balance.
    let (ms2, main_sk, _side_sk) =
        MainSidecar::recover(&InspireParams::secure_128_d2048(), ENTRY_SIZE, dir.path(), seed)
            .expect("recover");
    let got = read_recovered_main(&ms2, main_sk, 77);
    let expected = normalize_balance_be(&(424_242u128).to_be_bytes()).expect("norm");
    assert_eq!(&got[..], &expected[..], "kill-mid-fold: recovered served state byte-identical");
}

/// Appending an account past the current shard boundary creates a new shard that, after a
/// fold, answers byte-identically.
#[test]
#[serial]
fn append_past_shard_boundary() {
    let dir = tempfile::tempdir().expect("tempdir");
    // 4096 accounts = exactly two full shards (0, 1); the next account lands in shard 2.
    let mut demo = Demo::new(4096, 1_000_000, dir.path(), 0x0000_5A1D).expect("demo");
    let mut newaddr = [0u8; 20];
    newaddr[12..].copy_from_slice(&4096u64.to_be_bytes());

    // Appending into a new shard grows main at APPLY time (ensure_main_covers swaps main), so the
    // main epoch advances by one before any fold - the contract is monotonic-per-swap, not
    // exactly-+1-per-fold.
    let pre_epoch = demo.ms.main.current_epoch();
    demo.apply_block(1, &[(newaddr, 999_999)]).expect("apply new shard");
    assert_eq!(
        demo.ms.main.current_epoch(),
        pre_epoch.next(),
        "apply-time shard growth advances the main epoch by one"
    );

    // PRE-fold: the appended leaf lives in a shard main did not originally hold. The fan-out
    // must still answer byte-identically - main grows a zero shard at apply so its leg returns
    // absent and the consume-both selection falls through to the sidecar's fresh value, rather
    // than erroring on a missing-shard main leg.
    let (ok_pre, eng_pre) = demo.read_verify(&newaddr).expect("pre-fold read appended");
    assert!(ok_pre, "append-past-boundary: pre-fold read byte-identical");
    assert_eq!(eng_pre, AnsweringEngine::Sidecar, "pre-fold: sidecar serves the appended leaf");

    demo.fold().expect("fold");
    let (ok, eng) = demo.read_verify(&newaddr).expect("post-fold read appended");
    assert!(ok, "append-past-shard-boundary: post-fold new shard answers byte-identically");
    assert_eq!(eng, AnsweringEngine::Main, "post-fold: main serves the folded leaf");
}

/// The structural presence tag closes the zero-balance hole: a balance changed to exactly zero
/// is tagged-present in the sidecar, so a pre-fold read is served fresh by the SIDECAR and is
/// byte-identical to the ledger (no stale main fallback). The fold keeps it correct.
#[test]
#[serial]
fn zero_balance_heals_via_tag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut demo = Demo::new(3000, 1_000_000, dir.path(), 0x0000_2E20).expect("demo");
    let addr = demo.accounts[321];
    demo.apply_block(1, &[(addr, 0)]).expect("zero the balance");

    // Pre-fold: the sidecar's record is tagged-present even at zero, so the fan-out selects it
    // and the read is byte-identical to the ledger - the old stale-main hole is closed.
    let (ok_pre, eng_pre) = demo.read_verify(&addr).expect("pre-fold read");
    assert!(ok_pre, "present-zero read is byte-identical to the ledger pre-fold");
    assert_eq!(eng_pre, AnsweringEngine::Sidecar, "present-zero is served fresh by the sidecar");

    demo.fold().expect("fold");
    let (ok_post, _eng) = demo.read_verify(&addr).expect("post-fold read");
    assert!(ok_post, "still correct after the fold");
}

/// Reads are correct across a fold: a fresh account is served by the sidecar before the fold
/// and by main after (the swap is atomic; no read returns a wrong balance).
#[test]
#[serial]
fn fold_while_serving() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut demo = Demo::new(3000, 1_000_000, dir.path(), 0x0000_F01D).expect("demo");
    let addr = demo.accounts[123];
    demo.apply_block(1, &[(addr, 555_555)]).expect("apply");

    let (ok_pre, eng_pre) = demo.read_verify(&addr).expect("pre-fold read");
    assert!(ok_pre, "pre-fold read byte-identical");
    assert_eq!(eng_pre, AnsweringEngine::Sidecar, "pre-fold: sidecar serves the fresh value");

    demo.fold().expect("fold");

    let (ok_post, eng_post) = demo.read_verify(&addr).expect("post-fold read");
    assert!(ok_post, "post-fold read byte-identical");
    assert_eq!(eng_post, AnsweringEngine::Main, "post-fold: main serves the folded value");

    // an untouched account is correct throughout.
    let untouched = demo.accounts[200];
    let (ok_u, _) = demo.read_verify(&untouched).expect("untouched read");
    assert!(ok_u, "untouched account byte-identical across the fold");
}
