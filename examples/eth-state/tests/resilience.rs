//! Kill-mid-fold recovery, append past a shard boundary, and fold-while-serving.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use eth_state::fold::MainSidecar;
use eth_state::harness::Demo;
use eth_state::ingest::normalize_balance_be;
use eth_state::{build_session, AnsweringEngine, ENTRY_SIZE};
use raven_client::{build_seeded_query_rust, extract_response_rust};
use raven_inspire::params::InspireParams;
use serial_test::serial;

fn read_recovered_main(
    ms: &MainSidecar,
    sk: raven_inspire::rlwe::RlweSecretKey,
    leaf: u64,
) -> Vec<u8> {
    let params = InspireParams::secure_128_d2048();
    let crs = ms.main.current_snapshot().state.crs.clone();
    let shard_cfg = ms.main.current_snapshot().state.encoded_db.config.clone();
    let session = build_session(&crs, sk, params.sigma, 1).expect("session");
    let (state, q) = build_seeded_query_rust(&session, &params, &shard_cfg, leaf).expect("query");
    let (_e, resp) = ms.main.query(&q).expect("respond");
    extract_response_rust(&crs, &state, &resp, ENTRY_SIZE).expect("extract")
}

#[test]
#[serial]
fn kill_mid_fold_recover() {
    let dir = tempfile::tempdir().expect("tempdir");
    let seed = 0x0000_1701u64;

    {
        let mut demo = Demo::new(3000, 1_000_000, dir.path(), seed).expect("demo");
        let addr = demo.accounts[77];
        demo.apply_block(5, &[(addr, 424_242)]).expect("apply");
    }

    let (ms2, main_sk, _side_sk) = MainSidecar::recover(
        &InspireParams::secure_128_d2048(),
        ENTRY_SIZE,
        dir.path(),
        seed,
    )
    .expect("recover");
    let got = read_recovered_main(&ms2, main_sk, 77);
    let expected = normalize_balance_be(&(424_242u128).to_be_bytes()).expect("norm");
    assert_eq!(
        &got[..],
        &expected[..],
        "kill-mid-fold: recovered served state byte-identical"
    );
}

#[test]
#[serial]
fn append_past_shard_boundary() {
    let dir = tempfile::tempdir().expect("tempdir");
    // 4096 fills shards 0 and 1 exactly, so the next account lands in shard 2.
    let mut demo = Demo::new(4096, 1_000_000, dir.path(), 0x0000_5A1D).expect("demo");
    let mut newaddr = [0u8; 20];
    newaddr[12..].copy_from_slice(&4096u64.to_be_bytes());

    // Shard growth happens at apply time, so the epoch advances before any fold.
    let pre_epoch = demo.ms.main.current_epoch();
    demo.apply_block(1, &[(newaddr, 999_999)])
        .expect("apply new shard");
    assert_eq!(
        demo.ms.main.current_epoch(),
        pre_epoch.next(),
        "apply-time shard growth advances the main epoch by one"
    );

    // Main grew a zero shard at apply, so its leg reads absent rather than erroring.
    let (ok_pre, eng_pre) = demo.read_verify(&newaddr).expect("pre-fold read appended");
    assert!(ok_pre, "append-past-boundary: pre-fold read byte-identical");
    assert_eq!(
        eng_pre,
        AnsweringEngine::Sidecar,
        "pre-fold: sidecar serves the appended leaf"
    );

    demo.fold().expect("fold");
    let (ok, eng) = demo.read_verify(&newaddr).expect("post-fold read appended");
    assert!(
        ok,
        "append-past-shard-boundary: post-fold new shard answers byte-identically"
    );
    assert_eq!(
        eng,
        AnsweringEngine::Main,
        "post-fold: main serves the folded leaf"
    );
}

#[test]
#[serial]
fn zero_balance_heals_via_tag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut demo = Demo::new(3000, 1_000_000, dir.path(), 0x0000_2E20).expect("demo");
    let addr = demo.accounts[321];
    demo.apply_block(1, &[(addr, 0)]).expect("zero the balance");

    let (ok_pre, eng_pre) = demo.read_verify(&addr).expect("pre-fold read");
    assert!(
        ok_pre,
        "present-zero read is byte-identical to the ledger pre-fold"
    );
    assert_eq!(
        eng_pre,
        AnsweringEngine::Sidecar,
        "present-zero is served fresh by the sidecar"
    );

    demo.fold().expect("fold");
    let (ok_post, _eng) = demo.read_verify(&addr).expect("post-fold read");
    assert!(ok_post, "still correct after the fold");
}

#[test]
#[serial]
fn fold_while_serving() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut demo = Demo::new(3000, 1_000_000, dir.path(), 0x0000_F01D).expect("demo");
    let addr = demo.accounts[123];
    demo.apply_block(1, &[(addr, 555_555)]).expect("apply");

    let (ok_pre, eng_pre) = demo.read_verify(&addr).expect("pre-fold read");
    assert!(ok_pre, "pre-fold read byte-identical");
    assert_eq!(
        eng_pre,
        AnsweringEngine::Sidecar,
        "pre-fold: sidecar serves the fresh value"
    );

    demo.fold().expect("fold");

    let (ok_post, eng_post) = demo.read_verify(&addr).expect("post-fold read");
    assert!(ok_post, "post-fold read byte-identical");
    assert_eq!(
        eng_post,
        AnsweringEngine::Main,
        "post-fold: main serves the folded value"
    );

    let untouched = demo.accounts[200];
    let (ok_u, _) = demo.read_verify(&untouched).expect("untouched read");
    assert!(ok_u, "untouched account byte-identical across the fold");
}
