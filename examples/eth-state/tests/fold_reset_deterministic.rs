//! Fold/reset gate: deterministic in-process fold + reset (no chain).
//!
//! Seeds N>2048 accounts across 3 shards, drives in-place updates into shards 0 and 2
//! only (shard 1 untouched), folds once, and asserts: (a) only the dirty shards are
//! re-encoded; (b) the post-fold main answers updated + untouched balances byte-identically;
//! (c) the sidecar is reset to empty; (d) the main epoch advanced by exactly 1; (e) a
//! captured pre-fold snapshot still answers the pre-fold balance (old main served throughout).
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic, clippy::print_stdout, clippy::print_stderr)]


use bytes::Bytes;

use eth_state::fold::MainSidecar;
use eth_state::{build_session, FlatBalanceScheme, ENTRY_SIZE};
use raven_client::{build_seeded_query_rust, extract_response_rust};
use raven_inspire::params::{InspireParams, ShardConfig};
use raven_inspire::{ClientSession, SeededClientQuery, ServerCrs, ServerResponse};
use raven_server::PirScheme;

fn expected_be(balance: u128) -> [u8; ENTRY_SIZE] {
    let mut rec = [0u8; ENTRY_SIZE];
    rec[16..].copy_from_slice(&balance.to_be_bytes());
    rec
}

fn bytes_be(balance: u128) -> Bytes {
    Bytes::copy_from_slice(&expected_be(balance))
}

fn read(
    session: &ClientSession,
    params: &InspireParams,
    shard_cfg: &ShardConfig,
    crs: &ServerCrs,
    respond: impl FnOnce(&SeededClientQuery) -> ServerResponse,
    leaf: u64,
) -> Vec<u8> {
    let (state, q) = build_seeded_query_rust(session, params, shard_cfg, leaf).expect("query");
    let resp = respond(&q);
    extract_response_rust(crs, &state, &resp, ENTRY_SIZE).expect("extract")
}

#[test]
fn fold_reset_deterministic() {
    let params = InspireParams::secure_128_d2048();
    let dir = tempfile::tempdir().expect("tempdir");

    // 5000 accounts span shards 0 (0..2048), 1 (2048..4096), 2 (4096..5000). balance = leaf+1.
    let n = 5000usize;
    let mut db = vec![0u8; n * ENTRY_SIZE];
    for leaf in 0..n {
        db[leaf * ENTRY_SIZE..(leaf + 1) * ENTRY_SIZE]
            .copy_from_slice(&expected_be((leaf as u128) + 1));
    }

    let (mut ms, main_sk, side_sk) =
        MainSidecar::seed(&params, &db, ENTRY_SIZE, dir.path(), 0x0000_F01D).expect("seed");

    let main_crs = ms.main.current_snapshot().state.crs.clone();
    let side_crs = ms.sidecar.current_snapshot().state.crs.clone();
    let shard_cfg = ms.main.current_snapshot().state.encoded_db.config.clone();
    let main_session = build_session(&main_crs, main_sk, params.sigma, 1).expect("main session");
    let side_session = build_session(&side_crs, side_sk, params.sigma, 2).expect("side session");

    // 128 updates in shards 0 and 2 ONLY (shard 1 untouched), crossing the shard boundary.
    let mut updates = Vec::new();
    for leaf in 0u64..64 {
        updates.push((leaf, bytes_be((leaf as u128) + 1_000_000)));
    }
    for leaf in 4096u64..4160 {
        updates.push((leaf, bytes_be((leaf as u128) + 1_000_000)));
    }
    ms.apply_updates(1, &updates).expect("apply updates");

    let pre_snap = ms.main.current_snapshot();
    let pre_epoch = pre_snap.epoch;

    ms.fold().expect("fold");

    // (a) bounded materialization: only the 2 dirty shards (0, 2) re-encoded, not all 3.
    assert_eq!(
        ms.re_encode_count(),
        2,
        "only the 2 dirty shards re-encoded, not num_shards (3)"
    );

    // (b) post-fold correctness: updated leaf is fresh; untouched shard-1 leaf is unchanged.
    let b10 = read(
        &main_session,
        &params,
        &shard_cfg,
        &main_crs,
        |q| ms.main.query(q).expect("main respond").1,
        10,
    );
    assert_eq!(&b10[..], &expected_be(10 + 1_000_000)[..], "post-fold updated leaf 10");
    let b2500 = read(
        &main_session,
        &params,
        &shard_cfg,
        &main_crs,
        |q| ms.main.query(q).expect("main respond").1,
        2500,
    );
    assert_eq!(&b2500[..], &expected_be(2501)[..], "untouched shard-1 leaf 2500");

    // (c) sidecar reset to empty.
    let b_side = read(
        &side_session,
        &params,
        &shard_cfg,
        &side_crs,
        |q| ms.sidecar.query(q).expect("sidecar respond").1,
        10,
    );
    assert_eq!(&b_side[..], &[0u8; ENTRY_SIZE][..], "sidecar reset to empty after fold");

    // (d) epoch advanced by exactly 1.
    assert_eq!(ms.main.current_epoch(), pre_epoch.next(), "main epoch advanced by 1");

    // (e) old main served continuously: the captured pre-fold snapshot still answers the
    // pre-fold balance after the swap landed (snapshot isolation across swap_state).
    let b10_old = read(
        &main_session,
        &params,
        &shard_cfg,
        &main_crs,
        |q| <FlatBalanceScheme as PirScheme>::respond(&pre_snap.state, q).expect("snap respond"),
        10,
    );
    assert_eq!(&b10_old[..], &expected_be(11)[..], "captured pre-fold snapshot answers old balance");
}
