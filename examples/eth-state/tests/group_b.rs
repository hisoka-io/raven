//! Fold/encode optimization gates: bounded-materializer early-break, whole-shard dedup of the
//! fold re-encode, and WAL archive bounding the next recover's replay.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic, clippy::print_stdout, clippy::print_stderr)]


use bytes::Bytes;
use eth_state::fold::{materialize_shard_bytes, MainSidecar};
use eth_state::ingest::normalize_balance_be;
use eth_state::{build_session, ENTRIES_PER_SHARD, ENTRY_SIZE};
use raven_client::{build_seeded_query_rust, extract_response_rust};
use raven_core::storage::StorageBackend as _;
use raven_core::MemoryStore;
use raven_inspire::params::InspireParams;
use raven_inspire::rlwe::RlweSecretKey;
use serial_test::serial;

fn rec(bal: u128) -> Bytes {
    Bytes::copy_from_slice(&normalize_balance_be(&bal.to_be_bytes()).expect("balance fits"))
}

fn read_main(ms: &MainSidecar, sk: RlweSecretKey, leaf: u64) -> Vec<u8> {
    let params = InspireParams::secure_128_d2048();
    let crs = ms.main.current_snapshot().state.crs.clone();
    let shard_cfg = ms.main.current_snapshot().state.encoded_db.config.clone();
    let session = build_session(&crs, sk, params.sigma, 1).expect("session");
    let (state, q) = build_seeded_query_rust(&session, &params, &shard_cfg, leaf).expect("query");
    let (_e, resp) = ms.main.query(&q).expect("respond");
    extract_response_rust(&crs, &state, &resp, ENTRY_SIZE).expect("extract")
}

/// The materializer early-breaks past `shard_end`. A row in a far shard is never read - and
/// without the break its out-of-shard offset would index past the shard buffer and panic.
#[test]
fn materialize_early_break() {
    let store = MemoryStore::new();
    let mut txn = store.begin().expect("begin");
    for i in 0..4u64 {
        txn.insert(i, rec((i as u128 + 1) * 5)).expect("insert");
    }
    let far = 3 * ENTRIES_PER_SHARD as u64 + 10;
    txn.insert(far, rec(999)).expect("insert far");
    txn.commit().expect("commit");
    let snap = store.snapshot_concrete().expect("snap");

    let bytes = materialize_shard_bytes(&snap, 0, ENTRY_SIZE).expect("materialize");
    assert_eq!(bytes.len(), ENTRIES_PER_SHARD * ENTRY_SIZE);
    let off = 2 * ENTRY_SIZE;
    assert_eq!(
        &bytes[off..off + ENTRY_SIZE],
        &rec(15)[..],
        "leaf 2 materialized; the far shard-3 row is not read"
    );
}

/// A whole-shard change since the last fold makes the sidecar's encoded shard byte-identical
/// to main's re-encode of the same bytes, so the fold reuses it (the fold-site re-encode counter
/// does not advance) and the folded main still answers byte-identically.
#[test]
#[serial]
fn dedup_whole_shard_reuses_sidecar() {
    let dir = tempfile::tempdir().expect("tempdir");
    let params = InspireParams::secure_128_d2048();
    let n = 64usize; // one shard, fully covered by the change below
    let mut db = vec![0u8; n * ENTRY_SIZE];
    for i in 0..n {
        db[i * ENTRY_SIZE..(i + 1) * ENTRY_SIZE].copy_from_slice(&rec((i as u128 + 1) * 7));
    }
    let (mut ms, main_sk, _ssk) =
        MainSidecar::seed(&params, &db, ENTRY_SIZE, dir.path(), 0x0000_D4D0).expect("seed");

    let updates: Vec<(u64, Bytes)> =
        (0..n as u64).map(|i| (i, rec((i as u128 + 1) * 13))).collect();
    ms.apply_updates(1, &updates).expect("apply");
    let before = ms.re_encode_count();
    ms.fold().expect("fold");

    assert_eq!(
        ms.re_encode_count(),
        before,
        "whole-shard change reuses the sidecar encode; no fold-site re-encode"
    );
    assert_eq!(
        &read_main(&ms, main_sk, 5)[..],
        &rec(6 * 13)[..],
        "the reused shard answers byte-identically"
    );
}

/// A fold archives `current.log`, so the next recover replays only the post-fold tail; recover
/// still reproduces byte-identical state, including an update applied after the archive.
#[test]
#[serial]
fn wal_archive_after_fold_recover() {
    let dir = tempfile::tempdir().expect("tempdir");
    let params = InspireParams::secure_128_d2048();
    let n = 64usize;
    let mut db = vec![0u8; n * ENTRY_SIZE];
    for i in 0..n {
        db[i * ENTRY_SIZE..(i + 1) * ENTRY_SIZE].copy_from_slice(&rec((i as u128 + 1) * 7));
    }
    let seed = 0x0000_5A11u64;
    let (mut ms, _msk, _ssk) =
        MainSidecar::seed(&params, &db, ENTRY_SIZE, dir.path(), seed).expect("seed");

    ms.apply_updates(1, &[(3, rec(424_242))]).expect("apply1");
    ms.fold().expect("fold"); // archives the pre-fold WAL

    let archived = dir.path().join("wal").join("archived");
    let n_archived = std::fs::read_dir(&archived).map(|d| d.count()).unwrap_or(0);
    assert!(n_archived > 0, "the fold archived current.log");

    // An update appended after the archive, then a crash + recover from snapshot + short tail.
    ms.apply_updates(2, &[(7, rec(555_555))]).expect("apply2");
    drop(ms);
    let (ms2, main_sk, _ssk2) =
        MainSidecar::recover(&params, ENTRY_SIZE, dir.path(), seed).expect("recover");
    assert_eq!(
        &read_main(&ms2, main_sk, 7)[..],
        &rec(555_555)[..],
        "post-archive update recovered byte-identically"
    );
}

/// Cache survives shard growth: appending a leaf into a new shard grows main (ensure_main_covers)
/// and, after a fold, the cached respond path answers the new shard byte-identically. Covers the
/// ensure_main_covers path that the cache-equivalence KAT does not.
#[test]
#[serial]
fn cached_respond_survives_shard_growth() {
    let dir = tempfile::tempdir().expect("tempdir");
    let params = InspireParams::secure_128_d2048();
    let n = 64usize; // one seeded shard
    let mut db = vec![0u8; n * ENTRY_SIZE];
    for i in 0..n {
        db[i * ENTRY_SIZE..(i + 1) * ENTRY_SIZE].copy_from_slice(&rec((i as u128 + 1) * 7));
    }
    let (mut ms, main_sk, _ssk) =
        MainSidecar::seed(&params, &db, ENTRY_SIZE, dir.path(), 0x0000_6604).expect("seed");

    let new_leaf = ENTRIES_PER_SHARD as u64 + 5; // a leaf in a not-yet-present shard
    ms.apply_updates(1, &[(new_leaf, rec(987_654))]).expect("apply into a new shard");
    ms.fold().expect("fold"); // main re-encodes the grown shard

    assert_eq!(
        &read_main(&ms, main_sk, new_leaf)[..],
        &rec(987_654)[..],
        "cached respond is byte-identical on a grown shard"
    );
}
