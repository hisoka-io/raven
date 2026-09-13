//! Materializer early-break, whole-shard dedup of the fold re-encode, and WAL archiving.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use bytes::Bytes;
use eth_state::fold::{materialize_shard_bytes, MainSidecar};
use eth_state::ingest::normalize_balance_be;
use eth_state::{build_session, ENTRIES_PER_SHARD, ENTRY_SIZE};
use raven_client::{build_seeded_query_rust, extract_response_rust};
use raven_core::storage::StorageBackend as _;
use raven_core::MemoryStore;
use raven_inspire::params::InspireParams;
use raven_inspire::rlwe::RlweSecretKey;
use raven_storage::{Manifest, StoreLayout};
use serial_test::serial;

fn rec(bal: u128) -> Bytes {
    Bytes::copy_from_slice(&normalize_balance_be(&bal.to_be_bytes()).expect("balance fits"))
}

/// Total bytes sealed under `wal/archived`. A file count cannot separate an
/// empty seal from one carrying entries, so it cannot attribute a seal to the
/// publish under test.
fn sealed_bytes(data_dir: &std::path::Path) -> u64 {
    let archived = data_dir.join("wal").join("archived");
    let Ok(entries) = std::fs::read_dir(&archived) else {
        return 0;
    };
    entries
        .map(|e| {
            e.expect("archive dir entry")
                .metadata()
                .expect("archive metadata")
                .len()
        })
        .sum()
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

/// Without the early break, a far row's out-of-shard offset would index past the buffer.
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

    let updates: Vec<(u64, Bytes)> = (0..n as u64)
        .map(|i| (i, rec((i as u128 + 1) * 13)))
        .collect();
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
    let sealed_before_fold = sealed_bytes(dir.path());
    ms.fold().expect("fold");

    let sealed_after_fold = sealed_bytes(dir.path());
    assert!(
        sealed_after_fold > sealed_before_fold,
        "the fold must seal the applied update under wal/archived: {sealed_before_fold} \
         bytes before, {sealed_after_fold} after"
    );

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

#[test]
#[serial]
fn recover_rejects_manifest_identity_mismatch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let params = InspireParams::secure_128_d2048();
    let db = vec![0u8; 64 * ENTRY_SIZE];
    let seed = 0x0000_1D00u64;
    let (main_sidecar, _main_key, _sidecar_key) =
        MainSidecar::seed(&params, &db, ENTRY_SIZE, dir.path(), seed).expect("seed");
    drop(main_sidecar);

    let layout = StoreLayout::open(dir.path()).expect("layout");
    let mut manifest = Manifest::load(&layout)
        .expect("manifest load")
        .expect("manifest present");
    manifest.scheme_tag = "wrong-scheme".to_owned();
    manifest.save(&layout).expect("save mismatched manifest");

    let Err(error) = MainSidecar::recover(&params, ENTRY_SIZE, dir.path(), seed) else {
        panic!("manifest identity mismatch must fail closed");
    };
    assert!(error.to_string().contains("scheme_tag mismatch"), "{error}");
}

#[test]
#[serial]
fn recover_rejects_manifest_cell_shape_mismatch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let params = InspireParams::secure_128_d2048();
    let db = vec![0u8; 64 * ENTRY_SIZE];
    let seed = 0x0000_1D01u64;
    let (main_sidecar, _main_key, _sidecar_key) =
        MainSidecar::seed(&params, &db, ENTRY_SIZE, dir.path(), seed).expect("seed");
    drop(main_sidecar);

    let layout = StoreLayout::open(dir.path()).expect("layout");
    let mut manifest = Manifest::load(&layout)
        .expect("manifest load")
        .expect("manifest present");
    manifest.entry_size_bytes = Some(ENTRY_SIZE * 2);
    manifest.save(&layout).expect("save mismatched shape");

    let Err(error) = MainSidecar::recover(&params, ENTRY_SIZE, dir.path(), seed) else {
        panic!("manifest shape mismatch must fail closed");
    };
    let message = error.to_string();
    for needle in [
        "manifest cell shape mismatch",
        "32",
        "64",
        "re-bootstrapped",
    ] {
        assert!(message.contains(needle), "missing {needle}: {message}");
    }
}

#[test]
#[serial]
fn recover_refuses_legacy_manifest_when_rows_per_shard_cannot_be_derived() {
    let dir = tempfile::tempdir().expect("tempdir");
    let params = InspireParams::secure_128_d2048();
    let db = vec![0u8; 64 * ENTRY_SIZE];
    let seed = 0x0000_1D02u64;
    let (main_sidecar, _main_key, _sidecar_key) =
        MainSidecar::seed(&params, &db, ENTRY_SIZE, dir.path(), seed).expect("seed");
    drop(main_sidecar);

    let layout = StoreLayout::open(dir.path()).expect("layout");
    let mut manifest = Manifest::load(&layout)
        .expect("manifest load")
        .expect("manifest present");
    manifest.schema_version = 6;
    manifest.entry_size_bytes = None;
    manifest.rows_per_shard = None;
    manifest.save(&layout).expect("save legacy manifest");

    let Err(error) = MainSidecar::recover(&params, ENTRY_SIZE, dir.path(), seed) else {
        panic!("legacy rows_per_shard absence must not copy configuration");
    };
    let message = error.to_string();
    assert!(message.contains("no cell shape"), "{message}");
    assert!(message.contains("re-bootstrap"), "{message}");
}

/// Shard growth path, which the cache-equivalence KAT does not reach.
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
    ms.apply_updates(1, &[(new_leaf, rec(987_654))])
        .expect("apply into a new shard");
    ms.fold().expect("fold");

    assert_eq!(
        &read_main(&ms, main_sk, new_leaf)[..],
        &rec(987_654)[..],
        "cached respond is byte-identical on a grown shard"
    );
}
