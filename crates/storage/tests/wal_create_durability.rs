//! Creating the log is durable before its first acknowledged append: a power loss
//! must not drop `current.log`, or `wal/`, while frames written into it were
//! acknowledged. Own test binary, and one lock across its tests, so the
//! process-global directory-sync count is exact.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use raven_storage::wal::directory_syncs;
use raven_storage::{StoreLayout, Wal};
use std::sync::{Mutex, MutexGuard, PoisonError};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn syncs_during<T>(f: impl FnOnce() -> T) -> (T, u64) {
    let before = directory_syncs();
    let out = f();
    (out, directory_syncs() - before)
}

// Every directory from wal/ up to the root, the root included.
fn chain_len(layout: &StoreLayout) -> u64 {
    let wal_dir = std::fs::canonicalize(layout.wal_dir()).expect("canonical wal dir");
    u64::try_from(wal_dir.ancestors().count()).expect("depth fits u64")
}

#[test]
fn a_created_log_syncs_data_dir_entry_that_store_layout_open_left_unsynced() {
    let _serial = serial();
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("a").join("b");
    // The production path: StoreLayout::open creates data_dir, its parents and wal/
    // without syncing any of them, so Wal::open sees nothing missing.
    let layout = StoreLayout::open(&data_dir).expect("layout");
    assert!(layout.wal_dir().is_dir());

    let (wal, syncs) = syncs_during(|| Wal::open(&layout, None).expect("open"));
    let chain = chain_len(&layout);
    assert!(
        chain >= 5,
        "wal/, b/, a/, the tempdir and the root at least"
    );
    assert_eq!(syncs, chain, "every directory above current.log is synced");
    wal.append(&vec![0xAB_u8; 8], 1).expect("append");
}

#[test]
fn every_directory_the_open_created_has_its_entry_synced() {
    let _serial = serial();
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("a").join("b");
    let layout = StoreLayout::inspect(&data_dir);

    let (wal, syncs) = syncs_during(|| Wal::open(&layout, None).expect("open"));
    assert_eq!(syncs, chain_len(&layout), "wal/, b/, a/ and above");
    wal.append(&vec![0xAB_u8; 8], 1).expect("append");
}

#[test]
fn reopening_an_existing_log_syncs_no_directory() {
    let _serial = serial();
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    {
        let wal = Wal::open(&layout, None).expect("create");
        wal.append(&vec![0xAB_u8; 8], 1).expect("append");
    }

    let (wal, syncs) = syncs_during(|| Wal::open(&layout, None).expect("reopen"));
    assert_eq!(syncs, 0, "an existing log adds no directory sync");
    assert_eq!(wal.next_seq(), 1);
}
