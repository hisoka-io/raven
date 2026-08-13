//! A refused WAL open is observable, not merely fatal: the counter survives a
//! caller that swallows the error. Own test binary, so the process-global count
//! is exact.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use raven_storage::{PersistenceError, StoreLayout, Wal};

#[test]
fn a_refused_recovery_open_is_counted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    {
        let wal = Wal::open(&layout, None).expect("open");
        for i in 0..3u32 {
            wal.append(&vec![0xCC; 16], 100 + u64::from(i))
                .expect("append");
        }
    }

    let before = raven_storage::wal::resume_floor_refusals();
    let err = Wal::open(&layout, Some(40)).expect_err("a floor above the tail must be refused");
    assert!(matches!(err, PersistenceError::Invariant(_)), "got {err:?}");
    assert_eq!(
        raven_storage::wal::resume_floor_refusals(),
        before + 1,
        "a refusal must be counted"
    );

    Wal::open(&layout, Some(2)).expect("a floor at the tail must open");
    assert_eq!(
        raven_storage::wal::resume_floor_refusals(),
        before + 1,
        "an accepted open must not count"
    );
}
