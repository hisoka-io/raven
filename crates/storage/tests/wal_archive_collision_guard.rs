#![cfg(unix)]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use raven_storage::{StoreLayout, Wal};

/// Drive `Wal::archive` past its rename and into a failing reopen, using only std.
///
/// `rename(2)` is a documented no-op when both operands are links to the same inode
/// (POSIX rename, "resolve to ... different directory entries for the same existing
/// file"), so hard-linking the log's own name into the archive slot lets the rename
/// report success while leaving `current.log` in place. Pointing that surviving name
/// at a symlink into a missing directory makes the reopen's `O_CREAT` fail ENOENT.
#[test]
fn a_reopen_that_fails_after_the_rename_poisons_the_log() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let wal = Wal::open(&layout, None).expect("wal open");

    wal.append(&vec![1u8, 2, 3], 10).expect("append 0");
    wal.append(&vec![4u8, 5, 6], 20).expect("append 1");

    let current = layout.wal_current_path();
    let target = layout.wal_archived_path(0, 1);

    let unreachable_log = dir.path().join("no-such-dir").join("current.log");
    std::fs::remove_file(&current).expect("unlink the live log name");
    std::os::unix::fs::symlink(&unreachable_log, &current).expect("install dangling log name");
    std::fs::hard_link(&current, &target).expect("second link to the same symlink inode");

    assert!(!target.exists(), "the collision guard must not trip");

    let err = wal.archive(0, 1).expect_err("the reopen must fail");
    match &err {
        raven_storage::PersistenceError::Io(io) => {
            assert_eq!(io.kind(), std::io::ErrorKind::NotFound, "err was {err:?}");
        }
        other => panic!("expected Io, got {other:?}"),
    }

    assert!(
        current.symlink_metadata().is_ok(),
        "the no-op rename must leave current.log in place"
    );

    let poisoned = wal
        .append(&vec![7u8], 30)
        .expect_err("every append after a failed reopen must be refused");
    match poisoned {
        raven_storage::PersistenceError::Invariant(msg) => {
            assert!(msg.contains("poisoned"), "message was {msg}");
        }
        other => panic!("expected Invariant, got {other:?}"),
    }
}
