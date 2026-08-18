#![cfg(unix)]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use raven_storage::{StoreLayout, Wal};

/// A dangling symlink in the archive slot is a collision, and the guard must say so.
///
/// It reads as free to `Path::exists()`, which follows links to a missing target. That
/// mattered for more than tidiness: `rename(2)` is a documented no-op when both operands
/// resolve to one inode, so a slot that "does not exist" plus a log name pointing at the
/// same inode let the rename report success while moving nothing, and the reopen then
/// created a second live log the replay would never read. Occupancy is now decided by
/// `symlink_metadata`, which does not follow links.
#[test]
fn a_dangling_symlink_in_the_archive_slot_is_refused_as_a_collision() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let wal = Wal::open(&layout, None).expect("wal open");

    wal.append(&vec![1u8, 2, 3], 10).expect("append 0");
    wal.append(&vec![4u8, 5, 6], 20).expect("append 1");

    let target = layout.wal_archived_path(0, 1);
    std::fs::create_dir_all(target.parent().expect("archive parent")).expect("mkdir archived");
    let nowhere = dir.path().join("no-such-dir").join("sealed.log");
    std::os::unix::fs::symlink(&nowhere, &target).expect("install dangling archive slot");

    // The precondition that made the old hole reachable, asserted so this test cannot
    // quietly stop exercising it: the slot is occupied yet reads as absent.
    assert!(
        !target.exists(),
        "a dangling link must still read as absent"
    );
    assert!(
        target.symlink_metadata().is_ok(),
        "and must still be an entry in the directory"
    );

    let err = wal
        .archive(0, 1)
        .expect_err("an occupied archive slot must be refused, whatever it points at");
    match &err {
        raven_storage::PersistenceError::Invariant(msg) => {
            assert!(
                msg.contains("already sealed"),
                "the refusal must name the collision; message was {msg}"
            );
        }
        other => panic!("expected Invariant, got {other:?}"),
    }

    // Refused BEFORE the rename, so the live log is untouched and still appendable.
    // A guard that refuses after moving the log would be worse than no guard.
    assert!(
        layout.wal_current_path().symlink_metadata().is_ok(),
        "the live log must survive a refused archive"
    );
    wal.append(&vec![7u8], 30)
        .expect("a refused archive must not poison a healthy log");
}

/// The ordinary collision, kept alongside the exotic one so the guard is not narrowed to
/// symlinks by a later edit.
#[test]
fn an_occupied_archive_slot_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let wal = Wal::open(&layout, None).expect("wal open");

    wal.append(&vec![1u8, 2, 3], 10).expect("append 0");
    wal.append(&vec![4u8, 5, 6], 20).expect("append 1");

    let target = layout.wal_archived_path(0, 1);
    std::fs::create_dir_all(target.parent().expect("archive parent")).expect("mkdir archived");
    std::fs::write(&target, b"already sealed bytes").expect("occupy the slot");

    let err = wal
        .archive(0, 1)
        .expect_err("sealing a range twice must be refused");
    match &err {
        raven_storage::PersistenceError::Invariant(msg) => {
            assert!(msg.contains("already sealed"), "message was {msg}");
        }
        other => panic!("expected Invariant, got {other:?}"),
    }

    assert_eq!(
        std::fs::read(&target).expect("sealed file still there"),
        b"already sealed bytes",
        "the durable bytes the guard exists to protect must be untouched"
    );
}

/// And the guard must not fire on a free slot, or archiving would be impossible.
#[test]
fn a_free_archive_slot_seals_normally() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let wal = Wal::open(&layout, None).expect("wal open");

    wal.append(&vec![1u8, 2, 3], 10).expect("append 0");
    wal.append(&vec![4u8, 5, 6], 20).expect("append 1");

    wal.archive(0, 1).expect("a free slot must seal");
    assert!(
        layout.wal_archived_path(0, 1).symlink_metadata().is_ok(),
        "the sealed range must be on disk"
    );
    wal.append(&vec![7u8], 30)
        .expect("the fresh log must be appendable after a successful archive");
}
