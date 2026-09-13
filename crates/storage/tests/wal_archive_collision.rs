//! `archive()` seals a range under a path named from that range, so a second
//! seal of the same range would rename over durable bytes. The publish cases
//! arrive through `advance_manifest_and_archive`, the publish helper every
//! persistence caller uses; the symlink and free-slot cases hold the direct
//! `archive()` seam, whose occupancy rule is subtler than `Path::exists()`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use raven_storage::{
    advance_manifest_and_archive, Manifest, PersistenceError, SnapshotId, StoreLayout, Wal,
    MANIFEST_SCHEMA_VERSION,
};

fn fresh_manifest() -> Manifest {
    Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        scheme_tag: "test-scheme".to_owned(),
        instance_id: "test-instance".to_owned(),
        current_snapshot_id: SnapshotId(0),
        current_snapshot_seq: 0,
        current_marker: 0,
        encoder_label: "test-encoder".to_owned(),
        prev_encoder_label: None,
        entry_size_bytes: Some(32),
        rows_per_shard: Some(2048),
    }
}

fn point_at(m: &mut Manifest, id: SnapshotId, floor: u64) {
    m.current_snapshot_id = id;
    m.current_snapshot_seq = floor;
}

fn archived_names(layout: &StoreLayout) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(layout.root().join("wal").join("archived"))
        .expect("read archive dir")
        .filter_map(std::result::Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn log_bytes_for(entries: u32, filler: u8) -> Vec<u8> {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let wal = Wal::open(&layout, None).expect("open");
    for i in 0..entries {
        wal.append(&vec![filler; 24], 100 + u64::from(i))
            .expect("append");
    }
    drop(wal);
    std::fs::read(layout.wal_current_path()).expect("read log")
}

/// A `wal/` restored from a divergent backup replays the same seq range the live
/// archive already holds, so the next publish names the archive it would destroy.
#[test]
fn a_publish_that_would_reseal_an_existing_range_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");

    let mut manifest = fresh_manifest();
    {
        let wal = Wal::open(&layout, None).expect("open");
        for i in 0..6u32 {
            wal.append(&vec![0xAA; 24], 100 + u64::from(i))
                .expect("append");
        }
        advance_manifest_and_archive(&layout, &wal, &mut manifest, SnapshotId(1), point_at)
            .expect("first publish");
    }
    let sealed = archived_names(&layout);
    assert_eq!(
        sealed,
        vec!["seq-00000000000000000000-00000000000000000005.log"]
    );
    let sealed_path = layout.wal_archived_path(0, 5);
    let sealed_bytes = std::fs::read(&sealed_path).expect("read sealed");

    std::fs::write(layout.wal_current_path(), log_bytes_for(6, 0xBB)).expect("restore other log");
    let on_disk = Manifest::load(&layout).expect("load").expect("present");
    let wal = Wal::open(&layout, on_disk.current_snapshot_seq.checked_sub(1)).expect("reopen");

    let mut manifest = on_disk;
    let err = advance_manifest_and_archive(&layout, &wal, &mut manifest, SnapshotId(2), point_at)
        .expect_err("resealing an occupied archive path must be refused");

    let PersistenceError::Invariant(msg) = &err else {
        panic!("expected Invariant, got {err:?}");
    };
    assert!(
        msg.contains("0..=5"),
        "the error must name the range it refused to reseal; got `{msg}`"
    );
    assert!(
        msg.contains("seq-00000000000000000000-00000000000000000005.log"),
        "the error must name the occupied path; got `{msg}`"
    );

    assert_eq!(
        std::fs::read(&sealed_path).expect("re-read sealed"),
        sealed_bytes,
        "the already-sealed bytes must survive the refusal"
    );
    assert_eq!(
        archived_names(&layout),
        sealed,
        "a refused seal must add no archive"
    );
    assert!(
        !wal.replay().expect("replay").entries.is_empty(),
        "a refused seal must leave current.log in place"
    );
}

/// A snapshot cadence that fires with no appends in between must keep working:
/// there is no range to seal, so the seal is skipped rather than aliased onto a
/// path a previous publish already used.
#[test]
fn repeated_publishes_with_no_appends_seal_nothing_further() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");

    let mut manifest = fresh_manifest();
    let wal = Wal::open(&layout, None).expect("open");
    for i in 0..3u32 {
        wal.append(&vec![0xAA; 24], 100 + u64::from(i))
            .expect("append");
    }
    advance_manifest_and_archive(&layout, &wal, &mut manifest, SnapshotId(1), point_at)
        .expect("first publish");
    let sealed = archived_names(&layout);
    let sealed_bytes = std::fs::read(layout.wal_archived_path(0, 2)).expect("read sealed");

    for id in 2..=4u64 {
        advance_manifest_and_archive(&layout, &wal, &mut manifest, SnapshotId(id), point_at)
            .expect("publish with an empty log");
    }

    assert_eq!(
        archived_names(&layout),
        sealed,
        "an empty log has no range to seal"
    );
    assert_eq!(
        std::fs::read(layout.wal_archived_path(0, 2)).expect("re-read sealed"),
        sealed_bytes,
        "the first archive must survive every later publish"
    );
    assert_eq!(manifest.current_snapshot_id, SnapshotId(4));
    assert_eq!(manifest.current_snapshot_seq, 3);
}

/// A dangling symlink in the archive slot is a collision, and the guard must say so.
///
/// It reads as free to `Path::exists()`, which follows links to a missing target. That
/// mattered for more than tidiness: `rename(2)` is a documented no-op when both operands
/// resolve to one inode, so a slot that "does not exist" plus a log name pointing at the
/// same inode let the rename report success while moving nothing, and the reopen then
/// created a second live log the replay would never read. Occupancy is now decided by
/// `symlink_metadata`, which does not follow links.
#[cfg(unix)]
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
        PersistenceError::Invariant(msg) => {
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
