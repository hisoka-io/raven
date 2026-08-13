//! `archive()` seals a range under a path named from that range, so a second
//! seal of the same range would rename over durable bytes. Both cases below
//! arrive through `advance_manifest_and_archive`, the publish helper every
//! persistence caller uses.

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
