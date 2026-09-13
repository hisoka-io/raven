#![allow(clippy::expect_used, clippy::panic)]

use raven_storage::{
    open_recovery, Manifest, ManifestShape, PersistenceError, SnapshotFile, SnapshotId,
    StoreLayout, Wal, MANIFEST_SCHEMA_VERSION,
};

const MAGIC: [u8; 16] = *b"RECOVERY_TEST_01";

fn manifest(snapshot: SnapshotId, floor: u64) -> Manifest {
    Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        scheme_tag: "test-scheme".to_owned(),
        instance_id: "main".to_owned(),
        current_snapshot_id: snapshot,
        current_snapshot_seq: floor,
        current_marker: 7,
        encoder_label: "flat".to_owned(),
        prev_encoder_label: None,
        entry_size_bytes: Some(32),
        rows_per_shard: Some(2048),
    }
}

#[test]
fn missing_manifest_returns_none_without_opening_a_wal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let recovered = open_recovery(&layout, MAGIC, |_| Ok(())).expect("recovery");
    assert!(recovered.is_none());
    assert!(!layout.wal_current_path().exists());
}

#[test]
fn current_snapshot_and_wal_are_opened_at_the_manifest_floor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let wal = Wal::open(&layout, None).expect("wal");
    for marker in 0..4u64 {
        wal.append(&marker, marker).expect("append");
    }
    drop(wal);
    SnapshotFile::build(b"snapshot".to_vec(), MAGIC)
        .save(&layout, SnapshotId(1))
        .expect("snapshot");
    manifest(SnapshotId(1), 2).save(&layout).expect("manifest");

    let recovered = open_recovery(&layout, MAGIC, |stored| {
        stored.validate_shape(ManifestShape {
            entry_size_bytes: 32,
            rows_per_shard: 2048,
        })
    })
    .expect("recovery")
    .expect("present");

    assert_eq!(recovered.snapshot.expect("snapshot").data, b"snapshot");
    assert_eq!(
        recovered
            .replay
            .entries
            .iter()
            .map(|entry| entry.seq)
            .collect::<Vec<_>>(),
        [2, 3]
    );
    assert_eq!(recovered.wal.next_seq(), 4);
}

#[test]
fn snapshot_zero_returns_no_snapshot_and_replays_from_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    manifest(SnapshotId(0), 0).save(&layout).expect("manifest");

    let recovered = open_recovery(&layout, MAGIC, |_| Ok(()))
        .expect("recovery")
        .expect("present");
    assert!(recovered.snapshot.is_none());
    assert!(recovered.replay.entries.is_empty());
    assert_eq!(recovered.wal.next_seq(), 0);
}

#[test]
fn snapshot_zero_with_positive_floor_is_refused_before_wal_filtering() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let wal = Wal::open(&layout, None).expect("wal");
    for marker in 0..4u64 {
        wal.append(&marker, marker).expect("append");
    }
    drop(wal);
    manifest(SnapshotId(0), 2).save(&layout).expect("manifest");

    let error = open_recovery(&layout, MAGIC, |_| Ok(()))
        .expect_err("a positive floor without a snapshot would drop uncovered WAL entries");
    let message = error.to_string();
    assert!(message.contains("snapshot id 0"), "{message}");
    assert!(message.contains("replay floor 2"), "{message}");
    assert!(message.contains("restore"), "{message}");
}

#[test]
fn manifest_validation_runs_before_snapshot_io() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    manifest(SnapshotId(99), 0).save(&layout).expect("manifest");

    let error = open_recovery(&layout, MAGIC, |_| {
        Err(PersistenceError::Invariant(
            "validation sentinel".to_owned(),
        ))
    })
    .expect_err("validation must stop before missing snapshot lookup");
    assert!(error.to_string().contains("validation sentinel"), "{error}");
}

#[test]
fn corrupt_current_snapshot_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    SnapshotFile::build(b"snapshot".to_vec(), MAGIC)
        .save(&layout, SnapshotId(1))
        .expect("snapshot");
    std::fs::write(layout.snapshot_data_path(SnapshotId(1)), b"corrupt").expect("corrupt");
    manifest(SnapshotId(1), 0).save(&layout).expect("manifest");

    let error = open_recovery(&layout, MAGIC, |_| Ok(())).expect_err("corrupt snapshot");
    assert!(
        matches!(error, PersistenceError::SnapshotCorrupt(_)),
        "{error}"
    );
}
