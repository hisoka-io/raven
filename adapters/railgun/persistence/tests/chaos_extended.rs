//! Persistence-layer chaos: a partial snapshot dir left by disk-full must not
//! corrupt recovery. (The former two-instance "kill isolation" test proved
//! nothing: its instances were two unconnected tempdirs — removed with a
//! survived-mutation proof; Manifest::load-when-missing and save/load
//! round-trips live in crates/storage/src/manifest.rs unit tests.)

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::cast_possible_truncation
)]

use raven_railgun_persistence::{
    Manifest, PersistenceError, Snapshot, SnapshotId, StoreLayout, MANIFEST_SCHEMA_VERSION,
    SNAPSHOT_MAGIC,
};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-cache-session";

fn manifest_for(instance: &str, encoder_label: &str) -> Manifest {
    Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        scheme_tag: SCHEME_TAG.to_owned(),
        instance_id: instance.to_owned(),
        current_snapshot_id: SnapshotId(1),
        current_snapshot_seq: 0,
        current_marker: 0,
        encoder_label: encoder_label.to_owned(),
        prev_encoder_label: None,
    }
}

#[test]
fn partial_snapshot_dir_does_not_corrupt_subsequent_recovery() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");

    let snap = Snapshot::build(b"first valid snapshot".to_vec(), SNAPSHOT_MAGIC);
    snap.save(&layout, SnapshotId(1)).expect("save snap-1");
    let manifest = manifest_for("partial-snap-test", "per-leaf-bc");
    manifest.save(&layout).expect("save manifest");

    // Disk-full mid-write of snap-2: its dir is truncated and the manifest still
    // points at snap-1, because the atomic rename never fired.
    let snap2_dir = layout.snapshot_dir(SnapshotId(2));
    std::fs::create_dir_all(&snap2_dir).expect("mkdir snap-2");
    let snap2_full = Snapshot::build(
        b"snap-2 full payload that we will truncate".to_vec(),
        SNAPSHOT_MAGIC,
    );
    let header_bytes = bincode::serialize(&snap2_full.header).expect("ser header");
    std::fs::write(snap2_dir.join("header.bin"), &header_bytes).expect("write header");
    std::fs::write(snap2_dir.join("data.bincode"), b"trunc").expect("write trunc payload");

    let err = Snapshot::load(&layout, SnapshotId(2), SNAPSHOT_MAGIC)
        .expect_err("truncated snap must fail load");
    assert!(
        matches!(err, PersistenceError::SnapshotCorrupt(_)),
        "got {err:?}"
    );

    let layout2 = StoreLayout::open(dir.path()).expect("layout reopen");
    let manifest2 = Manifest::load(&layout2)
        .expect("manifest reload")
        .expect("present");
    assert_eq!(manifest2.current_snapshot_id, SnapshotId(1));
    let snap1_back = Snapshot::load(&layout2, manifest2.current_snapshot_id, SNAPSHOT_MAGIC)
        .expect("snap-1 must still load clean");
    assert_eq!(snap1_back.data, b"first valid snapshot");
}
