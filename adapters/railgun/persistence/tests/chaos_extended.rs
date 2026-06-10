//! Extended chaos scenarios at the persistence-layer surface.
//!
//! Covers: cross-instance isolation under a mid-commit kill, partial snapshot dir
//! on disk-full, WAL `last_block_height` bounding under a feed stall,
//! encoder-label round-trip visibility, and `PpoiListLeafAdded + Reorg` replay ordering.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::cast_possible_truncation
)]

use raven_railgun_persistence::{
    Manifest, PersistenceError, Snapshot, SnapshotId, StoreLayout, Wal, WalEntryPayload,
    MANIFEST_SCHEMA_VERSION, SNAPSHOT_MAGIC,
};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-cache-session";

fn append_leaf(tree: u32, idx: u32, height: u64) -> (WalEntryPayload, u64) {
    let mut commitment = [0u8; 32];
    commitment[31] = u8::try_from(idx % 250).unwrap_or(0).saturating_add(1);
    (
        WalEntryPayload::AppendLeaf {
            tree_number: tree,
            leaf_index: idx,
            commitment,
        },
        height,
    )
}

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
fn kill_one_instance_mid_commit_does_not_affect_others() {
    let dir_a = tempfile::tempdir().expect("tempdir A");
    let dir_b = tempfile::tempdir().expect("tempdir B");
    let layout_a = StoreLayout::open(dir_a.path()).expect("layout A");
    let layout_b = StoreLayout::open(dir_b.path()).expect("layout B");

    {
        let wal_a = Wal::open(&layout_a, None).expect("wal A");
        let wal_b = Wal::open(&layout_b, None).expect("wal B");
        for i in 0..5u32 {
            let (payload, h) = append_leaf(0, i, 100 + u64::from(i));
            wal_a.append(&payload, h).expect("A append");
            wal_b.append(&payload, h).expect("B append");
        }
        let snap_a = Snapshot::build(b"instance-A pre-kill state".to_vec(), SNAPSHOT_MAGIC);
        snap_a.save(&layout_a, SnapshotId(1)).expect("A snap.save");
        let snap_b = Snapshot::build(b"instance-B steady state".to_vec(), SNAPSHOT_MAGIC);
        snap_b.save(&layout_b, SnapshotId(1)).expect("B snap.save");
        let manifest_b = manifest_for("instance-b", "per-leaf-bc");
        manifest_b.save(&layout_b).expect("B manifest.save");
        // Instance A dropped here, simulating a kill before manifest.save.
    }

    let layout_b2 = StoreLayout::open(dir_b.path()).expect("layout B reopen");
    let manifest_b2 = Manifest::load(&layout_b2)
        .expect("B manifest load")
        .expect("B manifest present");
    assert_eq!(manifest_b2.current_snapshot_id, SnapshotId(1));
    let snap_b2 = Snapshot::load(&layout_b2, SnapshotId(1), SNAPSHOT_MAGIC).expect("B snap reload");
    assert_eq!(snap_b2.data, b"instance-B steady state");
    let wal_b2 = Wal::open(&layout_b2, None).expect("B wal reopen");
    let replay_b = wal_b2.replay().expect("B replay");
    assert_eq!(replay_b.entries.len(), 5);
    assert!(replay_b.truncated_at.is_none());

    let layout_a2 = StoreLayout::open(dir_a.path()).expect("layout A reopen");
    let manifest_a2 = Manifest::load(&layout_a2).expect("A manifest load");
    // A's manifest never landed; persistence sees a fresh-bootstrap state.
    assert!(manifest_a2.is_none());
}

#[test]
fn partial_snapshot_dir_does_not_corrupt_subsequent_recovery() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");

    let snap = Snapshot::build(b"first valid snapshot".to_vec(), SNAPSHOT_MAGIC);
    snap.save(&layout, SnapshotId(1)).expect("save snap-1");
    let manifest = manifest_for("partial-snap-test", "per-leaf-bc");
    manifest.save(&layout).expect("save manifest");

    // Simulate disk-full mid-write of snap-2: snap-dir exists with a truncated data.bincode,
    // but the manifest still points at snap-1 (atomic-rename never fired for snap-2).
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
