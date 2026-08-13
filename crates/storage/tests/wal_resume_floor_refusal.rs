//! Resume-floor refusal reached the way a recovery caller reaches it: publish a
//! snapshot, then open the WAL at `manifest.current_snapshot_seq.checked_sub(1)`
//! after `wal/` and `manifest.json` were restored from different points in time.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use proptest::prelude::*;
use raven_storage::{
    Manifest, PersistenceError, SnapshotId, StoreLayout, Wal, MANIFEST_SCHEMA_VERSION,
};

const TEST_MAGIC: [u8; 16] = *b"TESTMAGIC_000001";

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

/// Bytes of a `current.log` holding `entries` frames, built by the WAL itself so
/// the frames are well-formed; stands in for a log restored from a backup.
fn log_bytes_for(entries: u32, filler: u8) -> Vec<u8> {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let wal = Wal::open(&layout, None).expect("open");
    for i in 0..entries {
        wal.append(&vec![filler; 16], 100 + u64::from(i))
            .expect("append");
    }
    drop(wal);
    std::fs::read(layout.wal_current_path()).expect("read log")
}

/// Reproduces `Wal::open(&layout, manifest.current_snapshot_seq.checked_sub(1))`,
/// the recovery open every persistence caller performs after loading the
/// manifest. The manifest is the artifact the floor is derived from, so it can
/// never corroborate the floor: the refusal must not consult it.
#[test]
fn a_recovery_open_is_refused_when_the_log_sits_behind_the_manifest_floor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");

    let mut manifest = fresh_manifest();
    {
        let wal = Wal::open(&layout, None).expect("open");
        for i in 0..12u32 {
            wal.append(&vec![0xAA; 16], 100 + u64::from(i))
                .expect("append");
        }
        raven_storage::publish_snapshot(
            &layout,
            &wal,
            &mut manifest,
            SnapshotId(1),
            b"snapshot-payload".to_vec(),
            TEST_MAGIC,
            point_at,
        )
        .expect("publish");
    }
    assert_eq!(
        manifest.current_snapshot_seq, 12,
        "the publish must move the floor to the log tail"
    );
    let sealed_before = archived_names(&layout);
    assert_eq!(
        sealed_before.len(),
        1,
        "the publish sealed exactly one range; got {sealed_before:?}"
    );

    std::fs::write(layout.wal_current_path(), log_bytes_for(3, 0xBB)).expect("restore older log");

    let on_disk = Manifest::load(&layout).expect("load").expect("present");
    let err = Wal::open(&layout, on_disk.current_snapshot_seq.checked_sub(1))
        .expect_err("a floor above the restored tail must be refused");

    let PersistenceError::Invariant(msg) = &err else {
        panic!("expected Invariant, got {err:?}");
    };
    assert!(
        msg.contains("resume floor 12"),
        "the error must name the refused floor; got `{msg}`"
    );
    assert!(
        msg.contains("0..=2"),
        "the error must name the tail it would skip; got `{msg}`"
    );
    assert!(
        msg.contains("Operator:"),
        "the error must carry a runbook line; got `{msg}`"
    );

    assert_eq!(
        archived_names(&layout),
        sealed_before,
        "a refused open must seal nothing"
    );
    let reopened = Wal::open(&layout, Some(2)).expect("reopen at the tail the log actually holds");
    assert_eq!(
        reopened
            .replay()
            .expect("replay")
            .entries
            .iter()
            .map(|e| e.seq)
            .collect::<Vec<_>>(),
        vec![0, 1, 2],
        "a refused open must leave the log untouched"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Over every floor a recovery caller can derive, the open either resumes at
    /// the tail the log actually holds or refuses and touches nothing. No input
    /// yields an open that appends past a gap.
    #[test]
    fn a_derived_floor_either_resumes_at_the_tail_or_is_refused(
        entries in 1u32..12,
        current_snapshot_seq in 0u64..24,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        {
            let wal = Wal::open(&layout, None).expect("open");
            for i in 0..entries {
                wal.append(&vec![0xAA; 8], 100 + u64::from(i)).expect("append");
            }
        }
        let tail = u64::from(entries);
        let before = std::fs::read(layout.wal_current_path()).expect("read log");

        match Wal::open(&layout, current_snapshot_seq.checked_sub(1)) {
            Ok(wal) => {
                prop_assert!(
                    current_snapshot_seq <= tail,
                    "floor {current_snapshot_seq} above tail {tail} must not open"
                );
                prop_assert_eq!(wal.next_seq(), tail);
            }
            Err(PersistenceError::Invariant(msg)) => {
                prop_assert!(
                    current_snapshot_seq > tail,
                    "floor {} at or below tail {} must open; refused with `{}`",
                    current_snapshot_seq, tail, msg
                );
                prop_assert_eq!(
                    std::fs::read(layout.wal_current_path()).expect("re-read log"),
                    before,
                    "a refused open must leave current.log byte-identical"
                );
            }
            Err(e) => prop_assert!(false, "unexpected error {e:?}"),
        }
    }
}
