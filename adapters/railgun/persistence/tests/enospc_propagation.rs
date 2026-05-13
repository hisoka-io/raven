//! Fault-injected ENOSPC propagation through `Manifest::save_to_writer`.
//!
//! Uses a mock `Write` that returns `StorageFull` to exercise the `?`-propagation path
//! without a real tmpfs. Complements the EACCES and `/dev/full` coverage in
//! `atomic_write_enospc.rs`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::io::{self, Write};

use raven_railgun_persistence::{
    Manifest, PersistenceError, SnapshotId, StoreLayout, MANIFEST_SCHEMA_VERSION,
};

fn sample_manifest() -> Manifest {
    Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        scheme_tag: "raven-inspire-twopacking-inspiring-wp3".to_owned(),
        instance_id: "enospc-propagation-test".to_owned(),
        current_snapshot_id: SnapshotId(11),
        current_snapshot_seq: 256,
        current_block_height: 24_500_000,
        encoder_label: "per-leaf-bc".to_owned(),
        prev_encoder_label: None,
    }
}

/// Mock `Write` that always returns `StorageFull`.
#[derive(Debug, Default)]
struct StorageFullWriter {
    attempts: usize,
}

impl Write for StorageFullWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.attempts += 1;
        Err(io::Error::new(
            io::ErrorKind::StorageFull,
            format!(
                "fault-injected ENOSPC: refused {} bytes (no space left on device)",
                buf.len()
            ),
        ))
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.attempts += 1;
        Err(io::Error::new(
            io::ErrorKind::StorageFull,
            format!(
                "fault-injected ENOSPC: refused write_all of {} bytes (no space left on device)",
                buf.len()
            ),
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn manifest_save_to_writer_propagates_storage_full_as_typed_io_error() {
    let m = sample_manifest();
    let mut writer = StorageFullWriter::default();
    let result = m.save_to_writer(&mut writer);

    assert!(writer.attempts >= 1);
    let err = result.expect_err("StorageFull writer must surface a typed Err");
    match err {
        PersistenceError::Io(io_err) => {
            assert_eq!(io_err.kind(), io::ErrorKind::StorageFull);
        }
        other => panic!("expected PersistenceError::Io(StorageFull); got {other:?}"),
    }
}

#[test]
fn manifest_save_failure_does_not_corrupt_prior_on_disk_manifest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");

    let baseline = sample_manifest();
    baseline.save(&layout).expect("baseline save");

    let loaded_baseline = Manifest::load(&layout)
        .expect("load baseline")
        .expect("present");
    assert_eq!(loaded_baseline, baseline);

    let mutated = Manifest {
        current_snapshot_seq: baseline.current_snapshot_seq + 999,
        current_snapshot_id: SnapshotId(baseline.current_snapshot_id.0 + 1),
        ..sample_manifest()
    };
    let mut writer = StorageFullWriter::default();
    let err = mutated
        .save_to_writer(&mut writer)
        .expect_err("StorageFull writer must Err");
    assert!(matches!(err, PersistenceError::Io(_)), "got {err:?}");

    // Atomic-write contract: the failed write never reached the rename step,
    // so the baseline manifest must be intact.
    let loaded_post_failure = Manifest::load(&layout)
        .expect("load post-failure")
        .expect("present");
    assert_eq!(loaded_post_failure, baseline);

    mutated.save(&layout).expect("post-failure recovery save");
    let loaded_after_recovery = Manifest::load(&layout)
        .expect("load after recovery")
        .expect("present");
    assert_eq!(
        loaded_after_recovery.current_snapshot_seq,
        baseline.current_snapshot_seq + 999
    );
}
