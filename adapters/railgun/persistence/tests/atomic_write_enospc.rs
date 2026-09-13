//! Write-failure injection for `atomic_write` / `Manifest::save`. True ENOSPC
//! needs privileges CI lacks, so EACCES on a read-only parent exercises the same
//! `create_owner_only` -> `PersistenceError::Io` path. ENOSPC-specific errno
//! surfacing (errno 28) is kernel behaviour with no in-tree subject; the former
//! `/dev/full` test here self-skipped silently wherever the device was absent.

#![cfg(unix)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::os::unix::fs::PermissionsExt;

use raven_railgun_persistence::{
    Manifest, PersistenceError, SnapshotId, StoreLayout, MANIFEST_SCHEMA_VERSION,
};

fn sample_manifest() -> Manifest {
    Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        scheme_tag: "raven-inspire-twopacking-inspiring-wp3".to_owned(),
        instance_id: "atomic-write-enospc-test".to_owned(),
        current_snapshot_id: SnapshotId(7),
        current_snapshot_seq: 42,
        current_marker: 24_000_000,
        encoder_label: "per-leaf-bc".to_owned(),
        prev_encoder_label: None,
        entry_size_bytes: Some(32),
        rows_per_shard: Some(2048),
    }
}

#[test]
fn manifest_save_under_readonly_parent_propagates_typed_io_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");

    let baseline = sample_manifest();
    baseline.save(&layout).expect("baseline save");

    let perms_orig = std::fs::metadata(dir.path()).expect("stat").permissions();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500))
        .expect("chmod 500");

    let mutated = Manifest {
        current_snapshot_seq: 99,
        ..sample_manifest()
    };
    let result = mutated.save(&layout);

    // Restore permissions before asserting so a panic doesn't leave the tempdir un-cleanable.
    std::fs::set_permissions(dir.path(), perms_orig).expect("restore perms");

    let err = result.expect_err("save under read-only parent must fail");
    match err {
        PersistenceError::Io(io_err) => {
            assert_eq!(io_err.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("expected PersistenceError::Io; got {other:?}"),
    }

    // Atomic-rename never fired: the baseline manifest must be intact.
    let observed = Manifest::load(&layout)
        .expect("load after failed save")
        .expect("baseline still present");
    assert_eq!(observed.current_snapshot_seq, baseline.current_snapshot_seq);

    mutated.save(&layout).expect("post-restore save");
    let observed = Manifest::load(&layout).expect("load").expect("present");
    assert_eq!(observed.current_snapshot_seq, 99);
}
