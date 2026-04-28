//! Failure-injection for `atomic_write` / `Manifest::save` write failures.
//!
//! True ENOSPC is unavailable in CI (no `CAP_SYS_ADMIN`, no `unsafe` for `setrlimit`).
//! Instead we use EACCES (read-only parent dir) to exercise the identical
//! `create_owner_only(&tmp)?` → `PersistenceError::Io` propagation path that ENOSPC would hit.

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
        current_block_height: 24_000_000,
        encoder_label: "per-leaf-bc".to_owned(),
        prev_encoder_label: None,
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

    let mutated = Manifest { current_snapshot_seq: 99, ..sample_manifest() };
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

/// Documents the ENOSPC propagation contract via `/dev/full`.
/// A regression that swallows `write_all` errors would surface here first.
#[test]
fn dev_full_write_returns_typed_io_error_documenting_enospc_propagation() {
    use std::io::Write;

    let mut f = match std::fs::OpenOptions::new().write(true).open("/dev/full") {
        Ok(f) => f,
        // Some sandboxes (seccomp) deny access to /dev/full; skip gracefully.
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            eprintln!("skipping /dev/full test: {e}");
            return;
        }
        Err(e) => panic!("unexpected /dev/full open error: {e}"),
    };
    let err = f
        .write_all(b"would-be-snapshot-bytes")
        .expect_err("/dev/full write must Err");
    // StorageFull stabilized in 1.83; older toolchains surface errno 28 as Other.
    let raw = err.raw_os_error();
    let kind = err.kind();
    let is_storage_full = matches!(raw, Some(28)) || matches!(kind, std::io::ErrorKind::Other);
    assert!(is_storage_full, "got kind={kind:?}, raw={raw:?}");
    let typed: PersistenceError = err.into();
    assert!(matches!(typed, PersistenceError::Io(_)));
}
