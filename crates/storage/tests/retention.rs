#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::path::Path;

use proptest::prelude::*;
use raven_storage::{apply_retention, PersistenceError, RetentionPolicy, SnapshotId, StoreLayout};

#[cfg(unix)]
use std::os::unix::fs::symlink;

fn assert_wrong_type(error: &PersistenceError, expected_path: &Path, operation: &'static str) {
    assert!(
        matches!(
            error,
            PersistenceError::RetentionIo { operation: actual, path, source }
                if *actual == operation
                    && path == expected_path
                    && source.kind() == ErrorKind::InvalidData
        ),
        "{error}"
    );
}

fn names(path: &std::path::Path) -> BTreeSet<String> {
    std::fs::read_dir(path)
        .expect("read directory")
        .map(|entry| {
            entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

fn seed_retention_tree(layout: &StoreLayout) {
    for id in 1..=5 {
        std::fs::create_dir_all(layout.snapshot_dir(SnapshotId(id))).expect("snapshot dir");
    }
    for (from, to) in [(0, 1), (2, 3), (4, 5), (6, 7)] {
        std::fs::write(
            layout.wal_archived_path(from, to),
            [u8::try_from(from).expect("byte")],
        )
        .expect("archived WAL");
    }
    std::fs::write(layout.snapshots_dir().join("operator-note"), b"keep").expect("note");
    std::fs::write(layout.archived_wals_dir().join("README"), b"keep").expect("readme");
}

#[test]
fn retention_keeps_exact_newest_windows_plus_an_older_live_snapshot() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    seed_retention_tree(&layout);

    let report = apply_retention(
        &layout,
        SnapshotId(1),
        RetentionPolicy {
            archived_wals_retain: 2,
            snapshots_retain: 2,
        },
    )
    .expect("retention");

    assert_eq!(report.archived_wals_removed, 2);
    assert_eq!(report.snapshots_removed, 2);
    assert_eq!(
        names(&layout.archived_wals_dir()),
        BTreeSet::from([
            "README".to_owned(),
            "seq-00000000000000000004-00000000000000000005.log".to_owned(),
            "seq-00000000000000000006-00000000000000000007.log".to_owned(),
        ])
    );
    assert_eq!(
        names(&layout.snapshots_dir()),
        BTreeSet::from([
            "operator-note".to_owned(),
            "snap-000001".to_owned(),
            "snap-000004".to_owned(),
            "snap-000005".to_owned(),
        ])
    );
}

#[test]
fn zero_retention_removes_every_owned_entry_except_live_snapshot() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    seed_retention_tree(&layout);

    let report = apply_retention(
        &layout,
        SnapshotId(3),
        RetentionPolicy {
            archived_wals_retain: 0,
            snapshots_retain: 0,
        },
    )
    .expect("retention");

    assert_eq!(report.archived_wals_removed, 4);
    assert_eq!(report.snapshots_removed, 4);
    assert_eq!(
        names(&layout.archived_wals_dir()),
        BTreeSet::from(["README".to_owned()])
    );
    assert_eq!(
        names(&layout.snapshots_dir()),
        BTreeSet::from(["operator-note".to_owned(), "snap-000003".to_owned()])
    );
}

#[test]
fn forensic_retention_is_a_byte_preserving_noop() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    seed_retention_tree(&layout);
    let before_snapshots = names(&layout.snapshots_dir());
    let before_wals = names(&layout.archived_wals_dir());

    let report = apply_retention(
        &layout,
        SnapshotId(3),
        RetentionPolicy {
            archived_wals_retain: usize::MAX,
            snapshots_retain: usize::MAX,
        },
    )
    .expect("retention");

    assert_eq!(report.archived_wals_removed, 0);
    assert_eq!(report.snapshots_removed, 0);
    assert_eq!(names(&layout.snapshots_dir()), before_snapshots);
    assert_eq!(names(&layout.archived_wals_dir()), before_wals);
}

#[test]
fn layout_directory_accessors_are_the_paths_created_by_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");

    assert_eq!(layout.snapshots_dir(), dir.path().join("snapshots"));
    assert_eq!(layout.wal_dir(), dir.path().join("wal"));
    assert_eq!(
        layout.archived_wals_dir(),
        dir.path().join("wal").join("archived")
    );
    assert!(layout.snapshots_dir().is_dir());
    assert!(layout.archived_wals_dir().is_dir());
}

#[test]
fn inspect_layout_computes_paths_without_creating_the_root() {
    let parent = tempfile::tempdir().expect("tempdir");
    let missing = parent.path().join("missing-instance");
    let layout = StoreLayout::inspect(&missing);

    assert_eq!(layout.manifest_path(), missing.join("manifest.json"));
    assert_eq!(
        layout.snapshot_header_path(SnapshotId(7)),
        missing.join("snapshots/snap-000007/header.bin")
    );
    assert_eq!(
        layout.snapshot_data_path(SnapshotId(7)),
        missing.join("snapshots/snap-000007/data.bincode")
    );
    assert!(!missing.exists());
}

#[test]
fn retain_zero_never_deletes_noncanonical_snapshot_names() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let spellings = [
        "snap-1",
        "snap-0000001",
        "snap-000001-suffix",
        "snap-18446744073709551616",
    ];
    for spelling in spellings {
        std::fs::create_dir(layout.snapshots_dir().join(spelling)).expect("plant noncanonical");
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        std::fs::create_dir(
            layout
                .snapshots_dir()
                .join(std::ffi::OsString::from_vec(vec![
                    b's', b'n', b'a', b'p', b'-', 0xFF,
                ])),
        )
        .expect("plant non-UTF8");
    }

    let report = apply_retention(
        &layout,
        SnapshotId(99),
        RetentionPolicy {
            archived_wals_retain: usize::MAX,
            snapshots_retain: 0,
        },
    )
    .expect("retention");

    assert_eq!(report.snapshots_removed, 0);
    for spelling in spellings {
        assert!(layout.snapshots_dir().join(spelling).is_dir(), "{spelling}");
    }
    #[cfg(unix)]
    assert_eq!(
        std::fs::read_dir(layout.snapshots_dir())
            .expect("read")
            .count(),
        5
    );
}

#[test]
fn archived_wal_container_as_file_refuses_instead_of_reporting_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let archive_dir = layout.archived_wals_dir();
    std::fs::remove_dir(&archive_dir).expect("replace empty archive directory");
    std::fs::write(&archive_dir, b"not a directory").expect("archive file");

    let error = apply_retention(&layout, SnapshotId(0), RetentionPolicy::default())
        .expect_err("present non-directory archive container must refuse");
    assert_wrong_type(&error, &archive_dir, "inspect retention directory");
    assert_eq!(
        std::fs::read(&archive_dir).expect("archive bytes"),
        b"not a directory"
    );
}

#[test]
fn snapshot_container_as_file_refuses_instead_of_reporting_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let snapshots_dir = layout.snapshots_dir();
    std::fs::remove_dir(&snapshots_dir).expect("replace empty snapshots directory");
    std::fs::write(&snapshots_dir, b"not a directory").expect("snapshots file");

    let error = apply_retention(&layout, SnapshotId(0), RetentionPolicy::default())
        .expect_err("present non-directory snapshot container must refuse");
    assert_wrong_type(&error, &snapshots_dir, "inspect retention directory");
    assert_eq!(
        std::fs::read(&snapshots_dir).expect("snapshot bytes"),
        b"not a directory"
    );
}

#[test]
fn canonical_wal_directory_refuses_before_pruning_valid_wals() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let malformed = layout.wal_archived_path(10, 11);
    std::fs::create_dir(&malformed).expect("canonical WAL directory");
    let older = layout.wal_archived_path(1, 2);
    let newer = layout.wal_archived_path(3, 4);
    std::fs::write(&older, b"older WAL").expect("older WAL");
    std::fs::write(&newer, b"newer WAL").expect("newer WAL");

    let error = apply_retention(
        &layout,
        SnapshotId(0),
        RetentionPolicy {
            archived_wals_retain: 1,
            snapshots_retain: usize::MAX,
        },
    )
    .expect_err("canonical WAL directory must refuse before pruning");
    assert_wrong_type(&error, &malformed, "inspect artifact metadata");
    assert_eq!(
        std::fs::read(&older).expect("older WAL survives"),
        b"older WAL"
    );
    assert_eq!(
        std::fs::read(&newer).expect("newer WAL survives"),
        b"newer WAL"
    );
    assert!(malformed.is_dir());
}

#[test]
fn canonical_snapshot_file_refuses_before_pruning_valid_snapshots() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let malformed = layout.snapshot_dir(SnapshotId(11));
    std::fs::write(&malformed, b"not a snapshot directory").expect("canonical snapshot file");
    let older = layout.snapshot_dir(SnapshotId(1));
    let newer = layout.snapshot_dir(SnapshotId(2));
    std::fs::create_dir(&older).expect("older snapshot");
    std::fs::create_dir(&newer).expect("newer snapshot");

    let error = apply_retention(
        &layout,
        SnapshotId(0),
        RetentionPolicy {
            archived_wals_retain: usize::MAX,
            snapshots_retain: 1,
        },
    )
    .expect_err("canonical snapshot file must refuse before pruning");
    assert_wrong_type(&error, &malformed, "inspect artifact metadata");
    assert!(older.is_dir(), "older snapshot survives");
    assert!(newer.is_dir(), "newer snapshot survives");
    assert_eq!(
        std::fs::read(&malformed).expect("malformed bytes"),
        b"not a snapshot directory"
    );
}

#[cfg(unix)]
#[test]
fn canonical_snapshot_symlink_refuses_before_pruning_real_snapshots() {
    let root = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside tempdir");
    let layout = StoreLayout::open(root.path()).expect("layout");
    let older = layout.snapshot_dir(SnapshotId(1));
    let newer = layout.snapshot_dir(SnapshotId(2));
    std::fs::create_dir(&older).expect("older snapshot");
    std::fs::create_dir(&newer).expect("newer snapshot");
    let outside_snapshot = outside.path().join("snapshot");
    std::fs::create_dir(&outside_snapshot).expect("outside snapshot");
    std::fs::write(outside_snapshot.join("sentinel"), b"outside").expect("outside sentinel");
    let linked = layout.snapshot_dir(SnapshotId(99));
    symlink(&outside_snapshot, &linked).expect("snapshot symlink");

    let error = apply_retention(
        &layout,
        SnapshotId(0),
        RetentionPolicy {
            archived_wals_retain: usize::MAX,
            snapshots_retain: 1,
        },
    )
    .expect_err("canonical snapshot symlink must refuse");
    assert_wrong_type(&error, &linked, "inspect artifact metadata");
    assert!(older.is_dir());
    assert!(newer.is_dir());
    assert!(linked
        .symlink_metadata()
        .expect("link metadata")
        .file_type()
        .is_symlink());
    assert_eq!(
        std::fs::read(outside_snapshot.join("sentinel")).expect("outside sentinel"),
        b"outside"
    );
}

#[cfg(unix)]
#[test]
fn canonical_wal_symlink_refuses_before_pruning_real_wals() {
    let root = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside tempdir");
    let layout = StoreLayout::open(root.path()).expect("layout");
    let older = layout.wal_archived_path(1, 2);
    let newer = layout.wal_archived_path(3, 4);
    std::fs::write(&older, b"older WAL").expect("older WAL");
    std::fs::write(&newer, b"newer WAL").expect("newer WAL");
    let outside_wal = outside.path().join("wal");
    std::fs::write(&outside_wal, b"outside WAL").expect("outside WAL");
    let linked = layout.wal_archived_path(98, 99);
    symlink(&outside_wal, &linked).expect("WAL symlink");

    let error = apply_retention(
        &layout,
        SnapshotId(0),
        RetentionPolicy {
            archived_wals_retain: 1,
            snapshots_retain: usize::MAX,
        },
    )
    .expect_err("canonical WAL symlink must refuse");
    assert_wrong_type(&error, &linked, "inspect artifact metadata");
    assert_eq!(std::fs::read(&older).expect("older WAL"), b"older WAL");
    assert_eq!(std::fs::read(&newer).expect("newer WAL"), b"newer WAL");
    assert!(linked
        .symlink_metadata()
        .expect("link metadata")
        .file_type()
        .is_symlink());
    assert_eq!(
        std::fs::read(&outside_wal).expect("outside WAL"),
        b"outside WAL"
    );
}

#[cfg(unix)]
#[test]
fn snapshot_container_symlink_refuses_without_external_pruning() {
    let root = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside tempdir");
    let layout = StoreLayout::open(root.path()).expect("layout");
    let snapshots_dir = layout.snapshots_dir();
    std::fs::remove_dir(&snapshots_dir).expect("replace empty snapshots container");
    let older = outside.path().join("snap-000001");
    let newer = outside.path().join("snap-000002");
    std::fs::create_dir(&older).expect("outside older snapshot");
    std::fs::create_dir(&newer).expect("outside newer snapshot");
    std::fs::write(older.join("sentinel"), b"outside").expect("outside sentinel");
    symlink(outside.path(), &snapshots_dir).expect("container symlink");

    let error = apply_retention(
        &layout,
        SnapshotId(0),
        RetentionPolicy {
            archived_wals_retain: usize::MAX,
            snapshots_retain: 1,
        },
    )
    .expect_err("snapshot container symlink must refuse");
    assert_wrong_type(&error, &snapshots_dir, "inspect retention directory");
    assert!(older.is_dir());
    assert!(newer.is_dir());
    assert_eq!(
        std::fs::read(older.join("sentinel")).expect("outside sentinel"),
        b"outside"
    );
}

#[cfg(unix)]
#[test]
fn archived_wal_container_symlink_refuses_without_external_pruning() {
    let root = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside tempdir");
    let layout = StoreLayout::open(root.path()).expect("layout");
    let archive_dir = layout.archived_wals_dir();
    std::fs::remove_dir(&archive_dir).expect("replace empty archive container");
    let older = outside
        .path()
        .join("seq-00000000000000000001-00000000000000000002.log");
    let newer = outside
        .path()
        .join("seq-00000000000000000003-00000000000000000004.log");
    std::fs::write(&older, b"outside older WAL").expect("outside older WAL");
    std::fs::write(&newer, b"outside newer WAL").expect("outside newer WAL");
    symlink(outside.path(), &archive_dir).expect("archive symlink");

    let error = apply_retention(
        &layout,
        SnapshotId(0),
        RetentionPolicy {
            archived_wals_retain: 1,
            snapshots_retain: usize::MAX,
        },
    )
    .expect_err("archive container symlink must refuse");
    assert_wrong_type(&error, &archive_dir, "inspect retention directory");
    assert_eq!(
        std::fs::read(&older).expect("outside older WAL"),
        b"outside older WAL"
    );
    assert_eq!(
        std::fs::read(&newer).expect("outside newer WAL"),
        b"outside newer WAL"
    );
}

#[cfg(unix)]
#[test]
fn wal_parent_symlink_refuses_without_external_archive_pruning() {
    let root = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside tempdir");
    let layout = StoreLayout::open(root.path()).expect("layout");
    let wal_dir = layout.wal_dir();
    std::fs::remove_dir(layout.archived_wals_dir()).expect("remove empty archive");
    std::fs::remove_dir(&wal_dir).expect("replace empty WAL parent");
    let external_archive = outside.path().join("archived");
    std::fs::create_dir(&external_archive).expect("external archive");
    let older = external_archive.join("seq-00000000000000000001-00000000000000000002.log");
    let newer = external_archive.join("seq-00000000000000000003-00000000000000000004.log");
    std::fs::write(&older, b"outside older WAL").expect("outside older WAL");
    std::fs::write(&newer, b"outside newer WAL").expect("outside newer WAL");
    symlink(outside.path(), &wal_dir).expect("WAL parent symlink");

    let error = apply_retention(
        &layout,
        SnapshotId(0),
        RetentionPolicy {
            archived_wals_retain: 1,
            snapshots_retain: usize::MAX,
        },
    )
    .expect_err("WAL parent symlink must refuse");
    assert_wrong_type(&error, &wal_dir, "inspect retention directory");
    assert_eq!(
        std::fs::read(&older).expect("outside older WAL"),
        b"outside older WAL"
    );
    assert_eq!(
        std::fs::read(&newer).expect("outside newer WAL"),
        b"outside newer WAL"
    );
}

#[cfg(unix)]
#[test]
fn dangling_snapshot_container_symlink_is_not_an_absent_directory() {
    let root = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(root.path()).expect("layout");
    let snapshots_dir = layout.snapshots_dir();
    std::fs::remove_dir(&snapshots_dir).expect("replace empty snapshots container");
    let missing = root.path().join("missing-target");
    symlink(&missing, &snapshots_dir).expect("dangling container symlink");

    let error = apply_retention(&layout, SnapshotId(0), RetentionPolicy::default())
        .expect_err("dangling container symlink must refuse");
    assert_wrong_type(&error, &snapshots_dir, "inspect retention directory");
    assert!(!missing.exists());
    assert!(snapshots_dir
        .symlink_metadata()
        .expect("link metadata")
        .file_type()
        .is_symlink());
}

#[test]
fn truly_absent_snapshot_container_is_a_public_noop() {
    let root = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(root.path()).expect("layout");
    let snapshots_dir = layout.snapshots_dir();
    std::fs::remove_dir(&snapshots_dir).expect("remove empty snapshots container");

    let report = apply_retention(&layout, SnapshotId(0), RetentionPolicy::default())
        .expect("absent snapshots container is empty");
    assert_eq!(report.snapshots_removed, 0);
    assert!(!snapshots_dir.exists());
}

#[test]
fn truly_absent_archive_container_is_a_public_noop() {
    let root = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(root.path()).expect("layout");
    let archive_dir = layout.archived_wals_dir();
    std::fs::remove_dir(&archive_dir).expect("remove empty archive container");

    let report = apply_retention(&layout, SnapshotId(0), RetentionPolicy::default())
        .expect("absent archive container is empty");
    assert_eq!(report.archived_wals_removed, 0);
    assert!(!archive_dir.exists());
}

#[cfg(unix)]
#[test]
fn noncanonical_snapshot_symlink_is_ignored() {
    let root = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside tempdir");
    let layout = StoreLayout::open(root.path()).expect("layout");
    let linked = layout.snapshots_dir().join("snap-1");
    symlink(outside.path(), &linked).expect("noncanonical symlink");

    let report = apply_retention(
        &layout,
        SnapshotId(0),
        RetentionPolicy {
            archived_wals_retain: usize::MAX,
            snapshots_retain: 0,
        },
    )
    .expect("noncanonical symlink is ignored");
    assert_eq!(report.snapshots_removed, 0);
    assert!(linked
        .symlink_metadata()
        .expect("link metadata")
        .file_type()
        .is_symlink());
    assert!(outside.path().is_dir());
}

proptest! {
    #[test]
    fn canonical_wrong_type_refuses_across_bounded_ids(is_wal in any::<bool>(), id in 10u64..=14) {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let malformed = if is_wal {
            let malformed = layout.wal_archived_path(id, id + 1);
            std::fs::create_dir(&malformed).expect("canonical WAL directory");
            malformed
        } else {
            let malformed = layout.snapshot_dir(SnapshotId(id));
            std::fs::write(&malformed, b"not a directory").expect("canonical snapshot file");
            malformed
        };
        let policy = if is_wal {
            RetentionPolicy { archived_wals_retain: 0, snapshots_retain: usize::MAX }
        } else {
            RetentionPolicy { archived_wals_retain: usize::MAX, snapshots_retain: 0 }
        };
        let error = apply_retention(&layout, SnapshotId(0), policy)
            .expect_err("canonical wrong type must refuse");
        assert_wrong_type(&error, &malformed, "inspect artifact metadata");
    }
}
