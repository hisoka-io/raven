//! Snapshot and archived-WAL retention over [`crate::StoreLayout`].

use std::cmp::Reverse;
use std::path::{Path, PathBuf};

use crate::{fsync_parent_dir, PersistenceError, Result, SnapshotId, StoreLayout};

/// Counts of newest durability artifacts to retain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Sealed WAL files to retain. [`usize::MAX`] disables WAL pruning.
    pub archived_wals_retain: usize,
    /// Snapshot directories to retain. [`usize::MAX`] disables snapshot pruning.
    /// The live snapshot is always retained in addition to this window.
    pub snapshots_retain: usize,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            archived_wals_retain: 16,
            snapshots_retain: 4,
        }
    }
}

/// Number of owned durability artifacts removed by [`apply_retention`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetentionReport {
    /// Archived WAL files removed.
    pub archived_wals_removed: usize,
    /// Snapshot directories removed.
    pub snapshots_removed: usize,
}

/// Retain the newest owned durability artifacts and always preserve `live_snapshot`.
///
/// Unrecognized files and directories are left untouched. Successful removals are
/// synced at their parent directories before this function returns.
///
/// # Errors
///
/// Returns [`PersistenceError::RetentionIo`] when an owned directory or artifact
/// has the wrong type, cannot be read or removed, or deletion cannot be synced.
///
/// # Examples
///
/// ```
/// use raven_storage::{apply_retention, RetentionPolicy, SnapshotId, StoreLayout};
///
/// let dir = tempfile::tempdir()?;
/// let layout = StoreLayout::open(dir.path())?;
/// let report = apply_retention(&layout, SnapshotId(0), RetentionPolicy::default())?;
/// assert_eq!(report.archived_wals_removed, 0);
/// assert_eq!(report.snapshots_removed, 0);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn apply_retention(
    layout: &StoreLayout,
    live_snapshot: SnapshotId,
    policy: RetentionPolicy,
) -> Result<RetentionReport> {
    let archived_wals_removed = retain_archived_wals(layout, policy.archived_wals_retain)?;
    let snapshots_removed = retain_snapshots(layout, live_snapshot, policy.snapshots_retain)?;
    Ok(RetentionReport {
        archived_wals_removed,
        snapshots_removed,
    })
}

fn retention_io(operation: &'static str, path: &Path, source: std::io::Error) -> PersistenceError {
    PersistenceError::RetentionIo {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn retention_wrong_type(
    operation: &'static str,
    path: &Path,
    expected: &'static str,
) -> PersistenceError {
    retention_io(
        operation,
        path,
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected {expected}"),
        ),
    )
}

fn read_dir(path: &Path) -> Result<std::fs::ReadDir> {
    std::fs::read_dir(path).map_err(|source| retention_io("read directory", path, source))
}

fn retention_directory_exists(
    directory: &Path,
    metadata: impl FnOnce(&Path) -> std::io::Result<std::fs::Metadata>,
) -> Result<bool> {
    match metadata(directory) {
        Ok(metadata) if metadata.is_dir() => Ok(true),
        Ok(_) => Err(retention_wrong_type(
            "inspect retention directory",
            directory,
            "directory",
        )),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(retention_io(
            "inspect retention directory",
            directory,
            source,
        )),
    }
}

fn collect_owned_entries<T>(
    entries: impl Iterator<Item = std::io::Result<std::fs::DirEntry>>,
    directory: &Path,
    expected: &'static str,
    classify: impl Fn(PathBuf) -> Option<T>,
    inspect_kind: impl Fn(&Path) -> std::io::Result<bool>,
) -> Result<Vec<T>> {
    let mut owned = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|source| retention_io("read directory entry", directory, source))?;
        let path = entry.path();
        let Some(candidate) = classify(path.clone()) else {
            continue;
        };
        match inspect_kind(&path) {
            Ok(true) => owned.push(candidate),
            Ok(false) => {
                return Err(retention_wrong_type(
                    "inspect artifact metadata",
                    &path,
                    expected,
                ));
            }
            Err(source) => return Err(retention_io("inspect artifact metadata", &path, source)),
        }
    }
    Ok(owned)
}

fn archived_wal_range(path: PathBuf) -> Option<(u64, u64, PathBuf)> {
    let name = path.file_name()?.to_str()?;
    let body = name.strip_prefix("seq-")?.strip_suffix(".log")?;
    let (from, to) = body.split_once('-')?;
    if from.len() != 20 || to.len() != 20 {
        return None;
    }
    Some((from.parse().ok()?, to.parse().ok()?, path))
}

fn retain_archived_wals(layout: &StoreLayout, retain: usize) -> Result<usize> {
    if retain == usize::MAX {
        return Ok(0);
    }
    if !retention_directory_exists(&layout.wal_dir(), |path| std::fs::symlink_metadata(path))? {
        return Ok(0);
    }
    let archive_dir = layout.archived_wals_dir();
    if !retention_directory_exists(&archive_dir, |path| std::fs::symlink_metadata(path))? {
        return Ok(0);
    }
    let mut entries = collect_owned_entries(
        read_dir(&archive_dir)?,
        &archive_dir,
        "regular file",
        archived_wal_range,
        |path| std::fs::symlink_metadata(path).map(|metadata| metadata.is_file()),
    )?;
    entries.sort_by_key(|(from, to, _)| Reverse((*to, *from)));
    let mut removed = 0usize;
    for (_, _, path) in entries.into_iter().skip(retain) {
        std::fs::remove_file(&path)
            .map_err(|source| retention_io("remove archived WAL", &path, source))?;
        removed = removed.saturating_add(1);
    }
    if removed > 0 {
        fsync_parent_dir(&archive_dir)
            .map_err(|source| retention_io("sync archived WAL directory", &archive_dir, source))?;
    }
    Ok(removed)
}

fn snapshot_id(path: PathBuf) -> Option<(SnapshotId, PathBuf)> {
    let name = path.file_name()?.to_str()?;
    let id = name.strip_prefix("snap-")?.parse().ok()?;
    if name != format!("snap-{id:06}") {
        return None;
    }
    Some((SnapshotId(id), path))
}

fn retain_snapshots(
    layout: &StoreLayout,
    live_snapshot: SnapshotId,
    retain: usize,
) -> Result<usize> {
    if retain == usize::MAX {
        return Ok(0);
    }
    let snapshots_dir = layout.snapshots_dir();
    if !retention_directory_exists(&snapshots_dir, |path| std::fs::symlink_metadata(path))? {
        return Ok(0);
    }
    let mut entries = collect_owned_entries(
        read_dir(&snapshots_dir)?,
        &snapshots_dir,
        "directory",
        snapshot_id,
        |path| std::fs::symlink_metadata(path).map(|metadata| metadata.is_dir()),
    )?;
    entries.sort_by_key(|(id, _)| Reverse(*id));
    let mut removed = 0usize;
    for (id, path) in entries.into_iter().skip(retain) {
        if id == live_snapshot {
            continue;
        }
        std::fs::remove_dir_all(&path)
            .map_err(|source| retention_io("remove snapshot", &path, source))?;
        removed = removed.saturating_add(1);
    }
    if removed > 0 {
        fsync_parent_dir(&snapshots_dir)
            .map_err(|source| retention_io("sync snapshot directory", &snapshots_dir, source))?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use std::io;

    use proptest::prelude::*;

    use super::{
        archived_wal_range, collect_owned_entries, retention_directory_exists, snapshot_id,
    };
    use crate::{PersistenceError, SnapshotId, StoreLayout};

    #[test]
    fn archived_wal_entry_error_refuses_before_pruning() {
        let root = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(root.path()).expect("layout");
        let archive_dir = layout.archived_wals_dir();
        let owned = layout.wal_archived_path(1, 2);
        std::fs::write(&owned, b"keep until complete scan").expect("archived WAL");
        let entries = std::fs::read_dir(&archive_dir)
            .expect("read directory")
            .take(1)
            .chain(std::iter::once(Err(io::Error::other(
                "injected directory iteration fault",
            ))));

        let error = collect_owned_entries(
            entries,
            &archive_dir,
            "regular file",
            archived_wal_range,
            |path| std::fs::metadata(path).map(|metadata| metadata.is_file()),
        )
        .expect_err("a partial WAL inventory must refuse");

        assert!(matches!(
            error,
            PersistenceError::RetentionIo {
                operation: "read directory entry",
                path,
                source,
            } if path == archive_dir && source.kind() == io::ErrorKind::Other
        ));
        assert_eq!(
            std::fs::read(&owned).expect("owned WAL still present"),
            b"keep until complete scan"
        );
    }

    #[test]
    fn snapshot_entry_error_refuses_before_pruning() {
        let root = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(root.path()).expect("layout");
        let snapshots_dir = layout.snapshots_dir();
        let owned = layout.snapshot_dir(SnapshotId(1));
        std::fs::create_dir(&owned).expect("owned snapshot");
        let entries = std::fs::read_dir(&snapshots_dir)
            .expect("read directory")
            .take(1)
            .chain(std::iter::once(Err(io::Error::other(
                "injected directory iteration fault",
            ))));

        let error =
            collect_owned_entries(entries, &snapshots_dir, "directory", snapshot_id, |path| {
                std::fs::metadata(path).map(|metadata| metadata.is_dir())
            })
            .expect_err("a partial snapshot inventory must refuse");

        assert!(matches!(
            error,
            PersistenceError::RetentionIo {
                operation: "read directory entry",
                path,
                source,
            } if path == snapshots_dir && source.kind() == io::ErrorKind::Other
        ));
        assert!(owned.is_dir(), "owned snapshot must remain after refusal");
    }

    #[test]
    fn canonical_wal_metadata_error_refuses_before_pruning() {
        let root = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(root.path()).expect("layout");
        let archive_dir = layout.archived_wals_dir();
        let owned = layout.wal_archived_path(1, 2);
        std::fs::write(&owned, b"keep until complete scan").expect("archived WAL");

        let error = collect_owned_entries(
            std::fs::read_dir(&archive_dir).expect("read directory"),
            &archive_dir,
            "regular file",
            archived_wal_range,
            |_| Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        )
        .expect_err("canonical WAL metadata error must refuse");

        assert!(matches!(
            error,
            PersistenceError::RetentionIo {
                operation: "inspect artifact metadata",
                path,
                source,
            } if path == owned && source.kind() == io::ErrorKind::PermissionDenied
        ));
        assert!(owned.is_file(), "owned WAL must remain after refusal");
    }

    #[test]
    fn canonical_snapshot_metadata_error_refuses_before_pruning() {
        let root = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(root.path()).expect("layout");
        let snapshots_dir = layout.snapshots_dir();
        let owned = layout.snapshot_dir(SnapshotId(1));
        std::fs::create_dir(&owned).expect("owned snapshot");

        let error = collect_owned_entries(
            std::fs::read_dir(&snapshots_dir).expect("read directory"),
            &snapshots_dir,
            "directory",
            snapshot_id,
            |_| Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        )
        .expect_err("canonical snapshot metadata error must refuse");

        assert!(matches!(
            error,
            PersistenceError::RetentionIo {
                operation: "inspect artifact metadata",
                path,
                source,
            } if path == owned && source.kind() == io::ErrorKind::PermissionDenied
        ));
        assert!(owned.is_dir(), "owned snapshot must remain after refusal");
    }

    #[test]
    fn canonical_wal_disappearance_refuses_incomplete_inventory() {
        let root = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(root.path()).expect("layout");
        let archive_dir = layout.archived_wals_dir();
        let owned = layout.wal_archived_path(1, 2);
        std::fs::write(&owned, b"keep until complete scan").expect("archived WAL");

        let error = collect_owned_entries(
            std::fs::read_dir(&archive_dir).expect("read directory"),
            &archive_dir,
            "regular file",
            archived_wal_range,
            |_| Err(io::Error::from(io::ErrorKind::NotFound)),
        )
        .expect_err("canonical WAL disappearance must refuse");

        assert!(matches!(
            error,
            PersistenceError::RetentionIo {
                operation: "inspect artifact metadata",
                path,
                source,
            } if path == owned && source.kind() == io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn canonical_snapshot_disappearance_refuses_incomplete_inventory() {
        let root = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(root.path()).expect("layout");
        let snapshots_dir = layout.snapshots_dir();
        let owned = layout.snapshot_dir(SnapshotId(1));
        std::fs::create_dir(&owned).expect("owned snapshot");

        let error = collect_owned_entries(
            std::fs::read_dir(&snapshots_dir).expect("read directory"),
            &snapshots_dir,
            "directory",
            snapshot_id,
            |_| Err(io::Error::from(io::ErrorKind::NotFound)),
        )
        .expect_err("canonical snapshot disappearance must refuse");

        assert!(matches!(
            error,
            PersistenceError::RetentionIo {
                operation: "inspect artifact metadata",
                path,
                source,
            } if path == owned && source.kind() == io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn noncanonical_snapshot_never_probes_metadata() {
        let root = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(root.path()).expect("layout");
        let snapshots_dir = layout.snapshots_dir();
        std::fs::create_dir(snapshots_dir.join("snap-1")).expect("noncanonical snapshot");
        let metadata_probes = std::cell::Cell::new(0);

        let entries = collect_owned_entries(
            std::fs::read_dir(&snapshots_dir).expect("read directory"),
            &snapshots_dir,
            "directory",
            snapshot_id,
            |_| {
                metadata_probes.set(metadata_probes.get() + 1);
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            },
        )
        .expect("noncanonical spelling is ignored without metadata");

        assert_eq!(metadata_probes.get(), 0);
        assert!(entries.is_empty());
        assert!(snapshots_dir.join("snap-1").is_dir());
    }

    #[test]
    fn retention_directory_metadata_error_is_not_missing_directory() {
        let root = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(root.path()).expect("layout");
        for directory in [layout.archived_wals_dir(), layout.snapshots_dir()] {
            let error = retention_directory_exists(&directory, |_| {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            })
            .expect_err("unreadable retention directory must refuse");
            assert!(matches!(
                error,
                PersistenceError::RetentionIo {
                    operation: "inspect retention directory",
                    path,
                    source,
                } if path == directory && source.kind() == io::ErrorKind::PermissionDenied
            ));
        }
    }

    #[test]
    fn truly_missing_retention_directory_is_an_empty_inventory() {
        let root = tempfile::tempdir().expect("tempdir");
        let missing = root.path().join("missing");
        assert!(
            !retention_directory_exists(&missing, |path| std::fs::metadata(path))
                .expect("missing directory is empty")
        );
    }

    proptest! {
        #[test]
        fn every_item_error_position_refuses_a_partial_wal_inventory(
            (owned_count, fault_after) in (0usize..=4).prop_flat_map(|owned_count| {
                (Just(owned_count), 0usize..=owned_count)
            })
        ) {
            let root = tempfile::tempdir().expect("tempdir");
            let layout = StoreLayout::open(root.path()).expect("layout");
            let archive_dir = layout.archived_wals_dir();
            let mut owned_paths = Vec::new();
            for index in 0..owned_count {
                let from = u64::try_from(index).expect("bounded index");
                let owned = layout.wal_archived_path(from, from + 1);
                std::fs::write(&owned, b"keep until complete scan").expect("archived WAL");
                owned_paths.push(owned);
            }
            let mut entries = std::fs::read_dir(&archive_dir)
                .expect("read directory")
                .collect::<io::Result<Vec<_>>>()
                .expect("all fixture entries")
                .into_iter()
                .map(Ok)
                .collect::<Vec<_>>();
            prop_assert_eq!(entries.len(), owned_count);
            entries.insert(
                fault_after,
                Err(io::Error::other("injected directory iteration fault")),
            );

            let error = collect_owned_entries(
                entries.into_iter(),
                &archive_dir,
                "regular file",
                archived_wal_range,
                |path| std::fs::metadata(path).map(|metadata| metadata.is_file()),
            )
            .expect_err("any item error must refuse");

            let refused = matches!(
                error,
                PersistenceError::RetentionIo {
                    operation: "read directory entry",
                    path,
                    source,
                } if path == archive_dir && source.kind() == io::ErrorKind::Other
            );
            prop_assert!(refused);
            prop_assert!(owned_paths.iter().all(|path| path.is_file()));
        }
    }
}
