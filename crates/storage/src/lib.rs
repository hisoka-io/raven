//! Crash-consistent durability primitives for a PIR server. [`Manifest`] is
//! the single linearization point for snapshot commits; recovery truncates
//! the WAL at the first bad crc. Payloads are opaque `Vec<u8>`.
//! Server-side only; never on the wasm client path.

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]
#![deny(missing_docs)]

pub mod manifest;
pub mod snapshot;
pub mod wal;

use raven_core::InstanceId;
use std::path::PathBuf;

pub use manifest::{Manifest, MANIFEST_SCHEMA_VERSION, MIN_READABLE_MANIFEST_SCHEMA_VERSION};
pub use snapshot::{SnapshotFile, SnapshotHeader, SnapshotId};
pub use wal::{Wal, WalEntry, WalReplay, WAL_MAX_PAYLOAD_BYTES};

/// Typed errors from the durability layer.
#[derive(thiserror::Error, Debug)]
pub enum PersistenceError {
    /// I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Snapshot or WAL codec failure.
    #[error("bincode: {0}")]
    Bincode(String),

    /// Manifest codec failure.
    #[error("json: {0}")]
    Json(String),

    /// Manifest points at a snapshot that cannot be loaded.
    #[error("snapshot {0:?} not found")]
    SnapshotNotFound(SnapshotId),

    /// Missing or unparseable; recovery bootstraps fresh.
    #[error("manifest missing or corrupt: {0}")]
    ManifestMissing(String),

    /// Header magic or checksum mismatch.
    #[error("snapshot corrupt: {0}")]
    SnapshotCorrupt(String),

    /// crc32 mismatch; recovery truncates at this position.
    #[error("wal entry corrupt at seq {0}")]
    WalCorrupt(u64),

    /// Instance id unknown to this store.
    #[error("instance {0} not registered")]
    UnknownInstance(InstanceId),

    /// Post-condition violation surfaced as an error, not a panic.
    #[error("invariant violated: {0}")]
    Invariant(String),

    /// Another process holds `data_dir/.lock`.
    #[error("data_dir is locked by another process: {0}")]
    LockHeld(String),
}

impl From<bincode::Error> for PersistenceError {
    fn from(e: bincode::Error) -> Self {
        PersistenceError::Bincode(e.to_string())
    }
}

impl From<serde_json::Error> for PersistenceError {
    fn from(e: serde_json::Error) -> Self {
        PersistenceError::Json(e.to_string())
    }
}

/// Convenience [`Result`] alias.
pub type Result<T, E = PersistenceError> = core::result::Result<T, E>;

/// Filesystem layout for one instance. Assumes exclusive write ownership of
/// `data_dir`; [`StoreLayout::open_with_lock`] enforces that with `flock`.
#[derive(Clone, Debug)]
pub struct StoreLayout {
    data_dir: PathBuf,
}

impl StoreLayout {
    /// Creates subdirs if absent. Takes no lock, so concurrent writers can
    /// corrupt the WAL; prefer [`StoreLayout::open_with_lock`].
    pub fn open(data_dir: impl Into<PathBuf>) -> Result<Self> {
        let data_dir = data_dir.into();
        std::fs::create_dir_all(&data_dir)?;
        std::fs::create_dir_all(data_dir.join("snapshots"))?;
        std::fs::create_dir_all(data_dir.join("wal").join("archived"))?;
        Ok(Self { data_dir })
    }

    /// As [`StoreLayout::open`], plus an exclusive advisory lock released on
    /// [`ExclusiveLock`] drop.
    pub fn open_with_lock(data_dir: impl Into<PathBuf>) -> Result<(Self, ExclusiveLock)> {
        let layout = Self::open(data_dir)?;
        let lock = ExclusiveLock::acquire(layout.data_dir.join(".lock"))?;
        Ok((layout, lock))
    }

    /// Root directory.
    pub fn root(&self) -> &std::path::Path {
        &self.data_dir
    }

    /// `data_dir/manifest.json`.
    pub fn manifest_path(&self) -> PathBuf {
        self.data_dir.join("manifest.json")
    }

    /// `data_dir/wal/current.log`.
    pub fn wal_current_path(&self) -> PathBuf {
        self.data_dir.join("wal").join("current.log")
    }

    /// Archived WAL path for the sealed seq range `[from_seq, to_seq]`.
    pub fn wal_archived_path(&self, from_seq: u64, to_seq: u64) -> PathBuf {
        self.data_dir
            .join("wal")
            .join("archived")
            .join(format!("seq-{from_seq:020}-{to_seq:020}.log"))
    }

    /// Snapshot directory for the given id.
    pub fn snapshot_dir(&self, id: SnapshotId) -> PathBuf {
        self.data_dir
            .join("snapshots")
            .join(format!("snap-{:06}", id.0))
    }
}

/// Write to `path.tmp`, fsync, rename, fsync parent. The parent fsync is what
/// makes the same-fs atomic rename durable across a crash.
pub(crate) fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut f = create_owner_only(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        fsync_parent_dir(parent)?;
    }
    Ok(())
}

/// Mode 0o600 on Unix, blocking local tampering between fsync and restart on
/// multi-tenant hosts. Elsewhere the parent directory's ACLs apply.
pub(crate) fn create_owner_only(path: &std::path::Path) -> Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        Ok(std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?)
    }
    #[cfg(not(unix))]
    {
        Ok(std::fs::File::create(path)?)
    }
}

/// Exclusive advisory lock on `data_dir/.lock`, released on drop.
#[derive(Debug)]
pub struct ExclusiveLock {
    // held open so the kernel keeps the flock alive until drop
    _file: std::fs::File,
    path: PathBuf,
}

impl ExclusiveLock {
    /// Non-blocking; creates `path` if absent.
    pub fn acquire(path: PathBuf) -> Result<Self> {
        use fs4::{FileExt, TryLockError};

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;

        match <std::fs::File as FileExt>::try_lock(&file) {
            Ok(()) => Ok(Self { _file: file, path }),
            Err(TryLockError::WouldBlock) => Err(PersistenceError::LockHeld(format!(
                "flock on {} returned WouldBlock; another process \
                 holds the lock. Stop the other writer or pick a \
                 different data_dir.",
                path.display()
            ))),
            Err(TryLockError::Error(e)) => Err(PersistenceError::LockHeld(format!(
                "flock on {} failed: {e}; another process likely \
                 holds the lock. Stop the other writer or pick a \
                 different data_dir.",
                path.display()
            ))),
        }
    }

    /// Path of the lock file.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

/// Tolerates EINVAL (FSes that disallow dir fsync), `Unsupported`
/// (WSL2/virtio-fs) and `PermissionDenied`; propagates everything else.
pub(crate) fn fsync_parent_dir(parent: &std::path::Path) -> Result<()> {
    match std::fs::File::open(parent) {
        Ok(dir) => match dir.sync_all() {
            Ok(()) => Ok(()),
            Err(e)
                if matches!(e.raw_os_error(), Some(22))
                    || matches!(e.kind(), std::io::ErrorKind::Unsupported) =>
            {
                Ok(())
            }
            Err(e) => Err(PersistenceError::Io(e)),
        },
        Err(e) if matches!(e.kind(), std::io::ErrorKind::PermissionDenied) => Ok(()),
        Err(e) => Err(PersistenceError::Io(e)),
    }
}

/// Durably publish a snapshot: write it, advance the manifest, then archive the log.
///
/// The order is a crash-safety contract, not a style choice. The manifest save
/// moves the replay floor to `wal.next_seq()` BEFORE the archive moves the log,
/// so a crash between the two still replays the survivors in `current.log`.
/// Archiving first would strand entries the floor still points at.
///
/// `mutate` receives the snapshot id and the new replay floor and applies them to
/// the caller's manifest, so the caller keeps ownership of its own fields.
///
/// # Errors
/// Any snapshot write, manifest write, or archive failure, unmodified.
pub fn publish_snapshot<F>(
    layout: &StoreLayout,
    wal: &Wal,
    manifest: &mut Manifest,
    snapshot_id: SnapshotId,
    payload: Vec<u8>,
    magic: [u8; 16],
    mutate: F,
) -> Result<()>
where
    F: FnOnce(&mut Manifest, SnapshotId, u64),
{
    let archive_from = manifest.current_snapshot_seq;
    let archive_to = wal.next_seq().saturating_sub(1);
    let new_floor = wal.next_seq();

    SnapshotFile::build(payload, magic).save(layout, snapshot_id)?;
    mutate(manifest, snapshot_id, new_floor);
    manifest.save(layout)?;
    wal.archive(archive_from, archive_to)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_layout_creates_dirs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        assert!(layout.root().is_dir());
        assert!(layout.root().join("snapshots").is_dir());
        assert!(layout.root().join("wal").is_dir());
        assert!(layout.root().join("wal").join("archived").is_dir());
    }

    #[test]
    fn atomic_write_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.bin");
        atomic_write(&path, b"hello world").expect("write");
        let read = std::fs::read(&path).expect("read");
        assert_eq!(read, b"hello world");
    }

    #[test]
    fn atomic_write_overwrites_existing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.bin");
        atomic_write(&path, b"first").expect("write1");
        atomic_write(&path, b"second").expect("write2");
        let read = std::fs::read(&path).expect("read");
        assert_eq!(read, b"second");
    }

    #[test]
    fn open_with_lock_rejects_second_holder() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_layout, _lock) = StoreLayout::open_with_lock(dir.path()).expect("first lock");
        let err = StoreLayout::open_with_lock(dir.path()).expect_err("second must fail");
        assert!(matches!(err, PersistenceError::LockHeld(_)));
    }

    #[test]
    fn open_with_lock_succeeds_after_drop() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let (_layout, _lock) = StoreLayout::open_with_lock(dir.path()).expect("first");
        }
        let _again = StoreLayout::open_with_lock(dir.path()).expect("second after drop");
    }

    #[test]
    fn fs4_exclusive_lock_contention_returns_lock_held() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".lock");
        let _first = ExclusiveLock::acquire(path.clone()).expect("first acquire ok");
        let err = ExclusiveLock::acquire(path).expect_err("second must fail");
        match err {
            PersistenceError::LockHeld(msg) => {
                assert!(
                    msg.contains("flock"),
                    "expected fs4 flock error message; got `{msg}`"
                );
            }
            other => panic!("expected LockHeld, got {other:?}"),
        }
    }

    #[test]
    fn open_without_lock_does_not_lock() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _l1 = StoreLayout::open(dir.path()).expect("first bare open");
        let _l2 = StoreLayout::open(dir.path()).expect("second bare open");
    }

    #[test]
    fn fsync_parent_dir_propagates_notfound_on_missing_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("does-not-exist");
        let err = fsync_parent_dir(&missing).expect_err("missing parent must error");
        match err {
            PersistenceError::Io(io_err) => {
                assert_eq!(io_err.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected PersistenceError::Io, got {other:?}"),
        }
    }

    #[test]
    fn atomic_write_errors_on_missing_grandparent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("does-not-exist").join("file.bin");
        let err = atomic_write(&path, b"payload").expect_err("missing grandparent must error");
        match err {
            PersistenceError::Io(io_err) => {
                assert_eq!(io_err.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn fsync_parent_dir_ok_on_real_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        fsync_parent_dir(dir.path()).expect("fsync of real dir must succeed");
    }
}
