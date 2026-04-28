//! Crash-consistent persistence for the Raven Railgun PIR engine.
//!
//! Three layered primitives: [`Snapshot`] (bincode + atomic-rename),
//! [`Wal`] (crc32-framed append-only log), and [`Manifest`] (JSON,
//! atomic-renamed — the single linearization point for snapshot commits).
//! Recovery truncates on the first bad WAL crc (torn write at the tail).

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]
#![deny(missing_docs)]

pub mod manifest;
pub mod snapshot;
pub mod wal;

use raven_railgun_core::InstanceId;
use std::path::PathBuf;

pub use manifest::{Manifest, MANIFEST_SCHEMA_VERSION};
pub use snapshot::{Snapshot, SnapshotId};
pub use wal::{Wal, WalEntry, WalEntryPayload, WalReplay};

/// Typed errors from the persistence layer.
#[derive(thiserror::Error, Debug)]
pub enum PersistenceError {
    /// Underlying I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Bincode serialize / deserialize failure.
    #[error("bincode: {0}")]
    Bincode(String),

    /// JSON serialize / deserialize failure (manifest only).
    #[error("json: {0}")]
    Json(String),

    /// Snapshot referenced by the manifest cannot be loaded.
    #[error("snapshot {0:?} not found")]
    SnapshotNotFound(SnapshotId),

    /// Manifest is missing or unparseable; recovery bootstraps fresh.
    #[error("manifest missing or corrupt: {0}")]
    ManifestMissing(String),

    /// Snapshot header magic / checksum did not match.
    #[error("snapshot corrupt: {0}")]
    SnapshotCorrupt(String),

    /// WAL entry crc32 mismatch; recovery truncates at this position.
    #[error("wal entry corrupt at seq {0}")]
    WalCorrupt(u64),

    /// Instance id unknown to this persistence store.
    #[error("instance {0} not registered")]
    UnknownInstance(InstanceId),

    /// Invariant violation; not a panic — caller decides recovery strategy.
    #[error("invariant violated: {0}")]
    Invariant(String),

    /// Advisory lock on `data_dir/.lock` is held by another process.
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

/// Filesystem layout owned by a single persistent instance.
///
/// Assumes exclusive write ownership of `data_dir`. Use
/// [`StoreLayout::open_with_lock`] to enforce the single-writer contract
/// via a POSIX `flock` advisory lock.
#[derive(Clone, Debug)]
pub struct StoreLayout {
    data_dir: PathBuf,
}

impl StoreLayout {
    /// Build a layout rooted at `data_dir`, creating subdirs if absent.
    ///
    /// Does NOT acquire an advisory lock. Use [`StoreLayout::open_with_lock`]
    /// to prevent concurrent writers from corrupting the WAL.
    pub fn open(data_dir: impl Into<PathBuf>) -> Result<Self> {
        let data_dir = data_dir.into();
        std::fs::create_dir_all(&data_dir)?;
        std::fs::create_dir_all(data_dir.join("snapshots"))?;
        std::fs::create_dir_all(data_dir.join("wal").join("archived"))?;
        Ok(Self { data_dir })
    }

    /// Build a layout and acquire an exclusive advisory lock on `data_dir/.lock`.
    ///
    /// Returns `PersistenceError::LockHeld` if another process holds the lock.
    /// Dropping the returned [`ExclusiveLock`] releases it.
    /// Not available on `wasm32` (no concurrent-writer surface in browsers).
    #[cfg(not(target_arch = "wasm32"))]
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

/// Write `bytes` to `path` atomically: write to `path.tmp`, fsync, rename, fsync parent.
///
/// POSIX same-fs renames are atomic. Parent-dir fsync makes the rename durable after a crash.
/// Parent-fsync errors are propagated except EINVAL (some FSes disallow dir fsync),
/// `Unsupported` (WSL2/virtio-fs), and `PermissionDenied` on dir open (sandbox quirks).
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

/// Create a file with owner-only permissions on Unix (mode 0o600).
///
/// Prevents local tampering between fsync and restart on multi-tenant hosts.
/// On non-Unix targets the mode is ignored; ACLs from the parent directory apply.
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

/// Exclusive advisory lock on `data_dir/.lock`.
///
/// Acquired via [`StoreLayout::open_with_lock`]. Dropping the guard releases the lock.
/// Not compiled on `wasm32` — no concurrent-writer surface in browsers.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
pub struct ExclusiveLock {
    // Kept open so the kernel holds the flock alive until drop.
    _file: std::fs::File,
    path: PathBuf,
}

#[cfg(not(target_arch = "wasm32"))]
impl ExclusiveLock {
    /// Acquire an exclusive non-blocking advisory lock on `path`, creating it if absent.
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

/// Fsync a parent directory to make an atomic rename durable after a crash.
/// Tolerates EINVAL, Unsupported, and PermissionDenied; propagates everything else.
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

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn open_with_lock_rejects_second_holder() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_layout, _lock) = StoreLayout::open_with_lock(dir.path()).expect("first lock");
        let err = StoreLayout::open_with_lock(dir.path()).expect_err("second must fail");
        assert!(matches!(err, PersistenceError::LockHeld(_)));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn open_with_lock_succeeds_after_drop() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let (_layout, _lock) = StoreLayout::open_with_lock(dir.path()).expect("first");
        } // lock released on drop
        let _again = StoreLayout::open_with_lock(dir.path()).expect("second after drop");
    }

    /// Pins the fs4 `TryLockError::WouldBlock` → `LockHeld` mapping directly
    /// on `ExclusiveLock::acquire` so a regression shows as a type-shape failure.
    #[cfg(not(target_arch = "wasm32"))]
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

    /// `fsync_parent_dir` must propagate I/O errors rather than swallow them.
    /// A prior implementation used `let _ = dir.sync_all()` which masked ENOSPC/EIO.
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
