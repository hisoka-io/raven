//! Crash-consistent durability primitives for a PIR server. [`Manifest`] is
//! the single linearization point for snapshot commits; recovery truncates
//! the WAL at the first bad crc. Payloads are opaque `Vec<u8>`.
//! Server-side only; never on the wasm client path.

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]
#![deny(missing_docs)]

pub mod manifest;
pub mod recovery;
pub mod retention;
pub mod snapshot;
pub mod wal;

use raven_core::InstanceId;
use std::path::PathBuf;

pub use manifest::{
    Manifest, ManifestShape, MANIFEST_SCHEMA_VERSION, MIN_READABLE_MANIFEST_SCHEMA_VERSION,
};
pub use recovery::{open_recovery, StoreRecovery};
pub use retention::{apply_retention, RetentionPolicy, RetentionReport};
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

    /// Current manifest bytes omit the required cell geometry.
    #[error(
        "manifest schema v{schema_version} has no cell shape; recover geometry from the owning \
         snapshot and migrate the manifest, or restore/re-bootstrap this data_dir"
    )]
    ManifestShapeMissing {
        /// Schema version that omitted the shape.
        schema_version: u32,
    },

    /// Manifest cell geometry is partial or contains a zero dimension.
    #[error(
        "manifest schema v{schema_version} has invalid cell shape: entry_size_bytes={entry_size_bytes:?}, \
         rows_per_shard={rows_per_shard:?}; both fields must be present and nonzero"
    )]
    ManifestShapeInvalid {
        /// Schema version carrying the invalid shape.
        schema_version: u32,
        /// Stored record width, when present.
        entry_size_bytes: Option<usize>,
        /// Stored shard row count, when present.
        rows_per_shard: Option<u64>,
    },

    /// Persisted and configured/recovered cell geometry disagree.
    #[error(
        "manifest cell shape mismatch: stored entry_size_bytes={stored_entry_size_bytes}, \
         rows_per_shard={stored_rows_per_shard}; configured/recovered entry_size_bytes={configured_entry_size_bytes}, \
         rows_per_shard={configured_rows_per_shard}. Restore the configuration that created this \
         data_dir or have it re-bootstrapped; changing geometry does not migrate encoded rows"
    )]
    ManifestShapeMismatch {
        /// Persisted record width.
        stored_entry_size_bytes: usize,
        /// Persisted rows per shard.
        stored_rows_per_shard: u64,
        /// Configured or snapshot-derived record width.
        configured_entry_size_bytes: usize,
        /// Configured or snapshot-derived rows per shard.
        configured_rows_per_shard: u64,
    },

    /// Retention could not inspect or remove an owned path.
    #[error("retention {operation} failed for {}: {source}", path.display())]
    RetentionIo {
        /// Operation being attempted.
        operation: &'static str,
        /// Path the operation targeted.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: std::io::Error,
    },
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
    /// Compute all store paths without reading or creating the root.
    ///
    /// Use this for inspection/export. Passing the returned layout to a writer
    /// still performs that writer's documented filesystem operations.
    ///
    /// ```
    /// use raven_storage::StoreLayout;
    /// let dir = tempfile::tempdir()?;
    /// let missing = dir.path().join("missing");
    /// let layout = StoreLayout::inspect(&missing);
    /// assert!(!layout.root().exists());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn inspect(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
        }
    }

    /// Creates subdirs if absent. Takes no lock, so concurrent writers can
    /// corrupt the WAL; prefer [`StoreLayout::open_with_lock`].
    pub fn open(data_dir: impl Into<PathBuf>) -> Result<Self> {
        let layout = Self::inspect(data_dir);
        std::fs::create_dir_all(layout.root())?;
        std::fs::create_dir_all(layout.snapshots_dir())?;
        std::fs::create_dir_all(layout.archived_wals_dir())?;
        Ok(layout)
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

    /// `data_dir/snapshots`.
    pub fn snapshots_dir(&self) -> PathBuf {
        self.data_dir.join("snapshots")
    }

    /// `data_dir/wal`.
    pub fn wal_dir(&self) -> PathBuf {
        self.data_dir.join("wal")
    }

    /// `data_dir/wal/archived`.
    pub fn archived_wals_dir(&self) -> PathBuf {
        self.wal_dir().join("archived")
    }

    /// `data_dir/wal/current.log`.
    pub fn wal_current_path(&self) -> PathBuf {
        self.wal_dir().join("current.log")
    }

    /// Archived WAL path for the sealed seq range `[from_seq, to_seq]`.
    pub fn wal_archived_path(&self, from_seq: u64, to_seq: u64) -> PathBuf {
        self.archived_wals_dir()
            .join(format!("seq-{from_seq:020}-{to_seq:020}.log"))
    }

    /// Snapshot directory for the given id.
    pub fn snapshot_dir(&self, id: SnapshotId) -> PathBuf {
        self.snapshots_dir().join(format!("snap-{:06}", id.0))
    }

    /// Header file for a snapshot id.
    pub fn snapshot_header_path(&self, id: SnapshotId) -> PathBuf {
        self.snapshot_dir(id).join("header.bin")
    }

    /// Payload file for a snapshot id.
    pub fn snapshot_data_path(&self, id: SnapshotId) -> PathBuf {
        self.snapshot_dir(id).join("data.bincode")
    }
}

/// Atomically replaces a file and durably publishes its directory entry.
///
/// Missing parent directories are created. The sibling scratch file uses a
/// process-and-sequence suffix and mode `0o600` on Unix.
///
/// # Errors
///
/// Returns the underlying I/O error from directory creation, writing, syncing,
/// or renaming.
///
/// # Examples
///
/// ```
/// let dir = tempfile::tempdir()?;
/// let path = dir.path().join("nested").join("state.bin");
/// raven_storage::atomic_write(&path, b"state")?;
/// assert_eq!(std::fs::read(path)?, b"state");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "write path has no parent")
    })?;
    std::fs::create_dir_all(parent)?;
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "write path has no file name",
        )
    })?;
    let mut tmp_name = file_name.to_owned();
    tmp_name.push(format!(
        ".tmp.{:x}.{}",
        std::process::id(),
        next_atomic_write_seq()
    ));
    let tmp = path.with_file_name(tmp_name);
    {
        use std::io::Write;
        let mut f = create_owner_only(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    fsync_parent_dir(parent)?;
    Ok(())
}

fn next_atomic_write_seq() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

/// Mode 0o600 on Unix, blocking local tampering between fsync and restart on
/// multi-tenant hosts. Elsewhere the parent directory's ACLs apply.
pub(crate) fn create_owner_only(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::File::create(path)
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

/// Syncs a directory after creating, renaming, or removing one of its entries.
///
/// `EINVAL`, [`std::io::ErrorKind::Unsupported`], and failure to open the
/// directory due to [`std::io::ErrorKind::PermissionDenied`] are tolerated for
/// filesystems that do not permit directory syncing.
///
/// # Errors
///
/// Returns any other error from opening or syncing the directory.
///
/// # Examples
///
/// ```
/// let dir = tempfile::tempdir()?;
/// std::fs::write(dir.path().join("state.bin"), b"state")?;
/// raven_storage::fsync_parent_dir(dir.path())?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn fsync_parent_dir(parent: &std::path::Path) -> std::io::Result<()> {
    match std::fs::File::open(parent) {
        Ok(dir) => normalize_parent_sync_result(dir.sync_all()),
        Err(e) if matches!(e.kind(), std::io::ErrorKind::PermissionDenied) => Ok(()),
        Err(e) => Err(e),
    }
}

fn normalize_parent_sync_result(sync_result: std::io::Result<()>) -> std::io::Result<()> {
    match sync_result {
        Ok(()) => Ok(()),
        Err(e)
            if matches!(e.raw_os_error(), Some(22))
                || matches!(e.kind(), std::io::ErrorKind::Unsupported) =>
        {
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Durably publish a snapshot: write it, then [`advance_manifest_and_archive`].
///
/// A caller that must keep a slow snapshot write off its manifest lock calls the
/// two halves separately instead.
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
    SnapshotFile::build(payload, magic).save(layout, snapshot_id)?;
    advance_manifest_and_archive(layout, wal, manifest, snapshot_id, mutate)
}

/// Point the manifest at `snapshot_id`, then archive the WAL range it consumed.
///
/// The order is a crash-safety contract, not a style choice: the manifest save
/// moves the replay floor to `wal.next_seq()` BEFORE the archive moves the log,
/// so a crash between the two still replays the survivors in `current.log`.
/// Archiving first would strand entries the floor still points at.
///
/// `mutate` receives the snapshot id and the new replay floor, so the caller
/// keeps ownership of its own manifest fields. It MUST assign both: a manifest
/// left on the old floor with the log already sealed replays from a range the
/// archive took away. `mutate` runs against a staged copy that is validated
/// before it replaces `manifest`, so a refusal leaves the caller holding the
/// manifest it passed in rather than a half-advanced one.
///
/// The sealed range is named from the log rather than from the incoming
/// manifest, so a caller that pre-advanced its own floor cannot alias two
/// archives onto one path. A log holding nothing has no range to seal, so the
/// manifest advances and the log is left in place; a snapshot cadence that fires
/// with no appends in between would otherwise name one path over and over.
///
/// # Errors
/// [`PersistenceError::Invariant`] when `mutate` leaves the staged manifest off
/// `snapshot_id` or off the new floor, plus any manifest write or archive
/// failure, unmodified.
pub fn advance_manifest_and_archive<F>(
    layout: &StoreLayout,
    wal: &Wal,
    manifest: &mut Manifest,
    snapshot_id: SnapshotId,
    mutate: F,
) -> Result<()>
where
    F: FnOnce(&mut Manifest, SnapshotId, u64),
{
    let new_floor = wal.next_seq();
    let archive_to = new_floor.saturating_sub(1);
    let sealable = wal.first_seq();
    let archive_from = sealable.unwrap_or(new_floor);

    let mut staged = manifest.clone();
    mutate(&mut staged, snapshot_id, new_floor);
    if staged.current_snapshot_id != snapshot_id || staged.current_snapshot_seq != new_floor {
        return Err(PersistenceError::Invariant(format!(
            "publish must leave the manifest at snapshot {:?} floor {new_floor}; mutate left \
             snapshot {:?} floor {}. Nothing was written and the caller's manifest is unchanged, \
             so WAL seqs {archive_from}..={archive_to} still replay.",
            snapshot_id, staged.current_snapshot_id, staged.current_snapshot_seq
        )));
    }
    *manifest = staged;
    manifest.save(layout)?;
    if sealable.is_some() {
        wal.archive(archive_from, archive_to)?;
    }
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
    fn atomic_write_ignores_legacy_fixed_tmp_collision() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("manifest.json");
        let fixed_tmp = path.with_extension("tmp");
        std::fs::create_dir(&fixed_tmp).expect("reserve fixed tmp path");

        atomic_write(&path, b"new manifest").expect("unique tmp path must avoid collision");

        assert_eq!(std::fs::read(&path).expect("read final"), b"new manifest");
        assert!(fixed_tmp.is_dir(), "fixed tmp sentinel must be untouched");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_creates_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.bin");
        atomic_write(&path, b"secret").expect("write");

        let mode = std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    fn publish_fixture() -> (tempfile::TempDir, StoreLayout, Wal, Manifest) {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let wal = Wal::open(&layout, None).expect("wal");
        for i in 0..3u32 {
            wal.append(&i, 100 + u64::from(i)).expect("append");
        }
        let manifest = Manifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            scheme_tag: "test-scheme".to_owned(),
            instance_id: "test-instance".to_owned(),
            current_snapshot_id: SnapshotId(0),
            current_snapshot_seq: 0,
            current_marker: 0,
            encoder_label: "test-encoder".to_owned(),
            prev_encoder_label: None,
            entry_size_bytes: Some(32),
            rows_per_shard: Some(2048),
        };
        (dir, layout, wal, manifest)
    }

    fn point_at(m: &mut Manifest, id: SnapshotId, floor: u64) {
        m.current_snapshot_id = id;
        m.current_snapshot_seq = floor;
    }

    #[test]
    fn publish_snapshot_advances_the_floor_and_seals_the_log() {
        let (_d, layout, wal, mut manifest) = publish_fixture();
        let expected_floor = wal.next_seq();

        publish_snapshot(
            &layout,
            &wal,
            &mut manifest,
            SnapshotId(1),
            b"payload".to_vec(),
            *b"TESTMAGIC_000001",
            point_at,
        )
        .expect("publish");

        assert_eq!(
            manifest.current_snapshot_id,
            SnapshotId(1),
            "the staged mutation must be committed into the caller's manifest"
        );
        assert_eq!(manifest.current_snapshot_seq, expected_floor);
        let on_disk = Manifest::load(&layout).expect("load").expect("present");
        assert_eq!(on_disk, manifest, "disk must mirror the caller's manifest");
        assert_eq!(on_disk.current_snapshot_id, SnapshotId(1));
        assert_eq!(on_disk.current_snapshot_seq, expected_floor);
        assert!(
            wal.replay().expect("replay").entries.is_empty(),
            "the consumed log must be sealed"
        );
    }

    /// A crash between the two writes must not strand entries the floor still
    /// points at, so the archive runs only after the manifest lands.
    #[cfg(unix)]
    #[test]
    fn a_failed_manifest_save_leaves_the_log_unarchived() {
        use std::os::unix::fs::PermissionsExt;

        let (_d, layout, wal, mut manifest) = publish_fixture();
        let root = layout.root().to_path_buf();
        let restore = std::fs::metadata(&root).expect("meta").permissions();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o555)).expect("chmod");

        let err =
            advance_manifest_and_archive(&layout, &wal, &mut manifest, SnapshotId(1), point_at)
                .expect_err("manifest save must fail under a read-only root");

        std::fs::set_permissions(&root, restore).expect("restore");
        assert!(matches!(err, PersistenceError::Io(_)), "got {err:?}");
        assert_eq!(
            wal.replay().expect("replay").entries.len(),
            3,
            "entries must survive a failed publish"
        );
    }

    /// A mutate that leaves the floor behind would point recovery at a range
    /// the archive just took away, so nothing may be written.
    #[test]
    fn a_mutate_that_ignores_the_new_floor_is_refused_before_the_log_is_sealed() {
        let (_d, layout, wal, mut manifest) = publish_fixture();

        let err = advance_manifest_and_archive(
            &layout,
            &wal,
            &mut manifest,
            SnapshotId(1),
            |m, id, _floor| {
                m.current_snapshot_id = id;
            },
        )
        .expect_err("a mutate that leaves the floor behind must be refused");

        assert!(matches!(err, PersistenceError::Invariant(_)), "got {err:?}");
        assert_eq!(
            wal.replay().expect("replay").entries.len(),
            3,
            "the log must not be sealed when the floor did not advance"
        );
        assert!(
            Manifest::load(&layout).expect("load").is_none(),
            "no manifest may be written for a refused publish"
        );
    }

    /// A refusal must leave the caller holding the manifest it came in with. A
    /// half-advanced in-memory manifest matches neither the disk nor the log, so
    /// the next publish or recovery reads a floor nothing ever committed.
    #[test]
    fn a_refused_mutate_leaves_the_callers_manifest_untouched() {
        let (_d, layout, wal, mut manifest) = publish_fixture();
        let before = manifest.clone();

        let err = advance_manifest_and_archive(
            &layout,
            &wal,
            &mut manifest,
            SnapshotId(1),
            |m, id, _floor| {
                m.current_snapshot_id = id;
            },
        )
        .expect_err("a mutate that leaves the floor behind must be refused");

        assert!(matches!(err, PersistenceError::Invariant(_)), "got {err:?}");
        assert_eq!(
            manifest, before,
            "the caller's in-memory manifest must be byte-identical after a refusal; \
             reading manifest.json back cannot catch this because nothing was written"
        );
    }

    /// The sealed range is named from the log, not from the caller's incoming
    /// floor; otherwise two publishes can alias onto one archive path and the
    /// second, empty one replaces the first.
    #[test]
    fn a_second_publish_with_no_appends_keeps_the_first_archive() {
        let (_d, layout, wal, mut manifest) = publish_fixture();
        manifest.current_snapshot_seq = wal.next_seq();
        let sealed_len = std::fs::metadata(layout.wal_current_path())
            .expect("stat")
            .len();
        assert!(sealed_len > 0, "fixture must leave a non-empty log");

        advance_manifest_and_archive(&layout, &wal, &mut manifest, SnapshotId(1), point_at)
            .expect("first publish");
        advance_manifest_and_archive(&layout, &wal, &mut manifest, SnapshotId(2), point_at)
            .expect("second publish");

        let sizes: Vec<u64> = std::fs::read_dir(layout.root().join("wal").join("archived"))
            .expect("read archive dir")
            .filter_map(std::result::Result::ok)
            .map(|e| e.metadata().map_or(0, |m| m.len()))
            .collect();
        assert!(
            sizes.contains(&sealed_len),
            "the sealed entries must survive the second publish; archived sizes {sizes:?}, sealed {sealed_len} bytes"
        );
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
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn unsupported_parent_sync_is_tolerated() {
        let unsupported = std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "directory fsync unsupported",
        );
        normalize_parent_sync_result(Err(unsupported))
            .expect("unsupported directory fsync must be tolerated");
    }

    #[test]
    fn atomic_write_creates_missing_parent_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("does-not-exist").join("file.bin");
        atomic_write(&path, b"payload").expect("missing parents must be created");
        assert_eq!(std::fs::read(path).expect("read final"), b"payload");
    }

    #[test]
    fn fsync_parent_dir_ok_on_real_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        fsync_parent_dir(dir.path()).expect("fsync of real dir must succeed");
    }
}
