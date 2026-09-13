//! One manifest, snapshot, and WAL recovery pipeline.

use crate::{Manifest, Result, SnapshotFile, StoreLayout, Wal, WalReplay};

/// Open durability state recovered from one manifest generation.
#[derive(Debug)]
pub struct StoreRecovery {
    /// Schema-valid manifest selected for recovery.
    pub manifest: Manifest,
    /// Current snapshot, absent only when the manifest snapshot id is zero.
    pub snapshot: Option<SnapshotFile>,
    /// Appendable WAL opened at the manifest resume floor.
    pub wal: Wal,
    /// Current-log entries at or above `manifest.current_snapshot_seq`.
    pub replay: WalReplay,
}

/// Load and validate a manifest, recover its current snapshot, then open and
/// filter the WAL at the manifest replay floor.
///
/// `validate_manifest` runs before snapshot or WAL I/O. A missing manifest
/// returns `Ok(None)` without creating a WAL.
///
/// # Errors
///
/// Returns manifest, validation, snapshot, or WAL errors without weakening them.
///
/// # Examples
///
/// ```
/// use raven_storage::{open_recovery, StoreLayout};
/// let dir = tempfile::tempdir()?;
/// let layout = StoreLayout::open(dir.path())?;
/// assert!(open_recovery(
///     &layout,
///     *b"MYFMT00000000001",
///     |_| Ok(()),
/// )?.is_none());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn open_recovery<F>(
    layout: &StoreLayout,
    expected_magic: [u8; 16],
    validate_manifest: F,
) -> Result<Option<StoreRecovery>>
where
    F: FnOnce(&Manifest) -> Result<()>,
{
    let Some(manifest) = Manifest::load(layout)? else {
        return Ok(None);
    };
    validate_manifest(&manifest)?;
    if manifest.current_snapshot_id.0 == 0 && manifest.current_snapshot_seq > 0 {
        return Err(crate::PersistenceError::Invariant(format!(
            "manifest snapshot id 0 denotes no committed snapshot but replay floor {} would drop \
             uncovered WAL entries; restore manifest.json and wal/ from the same point, or \
             re-bootstrap this data_dir",
            manifest.current_snapshot_seq
        )));
    }
    let snapshot = if manifest.current_snapshot_id.0 == 0 {
        None
    } else {
        Some(SnapshotFile::load(
            layout,
            manifest.current_snapshot_id,
            expected_magic,
        )?)
    };
    let replay_floor = manifest.current_snapshot_seq;
    let wal = Wal::open(layout, replay_floor.checked_sub(1))?;
    let mut replay = wal.replay()?;
    replay.entries.retain(|entry| entry.seq >= replay_floor);
    Ok(Some(StoreRecovery {
        manifest,
        snapshot,
        wal,
        replay,
    }))
}
