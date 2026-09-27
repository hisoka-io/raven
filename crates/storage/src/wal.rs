//! Append-only crc32-framed write-ahead log.
//!
//! Frame: `[seq u64 BE | marker u64 BE | payload_len u32 BE | crc32 u32 BE | payload]`,
//! crc over everything preceding it plus the payload. `seq` is the WAL's own
//! monotonic counter; `marker` is caller-supplied and also monotonic. Payloads
//! are opaque - [`Wal::replay`] hands the raw bytes back undecoded.
//!
//! [`Wal::append_deferred`] writes a frame with one `write(2)` and no fsync, so a
//! process kill loses nothing but a power loss can drop the unsynced suffix;
//! [`Wal::sync`] makes it durable. Frames carry no incarnation tag and the seqs of
//! lost frames are reused, so after a power loss the crc and seq scan is sound
//! only if the filesystem never exposes stale or reordered data inside the file's
//! durable length. ext4 with `data=ordered` (the default) and XFS guarantee that.

use crate::{PersistenceError, Result, StoreLayout};
use parking_lot::Mutex;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicU64, Ordering};

/// Per-entry ceiling; rejects a nonsense `payload_len` from a torn write.
pub const WAL_MAX_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

// A frame buffer grown past this by one large payload is dropped, not kept.
const RETAINED_FRAME_BUFFER_BYTES: usize = 1024 * 1024;

static RESUME_FLOOR_REFUSALS: AtomicU64 = AtomicU64::new(0);

/// Process-wide count of [`Wal::open`] calls refused for a resume floor above a
/// non-empty tail. Monotonic; exporters read it, nothing resets it.
pub fn resume_floor_refusals() -> u64 {
    RESUME_FLOOR_REFUSALS.load(Ordering::Relaxed)
}

/// One on-the-wire WAL entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalEntry {
    /// Monotonic within the log.
    pub seq: u64,
    /// Caller-supplied, monotonic; lets a caller truncate above a value.
    pub marker: u64,
    /// Opaque to this crate.
    pub payload: Vec<u8>,
}

/// Append-only WAL. The mutex serializes `append`; `replay` opens its own read handle.
#[derive(Debug)]
pub struct Wal {
    layout: StoreLayout,
    inner: Mutex<WalState>,
}

#[derive(Debug)]
struct WalState {
    file: File,
    next_seq: u64,
    /// Lowest seq still in `current.log`; `None` once it holds nothing.
    first_seq: Option<u64>,
    last_marker: u64,
    /// Byte length of `current.log`, and so the rewind target of a failed frame
    /// write. Tracked rather than read with `fstat`, so every path that changes the
    /// length (append, rewind, archive, the torn-tail cut in `open`) must set it.
    len: u64,
    /// Prefix of `len` known durable. Below `len` means a sync is pending.
    synced_len: u64,
    /// Set when an append tore or a sync failed. Every later append and sync is
    /// refused, because an entry acknowledged as written that a later replay
    /// drops is worse than a refused write.
    poisoned: bool,
    /// A sync failed. Linux may drop the failed dirty pages and clear the error,
    /// so a retried fsync can report success over lost data: only a reopen
    /// clears this, never an archive. A reopen restores appends, not proof of
    /// durability: frames it replays may still be missing after a power loss,
    /// and the source of truth re-derives them.
    sync_failed: bool,
    /// Reused so header and payload leave in one `write(2)` without a fresh buffer.
    frame: Vec<u8>,
    /// One-shot fault points; `cfg(test)` prevents a production test door.
    #[cfg(test)]
    faults: WalFaults,
}

#[cfg(test)]
#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)] // independent one-shot fault points, not a state
struct WalFaults {
    frame_write: bool,
    rewind: bool,
    archive_reopen: bool,
    sync: bool,
}

fn poisoned_error() -> PersistenceError {
    PersistenceError::Invariant(
        "WAL is poisoned by an earlier torn append or failed sync; reopen to recover".to_owned(),
    )
}

impl WalState {
    /// fdatasync unless nothing is pending. A failure poisons for good: see
    /// `sync_failed`. Does not check `poisoned`, because a seal recovers a log a
    /// torn append poisoned; `refuse_seal_after_failed_sync` guards it instead.
    fn flush(&mut self) -> Result<()> {
        if !self.poisoned && self.synced_len == self.len {
            return Ok(());
        }
        #[cfg(test)]
        let synced = if std::mem::replace(&mut self.faults.sync, false) {
            Err(std::io::Error::other("injected sync failure"))
        } else {
            self.file.sync_data()
        };
        #[cfg(not(test))]
        let synced = self.file.sync_data();
        match synced {
            Ok(()) => {
                self.synced_len = self.len;
                Ok(())
            }
            Err(e) => {
                self.poisoned = true;
                self.sync_failed = true;
                Err(e.into())
            }
        }
    }

    fn sync(&mut self) -> Result<()> {
        if self.poisoned {
            return Err(poisoned_error());
        }
        self.flush()
    }

    fn refuse_seal_after_failed_sync(&self, layout: &StoreLayout) -> Result<()> {
        if self.sync_failed {
            return Err(PersistenceError::Invariant(format!(
                "wal archive refused: an earlier sync of wal/current.log failed, so its \
                 durable contents are unknown and sealing it would retry that sync as a \
                 success. Operator: restart to reopen the log. Path: {}",
                layout.root().display()
            )));
        }
        Ok(())
    }

    /// Restore the log to `tail` after a frame write failed part-way, because a
    /// header without its payload stops replay at it.
    fn rewind(&mut self, tail: u64) {
        #[cfg(test)]
        if std::mem::replace(&mut self.faults.rewind, false) {
            self.poisoned = true;
            return;
        }
        let cut = self.file.set_len(tail);
        let synced = cut.is_ok() && {
            let ok = self.file.sync_all().is_ok();
            self.sync_failed |= !ok;
            ok
        };
        let placed = synced && self.file.seek(SeekFrom::Start(tail)).is_ok();
        if synced {
            self.synced_len = tail;
        }
        // Poison on a rewind that failed OR that left the file shorter than the tail it
        // was meant to restore: both mean the on-disk extent is no longer known good,
        // and a successful truncation to the wrong length is the more dangerous of the
        // two because it looks like a clean recovery.
        let shorter_than_tail = match self.file.metadata() {
            Ok(m) => m.len() < tail,
            Err(_) => true,
        };
        self.poisoned = !placed || shorter_than_tail;
    }

    fn write_frame(&mut self, marker: u64, payload_len: u32, payload: &[u8]) -> Result<u64> {
        if self.poisoned {
            return Err(poisoned_error());
        }
        let seq = self.next_seq;
        let mut frame = std::mem::take(&mut self.frame);
        frame.clear();
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.extend_from_slice(&marker.to_be_bytes());
        frame.extend_from_slice(&payload_len.to_be_bytes());
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&frame);
        hasher.update(payload);
        frame.extend_from_slice(&hasher.finalize().to_be_bytes());
        frame.extend_from_slice(payload);

        // A partial write leaves a frame replay stops at, silently dropping every later
        // entry. Rewind to the last whole frame: the tracked length, never the fd offset,
        // because O_APPEND leaves the offset at 0 until the first write after a reopen.
        let tail = self.len;
        #[cfg(test)]
        let written = if std::mem::replace(&mut self.faults.frame_write, false) {
            Err(std::io::Error::other("injected frame-write failure"))
        } else {
            self.file.write_all(&frame)
        };
        #[cfg(not(test))]
        let written = self.file.write_all(&frame);
        let frame_len = frame.len() as u64;
        if frame.capacity() <= RETAINED_FRAME_BUFFER_BYTES {
            self.frame = frame;
        }
        if let Err(e) = written {
            self.rewind(tail);
            return Err(e.into());
        }

        self.len = tail.saturating_add(frame_len);
        self.next_seq = self.next_seq.saturating_add(1);
        self.first_seq.get_or_insert(seq);
        self.last_marker = marker;
        Ok(seq)
    }
}

/// Bincode `payload` under the size ceiling. Serializing here, outside the lock,
/// keeps the critical section to the write itself.
fn encode_payload<P: Serialize>(payload: &P) -> Result<(Vec<u8>, u32)> {
    let bytes = bincode::serialize(payload)?;
    if bytes.len() > WAL_MAX_PAYLOAD_BYTES {
        return Err(PersistenceError::Invariant(format!(
            "WAL payload {} bytes exceeds max {}",
            bytes.len(),
            WAL_MAX_PAYLOAD_BYTES
        )));
    }
    let payload_len = u32::try_from(bytes.len()).map_err(|_| {
        PersistenceError::Invariant(format!("WAL payload size {} overflows u32", bytes.len()))
    })?;
    Ok((bytes, payload_len))
}

impl Wal {
    /// Open or create `data_dir/wal/current.log`. `last_committed_seq` sets a
    /// resume floor; the on-disk tail wins when it is higher.
    ///
    /// A floor above a non-empty tail is refused, never repaired. Callers derive
    /// the floor from `manifest.json`, so the manifest cannot corroborate it, and
    /// nothing else on disk can: the divergence is between the manifest and the
    /// log, and only an operator knows which of the two is the good copy.
    /// Refusals are counted by [`resume_floor_refusals`].
    ///
    /// # Errors
    /// [`PersistenceError::Invariant`] when the floor sits above a non-empty
    /// tail, plus any I/O failure while scanning or truncating.
    pub fn open(layout: &StoreLayout, last_committed_seq: Option<u64>) -> Result<Self> {
        let path = layout.wal_current_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = open_wal_owner_only(&path)?;

        let scan = scan_for_tail(&path)?;

        let floor = match last_committed_seq {
            Some(s) => s.saturating_add(1),
            None => 0,
        };
        let mut next_seq = scan.next_seq;
        if floor > next_seq {
            if let Some(first) = scan.first_seq {
                let last = next_seq.saturating_sub(1);
                RESUME_FLOOR_REFUSALS.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    resume_floor = floor,
                    tail_first_seq = first,
                    tail_last_seq = last,
                    data_dir = %layout.root().display(),
                    "wal open refused: resume floor above the log tail"
                );
                return Err(PersistenceError::Invariant(format!(
                    "wal open refused: resume floor {floor} is above the tail of \
                     wal/current.log, which holds seqs {first}..={last}. Appending at {floor} \
                     would leave a seq gap that replay reads as a torn tail, dropping every \
                     entry written after it. Operator: restore manifest.json and wal/ from the \
                     same point in time, OR point manifest.json at a snapshot whose \
                     current_snapshot_seq is at most {next_seq}. Path: {}",
                    layout.root().display()
                )));
            }
            next_seq = floor;
        }

        if let Some(truncate_at) = scan.truncate_at {
            // some filesystems disallow concurrent write handles
            drop(file);
            let f = OpenOptions::new().write(true).open(&path)?;
            f.set_len(truncate_at)?;
            f.sync_all()?;
        }

        let file = open_wal_owner_only(&path)?;
        let len = rewind_target(&file)?;
        // An earlier process may have left written but unsynced frames, so only a
        // log this open just synced, or an empty one, starts clean.
        let synced_len = if scan.truncate_at.is_some() { len } else { 0 };

        Ok(Self {
            layout: layout.clone(),
            inner: Mutex::new(WalState {
                file,
                next_seq,
                first_seq: scan.first_seq,
                last_marker: scan.last_marker,
                len,
                synced_len,
                poisoned: false,
                sync_failed: false,
                frame: Vec::new(),
                #[cfg(test)]
                faults: WalFaults::default(),
            }),
        })
    }

    /// Assigns the next seq, writes the frame, syncs it and every deferred frame
    /// before it, and returns that seq: the frame is durable on return. The bound
    /// is `Serialize` alone because the WAL never decodes what it stores.
    ///
    /// # Errors
    /// A payload over [`WAL_MAX_PAYLOAD_BYTES`], a poisoned WAL, or an I/O
    /// failure. A failed sync poisons the WAL, and the frame may still replay.
    pub fn append<P: Serialize>(&self, payload: &P, marker: u64) -> Result<u64> {
        let (bytes, payload_len) = encode_payload(payload)?;
        let mut state = self.inner.lock();
        let seq = state.write_frame(marker, payload_len, &bytes)?;
        state.sync()?;
        Ok(seq)
    }

    /// [`Wal::append`] without the sync. The frame is handed to the kernel before
    /// this returns, so a process kill loses nothing; a power loss can lose it and
    /// every frame after it until [`Wal::sync`] succeeds. Replay keeps the longest
    /// valid prefix, so a loss is always a suffix, never a gap.
    ///
    /// # Errors
    /// As [`Wal::append`], less the sync.
    pub fn append_deferred<P: Serialize>(&self, payload: &P, marker: u64) -> Result<u64> {
        let (bytes, payload_len) = encode_payload(payload)?;
        self.inner.lock().write_frame(marker, payload_len, &bytes)
    }

    /// Make every frame written so far durable. A no-op when nothing is pending.
    ///
    /// # Errors
    /// A poisoned WAL, or the fdatasync failure, which poisons it: the sync is
    /// never retried, since a retry can report success over dropped pages.
    pub fn sync(&self) -> Result<()> {
        self.inner.lock().sync()
    }

    /// Byte length of `current.log` known durable.
    pub fn synced_len(&self) -> u64 {
        self.inner.lock().synced_len
    }

    /// All entries from the start of the file, in seq order.
    pub fn replay(&self) -> Result<WalReplay> {
        let path = self.layout.wal_current_path();
        let scan = scan_full(&path)?;
        Ok(scan)
    }

    /// Next seq the next `append` will assign.
    pub fn next_seq(&self) -> u64 {
        self.inner.lock().next_seq
    }

    /// Sync ahead of a seal and return `(next_seq, first_seq)` from the same lock
    /// hold, so no deferred frame can land between the sync and the floor read.
    /// Refuses only a failed sync, as [`Wal::archive`] does: a torn-append poison
    /// is recovered by the seal that follows.
    pub(crate) fn sync_for_seal(&self) -> Result<(u64, Option<u64>)> {
        let mut state = self.inner.lock();
        state.refuse_seal_after_failed_sync(&self.layout)?;
        state.flush()?;
        Ok((state.next_seq, state.first_seq))
    }

    /// Marker of the most recently appended entry.
    pub fn last_marker(&self) -> u64 {
        self.inner.lock().last_marker
    }

    /// Seal `current.log` under `wal/archived/` and start a fresh one. Both
    /// parent dirs are fsynced, so the rename is durable before this returns.
    ///
    /// The target path is named from `from_seq..=to_seq` alone, so an occupied
    /// path is refused: renaming onto it would destroy an already-sealed range
    /// with no trace.
    ///
    /// Occupancy is decided by `symlink_metadata`, which does not follow links.
    /// `Path::exists()` does follow them, so a DANGLING symlink in the archive slot
    /// read as free; the rename then had a second way to do nothing at all, because
    /// `rename(2)` is a documented no-op when both operands resolve to one inode.
    /// Any entry at the path is a collision, whatever it points at.
    ///
    /// # Errors
    /// [`PersistenceError::Invariant`] when `wal/archived/` already holds that
    /// range or an earlier sync failed, plus any I/O failure while syncing,
    /// renaming, or reopening.
    pub fn archive(&self, from_seq: u64, to_seq: u64) -> Result<()> {
        let mut state = self.inner.lock();
        state.refuse_seal_after_failed_sync(&self.layout)?;
        let target = self.layout.wal_archived_path(from_seq, to_seq);
        if std::fs::symlink_metadata(&target).is_ok() {
            return Err(PersistenceError::Invariant(format!(
                "wal archive refused: seqs {from_seq}..={to_seq} are already sealed at {}, and \
                 sealing them again would rename over that file. Operator: the log and \
                 wal/archived/ disagree about which seqs are sealed, which a restore from \
                 mismatched backups produces; reconcile them before publishing again. Path: {}",
                target.display(),
                self.layout.root().display()
            )));
        }
        // After the collision guard, so a refused seal leaves the log exactly as it
        // was; the publish helper's power-loss test relies on that order.
        state.flush()?;
        let archive_parent = match target.parent() {
            Some(p) => {
                std::fs::create_dir_all(p)?;
                p.to_path_buf()
            }
            None => {
                return Err(PersistenceError::Invariant(
                    "archive path has no parent".to_owned(),
                ))
            }
        };
        let current = self.layout.wal_current_path();
        std::fs::rename(&current, &target)?;
        // Past the rename the log has moved on disk while `state.file` still holds the
        // sealed inode. An early return here would leave appends writing and syncing
        // into a file `replay()` never opens - it resolves `current.log` by path - so
        // every acknowledged entry after it would be silently unreplayable.
        // Poison instead: a refused write beats an acknowledged one that is lost.
        #[cfg(test)]
        let reopened = if std::mem::replace(&mut state.faults.archive_reopen, false) {
            Err(PersistenceError::Io(std::io::Error::other(
                "injected post-archive reopen failure",
            )))
        } else {
            reopen_current_after_archive(&current, &archive_parent)
        };
        #[cfg(not(test))]
        let reopened = reopen_current_after_archive(&current, &archive_parent);
        match reopened {
            Ok(new_file) => {
                state.file = new_file;
                state.first_seq = None;
                state.len = 0;
                state.synced_len = 0;
                // a fresh file has no torn tail to be poisoned by
                state.poisoned = false;
                Ok(())
            }
            Err(e) => {
                state.poisoned = true;
                Err(e)
            }
        }
    }
}

/// Result of a full WAL replay.
#[derive(Debug)]
pub struct WalReplay {
    /// Valid entries, in seq order.
    pub entries: Vec<WalEntry>,
    /// Byte offset of a torn tail, if any.
    pub truncated_at: Option<u64>,
    /// Last valid seq + 1, or 0.
    pub next_seq: u64,
    /// Marker of the last valid entry, or 0.
    pub last_marker: u64,
}

#[derive(Debug)]
struct ScanResult {
    next_seq: u64,
    first_seq: Option<u64>,
    last_marker: u64,
    truncate_at: Option<u64>,
}

/// Reopen `current.log` after `archive` renamed it away, making both the removal and
/// the creation durable.
///
/// Every step runs with the log already moved, so the caller MUST poison on `Err`:
/// returning while `state.file` still points at the sealed inode turns later appends
/// into acknowledged, unreplayable writes.
fn reopen_current_after_archive(
    current: &std::path::Path,
    archive_parent: &std::path::Path,
) -> Result<File> {
    if let Some(source_parent) = current.parent() {
        crate::fsync_parent_dir(source_parent)?;
    }
    crate::fsync_parent_dir(archive_parent)?;
    let new_file = open_wal_owner_only(current)?;
    new_file.sync_all()?;
    // second pass makes the new current.log's creation durable
    if let Some(source_parent) = current.parent() {
        crate::fsync_parent_dir(source_parent)?;
    }
    Ok(new_file)
}

/// Byte length the log must be restored to if a frame write fails.
///
/// Not the fd offset: `O_APPEND` leaves it at 0 until the first write repositions it,
/// so the offset reads 0 on the first append after any reopen of a non-empty log.
fn rewind_target(file: &File) -> Result<u64> {
    Ok(file.metadata()?.len())
}

/// Mode 0o600 on Unix; default elsewhere.
fn open_wal_owner_only(path: &std::path::Path) -> Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        Ok(OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .mode(0o600)
            .open(path)?)
    }
    #[cfg(not(unix))]
    {
        Ok(OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)?)
    }
}

fn scan_for_tail(path: &std::path::Path) -> Result<ScanResult> {
    let scan = scan_full(path)?;
    Ok(ScanResult {
        next_seq: scan.next_seq,
        first_seq: scan.entries.first().map(|e| e.seq),
        last_marker: scan.last_marker,
        truncate_at: scan.truncated_at,
    })
}

#[allow(clippy::too_many_lines)] // single linear frame scanner; splitting hurts readability
fn scan_full(path: &std::path::Path) -> Result<WalReplay> {
    // Only NotFound is an empty log. `Path::exists()` is false for a permission failure or an
    // unresolvable link too, and treating those as empty drops every entry the log holds at
    // `Ok`. Discriminate on the error kind and fail closed.
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(WalReplay {
                entries: Vec::new(),
                truncated_at: None,
                next_seq: 0,
                last_marker: 0,
            })
        }
        Err(e) => return Err(e.into()),
    };
    let total = file.metadata()?.len();
    let mut entries = Vec::new();
    let mut next_seq: u64 = 0;
    let mut last_block: u64 = 0;
    let mut offset: u64 = 0;

    loop {
        if offset == total {
            break;
        }
        if total - offset < 24 {
            return Ok(WalReplay {
                entries,
                truncated_at: Some(offset),
                next_seq,
                last_marker: last_block,
            });
        }
        file.seek(SeekFrom::Start(offset))?;
        let mut header = [0u8; 24];
        file.read_exact(&mut header)?;

        let mut s = [0u8; 8];
        s.copy_from_slice(header.get(0..8).unwrap_or(&[0u8; 8]));
        let seq = u64::from_be_bytes(s);
        let mut h = [0u8; 8];
        h.copy_from_slice(header.get(8..16).unwrap_or(&[0u8; 8]));
        let marker = u64::from_be_bytes(h);
        let mut l = [0u8; 4];
        l.copy_from_slice(header.get(16..20).unwrap_or(&[0u8; 4]));
        let payload_len = u64::from(u32::from_be_bytes(l));
        let mut c = [0u8; 4];
        c.copy_from_slice(header.get(20..24).unwrap_or(&[0u8; 4]));
        let crc_expected = u32::from_be_bytes(c);

        if payload_len > WAL_MAX_PAYLOAD_BYTES as u64 || payload_len > usize::MAX as u64 {
            return Ok(WalReplay {
                entries,
                truncated_at: Some(offset),
                next_seq,
                last_marker: last_block,
            });
        }
        if total < offset + 24 + payload_len {
            return Ok(WalReplay {
                entries,
                truncated_at: Some(offset),
                next_seq,
                last_marker: last_block,
            });
        }
        let payload_len_usize = usize::try_from(payload_len).map_err(|_| {
            PersistenceError::Invariant(format!("payload_len {payload_len} overflows usize"))
        })?;
        let mut payload = vec![0u8; payload_len_usize];
        file.read_exact(&mut payload)?;

        let mut hasher = crc32fast::Hasher::new();
        hasher.update(header.get(0..20).unwrap_or(&[0u8; 20]));
        hasher.update(&payload);
        let crc_actual = hasher.finalize();

        if crc_actual != crc_expected {
            return Ok(WalReplay {
                entries,
                truncated_at: Some(offset),
                next_seq,
                last_marker: last_block,
            });
        }

        // CRC checks integrity, not order: a non-monotonic seq is a torn tail
        let expected_seq = if entries.is_empty() {
            None
        } else {
            Some(next_seq)
        };
        if let Some(exp) = expected_seq {
            if seq != exp {
                return Ok(WalReplay {
                    entries,
                    truncated_at: Some(offset),
                    next_seq,
                    last_marker: last_block,
                });
            }
        }

        entries.push(WalEntry {
            seq,
            marker,
            payload,
        });
        next_seq = seq.saturating_add(1);
        last_block = marker;
        offset += 24 + payload_len;
    }

    Ok(WalReplay {
        entries,
        truncated_at: None,
        next_seq,
        last_marker: last_block,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    fn make_layout() -> (tempfile::TempDir, StoreLayout) {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        (dir, layout)
    }

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct TestPayload {
        tag: u32,
        index: u32,
        blob: [u8; 32],
    }

    fn test_payload(idx: u32) -> TestPayload {
        TestPayload {
            tag: 3,
            index: idx,
            blob: [(idx & 0xff) as u8; 32],
        }
    }

    #[test]
    fn append_then_replay_round_trips() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, None).expect("open");
        for i in 0..10u32 {
            wal.append(&test_payload(i), 100 + u64::from(i))
                .expect("append");
        }
        let replay = wal.replay().expect("replay");
        assert_eq!(replay.entries.len(), 10);
        assert_eq!(replay.truncated_at, None);
        assert_eq!(replay.next_seq, 10);
        assert_eq!(replay.last_marker, 109);
        for (i, entry) in replay.entries.iter().enumerate() {
            let parsed: TestPayload = bincode::deserialize(&entry.payload).expect("deser");
            let i_u32 = u32::try_from(i).expect("test index fits in u32");
            assert_eq!(parsed, test_payload(i_u32));
            assert_eq!(entry.seq, i as u64);
        }
    }

    #[test]
    fn reopen_resumes_seq() {
        let (_d, layout) = make_layout();
        {
            let wal = Wal::open(&layout, None).expect("open");
            for i in 0..5u32 {
                wal.append(&test_payload(i), 100 + u64::from(i))
                    .expect("append");
            }
        }
        let wal2 = Wal::open(&layout, None).expect("reopen");
        assert_eq!(wal2.next_seq(), 5);
        wal2.append(&test_payload(99), 200).expect("append");
        let replay = wal2.replay().expect("replay");
        assert_eq!(replay.entries.len(), 6);
        assert_eq!(replay.next_seq, 6);
    }

    #[test]
    fn torn_tail_truncates_on_replay() {
        let (_d, layout) = make_layout();
        {
            let wal = Wal::open(&layout, None).expect("open");
            for i in 0..3u32 {
                wal.append(&test_payload(i), 100 + u64::from(i))
                    .expect("append");
            }
        }
        {
            use std::io::Write;
            let mut f = OpenOptions::new()
                .append(true)
                .open(layout.wal_current_path())
                .expect("open append");
            f.write_all(&[0xFF; 50]).expect("write garbage");
            f.sync_all().expect("sync");
        }
        let wal2 = Wal::open(&layout, None).expect("reopen with torn tail");
        let replay = wal2.replay().expect("replay");
        assert_eq!(replay.entries.len(), 3);
        assert_eq!(replay.next_seq, 3);
    }

    #[test]
    fn flipped_crc_byte_truncates() {
        let (_d, layout) = make_layout();
        {
            let wal = Wal::open(&layout, None).expect("open");
            for i in 0..3u32 {
                wal.append(&test_payload(i), 100 + u64::from(i))
                    .expect("append");
            }
        }
        let path = layout.wal_current_path();
        let mut bytes = std::fs::read(&path).expect("read");
        let last_idx = bytes.len() - 1;
        if let Some(b) = bytes.get_mut(last_idx) {
            *b ^= 0xFF;
        }
        std::fs::write(&path, &bytes).expect("write");
        let wal2 = Wal::open(&layout, None).expect("reopen");
        let replay = wal2.replay().expect("replay");
        assert_eq!(replay.entries.len(), 2);
        assert_eq!(replay.next_seq, 2);
    }

    #[test]
    fn archive_seals_current_and_starts_fresh() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, None).expect("open");
        for i in 0..3u32 {
            wal.append(&test_payload(i), 100 + u64::from(i))
                .expect("append");
        }
        wal.archive(0, 2).expect("archive");
        assert!(layout.wal_archived_path(0, 2).is_file());
        let replay = wal.replay().expect("replay");
        assert_eq!(replay.entries.len(), 0);
        wal.append(&test_payload(99), 200).expect("append");
        let replay = wal.replay().expect("replay");
        assert_eq!(replay.entries.len(), 1);
        assert_eq!(replay.entries.first().expect("present").seq, 3);
    }

    /// The range arguments only name the archive file; the whole `current.log`
    /// is sealed. A caller assuming partial semantics would lose the tail.
    #[test]
    fn archive_seals_the_whole_log_regardless_of_the_range_arguments() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, None).expect("open");
        for i in 0..5u32 {
            wal.append(&test_payload(i), 100 + u64::from(i))
                .expect("append");
        }
        wal.archive(0, 1).expect("archive");
        assert!(layout.wal_archived_path(0, 1).is_file());
        let replay = wal.replay().expect("replay");
        assert!(
            replay.entries.is_empty(),
            "seqs 2..=4 are outside the named range yet were sealed too; if they \
             now survive, archive honours its range and callers may rely on it"
        );
        wal.append(&test_payload(99), 200).expect("append");
        let replay = wal.replay().expect("replay");
        assert_eq!(
            replay.entries.first().expect("present").seq,
            5,
            "seq allocation continues across an archive"
        );
    }

    #[test]
    fn non_monotonic_seq_is_treated_as_torn_tail() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, None).expect("open");
        for i in 0..3u32 {
            wal.append(&test_payload(i), 100 + u64::from(i))
                .expect("append");
        }
        drop(wal);

        let payload_bin = bincode::serialize(&test_payload(99)).expect("ser");
        let payload_len: u32 = payload_bin.len().try_into().expect("len");
        let mut header = [0u8; 24];
        header[0..8].copy_from_slice(&99u64.to_be_bytes()); // next valid seq is 3
        header[8..16].copy_from_slice(&200u64.to_be_bytes());
        header[16..20].copy_from_slice(&payload_len.to_be_bytes());
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&header[0..20]);
        hasher.update(&payload_bin);
        let crc = hasher.finalize();
        header[20..24].copy_from_slice(&crc.to_be_bytes());

        {
            use std::io::Write;
            let mut f = OpenOptions::new()
                .append(true)
                .open(layout.wal_current_path())
                .expect("open append");
            f.write_all(&header).expect("write hdr");
            f.write_all(&payload_bin).expect("write payload");
            f.sync_all().expect("sync");
        }

        let wal2 = Wal::open(&layout, None).expect("reopen");
        let replay = wal2.replay().expect("replay");
        assert_eq!(
            replay.entries.len(),
            3,
            "non-monotonic seq=99 frame must NOT be accepted"
        );
        assert_eq!(replay.next_seq, 3);
    }

    fn publish_manifest_at(layout: &StoreLayout, replay_floor: u64) {
        crate::Manifest {
            schema_version: crate::MANIFEST_SCHEMA_VERSION,
            scheme_tag: "test-scheme".to_owned(),
            instance_id: "test-instance".to_owned(),
            current_snapshot_id: crate::SnapshotId(1),
            current_snapshot_seq: replay_floor,
            current_marker: 0,
            encoder_label: "test-encoder".to_owned(),
            prev_encoder_label: None,
            entry_size_bytes: Some(32),
            rows_per_shard: Some(2048),
        }
        .save(layout)
        .expect("manifest save");
    }

    /// An empty log has no frame a floor can skip, so resuming at the floor
    /// loses nothing; this is the normal boot after an archive.
    #[test]
    fn fresh_open_with_min_seq_floor_resumes_at_floor() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, Some(99)).expect("open");
        let seq = wal.append(&test_payload(0), 100).expect("append");
        assert_eq!(seq, 100);
    }

    /// Callers derive the floor from `manifest.json`, so a manifest that reaches
    /// the floor is restating the floor, not vouching for it. It must not buy
    /// permission to append past the tail.
    #[test]
    fn a_floor_above_the_tail_is_refused_when_the_manifest_reaches_it() {
        let (_d, layout) = make_layout();
        {
            let wal = Wal::open(&layout, None).expect("open");
            for i in 0..3u32 {
                wal.append(&test_payload(i), 100 + u64::from(i))
                    .expect("append");
            }
        }
        publish_manifest_at(&layout, 10);

        let err = Wal::open(&layout, Some(9))
            .expect_err("a manifest at the floor must not license the floor");
        assert!(matches!(err, PersistenceError::Invariant(_)), "got {err:?}");
        assert!(
            std::fs::read_dir(layout.root().join("wal").join("archived"))
                .expect("read archive dir")
                .next()
                .is_none(),
            "a refused open must seal nothing"
        );
        let reopened = Wal::open(&layout, Some(2)).expect("reopen at the tail");
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

    /// The refusal names the floor, the tail it would skip, and the way out.
    #[test]
    fn a_floor_above_the_tail_is_refused_when_the_manifest_falls_short() {
        let (_d, layout) = make_layout();
        {
            let wal = Wal::open(&layout, None).expect("open");
            for i in 0..3u32 {
                wal.append(&test_payload(i), 100 + u64::from(i))
                    .expect("append");
            }
        }
        publish_manifest_at(&layout, 5);

        let err = Wal::open(&layout, Some(9)).expect_err("floor 10 above tail 3 must be refused");
        let PersistenceError::Invariant(msg) = &err else {
            panic!("expected Invariant, got {err:?}");
        };
        assert!(
            msg.contains("resume floor 10"),
            "the error must name the refused floor; got `{msg}`"
        );
        assert!(
            msg.contains("seqs 0..=2"),
            "the error must name the tail it would skip; got `{msg}`"
        );
        assert!(
            msg.contains("at most 3"),
            "the error must name the highest floor the log admits; got `{msg}`"
        );
        assert!(
            msg.contains("Operator:"),
            "the error must carry a runbook line; got `{msg}`"
        );

        assert!(
            std::fs::read_dir(layout.root().join("wal").join("archived"))
                .expect("read archive dir")
                .next()
                .is_none(),
            "a refused open must seal nothing"
        );
        let reopened = Wal::open(&layout, Some(2)).expect("reopen at the tail");
        assert_eq!(
            reopened.replay().expect("replay").entries.len(),
            3,
            "a refused open must leave the log untouched"
        );
    }

    /// No manifest means nothing vouches for the floor, so the survivors cannot
    /// be shown to be inside any snapshot and the open is refused.
    #[test]
    fn a_resume_floor_above_a_non_empty_tail_is_refused() {
        let (_d, layout) = make_layout();
        {
            let wal = Wal::open(&layout, None).expect("open");
            for i in 0..3u32 {
                wal.append(&test_payload(i), 100 + u64::from(i))
                    .expect("append");
            }
        }
        assert!(
            crate::Manifest::load(&layout).expect("load").is_none(),
            "this fixture must publish no snapshot"
        );

        let err = Wal::open(&layout, Some(9)).expect_err("a floor above the tail must be refused");
        assert!(matches!(err, PersistenceError::Invariant(_)), "got {err:?}");

        let reopened = Wal::open(&layout, Some(2)).expect("reopen at the real floor");
        assert_eq!(
            reopened.replay().expect("replay").entries.len(),
            3,
            "a refused open must leave the log untouched"
        );
    }

    /// The post-rename reopen must report failure rather than half-succeeding, because
    /// its caller poisons on `Err` and would otherwise keep the sealed inode live.
    #[test]
    fn reopen_after_archive_errors_when_current_cannot_be_recreated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("no-such-dir");
        let current = missing.join("current.log");
        let err = reopen_current_after_archive(&current, dir.path())
            .expect_err("a current.log under a missing parent cannot be recreated");
        assert!(
            matches!(err, PersistenceError::Io(_)),
            "expected an I/O failure, got: {err}"
        );
    }

    /// The collision guard fires BEFORE the rename, so the log has not moved and the
    /// WAL must stay usable. Poisoning here would turn a safe refusal into an outage.
    #[test]
    fn an_archive_refused_before_the_rename_leaves_the_log_appendable() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, None).expect("open");
        wal.append(&test_payload(0), 1).expect("first");
        wal.append(&test_payload(1), 2).expect("second");
        wal.archive(0, 1).expect("first archive seals 0..=1");

        wal.append(&test_payload(2), 3)
            .expect("append after archive");
        let err = wal
            .archive(0, 1)
            .expect_err("re-sealing an existing range must be refused");
        assert!(
            format!("{err}").contains("already sealed"),
            "expected the no-clobber refusal, got: {err}"
        );

        let seq = wal
            .append(&test_payload(3), 4)
            .expect("a pre-rename refusal must not poison the log");
        let replay = wal.replay().expect("replay");
        assert_eq!(
            replay.entries.len(),
            2,
            "current.log holds only what was written after the successful archive"
        );
        assert_eq!(replay.entries.last().expect("two entries").seq, seq);
    }

    /// The same tear on the FIRST append after a REOPEN, which is the D-0 defect exactly.
    ///
    /// `O_APPEND` leaves the fd offset at 0 until the kernel repositions it on the first write, so
    /// on a reopened non-empty log the offset reads 0 while the length is the whole log. A rewind
    /// to the offset truncates everything, SUCCEEDS, and therefore does not poison - the log then
    /// replays as clean and empty. Nothing exercised that through `append` before this: the
    /// standalone test proves only the filesystem fact.
    #[test]
    fn a_tear_on_the_first_append_after_a_reopen_does_not_truncate_the_log() {
        let (_d, layout) = make_layout();
        {
            let wal = Wal::open(&layout, None).expect("open");
            wal.append(&test_payload(0), 1).expect("first");
            wal.append(&test_payload(1), 2).expect("second");
        }
        let len_before = std::fs::metadata(layout.wal_current_path())
            .expect("metadata")
            .len();
        assert!(len_before > 0, "precondition: the log is non-empty on disk");

        let reopened = Wal::open(&layout, None).expect("reopen");
        reopened.inner.lock().faults.frame_write = true;
        reopened
            .append(&test_payload(2), 3)
            .expect_err("the injected failure must surface");

        assert_eq!(
            std::fs::metadata(layout.wal_current_path())
                .expect("metadata")
                .len(),
            len_before,
            "rewinding to the fd offset would set_len(0) here and destroy both committed frames"
        );
        assert_eq!(
            reopened.replay().expect("replay").entries.len(),
            2,
            "both frames written before the reopen must still replay"
        );
        assert!(
            !reopened.inner.lock().poisoned,
            "the rewind restored the log, so this tear is recoverable"
        );
    }

    /// A torn frame write REWINDS to the log's byte length and does NOT poison.
    ///
    /// This is the D-0 defect's actual subject, reached through the production `append` for the
    /// first time. The old standalone rewind test proved only the filesystem fact that `O_APPEND`
    /// reports offset 0 after a reopen — never that `append` rewinds to the right place — and was
    /// deleted once mutation testing showed it vacuous. Here the write
    /// fails, the log must come back to exactly its previous length, the earlier entry must still
    /// replay, and the seq must not be burned.
    ///
    /// It must also NOT poison: a recoverable tear that refuses every later append is an outage.
    #[test]
    fn a_torn_frame_write_rewinds_to_the_log_length_and_does_not_poison() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, None).expect("open");
        let first = wal.append(&test_payload(0), 1).expect("first");
        let len_before = std::fs::metadata(layout.wal_current_path())
            .expect("metadata")
            .len();

        wal.inner.lock().faults.frame_write = true;
        let err = wal
            .append(&test_payload(1), 2)
            .expect_err("the injected failure must surface");
        assert!(
            matches!(err, PersistenceError::Io(_)),
            "expected the write error to propagate, got: {err}"
        );

        assert!(
            !wal.inner.lock().poisoned,
            "a tear whose rewind restored the log is recoverable; poisoning it is an outage"
        );
        assert_eq!(
            std::fs::metadata(layout.wal_current_path())
                .expect("metadata")
                .len(),
            len_before,
            "the rewind target is the log LENGTH; anything else truncates committed frames"
        );
        assert_eq!(wal.next_seq(), first + 1, "a refused append burns no seq");

        let replay = wal.replay().expect("replay");
        assert_eq!(
            replay.entries.len(),
            1,
            "the entry written before the tear must survive it"
        );
        assert_eq!(replay.entries.first().expect("one entry").seq, first);

        let second = wal
            .append(&test_payload(1), 2)
            .expect("the log stays appendable after a recoverable tear");
        assert_eq!(second, first + 1, "the burned-nothing seq is reused");
    }

    #[test]
    fn rewind_failure_poison_prevents_unreplayable_followup() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, None).expect("open");
        wal.append(&test_payload(0), 1).expect("first");
        let next_seq = wal.next_seq();
        let len_before = std::fs::metadata(layout.wal_current_path())
            .expect("metadata")
            .len();

        {
            let mut state = wal.inner.lock();
            state.faults.frame_write = true;
            state.faults.rewind = true;
        }
        let err = wal
            .append(&test_payload(1), 2)
            .expect_err("the injected frame-write failure must surface");
        assert!(matches!(err, PersistenceError::Io(_)), "got {err:?}");
        assert!(
            wal.inner.lock().poisoned,
            "a failed rewind leaves the on-disk extent unknown"
        );

        let refused = wal
            .append(&test_payload(2), 3)
            .expect_err("poison must refuse a followup append");
        assert!(format!("{refused}").contains("poisoned"), "got {refused}");
        assert_eq!(wal.next_seq(), next_seq, "both failed appends burn no seq");
        assert_eq!(
            std::fs::metadata(layout.wal_current_path())
                .expect("metadata")
                .len(),
            len_before,
            "a refused followup must not advance the log"
        );
    }

    #[test]
    fn post_archive_reopen_failure_poison_prevents_sealed_inode_append() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, None).expect("open");
        wal.append(&test_payload(0), 1).expect("first");
        let next_seq = wal.next_seq();
        let current = layout.wal_current_path();
        let archived = layout.wal_archived_path(0, 0);
        let sealed_bytes = std::fs::read(&current).expect("read current");

        wal.inner.lock().faults.archive_reopen = true;
        let err = wal
            .archive(0, 0)
            .expect_err("the injected post-rename reopen failure must surface");
        assert!(matches!(err, PersistenceError::Io(_)), "got {err:?}");
        assert!(
            wal.inner.lock().poisoned,
            "a failed post-rename reopen leaves the handle on the sealed inode"
        );

        let refused = wal
            .append(&test_payload(1), 2)
            .expect_err("poison must refuse writes through the sealed inode");
        assert!(format!("{refused}").contains("poisoned"), "got {refused}");
        assert_eq!(wal.next_seq(), next_seq, "the refused append burns no seq");
        assert!(
            !current.exists(),
            "the injected reopen did not create a misleading current.log"
        );
        assert_eq!(
            std::fs::read(&archived).expect("read archive"),
            sealed_bytes,
            "the refused append must not advance the sealed inode"
        );
    }

    /// Poison means the on-disk extent is no longer known good, so a further append would land
    /// past a hole `replay` stops at and every entry after it would be fsync-acknowledged and
    /// unreplayable.
    ///
    /// Direct injection isolates this honour guard from the fault-point tests above.
    #[test]
    fn a_poisoned_wal_refuses_every_append_until_it_is_reopened() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, None).expect("open");
        let first = wal.append(&test_payload(0), 1).expect("first");

        wal.inner.lock().poisoned = true;

        let err = wal
            .append(&test_payload(1), 2)
            .expect_err("a poisoned WAL must refuse every append");
        assert!(
            format!("{err}").contains("poisoned"),
            "the refusal must name the poison so an operator can act on it, got: {err}"
        );
        assert_eq!(
            wal.next_seq(),
            first + 1,
            "a refused append burns no seq: the next successful one reuses it"
        );
        assert_eq!(
            wal.replay().expect("replay").entries.len(),
            1,
            "and writes nothing"
        );
    }

    /// Reopening is the documented recovery, and a fresh `Wal` must start clean or the
    /// refusal above becomes permanent.
    #[test]
    fn reopening_clears_the_poison_and_restores_appends() {
        let (_d, layout) = make_layout();
        {
            let wal = Wal::open(&layout, None).expect("open");
            wal.append(&test_payload(0), 1).expect("first");
            wal.inner.lock().poisoned = true;
            wal.append(&test_payload(1), 2)
                .expect_err("refused while poisoned");
        }
        let reopened = Wal::open(&layout, None).expect("reopen");
        assert!(
            !reopened.inner.lock().poisoned,
            "a fresh Wal starts unpoisoned; that is the whole recovery route"
        );
        reopened
            .append(&test_payload(1), 2)
            .expect("appends work again after a reopen");
        assert_eq!(reopened.replay().expect("replay").entries.len(), 2);
    }

    /// A log that is present but UNREADABLE must not replay as an empty one. `Path::exists()`
    /// reports false for an unresolvable link exactly as it does for absence, so the scan
    /// returned `Ok` with zero entries and the durable log was silently dropped.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_log_fails_closed_instead_of_replaying_as_empty() {
        let (_d, layout) = make_layout();
        let path = layout.wal_current_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("wal dir");
        }
        // Self-referential link: unresolvable, so `exists()` is false while `open` reports
        // a loop rather than NotFound.
        std::os::unix::fs::symlink("current.log", &path).expect("symlink");
        assert!(
            !path.exists(),
            "precondition: exists() cannot see this file"
        );

        let err = scan_full(&path).expect_err("an unresolvable log must not scan as empty");
        assert!(
            matches!(err, PersistenceError::Io(_)),
            "expected an I/O failure, got: {err}"
        );
    }

    /// A successful archive CLEARS the flag, which is the only in-process route out of poison -
    /// a reopen is the other, and it is a new process. Production reaches it through
    /// `advance_manifest_and_archive`. Without it a WAL poisoned by a torn append stays
    /// refusing every append after a clean seal.
    #[test]
    fn a_successful_archive_clears_the_poison() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, None).expect("open");
        wal.append(&test_payload(0), 1).expect("first");
        wal.inner.lock().poisoned = true;

        wal.archive(0, 0)
            .expect("archive seals the log and reopens a fresh one");

        assert!(
            !wal.inner.lock().poisoned,
            "a fresh log has no torn tail, so the seal is the recovery"
        );
        wal.append(&test_payload(1), 2)
            .expect("appends must work again once the flag is cleared");
    }

    /// A successful archive leaves a fresh, unpoisoned, appendable log.
    #[test]
    fn a_successful_archive_leaves_the_log_appendable_and_unpoisoned() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, None).expect("open");
        wal.append(&test_payload(0), 1).expect("first");
        wal.archive(0, 0).expect("archive");
        assert!(
            !wal.inner.lock().poisoned,
            "a clean archive must not poison"
        );
        wal.append(&test_payload(1), 2)
            .expect("append after archive");
        assert_eq!(wal.replay().expect("replay").entries.len(), 1);
    }

    /// The rewind target of a reopened non-empty log is its length. `O_APPEND` leaves
    /// the fd offset at 0 until the first write repositions it, so an offset-derived
    /// target truncates the whole log on the first append after any reopen.
    #[test]
    fn rewind_target_reports_file_length_not_fd_offset() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("current.log");
        let seeded = vec![0u8; 3840];
        std::fs::write(&path, &seeded).expect("seed a non-empty log");

        let file = open_wal_owner_only(&path).expect("reopen through the production option set");

        assert_eq!(
            rewind_target(&file).expect("rewind target"),
            u64::try_from(seeded.len()).expect("a 3840-byte seed fits u64"),
            "rewind target must be the file length; an fd-offset target reads 0 here and \
             truncates every committed frame"
        );
    }

    /// A refused append must leave the log appendable, with no bytes that make replay
    /// drop later entries. Does NOT reach the rewind block - see
    /// `rewind_target_reports_file_length_not_fd_offset` for that.
    #[test]
    fn an_append_refused_at_the_size_guard_leaves_the_log_appendable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let wal = Wal::open(&layout, None).expect("open");

        wal.append(&test_payload(0), 1).expect("first append");

        // refused at the size guard, which returns before the mutex, the poison check
        // and the rewind block - a write error takes none of this path
        let oversized = vec![0u8; WAL_MAX_PAYLOAD_BYTES + 1];
        assert!(
            wal.append(&oversized, 2).is_err(),
            "oversized must be refused"
        );

        let seq = wal
            .append(&test_payload(2), 3)
            .expect("append after a refused write");
        let replay = wal.replay().expect("replay");

        assert_eq!(
            replay.entries.len(),
            2,
            "both good entries must survive a refused append; got {:?}",
            replay.entries.iter().map(|e| e.seq).collect::<Vec<_>>()
        );
        let last = replay.entries.last().expect("two entries asserted above");
        assert_eq!(last.seq, seq);
        assert_eq!(replay.truncated_at, None, "no torn tail may remain");
    }

    /// The file offset must not drift when an append is refused, or the next
    /// frame is written into a hole.
    #[test]
    fn a_refused_append_leaves_the_write_offset_where_it_was() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let wal = Wal::open(&layout, None).expect("open");

        wal.append(&test_payload(0), 1).expect("first append");
        let before = std::fs::metadata(layout.wal_current_path())
            .expect("stat")
            .len();

        let oversized = vec![0u8; WAL_MAX_PAYLOAD_BYTES + 1];
        let _ = wal.append(&oversized, 2);

        let after = std::fs::metadata(layout.wal_current_path())
            .expect("stat")
            .len();
        assert_eq!(before, after, "a refused append must not grow the file");
    }

    fn replayed_seqs(wal: &Wal) -> Vec<u64> {
        wal.replay()
            .expect("replay")
            .entries
            .iter()
            .map(|e| e.seq)
            .collect()
    }

    /// A failed sync poisons for good. Linux can drop the failed dirty pages and clear
    /// the error, so a retried fsync reports success over lost data (fsyncgate); the
    /// only honest answer to every later sync, append and seal is a refusal.
    #[test]
    fn a_failed_sync_poisons_and_is_never_retried_as_a_success() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, None).expect("open");
        wal.append(&test_payload(0), 1).expect("synced");
        wal.append_deferred(&test_payload(1), 2).expect("deferred");

        wal.inner.lock().faults.sync = true;
        let err = wal
            .sync()
            .expect_err("the injected sync failure must surface");
        assert!(matches!(err, PersistenceError::Io(_)), "got {err:?}");

        let retried = wal
            .sync()
            .expect_err("a retried sync must be refused, never reported durable");
        assert!(format!("{retried}").contains("poisoned"), "got {retried}");
        let refused = wal
            .append_deferred(&test_payload(2), 3)
            .expect_err("a deferred append after a failed sync must be refused");
        assert!(format!("{refused}").contains("poisoned"), "got {refused}");
        wal.append(&test_payload(2), 3)
            .expect_err("a synced append after a failed sync must be refused");
        let sealed = wal
            .archive(0, 1)
            .expect_err("sealing would retry the failed sync as a success");
        assert!(format!("{sealed}").contains("sync"), "got {sealed}");
        assert_eq!(wal.next_seq(), 2, "refused appends burn no seq");
        drop(wal);

        let reopened = Wal::open(&layout, None).expect("a reopen is the recovery");
        assert_eq!(replayed_seqs(&reopened), vec![0, 1]);
        reopened
            .append(&test_payload(2), 3)
            .expect("appends work again after a reopen");
    }

    /// `append` is `append_deferred` plus `sync`, so a failed sync inside it poisons too.
    #[test]
    fn a_failed_sync_inside_append_poisons() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, None).expect("open");
        wal.inner.lock().faults.sync = true;
        wal.append(&test_payload(0), 1)
            .expect_err("the injected sync failure must surface");
        wal.append(&test_payload(1), 2)
            .expect_err("the log is poisoned after it");
    }

    /// Nothing is pending after a sync, so a second one does no I/O: an armed sync
    /// fault is not consumed by it.
    #[test]
    fn a_sync_with_nothing_pending_is_a_no_op() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, None).expect("open");
        wal.append_deferred(&test_payload(0), 1).expect("deferred");
        wal.sync().expect("sync");
        let len = std::fs::metadata(layout.wal_current_path())
            .expect("metadata")
            .len();
        assert_eq!(wal.synced_len(), len, "a sync covers every written byte");

        wal.inner.lock().faults.sync = true;
        wal.sync()
            .expect("nothing pending, so no fdatasync is issued");
        assert!(
            wal.inner.lock().faults.sync,
            "the fault must still be armed"
        );
    }

    /// A reopened log may hold frames an earlier process wrote but never synced, so
    /// the first sync after `open` must reach the disk rather than trust it clean.
    #[test]
    fn a_reopened_non_empty_log_is_synced_by_the_first_sync() {
        let (_d, layout) = make_layout();
        {
            let wal = Wal::open(&layout, None).expect("open");
            wal.append_deferred(&test_payload(0), 1).expect("deferred");
        }
        let reopened = Wal::open(&layout, None).expect("reopen");
        assert_eq!(reopened.synced_len(), 0, "nothing is known durable yet");
        reopened.inner.lock().faults.sync = true;
        reopened
            .sync()
            .expect_err("the first sync must issue an fdatasync, and so meet the fault");
    }

    /// The rewind target is the tracked length, which `open` sets from the file. A
    /// tracked length left at 0 after a reopen truncates every committed frame.
    #[test]
    fn a_failed_append_after_a_reopen_keeps_every_earlier_frame() {
        let (_d, layout) = make_layout();
        {
            let wal = Wal::open(&layout, None).expect("open");
            wal.append(&test_payload(0), 1).expect("synced");
            wal.append_deferred(&test_payload(1), 2).expect("deferred");
        }
        let reopened = Wal::open(&layout, None).expect("reopen");
        reopened
            .append_deferred(&test_payload(2), 3)
            .expect("deferred after reopen");
        let len_before = std::fs::metadata(layout.wal_current_path())
            .expect("metadata")
            .len();

        reopened.inner.lock().faults.frame_write = true;
        reopened
            .append_deferred(&test_payload(3), 4)
            .expect_err("the injected failure must surface");

        assert_eq!(
            std::fs::metadata(layout.wal_current_path())
                .expect("metadata")
                .len(),
            len_before
        );
        assert_eq!(replayed_seqs(&reopened), vec![0, 1, 2]);
        assert_eq!(
            reopened.synced_len(),
            len_before,
            "the rewind synced the log, so everything below it is durable"
        );
        let seq = reopened
            .append(&test_payload(3), 4)
            .expect("the log stays appendable");
        assert_eq!(replayed_seqs(&reopened), vec![0, 1, 2, seq]);
    }

    /// `open` cuts a torn tail, and the tracked length must follow the cut: a length
    /// read before it makes a later rewind grow the file past the last whole frame.
    #[test]
    fn a_failed_append_after_a_torn_tail_cut_rewinds_to_the_cut() {
        let (_d, layout) = make_layout();
        {
            let wal = Wal::open(&layout, None).expect("open");
            wal.append(&test_payload(0), 1).expect("first");
            wal.append(&test_payload(1), 2).expect("second");
        }
        let whole = std::fs::metadata(layout.wal_current_path())
            .expect("metadata")
            .len();
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(layout.wal_current_path())
                .expect("open append");
            f.write_all(&[0xFF; 50]).expect("write garbage");
        }
        let reopened = Wal::open(&layout, None).expect("reopen cuts the torn tail");
        assert_eq!(reopened.synced_len(), whole, "the cut was synced by open");

        reopened.inner.lock().faults.frame_write = true;
        reopened
            .append(&test_payload(2), 3)
            .expect_err("the injected failure must surface");
        assert_eq!(
            std::fs::metadata(layout.wal_current_path())
                .expect("metadata")
                .len(),
            whole,
            "the rewind target is the length after the cut"
        );
        let seq = reopened.append(&test_payload(2), 3).expect("appendable");
        assert_eq!(replayed_seqs(&reopened), vec![0, 1, seq]);
    }

    /// `archive` starts a fresh file, so the tracked length must restart at 0. The
    /// sealed file's length would make a rewind grow the new log with zeroes that
    /// replay stops at, hiding every frame after them.
    #[test]
    fn a_failed_append_after_an_archive_keeps_every_earlier_frame() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, None).expect("open");
        for i in 0..3u32 {
            wal.append(&test_payload(i), u64::from(i)).expect("append");
        }
        wal.archive(0, 2).expect("archive");
        assert_eq!(wal.synced_len(), 0);
        wal.append_deferred(&test_payload(3), 3).expect("deferred");
        wal.append_deferred(&test_payload(4), 4).expect("deferred");
        let len_before = std::fs::metadata(layout.wal_current_path())
            .expect("metadata")
            .len();

        wal.inner.lock().faults.frame_write = true;
        wal.append_deferred(&test_payload(5), 5)
            .expect_err("the injected failure must surface");

        assert_eq!(
            std::fs::metadata(layout.wal_current_path())
                .expect("metadata")
                .len(),
            len_before
        );
        let seq = wal.append(&test_payload(5), 5).expect("appendable");
        assert_eq!(replayed_seqs(&wal), vec![3, 4, seq]);
    }

    /// A torn append poisons with no failed sync behind it, so a seal is still its
    /// recovery; a failed sync blocks the seal, which would retry it.
    #[test]
    fn an_archive_after_a_sync_failure_is_refused_but_after_a_tear_it_seals() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, None).expect("open");
        wal.append(&test_payload(0), 1).expect("first");
        wal.inner.lock().poisoned = true;
        wal.archive(0, 0)
            .expect("a torn-append poison has no failed sync behind it");

        wal.append(&test_payload(1), 2).expect("fresh log");
        wal.inner.lock().sync_failed = true;
        wal.archive(1, 1)
            .expect_err("a failed sync must block the seal");
        assert!(layout.wal_current_path().is_file(), "the log did not move");
    }

    /// `archive` syncs before it seals, so a sync that fails there refuses the seal
    /// and leaves the unsynced frames in `current.log` rather than sealing them.
    #[test]
    fn an_archive_whose_sync_fails_does_not_seal() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, None).expect("open");
        wal.append(&test_payload(0), 1).expect("synced");
        wal.append_deferred(&test_payload(1), 2).expect("deferred");
        let len = std::fs::metadata(layout.wal_current_path())
            .expect("metadata")
            .len();

        wal.inner.lock().faults.sync = true;
        let err = wal
            .archive(0, 1)
            .expect_err("the seal must not outrun a failed sync");
        assert!(matches!(err, PersistenceError::Io(_)), "got {err:?}");
        assert!(wal.inner.lock().sync_failed, "the failure poisons for good");
        assert!(
            std::fs::symlink_metadata(layout.wal_archived_path(0, 1)).is_err(),
            "nothing was sealed"
        );
        assert_eq!(
            std::fs::metadata(layout.wal_current_path())
                .expect("the log did not move")
                .len(),
            len
        );
        assert_eq!(replayed_seqs(&wal), vec![0, 1]);
    }

    fn manifest_at(replay_floor: u64) -> crate::Manifest {
        crate::Manifest {
            schema_version: crate::MANIFEST_SCHEMA_VERSION,
            scheme_tag: "test-scheme".to_owned(),
            instance_id: "test-instance".to_owned(),
            current_snapshot_id: crate::SnapshotId(0),
            current_snapshot_seq: replay_floor,
            current_marker: 0,
            encoder_label: "test-encoder".to_owned(),
            prev_encoder_label: None,
            entry_size_bytes: Some(32),
            rows_per_shard: Some(2048),
        }
    }

    fn point_at(m: &mut crate::Manifest, id: crate::SnapshotId, floor: u64) {
        m.current_snapshot_id = id;
        m.current_snapshot_seq = floor;
    }

    /// A tear whose rewind failed poisons with no failed sync behind it. The commit
    /// still seals the log, which excludes the torn frame and clears the poison;
    /// refusing it would turn a recoverable tear into an outage until restart.
    #[test]
    fn a_commit_seals_a_log_a_torn_append_poisoned() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, None).expect("open");
        wal.append(&test_payload(0), 1).expect("first");
        wal.append_deferred(&test_payload(1), 2).expect("second");
        {
            let mut state = wal.inner.lock();
            state.faults.frame_write = true;
            state.faults.rewind = true;
        }
        wal.append_deferred(&test_payload(2), 3)
            .expect_err("the injected tear must surface");
        assert!(wal.inner.lock().poisoned);

        let mut manifest = manifest_at(0);
        crate::advance_manifest_and_archive(
            &layout,
            &wal,
            &mut manifest,
            crate::SnapshotId(1),
            point_at,
        )
        .expect("a torn-append poison is recovered by the seal");

        let on_disk = crate::Manifest::load(&layout)
            .expect("load")
            .expect("the manifest landed");
        assert_eq!(
            on_disk.current_snapshot_seq, 2,
            "the floor excludes the tear"
        );
        assert!(layout.wal_archived_path(0, 1).is_file());
        assert!(!wal.inner.lock().poisoned, "the seal cleared the poison");
        assert_eq!(wal.append(&test_payload(2), 3).expect("appendable"), 2);
    }

    /// After a failed sync the durable tail is unknown, so a commit must refuse
    /// before the manifest records a floor the disk may not hold.
    #[test]
    fn a_commit_after_a_failed_sync_writes_no_manifest() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, None).expect("open");
        wal.append(&test_payload(0), 1).expect("synced");
        wal.append_deferred(&test_payload(1), 2).expect("deferred");
        wal.inner.lock().faults.sync = true;
        wal.sync()
            .expect_err("the injected sync failure must surface");

        let mut manifest = manifest_at(0);
        let err = crate::advance_manifest_and_archive(
            &layout,
            &wal,
            &mut manifest,
            crate::SnapshotId(1),
            point_at,
        )
        .expect_err("a commit over a failed sync must be refused");
        assert!(format!("{err}").contains("sync"), "got {err}");
        assert!(
            crate::Manifest::load(&layout).expect("load").is_none(),
            "no manifest may be written"
        );
        assert_eq!(
            manifest.current_snapshot_seq, 0,
            "the caller's copy is untouched"
        );
        assert_eq!(replayed_seqs(&wal), vec![0, 1], "the log did not move");
    }
}
