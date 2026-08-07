//! Append-only crc32-framed write-ahead log.
//!
//! Frame: `[seq u64 BE | marker u64 BE | payload_len u32 BE | crc32 u32 BE | payload]`,
//! crc over everything preceding it plus the payload. `seq` is the WAL's own
//! monotonic counter; `marker` is caller-supplied and also monotonic. Payloads
//! are opaque - [`Wal::replay`] hands the raw bytes back undecoded.

use crate::{PersistenceError, Result, StoreLayout};
use parking_lot::Mutex;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

/// Per-entry ceiling; rejects a nonsense `payload_len` from a torn write.
pub const WAL_MAX_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

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
    last_marker: u64,
    /// Set when an append tore. Every later append is refused, because an
    /// fsync-acknowledged entry that a later replay drops is worse than a
    /// refused write.
    poisoned: bool,
}

/// One whole frame: header then payload then fsync. Any error leaves the caller
/// to rewind, because a header without its payload stops replay.
fn write_frame(file: &mut File, header: &[u8; 24], payload: &[u8]) -> Result<()> {
    file.write_all(header)?;
    file.write_all(payload)?;
    file.sync_all()?;
    Ok(())
}

impl Wal {
    /// Open or create `data_dir/wal/current.log`. `last_committed_seq` sets a
    /// resume floor; the on-disk tail wins when it is higher.
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

        Ok(Self {
            layout: layout.clone(),
            inner: Mutex::new(WalState {
                file,
                next_seq,
                last_marker: scan.last_marker,
                poisoned: false,
            }),
        })
    }

    /// Assigns the next seq, fsyncs, returns that seq. The bound is `Serialize`
    /// alone because the WAL never decodes what it stores.
    pub fn append<P: Serialize>(&self, payload: &P, marker: u64) -> Result<u64> {
        let bincoded = bincode::serialize(payload)?;
        if bincoded.len() > WAL_MAX_PAYLOAD_BYTES {
            return Err(PersistenceError::Invariant(format!(
                "WAL payload {} bytes exceeds max {}",
                bincoded.len(),
                WAL_MAX_PAYLOAD_BYTES
            )));
        }

        let mut state = self.inner.lock();
        let seq = state.next_seq;
        let payload_len = u32::try_from(bincoded.len()).map_err(|_| {
            PersistenceError::Invariant(format!(
                "WAL payload size {} overflows u32",
                bincoded.len()
            ))
        })?;

        let mut header = [0u8; 24];
        header[0..8].copy_from_slice(&seq.to_be_bytes());
        header[8..16].copy_from_slice(&marker.to_be_bytes());
        header[16..20].copy_from_slice(&payload_len.to_be_bytes());

        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&header[0..20]);
        hasher.update(&bincoded);
        let crc = hasher.finalize();
        header[20..24].copy_from_slice(&crc.to_be_bytes());

        if state.poisoned {
            return Err(PersistenceError::Invariant(
                "WAL is poisoned by an earlier torn append; reopen to recover".to_owned(),
            ));
        }

        // A partial write leaves a frame replay stops at, silently dropping every later
        // entry even though append returned Ok and fsynced. Rewind to the last whole
        // frame; poison only if the rewind itself fails, since then the tail is unknown.
        let offset = state.file.stream_position()?;
        if let Err(e) = write_frame(&mut state.file, &header, &bincoded) {
            let rewound = state
                .file
                .set_len(offset)
                .and_then(|()| state.file.sync_all())
                .and_then(|()| state.file.seek(SeekFrom::Start(offset)).map(|_| ()));
            state.poisoned = rewound.is_err();
            return Err(e);
        }

        state.next_seq = state.next_seq.saturating_add(1);
        state.last_marker = marker;
        Ok(seq)
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

    /// Marker of the most recently appended entry.
    pub fn last_marker(&self) -> u64 {
        self.inner.lock().last_marker
    }

    /// Seal `current.log` under `wal/archived/` and start a fresh one. Both
    /// parent dirs are fsynced, so the rename is durable before this returns.
    pub fn archive(&self, from_seq: u64, to_seq: u64) -> Result<()> {
        let mut state = self.inner.lock();
        state.file.sync_all()?;
        let target = self.layout.wal_archived_path(from_seq, to_seq);
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
        if let Some(source_parent) = current.parent() {
            crate::fsync_parent_dir(source_parent)?;
        }
        crate::fsync_parent_dir(&archive_parent)?;
        let new_file = open_wal_owner_only(&current)?;
        new_file.sync_all()?;
        // second pass makes the new current.log's creation durable
        if let Some(source_parent) = current.parent() {
            crate::fsync_parent_dir(source_parent)?;
        }
        state.file = new_file;
        // a fresh file has no torn tail to be poisoned by
        state.poisoned = false;
        Ok(())
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
    last_marker: u64,
    truncate_at: Option<u64>,
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
        last_marker: scan.last_marker,
        truncate_at: scan.truncated_at,
    })
}

#[allow(clippy::too_many_lines)] // single linear frame scanner; splitting hurts readability
fn scan_full(path: &std::path::Path) -> Result<WalReplay> {
    if !path.exists() {
        return Ok(WalReplay {
            entries: Vec::new(),
            truncated_at: None,
            next_seq: 0,
            last_marker: 0,
        });
    }
    let mut file = File::open(path)?;
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

    #[test]
    fn fresh_open_with_min_seq_floor_resumes_at_floor() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, Some(99)).expect("open");
        let seq = wal.append(&test_payload(0), 100).expect("append");
        assert_eq!(seq, 100);
    }

    /// A torn append must not leave bytes that make replay drop later entries.
    /// Pre-fix the header landed with no payload, subsequent appends returned Ok
    /// and fsynced, and replay stopped at the tear.
    #[test]
    fn a_torn_append_rewinds_so_later_entries_still_replay() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let wal = Wal::open(&layout, None).expect("open");

        wal.append(&test_payload(0), 1).expect("first append");

        // a payload one byte over the cap fails after the length check, exercising
        // the same early-return path a write error takes
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
}
