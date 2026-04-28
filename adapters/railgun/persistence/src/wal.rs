//! Append-only crc32-framed write-ahead log.
//!
//! Frame layout: `[seq u64 BE | block_height u64 BE | payload_len u32 BE | crc32 u32 BE | payload]`.
//! CRC covers all preceding fields + payload. Torn write at the tail → bad CRC → truncate.
//! `seq` is monotonically increasing; `block_height` enables reorg-safe truncation.

use crate::{PersistenceError, Result, StoreLayout};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

#[allow(dead_code)] // on-the-wire format is hand-coded; constant is for documentation
const WAL_HEADER_BYTES: usize = 24;

/// Maximum payload length per entry; guards against nonsense `payload_len` from torn writes.
pub const WAL_MAX_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

/// One on-the-wire WAL entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalEntry {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Chain block height; used for reorg-safe truncation.
    pub block_height: u64,
    /// Bincode-serialized [`WalEntryPayload`].
    pub payload: Vec<u8>,
}

/// Scheme-agnostic payload variants.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WalEntryPayload {
    /// Append a leaf to a Railgun commitment-tree shard.
    AppendLeaf {
        /// Tree index (`0..=tree_count-1`).
        tree_number: u32,
        /// Leaf index within the tree.
        leaf_index: u32,
        /// 32-byte Poseidon BN254 commitment hash.
        commitment: [u8; 32],
    },
    /// Add / update a PPOI status row.
    PpoiStatus {
        /// 32-byte list key.
        list_key: [u8; 32],
        /// 32-byte blinded commitment.
        blinded_commitment: [u8; 32],
        /// Status byte (`Valid` / `ShieldBlocked` / `ProofSubmitted` / `Missing`).
        status: u8,
    },
    /// New leaf appended to a per-list PPOI Merkle tree.
    /// Drives per-list IMT growth and the `(blinded_commitment → list_index)` oracle.
    PpoiListLeafAdded {
        /// 32-byte list key.
        list_key: [u8; 32],
        /// Upstream-issued contiguous index within the list.
        list_index: u32,
        /// 32-byte blinded commitment.
        blinded_commitment: [u8; 32],
        /// Initial status byte.
        status: u8,
    },
    /// Reorg marker: engine truncates WAL entries with `block_height > height`.
    Reorg {
        /// Chain height at the fork point.
        height: u64,
    },
    /// Heartbeat (no-op) emitted at each snapshot to mark the WAL.
    Heartbeat {
        /// Unix milliseconds at emission.
        wallclock_unix_ms: u64,
    },
}

/// Append-only WAL. Internal mutex serializes `append`; `replay` opens a fresh read handle.
#[derive(Debug)]
pub struct Wal {
    layout: StoreLayout,
    inner: Mutex<WalState>,
}

#[derive(Debug)]
struct WalState {
    file: File,
    next_seq: u64,
    last_block_height: u64,
}

impl Wal {
    /// Open or create the WAL at `data_dir/wal/current.log`.
    ///
    /// `last_committed_seq`: `Some(s)` = snapshot committed through seq `s`; `None` = fresh DB.
    /// The on-disk tail wins when higher than the floor.
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
            // Drop before re-opening for write; some filesystems disallow concurrent write handles.
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
                last_block_height: scan.last_block_height,
            }),
        })
    }

    /// Append a payload entry; assigns next seq, fsyncs, returns the assigned seq.
    pub fn append(&self, payload: &WalEntryPayload, block_height: u64) -> Result<u64> {
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
        header[8..16].copy_from_slice(&block_height.to_be_bytes());
        header[16..20].copy_from_slice(&payload_len.to_be_bytes());

        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&header[0..20]);
        hasher.update(&bincoded);
        let crc = hasher.finalize();
        header[20..24].copy_from_slice(&crc.to_be_bytes());

        state.file.write_all(&header)?;
        state.file.write_all(&bincoded)?;
        state.file.sync_all()?;

        state.next_seq = state.next_seq.saturating_add(1);
        state.last_block_height = block_height;
        Ok(seq)
    }

    /// Replay all entries from the start of the file.
    pub fn replay(&self) -> Result<WalReplay> {
        let path = self.layout.wal_current_path();
        let scan = scan_full(&path)?;
        Ok(scan)
    }

    /// Next seq the next `append` will assign.
    pub fn next_seq(&self) -> u64 {
        self.inner.lock().next_seq
    }

    /// Block height of the most recently appended entry.
    pub fn last_block_height(&self) -> u64 {
        self.inner.lock().last_block_height
    }

    /// Archive `current.log` and start a fresh one.
    ///
    /// Fsyncs both the source (`wal/`) and target (`wal/archived/`) parent directories
    /// after the rename so the rename is durable before returning success.
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
        // Fsync source parent again to make the new current.log creation durable.
        if let Some(source_parent) = current.parent() {
            crate::fsync_parent_dir(source_parent)?;
        }
        state.file = new_file;
        Ok(())
    }
}

/// Result of a full WAL replay.
#[derive(Debug)]
pub struct WalReplay {
    /// All valid entries in seq order.
    pub entries: Vec<WalEntry>,
    /// Byte offset of a torn tail, if any.
    pub truncated_at: Option<u64>,
    /// Next free seq (last valid seq + 1, or 0).
    pub next_seq: u64,
    /// Block height of the last valid entry, or 0.
    pub last_block_height: u64,
}

#[derive(Debug)]
struct ScanResult {
    next_seq: u64,
    last_block_height: u64,
    truncate_at: Option<u64>,
}

/// Open the WAL with owner-only mode on Unix (0o600); falls back to default on non-Unix.
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
        last_block_height: scan.last_block_height,
        truncate_at: scan.truncated_at,
    })
}

#[allow(clippy::too_many_lines)] // added monotonic-seq invariant
fn scan_full(path: &std::path::Path) -> Result<WalReplay> {
    if !path.exists() {
        return Ok(WalReplay {
            entries: Vec::new(),
            truncated_at: None,
            next_seq: 0,
            last_block_height: 0,
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
            // Partial header; truncate at the start of this entry.
            return Ok(WalReplay {
                entries,
                truncated_at: Some(offset),
                next_seq,
                last_block_height: last_block,
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
        let block_height = u64::from_be_bytes(h);
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
                last_block_height: last_block,
            });
        }
        if total < offset + 24 + payload_len {
            return Ok(WalReplay {
                entries,
                truncated_at: Some(offset),
                next_seq,
                last_block_height: last_block,
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
                last_block_height: last_block,
            });
        }

        // CRC validates internal consistency but not monotonicity.
        // A CRC-valid frame with a non-monotonic seq (e.g. retry landed at wrong offset)
        // is treated as a torn tail: truncate at this entry's start.
        let expected_seq = if entries.is_empty() { None } else { Some(next_seq) };
        if let Some(exp) = expected_seq {
            if seq != exp {
                return Ok(WalReplay {
                    entries,
                    truncated_at: Some(offset),
                    next_seq,
                    last_block_height: last_block,
                });
            }
        }

        entries.push(WalEntry {
            seq,
            block_height,
            payload,
        });
        next_seq = seq.saturating_add(1);
        last_block = block_height;
        offset += 24 + payload_len;
    }

    Ok(WalReplay {
        entries,
        truncated_at: None,
        next_seq,
        last_block_height: last_block,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_layout() -> (tempfile::TempDir, StoreLayout) {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        (dir, layout)
    }

    fn payload_leaf(idx: u32) -> WalEntryPayload {
        WalEntryPayload::AppendLeaf {
            tree_number: 3,
            leaf_index: idx,
            commitment: [(idx & 0xff) as u8; 32],
        }
    }

    #[test]
    fn append_then_replay_round_trips() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, None).expect("open");
        for i in 0..10u32 {
            wal.append(&payload_leaf(i), 100 + u64::from(i))
                .expect("append");
        }
        let replay = wal.replay().expect("replay");
        assert_eq!(replay.entries.len(), 10);
        assert_eq!(replay.truncated_at, None);
        assert_eq!(replay.next_seq, 10);
        assert_eq!(replay.last_block_height, 109);
        for (i, entry) in replay.entries.iter().enumerate() {
            let parsed: WalEntryPayload = bincode::deserialize(&entry.payload).expect("deser");
            let i_u32 = u32::try_from(i).expect("test index fits in u32");
            assert_eq!(parsed, payload_leaf(i_u32));
            assert_eq!(entry.seq, i as u64);
        }
    }

    #[test]
    fn reopen_resumes_seq() {
        let (_d, layout) = make_layout();
        {
            let wal = Wal::open(&layout, None).expect("open");
            for i in 0..5u32 {
                wal.append(&payload_leaf(i), 100 + u64::from(i))
                    .expect("append");
            }
        }
        let wal2 = Wal::open(&layout, None).expect("reopen");
        assert_eq!(wal2.next_seq(), 5);
        wal2.append(&payload_leaf(99), 200).expect("append");
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
                wal.append(&payload_leaf(i), 100 + u64::from(i))
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
        // The 3 valid entries survive; garbage was truncated.
        assert_eq!(replay.entries.len(), 3);
        assert_eq!(replay.next_seq, 3);
    }

    #[test]
    fn flipped_crc_byte_truncates() {
        let (_d, layout) = make_layout();
        {
            let wal = Wal::open(&layout, None).expect("open");
            for i in 0..3u32 {
                wal.append(&payload_leaf(i), 100 + u64::from(i))
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
            wal.append(&payload_leaf(i), 100 + u64::from(i))
                .expect("append");
        }
        wal.archive(0, 2).expect("archive");
        assert!(layout.wal_archived_path(0, 2).is_file());
        let replay = wal.replay().expect("replay");
        assert_eq!(replay.entries.len(), 0);
        wal.append(&payload_leaf(99), 200).expect("append");
        let replay = wal.replay().expect("replay");
        assert_eq!(replay.entries.len(), 1);
        assert_eq!(replay.entries.first().expect("present").seq, 3);
    }

    /// A CRC-valid frame with a non-monotonic seq must be detected and truncated.
    #[test]
    fn non_monotonic_seq_is_treated_as_torn_tail() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, None).expect("open");
        for i in 0..3u32 {
            wal.append(&payload_leaf(i), 100 + u64::from(i))
                .expect("append");
        }
        drop(wal);

        let payload_bin = bincode::serialize(&payload_leaf(99)).expect("ser");
        let payload_len: u32 = payload_bin.len().try_into().expect("len");
        let mut header = [0u8; 24];
        header[0..8].copy_from_slice(&99u64.to_be_bytes()); // seq=99, should be 3
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
        assert_eq!(replay.entries.len(), 3, "non-monotonic seq=99 frame must NOT be accepted");
        assert_eq!(replay.next_seq, 3);
    }

    #[test]
    fn fresh_open_with_min_seq_floor_resumes_at_floor() {
        let (_d, layout) = make_layout();
        let wal = Wal::open(&layout, Some(99)).expect("open");
        let seq = wal.append(&payload_leaf(0), 100).expect("append");
        assert_eq!(seq, 100);
    }
}
