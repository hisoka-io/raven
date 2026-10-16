//! The positional Howl discovery table, durable and append-only.
//!
//! Row `i` belongs to tree leaf `i`. For every leaf the store keeps three things: the
//! 256-byte `howl-note-v1` cell a wallet retrieves privately, the six-byte tag prefix it
//! publishes, and the tree leaf itself, which it serves in blocks of [`LEAF_BLOCK_ROWS`].
//!
//! Cells are grouped into shards of [`ROWS_PER_SHARD`] rows, the unit a PIR engine encodes.
//! Leaves only ever arrive at the end, so an append changes the newest shard and no other.
//! A shard that fills is sealed: written once to its own checksummed file and never
//! rewritten. [`NoteStore::shard`] returns a shard's cells together with a digest of them,
//! so anything derived from a shard can be bound to the exact bytes it was derived from.
//!
//! Durability rests on Raven's storage primitives. A batch is one synced write-ahead-log
//! frame carrying its rows and the indexer's position, so the table and the point to
//! resume indexing from move together. A checkpoint seals full shards, snapshots the rows
//! of the newest one, and advances the manifest, which is the single commit point: a crash
//! anywhere before it replays the log over the previous snapshot and arrives at the same
//! table. A checkpoint runs when a shard fills and when the log passes [`MAX_LOG_BYTES`],
//! so the log a restart replays is bounded whether or not leaves arrive.
//!
//! A batch may carry the hash of the chain block it ends at. The store keeps the newest
//! [`MAX_MARKS`] of those [`Mark`]s: the points a follower checks against the chain and
//! [`NoteStore::rewind`]s to when the chain reorganises below its tip.

#![deny(missing_docs)]

// Lets the helpers shared with the integration tests name this crate the same way.
#[cfg(test)]
extern crate self as howl_store;

use std::fmt::Write as _;
use std::ops::{Range, RangeInclusive};
use std::path::PathBuf;

use howl_indexer::{Batch, Checkpoint, Leaf, TREE_DEPTH};
use howl_prefix_feed::{segment, tag_prefix, FeedError, Segment, GENESIS_PREFIX, PREFIX_BYTES};
use howl_record::CELL_BYTES;
use raven_storage::{
    advance_manifest_and_archive, apply_retention, atomic_write, decode_no_trailing, open_recovery,
    ExclusiveLock, Manifest, ManifestShape, PersistenceError, RetentionPolicy, SnapshotFile,
    SnapshotId, StoreLayout, Wal, MANIFEST_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Rows in one shard of the discovery table.
pub const ROWS_PER_SHARD: usize = 2_048;

/// Bytes of cells in one shard.
pub const SHARD_BYTES: usize = ROWS_PER_SHARD * CELL_BYTES;

/// Tree leaves in one block of [`NoteStore::leaf_block`].
pub const LEAF_BLOCK_ROWS: usize = 1_024;

/// Most leaves one [`NoteStore::append`] takes, which keeps a batch inside one log frame.
pub const MAX_BATCH_ROWS: usize = 65_536;

/// Log size past which an append retires the log. A batch with no leaf still writes a
/// frame, so without this a quiet chain would grow the log until the next shard filled.
pub const MAX_LOG_BYTES: u64 = 1 << 20;

/// Chain marks kept: one per batch that named its block hash, newest last.
pub const MAX_MARKS: usize = 256;

const LEAF_BYTES: usize = 32;
const SCHEME_TAG: &str = "howl-db1";
// Names the cell layout and the prefix rule: a directory written under another pair is refused.
const ENCODER_LABEL: &str = "howl-note-v1+tag-low6";
const SNAPSHOT_MAGIC: [u8; 16] = *b"HOWL-DB1-TAIL-01";
const SHARD_MAGIC: [u8; 8] = *b"HOWLSHRD";
const SHARD_VERSION: u32 = 1;
const SHARD_HEADER_BYTES: usize = 8 + 4 + 4 + 32;
const SHARD_BODY_BYTES: usize = ROWS_PER_SHARD * (LEAF_BYTES + PREFIX_BYTES + CELL_BYTES);

/// Why the store refused an operation.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The durability layer failed or refused.
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    /// A file could not be read or written.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The batch does not start at the next row.
    #[error("batch holds leaf {found} where leaf {expected} is next")]
    NotContiguous {
        /// Position found in the batch.
        found: u64,
        /// Position the table expects.
        expected: u64,
    },
    /// The batch's checkpoint does not describe the table the batch produces.
    #[error("batch checkpoint is at {checkpoint} leaves and the table would hold {table}")]
    CheckpointMismatch {
        /// Leaf count in the checkpoint.
        checkpoint: u64,
        /// Leaf count after the batch.
        table: u64,
    },
    /// The batch's checkpoint is behind the block already recorded.
    #[error("batch ends at block {found:?} and the table is already at {held:?}")]
    BlockRegression {
        /// Final block in the batch.
        found: Option<u64>,
        /// Final block recorded.
        held: Option<u64>,
    },
    /// More leaves than one append takes.
    #[error("batch of {rows} leaves exceeds the {MAX_BATCH_ROWS} one append takes")]
    BatchTooLarge {
        /// Leaves in the batch.
        rows: usize,
    },
    /// A shard index beyond the table.
    #[error("shard {shard} is beyond the {count} shards held")]
    NoSuchShard {
        /// Shard asked for.
        shard: u32,
        /// Shards held.
        count: u32,
    },
    /// A sealed shard file is missing, damaged, or not the file this store sealed.
    #[error("sealed shard {shard}: {reason}")]
    SealedShard {
        /// The shard.
        shard: u32,
        /// What was wrong with its file.
        reason: &'static str,
    },
    /// Durable state that does not fit together.
    #[error("stored table is inconsistent: {0}")]
    Inconsistent(&'static str),
    /// A rewind to a point the table is not past.
    #[error("cannot rewind to {to} leaves at block {block:?}: the table holds {held} leaves at block {held_block:?}")]
    RewindForward {
        /// Leaf count asked for.
        to: u64,
        /// Block asked for.
        block: Option<u64>,
        /// Leaves held.
        held: u64,
        /// Block held.
        held_block: Option<u64>,
    },
    /// A fault injected by a crash test.
    #[cfg(test)]
    #[error("injected crash at {0:?}")]
    Injected(CrashPoint),
}

/// What one [`NoteStore::append`] changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Appended {
    /// Rows added.
    pub leaves: Range<u64>,
    /// Shards whose cells changed, `None` when no row was added. Every shard outside the
    /// range holds the bytes it held before.
    pub shards: Option<RangeInclusive<u32>>,
}

/// What one [`NoteStore::rewind`] dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rewound {
    /// Rows removed.
    pub leaves: Range<u64>,
}

/// What [`NoteStore::open`] found in the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recovery {
    /// Batches replayed from the log over the snapshot.
    pub replayed_batches: usize,
    /// Bytes of log read to replay them.
    pub log_bytes: u64,
    /// Bytes cut from the end of the log because they held no whole batch. A process that
    /// died inside a write leaves part of one batch here. More than that means stored
    /// batches were damaged: the table stands at [`NoteStore::resume_point`] and the
    /// indexer reads the rest from the chain again.
    pub cut_bytes: u64,
}

/// Where the table stood at the end of a batch, with the hash of the block it ended at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mark {
    /// The batch's final block.
    pub block: u64,
    /// That block's hash as the chain reported it.
    pub hash: [u8; 32],
    /// Leaves in the table after the batch.
    pub leaf_count: u64,
}

/// One shard of the discovery table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shard {
    /// Index of the shard.
    pub index: u32,
    /// Rows that hold a leaf; the rest are zero.
    pub rows: u32,
    /// SHA-256 of `cells`. Equal digests mean equal cells, so a value derived from a shard
    /// is current exactly while this matches.
    pub digest: [u8; 32],
    /// [`SHARD_BYTES`] bytes: [`ROWS_PER_SHARD`] cells in row order.
    pub cells: Vec<u8>,
}

impl Shard {
    /// Whether the shard is full and so can never change again.
    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.rows as usize == ROWS_PER_SHARD
    }
}

/// Consecutive tree leaves, with the tree they were read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafBlock<'a> {
    /// Index of the block: it starts at leaf `block_index * LEAF_BLOCK_ROWS`.
    pub block_index: u32,
    /// The leaves, 32 big-endian bytes each, in tree order. The newest block holds the
    /// leaves inserted so far; a block beyond it is empty.
    pub leaves: &'a [u8],
    /// Leaves in the tree when the block was read.
    pub leaf_count: u64,
    /// Root of that tree.
    pub root: [u8; 32],
}

impl LeafBlock<'_> {
    /// Leaves in the block.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.leaves.len() / LEAF_BYTES
    }

    /// Whether the block holds no leaf.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Whether the block holds all [`LEAF_BLOCK_ROWS`] leaves and so can never change.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.len() == LEAF_BLOCK_ROWS
    }
}

/// Rows in the form they are logged and snapshotted: three parallel byte runs.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Rows {
    first_leaf: u64,
    leaves: Vec<u8>,
    prefixes: Vec<u8>,
    cells: Vec<u8>,
}

impl Rows {
    fn of(first_leaf: u64, leaves: &[Leaf]) -> Self {
        let mut rows = Self {
            first_leaf,
            leaves: Vec::with_capacity(leaves.len() * LEAF_BYTES),
            prefixes: Vec::with_capacity(leaves.len() * PREFIX_BYTES),
            cells: Vec::with_capacity(leaves.len() * CELL_BYTES),
        };
        for leaf in leaves {
            rows.leaves.extend_from_slice(&leaf.commitment);
            rows.prefixes
                .extend_from_slice(&leaf.tag.as_ref().map_or(GENESIS_PREFIX, tag_prefix));
            rows.cells.extend_from_slice(&leaf.cell);
        }
        rows
    }

    /// Row count, or `None` when the three runs disagree.
    fn count(&self) -> Option<usize> {
        let count = self.leaves.len() / LEAF_BYTES;
        (self.leaves.len() == count * LEAF_BYTES
            && self.prefixes.len() == count * PREFIX_BYTES
            && self.cells.len() == count * CELL_BYTES)
            .then_some(count)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Cursor {
    leaf_count: u64,
    final_block: Option<u64>,
    root: [u8; 32],
    frontier: [[u8; 32]; TREE_DEPTH],
    block_hash: Option<[u8; 32]>,
}

impl Cursor {
    fn of(checkpoint: &Checkpoint, block_hash: Option<[u8; 32]>) -> Self {
        Self {
            leaf_count: checkpoint.leaf_count,
            final_block: checkpoint.final_block,
            root: checkpoint.root,
            frontier: checkpoint.frontier,
            block_hash,
        }
    }

    fn mark(&self) -> Option<Mark> {
        Some(Mark {
            block: self.final_block?,
            hash: self.block_hash?,
            leaf_count: self.leaf_count,
        })
    }
}

impl From<Cursor> for Checkpoint {
    fn from(cursor: Cursor) -> Self {
        Self {
            leaf_count: cursor.leaf_count,
            final_block: cursor.final_block,
            root: cursor.root,
            frontier: cursor.frontier,
        }
    }
}

/// One log frame: a batch's rows and where the indexer stood after them.
#[derive(Debug, Serialize, Deserialize)]
struct LogEntry {
    rows: Rows,
    cursor: Cursor,
}

/// The snapshot payload: the rows no sealed shard holds yet, and which files hold the rest.
#[derive(Debug, Serialize, Deserialize)]
struct TailSnapshot {
    /// Checksum of every sealed shard's file, in shard order. A file is served only while
    /// it is the one named here, so a well-formed file from elsewhere is refused.
    sealed: Vec<[u8; 32]>,
    rows: Rows,
    cursor: Cursor,
    /// The newest marks, oldest first; the cursor's own mark is the last when it has one.
    marks: Vec<Mark>,
}

/// The two digests kept for a sealed shard.
#[derive(Debug, Clone, Copy)]
struct Sealed {
    /// Checksum of the shard's file: leaves, prefixes and cells.
    file: [u8; 32],
    /// Digest of the cells alone, which [`Shard::digest`] returns.
    cells: [u8; 32],
}

/// A point in an append at which a crash test stops the store.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashPoint {
    /// The batch is in the log and nothing else has happened.
    AfterLog,
    /// A full shard's file is written; the manifest still names the old snapshot.
    AfterSeal,
    /// The new snapshot is written; the manifest still names the old one.
    AfterSnapshot,
    /// The manifest is advanced and the log archived; old snapshots are not yet pruned.
    AfterCommit,
}

/// Everything derived from the leaves, rebuilt on open from disk.
#[derive(Debug)]
struct Table {
    /// Every tree leaf, 32 bytes each.
    leaves: Vec<u8>,
    /// Every published prefix, six bytes each.
    prefixes: Vec<u8>,
    sealed: Vec<Sealed>,
    /// Cells of the rows after the last sealed shard.
    tail: Vec<u8>,
    resume: Checkpoint,
    marks: Vec<Mark>,
}

impl Table {
    fn empty() -> Self {
        Self {
            leaves: Vec::new(),
            prefixes: Vec::new(),
            sealed: Vec::new(),
            tail: Vec::new(),
            resume: Checkpoint {
                leaf_count: 0,
                final_block: None,
                root: [0u8; 32],
                frontier: [[0u8; 32]; TREE_DEPTH],
            },
            marks: Vec::new(),
        }
    }

    fn leaf_count(&self) -> u64 {
        (self.leaves.len() / LEAF_BYTES) as u64
    }

    fn sealed_rows(&self) -> u64 {
        (self.sealed.len() * ROWS_PER_SHARD) as u64
    }

    fn apply(&mut self, rows: Rows, cursor: Cursor) -> Result<(), StoreError> {
        let count = rows
            .count()
            .ok_or(StoreError::Inconsistent("a stored batch has ragged rows"))?;
        if rows.first_leaf != self.leaf_count() {
            return Err(StoreError::Inconsistent(
                "a stored batch does not start at the next row",
            ));
        }
        if cursor.leaf_count != self.leaf_count() + count as u64 {
            return Err(StoreError::Inconsistent(
                "a stored batch disagrees with its own checkpoint",
            ));
        }
        self.leaves.extend_from_slice(&rows.leaves);
        self.prefixes.extend_from_slice(&rows.prefixes);
        self.tail.extend_from_slice(&rows.cells);
        self.note_mark(cursor.mark());
        self.resume = cursor.into();
        Ok(())
    }

    fn note_mark(&mut self, mark: Option<Mark>) {
        if let Some(mark) = mark {
            self.marks.push(mark);
            let excess = self.marks.len().saturating_sub(MAX_MARKS);
            self.marks.drain(..excess);
        }
    }

    fn unsealed_rows(&self) -> Rows {
        let first = usize::try_from(self.sealed_rows()).unwrap_or(usize::MAX);
        Rows {
            first_leaf: self.sealed_rows(),
            leaves: tail_of(&self.leaves, first, LEAF_BYTES).to_vec(),
            prefixes: tail_of(&self.prefixes, first, PREFIX_BYTES).to_vec(),
            cells: self.tail.clone(),
        }
    }
}

fn tail_of(run: &[u8], first_row: usize, width: usize) -> &[u8] {
    run.get(first_row.saturating_mul(width)..)
        .unwrap_or_default()
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn shard_path(layout: &StoreLayout, shard: u32) -> PathBuf {
    layout
        .root()
        .join("shards")
        .join(format!("shard-{shard:08}.bin"))
}

/// The rows of one sealed shard, as read back from its file.
struct SealedShard {
    checksum: [u8; 32],
    leaves: Vec<u8>,
    prefixes: Vec<u8>,
    cells: Vec<u8>,
}

/// Write a full shard to its file and return the file's checksum. The bytes depend only on
/// the rows, so writing the same shard again after a crash replaces the file with an
/// identical one.
fn write_sealed(
    layout: &StoreLayout,
    shard: u32,
    leaves: &[u8],
    prefixes: &[u8],
    cells: &[u8],
) -> Result<[u8; 32], StoreError> {
    let mut body = Vec::with_capacity(SHARD_BODY_BYTES);
    body.extend_from_slice(leaves);
    body.extend_from_slice(prefixes);
    body.extend_from_slice(cells);
    if body.len() != SHARD_BODY_BYTES {
        return Err(StoreError::Inconsistent("a sealed shard is not full"));
    }
    let mut file = Vec::with_capacity(SHARD_HEADER_BYTES + SHARD_BODY_BYTES);
    file.extend_from_slice(&SHARD_MAGIC);
    file.extend_from_slice(&SHARD_VERSION.to_le_bytes());
    file.extend_from_slice(&shard.to_le_bytes());
    let checksum = digest(&body);
    file.extend_from_slice(&checksum);
    file.extend_from_slice(&body);
    atomic_write(&shard_path(layout, shard), &file)?;
    Ok(checksum)
}

fn read_sealed(layout: &StoreLayout, shard: u32) -> Result<SealedShard, StoreError> {
    let refuse = |reason| StoreError::SealedShard { shard, reason };
    let file = match std::fs::read(shard_path(layout, shard)) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(refuse("file is missing"))
        }
        Err(e) => return Err(e.into()),
    };
    if file.len() != SHARD_HEADER_BYTES + SHARD_BODY_BYTES {
        return Err(refuse("file has the wrong length"));
    }
    let (header, body) = file.split_at(SHARD_HEADER_BYTES);
    let checksum = digest(body);
    let mut expected = Vec::with_capacity(SHARD_HEADER_BYTES);
    expected.extend_from_slice(&SHARD_MAGIC);
    expected.extend_from_slice(&SHARD_VERSION.to_le_bytes());
    expected.extend_from_slice(&shard.to_le_bytes());
    expected.extend_from_slice(&checksum);
    if header != expected.as_slice() {
        return Err(refuse("header or checksum does not match the contents"));
    }
    let (leaves, rest) = body.split_at(ROWS_PER_SHARD * LEAF_BYTES);
    let (prefixes, cells) = rest.split_at(ROWS_PER_SHARD * PREFIX_BYTES);
    Ok(SealedShard {
        checksum,
        leaves: leaves.to_vec(),
        prefixes: prefixes.to_vec(),
        cells: cells.to_vec(),
    })
}

/// The discovery table of one pool deployment, in one directory.
#[derive(Debug)]
pub struct NoteStore {
    layout: StoreLayout,
    // Held for the life of the store: two writers on one directory corrupt the log.
    _lock: ExclusiveLock,
    wal: Wal,
    manifest: Manifest,
    table: Table,
    recovery: Recovery,
    // `MAX_LOG_BYTES`, as a field so a test can reach many retirements with few batches.
    log_limit: u64,
    #[cfg(test)]
    crash_at: Option<CrashPoint>,
}

/// Length of the log file, zero while there is none.
fn log_len(layout: &StoreLayout) -> Result<u64, StoreError> {
    match std::fs::metadata(layout.wal_current_path()) {
        Ok(file) => Ok(file.len()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e.into()),
    }
}

impl NoteStore {
    /// Open the table in `data_dir`, creating it when the directory is new and recovering
    /// it otherwise. The directory is bound to the deployment it was created for.
    ///
    /// # Errors
    /// [`StoreError::Persistence`] when another process holds the directory, when it was
    /// created for another deployment or layout, or when a snapshot or the log is
    /// unreadable; [`StoreError::SealedShard`] when a sealed shard's file is missing,
    /// altered, or another file than the one that was sealed.
    ///
    /// A log whose end holds no whole batch is cut there and the open succeeds;
    /// [`NoteStore::recovery`] says how much was cut.
    pub fn open(
        data_dir: impl Into<PathBuf>,
        chain_id: u64,
        pool: [u8; 20],
    ) -> Result<Self, StoreError> {
        let (layout, lock) = StoreLayout::open_with_lock(data_dir)?;
        let mut instance_id = format!("{chain_id}-0x");
        for byte in pool {
            let _ = write!(instance_id, "{byte:02x}");
        }
        let shape = ManifestShape {
            entry_size_bytes: CELL_BYTES,
            rows_per_shard: ROWS_PER_SHARD as u64,
        };
        let validate = |manifest: &Manifest| {
            manifest.validate_identity(SCHEME_TAG, &instance_id, ENCODER_LABEL)?;
            manifest.validate_shape(shape)
        };
        // Recovery cuts a damaged end off the log without saying so; the length before
        // and after is the only trace it leaves.
        let log_before = log_len(&layout)?;
        let recovery = match open_recovery(&layout, SNAPSHOT_MAGIC, validate)? {
            Some(recovery) => recovery,
            None => {
                Manifest {
                    schema_version: MANIFEST_SCHEMA_VERSION,
                    scheme_tag: SCHEME_TAG.to_owned(),
                    instance_id: instance_id.clone(),
                    current_snapshot_id: SnapshotId(0),
                    current_snapshot_seq: 0,
                    current_marker: 0,
                    encoder_label: ENCODER_LABEL.to_owned(),
                    prev_encoder_label: None,
                    entry_size_bytes: Some(shape.entry_size_bytes),
                    rows_per_shard: Some(shape.rows_per_shard),
                }
                .save(&layout)?;
                open_recovery(&layout, SNAPSHOT_MAGIC, validate)?.ok_or(
                    StoreError::Inconsistent("the manifest just written is gone"),
                )?
            }
        };

        let mut table = Table::empty();
        if let Some(snapshot) = &recovery.snapshot {
            let tail: TailSnapshot =
                decode_no_trailing(&snapshot.data).map_err(PersistenceError::from)?;
            for (shard, expected) in (0u32..).zip(&tail.sealed) {
                let sealed = read_sealed(&layout, shard)?;
                if sealed.checksum != *expected {
                    return Err(StoreError::SealedShard {
                        shard,
                        reason: "file is not the one that was sealed",
                    });
                }
                table.leaves.extend_from_slice(&sealed.leaves);
                table.prefixes.extend_from_slice(&sealed.prefixes);
                table.sealed.push(Sealed {
                    file: sealed.checksum,
                    cells: digest(&sealed.cells),
                });
            }
            table.apply(tail.rows, tail.cursor)?;
            table.marks = tail.marks;
        }
        for entry in &recovery.replay.entries {
            let entry: LogEntry =
                decode_no_trailing(&entry.payload).map_err(PersistenceError::from)?;
            table.apply(entry.rows, entry.cursor)?;
        }
        let log_bytes = log_len(&layout)?;

        let mut store = Self {
            layout,
            _lock: lock,
            wal: recovery.wal,
            manifest: recovery.manifest,
            table,
            recovery: Recovery {
                replayed_batches: recovery.replay.entries.len(),
                log_bytes,
                cut_bytes: log_before.saturating_sub(log_bytes),
            },
            log_limit: MAX_LOG_BYTES,
            #[cfg(test)]
            crash_at: None,
        };
        // A crash between a batch and its seal leaves a full shard in the log.
        if store.table.tail.len() >= SHARD_BYTES {
            store.checkpoint()?;
        }
        Ok(store)
    }

    /// What opening this store found in the log: how much it replayed, and how much it cut.
    #[must_use]
    pub const fn recovery(&self) -> Recovery {
        self.recovery
    }

    /// Leaves in the table.
    #[must_use]
    pub fn leaf_count(&self) -> u64 {
        self.table.leaf_count()
    }

    /// Where the indexer that feeds this table stood after the last batch. Resume it from
    /// here: the table and this point are written together.
    #[must_use]
    pub const fn resume_point(&self) -> &Checkpoint {
        &self.table.resume
    }

    /// Shards the table spans, counting the newest one while it fills.
    #[must_use]
    pub fn shard_count(&self) -> u32 {
        u32::try_from(self.leaf_count().div_ceil(ROWS_PER_SHARD as u64)).unwrap_or(u32::MAX)
    }

    /// Add a batch of leaves. On return the batch is durable.
    ///
    /// A batch added this way leaves no [`Mark`], so it is never a point to rewind to; a
    /// follower of a chain that can reorganise uses [`NoteStore::append_at`].
    ///
    /// # Errors
    /// The batch is refused, and nothing is written, when it does not start at the next
    /// row, when its checkpoint does not match its leaves, or when it is larger than
    /// [`MAX_BATCH_ROWS`]. A storage failure is returned as is; reopen the store after one.
    pub fn append(&mut self, batch: &Batch) -> Result<Appended, StoreError> {
        self.append_marked(batch, None)
    }

    /// [`NoteStore::append`], recording that the batch's final block had hash `block_hash`.
    /// The batch becomes a [`Mark`] once its checkpoint names a block.
    ///
    /// # Errors
    /// As [`NoteStore::append`].
    pub fn append_at(
        &mut self,
        batch: &Batch,
        block_hash: [u8; 32],
    ) -> Result<Appended, StoreError> {
        self.append_marked(batch, Some(block_hash))
    }

    fn append_marked(
        &mut self,
        batch: &Batch,
        block_hash: Option<[u8; 32]>,
    ) -> Result<Appended, StoreError> {
        let held = self.leaf_count();
        let rows = batch.leaves.len();
        if rows > MAX_BATCH_ROWS {
            return Err(StoreError::BatchTooLarge { rows });
        }
        for (offset, leaf) in batch.leaves.iter().enumerate() {
            let expected = held + offset as u64;
            if u64::from(leaf.leaf_index) != expected {
                return Err(StoreError::NotContiguous {
                    found: u64::from(leaf.leaf_index),
                    expected,
                });
            }
        }
        let end = held + rows as u64;
        if batch.checkpoint.leaf_count != end {
            return Err(StoreError::CheckpointMismatch {
                checkpoint: batch.checkpoint.leaf_count,
                table: end,
            });
        }
        if batch.checkpoint.final_block < self.table.resume.final_block {
            return Err(StoreError::BlockRegression {
                found: batch.checkpoint.final_block,
                held: self.table.resume.final_block,
            });
        }
        if batch.checkpoint == self.table.resume {
            return Ok(Appended {
                leaves: held..held,
                shards: None,
            });
        }

        let entry = LogEntry {
            rows: Rows::of(held, &batch.leaves),
            cursor: Cursor::of(&batch.checkpoint, block_hash),
        };
        self.wal
            .append(&entry, batch.checkpoint.final_block.unwrap_or(0))?;
        #[cfg(test)]
        self.reached(CrashPoint::AfterLog)?;
        self.table.apply(entry.rows, entry.cursor)?;
        if self.table.tail.len() >= SHARD_BYTES || self.wal.synced_len() > self.log_limit {
            self.checkpoint()?;
        }

        let shard_of = |row: u64| u32::try_from(row / ROWS_PER_SHARD as u64).unwrap_or(u32::MAX);
        Ok(Appended {
            leaves: held..end,
            shards: (rows > 0).then(|| shard_of(held)..=shard_of(end - 1)),
        })
    }

    /// Seal every full shard, snapshot the rows of the newest one, and retire the log.
    ///
    /// [`NoteStore::append`] does this whenever a shard fills or the log passes
    /// [`MAX_LOG_BYTES`]. Call it at other times to shorten the log a restart replays.
    ///
    /// # Errors
    /// A storage failure. The table on disk stays recoverable at every step: the manifest
    /// is advanced last, and until then a restart replays the log.
    pub fn checkpoint(&mut self) -> Result<(), StoreError> {
        while self.table.tail.len() >= SHARD_BYTES {
            let shard = u32::try_from(self.table.sealed.len()).unwrap_or(u32::MAX);
            let first = self.table.sealed.len() * ROWS_PER_SHARD;
            let run = |bytes: &[u8], width: usize| -> Vec<u8> {
                bytes
                    .get(first * width..(first + ROWS_PER_SHARD) * width)
                    .unwrap_or_default()
                    .to_vec()
            };
            let cells = self.table.tail.get(..SHARD_BYTES).unwrap_or_default();
            let sealed = Sealed {
                file: write_sealed(
                    &self.layout,
                    shard,
                    &run(&self.table.leaves, LEAF_BYTES),
                    &run(&self.table.prefixes, PREFIX_BYTES),
                    cells,
                )?,
                cells: digest(cells),
            };
            self.table.tail.drain(..SHARD_BYTES);
            self.table.sealed.push(sealed);
            #[cfg(test)]
            self.reached(CrashPoint::AfterSeal)?;
        }

        let snapshot = TailSnapshot {
            sealed: self.table.sealed.iter().map(|shard| shard.file).collect(),
            rows: self.table.unsealed_rows(),
            cursor: Cursor::of(&self.table.resume, None),
            marks: self.table.marks.clone(),
        };
        let payload = bincode::serialize(&snapshot).map_err(PersistenceError::from)?;
        let id = self.manifest.current_snapshot_id.next();
        SnapshotFile::build(payload, SNAPSHOT_MAGIC).save(&self.layout, id)?;
        #[cfg(test)]
        self.reached(CrashPoint::AfterSnapshot)?;

        let marker = self.table.resume.final_block.unwrap_or(0);
        advance_manifest_and_archive(
            &self.layout,
            &self.wal,
            &mut self.manifest,
            id,
            |manifest, id, floor| {
                manifest.current_snapshot_id = id;
                manifest.current_snapshot_seq = floor;
                manifest.current_marker = marker;
            },
        )?;
        #[cfg(test)]
        self.reached(CrashPoint::AfterCommit)?;
        apply_retention(&self.layout, id, RetentionPolicy::default())?;
        Ok(())
    }

    /// One shard's cells, zero-filled past the last leaf, with the digest that names them.
    ///
    /// # Errors
    /// [`StoreError::NoSuchShard`] beyond the table, and [`StoreError::SealedShard`] when a
    /// sealed shard's file is no longer the file that was sealed.
    pub fn shard(&self, index: u32) -> Result<Shard, StoreError> {
        let count = self.shard_count();
        if index >= count {
            return Err(StoreError::NoSuchShard {
                shard: index,
                count,
            });
        }
        if let Some(sealed) = self.table.sealed.get(index as usize) {
            // The file's checksum covers the cells, so one comparison binds them.
            let file = read_sealed(&self.layout, index)?;
            if file.checksum != sealed.file {
                return Err(StoreError::SealedShard {
                    shard: index,
                    reason: "file is not the one that was sealed",
                });
            }
            return Ok(Shard {
                index,
                rows: ROWS_PER_SHARD as u32,
                digest: sealed.cells,
                cells: file.cells,
            });
        }
        let skip = (index as usize - self.table.sealed.len()) * SHARD_BYTES;
        let held = self.table.tail.get(skip..).unwrap_or_default();
        let held = held.get(..SHARD_BYTES).unwrap_or(held);
        let mut cells = vec![0u8; SHARD_BYTES];
        if let Some(filled) = cells.get_mut(..held.len()) {
            filled.copy_from_slice(held);
        }
        Ok(Shard {
            index,
            rows: u32::try_from(held.len() / CELL_BYTES).unwrap_or(u32::MAX),
            digest: digest(&cells),
            cells,
        })
    }

    /// The newest marks, oldest first.
    #[must_use]
    pub fn marks(&self) -> &[Mark] {
        &self.table.marks
    }

    /// Cut the table back to `to`, a point an indexer stood at earlier on this chain: the
    /// leaves after `to.leaf_count` and the marks after `to.final_block` are dropped, and the
    /// indexer resumes from `to`. On return the cut is durable.
    ///
    /// The store cannot check that `to`'s root and frontier describe its first leaves; the
    /// caller derives them from those leaves.
    ///
    /// # Errors
    /// [`StoreError::RewindForward`] when `to` is past the table's leaves or block, which
    /// changes nothing. A storage failure is returned as is; reopen the store after one.
    pub fn rewind(&mut self, to: &Checkpoint) -> Result<Rewound, StoreError> {
        let held = self.leaf_count();
        if to.leaf_count > held || to.final_block > self.table.resume.final_block {
            return Err(StoreError::RewindForward {
                to: to.leaf_count,
                block: to.final_block,
                held,
                held_block: self.table.resume.final_block,
            });
        }
        let keep = usize::try_from(to.leaf_count).unwrap_or(usize::MAX);
        let keep_sealed = (keep / ROWS_PER_SHARD).min(self.table.sealed.len());
        let tail_rows = keep - keep_sealed * ROWS_PER_SHARD;
        if keep_sealed < self.table.sealed.len() {
            let shard = u32::try_from(keep_sealed).unwrap_or(u32::MAX);
            let file = read_sealed(&self.layout, shard)?;
            if file.checksum
                != self
                    .table
                    .sealed
                    .get(keep_sealed)
                    .map_or([0u8; 32], |s| s.file)
            {
                return Err(StoreError::SealedShard {
                    shard,
                    reason: "file is not the one that was sealed",
                });
            }
            self.table.tail = file.cells;
            self.table.sealed.truncate(keep_sealed);
        }
        self.table.tail.truncate(tail_rows * CELL_BYTES);
        self.table.leaves.truncate(keep * LEAF_BYTES);
        self.table.prefixes.truncate(keep * PREFIX_BYTES);
        self.table
            .marks
            .retain(|mark| mark.leaf_count <= to.leaf_count && Some(mark.block) <= to.final_block);
        self.table.resume = to.clone();
        self.checkpoint()?;
        Ok(Rewound {
            leaves: to.leaf_count..held,
        })
    }

    /// The segment of the public tag index that starts at row `since`.
    ///
    /// # Errors
    /// [`FeedError::PastFrontier`] when `since` is beyond the last row.
    pub fn prefix_segment(&self, since: u64) -> Result<Segment<'_>, FeedError> {
        segment(&self.table.prefixes, since)
    }

    /// Block `block_index` of the tree's leaves: leaves `block_index * 1024` onward, at
    /// most [`LEAF_BLOCK_ROWS`] of them. This is a plain read of public data.
    #[must_use]
    pub fn leaf_block(&self, block_index: u32) -> LeafBlock<'_> {
        let start = (block_index as usize).saturating_mul(LEAF_BLOCK_ROWS * LEAF_BYTES);
        let from = self.table.leaves.get(start..).unwrap_or_default();
        LeafBlock {
            block_index,
            leaves: from.get(..LEAF_BLOCK_ROWS * LEAF_BYTES).unwrap_or(from),
            leaf_count: self.leaf_count(),
            root: self.table.resume.root,
        }
    }

    #[cfg(test)]
    fn reached(&mut self, point: CrashPoint) -> Result<(), StoreError> {
        if self.crash_at == Some(point) {
            self.crash_at = None;
            return Err(StoreError::Injected(point));
        }
        Ok(())
    }
}

#[cfg(test)]
mod crash_tests;
