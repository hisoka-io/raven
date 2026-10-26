//! Keeps the table on the chain's newest block, rewinding when the chain reorganises.
//!
//! Each step reads the blocks after the table's last one, up to the head, and appends their
//! leaves with the hash of the final block. Leaves are served as soon as their block is read:
//! every answer names the block it reflects and the wallet decides how deep a block it
//! trusts. A step first compares the hash recorded for the table's last block with the
//! chain's. When they differ the chain reorganised below the tip: the table goes back to the
//! newest recorded block the chain still has, and the step reads on from there.
//!
//! Within the walk depth of the head a step also reads the header of every block it covers. The
//! headers must link to each other and to the table's last block, every log must name one of them,
//! and the pool's leaf count is read at the final header's hash. Leaves are applied only in order
//! and only if the batch ends exactly at that count, so the leaves applied are all of the walked
//! chain's, whatever the endpoint answered between reads. Before the pool has code its count is
//! zero. Deeper ranges are checked by reading the final block's hash before the logs and on both
//! sides of the table's own check, and every log of the final block must carry that hash. Their
//! count is not read: that needs the state of an old block, which a pruned endpoint no longer has.
//! Every leaf must still follow the table's last and reproduce its logged root, and the first
//! walked step checks the total count, so a deep range that dropped leaves is refused when the next
//! leaf or that count arrives. Until then the table serves fewer leaves than the chain holds at the
//! block it names: a load-balanced endpoint whose logs come from a replica more than the walk depth
//! behind can cause that. A leaf whose logged root the table cannot reproduce, or that does not
//! follow the table's last, means the table's rows are not the chain's even where the hashes agree,
//! and the table goes back one more mark; so does a count refused twice at the same block.
//!
//! A read covers as many blocks as fitted one batch of [`MAX_BATCH_ROWS`] leaves last time,
//! doubling while it holds less than half of one, and is cut at the last block that fits before
//! any root is checked. A logs read the endpoint refuses (a range or result cap, an answer past
//! the source's byte limit, a timeout) is halved and read again in the same step, down to one
//! block, and the range then stays at the size that answered for [`HOLD_READS`] reads. What one
//! read holds is thus bounded by the source's answer limit, not by the range times the density.

use std::collections::{BTreeMap, VecDeque};
use std::ops::Range;

use howl_indexer::{
    Checkpoint, IndexError, Indexer, IndexerConfig, RawLog, TOPIC_LEAF_INSERTED, TREE_DEPTH,
};
use howl_store::{Mark, NoteStore, StoreError, MAX_BATCH_ROWS};
use howl_wire::tree::{block_node, Node, TreeError, TreeView, BLOCK_LEAVES};

use crate::chain::{BlockLog, Chain, ChainError};

/// Why a step failed. The table is left where it was; a later step retries.
#[derive(Debug, thiserror::Error)]
pub enum FollowError {
    /// The chain read failed.
    #[error(transparent)]
    Chain(#[from] ChainError),
    /// The logs read did not index.
    #[error(transparent)]
    Index(#[from] IndexError),
    /// The table refused.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The tree arithmetic refused.
    #[error(transparent)]
    Tree(#[from] TreeError),
}

/// What one step did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// The table is at the head.
    Idle {
        /// The head.
        head: u64,
    },
    /// Blocks were read.
    Read {
        /// Leaves added.
        leaves: Range<u64>,
        /// The final block read.
        block: u64,
    },
    /// The chain reorganised and the table went back.
    Rewound {
        /// Leaves dropped.
        leaves: Range<u64>,
        /// The block the table now ends at, `None` when it went back to nothing.
        block: Option<u64>,
    },
    /// The head moved while a range was read; nothing was applied.
    Moved,
}

/// Steps the table's last block may be missing from the chain, with the blocks below it
/// unchanged, before the chain is taken to be shorter. Until then it is a replica behind.
pub const LAG_STEPS: u32 = 8;

/// The default walk depth: blocks below the head within which a step reads the header of every
/// block it covers and the pool's count at the newest. The count is read up to this deep, right
/// after the newest header, so the depth plus the blocks produced while one step runs must lie
/// within the recent state the endpoint keeps (geth keeps 128 blocks by default); a deeper walk
/// needs an endpoint that keeps more. At least one block is always walked. It is not a finality
/// bound on every chain: 64 blocks are two Ethereum epochs, but seconds on a rollup with fast
/// blocks. A reorganisation deeper than the walk is still healed: its leaves fail the root check
/// or the next walked count, and the table goes back.
pub const WALK_BLOCKS: u64 = 64;

/// Reads after a refused logs read during which the range does not grow past the size that
/// answered.
pub const HOLD_READS: u32 = 8;

/// Hashes of read blocks kept to tell a replica behind from a chain that replaced them.
const RECENT_BLOCKS: usize = 256;

/// Blocks a step read and checked, ready to index.
struct Span {
    to: u64,
    /// Hash of each block whose hash the step established, ascending; `to`'s is the last.
    hashes: Vec<(u64, [u8; 32])>,
    logs: Vec<RawLog>,
    count: Option<u64>,
    /// Whether the read was cut short of its range to fit one batch.
    cut: bool,
}

/// The last block of `from..=to` whose leaves, with every block before it, fit one batch, and
/// whether that is short of `to`. A first block that alone does not fit is kept, for the table
/// to refuse.
fn fit(pool: [u8; 20], from: u64, to: u64, logs: &[BlockLog]) -> (u64, bool) {
    let mut per_block = BTreeMap::new();
    for logged in logs {
        let log = &logged.log;
        if log.address == pool
            && (from..=to).contains(&log.block_number)
            && log.topics.first() == Some(&TOPIC_LEAF_INSERTED)
        {
            *per_block.entry(log.block_number).or_insert(0usize) += 1;
        }
    }
    let mut held = 0usize;
    for (&block, &leaves) in &per_block {
        held += leaves;
        if held > MAX_BATCH_ROWS && block > from {
            return (block - 1, true);
        }
    }
    (to, false)
}

/// The table, the indexer that feeds it, and the upper nodes of its full blocks.
#[derive(Debug)]
pub struct Follower<C> {
    chain: C,
    store: NoteStore,
    indexer: Indexer,
    config: IndexerConfig,
    upper: Vec<Node>,
    max_range: u64,
    range: u64,
    walk_blocks: u64,
    /// A logs range the endpoint refused, and the reads since.
    refused_range: Option<(u64, u32)>,
    lagged: u32,
    recent: VecDeque<(u64, [u8; 32])>,
    /// The block a step last read from when the pool's count refused its batch.
    refused: Option<u64>,
}

fn nodes(bytes: &[u8]) -> Vec<Node> {
    bytes.as_chunks::<32>().0.to_vec()
}

/// Level-10 nodes of every full block of `store`.
fn upper_of(store: &NoteStore, from: u64) -> Result<Vec<Node>, TreeError> {
    (from..store.leaf_count() / BLOCK_LEAVES)
        .map(|block| {
            let block = store.leaf_block(u32::try_from(block).unwrap_or(u32::MAX));
            block_node(&nodes(block.leaves))
        })
        .collect()
}

impl<C: Chain> Follower<C> {
    /// Follow `config`'s pool on `chain` into `store`, resuming where the table stopped.
    /// `max_range` bounds the blocks one read covers; `walk_blocks` is the walk depth (see
    /// [`WALK_BLOCKS`]), at least 1.
    ///
    /// # Errors
    /// [`FollowError`] when the table's resume point does not reproduce its root.
    pub fn new(
        chain: C,
        store: NoteStore,
        config: IndexerConfig,
        max_range: u64,
        walk_blocks: u64,
    ) -> Result<Self, FollowError> {
        let indexer = Indexer::resume(config, store.resume_point())?;
        let upper = upper_of(&store, 0)?;
        let max_range = max_range.max(1);
        Ok(Self {
            chain,
            store,
            indexer,
            config,
            upper,
            max_range,
            // The density of leaves is unknown until a read: start at one block and double.
            range: 1,
            walk_blocks: walk_blocks.max(1),
            refused_range: None,
            lagged: 0,
            recent: VecDeque::new(),
            refused: None,
        })
    }

    /// The table.
    #[must_use]
    pub const fn store(&self) -> &NoteStore {
        &self.store
    }

    /// Level-10 nodes of the table's full blocks.
    #[must_use]
    pub fn upper(&self) -> &[Node] {
        &self.upper
    }

    /// The chain read.
    #[must_use]
    pub const fn chain(&self) -> &C {
        &self.chain
    }

    /// Read on from the table's last block, or go back if the chain reorganised.
    ///
    /// # Errors
    /// [`FollowError`]; the table and the follower stay where they were.
    pub async fn step(&mut self) -> Result<Step, FollowError> {
        if let Some(step) = self.reorganised().await? {
            return Ok(step);
        }
        let head = self.chain.head().await?;
        let from = self.indexer.next_block();
        if from > head {
            return Ok(Step::Idle { head });
        }
        let last = from.saturating_add(self.range - 1);
        let span = if head - from < self.walk_blocks {
            self.read_walked(from, head.min(last)).await?
        } else {
            self.read_deep(from, (head - self.walk_blocks).min(last))
                .await?
        };
        let span = match span {
            Ok(span) => span,
            Err(step) => return Ok(step),
        };
        let Some(&(_, hash)) = span.hashes.last() else {
            return Ok(Step::Moved);
        };
        let held = self.store.leaf_count();
        let batch = match self.indexer.ingest(span.to, &span.logs, span.count) {
            Ok(batch) => batch,
            Err(e) => {
                self.reset()?;
                let walk_back = match e {
                    // The chain's tree does not continue the table's: rows below the newest
                    // mark belong to another fork, whatever the hashes say.
                    IndexError::RootMismatch { .. } | IndexError::LeafOutOfOrder { .. } => true,
                    // Once may be a log index trailing its state; twice at the same block
                    // is the table disagreeing with the chain.
                    IndexError::LeafCountMismatch { .. } => {
                        self.refused.replace(from) == Some(from)
                    }
                    _ => false,
                };
                if walk_back {
                    return Ok(match self.reorganised().await? {
                        Some(step) => step,
                        None => self.back_to(self.store.marks().iter().rev().nth(1).copied())?,
                    });
                }
                return Err(e.into());
            }
        };
        if let Err(e) = self.store.append_at(&batch, hash) {
            self.reset()?;
            return Err(e.into());
        }
        // Grow only while a read holds less than half a batch, so a read rarely overshoots.
        let added = self.store.leaf_count() - held;
        let read = span.to - from + 1;
        let mut grown = self.range.saturating_mul(2).min(self.max_range);
        if let Some((refused, reads)) = self.refused_range {
            if reads < HOLD_READS {
                self.refused_range = Some((refused, reads + 1));
                grown = grown.min((refused / 2).max(1));
            } else {
                self.refused_range = None;
            }
        }
        self.range = if span.cut {
            read
        } else if added.saturating_mul(2) <= MAX_BATCH_ROWS as u64 {
            grown.max(self.range)
        } else {
            self.range
        };
        self.refused = None;
        self.remember(&span.hashes);
        let mut fresh = upper_of(&self.store, self.upper.len() as u64)?;
        self.upper.append(&mut fresh);
        Ok(Step::Read {
            leaves: held..self.store.leaf_count(),
            block: span.to,
        })
    }

    /// The range end after the endpoint refused the logs of `from..=to`: half of it, down to
    /// one block, where the error stands.
    fn halve(&mut self, from: u64, to: u64, error: ChainError) -> Result<u64, FollowError> {
        let blocks = to - from + 1;
        if blocks == 1 {
            return Err(error.into());
        }
        tracing::debug!(error = %error, blocks, "logs read refused; halving the range");
        self.range = blocks / 2;
        self.refused_range = Some((blocks, 0));
        Ok(from + self.range - 1)
    }

    /// Blocks `from..=to`, settled: the final block is read before the logs and on both sides
    /// of the table's own check, so it descends from the table's last block, and the endpoint
    /// held it when it answered the logs.
    async fn read_deep(&mut self, from: u64, to: u64) -> Result<Result<Span, Step>, FollowError> {
        let mut to = to;
        let mut logs = loop {
            if self.chain.block_hash(to).await?.is_none() {
                return Ok(Err(Step::Moved));
            }
            match self.chain.logs(from, to).await {
                Ok(logs) => break logs,
                Err(e) => to = self.halve(from, to, e)?,
            }
        };
        let (to, cut) = fit(self.config.pool, from, to, &logs);
        logs.retain(|logged| logged.log.block_number <= to);
        let Some(hash) = self.chain.block_hash(to).await? else {
            return Ok(Err(Step::Moved));
        };
        if logs
            .iter()
            .any(|logged| logged.log.block_number == to && logged.block_hash != hash)
        {
            return Ok(Err(Step::Moved));
        }
        if let Some(step) = self.reorganised().await? {
            return Ok(Err(step));
        }
        if self.chain.block_hash(to).await? != Some(hash) {
            return Ok(Err(Step::Moved));
        }
        Ok(Ok(Span {
            to,
            hashes: vec![(to, hash)],
            logs: logs.into_iter().map(|logged| logged.log).collect(),
            count: None,
            cut,
        }))
    }

    /// Blocks `from..=to` near the head: every header read, linked to the next and to the
    /// table's last block, every log on one of them, and the count at `to`'s.
    async fn read_walked(&mut self, from: u64, to: u64) -> Result<Result<Span, Step>, FollowError> {
        let mut to = to;
        let mut logs = loop {
            match self.chain.logs(from, to).await {
                Ok(logs) => break logs,
                Err(e) => to = self.halve(from, to, e)?,
            }
        };
        let (to, cut) = fit(self.config.pool, from, to, &logs);
        logs.retain(|logged| logged.log.block_number <= to);
        let mut hashes = Vec::new();
        let mut parent = None;
        let mut count = None;
        for number in (from..=to).rev() {
            let Some(header) = self.chain.header(number).await? else {
                return Ok(Err(Step::Moved));
            };
            if parent.is_some_and(|parent| parent != header.hash) {
                return Ok(Err(Step::Moved));
            }
            if parent.is_none() {
                // Read at once: the endpoint's recent state moves on with the head.
                count = self.count_at(header.hash, to, &logs).await?;
            }
            parent = Some(header.parent);
            hashes.push((number, header.hash));
        }
        hashes.reverse();
        let continues = match (self.store.marks().last(), parent) {
            (Some(mark), Some(parent)) if mark.block.checked_add(1) == Some(from) => {
                mark.hash == parent
            }
            _ => true,
        };
        let placed = logs.iter().all(|logged| {
            logged
                .log
                .block_number
                .checked_sub(from)
                .and_then(|offset| usize::try_from(offset).ok())
                .and_then(|offset| hashes.get(offset))
                .is_some_and(|(_, hash)| *hash == logged.block_hash)
        });
        if !(continues && placed) {
            return Ok(Err(Step::Moved));
        }
        if hashes.is_empty() {
            return Ok(Err(Step::Moved));
        }
        Ok(Ok(Span {
            to,
            hashes,
            logs: logs.into_iter().map(|logged| logged.log).collect(),
            count,
            cut,
        }))
    }

    /// The pool's count at block `number`, whose hash is `hash`. A pool without code there has
    /// no leaves yet, which holds only while the table has no leaf and `logs` no pool log.
    async fn count_at(
        &self,
        hash: [u8; 32],
        number: u64,
        logs: &[BlockLog],
    ) -> Result<Option<u64>, FollowError> {
        match self.chain.leaf_count(hash).await {
            Err(ChainError::NoCode)
                if self.store.leaf_count() == 0
                    && !logs
                        .iter()
                        .any(|logged| logged.log.address == self.config.pool) =>
            {
                tracing::warn!(block = number, "the pool has no code yet at this block");
                Ok(Some(0))
            }
            other => Ok(other?),
        }
    }

    fn remember(&mut self, hashes: &[(u64, [u8; 32])]) {
        for &(number, hash) in hashes {
            while self.recent.back().is_some_and(|(held, _)| *held >= number) {
                self.recent.pop_back();
            }
            self.recent.push_back((number, hash));
        }
        let excess = self.recent.len().saturating_sub(RECENT_BLOCKS);
        self.recent.drain(..excess);
    }

    /// The hash the table read for block `number`, when it kept one.
    fn read_hash(&self, number: u64) -> Option<[u8; 32]> {
        self.recent
            .iter()
            .rev()
            .find(|(held, _)| *held == number)
            .map(|(_, hash)| *hash)
            .or_else(|| {
                self.store
                    .marks()
                    .iter()
                    .rev()
                    .find(|mark| mark.block == number)
                    .map(|mark| mark.hash)
            })
    }

    fn reset(&mut self) -> Result<(), FollowError> {
        self.indexer = Indexer::resume(self.config, self.store.resume_point())?;
        Ok(())
    }

    /// Go back to the newest mark the chain still has, when the newest one is gone. A newest
    /// block missing above a head that is still the table's own is waited for [`LAG_STEPS`]
    /// steps: a load-balanced endpoint may answer from a replica behind the one the table was
    /// read from, and that looks the same as a chain cut back with nothing added yet.
    async fn reorganised(&mut self) -> Result<Option<Step>, FollowError> {
        let marks: Vec<Mark> = self.store.marks().to_vec();
        let Some(newest) = marks.last() else {
            return Ok(None);
        };
        match self.chain.block_hash(newest.block).await? {
            Some(hash) if hash == newest.hash => {
                self.lagged = 0;
                return Ok(None);
            }
            Some(_) => {}
            None if self.lagged < LAG_STEPS => {
                let head = self.chain.head().await?;
                if head < newest.block && self.is_prefix(&marks, head).await? {
                    self.lagged += 1;
                    return Ok(Some(Step::Moved));
                }
            }
            None => {}
        }
        let mut keep = None;
        for mark in marks.iter().rev().skip(1) {
            if self.chain.block_hash(mark.block).await? == Some(mark.hash) {
                keep = Some(*mark);
                break;
            }
        }
        self.back_to(keep).map(Some)
    }

    /// Whether the chain up to `head` may be a prefix of the table's: the newest mark at or
    /// below it is intact, and the head block is the one the table read there when it kept
    /// that block's hash.
    async fn is_prefix(&self, marks: &[Mark], head: u64) -> Result<bool, FollowError> {
        if let Some(mark) = marks.iter().rev().find(|mark| mark.block <= head) {
            if self.chain.block_hash(mark.block).await? != Some(mark.hash) {
                return Ok(false);
            }
        }
        Ok(match self.read_hash(head) {
            Some(hash) => self.chain.block_hash(head).await? == Some(hash),
            None => true,
        })
    }

    /// Rewind the table to `mark`, or to nothing.
    fn back_to(&mut self, mark: Option<Mark>) -> Result<Step, FollowError> {
        let held = self.store.leaf_count();
        let to = match mark {
            Some(mark) => self.checkpoint_at(mark.leaf_count, Some(mark.block))?,
            // Deeper than every mark: index the pool again from its deployment.
            None => self.checkpoint_at(0, None)?,
        };
        self.store.rewind(&to)?;
        self.recent
            .retain(|(number, _)| Some(*number) <= to.final_block);
        self.upper
            .truncate(usize::try_from(to.leaf_count / BLOCK_LEAVES).unwrap_or(0));
        self.reset()?;
        self.lagged = 0;
        self.refused = None;
        Ok(Step::Rewound {
            leaves: to.leaf_count..held,
            block: to.final_block,
        })
    }

    /// Where an indexer stood after the first `n` leaves, at `block`.
    fn checkpoint_at(&self, n: u64, block: Option<u64>) -> Result<Checkpoint, FollowError> {
        let tail = self
            .store
            .leaf_block(u32::try_from(n.saturating_sub(1) / BLOCK_LEAVES).unwrap_or(u32::MAX));
        let tail = nodes(tail.leaves);
        let (side, root) = TreeView {
            n,
            upper: &self.upper,
            tail: &tail,
        }
        .frontier()?;
        let mut frontier = [[0u8; 32]; TREE_DEPTH];
        for (slot, node) in frontier.iter_mut().zip(side) {
            *slot = node;
        }
        Ok(Checkpoint {
            leaf_count: n,
            final_block: block,
            root,
            frontier,
        })
    }
}
