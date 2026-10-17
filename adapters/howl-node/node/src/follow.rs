//! Keeps the table on the chain's newest block, rewinding when the chain reorganises.
//!
//! Each step reads the blocks after the table's last one, up to the head, and appends their
//! leaves with the hash of the final block. Leaves are served as soon as their block is read:
//! every answer names the block it reflects and the wallet decides how deep a block it
//! trusts. A step first compares the hash recorded for the table's last block with the
//! chain's. When they differ the chain reorganised below the tip: the table goes back to the
//! newest recorded block the chain still has, and the step reads on from there.
//!
//! Within [`WALK_BLOCKS`] of the head a step also reads the header of every block it covers.
//! The headers must link to each other and to the table's last block, every log must name one
//! of them, and the pool's leaf count is read at the final header's hash. Leaves are applied
//! only in order and only up to that count, so the leaves applied are all of the walked
//! chain's, whatever the endpoint answered between reads. Deeper ranges are checked by reading
//! the final block's hash on both sides of the table's own check, and their count at that
//! hash. A leaf whose logged root the table cannot reproduce, or that does not follow the
//! table's last, means the table's rows are not the chain's even where the hashes agree, and
//! the table goes back one more mark; so does a count refused twice at the same block.

use std::collections::VecDeque;
use std::ops::Range;

use howl_indexer::{Checkpoint, IndexError, Indexer, IndexerConfig, RawLog, TREE_DEPTH};
use howl_store::{Mark, NoteStore, StoreError, MAX_BATCH_ROWS};
use howl_wire::tree::{block_node, Node, TreeError, TreeView, BLOCK_LEAVES};

use crate::chain::{Chain, ChainError};

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

/// Blocks below the head within which a step reads the header of every block it covers. Two
/// epochs: on Ethereum a block this deep is final, and a reorganisation reaching below it is
/// still healed by the root check.
pub const WALK_BLOCKS: u64 = 64;

/// Hashes of read blocks kept to tell a replica behind from a chain that replaced them.
const RECENT_BLOCKS: usize = 256;

/// Blocks a step read and checked, ready to index.
struct Span {
    to: u64,
    /// Hash of each block whose hash the step established, ascending; `to`'s is the last.
    hashes: Vec<(u64, [u8; 32])>,
    logs: Vec<RawLog>,
    count: Option<u64>,
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
    /// `max_range` bounds the blocks one read covers.
    ///
    /// # Errors
    /// [`FollowError`] when the table's resume point does not reproduce its root.
    pub fn new(
        chain: C,
        store: NoteStore,
        config: IndexerConfig,
        max_range: u64,
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
            range: max_range,
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
        let span = if head - from < WALK_BLOCKS {
            self.read_walked(from, head.min(last)).await?
        } else {
            self.read_deep(from, (head - WALK_BLOCKS).min(last)).await?
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
        if batch.leaves.len() > MAX_BATCH_ROWS {
            // Too many leaves for one frame: read a shorter range next time.
            self.reset()?;
            self.range = (self.range / 2).max(1);
            return Ok(Step::Moved);
        }
        if let Err(e) = self.store.append_at(&batch, hash) {
            self.reset()?;
            return Err(e.into());
        }
        self.range = self.max_range;
        self.refused = None;
        self.remember(&span.hashes);
        let mut fresh = upper_of(&self.store, self.upper.len() as u64)?;
        self.upper.append(&mut fresh);
        Ok(Step::Read {
            leaves: held..self.store.leaf_count(),
            block: span.to,
        })
    }

    /// Blocks `from..=to`, settled: `to` is read on both sides of the table's own check, so it
    /// descends from the table's last block.
    async fn read_deep(&mut self, from: u64, to: u64) -> Result<Result<Span, Step>, FollowError> {
        let Some(hash) = self.chain.block_hash(to).await? else {
            return Ok(Err(Step::Moved));
        };
        let logs = self.chain.logs(from, to).await?;
        let count = self.chain.leaf_count(hash).await?;
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
            count,
        }))
    }

    /// Blocks `from..=to` near the head: every header read, linked to the next and to the
    /// table's last block, every log on one of them, and the count at `to`'s.
    async fn read_walked(&mut self, from: u64, to: u64) -> Result<Result<Span, Step>, FollowError> {
        let logs = self.chain.logs(from, to).await?;
        let mut hashes = Vec::new();
        let mut parent = None;
        for number in (from..=to).rev() {
            let Some(header) = self.chain.header(number).await? else {
                return Ok(Err(Step::Moved));
            };
            if parent.is_some_and(|parent| parent != header.hash) {
                return Ok(Err(Step::Moved));
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
        let Some(&(_, newest)) = hashes.last() else {
            return Ok(Err(Step::Moved));
        };
        let count = self.chain.leaf_count(newest).await?;
        Ok(Ok(Span {
            to,
            hashes,
            logs: logs.into_iter().map(|logged| logged.log).collect(),
            count,
        }))
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
