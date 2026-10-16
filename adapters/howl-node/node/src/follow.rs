//! Keeps the table on the chain's newest block, rewinding when the chain reorganises.
//!
//! Each step reads the blocks after the table's last one, up to the head, and appends their
//! leaves with the hash of the final block. Leaves are served as soon as their block is read:
//! every answer names the block it reflects and the wallet decides how deep a block it
//! trusts. A step compares the hash recorded for the table's last block with the chain's
//! before it reads and again before it applies what it read, so a read that straddles a
//! reorganisation is never applied. When they differ the chain reorganised below the tip:
//! the table goes back to the newest recorded block the chain still has, and the step reads
//! on from there. A leaf whose logged root the table cannot reproduce means the table's rows
//! are not the chain's even where the hashes agree, and the table goes back one more mark.

use std::ops::Range;

use howl_indexer::{Checkpoint, IndexError, Indexer, IndexerConfig, TREE_DEPTH};
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
        let to = head.min(from.saturating_add(self.range - 1));
        let Some(hash) = self.chain.block_hash(to).await? else {
            return Ok(Step::Moved);
        };
        let logs = self.chain.logs(from, to).await?;
        let count = self.chain.leaf_count(to).await?;
        // The table's last block still there, and `to` unchanged on both sides of that look:
        // `to` descends from it, so the reads continue the table.
        if let Some(step) = self.reorganised().await? {
            return Ok(step);
        }
        if self.chain.block_hash(to).await? != Some(hash) {
            return Ok(Step::Moved);
        }
        let held = self.store.leaf_count();
        let batch = match self.indexer.ingest(to, &logs, count) {
            Ok(batch) => batch,
            Err(e) => {
                self.reset()?;
                if matches!(e, IndexError::RootMismatch { .. }) {
                    // The chain's tree does not continue the table's: rows below the newest
                    // mark belong to another fork, whatever the hashes say.
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
        let mut fresh = upper_of(&self.store, self.upper.len() as u64)?;
        self.upper.append(&mut fresh);
        Ok(Step::Read {
            leaves: held..self.store.leaf_count(),
            block: to,
        })
    }

    fn reset(&mut self) -> Result<(), FollowError> {
        self.indexer = Indexer::resume(self.config, self.store.resume_point())?;
        Ok(())
    }

    /// Go back to the newest mark the chain still has, when the newest one is gone. A newest
    /// block missing above the head, with the newest mark at or below the head intact, is
    /// waited for [`LAG_STEPS`] steps: a load-balanced endpoint may answer from a replica
    /// behind the one the table was read from.
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
                let below = marks.iter().rev().find(|mark| mark.block <= head);
                let intact = match below {
                    Some(mark) => self.chain.block_hash(mark.block).await? == Some(mark.hash),
                    None => true,
                };
                if head < newest.block && intact {
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

    /// Rewind the table to `mark`, or to nothing.
    fn back_to(&mut self, mark: Option<Mark>) -> Result<Step, FollowError> {
        let held = self.store.leaf_count();
        let to = match mark {
            Some(mark) => self.checkpoint_at(mark.leaf_count, Some(mark.block))?,
            // Deeper than every mark: index the pool again from its deployment.
            None => self.checkpoint_at(0, None)?,
        };
        self.store.rewind(&to)?;
        self.upper
            .truncate(usize::try_from(to.leaf_count / BLOCK_LEAVES).unwrap_or(0));
        self.reset()?;
        self.lagged = 0;
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
