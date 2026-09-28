//! Coverage-proven store resolution for the wallet-shim routes.
//!
//! The shim answers questions whose domain is a whole list or a whole commit tree: a 404 and
//! the end of an index segment are claims about ABSENCE, and absence is only sound over a
//! complete domain. A store that holds one 65,536-row block of a 358,320-row list can answer
//! neither, yet every such answer is a well-formed 200.
//!
//! So a route never reaches a store directly. It proves coverage first, and a failed proof
//! names the rule that failed.

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use raven_railgun_engine::inspire::LogicalLeafStore;
use raven_railgun_engine::orchestrator::{DataSourceFilter, LEAVES_PER_PPOI_BLOCK};
use sha2::{Digest, Sha256};

use crate::poi_shim::BC_INDEX_PREFIX_BYTES;

/// Shared logical leaf store, as the orchestrator hands it out per instance.
pub type SharedLogicalStore = Arc<parking_lot::Mutex<LogicalLeafStore>>;

/// Upstream's own row count for one list, and how long ago it gave it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamTip {
    /// Rows upstream held when its answer came back short of a full page.
    pub rows: u64,
    /// Seconds since that answer.
    pub age_secs: u64,
}

/// Oldest upstream count a frontier may rest on. A caught-up mirror renews it every poll, and
/// this outlasts two failed polls in a row; the boot that wires the two pins that against the
/// mirror's own timings. Past it the list routes refuse rather than answer absence over rows
/// upstream may have added since.
pub const UPSTREAM_TIP_MAX_AGE_SECS: u64 = 120;

/// What a shim route could not prove about the stores it was given.
///
/// Every variant names the list key or tree and the rule that failed, because a bare 503
/// is the same signal as a crashed process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverageRefusal {
    /// No wired store declares any part of this list.
    NoListStore {
        /// List key asked about.
        list_key: [u8; 32],
    },
    /// Two stores declare the same block of one list; picking one silently is the defect.
    DuplicateBlock {
        /// List key asked about.
        list_key: [u8; 32],
        /// Block declared more than once.
        block: u32,
    },
    /// The declared blocks are not `0..=k`: rows between the gap's edges are held by nobody.
    BlockGap {
        /// List key asked about.
        list_key: [u8; 32],
        /// Block number the contiguous run needed next.
        expected_block: u32,
        /// Block number actually found there.
        found_block: u32,
    },
    /// A block is short while a later declared block holds rows, so the list has a hole.
    ShortBlock {
        /// List key asked about.
        list_key: [u8; 32],
        /// Block that is short.
        block: u32,
        /// Rows it holds.
        held: u32,
        /// Rows a sealed block must hold.
        expected: u32,
    },
    /// Every declared block is full, so a successor block may exist upstream and is wired to
    /// nothing. Refused rather than guessed.
    FrontierFull {
        /// List key asked about.
        list_key: [u8; 32],
        /// The full frontier block.
        block: u32,
    },
    /// The frontier block is short of full, and upstream has not said recently enough that
    /// the list ends where the local rows do. Rows past them may exist upstream and nothing
    /// local holds them, so contiguity alone proves nothing about the tip.
    FrontierUnanchored {
        /// List key asked about.
        list_key: [u8; 32],
        /// The frontier block.
        block: u32,
        /// Rows held across the covered prefix, list-wide.
        held: u64,
        /// Upstream's latest count, when it has stated one.
        asserted: Option<UpstreamTip>,
    },
    /// A block's rows do not sit at the indices its tree counts, so reading it gives no
    /// gap-free prefix.
    TornBlock {
        /// List key asked about.
        list_key: [u8; 32],
        /// Block whose rows are out of place.
        block: u32,
    },
    /// No wired store declares this commit tree.
    NoTreeStore {
        /// Tree asked about.
        tree_number: u32,
    },
    /// Two stores declare the same commit tree.
    DuplicateTree {
        /// Tree declared more than once.
        tree_number: u32,
    },
}

impl std::fmt::Display for CoverageRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoListStore { list_key } => {
                write!(f, "no wired store declares list {}", hex32(list_key))
            }
            Self::DuplicateBlock { list_key, block } => write!(
                f,
                "list {} block {block} is declared by more than one instance",
                hex32(list_key)
            ),
            Self::BlockGap {
                list_key,
                expected_block,
                found_block,
            } => write!(
                f,
                "list {} is missing block {expected_block}; next declared block is {found_block}",
                hex32(list_key)
            ),
            Self::ShortBlock {
                list_key,
                block,
                held,
                expected,
            } => write!(
                f,
                "list {} block {block} holds {held} of {expected} rows while a later block \
                 holds rows, so the list has a hole",
                hex32(list_key)
            ),
            Self::FrontierFull { list_key, block } => write!(
                f,
                "list {} block {block} is full at {LEAVES_PER_PPOI_BLOCK} rows and no successor \
                 block is wired, so rows past it are held by nobody",
                hex32(list_key)
            ),
            Self::FrontierUnanchored {
                list_key,
                block,
                held,
                asserted,
            } => {
                write!(
                    f,
                    "list {} frontier block {block} ends at {held} rows list-wide and ",
                    hex32(list_key)
                )?;
                match asserted {
                    None => write!(f, "upstream has stated no row count"),
                    Some(tip) if tip.age_secs > UPSTREAM_TIP_MAX_AGE_SECS => write!(
                        f,
                        "upstream's last count, {} rows, is {} s old, past the {} s bound",
                        tip.rows, tip.age_secs, UPSTREAM_TIP_MAX_AGE_SECS
                    ),
                    Some(tip) => write!(
                        f,
                        "upstream counted {} rows {} s ago",
                        tip.rows, tip.age_secs
                    ),
                }?;
                write!(
                    f,
                    ", so rows past the local ones may exist and are held by nobody"
                )
            }
            Self::TornBlock { list_key, block } => write!(
                f,
                "list {} block {block} holds rows that do not sit at the indices its tree \
                 counts, so it is no gap-free prefix",
                hex32(list_key)
            ),
            Self::NoTreeStore { tree_number } => {
                write!(f, "no wired store declares commit tree {tree_number}")
            }
            Self::DuplicateTree { tree_number } => write!(
                f,
                "commit tree {tree_number} is declared by more than one instance"
            ),
        }
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Every logical store a shim route may reach, each tagged with the routing filter its
/// instance was configured with. Installed once at boot; without it every shim route refuses.
#[derive(Debug, Default)]
pub struct ShimStoreRegistry {
    ppoi_blocks: BTreeMap<([u8; 32], u32), Vec<SharedLogicalStore>>,
    chain_trees: BTreeMap<u32, Vec<SharedLogicalStore>>,
    publishing: Publishing,
}

/// Index-channel segments read at once. A read holds a blocking-pool thread for up to one
/// block's walk and `/batch` responds on that pool, so a flood of segment requests waits here
/// instead of taking the threads a query needs.
pub const SEGMENT_READS_AT_ONCE: usize = 4;

/// What the index channel keeps between requests: the read permits, and each sealed block's
/// body, so a repeat for a sealed block reads, copies and hashes no rows.
#[derive(Debug)]
pub(crate) struct Publishing {
    segment_reads: Arc<tokio::sync::Semaphore>,
    sealed: parking_lot::Mutex<BTreeMap<([u8; 32], u32), SealedBlock>>,
    #[cfg(test)]
    probes: Probes,
}

impl Default for Publishing {
    fn default() -> Self {
        Self {
            segment_reads: Arc::new(tokio::sync::Semaphore::new(SEGMENT_READS_AT_ONCE)),
            sealed: parking_lot::Mutex::default(),
            #[cfg(test)]
            probes: Probes::default(),
        }
    }
}

/// A sealed block's whole prefix body and the rows stamp it was read at. While the store's stamp
/// is unchanged no row was added or removed, so these are still the block's bytes; one entry per
/// declared block.
#[derive(Debug, Clone)]
struct SealedBlock {
    rows_stamp: u64,
    prefixes: Bytes,
    etag: String,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct Probes {
    blocks_walked: std::sync::atomic::AtomicUsize,
    rows_read: std::sync::atomic::AtomicUsize,
    segment_reads_now: std::sync::atomic::AtomicUsize,
    segment_reads_peak: std::sync::atomic::AtomicUsize,
}

/// Counts one segment read as running until dropped.
#[cfg(test)]
pub(crate) struct SegmentReadProbe<'a>(&'a Probes);

#[cfg(test)]
impl Drop for SegmentReadProbe<'_> {
    fn drop(&mut self) {
        self.0
            .segment_reads_now
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// One `since` read of the prefix channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexSegment {
    /// Global index one past the last row read.
    pub next: u32,
    /// The segment's block was read full, so its rows can never change.
    pub sealed: bool,
    /// The first [`BC_INDEX_PREFIX_BYTES`] bytes of each row from `since` on, in index order.
    pub prefixes: Bytes,
    /// Quoted SHA-256(`prefixes`)[..16] hex.
    pub etag: String,
}

/// Why a prefix-channel segment was not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SegmentRefusal {
    /// `since` is past every row held.
    PastFrontier {
        /// Rows the covered prefix holds, list-wide.
        total: u32,
    },
    /// What was read is no gap-free prefix of the list.
    Uncovered(CoverageRefusal),
}

impl ShimStoreRegistry {
    /// Build from `(filter, store)` declarations, one per configured instance.
    pub fn from_declarations<I>(declarations: I) -> Self
    where
        I: IntoIterator<Item = (DataSourceFilter, SharedLogicalStore)>,
    {
        let mut registry = Self::default();
        for (filter, store) in declarations {
            match filter {
                DataSourceFilter::ChainTreeNumber(tree_number) => {
                    registry
                        .chain_trees
                        .entry(tree_number)
                        .or_default()
                        .push(store);
                }
                DataSourceFilter::PpoiListBlock { list_key, block } => {
                    registry
                        .ppoi_blocks
                        .entry((list_key, block))
                        .or_default()
                        .push(store);
                }
            }
        }
        registry
    }

    /// Permits for index-channel segment reads.
    pub(crate) fn segment_reads(&self) -> &Arc<tokio::sync::Semaphore> {
        &self.publishing.segment_reads
    }

    /// Blocks whose rows were walked through this registry's coverages.
    #[cfg(test)]
    pub(crate) fn blocks_walked(&self) -> usize {
        self.publishing
            .probes
            .blocks_walked
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Index rows read through this registry's coverages, a count included.
    #[cfg(test)]
    pub(crate) fn rows_read(&self) -> usize {
        self.publishing
            .probes
            .rows_read
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Mark one segment read as running until the probe drops.
    #[cfg(test)]
    pub(crate) fn segment_read_probe(&self) -> SegmentReadProbe<'_> {
        use std::sync::atomic::Ordering::SeqCst;
        let probes = &self.publishing.probes;
        let now = probes.segment_reads_now.fetch_add(1, SeqCst) + 1;
        probes.segment_reads_peak.fetch_max(now, SeqCst);
        SegmentReadProbe(probes)
    }

    /// Segment reads running now, and the most ever running at once.
    #[cfg(test)]
    pub(crate) fn segment_reads_now_and_peak(&self) -> (usize, usize) {
        use std::sync::atomic::Ordering::SeqCst;
        let probes = &self.publishing.probes;
        (
            probes.segment_reads_now.load(SeqCst),
            probes.segment_reads_peak.load(SeqCst),
        )
    }

    /// True when no declaration the shim answers from was supplied.
    pub fn is_empty(&self) -> bool {
        self.ppoi_blocks.is_empty() && self.chain_trees.is_empty()
    }

    /// Resolve the single store declared for `tree_number`.
    pub fn prove_tree(&self, tree_number: u32) -> Result<&SharedLogicalStore, CoverageRefusal> {
        let declared = self
            .chain_trees
            .get(&tree_number)
            .ok_or(CoverageRefusal::NoTreeStore { tree_number })?;
        match declared.as_slice() {
            [single] => Ok(single),
            _ => Err(CoverageRefusal::DuplicateTree { tree_number }),
        }
    }

    /// Prove that the declared blocks hold a gap-free prefix of `list_key` whose frontier is
    /// not sitting on the per-IMT capacity wall, and reaches at least as far as `tip`, the
    /// count upstream gave for the list no more than [`UPSTREAM_TIP_MAX_AGE_SECS`] ago. Blocks
    /// declared past the frontier may be empty, since that count ends the list before them.
    pub fn prove_list_coverage(
        &self,
        list_key: &[u8; 32],
        tip: Option<UpstreamTip>,
    ) -> Result<ListCoverage<'_>, CoverageRefusal> {
        let declared: Vec<(u32, &Vec<SharedLogicalStore>)> = self
            .ppoi_blocks
            .range((*list_key, 0u32)..)
            .take_while(|((key, _), _)| key == list_key)
            .map(|((_, block), stores)| (*block, stores))
            .collect();
        if declared.is_empty() {
            return Err(CoverageRefusal::NoListStore {
                list_key: *list_key,
            });
        }

        let mut blocks: Vec<&SharedLogicalStore> = Vec::with_capacity(declared.len());
        for (position, (block, stores)) in declared.iter().enumerate() {
            let expected_block = u32::try_from(position).unwrap_or(u32::MAX);
            if *block != expected_block {
                return Err(CoverageRefusal::BlockGap {
                    list_key: *list_key,
                    expected_block,
                    found_block: *block,
                });
            }
            match stores.as_slice() {
                [single] => blocks.push(single),
                _ => {
                    return Err(CoverageRefusal::DuplicateBlock {
                        list_key: *list_key,
                        block: *block,
                    })
                }
            }
        }

        let coverage = ListCoverage {
            list_key: *list_key,
            blocks,
            publishing: &self.publishing,
        };
        coverage.prove_prefix(tip)?;
        Ok(coverage)
    }
}

/// Rows of the gap-free prefix `held` describes: every full block, then the first short one.
fn contiguous_rows(held: &[u32]) -> u64 {
    let mut total = 0u64;
    for &rows in held {
        total = total.saturating_add(u64::from(rows));
        if rows < LEAVES_PER_PPOI_BLOCK {
            break;
        }
    }
    total
}

/// Quoted SHA-256(body)[..16] hex.
pub(crate) fn body_etag(body: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(body);
    let mut etag = String::with_capacity(2 + 32);
    etag.push('"');
    for b in digest.iter().take(16) {
        let _ = write!(etag, "{b:02x}");
    }
    etag.push('"');
    etag
}

/// A proven gap-free prefix of one list, in block order. Index in `blocks` is the block number.
#[derive(Debug)]
pub struct ListCoverage<'a> {
    list_key: [u8; 32],
    blocks: Vec<&'a SharedLogicalStore>,
    publishing: &'a Publishing,
}

impl ListCoverage<'_> {
    fn prove_prefix(&self, tip: Option<UpstreamTip>) -> Result<(), CoverageRefusal> {
        let held: Vec<u32> = self
            .blocks
            .iter()
            .map(|store| self.held_rows(store))
            .collect();
        let frontier = held
            .iter()
            .position(|&rows| rows < LEAVES_PER_PPOI_BLOCK)
            .unwrap_or_else(|| held.len().saturating_sub(1));
        let block = u32::try_from(frontier).unwrap_or(u32::MAX);
        let frontier_rows = held.get(frontier).copied().unwrap_or(0);
        if frontier_rows >= LEAVES_PER_PPOI_BLOCK {
            return Err(CoverageRefusal::FrontierFull {
                list_key: self.list_key,
                block,
            });
        }
        // An operator declares the next block before the current one fills, so a block past the
        // frontier may sit empty; one holding a row leaves a hole under it.
        if held.iter().skip(frontier + 1).any(|&rows| rows > 0) {
            return Err(CoverageRefusal::ShortBlock {
                list_key: self.list_key,
                block,
                held: frontier_rows,
                expected: LEAVES_PER_PPOI_BLOCK,
            });
        }
        let held_total =
            u64::from(block) * u64::from(LEAVES_PER_PPOI_BLOCK) + u64::from(frontier_rows);
        // A contiguous prefix says nothing about where upstream's list ends: a cold sync, or a
        // restart that missed rows, leaves the frontier short while upstream holds more. Only
        // upstream's own recent count says the rows past the local ones do not exist, and the
        // same count puts every block past the frontier beyond the list's end.
        let current = tip
            .is_some_and(|tip| tip.age_secs <= UPSTREAM_TIP_MAX_AGE_SECS && held_total >= tip.rows);
        if !current {
            return Err(CoverageRefusal::FrontierUnanchored {
                list_key: self.list_key,
                block,
                held: held_total,
                asserted: tip,
            });
        }
        Ok(())
    }

    /// Re-check the frontier after the answer was read.
    ///
    /// The proof and the read are separate lock acquisitions, and the list grows in between.
    /// If the last declared block reached capacity meanwhile, rows past it may exist upstream
    /// and are held by nobody, so the answer just read is no longer a complete prefix.
    pub fn recheck_frontier(&self) -> Result<(), CoverageRefusal> {
        let Some(store) = self.blocks.last() else {
            return Ok(());
        };
        let block = u32::try_from(self.blocks.len().saturating_sub(1)).unwrap_or(u32::MAX);
        if self.held_rows(store) >= LEAVES_PER_PPOI_BLOCK {
            return Err(CoverageRefusal::FrontierFull {
                list_key: self.list_key,
                block,
            });
        }
        Ok(())
    }

    /// Rows held for this list, from the IMT leaf count rather than a scan: appends are
    /// contiguous from zero by `checked_imt_append`, so the count IS the frontier.
    fn held_rows(&self, store: &SharedLogicalStore) -> u32 {
        self.block_rows(&store.lock())
    }

    /// Height the composed answer is complete as of: the lowest any contributor has reached.
    pub fn epoch(&self) -> u64 {
        self.blocks
            .iter()
            .map(|store| store.lock().last_block_height())
            .min()
            .unwrap_or(0)
    }

    /// Row count of one block, read under the caller's lock.
    fn block_rows(&self, store: &LogicalLeafStore) -> u32 {
        store
            .ppoi_imt(&self.list_key)
            .map_or(0, |imt| u32::try_from(imt.leaf_count()).unwrap_or(u32::MAX))
    }

    /// One block's index in local-index order. Every read of the index goes through here, so the
    /// test probe counts each row a request reads, a bare count included.
    fn index_rows<'g>(
        &'g self,
        guard: &'g LogicalLeafStore,
    ) -> impl Iterator<Item = (u32, &'g [u8; 32])> + 'g {
        guard.ppoi_list_leaves_iter(&self.list_key).inspect(|_| {
            #[cfg(test)]
            self.publishing
                .probes
                .rows_read
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })
    }

    /// Hand each of one block's rows to `visit` in local-index order under the caller's lock,
    /// and return the block's row count. A block whose rows do not sit at the indices its tree
    /// counts gives no gap-free prefix, so it is refused.
    fn walk_block(
        &self,
        guard: &LogicalLeafStore,
        block: u32,
        visit: &mut dyn FnMut(&[u8; 32]),
    ) -> Result<u32, CoverageRefusal> {
        #[cfg(test)]
        self.publishing
            .probes
            .blocks_walked
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let count = self.block_rows(guard);
        let mut read = 0u32;
        for (local, bc) in self.index_rows(guard) {
            if local != read {
                return Err(self.torn(block));
            }
            visit(bc);
            read = read.saturating_add(1);
        }
        if read != count {
            return Err(self.torn(block));
        }
        Ok(count)
    }

    /// Every row's prefix in one block, its row count, and the body's ETag when the block is
    /// sealed. A sealed block whose rows stamp is the one its body was read at is answered from
    /// that body without reading a row. The root alone would not do: it does not move when a
    /// reorg drops a middle row, and the stamp does.
    fn block_prefixes(
        &self,
        store: &SharedLogicalStore,
        block: u32,
    ) -> Result<(u32, Bytes, Option<String>), CoverageRefusal> {
        let guard = store.lock();
        let rows_stamp = guard.list_rows_stamp();
        let count = self.block_rows(&guard);
        if count >= LEAVES_PER_PPOI_BLOCK {
            let kept = self
                .publishing
                .sealed
                .lock()
                .get(&(self.list_key, block))
                .filter(|kept| kept.rows_stamp == rows_stamp)
                .cloned();
            if let Some(kept) = kept {
                return Ok((count, kept.prefixes, Some(kept.etag)));
            }
        }
        let mut body = Vec::with_capacity(
            usize::try_from(count)
                .unwrap_or(0)
                .saturating_mul(BC_INDEX_PREFIX_BYTES),
        );
        let walked = self.walk_block(&guard, block, &mut |bc| {
            body.extend(bc.iter().copied().take(BC_INDEX_PREFIX_BYTES));
        });
        drop(guard);
        let read = match walked {
            Ok(walked) => walked,
            Err(refusal) => {
                self.publishing
                    .sealed
                    .lock()
                    .remove(&(self.list_key, block));
                return Err(refusal);
            }
        };
        let prefixes = Bytes::from(body);
        if read < LEAVES_PER_PPOI_BLOCK {
            return Ok((read, prefixes, None));
        }
        let etag = body_etag(&prefixes);
        self.publishing.sealed.lock().insert(
            (self.list_key, block),
            SealedBlock {
                rows_stamp,
                prefixes: prefixes.clone(),
                etag: etag.clone(),
            },
        );
        Ok((read, prefixes, Some(etag)))
    }

    /// Read the prefix-channel segment starting at global index `since`: the rows of that one
    /// block from `since` on.
    ///
    /// Only that block's rows are read, so a row's position in the segment is its global index
    /// by construction. The segment is sealed only when its block was read full; a short one is
    /// the frontier, and a later block holding rows under it is refused as a hole.
    pub fn segment(&self, since: u32) -> Result<IndexSegment, SegmentRefusal> {
        self.segment_with(since, &mut |_| {})
    }

    fn segment_with(
        &self,
        since: u32,
        between_blocks: &mut dyn FnMut(u32),
    ) -> Result<IndexSegment, SegmentRefusal> {
        let block = since / LEAVES_PER_PPOI_BLOCK;
        let base = block * LEAVES_PER_PPOI_BLOCK;
        let held: Vec<u32> = self
            .blocks
            .iter()
            .map(|store| self.held_rows(store))
            .collect();
        let total = contiguous_rows(&held);
        if u64::from(since) > total {
            return Err(SegmentRefusal::PastFrontier {
                total: u32::try_from(total).unwrap_or(u32::MAX),
            });
        }
        let position = usize::try_from(block).unwrap_or(usize::MAX);
        let (read, whole, sealed_etag) = match self.blocks.get(position) {
            None => (0, Bytes::new(), None),
            Some(store) => self
                .block_prefixes(store, block)
                .map_err(SegmentRefusal::Uncovered)?,
        };
        between_blocks(block);
        let next = base.saturating_add(read);
        if since > next {
            return Err(SegmentRefusal::PastFrontier { total: next });
        }
        let sealed = read >= LEAVES_PER_PPOI_BLOCK;
        if !sealed {
            let later = self.blocks.iter().skip(position.saturating_add(1));
            if later
                .map(|store| self.held_rows(store))
                .any(|rows| rows > 0)
            {
                return Err(SegmentRefusal::Uncovered(CoverageRefusal::ShortBlock {
                    list_key: self.list_key,
                    block,
                    held: read,
                    expected: LEAVES_PER_PPOI_BLOCK,
                }));
            }
        }
        let skip = usize::try_from(since - base)
            .unwrap_or(usize::MAX)
            .saturating_mul(BC_INDEX_PREFIX_BYTES)
            .min(whole.len());
        let prefixes = whole.slice(skip..);
        let etag = match sealed_etag {
            Some(etag) if skip == 0 => etag,
            _ => body_etag(&prefixes),
        };
        Ok(IndexSegment {
            next,
            sealed,
            prefixes,
            etag,
        })
    }

    fn torn(&self, block: u32) -> CoverageRefusal {
        CoverageRefusal::TornBlock {
            list_key: self.list_key,
            block,
        }
    }

    /// The block that holds `blinded_commitment`, as `(store, local_index)`.
    pub fn owner_of(&self, blinded_commitment: &[u8; 32]) -> Option<(&SharedLogicalStore, u32)> {
        self.blocks.iter().find_map(|store| {
            let local = store
                .lock()
                .ppoi_index_of(&self.list_key, blinded_commitment)?;
            Some((*store, local))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_railgun_engine::inspire::apply_wal_entry;
    use raven_railgun_engine::pir_table::PerLeafCommitmentEncoder;
    use raven_railgun_persistence::WalEntryPayload;

    const LIST_KEY: [u8; 32] = [0x42; 32];

    fn encoder() -> PerLeafCommitmentEncoder {
        PerLeafCommitmentEncoder::new(32, 65_536, 0).expect("encoder")
    }

    /// Canonical BN254 Fr: the top byte stays zero so the value is under the modulus. The seed
    /// also sits in the six-byte prefix the index channel publishes, so rows stay apart there.
    fn fr(seed: u32) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[1..5].copy_from_slice(&seed.to_be_bytes());
        out[28..].copy_from_slice(&seed.to_be_bytes());
        out[20] = 0x01;
        out
    }

    fn prefixes(seeds: std::ops::Range<u32>) -> Vec<u8> {
        seeds
            .flat_map(|seed| fr(seed).into_iter().take(BC_INDEX_PREFIX_BYTES))
            .collect()
    }

    fn block_store(local_indices: std::ops::Range<u32>, seed_base: u32) -> SharedLogicalStore {
        let store = Arc::new(parking_lot::Mutex::new(LogicalLeafStore::new()));
        append(&store, local_indices, seed_base);
        store
    }

    /// Append rows at `local_indices`, each at height `1_000 + local`.
    fn append(store: &SharedLogicalStore, local_indices: std::ops::Range<u32>, seed_base: u32) {
        let enc = encoder();
        let mut guard = store.lock();
        for local in local_indices {
            apply_wal_entry(
                &mut guard,
                &WalEntryPayload::PpoiListLeafAdded {
                    list_key: LIST_KEY,
                    list_index: local,
                    blinded_commitment: fr(seed_base.saturating_add(local)),
                    event_type: raven_railgun_persistence::PpoiEventType::Shield,
                    validated_merkleroot: [0; 32],
                },
                1_000 + u64::from(local),
                &enc,
            )
            .expect("seed ppoi leaf");
        }
    }

    /// A short block 0 with four rows and an empty block 1 the test can grow mid-read, proven
    /// at upstream's count of four.
    fn short_block_then_empty() -> (ShimStoreRegistry, SharedLogicalStore) {
        let block_one = block_store(0..0, 100);
        let registry = ShimStoreRegistry::from_declarations([
            (block_filter(0), block_store(0..4, 0)),
            (block_filter(1), Arc::clone(&block_one)),
        ]);
        (registry, block_one)
    }

    fn block_filter(block: u32) -> DataSourceFilter {
        DataSourceFilter::PpoiListBlock {
            list_key: LIST_KEY,
            block,
        }
    }

    fn counted(rows: u64, age_secs: u64) -> UpstreamTip {
        UpstreamTip { rows, age_secs }
    }

    fn unanchored(held: u64, asserted: Option<UpstreamTip>) -> CoverageRefusal {
        CoverageRefusal::FrontierUnanchored {
            list_key: LIST_KEY,
            block: 0,
            held,
            asserted,
        }
    }

    #[test]
    fn a_single_short_block_covers_the_list_it_declares() {
        let registry =
            ShimStoreRegistry::from_declarations([(block_filter(0), block_store(0..4, 0))]);
        let coverage = registry
            .prove_list_coverage(&LIST_KEY, Some(counted(4, 0)))
            .expect("covered");
        let segment = coverage.segment(0).expect("read");
        assert_eq!(segment.next, 4);
        assert_eq!(segment.prefixes.to_vec(), prefixes(0..4));
    }

    #[test]
    fn one_block_of_a_multi_block_list_is_refused_not_answered() {
        // Block 2 alone: the rows it holds are real, but blocks 0 and 1 are held by nobody,
        // so every absence claim over the list is unfounded.
        let registry =
            ShimStoreRegistry::from_declarations([(block_filter(2), block_store(0..4, 0))]);
        assert_eq!(
            registry
                .prove_list_coverage(&LIST_KEY, Some(counted(u64::MAX, 0)))
                .err(),
            Some(CoverageRefusal::BlockGap {
                list_key: LIST_KEY,
                expected_block: 0,
                found_block: 2,
            })
        );
    }

    #[test]
    fn a_gap_between_declared_blocks_is_refused() {
        let registry = ShimStoreRegistry::from_declarations([
            (block_filter(0), block_store(0..4, 0)),
            (block_filter(2), block_store(0..4, 100)),
        ]);
        assert_eq!(
            registry
                .prove_list_coverage(&LIST_KEY, Some(counted(u64::MAX, 0)))
                .err(),
            Some(CoverageRefusal::BlockGap {
                list_key: LIST_KEY,
                expected_block: 1,
                found_block: 2,
            })
        );
    }

    #[test]
    fn a_short_block_under_a_later_one_is_refused() {
        let registry = ShimStoreRegistry::from_declarations([
            (block_filter(0), block_store(0..4, 0)),
            (block_filter(1), block_store(0..4, 100)),
        ]);
        assert_eq!(
            registry
                .prove_list_coverage(&LIST_KEY, Some(counted(u64::MAX, 0)))
                .err(),
            Some(CoverageRefusal::ShortBlock {
                list_key: LIST_KEY,
                block: 0,
                held: 4,
                expected: LEAVES_PER_PPOI_BLOCK,
            })
        );
    }

    /// The next block declared before the current one fills: it holds nothing upstream counts, so
    /// it is covered empty, and the count still decides the frontier under it.
    #[test]
    fn a_block_declared_ahead_of_the_list_is_covered_empty() {
        let registry = ShimStoreRegistry::from_declarations([
            (block_filter(0), block_store(0..4, 0)),
            (block_filter(1), block_store(0..0, 100)),
            (block_filter(2), block_store(0..0, 200)),
        ]);
        let coverage = registry
            .prove_list_coverage(&LIST_KEY, Some(counted(4, 0)))
            .expect("covered");
        assert_eq!(coverage.segment(0).expect("read").next, 4);
        for tip in [None, Some(counted(5, 0))] {
            assert_eq!(
                registry.prove_list_coverage(&LIST_KEY, tip).err(),
                Some(unanchored(4, tip))
            );
        }
    }

    #[test]
    fn a_row_past_an_empty_block_is_a_hole() {
        let registry = ShimStoreRegistry::from_declarations([
            (block_filter(0), block_store(0..4, 0)),
            (block_filter(1), block_store(0..0, 100)),
            (block_filter(2), block_store(0..1, 200)),
        ]);
        assert_eq!(
            registry
                .prove_list_coverage(&LIST_KEY, Some(counted(0, 0)))
                .err(),
            Some(CoverageRefusal::ShortBlock {
                list_key: LIST_KEY,
                block: 0,
                held: 4,
                expected: LEAVES_PER_PPOI_BLOCK,
            })
        );
    }

    #[test]
    fn two_stores_declaring_one_block_are_refused() {
        let registry = ShimStoreRegistry::from_declarations([
            (block_filter(0), block_store(0..4, 0)),
            (block_filter(0), block_store(0..4, 100)),
        ]);
        assert_eq!(
            registry
                .prove_list_coverage(&LIST_KEY, Some(counted(u64::MAX, 0)))
                .err(),
            Some(CoverageRefusal::DuplicateBlock {
                list_key: LIST_KEY,
                block: 0,
            })
        );
    }

    #[test]
    fn an_undeclared_list_is_refused() {
        let registry =
            ShimStoreRegistry::from_declarations([(block_filter(0), block_store(0..4, 0))]);
        let other = [0x99; 32];
        assert_eq!(
            registry
                .prove_list_coverage(&other, Some(counted(0, 0)))
                .err(),
            Some(CoverageRefusal::NoListStore { list_key: other })
        );
    }

    #[test]
    fn a_tree_no_store_declares_is_refused() {
        let registry = ShimStoreRegistry::from_declarations([(
            DataSourceFilter::ChainTreeNumber(0),
            block_store(0..1, 0),
        )]);
        assert!(registry.prove_tree(0).is_ok());
        assert_eq!(
            registry.prove_tree(7).err(),
            Some(CoverageRefusal::NoTreeStore { tree_number: 7 })
        );
    }

    #[test]
    fn two_stores_declaring_one_tree_are_refused() {
        let registry = ShimStoreRegistry::from_declarations([
            (DataSourceFilter::ChainTreeNumber(3), block_store(0..1, 0)),
            (DataSourceFilter::ChainTreeNumber(3), block_store(0..1, 5)),
        ]);
        assert_eq!(
            registry.prove_tree(3).err(),
            Some(CoverageRefusal::DuplicateTree { tree_number: 3 })
        );
    }

    /// The arithmetic the block width pins, without paying 65,536 Poseidon inserts: a
    /// localized index in block `b` is `b * 65_536 + local` and nothing else.
    #[test]
    fn global_index_arithmetic_is_the_inverse_of_the_router_localization() {
        for (global, block, local) in [
            (0u32, 0u32, 0u32),
            (65_535, 0, 65_535),
            (65_536, 1, 0),
            (131_072, 2, 0),
            (358_319, 5, 30_639),
        ] {
            assert_eq!(global / LEAVES_PER_PPOI_BLOCK, block);
            assert_eq!(global % LEAVES_PER_PPOI_BLOCK, local);
            assert_eq!(block * LEAVES_PER_PPOI_BLOCK + local, global);
        }
    }

    #[test]
    fn a_registry_with_no_declarations_reports_empty() {
        assert!(ShimStoreRegistry::default().is_empty());
        assert!(
            !ShimStoreRegistry::from_declarations([(block_filter(0), block_store(0..1, 0))])
                .is_empty()
        );
    }

    #[test]
    fn a_frontier_no_upstream_count_vouches_for_is_refused() {
        let registry =
            ShimStoreRegistry::from_declarations([(block_filter(0), block_store(0..4, 0))]);
        assert_eq!(
            registry.prove_list_coverage(&LIST_KEY, None).err(),
            Some(unanchored(4, None))
        );
    }

    #[test]
    fn a_frontier_behind_upstreams_count_is_refused_and_one_at_or_past_it_is_not() {
        let registry =
            ShimStoreRegistry::from_declarations([(block_filter(0), block_store(0..4, 0))]);
        assert_eq!(
            registry
                .prove_list_coverage(&LIST_KEY, Some(counted(5, 0)))
                .err(),
            Some(unanchored(4, Some(counted(5, 0))))
        );
        // Rows the store applied after upstream's answer still leave it complete as of then.
        for rows in [4, 3] {
            assert!(registry
                .prove_list_coverage(&LIST_KEY, Some(counted(rows, 0)))
                .is_ok());
        }
    }

    #[test]
    fn an_upstream_count_past_the_age_bound_anchors_nothing() {
        let registry =
            ShimStoreRegistry::from_declarations([(block_filter(0), block_store(0..4, 0))]);
        assert!(registry
            .prove_list_coverage(&LIST_KEY, Some(counted(4, UPSTREAM_TIP_MAX_AGE_SECS)))
            .is_ok());
        let stale = Some(counted(4, UPSTREAM_TIP_MAX_AGE_SECS + 1));
        assert_eq!(
            registry.prove_list_coverage(&LIST_KEY, stale).err(),
            Some(unanchored(4, stale))
        );
    }

    /// An empty frontier is refused on its own and answered once upstream says the list is empty
    /// too: the count is the anchor, not the row count.
    #[test]
    fn an_empty_frontier_is_covered_only_when_upstream_counts_it_empty() {
        let registry =
            ShimStoreRegistry::from_declarations([(block_filter(0), block_store(0..0, 0))]);
        assert_eq!(
            registry.prove_list_coverage(&LIST_KEY, None).err(),
            Some(unanchored(0, None))
        );
        assert_eq!(
            registry
                .prove_list_coverage(&LIST_KEY, Some(counted(1, 0)))
                .err(),
            Some(unanchored(0, Some(counted(1, 0))))
        );
        assert!(registry
            .prove_list_coverage(&LIST_KEY, Some(counted(0, 0)))
            .is_ok());
    }

    #[test]
    fn an_unanchored_refusal_names_the_list_the_block_and_both_counts() {
        let refusal = CoverageRefusal::FrontierUnanchored {
            list_key: LIST_KEY,
            block: 5,
            held: 327_697,
            asserted: Some(counted(358_344, 7)),
        };
        let text = refusal.to_string();
        for needle in [
            hex32(&LIST_KEY).as_str(),
            "block 5",
            "327697",
            "358344",
            "7 s",
        ] {
            assert!(text.contains(needle), "{needle} missing from: {text}");
        }
        let stale = CoverageRefusal::FrontierUnanchored {
            list_key: LIST_KEY,
            block: 0,
            held: 3,
            asserted: Some(counted(3, UPSTREAM_TIP_MAX_AGE_SECS + 9)),
        }
        .to_string();
        assert!(stale.contains("past the"), "{stale}");
        let silent = CoverageRefusal::FrontierUnanchored {
            list_key: LIST_KEY,
            block: 0,
            held: 0,
            asserted: None,
        }
        .to_string();
        assert!(silent.contains("no row count"), "{silent}");
    }

    /// The prefix channel reads only the block `since` falls in, so a row's position is its global
    /// index by construction, and rows landing in a later block while the frontier is read are a
    /// hole to refuse, not a segment to serve with block 1's rows renumbered into block 0.
    #[test]
    fn a_segment_reads_only_its_own_block_and_refuses_rows_landing_past_it_mid_read() {
        let (registry, block_one) = short_block_then_empty();
        let coverage = registry
            .prove_list_coverage(&LIST_KEY, Some(counted(4, 0)))
            .expect("covered before the interleaving");
        let walked_before = registry.blocks_walked();
        let segment = coverage.segment_with(0, &mut |block| {
            if block == 0 {
                append(&block_one, 0..2, 100);
            }
        });
        assert_eq!(
            segment,
            Err(SegmentRefusal::Uncovered(CoverageRefusal::ShortBlock {
                list_key: LIST_KEY,
                block: 0,
                held: 4,
                expected: LEAVES_PER_PPOI_BLOCK,
            }))
        );
        assert_eq!(
            registry.blocks_walked() - walked_before,
            1,
            "two blocks are declared, and only the one `since` falls in may have its rows walked"
        );
    }

    /// Position i of a segment is the row at global index `since + i`, and its ETag is the
    /// digest of exactly the bytes served.
    #[test]
    fn a_segment_starts_at_since_and_ends_at_the_frontier() {
        let (registry, _block_one) = short_block_then_empty();
        let coverage = registry
            .prove_list_coverage(&LIST_KEY, Some(counted(4, 0)))
            .expect("covered");
        let tail = coverage.segment(1).expect("read");
        assert_eq!((tail.next, tail.sealed), (4, false));
        assert_eq!(tail.prefixes.to_vec(), prefixes(1..4));
        assert_eq!(tail.etag, body_etag(&prefixes(1..4)));
        let caught_up = coverage.segment(4).expect("read");
        assert_eq!((caught_up.next, caught_up.sealed), (4, false));
        assert!(caught_up.prefixes.is_empty());
        assert_eq!(
            coverage.segment(5),
            Err(SegmentRefusal::PastFrontier { total: 4 })
        );
    }

    /// A reorg that drops a middle row leaves the tree counting past a hole in the index, with
    /// its count, root and height all unchanged. Its rows no longer sit at their indices, so the
    /// block is refused rather than served shifted.
    #[test]
    fn a_block_whose_rows_do_not_sit_at_their_indices_is_refused() {
        let store = Arc::new(parking_lot::Mutex::new(LogicalLeafStore::new()));
        let enc = encoder();
        let registry =
            ShimStoreRegistry::from_declarations([(block_filter(0), Arc::clone(&store))]);
        {
            let mut guard = store.lock();
            for (local, height) in [(0u32, 1_000u64), (1, 2_000), (2, 1_001)] {
                apply_wal_entry(
                    &mut guard,
                    &WalEntryPayload::PpoiListLeafAdded {
                        list_key: LIST_KEY,
                        list_index: local,
                        blinded_commitment: fr(local),
                        event_type: raven_railgun_persistence::PpoiEventType::Shield,
                        validated_merkleroot: [0; 32],
                    },
                    height,
                    &enc,
                )
                .expect("seed ppoi leaf");
            }
        }
        let coverage = registry
            .prove_list_coverage(&LIST_KEY, Some(counted(3, 0)))
            .expect("covered");
        assert!(coverage.segment(0).is_ok(), "no hole before the reorg");
        apply_wal_entry(
            &mut store.lock(),
            &WalEntryPayload::Reorg { height: 1_500 },
            1_500,
            &enc,
        )
        .expect("reorg");
        let torn = CoverageRefusal::TornBlock {
            list_key: LIST_KEY,
            block: 0,
        };
        assert_eq!(coverage.segment(0), Err(SegmentRefusal::Uncovered(torn)));
    }
}
