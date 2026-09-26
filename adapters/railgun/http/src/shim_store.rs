//! Coverage-proven store resolution for the wallet-shim routes.
//!
//! The shim answers questions whose domain is a whole list or a whole commit tree:
//! `"Missing"`, an empty blocked-set and a 404 are all claims about ABSENCE, and absence is
//! only sound over a complete domain. A store that holds one 65,536-row block of a
//! 358,320-row list can answer none of them, yet every such answer is a well-formed 200.
//!
//! So a route never reaches a store directly. It proves coverage first, and a failed proof
//! names the rule that failed.

use std::collections::BTreeMap;
use std::sync::Arc;

use raven_railgun_engine::inspire::LogicalLeafStore;
use raven_railgun_engine::orchestrator::{DataSourceFilter, LEAVES_PER_PPOI_BLOCK};

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
/// instance was configured with.
///
/// Installed once at boot. Installing it at all is what makes the legacy single-store field
/// unreachable, so a production server cannot answer from an undeclared store.
#[derive(Debug, Default)]
pub struct ShimStoreRegistry {
    ppoi_blocks: BTreeMap<([u8; 32], u32), Vec<SharedLogicalStore>>,
    ppoi_whole: BTreeMap<[u8; 32], Vec<SharedLogicalStore>>,
    chain_trees: BTreeMap<u32, Vec<SharedLogicalStore>>,
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
                DataSourceFilter::PpoiList(list_key) => {
                    registry.ppoi_whole.entry(list_key).or_default().push(store);
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

    /// True when no declaration was supplied at all.
    pub fn is_empty(&self) -> bool {
        self.ppoi_blocks.is_empty() && self.ppoi_whole.is_empty() && self.chain_trees.is_empty()
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

    /// Prove that the wired stores hold a gap-free prefix of `list_key` whose frontier is
    /// not sitting on the per-IMT capacity wall, and reaches at least as far as `tip`, the
    /// count upstream gave for the list no more than [`UPSTREAM_TIP_MAX_AGE_SECS`] ago. Blocks
    /// declared past the frontier may be empty, since that count ends the list before them.
    ///
    /// Block declarations are tried first: they are the only shape that can span more than
    /// one IMT, and the list outgrew one IMT long ago.
    pub fn prove_list_coverage(
        &self,
        list_key: &[u8; 32],
        tip: Option<UpstreamTip>,
    ) -> Result<ListCoverage<'_>, CoverageRefusal> {
        match self.prove_from_blocks(list_key, tip) {
            Ok(coverage) => Ok(coverage),
            // Blocks are declared for this list but do not cover it. The whole-list store is
            // then provably behind them - it stops at one IMT while they do not - so falling
            // back to it would answer from strictly less than the process already holds.
            Err(refusal @ CoverageRefusal::NoListStore { .. }) => self
                .prove_from_whole_list(list_key, tip)
                .map_err(|fallback| {
                    if matches!(fallback, CoverageRefusal::NoListStore { .. }) {
                        refusal
                    } else {
                        fallback
                    }
                }),
            Err(refusal) => Err(refusal),
        }
    }

    fn prove_from_blocks(
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
        };
        coverage.prove_prefix(tip)?;
        Ok(coverage)
    }

    fn prove_from_whole_list(
        &self,
        list_key: &[u8; 32],
        tip: Option<UpstreamTip>,
    ) -> Result<ListCoverage<'_>, CoverageRefusal> {
        let declared = self
            .ppoi_whole
            .get(list_key)
            .ok_or(CoverageRefusal::NoListStore {
                list_key: *list_key,
            })?;
        let [single] = declared.as_slice() else {
            return Err(CoverageRefusal::DuplicateBlock {
                list_key: *list_key,
                block: 0,
            });
        };
        // A whole-list route carries GLOBAL indices unlocalized and `checked_imt_append`
        // refuses at capacity, so "block 0, frontier below the wall" is exactly the rule
        // that separates a complete small list from one that silently stopped ingesting.
        let coverage = ListCoverage {
            list_key: *list_key,
            blocks: vec![single],
        };
        coverage.prove_prefix(tip)?;
        Ok(coverage)
    }
}

/// A proven gap-free prefix of one list, in block order. Index in `blocks` is the block number.
#[derive(Debug)]
pub struct ListCoverage<'a> {
    list_key: [u8; 32],
    blocks: Vec<&'a SharedLogicalStore>,
}

/// One row of a covered list, carrying the index a client can act on.
#[derive(Debug, Clone, Copy)]
pub struct CoveredLeaf {
    /// Index into the whole list, not into the block that holds it.
    pub global_index: u32,
    /// Blinded commitment at that index.
    pub blinded_commitment: [u8; 32],
    /// Status byte for that commitment, absent when the row has none.
    pub status: Option<u8>,
}

impl<'a> ListCoverage<'a> {
    /// Wrap a single undeclared store, asserting coverage instead of proving it.
    ///
    /// Reachable only from [`AppState::with_logical_store`](crate::AppState::with_logical_store),
    /// which has no production caller. It exists so unit tests can drive the handlers without a
    /// six-instance boot; a server that installs a [`ShimStoreRegistry`] never reaches it.
    pub(crate) fn undeclared(list_key: [u8; 32], store: &'a SharedLogicalStore) -> Self {
        Self {
            list_key,
            blocks: vec![store],
        }
    }

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
        let guard = store.lock();
        let leaves = guard
            .ppoi_imt(&self.list_key)
            .map_or(0, raven_railgun_engine::imt::Imt::leaf_count);
        u32::try_from(leaves).unwrap_or(u32::MAX)
    }

    /// Height the composed answer is complete as of: the lowest any contributor has reached.
    pub fn epoch(&self) -> u64 {
        self.blocks
            .iter()
            .map(|store| store.lock().last_block_height())
            .min()
            .unwrap_or(0)
    }

    /// Every covered row in ascending global-index order. Each block is locked once.
    pub fn leaves(&self) -> Vec<CoveredLeaf> {
        let mut out = Vec::new();
        for (block, store) in self.blocks.iter().enumerate() {
            let base = u32::try_from(block)
                .unwrap_or(u32::MAX)
                .saturating_mul(LEAVES_PER_PPOI_BLOCK);
            let guard = store.lock();
            out.extend(
                guard
                    .ppoi_list_leaves_iter(&self.list_key)
                    .map(|(local, bc)| CoveredLeaf {
                        global_index: base.saturating_add(local),
                        blinded_commitment: *bc,
                        status: guard.ppoi_status(&self.list_key, bc),
                    })
                    .collect::<Vec<_>>(),
            );
        }
        out
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

    /// Status byte per requested blinded commitment, positionally. Each block is locked once.
    ///
    /// The block that OWNS a commitment is authoritative: it saw the leaf's own status as
    /// well as every broadcast update, while a non-owner saw only the broadcasts. `None`
    /// means the covered list does not carry that commitment at all.
    pub fn statuses_of(&self, blinded_commitments: &[[u8; 32]]) -> Vec<Option<u8>> {
        let mut resolved: Vec<(Option<u8>, bool)> = vec![(None, false); blinded_commitments.len()];
        for store in &self.blocks {
            let guard = store.lock();
            for (slot, bc) in resolved.iter_mut().zip(blinded_commitments.iter()) {
                if slot.1 {
                    continue;
                }
                if guard.ppoi_index_of(&self.list_key, bc).is_some() {
                    *slot = (guard.ppoi_status(&self.list_key, bc), true);
                } else if slot.0.is_none() {
                    slot.0 = guard.ppoi_status(&self.list_key, bc);
                }
            }
        }
        resolved.into_iter().map(|(status, _)| status).collect()
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

    /// Canonical BN254 Fr: the top byte stays zero so the value is under the modulus.
    fn fr(seed: u32) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[28..].copy_from_slice(&seed.to_be_bytes());
        out[20] = 0x01;
        out
    }

    fn block_store(local_indices: std::ops::Range<u32>, seed_base: u32) -> SharedLogicalStore {
        let mut store = LogicalLeafStore::new();
        let enc = encoder();
        for local in local_indices {
            apply_wal_entry(
                &mut store,
                &WalEntryPayload::PpoiListLeafAdded {
                    list_key: LIST_KEY,
                    list_index: local,
                    blinded_commitment: fr(seed_base.saturating_add(local)),
                    status: 0,
                    event_type: raven_railgun_persistence::PpoiEventType::Shield,
                    signature: vec![0; 64],
                    validated_merkleroot: [0; 32],
                },
                1_000 + u64::from(local),
                &enc,
            )
            .expect("seed ppoi leaf");
        }
        Arc::new(parking_lot::Mutex::new(store))
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
        let leaves = coverage.leaves();
        assert_eq!(leaves.len(), 4);
        assert_eq!(leaves[3].global_index, 3);
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
        assert_eq!(coverage.leaves().len(), 4);
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

    /// A whole-list store stops at one IMT while block stores do not, so once blocks are
    /// declared it holds strictly less. Answering from it after the blocks failed would
    /// serve less than the same process already has.
    #[test]
    fn a_whole_list_store_does_not_rescue_a_failed_block_proof() {
        let registry = ShimStoreRegistry::from_declarations([
            (block_filter(2), block_store(0..4, 0)),
            (DataSourceFilter::PpoiList(LIST_KEY), block_store(0..4, 100)),
        ]);
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

    /// With no block declared, the whole-list store is the coverage, and its own frontier
    /// rule is what refuses it once it reaches the wall it cannot append past.
    #[test]
    fn a_whole_list_store_covers_a_list_that_still_fits_one_imt() {
        let registry = ShimStoreRegistry::from_declarations([(
            DataSourceFilter::PpoiList(LIST_KEY),
            block_store(0..4, 0),
        )]);
        let coverage = registry
            .prove_list_coverage(&LIST_KEY, Some(counted(4, 0)))
            .expect("covered");
        assert_eq!(coverage.leaves().len(), 4);
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

    /// The whole-list shape has no sealed block under its frontier, so without a count a store
    /// three rows into a long list would prove the whole of it.
    #[test]
    fn a_whole_list_store_short_of_upstreams_count_is_refused() {
        let registry = ShimStoreRegistry::from_declarations([(
            DataSourceFilter::PpoiList(LIST_KEY),
            block_store(0..3, 0),
        )]);
        assert_eq!(
            registry.prove_list_coverage(&LIST_KEY, None).err(),
            Some(unanchored(3, None))
        );
        assert_eq!(
            registry
                .prove_list_coverage(&LIST_KEY, Some(counted(358_344, 4)))
                .err(),
            Some(unanchored(3, Some(counted(358_344, 4))))
        );
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
}
