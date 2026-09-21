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
    /// A block below the frontier is short, so the list has a hole under a later block.
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
    /// The last declared block is full, so a successor block may exist upstream and is
    /// wired to nothing. Refused rather than guessed.
    FrontierFull {
        /// List key asked about.
        list_key: [u8; 32],
        /// The full frontier block.
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
                "list {} block {block} holds {held} of {expected} rows while a later block is \
                 declared, so the list has a hole",
                hex32(list_key)
            ),
            Self::FrontierFull { list_key, block } => write!(
                f,
                "list {} block {block} is full at {LEAVES_PER_PPOI_BLOCK} rows and no successor \
                 block is wired, so rows past it are held by nobody",
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
    /// not sitting on the per-IMT capacity wall.
    ///
    /// Block declarations are tried first: they are the only shape that can span more than
    /// one IMT, and the list outgrew one IMT long ago.
    pub fn prove_list_coverage(
        &self,
        list_key: &[u8; 32],
    ) -> Result<ListCoverage<'_>, CoverageRefusal> {
        match self.prove_from_blocks(list_key) {
            Ok(coverage) => Ok(coverage),
            // Blocks are declared for this list but do not cover it. The whole-list store is
            // then provably behind them - it stops at one IMT while they do not - so falling
            // back to it would answer from strictly less than the process already holds.
            Err(refusal @ CoverageRefusal::NoListStore { .. }) => {
                self.prove_from_whole_list(list_key).map_err(|fallback| {
                    if matches!(fallback, CoverageRefusal::NoListStore { .. }) {
                        refusal
                    } else {
                        fallback
                    }
                })
            }
            Err(refusal) => Err(refusal),
        }
    }

    fn prove_from_blocks(&self, list_key: &[u8; 32]) -> Result<ListCoverage<'_>, CoverageRefusal> {
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
        coverage.prove_prefix()?;
        Ok(coverage)
    }

    fn prove_from_whole_list(
        &self,
        list_key: &[u8; 32],
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
        coverage.prove_prefix()?;
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

    fn prove_prefix(&self) -> Result<(), CoverageRefusal> {
        let frontier = self.blocks.len().saturating_sub(1);
        for (position, store) in self.blocks.iter().enumerate() {
            let held = self.held_rows(store);
            let block = u32::try_from(position).unwrap_or(u32::MAX);
            if position == frontier {
                if held >= LEAVES_PER_PPOI_BLOCK {
                    return Err(CoverageRefusal::FrontierFull {
                        list_key: self.list_key,
                        block,
                    });
                }
            } else if held != LEAVES_PER_PPOI_BLOCK {
                return Err(CoverageRefusal::ShortBlock {
                    list_key: self.list_key,
                    block,
                    held,
                    expected: LEAVES_PER_PPOI_BLOCK,
                });
            }
        }
        Ok(())
    }

    /// Re-check the frontier after the answer was read.
    ///
    /// The proof and the read are separate lock acquisitions, and the frontier block is the
    /// one that grows. If it reached capacity in between, a successor block exists upstream
    /// and the answer just read is no longer a complete prefix.
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

    #[test]
    fn a_single_short_block_covers_the_list_it_declares() {
        let registry =
            ShimStoreRegistry::from_declarations([(block_filter(0), block_store(0..4, 0))]);
        let coverage = registry.prove_list_coverage(&LIST_KEY).expect("covered");
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
            registry.prove_list_coverage(&LIST_KEY).err(),
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
            registry.prove_list_coverage(&LIST_KEY).err(),
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
            registry.prove_list_coverage(&LIST_KEY).err(),
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
            registry.prove_list_coverage(&LIST_KEY).err(),
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
            registry.prove_list_coverage(&LIST_KEY).err(),
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
        let coverage = registry.prove_list_coverage(&LIST_KEY).expect("covered");
        assert_eq!(coverage.leaves().len(), 4);
    }

    #[test]
    fn an_undeclared_list_is_refused() {
        let registry =
            ShimStoreRegistry::from_declarations([(block_filter(0), block_store(0..4, 0))]);
        let other = [0x99; 32];
        assert_eq!(
            registry.prove_list_coverage(&other).err(),
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
}
