//! `bootstrap-from-subsquid` over synthetic [`SubsquidLeavesSource`] /
//! [`ChainOracle`] / [`PpoiEventsSource`] stubs.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::items_after_statements,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::ignore_without_reason,
    clippy::print_stderr
)]

use async_trait::async_trait;
use parking_lot::Mutex;
use raven_railgun_cli::bootstrap_subsquid::{
    bootstrap_one_list, bootstrap_one_list_with_mode, bootstrap_one_tree,
    bootstrap_one_tree_with_carry, decode_bigint_to_be_bytes32, modulus_be, BootstrapError,
    BootstrapTreeConfig, ChainOracle, CommitmentRow, OracleKind, PpoiBootstrapMode, PpoiEventRow,
    PpoiEventsSource, RailwayPpoiClient, StowawayCarry, SubsquidLeavesSource,
};
use raven_railgun_engine::imt::Imt;
use raven_railgun_engine::pir_table::EncoderKind;

/// Covers live byte-identity, static membership, and the pruning branch.
struct StubChain {
    head: u64,
    active_tree: u32,
    chain_root: Mutex<Option<[u8; 32]>>,
    recorded_roots: Mutex<Vec<(u32, [u8; 32])>>,
    pruning: Mutex<bool>,
    chain_events: Mutex<Vec<ChainEventRow>>,
    /// Block-indexed chain state, so a ROLLOVER is expressible. Both maps are step functions
    /// keyed on the first block the value holds from; empty means "constant", which is what
    /// every pre-existing test wants and gets from the two scalars above.
    active_tree_from: Mutex<std::collections::BTreeMap<u64, u32>>,
    root_from: Mutex<std::collections::BTreeMap<u64, [u8; 32]>>,
    /// Block below which the contract had no code. `eth_call` to a codeless address succeeds
    /// with empty returndata, so a real node answers such a probe with a DECODE failure, not a
    /// transport error - and a stub that answers happily at every height cannot see a search
    /// that reads below deployment.
    deploy_floor: Mutex<Option<u64>>,
}

type ChainEventRow = (u64, u32, u32, [u8; 32]);

/// Spacing between synthetic rollovers. Small, so every rollover sits above any fixture's row
/// block and below the checkpoint.
const ROLLOVER_STEP_BLOCKS: u64 = 10;

impl StubChain {
    fn new(head: u64, active_tree: u32) -> Self {
        Self {
            head,
            active_tree,
            chain_root: Mutex::new(None),
            recorded_roots: Mutex::new(Vec::new()),
            pruning: Mutex::new(false),
            chain_events: Mutex::new(Vec::new()),
            // Rollovers packed just under the checkpoint, so tree 0 spans almost the whole
            // chain. Two properties the tests depend on: the active tree AT the checkpoint is
            // `active_tree`, and a closed tree's rollover block is nowhere near its tree NUMBER -
            // so a search that returned the tree number would read the wrong root and be caught.
            active_tree_from: Mutex::new(
                std::iter::once((0u64, 0u32))
                    .chain((1..=active_tree).map(|k| {
                        (
                            head.saturating_sub(64)
                                - u64::from(active_tree - k) * ROLLOVER_STEP_BLOCKS,
                            k,
                        )
                    }))
                    .collect(),
            ),
            root_from: Mutex::new(std::collections::BTreeMap::new()),
            deploy_floor: Mutex::new(None),
        }
    }

    /// Below `block` the contract has no code, so every read there fails to decode.
    fn set_deploy_floor(&self, block: u64) {
        *self.deploy_floor.lock() = Some(block);
    }

    /// REPLACES the ladder. `new`'s default maps tree k to block k, which makes the rollover
    /// block equal the tree number, so a search that merely returned `tree_number` would agree
    /// with a correct one on every fixture built from it.
    fn set_rollover_ladder(&self, entries: &[(u64, u32)]) {
        let mut ladder = self.active_tree_from.lock();
        ladder.clear();
        for (block, tree) in entries {
            ladder.insert(*block, *tree);
        }
    }

    fn undecodable_below_floor(&self, block: u64) -> Option<BootstrapError> {
        let floor = (*self.deploy_floor.lock())?;
        (block < floor).then(|| BootstrapError::ChainStateUndecodable {
            block,
            detail: "treeNumber: ABI decoding failed: buffer overrun while deserializing"
                .to_owned(),
        })
    }

    /// From `block` onward the chain merkle root is `root`.
    fn set_root_from(&self, block: u64, root: [u8; 32]) {
        self.root_from.lock().insert(block, root);
    }

    fn set_chain_root(&self, r: [u8; 32]) {
        *self.chain_root.lock() = Some(r);
    }

    fn record_root(&self, tree: u32, r: [u8; 32]) {
        self.recorded_roots.lock().push((tree, r));
    }

    fn set_pruning(&self) {
        *self.pruning.lock() = true;
    }

    fn add_chain_event(&self, block: u64, tree: u32, leaf_index: u32, hash: [u8; 32]) {
        self.chain_events
            .lock()
            .push((block, tree, leaf_index, hash));
    }

    fn pruning_err() -> BootstrapError {
        BootstrapError::RpcUnreachable(
            "-32000 historical state at block N is not available (try an archive node)".to_owned(),
        )
    }
}

#[async_trait]
impl ChainOracle for StubChain {
    async fn chain_head(&self) -> Result<u64, BootstrapError> {
        Ok(self.head)
    }
    async fn active_tree_number_at(&self, block: u64) -> Result<u32, BootstrapError> {
        if *self.pruning.lock() {
            return Err(Self::pruning_err());
        }
        if let Some(e) = self.undecodable_below_floor(block) {
            return Err(e);
        }
        Ok(self
            .active_tree_from
            .lock()
            .range(..=block)
            .next_back()
            .map_or(self.active_tree, |(_, t)| *t))
    }
    async fn merkle_root_at(&self, block: u64) -> Result<[u8; 32], BootstrapError> {
        if *self.pruning.lock() {
            return Err(Self::pruning_err());
        }
        if let Some(e) = self.undecodable_below_floor(block) {
            return Err(e);
        }
        if let Some((_, r)) = self.root_from.lock().range(..=block).next_back() {
            return Ok(*r);
        }
        if let Some(r) = *self.chain_root.lock() {
            return Ok(r);
        }
        // Fall back to the LAST root rootHistory holds for the tree active at `block`. That is
        // what a closed tree's closing root is on chain: rootHistory accumulates one entry per
        // batch, so its final entry for a tree is the root that tree ended at.
        let active = self
            .active_tree_from
            .lock()
            .range(..=block)
            .next_back()
            .map_or(self.active_tree, |(_, t)| *t);
        self.recorded_roots
            .lock()
            .iter()
            .rev()
            .find(|(t, _)| *t == active)
            .map(|(_, r)| *r)
            .ok_or_else(|| {
                BootstrapError::RpcUnreachable(format!(
                    "StubChain has no root for the tree active at block {block}"
                ))
            })
    }
    async fn root_history_at(
        &self,
        tree_number: u32,
        merkle_root: [u8; 32],
        _block: u64,
    ) -> Result<bool, BootstrapError> {
        if *self.pruning.lock() {
            return Err(Self::pruning_err());
        }
        Ok(self
            .recorded_roots
            .lock()
            .iter()
            .any(|(t, r)| *t == tree_number && *r == merkle_root))
    }
    async fn commitment_events_in_range(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<(u32, u32, [u8; 32])>, BootstrapError> {
        if *self.pruning.lock() {
            return Err(Self::pruning_err());
        }
        let events = self.chain_events.lock();
        let mut out = Vec::new();
        for (block, tree, leaf_index, hash) in events.iter() {
            if *block >= from_block && *block <= to_block {
                out.push((*tree, *leaf_index, *hash));
            }
        }
        Ok(out)
    }
}

/// Synthetic leaves-only Subsquid source.
struct StubLeaves {
    rows: Vec<CommitmentRow>,
    fail_with_503: bool,
    /// Caps pagination below `rows.len()` to simulate partial-leaf-count drift.
    cap: Option<usize>,
}

impl StubLeaves {
    fn new(rows: Vec<CommitmentRow>) -> Self {
        Self {
            rows,
            fail_with_503: false,
            cap: None,
        }
    }

    fn fail_with_503(mut self) -> Self {
        self.fail_with_503 = true;
        self
    }

    fn cap_at(mut self, cap: usize) -> Self {
        self.cap = Some(cap);
        self
    }
}

#[async_trait]
impl SubsquidLeavesSource for StubLeaves {
    async fn fetch_commitments_page(
        &self,
        _tree_number: u32,
        _checkpoint_block: u64,
        cursor: Option<u64>,
        page_size: usize,
    ) -> Result<Vec<CommitmentRow>, BootstrapError> {
        if self.fail_with_503 {
            return Err(BootstrapError::SubsquidUnreachable("503".to_owned()));
        }
        let cap = self.cap.unwrap_or(self.rows.len());
        let after = cursor.unwrap_or(u64::MAX.wrapping_sub(0));
        let mut out = Vec::with_capacity(page_size);
        for row in self.rows.iter().take(cap) {
            let pass = if cursor.is_none() {
                true
            } else {
                row.tree_position > after
            };
            if pass && out.len() < page_size {
                out.push(row.clone());
            }
        }
        Ok(out)
    }
}

/// Canonical leaves `leaf = BE(index+1)` -> `(rows, local_root)`.
fn synthetic_leaves(count: usize) -> (Vec<CommitmentRow>, [u8; 32]) {
    synthetic_leaves_at_block(count, 1)
}

/// [`synthetic_leaves`] with a fixed block number to correlate chain-injected events.
fn synthetic_leaves_at_block(count: usize, block_number: u64) -> (Vec<CommitmentRow>, [u8; 32]) {
    let mut rows = Vec::with_capacity(count);
    for i in 0..count {
        let mut leaf = [0u8; 32];
        let v = (i as u64) + 1;
        leaf[24..32].copy_from_slice(&v.to_be_bytes());
        rows.push(CommitmentRow {
            tree_position: i as u64,
            leaf,
            block_number,
        });
    }
    let mut imt = Imt::new().expect("imt new");
    for (i, r) in rows.iter().enumerate() {
        imt.insert_leaves(i, &[r.leaf]).expect("insert");
    }
    (rows, imt.root())
}

fn fresh_data_dir(stem: &str) -> std::path::PathBuf {
    let base = tempfile::tempdir().expect("tempdir");
    let path = base.path().join(stem);
    // leak so the dir outlives the handle for the test body
    std::mem::forget(base);
    path
}

fn cfg_for(tree_number: u32, dir: std::path::PathBuf) -> BootstrapTreeConfig {
    BootstrapTreeConfig {
        tree_number,
        checkpoint_depth: 64,
        data_dir: dir,
        instance_id: format!("commit-tree-{tree_number}"),
        max_wall_mins: 5,
        // A real caller builds the encoder from the tree it is bootstrapping; inheriting
        // the default's tree-0 encoder is the mismatch `EncoderTreeMismatch` refuses.
        encoder_kind: EncoderKind::PerLeafBc { tree_number },
        ..BootstrapTreeConfig::default()
    }
}

/// The bootstrap loop is a durable-WAL ingress: a second run over an already
/// populated data_dir would re-append leaf 0.. on top of the recovered prefix,
/// leaving entries no replay can ever apply.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_bootstrap_over_a_populated_data_dir_refuses_before_the_wal_grows() {
    let (rows, root) = synthetic_leaves(8);
    let dir = fresh_data_dir("commit-tree-0-rerun");
    let cfg = cfg_for(0, dir.clone());
    let chain = StubChain::new(20_000_000, 99);
    chain.record_root(0, root);

    let first = bootstrap_one_tree(&cfg, &StubLeaves::new(rows.clone()), &chain)
        .await
        .expect("first bootstrap seeds the data dir");
    assert_eq!(first.leaves, 8);

    let wal = dir.join("wal").join("current.log");
    let before = std::fs::metadata(&wal)
        .expect("wal/current.log after the first bootstrap")
        .len();
    assert!(before > 0, "the first bootstrap must have written the WAL");

    let err = bootstrap_one_tree(&cfg, &StubLeaves::new(rows), &chain)
        .await
        .expect_err("a re-bootstrap over a populated data_dir must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("expected leaf_index 8, got 0"),
        "the refusal must name the recovered leaf count and the offending index; got: {msg}"
    );
    assert!(
        msg.contains("empty --data-dir"),
        "the refusal must tell the operator what to do; got: {msg}"
    );

    let after = std::fs::metadata(&wal)
        .expect("wal/current.log after the refused bootstrap")
        .len();
    assert_eq!(
        before, after,
        "a refused bootstrap must not have appended to the WAL"
    );
}

/// The closing root is read at the ROLLOVER, and the rollover is found by search.
///
/// The ladder is set explicitly so the rollover block is unrelated to the tree NUMBER and to any
/// arithmetic in the stub's default. Three distinct roots are seeded, so landing on the wrong block
/// yields the wrong root rather than a coincidence: what a `closed_at = tree_number` shortcut would
/// read, the closing root one block below the rollover, and the successor's root at the rollover.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_closing_root_is_read_at_the_rollover_block_not_at_the_tree_number() {
    const TREE_0_ROLLOVER: u64 = 17_000_000;
    let (rows, root) = synthetic_leaves(6);
    let leaves = StubLeaves::new(rows);
    let chain = StubChain::new(20_000_000, 3);
    chain.set_rollover_ladder(&[
        (0, 0),
        (TREE_0_ROLLOVER, 1),
        (18_000_000, 2),
        (19_000_000, 3),
    ]);

    chain.set_root_from(0, [0xAA; 32]);
    chain.set_root_from(TREE_0_ROLLOVER - 1, root);
    chain.set_root_from(TREE_0_ROLLOVER, [0xBB; 32]);
    chain.record_root(0, root);

    let cfg = cfg_for(0, fresh_data_dir("commit-tree-0-rollover-search"));
    let report = bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect("the closing root is the one held one block below the rollover");
    assert_eq!(report.local_root, root);
    assert_eq!(report.chain_static_membership, Some(true));
}

/// The rollover search must never probe a block at which the contract had no code.
///
/// An `eth_call` to a codeless address SUCCEEDS and returns empty data, so a real node answers such
/// a probe with an ABI-decode failure, which no pruning heuristic matches and no RPC change fixes.
/// A search floored at 0 against this head probes ~10M on its first iteration, well below
/// deployment, so an unfloored search fails here on iteration one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_probe_below_the_contract_deployment_is_never_made() {
    const TREE_0_ROLLOVER: u64 = 17_000_000;
    let (rows, root) = synthetic_leaves(6);
    let leaves = StubLeaves::new(rows);
    let chain = StubChain::new(20_000_000, 3);
    chain.set_rollover_ladder(&[
        (0, 0),
        (TREE_0_ROLLOVER, 1),
        (18_000_000, 2),
        (19_000_000, 3),
    ]);
    chain.set_deploy_floor(14_737_691);
    chain.set_root_from(TREE_0_ROLLOVER - 1, root);
    chain.record_root(0, root);

    let cfg = cfg_for(0, fresh_data_dir("commit-tree-0-deploy-floor"));
    assert!(
        cfg.contract_start_block < TREE_0_ROLLOVER,
        "premise: the floor is below the rollover, so a floored search can still find it"
    );
    assert!(
        cfg.contract_start_block >= 14_737_691,
        "premise: the default floor is at or above the stub's deployment block"
    );
    let report = bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect("a full-history node answers every probe at or above deployment");
    assert_eq!(report.local_root, root);
}

/// A floor above the tree's own rollover is refused, not guessed around.
///
/// Reading at `floor - 1` there would return a root from before this tree existed and present it as
/// the tree's closing root - a wrong answer rather than a refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_search_floor_above_the_trees_own_rollover_is_refused() {
    let (rows, root) = synthetic_leaves(6);
    let leaves = StubLeaves::new(rows);
    let chain = StubChain::new(20_000_000, 3);
    chain.set_rollover_ladder(&[(0, 0), (17_000_000, 1), (18_000_000, 2), (19_000_000, 3)]);
    chain.record_root(0, root);

    let cfg = BootstrapTreeConfig {
        contract_start_block: 18_500_000,
        ..cfg_for(0, fresh_data_dir("commit-tree-0-floor-too-high"))
    };
    let err = bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect_err("a floor past the rollover cannot bracket it");
    let msg = err.to_string();
    assert!(
        msg.contains("closed at or below the floor"),
        "the refusal must say the floor is the problem; got: {msg}"
    );
}

/// A repair trigger above the tree's capacity can never fire, so it is refused rather than obeyed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repair_trigger_above_capacity_is_refused_because_it_can_never_be_reached() {
    let (rows, root) = synthetic_leaves(6);
    let leaves = StubLeaves::new(rows);
    let chain = StubChain::new(20_000_000, 3);
    chain.record_root(0, root);

    let base = cfg_for(0, fresh_data_dir("commit-tree-0-threshold-unreachable"));
    let cfg = BootstrapTreeConfig {
        repair_trigger_threshold: base.expected_filled_count + 1,
        ..base
    };
    let err = bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect_err("an unreachable repair trigger silently disables self-healing");
    let msg = err.to_string();
    assert!(
        msg.contains("can never be reached"),
        "the refusal must say why the value is illegal; got: {msg}"
    );
}

/// The tail must be EXPLAINED, and static membership alone cannot explain it.
///
/// `rootHistory` records one entry per BATCH and the IMT is fixed-depth and zero-padded, so the
/// root over any batch-boundary prefix of a closed tree is a root the chain genuinely holds.
/// A fetch that stops early therefore passes `rootHistory` and persists a short tree, at `Ok`.
/// Here the chain holds both the prefix root and the closing root; the local fetch is the
/// prefix, and it must be refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_prefix_truncated_closed_tree_is_refused_even_though_root_history_holds_it() {
    let (_full_rows, full_root) = synthetic_leaves(8);
    let (short_rows, short_root) = synthetic_leaves(5);
    assert_ne!(
        short_root, full_root,
        "premise: the prefix has its own root"
    );

    let leaves = StubLeaves::new(short_rows);
    let chain = StubChain::new(20_000_000, 99);
    // The chain holds the prefix root - it was a real batch boundary - and then the root the
    // tree closed at. Recorded in that order, so the LAST entry is the closing root.
    chain.record_root(0, short_root);
    chain.record_root(0, full_root);

    let cfg = cfg_for(0, fresh_data_dir("commit-tree-0-truncated"));
    let err = bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect_err("a prefix of a closed tree must not bootstrap as the whole tree");
    let msg = format!("{err}");
    assert!(
        msg.contains("PREFIX of the closed tree"),
        "the refusal must say the fetch is short rather than blaming membership; got: {msg}"
    );
}

/// The repair threshold can no longer let a short tree through, only decide whether we self-heal.
///
/// Below the threshold `repair_boundary_if_needed` returns without gap-walking at all, which is
/// what made an unprovenanced slack look load-bearing. But repair runs BEFORE the root is computed,
/// and a closed tree's root is a commitment to its entire leaf set - so an unrepaired tree fails the
/// closing-root comparison and is refused. The threshold therefore governs self-heal versus refuse,
/// not accept versus refuse.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_short_tree_below_the_repair_threshold_is_refused_not_accepted() {
    let (_full, full_root) = synthetic_leaves(8);
    let (short_rows, short_root) = synthetic_leaves(3);

    let leaves = StubLeaves::new(short_rows);
    let chain = StubChain::new(20_000_000, 99);
    chain.record_root(0, short_root);
    chain.record_root(0, full_root);

    let cfg = cfg_for_boundary(0, fresh_data_dir("commit-tree-0-below-threshold"));
    // premise: 3 rows is below `repair_trigger_threshold: 4`, so no gap-walk runs at all.
    assert!(3 < cfg.repair_trigger_threshold);

    let err = bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect_err("an unrepaired short tree must be refused, not persisted");
    assert!(
        format!("{err}").contains("PREFIX of the closed tree"),
        "the refusal must come from the closing-root comparison; got: {err}"
    );
}

/// The inverse, and it is what keeps this from being a row-count floor: a tree that CLOSED
/// short of capacity is legitimate. `Commitments.sol` moves an entire overflowing batch to the
/// next tree, so a closed tree can hold far fewer than 65,536 leaves. What makes it acceptable
/// is that its root IS the root the chain closed it at - not how many rows it has.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_tree_that_legitimately_ended_short_still_bootstraps() {
    let (rows, root) = synthetic_leaves(5);
    let leaves = StubLeaves::new(rows);
    let chain = StubChain::new(20_000_000, 99);
    chain.record_root(0, root);

    let cfg = cfg_for(0, fresh_data_dir("commit-tree-0-short-but-closed"));
    let report = bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect("a short tree whose root is its CLOSING root is complete");
    assert_eq!(report.leaves, 5);
    assert_eq!(report.local_root, root);
    assert_eq!(report.chain_static_membership, Some(true));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_static_tree_membership_oracle_pass() {
    let (rows, root) = synthetic_leaves(8);
    let leaves = StubLeaves::new(rows);
    // active tree 99 != queried tree 0 -> static path
    let chain = StubChain::new(20_000_000, 99);
    chain.record_root(0, root);
    let cfg = cfg_for(0, fresh_data_dir("commit-tree-0-static"));
    let report = bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect("static membership ok");
    assert_eq!(report.tree_number, 0);
    assert_eq!(report.leaves, 8);
    assert_eq!(report.local_root, root);
    assert_eq!(report.chain_static_membership, Some(true));
    assert!(report.chain_live_root.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_live_tree_byte_identity_pass() {
    let (rows, root) = synthetic_leaves(8);
    let leaves = StubLeaves::new(rows);
    let chain = StubChain::new(20_000_000, 3);
    chain.set_chain_root(root);
    let cfg = cfg_for(3, fresh_data_dir("commit-tree-3-live"));
    let report = bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect("live byte-identity ok");
    assert_eq!(report.chain_live_root, Some(root));
    assert!(report.chain_static_membership.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_static_tree_membership_mismatch_hard_stop() {
    let (rows, root) = synthetic_leaves(8);
    let leaves = StubLeaves::new(rows);
    let chain = StubChain::new(20_000_000, 99);
    // record a different root for tree 0 so membership returns false
    let mut other = root;
    other[0] ^= 0xff;
    chain.record_root(0, other);
    let cfg = cfg_for(0, fresh_data_dir("commit-tree-0-static-bad"));
    let err = bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect_err("must hard-stop on rootHistory==false");
    match err {
        BootstrapError::OracleByteIdentityMismatch { kind, .. } => {
            assert_eq!(kind, OracleKind::ChainStaticTree);
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_live_tree_byte_identity_mismatch_hard_stop() {
    let (rows, root) = synthetic_leaves(8);
    let leaves = StubLeaves::new(rows);
    let chain = StubChain::new(20_000_000, 3);
    let mut bad_chain_root = root;
    bad_chain_root[0] ^= 0xff;
    chain.set_chain_root(bad_chain_root);
    let cfg = cfg_for(3, fresh_data_dir("commit-tree-3-corrupt-chain"));
    let err = bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect_err("must hard-stop on chain disagreement");
    match err {
        BootstrapError::OracleByteIdentityMismatch { kind, .. } => {
            assert_eq!(kind, OracleKind::ChainLiveTree);
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_subsquid_unreachable_actionable_error() {
    let (rows, _root) = synthetic_leaves(4);
    let leaves = StubLeaves::new(rows).fail_with_503();
    let chain = StubChain::new(20_000_000, 99);
    let cfg = cfg_for(0, fresh_data_dir("commit-tree-0-503"));
    let err = bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect_err("503 must surface");
    assert!(matches!(err, BootstrapError::SubsquidUnreachable(_)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_partial_leaf_count_hard_stop() {
    // cap source at 7 while chain recorded the full-8 root: local 7-leaf root mismatches
    let (rows, root_full) = synthetic_leaves(8);
    let leaves = StubLeaves::new(rows).cap_at(7);
    let chain = StubChain::new(20_000_000, 99);
    chain.record_root(0, root_full);
    let cfg = cfg_for(0, fresh_data_dir("commit-tree-0-partial"));
    let err = bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect_err("partial pagination triggers oracle mismatch");
    assert!(matches!(
        err,
        BootstrapError::OracleByteIdentityMismatch {
            kind: OracleKind::ChainStaticTree,
            ..
        }
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_concurrent_run_lock_contention() {
    let dir = fresh_data_dir("commit-tree-0-conflict");
    std::fs::create_dir_all(&dir).expect("mkdir");
    // hold the lock first so the bootstrap runner contends for it
    let (_layout, _lock) =
        raven_railgun_persistence::StoreLayout::open_with_lock(&dir).expect("acquire first lock");
    let (rows, root) = synthetic_leaves(2);
    let leaves = StubLeaves::new(rows);
    let chain = StubChain::new(20_000_000, 99);
    chain.record_root(0, root);
    let cfg = cfg_for(0, dir);
    let err = bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect_err("second runner must fail");
    assert!(matches!(err, BootstrapError::LockHeld { .. }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_resume_from_partial_state() {
    let (rows, root) = synthetic_leaves(4);
    let dir = fresh_data_dir("commit-tree-0-resume");
    let leaves = StubLeaves::new(rows.clone());
    let chain = StubChain::new(20_000_000, 99);
    chain.record_root(0, root);
    let cfg = cfg_for(0, dir.clone());
    bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect("first run");

    let layout = raven_railgun_persistence::StoreLayout::open(&dir).expect("layout");
    let manifest = raven_railgun_persistence::Manifest::load(&layout)
        .expect("load")
        .expect("manifest present after first bootstrap");
    let head = chain.chain_head().await.unwrap();
    assert_eq!(manifest.current_marker, head - cfg.checkpoint_depth);
}

#[tokio::test]
async fn bootstrap_bigint_decoder_parity_with_subsquid_fixture() {
    // decoder must accept both shapes: Subsquid serialises BigInt as decimal,
    // some gateways relay as 0x-hex
    let leaf_hex = "0x23486ab54b4335993cbd8e0828229814f6719251e6bec45373efde528c4ec30b";
    let from_hex = decode_bigint_to_be_bytes32(leaf_hex).expect("hex shape decodes");
    let from_dec = decode_bigint_to_be_bytes32(
        "15958899161867544024902795852994276623318609558385493437315453628282930381579",
    )
    .expect("decimal shape decodes");
    assert_eq!(
        from_hex, from_dec,
        "decimal + hex shapes must yield byte-identical leaves"
    );
    let m = modulus_be();
    assert_eq!(m[0], 0x30, "BN254 modulus high byte");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_pagination_treeposition_cursor_handles_gap() {
    // 1500 leaves over 2 pages: the cursor must advance across the boundary
    let (rows, root) = synthetic_leaves(1500);
    let leaves = StubLeaves::new(rows);
    let chain = StubChain::new(20_000_000, 99);
    chain.record_root(0, root);
    let cfg = cfg_for(0, fresh_data_dir("commit-tree-0-page"));
    let report = bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect("paginated bootstrap");
    assert_eq!(report.leaves, 1500);
    assert!(report.subsquid_pages >= 2, "must span >=2 pages");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_no_archival_rpc_actionable_error() {
    // a pruning chain must classify as NoArchivalRpc with an actionable message
    let chain = StubChain::new(20_000_000, 99);
    chain.set_pruning();
    let probe_block = 20_000_000u64.saturating_sub(64);
    let err = chain
        .archival_probe(probe_block)
        .await
        .expect_err("must classify as NoArchivalRpc");
    match err {
        BootstrapError::NoArchivalRpc {
            checkpoint_block,
            actionable,
        } => {
            assert_eq!(checkpoint_block, probe_block);
            assert!(
                actionable.contains("archival") || actionable.contains("rpc-pool.toml"),
                "actionable message must point operators at the fix: {actionable}"
            );
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_pruning_during_run_classified_as_no_archival() {
    // mid-run pruning failure must also classify as NoArchivalRpc, not generic RpcUnreachable
    let (rows, _root) = synthetic_leaves(4);
    let leaves = StubLeaves::new(rows);
    let chain = StubChain::new(20_000_000, 99);
    chain.set_pruning();
    let cfg = cfg_for(0, fresh_data_dir("commit-tree-0-prune"));
    let err = bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect_err("must surface NoArchivalRpc");
    assert!(matches!(err, BootstrapError::NoArchivalRpc { .. }));
}

/// Synthetic PPOI source; each event carries the per-step IMT root the upstream signed.
struct StubPpoi {
    events: Vec<PpoiEventRow>,
}

#[async_trait]
impl PpoiEventsSource for StubPpoi {
    async fn fetch_all_events(
        &self,
        _list_key: [u8; 32],
    ) -> Result<Vec<PpoiEventRow>, BootstrapError> {
        Ok(self.events.clone())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ppoi_list_root_via_railway_capture() {
    // upstream validatedMerkleroot at each step is the local IMT root; bootstrap asserts parity
    let mut imt = Imt::new().expect("imt new");
    let mut events = Vec::new();
    for i in 0..4 {
        let mut leaf = [0u8; 32];
        leaf[31] = u8::try_from(i + 1).unwrap_or(0);
        imt.insert_leaves(i, &[leaf]).expect("insert");
        events.push(PpoiEventRow {
            index: i as u64,
            leaf,
            event_type: None,
            signature: None,
            validated_merkleroot: imt.root(),
        });
    }
    let src = StubPpoi { events };
    let report = bootstrap_one_list([0xab; 32], &src, "/tmp/raven/list-{LIST_KEY}")
        .await
        .expect("ppoi bootstrap ok");
    assert_eq!(report.events, 4);

    // corrupt the last validated_merkleroot: the oracle must fire
    let mut bad = src.events.clone();
    let last = bad.len() - 1;
    bad[last].validated_merkleroot[0] ^= 0xff;
    let bad_src = StubPpoi { events: bad };
    let err = bootstrap_one_list([0xab; 32], &bad_src, "/tmp/raven/list-{LIST_KEY}")
        .await
        .expect_err("corrupted upstream root must hard-stop");
    assert!(matches!(
        err,
        BootstrapError::OracleByteIdentityMismatch {
            kind: OracleKind::PpoiUpstreamList,
            ..
        }
    ));
}

/// Boundary-repair config at fixture size: 8-leaf trees, repair trigger low
/// enough that sparse rows fire the gap-walk + chain backfill.
fn cfg_for_boundary(tree_number: u32, dir: std::path::PathBuf) -> BootstrapTreeConfig {
    BootstrapTreeConfig {
        tree_number,
        checkpoint_depth: 64,
        data_dir: dir,
        instance_id: format!("commit-tree-boundary-{tree_number}"),
        max_wall_mins: 5,
        repair_trigger_threshold: 4,
        expected_filled_count: 8,
        encoder_kind: EncoderKind::PerLeafBc { tree_number },
        ..BootstrapTreeConfig::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boundary_repair_captures_stowaway_at_treeposition_65536_into_carry() {
    let (mut rows, root) = synthetic_leaves_at_block(8, 21_332_254);
    let mut stowaway_leaf = [0u8; 32];
    stowaway_leaf[31] = 0xff;
    rows.push(CommitmentRow {
        tree_position: 65_536,
        leaf: stowaway_leaf,
        block_number: 21_332_254,
    });
    let leaves = StubLeaves::new(rows);
    let chain = StubChain::new(20_000_000, 99);
    chain.record_root(0, root);
    let cfg = cfg_for_boundary(0, fresh_data_dir("commit-tree-0-stowaway"));
    let mut carry = StowawayCarry::new();
    let report = bootstrap_one_tree_with_carry(&cfg, &leaves, &chain, &mut carry)
        .await
        .expect("boundary repair re-tags the stowaway into carry");
    assert_eq!(report.leaves, 8);
    assert_eq!(report.local_root, root);
    assert_eq!(report.chain_static_membership, Some(true));
    let next_bucket = carry
        .get(&1)
        .expect("stowaway must be re-tagged into tree 1");
    assert_eq!(next_bucket.len(), 1, "exactly one stowaway carried");
    assert_eq!(next_bucket[0].tree_position, 0, "re-tagged to position 0");
    assert_eq!(
        next_bucket[0].leaf, stowaway_leaf,
        "re-tagged leaf bytes preserved"
    );
    assert_eq!(next_bucket[0].block_number, 21_332_254);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boundary_repair_retags_stowaway_as_tree_n_plus_1_position_0() {
    let (tree1_full, tree1_root) = synthetic_leaves_at_block(8, 21_332_254);
    let tree1_pos0_leaf = tree1_full[0].leaf;

    let mut tree0_rows = Vec::new();
    let mut tree0_imt = Imt::new().expect("imt new");
    for i in 0usize..8 {
        let mut leaf = [0u8; 32];
        leaf[24..32].copy_from_slice(&((i as u64) + 100).to_be_bytes());
        tree0_imt.insert_leaves(i, &[leaf]).expect("insert");
        tree0_rows.push(CommitmentRow {
            tree_position: i as u64,
            leaf,
            block_number: 21_332_254,
        });
    }
    let tree0_root = tree0_imt.root();
    tree0_rows.push(CommitmentRow {
        tree_position: 65_536,
        leaf: tree1_pos0_leaf,
        block_number: 21_332_254,
    });

    let chain = StubChain::new(20_000_000, 99);
    chain.record_root(0, tree0_root);
    chain.record_root(1, tree1_root);

    let mut carry = StowawayCarry::new();
    let cfg0 = cfg_for_boundary(0, fresh_data_dir("retag-tree-0"));
    let r0 = bootstrap_one_tree_with_carry(&cfg0, &StubLeaves::new(tree0_rows), &chain, &mut carry)
        .await
        .expect("tree 0 boundary repair");
    assert_eq!(r0.local_root, tree0_root);
    assert_eq!(r0.chain_static_membership, Some(true));

    let tree1_sparse: Vec<CommitmentRow> = tree1_full.iter().skip(1).cloned().collect();
    let cfg1 = cfg_for_boundary(1, fresh_data_dir("retag-tree-1"));
    let r1 =
        bootstrap_one_tree_with_carry(&cfg1, &StubLeaves::new(tree1_sparse), &chain, &mut carry)
            .await
            .expect("tree 1 byte-identity after re-tag");
    assert_eq!(r1.leaves, 8);
    assert_eq!(
        r1.local_root, tree1_root,
        "tree 1 IMT root must include the re-tagged stowaway at position 0"
    );
    assert_eq!(r1.chain_static_membership, Some(true));
    assert!(carry.is_empty(), "no residual carry after tree 1 drains it");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boundary_repair_recovers_missing_position_0_in_tree_1_via_carry_with_tail_default() {
    let (tree1_full, _) = synthetic_leaves_at_block(8, 21_332_254);
    let tree1_pos0_leaf = tree1_full[0].leaf;
    let last_idx = tree1_full.len() - 1;
    let last_position: u32 = u32::try_from(last_idx).expect("u32");

    let mut tree0_rows = Vec::new();
    for i in 0usize..4 {
        let mut leaf = [0u8; 32];
        leaf[24..32].copy_from_slice(&((i as u64) + 200).to_be_bytes());
        tree0_rows.push(CommitmentRow {
            tree_position: i as u64,
            leaf,
            block_number: 21_332_254,
        });
    }
    let mut tree0_imt = Imt::new().expect("imt new");
    for (i, r) in tree0_rows.iter().enumerate() {
        tree0_imt.insert_leaves(i, &[r.leaf]).expect("insert");
    }
    let tree0_root_4 = tree0_imt.root();
    tree0_rows.push(CommitmentRow {
        tree_position: 65_536,
        leaf: tree1_pos0_leaf,
        block_number: 21_332_254,
    });

    let cfg_tree0_local = BootstrapTreeConfig {
        tree_number: 0,
        checkpoint_depth: 64,
        data_dir: fresh_data_dir("recover-tree-0"),
        instance_id: "commit-tree-0-recover".to_owned(),
        max_wall_mins: 5,
        repair_trigger_threshold: 4,
        expected_filled_count: 4,
        ..BootstrapTreeConfig::default()
    };

    let sparse_rows: Vec<CommitmentRow> = tree1_full[1..last_idx].to_vec();
    assert!(sparse_rows.iter().all(|r| r.tree_position != 0));
    assert!(sparse_rows
        .iter()
        .all(|r| r.tree_position != u64::from(last_position)));

    let mut tree1_partial_imt = Imt::new().expect("imt new");
    tree1_partial_imt
        .insert_leaves(0, &[tree1_pos0_leaf])
        .expect("insert");
    for (offset, r) in sparse_rows.iter().enumerate() {
        tree1_partial_imt
            .insert_leaves(offset + 1, &[r.leaf])
            .expect("insert");
    }
    let tree1_partial_root = tree1_partial_imt.root();

    let chain = StubChain::new(20_000_000, 99);
    chain.record_root(0, tree0_root_4);
    chain.record_root(1, tree1_partial_root);

    let mut carry = StowawayCarry::new();
    let _r0 = bootstrap_one_tree_with_carry(
        &cfg_tree0_local,
        &StubLeaves::new(tree0_rows),
        &chain,
        &mut carry,
    )
    .await
    .expect("tree 0 prep");
    assert!(
        carry.contains_key(&1),
        "stowaway carried to tree 1 before tree 1 bootstrap"
    );

    let cfg1 = cfg_for_boundary(1, fresh_data_dir("recover-tree-1"));
    let r1 =
        bootstrap_one_tree_with_carry(&cfg1, &StubLeaves::new(sparse_rows), &chain, &mut carry)
            .await
            .expect("tree 1: position 0 from carry, tail default at position 7");
    assert_eq!(r1.leaves, last_idx);
    assert_eq!(r1.local_root, tree1_partial_root);
    assert_eq!(r1.chain_static_membership, Some(true));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boundary_repair_skips_tail_gap_when_tree_closed_short_of_capacity() {
    let (full_rows, _) = synthetic_leaves_at_block(8, 21_332_254);
    let last_idx = full_rows.len() - 1;
    let last_position: u32 = u32::try_from(last_idx).expect("u32");
    let sparse_rows: Vec<CommitmentRow> = full_rows[..last_idx].to_vec();
    assert!(sparse_rows
        .iter()
        .all(|r| r.tree_position != u64::from(last_position)));

    let mut partial_imt = Imt::new().expect("imt new");
    for (i, r) in sparse_rows.iter().enumerate() {
        partial_imt.insert_leaves(i, &[r.leaf]).expect("insert");
    }
    let partial_root = partial_imt.root();

    let leaves = StubLeaves::new(sparse_rows);
    let chain = StubChain::new(20_000_000, 99);
    chain.record_root(1, partial_root);
    let cfg = cfg_for_boundary(1, fresh_data_dir("commit-tree-1-tail-short"));
    let report = bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect("boundary repair tolerates tail gap when tree closed short");
    assert_eq!(report.leaves, last_idx);
    assert_eq!(report.local_root, partial_root);
    assert_eq!(report.chain_static_membership, Some(true));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boundary_repair_post_fix_chain_oracle_byte_identity_passes_all_three_filled_trees() {
    let (tree1_full, tree1_root) = synthetic_leaves_at_block(8, 21_332_254);
    let tree1_pos0 = tree1_full[0].leaf;
    let tree1_last_idx = tree1_full.len() - 1;
    let tree1_last_pos = u32::try_from(tree1_last_idx).expect("u32");
    let tree1_last_leaf = tree1_full[tree1_last_idx].leaf;
    let tree1_subsquid: Vec<CommitmentRow> = tree1_full[1..tree1_last_idx].to_vec();

    let (tree2_full, tree2_root) = synthetic_leaves_at_block(8, 21_332_254);
    let tree2_pos0 = tree2_full[0].leaf;
    let tree2_subsquid: Vec<CommitmentRow> = tree2_full.iter().skip(1).cloned().collect();

    let mut tree0_rows: Vec<CommitmentRow> = Vec::new();
    let mut tree0_imt = Imt::new().expect("imt new");
    for i in 0usize..8 {
        let mut leaf = [0u8; 32];
        leaf[24..32].copy_from_slice(&((i as u64) + 1000).to_be_bytes());
        tree0_imt.insert_leaves(i, &[leaf]).expect("insert");
        tree0_rows.push(CommitmentRow {
            tree_position: i as u64,
            leaf,
            block_number: 21_332_254,
        });
    }
    let tree0_root = tree0_imt.root();
    tree0_rows.push(CommitmentRow {
        tree_position: 65_536,
        leaf: tree1_pos0,
        block_number: 21_332_254,
    });

    let mut tree1_with_stowaway = tree1_subsquid.clone();
    tree1_with_stowaway.push(CommitmentRow {
        tree_position: 65_536,
        leaf: tree2_pos0,
        block_number: 21_332_254,
    });

    let mut tree1_partial_imt = Imt::new().expect("imt new");
    tree1_partial_imt
        .insert_leaves(0, &[tree1_pos0])
        .expect("insert");
    for (offset, r) in tree1_subsquid.iter().enumerate() {
        tree1_partial_imt
            .insert_leaves(offset + 1, &[r.leaf])
            .expect("insert");
    }
    let tree1_partial_root = tree1_partial_imt.root();
    let _ = (tree1_root, tree1_last_pos, tree1_last_leaf);

    let chain = StubChain::new(20_000_000, 99);
    chain.record_root(0, tree0_root);
    chain.record_root(1, tree1_partial_root);
    chain.record_root(2, tree2_root);

    let mut carry = StowawayCarry::new();

    let cfg0 = cfg_for_boundary(0, fresh_data_dir("e2e-all-three-tree-0"));
    let r0 = bootstrap_one_tree_with_carry(&cfg0, &StubLeaves::new(tree0_rows), &chain, &mut carry)
        .await
        .expect("tree 0 byte-identity");
    assert_eq!(r0.local_root, tree0_root);
    assert_eq!(r0.chain_static_membership, Some(true));

    let cfg1 = cfg_for_boundary(1, fresh_data_dir("e2e-all-three-tree-1"));
    let r1 = bootstrap_one_tree_with_carry(
        &cfg1,
        &StubLeaves::new(tree1_with_stowaway),
        &chain,
        &mut carry,
    )
    .await
    .expect("tree 1 byte-identity (closed short of capacity; tail default)");
    assert_eq!(r1.local_root, tree1_partial_root);
    assert_eq!(r1.chain_static_membership, Some(true));

    let cfg2 = cfg_for_boundary(2, fresh_data_dir("e2e-all-three-tree-2"));
    let r2 =
        bootstrap_one_tree_with_carry(&cfg2, &StubLeaves::new(tree2_subsquid), &chain, &mut carry)
            .await
            .expect("tree 2 byte-identity");
    assert_eq!(r2.local_root, tree2_root);
    assert_eq!(r2.chain_static_membership, Some(true));

    assert!(carry.is_empty(), "no residue after final tree drains carry");
}

/// Bootstrap at the encoder-derived production cell (65,536 x 32 B) must recover the
/// exact root the chain recorded, not merely finish.
///
/// Formerly three "seeds" that asserted nothing. The three runs shared one
/// `synthetic_leaves(64)` corpus and one `StubChain` and differed only in their
/// `data_dir` name, so they were the same bootstrap three times — three full
/// production-cell bootstraps per push, buying nothing. One run, asserted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "one full bootstrap at the 65,536 x 32 B production cell. Trigger: changing the \
            bootstrap path or the closing-root comparison at production parameters."]
async fn bootstrap_three_seed_production_cell_bench() {
    let (rows, root) = synthetic_leaves(64);
    let chain = StubChain::new(20_000_000, 99);
    chain.record_root(0, root);
    let cfg = BootstrapTreeConfig {
        tree_number: 0,
        checkpoint_depth: 64,
        data_dir: fresh_data_dir("prod-cell-bootstrap"),
        instance_id: "commit-tree-prod-cell".to_owned(),
        max_wall_mins: 30,
        ..BootstrapTreeConfig::default()
    };
    let leaves = StubLeaves::new(rows.clone());
    let report = bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect("production-cell bootstrap");

    assert_eq!(report.tree_number, 0);
    assert_eq!(
        report.leaves,
        rows.len(),
        "every fed leaf must land in the tree"
    );
    assert_eq!(
        report.local_root, root,
        "the rebuilt root must be byte-identical to the one the chain recorded"
    );
    assert_eq!(
        report.chain_static_membership,
        Some(true),
        "the closing root must be one rootHistory holds"
    );
    eprintln!(
        "production cell (65536 x 32 B): leaves={} wall={:.3}s",
        report.leaves, report.wall_clock_secs
    );
}

/// The three boundary-repair arms on a synthetic 8-leaf cell, each asserted on
/// its OUTCOME rather than its wall time:
///
/// - tree 0, a stowaway at `treePosition` 65,536: dropped into the carry, the
///   eight real leaves recover and the closing root is one the chain holds.
/// - tree 1, a FRONT gap (leaf 0 withheld from the feed): gap-walked and
///   chain-backfilled, so the tree still closes at eight leaves.
/// - tree 2, a TAIL gap (leaf 7 withheld): `repair_boundary_if_needed`
///   deliberately does NOT backfill past `max_observed_position` — a batch
///   never spans two trees, so a position beyond the last observed one means
///   the tree closed early rather than that a row was lost
///   (`bootstrap_subsquid.rs`, the tail-gap branch). The tree is therefore
///   short one leaf, and the closing-root comparison must REFUSE it loudly.
///   That refusal is the whole point: it is what stops a tail-truncated feed
///   from publishing a seven-leaf tree as if it were the closed eight-leaf one.
///
/// Formerly a `_bench` that ran three identical "seeds" per tree and asserted
/// nothing. `synthetic_leaves_at_block` takes no seed, so the three runs were
/// the same computation three times; one run per arm carries the same coverage
/// at a third of the wall time. The name is retained only so the cli-ignored
/// lane's subtraction term at ci.yml keeps resolving until that term is
/// removed — it now asserts and passes, so the subtraction should die.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "~26 s: three full bootstraps over a synthetic 8-leaf cell. Trigger: changing boundary \
            repair, the tail-gap policy, or the closing-root comparison."]
async fn boundary_repair_three_seed_per_tree_bench() {
    for tree_number in 0u32..3 {
        let (full_rows, root) = synthetic_leaves_at_block(8, 21_332_254);
        let mut sparse: Vec<CommitmentRow>;
        let chain = StubChain::new(20_000_000, 99);
        chain.record_root(tree_number, root);
        match tree_number {
            0 => {
                let mut rows = full_rows.clone();
                let mut stowaway = [0u8; 32];
                stowaway[31] = 0xff;
                rows.push(CommitmentRow {
                    tree_position: 65_536,
                    leaf: stowaway,
                    block_number: 21_332_254,
                });
                sparse = rows;
            }
            1 => {
                let pos0 = full_rows[0].leaf;
                sparse = full_rows.iter().skip(1).cloned().collect();
                chain.add_chain_event(21_332_254, 1, 0, pos0);
            }
            _ => {
                let last_idx = full_rows.len() - 1;
                let last_leaf = full_rows[last_idx].leaf;
                let last_pos = u32::try_from(last_idx).expect("u32");
                sparse = full_rows[..last_idx].to_vec();
                chain.add_chain_event(21_332_254, tree_number, last_pos, last_leaf);
            }
        }
        sparse.sort_by_key(|r| r.tree_position);
        let cfg = cfg_for_boundary(
            tree_number,
            fresh_data_dir(&format!("boundary-arm-tree{tree_number}")),
        );
        let leaves = StubLeaves::new(sparse);
        let outcome = bootstrap_one_tree(&cfg, &leaves, &chain).await;

        if tree_number == 2 {
            let err = outcome.expect_err(
                "a tail-truncated closed tree must be REFUSED: boundary repair does not backfill \
                 past the last observed position, so the tree is short its final leaf",
            );
            match err {
                BootstrapError::OracleByteIdentityMismatch {
                    kind,
                    tree_number: t,
                    first_match_index,
                    ..
                } => {
                    assert!(matches!(kind, OracleKind::ChainStaticTree), "got {kind:?}");
                    assert_eq!(t, 2);
                    // Seven leaves recovered; the refusal names the missing eighth.
                    assert_eq!(
                        first_match_index, 7,
                        "the refusal must name the leaf count it got to"
                    );
                }
                other => panic!("expected a closing-root refusal, got {other:?}"),
            }
            continue;
        }

        let report = outcome.expect("boundary repair must recover a stowaway and a front gap");
        assert_eq!(
            report.leaves, 8,
            "tree {tree_number} must close at all eight leaves after repair"
        );
        assert_eq!(
            report.local_root, root,
            "tree {tree_number} must rebuild the SAME root the chain recorded, not merely some \
             root of the right shape"
        );
        assert_eq!(
            report.chain_static_membership,
            Some(true),
            "tree {tree_number} closing root must be one rootHistory holds"
        );
        assert_eq!(report.tree_number, tree_number);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_with_encoder_per_node_writes_correct_manifest_label() {
    let (rows, root) = synthetic_leaves(8);
    let leaves = StubLeaves::new(rows);
    let chain = StubChain::new(20_000_000, 99);
    chain.record_root(0, root);
    let dir = fresh_data_dir("commit-tree-0-encoder-per-node");
    let mut cfg = cfg_for(0, dir.clone());
    cfg.encoder_kind = EncoderKind::PerNode { tree_number: 0 };
    bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect("bootstrap with per-node encoder ok");
    let layout = raven_railgun_persistence::StoreLayout::open(&dir).expect("layout");
    let manifest = raven_railgun_persistence::Manifest::load(&layout)
        .expect("load")
        .expect("manifest present");
    assert_eq!(
        manifest.encoder_label, "per-node",
        "manifest must carry the operator-supplied encoder label"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_default_encoder_field_is_per_leaf_bc_for_backward_compat() {
    let (rows, root) = synthetic_leaves(8);
    let leaves = StubLeaves::new(rows);
    let chain = StubChain::new(20_000_000, 99);
    chain.record_root(0, root);
    let dir = fresh_data_dir("commit-tree-0-encoder-default");
    let cfg = cfg_for(0, dir.clone());
    bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect("bootstrap with default encoder ok");
    let layout = raven_railgun_persistence::StoreLayout::open(&dir).expect("layout");
    let manifest = raven_railgun_persistence::Manifest::load(&layout)
        .expect("load")
        .expect("manifest present");
    assert_eq!(
        manifest.encoder_label, "per-leaf-bc",
        "BootstrapTreeConfig::default()'s encoder_kind must remain PerLeafBc \
         (existing tests rely on this default)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_with_encoder_per_leaf_path_writes_correct_manifest_label() {
    use raven_railgun_engine::pir_table::EncoderKind;
    let (rows, root) = synthetic_leaves(8);
    let leaves = StubLeaves::new(rows);
    let chain = StubChain::new(20_000_000, 99);
    chain.record_root(0, root);
    let dir = fresh_data_dir("commit-tree-0-encoder-per-leaf-path");
    let mut cfg = cfg_for(0, dir.clone());
    cfg.encoder_kind = EncoderKind::PerLeafPath { tree_number: 0 };
    bootstrap_one_tree(&cfg, &leaves, &chain)
        .await
        .expect("bootstrap with per-leaf-path encoder ok");
    let layout = raven_railgun_persistence::StoreLayout::open(&dir).expect("layout");
    let manifest = raven_railgun_persistence::Manifest::load(&layout)
        .expect("load")
        .expect("manifest present");
    assert_eq!(manifest.encoder_label, "per-leaf-path");
}

#[test]
fn bootstrap_rejects_invalid_encoder_kind_at_parse_time() {
    let bin = env!("CARGO_BIN_EXE_raven-railgun");
    let tmp = tempfile::tempdir().expect("tempdir");
    let pool_cfg = tmp.path().join("rpc-pool.toml");
    std::fs::write(&pool_cfg, "[[endpoint]]\nurl = \"http://127.0.0.1:1\"\n")
        .expect("write pool cfg");
    let template = tmp.path().join("tree-{N}").to_string_lossy().into_owned();
    let out = std::process::Command::new(bin)
        .arg("bootstrap-from-subsquid")
        .arg("--rpc-pool-config")
        .arg(&pool_cfg)
        .arg("--data-dir-template")
        .arg(&template)
        .arg("--tree-numbers")
        .arg("0")
        .arg("--encoder")
        .arg("garbage")
        .output()
        .expect("spawn raven-railgun");
    assert!(
        !out.status.success(),
        "expected non-zero exit on bogus --encoder"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unknown --encoder garbage"),
        "stderr must surface the encoder-parse error verbatim; got: {stderr}"
    );
    assert!(
        stderr.contains("per-leaf-bc")
            && stderr.contains("per-leaf-path")
            && stderr.contains("per-node"),
        "stderr must list the accepted encoder family names; got: {stderr}"
    );
}

#[test]
fn bootstrap_rejects_invalid_ppoi_status_encoder_at_parse_time() {
    let bin = env!("CARGO_BIN_EXE_raven-railgun");
    let tmp = tempfile::tempdir().expect("tempdir");
    let pool_cfg = tmp.path().join("rpc-pool.toml");
    std::fs::write(&pool_cfg, "[[endpoint]]\nurl = \"http://127.0.0.1:1\"\n")
        .expect("write pool cfg");
    let template = tmp.path().join("tree-{N}").to_string_lossy().into_owned();
    let out = std::process::Command::new(bin)
        .arg("bootstrap-from-subsquid")
        .arg("--rpc-pool-config")
        .arg(&pool_cfg)
        .arg("--data-dir-template")
        .arg(&template)
        .arg("--tree-numbers")
        .arg("0")
        .arg("--ppoi-status-encoder")
        .arg("not-a-real-encoder")
        .output()
        .expect("spawn raven-railgun");
    assert!(
        !out.status.success(),
        "expected non-zero exit on bogus --ppoi-status-encoder"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unknown ppoi encoder not-a-real-encoder"),
        "stderr must surface the ppoi-encoder-parse error; got: {stderr}"
    );
}

mod ppoi_resilience {
    use super::*;
    use axum::{routing::post, Json, Router};
    use parking_lot::Mutex as PMutex;
    use std::io;
    use std::sync::Arc as StdArc;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    type StubFn = StdArc<
        dyn Fn(
                serde_json::Value,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = (axum::http::StatusCode, String)> + Send>,
            > + Send
            + Sync,
    >;

    async fn spawn_ppoi_stub(handler: StubFn) -> (String, oneshot::Sender<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let app = Router::new().route(
            "/",
            post(move |Json(body): Json<serde_json::Value>| {
                let h = StdArc::clone(&handler);
                async move { h(body).await }
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });
        (format!("http://{addr}"), shutdown_tx)
    }

    /// Bootstrap is bounded by `ppoi_node_status`, so EVERY stub must answer it.
    /// A stub that does not panics on the absent `startIndex`, drops the connection, and
    /// turns a row-semantics test into a transport test that proves nothing.
    fn node_status_result(request: &serde_json::Value, total: u64) -> (axum::http::StatusCode, String) {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {
                "forNetwork": {
                    "Ethereum": {
                        "listStatuses": {
                            "abababababababababababababababababababababababababababababababab": {
                                "poiEventLengths": { "Shield": total },
                                "historicalMerklerootsLength": total
                            }
                        }
                    }
                }
            }
        });
        (
            axum::http::StatusCode::OK,
            serde_json::to_string(&body).expect("serialize"),
        )
    }

    fn ok_body_one_event() -> StubFn {
        StdArc::new(|request: serde_json::Value| {
            Box::pin(async move {
                if request.get("method") == Some(&serde_json::json!("ppoi_node_status")) {
                    return node_status_result(&request, 1);
                }
                let mut imt = Imt::new().expect("imt");
                let mut leaf = [0u8; 32];
                leaf[31] = 0x01;
                imt.insert_leaves(0, &[leaf]).expect("insert");
                let root = imt.root();
                let start = request["params"]["startIndex"]
                    .as_u64()
                    .expect("startIndex");
                let result = if start == 0 {
                    serde_json::json!([{
                        "signedPOIEvent": {
                            "index": 0u64,
                            "blindedCommitment": format!("0x{}", hex_lower(&leaf)),
                            "signature": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                            "type": "Shield",
                        },
                        "validatedMerkleroot": format!("0x{}", hex_lower(&root)),
                    }])
                } else {
                    serde_json::json!([])
                };
                (
                    axum::http::StatusCode::OK,
                    serde_json::to_string(&serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": request["id"],
                        "result": result,
                    }))
                    .expect("ser"),
                )
            })
        })
    }

    fn always_503() -> StubFn {
        StdArc::new(|_body: serde_json::Value| {
            Box::pin(async move {
                (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "boom".to_owned(),
                )
            })
        })
    }

    fn hex_lower(b: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            let _ = write!(s, "{byte:02x}");
        }
        s
    }

    /// URL on a bound-then-closed port so connects fail fast (connect-refused branch).
    async fn sealed_url() -> String {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = l.local_addr().expect("local addr");
        drop(l);
        format!("http://{addr}")
    }

    #[derive(Clone, Default)]
    struct LogCapture(StdArc<PMutex<Vec<u8>>>);

    impl LogCapture {
        fn snapshot(&self) -> String {
            String::from_utf8_lossy(&self.0.lock()).to_string()
        }
    }

    impl io::Write for LogCapture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
        type Writer = LogCapture;
        fn make_writer(&'a self) -> Self::Writer {
            LogCapture(StdArc::clone(&self.0))
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ppoi_bootstrap_refuses_a_sparse_scan_that_ends_at_the_advertised_count() {
        let mut imt = Imt::new().expect("imt");
        let mut events = Vec::new();
        for index in 0..502usize {
            let index_u64 = u64::try_from(index).expect("index fits u64");
            let mut leaf = [0u8; 32];
            leaf[24..].copy_from_slice(&(index_u64 + 1).to_be_bytes());
            imt.insert_leaves(index, &[leaf]).expect("insert");
            events.push(serde_json::json!({
                "signedPOIEvent": {
                    "index": index_u64,
                    "blindedCommitment": format!("0x{}", hex_lower(&leaf)),
                    "signature": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "type": "Shield",
                },
                "validatedMerkleroot": format!("0x{}", hex_lower(&imt.root())),
            }));
        }
        let events = StdArc::new(events);
        let spans = StdArc::new(PMutex::new(Vec::new()));
        let handler: StubFn = StdArc::new({
            let events = StdArc::clone(&events);
            let spans = StdArc::clone(&spans);
            move |request: serde_json::Value| {
                let events = StdArc::clone(&events);
                let spans = StdArc::clone(&spans);
                Box::pin(async move {
                    assert_eq!(request.get("jsonrpc"), Some(&serde_json::json!("2.0")));
                    if request.get("method") == Some(&serde_json::json!("ppoi_node_status")) {
                        let body = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": request["id"],
                            "result": {
                                "forNetwork": {
                                    "Ethereum": {
                                        "listStatuses": {
                                            "abababababababababababababababababababababababababababababababab": {
                                                "poiEventLengths": { "Shield": 502 },
                                                "historicalMerklerootsLength": 502
                                            }
                                        }
                                    }
                                }
                            }
                        });
                        return (
                            axum::http::StatusCode::OK,
                            serde_json::to_string(&body).expect("serialize"),
                        );
                    }
                    assert_eq!(
                        request.get("method"),
                        Some(&serde_json::json!("ppoi_poi_events"))
                    );
                    let params = &request["params"];
                    assert_eq!(params.get("chainType"), Some(&serde_json::json!("0")));
                    assert_eq!(params.get("chainID"), Some(&serde_json::json!("1")));
                    let start = params["startIndex"].as_u64().expect("startIndex");
                    let end = params["endIndex"].as_u64().expect("endIndex");
                    spans.lock().push((start, end));
                    let page = events
                        .iter()
                        .filter(|event| {
                            let index = event["signedPOIEvent"]["index"].as_u64().expect("index");
                            index != 250 && (start..=end).contains(&index)
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    let body = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": request["id"],
                        "result": page,
                    });
                    (
                        axum::http::StatusCode::OK,
                        serde_json::to_string(&body).expect("serialize"),
                    )
                })
            }
        });
        let (endpoint, shutdown) = spawn_ppoi_stub(handler).await;
        let client = RailwayPpoiClient::new(endpoint, 0, 1).expect("client");

        let error = client
            .fetch_all_events([0xab; 32])
            .await
            .expect_err("missing index 250 must not return a truncated successful prefix");

        assert!(error.to_string().contains("501 rows"), "{error}");
        assert!(error.to_string().contains("count 502"), "{error}");
        assert_eq!(*spans.lock(), vec![(0, 500), (501, 501)]);
        let _ = shutdown.send(());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ppoi_bootstrap_falls_back_after_semantically_invalid_rows() {
        let malformed: StubFn = StdArc::new(|request: serde_json::Value| {
            Box::pin(async move {
                if request.get("method") == Some(&serde_json::json!("ppoi_node_status")) {
                    return node_status_result(&request, 1);
                }
                let body = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "result": [{
                        "signedPOIEvent": {"index": 0, "blindedCommitment": "not-hex"},
                        "validatedMerkleroot": "00"
                    }],
                });
                (
                    axum::http::StatusCode::OK,
                    serde_json::to_string(&body).expect("serialize"),
                )
            })
        });
        let (bad, bad_shutdown) = spawn_ppoi_stub(malformed).await;
        let (good, good_shutdown) = spawn_ppoi_stub(ok_body_one_event()).await;
        let client = RailwayPpoiClient::new_multi(vec![bad, good], 0, 1).expect("client");

        let rows = client
            .fetch_all_events([0xab; 32])
            .await
            .expect("healthy second base wins");

        assert_eq!(rows.len(), 1);
        let _ = bad_shutdown.send(());
        let _ = good_shutdown.send(());
    }

    /// Multi-URL walker skips two dead bases (sealed + 503) and serves from the third.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ppoi_bootstrap_multi_url_fallback_walks_url_list() {
        let bad = sealed_url().await;
        let (mid, mid_shutdown) = spawn_ppoi_stub(always_503()).await;
        let (good, good_shutdown) = spawn_ppoi_stub(ok_body_one_event()).await;

        let client =
            RailwayPpoiClient::new_multi(vec![bad.clone(), mid.clone(), good.clone()], 0, 1)
                .expect("multi-URL client builds");
        let bases = client.bases().to_vec();
        assert_eq!(bases.len(), 3, "all 3 bases retained");

        let report = bootstrap_one_list_with_mode(
            [0xab; 32],
            &client,
            "/tmp/raven/list-{LIST_KEY}",
            PpoiBootstrapMode::Strict,
            &bases,
        )
        .await
        .expect("walker reaches the third base");
        assert_eq!(
            report.events, 1,
            "exactly one event served from the third base"
        );

        let _ = mid_shutdown.send(());
        let _ = good_shutdown.send(());
    }

    /// All sources dead: skip-on-unreachable WARNs about the signature gap and seeds an empty IMT.
    ///
    /// `current_thread` so the `set_default` thread-local subscriber sees the bootstrap's emissions.
    #[tokio::test(flavor = "current_thread")]
    async fn ppoi_bootstrap_skip_on_unreachable_logs_gap_and_seeds_empty_imt() {
        let bad1 = sealed_url().await;
        let bad2 = sealed_url().await;

        let client = RailwayPpoiClient::new_multi(vec![bad1.clone(), bad2.clone()], 0, 1)
            .expect("client builds");
        let bases = client.bases().to_vec();

        let capture = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::WARN)
            .without_time()
            .with_ansi(false)
            .finish();

        let guard = tracing::subscriber::set_default(subscriber);
        let report = bootstrap_one_list_with_mode(
            [0xcd; 32],
            &client,
            "/tmp/raven/list-{LIST_KEY}",
            PpoiBootstrapMode::SkipOnUnreachable,
            &bases,
        )
        .await
        .expect("skip-on-unreachable returns Ok with empty IMT");
        drop(guard);

        assert_eq!(report.events, 0, "empty IMT seeded");
        let empty = Imt::new().expect("imt").root();
        assert_eq!(report.local_root, empty, "local_root is the empty-IMT root");

        let logs = capture.snapshot();
        assert!(
            logs.contains("PPOI bootstrap skipped"),
            "warn log fires: {logs}"
        );
        assert!(
            logs.contains("UPSTREAM SIGNATURE VERIFY GAP"),
            "warn log surfaces signature gap: {logs}"
        );
        assert!(
            logs.contains("seeded EMPTY"),
            "warn log states the IMT seeding: {logs}"
        );
        assert!(
            logs.contains(&bad1) || logs.contains(&bad2),
            "warn log lists at least one tried source: {logs}"
        );
    }

    /// Strict mode (the default) hard-stops with `PpoiUnreachable` when every source fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ppoi_bootstrap_strict_mode_returns_pp_unreachable_error_when_all_fail() {
        let bad1 = sealed_url().await;
        let (bad2, shutdown_bad2) = spawn_ppoi_stub(always_503()).await;
        let client = RailwayPpoiClient::new_multi(vec![bad1, bad2], 0, 1).expect("client");
        let bases = client.bases().to_vec();
        let err = bootstrap_one_list_with_mode(
            [0xef; 32],
            &client,
            "/tmp/raven/list-{LIST_KEY}",
            PpoiBootstrapMode::Strict,
            &bases,
        )
        .await
        .expect_err("strict mode hard-stops");
        match err {
            BootstrapError::PpoiUnreachable(msg) => {
                assert!(
                    msg.contains("all"),
                    "error message mentions exhausted bases: {msg}"
                );
            }
            other => panic!("expected PpoiUnreachable, got {other:?}"),
        }
        let _ = shutdown_bad2.send(());
    }

    /// The multi-URL constructor rejects empty and whitespace-only base lists.
    #[test]
    fn railway_ppoi_client_rejects_empty_base_list() {
        let err = RailwayPpoiClient::new_multi(vec![], 0, 1).expect_err("empty list rejected");
        assert!(err.to_string().contains("at least one"), "{err}");
        let err2 = RailwayPpoiClient::new_multi(vec!["   ".to_owned()], 0, 1)
            .expect_err("whitespace-only rejected");
        assert!(err2.to_string().contains("empty"), "{err2}");
    }

    /// Single-base `RailwayPpoiClient::new` must enforce a per-URL timeout against a
    /// silent server; a no-timeout `reqwest::Client::new()` would hang forever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn railway_ppoi_single_base_times_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind silent listener");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let _hold = stream;
                    std::future::pending::<()>().await;
                });
            }
        });
        let url = format!("http://{addr}");
        let client = RailwayPpoiClient::new(url, 0, 1).expect("bounded client");

        // 60s outer bracket so a missing per-URL timeout fails fast instead of hanging
        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            bootstrap_one_list_with_mode(
                [0xcd; 32],
                &client,
                "/tmp/raven/list-{LIST_KEY}",
                PpoiBootstrapMode::SkipOnUnreachable,
                client.bases(),
            ),
        )
        .await
        .expect("must error inside 60s when per-URL timeout is wired");
        let elapsed = started.elapsed();

        let report = outcome.expect("skip-on-unreachable degrades to empty");
        assert_eq!(report.events, 0, "no events from a silent server");
        assert!(
            elapsed < std::time::Duration::from_secs(45),
            "elapsed {elapsed:?} > 45s suggests the per-URL timeout did not fire"
        );
    }

    /// Mode parser smoke.
    #[test]
    fn ppoi_bootstrap_mode_parses_cli_strings() {
        assert_eq!(
            PpoiBootstrapMode::parse_cli("strict").expect("strict ok"),
            PpoiBootstrapMode::Strict
        );
        assert_eq!(
            PpoiBootstrapMode::parse_cli("skip-on-unreachable").expect("skip ok"),
            PpoiBootstrapMode::SkipOnUnreachable
        );
        let err = PpoiBootstrapMode::parse_cli("nonsense").expect_err("rejects unknown");
        assert!(err.contains("unknown"), "{err}");
    }
}
