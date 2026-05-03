//! Workstream H closure for Layer 2 root-verifier wiring into the
//! orchestrator's `drive_commit` loop. Locks: per-commit verify on
//! ChainRootHistory; OutOfSync cascade through `apply_reorg`;
//! UpstreamSignature instances never call the verifier.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::redundant_closure_for_method_calls
)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::{CommitmentLeaf, RailgunEvent};
use raven_railgun_engine::inspire::{setup_state, InspireServerState};
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine, OrchestratorConfig, VerificationMode,
};
use raven_railgun_engine::persistence::{ConsumerEvent, SnapshotPolicy};
use raven_railgun_engine::InstanceRole;
use raven_railgun_indexer::{BlockId, ChainSource, IndexerError, Result as IndexerResult};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-w2-layer2-test";

/// Synthetic [`ChainSource`] for verifier wiring tests. Returns
/// `InSync` for the first `flip_after_calls` rounds, then `OutOfSync`
/// (fixed `[0xee; 32]` root) so the active-tree branch sees rootHistory
/// hit but merkle_root mismatch.
struct SyntheticChainSource {
    verify_calls: AtomicU64,
    merkle_root_calls: AtomicU64,
    root_history_calls: AtomicU64,
    active_tree_calls: AtomicU64,
    flip_after_calls: u64,
    // Verifier runs `root_history(tree, local_root)` BEFORE
    // `merkle_root()`; caching the value here lets the synthetic
    // `merkle_root()` return the in-sync match without mirroring the
    // engine's IMT in the test.
    last_seen_root: parking_lot::Mutex<[u8; 32]>,
}

impl SyntheticChainSource {
    fn new(flip_after_calls: u64) -> Self {
        Self {
            verify_calls: AtomicU64::new(0),
            merkle_root_calls: AtomicU64::new(0),
            root_history_calls: AtomicU64::new(0),
            active_tree_calls: AtomicU64::new(0),
            flip_after_calls,
            last_seen_root: parking_lot::Mutex::new([0u8; 32]),
        }
    }

    fn verify_count(&self) -> u64 {
        self.verify_calls.load(Ordering::SeqCst)
    }

    fn root_history_count(&self) -> u64 {
        self.root_history_calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ChainSource for SyntheticChainSource {
    async fn latest_block(&self) -> IndexerResult<u64> {
        Ok(20_000_000)
    }
    async fn events_in_range(
        &self,
        _from_block: u64,
        _to_block: u64,
    ) -> IndexerResult<Vec<RailgunEvent>> {
        Err(IndexerError::Rpc("synthetic: events_in_range".into()))
    }
    async fn root_history(
        &self,
        _tree_number: u32,
        merkle_root: [u8; 32],
        _at: Option<BlockId>,
    ) -> IndexerResult<bool> {
        self.root_history_calls.fetch_add(1, Ordering::SeqCst);
        *self.last_seen_root.lock() = merkle_root;
        Ok(true)
    }
    async fn block_hash(&self, _block_number: u64) -> IndexerResult<[u8; 32]> {
        Err(IndexerError::Rpc("synthetic: block_hash".into()))
    }
    async fn merkle_root(&self, _at: Option<BlockId>) -> IndexerResult<[u8; 32]> {
        self.merkle_root_calls.fetch_add(1, Ordering::SeqCst);
        let v = self.verify_calls.fetch_add(1, Ordering::SeqCst);
        if v + 1 > self.flip_after_calls {
            Ok([0xee; 32])
        } else {
            Ok(*self.last_seen_root.lock())
        }
    }
    async fn active_tree_number(&self, _at: Option<BlockId>) -> IndexerResult<u32> {
        self.active_tree_calls.fetch_add(1, Ordering::SeqCst);
        Ok(0)
    }
}

fn build_toy_state() -> raven_railgun_core::Result<InspireServerState> {
    let params = InspireParams::secure_128_d2048();
    let entries = 256usize;
    let entry_size = 256usize;
    let db: Vec<u8> = (0..entries)
        .flat_map(|i| (0..entry_size).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
        .collect();
    let (state, _sk) = setup_state(&params, &db, entry_size, InspireVariant::TwoPacking)?;
    Ok(state)
}

fn canonical_commitment(byte: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    // High byte must be < 0x30 to keep the value Fr-canonical for the
    // IMT's Poseidon hash; differentiate via the low byte.
    b[31] = byte;
    b
}

fn aggressive_snapshot_policy() -> SnapshotPolicy {
    SnapshotPolicy {
        max_appends_per_snapshot: 1,
        ..SnapshotPolicy::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn layer2_verifier_fires_per_commit_and_cascades_reorg_on_out_of_sync() {
    let dir = tempfile::tempdir().expect("tempdir");
    let chain_source = Arc::new(SyntheticChainSource::new(5));

    let mut config = OrchestratorConfig::demo(dir.path().to_path_buf(), "w2-positive");
    config.use_flock = false;
    config.role = InstanceRole::Live;
    config.scheme_tag = SCHEME_TAG.to_owned();
    config.snapshot_policy = aggressive_snapshot_policy();
    config.verification_mode = VerificationMode::ChainRootHistory;
    config.verification_cadence_n = 1;
    config.verification_tree_number = 0;
    config.chain_source = Some(Arc::clone(&chain_source) as Arc<dyn ChainSource>);

    let params = InspireParams::secure_128_d2048();
    let handle = bootstrap_railgun_engine(config, params, build_toy_state).expect("bootstrap");

    // 50 single-leaf Transacts at blocks 100..150; every event triggers
    // a commit (max_appends_per_snapshot = 1) and the verifier fires
    // (cadence_n = 1). The synthetic source stashes the root the
    // verifier passes to `root_history` and returns it from
    // `merkle_root()`, so we don't thread roots through a side channel.
    for i in 0..50u32 {
        let height = 100 + u64::from(i);
        let leaf = canonical_commitment(u8::try_from((i & 0xff) | 0x01).expect("byte"));
        let event = RailgunEvent::Transact {
            block_number: height,
            tx_hash: [0u8; 32],
            tree_number: 0,
            start_position: i,
            leaves: vec![CommitmentLeaf {
                tree_number: 0,
                leaf_index: i,
                commitment_hash: leaf,
                ciphertext: vec![],
            }],
        };
        handle
            .sender
            .send(ConsumerEvent::Chain(event, height))
            .await
            .expect("send leaf");
    }

    // First 5 leaves verify InSync; the 6th flips and cascades a
    // synthetic Reorg(104) through `apply_reorg`. Asserting on
    // `reorgs_handled >= 1` rather than full drain because the cascade
    // is the load-bearing post-condition (post-cascade leaf appends are
    // rejected as non-contiguous, so events_processed stalls).
    let drain_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let m = *handle.metrics.lock();
        if m.reorgs_handled >= 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < drain_deadline,
            "cascade reorg did not fire within 20 s; \
             events_processed = {}, commits_fired = {}, reorgs_handled = {}, verify_calls = {}",
            m.events_processed,
            m.commits_fired,
            m.reorgs_handled,
            chain_source.verify_count(),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Final tick for the verifier to run on trailing commits.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let verify_calls = chain_source.verify_count();
    assert!(
        verify_calls >= 6,
        "verifier must have fired at least 6 times (5 InSync + 1 OutOfSync flip); got {verify_calls}"
    );

    let metrics = *handle.metrics.lock();
    assert!(
        metrics.reorgs_handled >= 1,
        "OutOfSync cascade must have fired apply_reorg at least once; got {}",
        metrics.reorgs_handled,
    );

    let post_cascade_count = handle.logical_store.lock().leaf_count();
    assert!(
        post_cascade_count <= 5,
        "post-cascade leaf_count must be <= 5 (the flip-window survivor); got {post_cascade_count}"
    );

    // Leaf at index 0 landed at block 100 <= last_in_sync_height = 104.
    assert!(
        handle.logical_store.lock().leaf(0, 0).is_some(),
        "leaf at index 0 must survive the cascade",
    );

    // root_history must be consulted at least once per verify cycle
    // (anchor-threading regression guard).
    let history_calls = chain_source.root_history_count();
    assert!(
        history_calls >= verify_calls,
        "root_history must be called at least once per verify cycle; verify={verify_calls}, history={history_calls}"
    );

    handle
        .sender
        .send(ConsumerEvent::Shutdown)
        .await
        .expect("shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(10), handle.consumer).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn layer2_verifier_does_not_fire_on_upstream_signature_instance() {
    let dir = tempfile::tempdir().expect("tempdir");
    // flip_after_calls = 0: fail on first verify call. If the verifier
    // fires for an UpstreamSignature instance, verify_count() > 0
    // catches it immediately.
    let chain_source = Arc::new(SyntheticChainSource::new(0));

    let mut config = OrchestratorConfig::demo(dir.path().to_path_buf(), "w2-ppoi-regression");
    config.use_flock = false;
    config.role = InstanceRole::Live;
    config.scheme_tag = SCHEME_TAG.to_owned();
    config.snapshot_policy = aggressive_snapshot_policy();
    config.verification_mode = VerificationMode::UpstreamSignature;
    config.verification_cadence_n = 1;
    config.verification_tree_number = 0;
    config.chain_source = Some(Arc::clone(&chain_source) as Arc<dyn ChainSource>);

    let params = InspireParams::secure_128_d2048();
    let handle = bootstrap_railgun_engine(config, params, build_toy_state).expect("bootstrap");

    for i in 0..10u32 {
        let height = 200 + u64::from(i);
        let event = RailgunEvent::Transact {
            block_number: height,
            tx_hash: [0u8; 32],
            tree_number: 0,
            start_position: i,
            leaves: vec![CommitmentLeaf {
                tree_number: 0,
                leaf_index: i,
                commitment_hash: canonical_commitment(
                    u8::try_from((i & 0xff) | 0x10).expect("byte"),
                ),
                ciphertext: vec![],
            }],
        };
        handle
            .sender
            .send(ConsumerEvent::Chain(event, height))
            .await
            .expect("send");
    }

    let drain_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let m = *handle.metrics.lock();
        if m.events_processed >= 10 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < drain_deadline,
            "consumer did not drain 10 events within 10 s; events_processed = {}",
            m.events_processed,
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        chain_source.verify_count(),
        0,
        "UpstreamSignature instance MUST NOT call the chain verifier",
    );
    let metrics = *handle.metrics.lock();
    assert_eq!(
        metrics.reorgs_handled, 0,
        "no synthetic reorg should fire on an UpstreamSignature instance",
    );

    handle
        .sender
        .send(ConsumerEvent::Shutdown)
        .await
        .expect("shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(10), handle.consumer).await;
}
