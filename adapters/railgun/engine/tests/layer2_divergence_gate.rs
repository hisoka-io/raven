//! The Layer 2 divergence gate. Every unrepaired out-of-sync verdict must mark
//! the instance, the mark must outlive the process, and a commit stream that has
//! stalled must not silence the verifier that would set it.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::redundant_closure_for_method_calls
)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::{CommitmentLeaf, RailgunEvent};
use raven_railgun_engine::inspire::{setup_state, InspireServerState};
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine, OrchestratorConfig, VerificationMode,
};
use raven_railgun_engine::persistence::{
    clear_layer2_divergent, layer2_divergent_instances, ConsumerEvent, ConsumerMetrics,
    SnapshotPolicy,
};
use raven_railgun_engine::InstanceRole;
use raven_railgun_indexer::{BlockId, ChainSource, IndexerError, Result as IndexerResult};
use raven_railgun_persistence::SnapshotId;

const SCHEME_TAG: &str = "raven-inspire-twopacking-layer2-divergence-gate";
const TOY_ENTRY_SIZE: usize = 256;

/// Verdict is flipped by the test between phases; `root_history` caches the
/// engine's root so the in-sync branch agrees without mirroring the IMT.
struct ScriptedChainSource {
    in_sync: AtomicBool,
    rounds: AtomicU64,
    last_seen_root: parking_lot::Mutex<[u8; 32]>,
}

impl ScriptedChainSource {
    fn new(in_sync: bool) -> Self {
        Self {
            in_sync: AtomicBool::new(in_sync),
            rounds: AtomicU64::new(0),
            last_seen_root: parking_lot::Mutex::new([0u8; 32]),
        }
    }

    fn set_in_sync(&self, v: bool) {
        self.in_sync.store(v, Ordering::SeqCst);
    }

    fn rounds(&self) -> u64 {
        self.rounds.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ChainSource for ScriptedChainSource {
    async fn latest_block(&self) -> IndexerResult<u64> {
        Ok(20_000_000)
    }
    async fn events_in_range(
        &self,
        _from_block: u64,
        _to_block: u64,
    ) -> IndexerResult<Vec<RailgunEvent>> {
        Err(IndexerError::Rpc("scripted: events_in_range".into()))
    }
    async fn root_history(
        &self,
        _tree_number: u32,
        merkle_root: [u8; 32],
        _at: Option<BlockId>,
    ) -> IndexerResult<bool> {
        *self.last_seen_root.lock() = merkle_root;
        Ok(true)
    }
    async fn block_hash(&self, _block_number: u64) -> IndexerResult<[u8; 32]> {
        Err(IndexerError::Rpc("scripted: block_hash".into()))
    }
    async fn merkle_root(&self, _at: Option<BlockId>) -> IndexerResult<[u8; 32]> {
        self.rounds.fetch_add(1, Ordering::SeqCst);
        if self.in_sync.load(Ordering::SeqCst) {
            Ok(*self.last_seen_root.lock())
        } else {
            Ok([0xee; 32])
        }
    }
    async fn active_tree_number(&self, _at: Option<BlockId>) -> IndexerResult<u32> {
        Ok(0)
    }
}

fn build_toy_state() -> raven_railgun_core::Result<InspireServerState> {
    let params = InspireParams::secure_128_d2048();
    let entries = 256usize;
    let db: Vec<u8> = (0..entries)
        .flat_map(|i| (0..TOY_ENTRY_SIZE).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
        .collect();
    let (state, _sk) = setup_state(&params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking)?;
    Ok(state)
}

fn canonical_commitment(byte: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    // Keeps the value Fr-canonical for the IMT's Poseidon hash.
    b[31] = byte;
    b
}

fn leaf_event(leaf_index: u32, height: u64) -> RailgunEvent {
    RailgunEvent::Transact {
        block_number: height,
        tx_hash: [0u8; 32],
        tree_number: 0,
        start_position: leaf_index,
        leaves: vec![CommitmentLeaf {
            tree_number: 0,
            leaf_index,
            commitment_hash: canonical_commitment(
                u8::try_from((leaf_index & 0xff) | 0x60).expect("byte"),
            ),
            ciphertext: vec![],
        }],
    }
}

fn verifying_config(
    dir: &std::path::Path,
    instance_id: &str,
    chain_source: &Arc<ScriptedChainSource>,
    appends_per_snapshot: usize,
) -> OrchestratorConfig {
    let mut config = OrchestratorConfig::demo(dir.to_path_buf(), instance_id);
    config.record_size = TOY_ENTRY_SIZE;
    config.use_flock = false;
    config.role = InstanceRole::Live;
    SCHEME_TAG.clone_into(&mut config.scheme_tag);
    config.snapshot_policy = SnapshotPolicy {
        max_appends_per_snapshot: appends_per_snapshot,
        ..SnapshotPolicy::default()
    };
    config.verification_mode = VerificationMode::ChainRootHistory;
    config.verification_cadence_n = 1;
    config.verification_tree_number = 0;
    config.chain_source = Some(Arc::clone(chain_source) as Arc<dyn ChainSource>);
    config
}

async fn await_marked(instance_id: &str, label: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while !layer2_divergent_instances()
        .iter()
        .any(|id| id == instance_id)
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{label}: {instance_id} was never marked divergent; marked = {:?}",
            layer2_divergent_instances(),
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn await_metrics<F: Fn(&ConsumerMetrics) -> bool>(
    metrics: &parking_lot::Mutex<ConsumerMetrics>,
    label: &str,
    done: F,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let snap = *metrics.lock();
        if done(&snap) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{label}: events_processed = {}, commits_fired = {}, \
             consumer_errors = {}, reorgs_handled = {}",
            snap.events_processed,
            snap.commits_fired,
            snap.consumer_errors,
            snap.reorgs_handled,
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// The anchored arm repairs by cascading a synthetic reorg. When that repair
/// fails the verdict stands unrepaired, so it must mark exactly as the arm with
/// no anchor does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_anchored_verdict_whose_repair_fails_marks_the_instance_divergent() {
    const INSTANCE_ID: &str = "layer2-gate-failed-repair";
    clear_layer2_divergent(INSTANCE_ID);

    let dir = tempfile::tempdir().expect("tempdir");
    let chain_source = Arc::new(ScriptedChainSource::new(true));
    let config = verifying_config(dir.path(), INSTANCE_ID, &chain_source, 1);
    let params = InspireParams::secure_128_d2048();
    let handle = bootstrap_railgun_engine(config, params, build_toy_state).expect("bootstrap");

    handle
        .sender
        .send(ConsumerEvent::Chain(leaf_event(0, 100), 100))
        .await
        .expect("send anchoring leaf");
    await_metrics(&handle.metrics, "anchoring leaf", |m| m.commits_fired >= 1).await;
    assert!(
        !layer2_divergent_instances()
            .iter()
            .any(|id| id == INSTANCE_ID),
        "an in-sync verdict must leave the instance unmarked",
    );

    // The next leaf commits first, so the synthetic reorg's commit is the one
    // after it; a plain file where its staging dir goes fails that save.
    let blocked = handle
        .persistence
        .layout()
        .snapshot_dir(SnapshotId(handle.persistence.current_snapshot_id().0 + 2))
        .with_extension("tmp");
    std::fs::write(&blocked, b"repair-must-fail").expect("plant the commit blocker");

    chain_source.set_in_sync(false);
    handle
        .sender
        .send(ConsumerEvent::Chain(leaf_event(1, 101), 101))
        .await
        .expect("send diverging leaf");
    await_marked(INSTANCE_ID, "failed repair").await;

    assert!(
        handle.metrics.lock().consumer_errors >= 1,
        "the failed synthetic reorg must also be recorded as a consumer error",
    );

    handle
        .sender
        .send(ConsumerEvent::Shutdown)
        .await
        .expect("shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(30), handle.consumer).await;
    clear_layer2_divergent(INSTANCE_ID);
}

/// A restart is not evidence of repair, so the mark has to be on disk. The
/// in-memory clear here stands in for the empty registry a new process starts
/// with; the second open must re-derive the mark from the store alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_divergence_mark_outlives_the_process_that_set_it() {
    const INSTANCE_ID: &str = "layer2-gate-restart";
    clear_layer2_divergent(INSTANCE_ID);

    let dir = tempfile::tempdir().expect("tempdir");
    let chain_source = Arc::new(ScriptedChainSource::new(false));
    let config = verifying_config(dir.path(), INSTANCE_ID, &chain_source, 1);
    let params = InspireParams::secure_128_d2048();
    let handle = bootstrap_railgun_engine(config, params, build_toy_state).expect("bootstrap 1");

    handle
        .sender
        .send(ConsumerEvent::Chain(leaf_event(0, 100), 100))
        .await
        .expect("send leaf");
    await_marked(INSTANCE_ID, "no-anchor suppression").await;

    handle
        .sender
        .send(ConsumerEvent::Shutdown)
        .await
        .expect("shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(30), handle.consumer).await;

    clear_layer2_divergent(INSTANCE_ID);
    let reopened_source = Arc::new(ScriptedChainSource::new(false));
    let reopened_config = verifying_config(dir.path(), INSTANCE_ID, &reopened_source, 1);
    let reopened = bootstrap_railgun_engine(
        reopened_config,
        InspireParams::secure_128_d2048(),
        build_toy_state,
    )
    .expect("bootstrap 2");

    assert!(
        layer2_divergent_instances()
            .iter()
            .any(|id| id == INSTANCE_ID),
        "reopening a store carrying a divergence marker must re-mark it; \
         marked = {:?}",
        layer2_divergent_instances(),
    );

    reopened
        .sender
        .send(ConsumerEvent::Shutdown)
        .await
        .expect("shutdown 2");
    let _ = tokio::time::timeout(Duration::from_secs(30), reopened.consumer).await;
    clear_layer2_divergent(INSTANCE_ID);
}

/// A wedged instance keeps applying events while its commits fail. Gating the
/// verifier on commit progress alone means that instance is never verified and
/// so never marked, which is exactly the state operators need to see.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_commit_stream_must_not_silence_the_verifier() {
    const INSTANCE_ID: &str = "layer2-gate-commit-stall";
    clear_layer2_divergent(INSTANCE_ID);

    let dir = tempfile::tempdir().expect("tempdir");
    let chain_source = Arc::new(ScriptedChainSource::new(false));
    let config = verifying_config(dir.path(), INSTANCE_ID, &chain_source, usize::MAX);
    let params = InspireParams::secure_128_d2048();
    let handle = bootstrap_railgun_engine(config, params, build_toy_state).expect("bootstrap");

    for i in 0..3u32 {
        let height = 100 + u64::from(i);
        handle
            .sender
            .send(ConsumerEvent::Chain(leaf_event(i, height), height))
            .await
            .expect("send leaf");
    }
    await_metrics(&handle.metrics, "quiet stall", |m| m.events_processed >= 3).await;
    assert_eq!(
        handle.metrics.lock().commits_fired,
        0,
        "the policy must hold every commit back for this scenario",
    );
    assert_eq!(
        chain_source.rounds(),
        0,
        "a quiet inter-commit window must not spend an RPC round per event",
    );

    // A non-contiguous index is refused before the WAL write, which is what a
    // wedged instance looks like: events flowing, nothing committing.
    handle
        .sender
        .send(ConsumerEvent::Chain(leaf_event(7, 103), 103))
        .await
        .expect("send wedging leaf");
    await_metrics(&handle.metrics, "wedge", |m| m.consumer_errors >= 1).await;

    handle
        .sender
        .send(ConsumerEvent::Chain(leaf_event(3, 104), 104))
        .await
        .expect("send leaf after the wedge");
    await_marked(INSTANCE_ID, "wedged instance").await;

    assert_eq!(
        handle.metrics.lock().commits_fired,
        0,
        "the verifier must have run without a single commit having fired",
    );

    handle
        .sender
        .send(ConsumerEvent::Shutdown)
        .await
        .expect("shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(30), handle.consumer).await;
    clear_layer2_divergent(INSTANCE_ID);
}
