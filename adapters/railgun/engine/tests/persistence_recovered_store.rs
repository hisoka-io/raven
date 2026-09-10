//! Single-instance restart must carry the recovered logical leaf store into the
//! consumer task. A store that starts empty behind an N-leaf encoded DB rejects
//! every later append as non-contiguous, which no amount of retrying repairs.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use raven_inspire::params::InspireParams;
use raven_railgun_core::{CommitmentLeaf, RailgunEvent};
use raven_railgun_engine::inspire::InspireServerState;
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine, OrchestratorConfig, OrchestratorHandle, VerificationMode,
};
use raven_railgun_engine::persistence::{ConsumerEvent, SnapshotPolicy};
use raven_railgun_engine::InstanceRole;
use raven_railgun_indexer::{
    BlockId, ChainSource, IndexerError, IndexerWorker, IndexerWorkerConfig, Result as IndexerResult,
};

const SCHEME_TAG: &str = "raven-inspire-twopacking-recovered-store";
const INSTANCE_ID: &str = "recovered-store";
const TOY_ENTRY_SIZE: usize = 256;
const SEEDED_LEAVES: u32 = 4;

fn build_toy_state() -> raven_railgun_core::Result<InspireServerState> {
    raven_railgun_testkit::try_toy_state(TOY_ENTRY_SIZE)
}

use raven_railgun_testkit::canonical_zeroable as canonical_commitment;

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
                u8::try_from((leaf_index & 0xff) | 0x10).expect("byte"),
            ),
            ciphertext: vec![],
        }],
    }
}

fn transact(height: u64, start_position: u32, commitments: &[u8]) -> RailgunEvent {
    RailgunEvent::Transact {
        block_number: height,
        tx_hash: [0u8; 32],
        tree_number: 0,
        start_position,
        leaves: commitments
            .iter()
            .enumerate()
            .map(|(offset, value)| CommitmentLeaf {
                tree_number: 0,
                leaf_index: start_position + u32::try_from(offset).expect("leaf offset"),
                commitment_hash: canonical_commitment(*value),
                ciphertext: vec![],
            })
            .collect(),
    }
}

fn event_height(event: &RailgunEvent) -> u64 {
    match event {
        RailgunEvent::Shield { block_number, .. }
        | RailgunEvent::Transact { block_number, .. }
        | RailgunEvent::Nullified { block_number, .. }
        | RailgunEvent::Unshield { block_number, .. } => *block_number,
    }
}

#[derive(Debug)]
struct RestartChain {
    hashes: Mutex<BTreeMap<u64, [u8; 32]>>,
    events: Mutex<Vec<RailgunEvent>>,
    events_denied: AtomicBool,
}

impl RestartChain {
    fn new() -> Self {
        Self {
            hashes: Mutex::new(BTreeMap::from([(1, [0x11; 32]), (2, [0x22; 32])])),
            events: Mutex::new(vec![transact(1, 0, &[0x31]), transact(2, 1, &[0x41, 0x42])]),
            events_denied: AtomicBool::new(false),
        }
    }

    fn reorg_while_down(&self) {
        self.hashes.lock().expect("hashes").insert(2, [0x23; 32]);
        *self.events.lock().expect("events") =
            vec![transact(1, 0, &[0x31]), transact(2, 1, &[0x51, 0x52])];
        self.events_denied.store(true, Ordering::Release);
    }

    fn allow_events(&self) {
        self.events_denied.store(false, Ordering::Release);
    }
}

#[async_trait]
impl ChainSource for RestartChain {
    async fn latest_block(&self) -> IndexerResult<u64> {
        Ok(2)
    }

    async fn events_in_range(&self, from: u64, to: u64) -> IndexerResult<Vec<RailgunEvent>> {
        if self.events_denied.load(Ordering::Acquire) {
            return Err(IndexerError::Rpc(
                "restart fixture holds canonical replay until the fence commits".to_owned(),
            ));
        }
        Ok(self
            .events
            .lock()
            .expect("events")
            .iter()
            .filter(|event| (from..=to).contains(&event_height(event)))
            .cloned()
            .collect())
    }

    async fn root_history(
        &self,
        _tree: u32,
        _root: [u8; 32],
        _at: Option<BlockId>,
    ) -> IndexerResult<bool> {
        Ok(true)
    }

    async fn block_hash(&self, height: u64) -> IndexerResult<[u8; 32]> {
        self.hashes
            .lock()
            .expect("hashes")
            .get(&height)
            .copied()
            .ok_or_else(|| IndexerError::Rpc(format!("missing block {height}")))
    }

    async fn merkle_root(&self, _at: Option<BlockId>) -> IndexerResult<[u8; 32]> {
        Ok([0u8; 32])
    }

    async fn active_tree_number(&self, _at: Option<BlockId>) -> IndexerResult<u32> {
        Ok(0)
    }
}

fn worker_config(start_block: u64, window: std::path::PathBuf) -> IndexerWorkerConfig {
    IndexerWorkerConfig {
        start_block,
        recovered_block_height: start_block,
        reorg_window_required: start_block > 0,
        poll_interval_secs: 1,
        chunk_blocks: 1,
        reorg_window_path: Some(window),
        ..IndexerWorkerConfig::default()
    }
}

fn boot(dir: &std::path::Path) -> OrchestratorHandle {
    let mut config = OrchestratorConfig::demo(dir.to_path_buf(), INSTANCE_ID);
    config.record_size = TOY_ENTRY_SIZE;
    config.use_flock = false;
    config.role = InstanceRole::Live;
    SCHEME_TAG.clone_into(&mut config.scheme_tag);
    config.snapshot_policy = SnapshotPolicy {
        max_appends_per_snapshot: 1,
        ..SnapshotPolicy::default()
    };
    config.verification_mode = VerificationMode::UpstreamSignature;
    config.verification_cadence_n = 0;
    config.chain_source = None;
    let params = InspireParams::secure_128_d2048();
    bootstrap_railgun_engine(config, params, build_toy_state).expect("bootstrap")
}

async fn drain_until<F: Fn(&raven_railgun_engine::persistence::ConsumerMetrics) -> bool>(
    handle: &OrchestratorHandle,
    label: &str,
    done: F,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let snap = *handle.metrics.lock();
        if done(&snap) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{label}: events_processed = {}, commits_fired = {}, consumer_errors = {}, \
             leaf_count = {}",
            snap.events_processed,
            snap.commits_fired,
            snap.consumer_errors,
            handle.logical_store.lock().leaf_count(),
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn shutdown(handle: OrchestratorHandle) {
    handle
        .sender
        .send(ConsumerEvent::Shutdown)
        .await
        .expect("shutdown");
    tokio::time::timeout(Duration::from_secs(30), handle.consumer)
        .await
        .expect("consumer shutdown timeout")
        .expect("consumer join")
        .expect("consumer shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_restores_the_logical_store_and_keeps_appends_contiguous() {
    let dir = tempfile::tempdir().expect("tempdir");

    let first = boot(dir.path());
    for i in 0..SEEDED_LEAVES {
        let height = 200 + u64::from(i);
        first
            .sender
            .send(ConsumerEvent::Chain(leaf_event(i, height), height))
            .await
            .expect("send leaf");
    }
    drain_until(&first, "seed", |m| {
        m.events_processed >= u64::from(SEEDED_LEAVES)
    })
    .await;
    assert_eq!(
        first.logical_store.lock().leaf_count(),
        SEEDED_LEAVES as usize,
        "seed phase must apply every leaf",
    );
    shutdown(first).await;

    let second = boot(dir.path());
    assert_eq!(
        second.logical_store.lock().leaf_count(),
        SEEDED_LEAVES as usize,
        "restart must seed the consumer task with the recovered logical store, not \
         an empty one",
    );
    assert_eq!(
        second.logical_store.lock().leaf(0, 0).copied(),
        Some(canonical_commitment(0x10)),
        "the recovered store must carry the leaf bytes, not just a leaf count",
    );

    let next_height = 200 + u64::from(SEEDED_LEAVES);
    second
        .sender
        .send(ConsumerEvent::Chain(
            leaf_event(SEEDED_LEAVES, next_height),
            next_height,
        ))
        .await
        .expect("send post-restart leaf");
    drain_until(&second, "post-restart append", |m| {
        m.events_processed >= 1 || m.consumer_errors >= 1
    })
    .await;

    let after = *second.metrics.lock();
    assert_eq!(
        after.consumer_errors, 0,
        "an append at index {SEEDED_LEAVES} must be contiguous after restart; a \
         reset store rejects it and wedges the tree permanently",
    );
    assert_eq!(
        second.logical_store.lock().leaf_count(),
        (SEEDED_LEAVES + 1) as usize,
    );

    shutdown(second).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reorg_while_down_replaces_persisted_orphan_leaves() {
    let dir = tempfile::tempdir().expect("tempdir");
    let window = dir.path().join("indexer_reorg_window.bin");
    let source = Arc::new(RestartChain::new());

    let first = boot(dir.path());
    let first_worker = IndexerWorker::new(Arc::clone(&source), first.channels.indexer_tx.clone());
    let first_run = tokio::spawn({
        let window = window.clone();
        async move { first_worker.run(worker_config(0, window)).await }
    });
    drain_until(&first, "first canonical run", |metrics| {
        metrics.last_scanned_block >= 2 && metrics.events_processed >= 2
    })
    .await;
    assert_eq!(first.logical_store.lock().leaf_count(), 3);
    assert_eq!(
        raven_railgun_indexer::load_reorg_window(&window).expect("first-run sidecar"),
        BTreeMap::from([(1, [0x11; 32]), (2, [0x22; 32])]),
        "restart precondition requires the old canonical hashes on disk"
    );
    first_run.abort();
    assert!(
        first_run
            .await
            .expect_err("aborted worker must not complete")
            .is_cancelled(),
        "the first worker must stop before the chain changes"
    );
    shutdown(first).await;

    source.reorg_while_down();
    let second = boot(dir.path());
    assert_eq!(second.persistence.manifest_block_height(), 2);
    assert_eq!(
        second.logical_store.lock().leaf(0, 1).copied(),
        Some(canonical_commitment(0x41)),
        "restart precondition must include the orphaned suffix"
    );
    assert_eq!(
        second.logical_store.lock().leaf(0, 2).copied(),
        Some(canonical_commitment(0x42)),
        "restart precondition must include the complete orphaned suffix"
    );
    let second_worker = IndexerWorker::new(Arc::clone(&source), second.channels.indexer_tx.clone());
    let second_run = tokio::time::timeout(
        Duration::from_secs(10),
        second_worker.spawn_reconciled(worker_config(2, window.clone())),
    )
    .await
    .expect("startup reconciliation timeout")
    .expect("startup reconciliation");
    assert_eq!(
        second.persistence.manifest_block_height(),
        1,
        "startup readiness must follow the durable rewind"
    );
    {
        let store = second.logical_store.lock();
        assert_eq!(
            store.leaf_count(),
            1,
            "the fence must delete the orphaned suffix"
        );
        assert_eq!(store.leaf(0, 1), None);
        assert_eq!(store.leaf(0, 2), None);
    }

    source.allow_events();
    drain_until(&second, "canonical replay", |metrics| {
        metrics.events_processed == 1 && metrics.last_applied_leaf_block == 2
    })
    .await;

    second_run.abort();
    assert!(
        second_run
            .await
            .expect_err("aborted worker must not complete")
            .is_cancelled(),
        "the second worker must stay live after canonical replay"
    );
    let metrics = *second.metrics.lock();
    assert_eq!(
        metrics.reorgs_handled, 1,
        "startup must emit one verified fence"
    );
    assert_eq!(
        metrics.consumer_errors, 0,
        "canonical replay must stay contiguous"
    );
    assert_eq!(metrics.events_processed, 1);
    assert_eq!(metrics.last_applied_leaf_block, 2);
    {
        let store = second.logical_store.lock();
        assert_eq!(store.leaf_count(), 3);
        assert_eq!(store.leaf(0, 0).copied(), Some(canonical_commitment(0x31)));
        assert_eq!(store.leaf(0, 1).copied(), Some(canonical_commitment(0x51)));
        assert_eq!(store.leaf(0, 2).copied(), Some(canonical_commitment(0x52)));
    }
    shutdown(second).await;
}
