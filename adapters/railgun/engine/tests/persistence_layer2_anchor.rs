//! Layer 2 fork anchors and the divergence gate. A mirror row carries height 0,
//! so an in-sync verdict observed on one must never become the anchor a later
//! out-of-sync verdict rewinds to; and an unrepairable out-of-sync verdict must
//! leave the instance marked divergent.

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
    layer2_divergent_instances, ConsumerEvent, SnapshotPolicy,
};
use raven_railgun_engine::InstanceRole;
use raven_railgun_indexer::{BlockId, ChainSource, IndexerError, Result as IndexerResult};
use raven_railgun_persistence::WalEntryPayload;

const SCHEME_TAG: &str = "raven-inspire-twopacking-layer2-anchor";
const INSTANCE_ID: &str = "layer2-anchor";
const TOY_ENTRY_SIZE: usize = 256;
const LIST_KEY: [u8; 32] = [0x5d; 32];
const LEAVES: u32 = 5;

/// Verdict is flipped by the test between phases; `root_history` caches the
/// engine's root so the in-sync branch agrees without mirroring the IMT.
struct ScriptedChainSource {
    in_sync: AtomicBool,
    rounds: AtomicU64,
    last_seen_root: parking_lot::Mutex<[u8; 32]>,
}

impl ScriptedChainSource {
    fn new() -> Self {
        Self {
            in_sync: AtomicBool::new(false),
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

async fn await_rounds(source: &ScriptedChainSource, target: u64, label: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while source.rounds() < target {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{label}: verifier reached only {} of {target} rounds",
            source.rounds(),
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    // Let the post-verdict bookkeeping settle before the assertions read it.
    tokio::time::sleep(Duration::from_millis(200)).await;
}

fn verifying_config(
    dir: &std::path::Path,
    chain_source: &Arc<ScriptedChainSource>,
) -> OrchestratorConfig {
    let mut config = OrchestratorConfig::demo(dir.to_path_buf(), INSTANCE_ID);
    config.record_size = TOY_ENTRY_SIZE;
    config.use_flock = false;
    config.role = InstanceRole::Live;
    SCHEME_TAG.clone_into(&mut config.scheme_tag);
    config.snapshot_policy = SnapshotPolicy {
        max_appends_per_snapshot: 1,
        ..SnapshotPolicy::default()
    };
    config.verification_mode = VerificationMode::ChainRootHistory;
    config.verification_cadence_n = 1;
    config.verification_tree_number = 0;
    config.chain_source = Some(Arc::clone(chain_source) as Arc<dyn ChainSource>);
    config
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

fn mirror_row(byte: u8) -> WalEntryPayload {
    WalEntryPayload::PpoiStatus {
        list_key: LIST_KEY,
        blinded_commitment: canonical_commitment(byte),
        status: 1,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mirror_height_zero_in_sync_verdict_must_not_become_a_fork_anchor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let chain_source = Arc::new(ScriptedChainSource::new());
    let config = verifying_config(dir.path(), &chain_source);

    let params = InspireParams::secure_128_d2048();
    let handle = bootstrap_railgun_engine(config, params, build_toy_state).expect("bootstrap");

    // Phase 1: every chain-height verdict is out of sync, so no real anchor is
    // ever recorded and the cascade must stay suppressed.
    for i in 0..LEAVES {
        let height = 100 + u64::from(i);
        handle
            .sender
            .send(ConsumerEvent::Chain(leaf_event(i, height), height))
            .await
            .expect("send leaf");
    }
    await_rounds(&chain_source, u64::from(LEAVES), "phase 1").await;

    assert_eq!(
        handle.metrics.lock().reorgs_handled,
        0,
        "an out-of-sync verdict with no anchor must not cascade a reorg",
    );
    assert_eq!(
        layer2_divergent_instances(),
        vec![INSTANCE_ID.to_owned()],
        "a suppressed cascade must leave the instance marked divergent",
    );

    // Phase 2: a mirror row verifies in sync at height 0. The root now matches
    // the chain, but 0 is not a chain height and must not anchor a rewind.
    chain_source.set_in_sync(true);
    let before = chain_source.rounds();
    handle
        .sender
        .send(ConsumerEvent::Ppoi(mirror_row(0x91), 0))
        .await
        .expect("send mirror row");
    await_rounds(&chain_source, before + 1, "phase 2").await;

    assert!(
        layer2_divergent_instances().is_empty(),
        "an in-sync verdict proves the local root is on chain and must clear the \
         divergence mark; got {:?}",
        layer2_divergent_instances(),
    );

    // Phase 3: the next verdict flips out of sync. Phase 2 supplied no anchor,
    // so this must suppress rather than rewind to genesis.
    chain_source.set_in_sync(false);
    let before = chain_source.rounds();
    handle
        .sender
        .send(ConsumerEvent::Ppoi(mirror_row(0x92), 0))
        .await
        .expect("send mirror row");
    await_rounds(&chain_source, before + 1, "phase 3").await;

    let metrics = *handle.metrics.lock();
    assert_eq!(
        metrics.reorgs_handled, 0,
        "an in-sync verdict at mirror height 0 must not become the fork anchor a \
         later out-of-sync verdict rewinds to",
    );
    let leaf_count = handle.logical_store.lock().leaf_count();
    assert_eq!(
        leaf_count, LEAVES as usize,
        "a cascade anchored at height 0 truncates every leaf above block 0; the \
         tree must be intact",
    );
    assert_eq!(
        layer2_divergent_instances(),
        vec![INSTANCE_ID.to_owned()],
        "the re-suppressed cascade must re-mark the instance divergent",
    );

    handle
        .sender
        .send(ConsumerEvent::Shutdown)
        .await
        .expect("shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(30), handle.consumer).await;
}
