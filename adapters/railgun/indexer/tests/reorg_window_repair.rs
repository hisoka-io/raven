//! The Layer 1 reorg window must stay usable at production chunk spans.
//!
//! Three invariants: retention is bounded by ENTRY COUNT (not block
//! distance, which a 499-block tick collapses to a single entry); the scan
//! cursor never advances past a block whose hash could not be cached; and a
//! window miss fails closed instead of masquerading as a divergence.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::needless_continue,
    clippy::match_same_arms
)]

use async_trait::async_trait;
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use raven_railgun_core::RailgunEvent;
use raven_railgun_indexer::{
    detect_reorg_layer1, ChainSource, IndexerError, IndexerMessage, IndexerWorker,
    IndexerWorkerConfig, Result,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::mpsc;

fn snap() -> &'static Snapshotter {
    static SNAP: OnceLock<Snapshotter> = OnceLock::new();
    SNAP.get_or_init(|| {
        let recorder = DebuggingRecorder::new();
        let s = recorder.snapshotter();
        let _ = metrics::set_global_recorder(recorder);
        s
    })
}

const TIP_HASH_FAILED: &str = "raven_railgun_indexer_reorg_window_tip_hash_failed_total";

fn counter_by_name(snap: &Snapshotter, name: &str) -> u64 {
    for (composite_key, _, _, value) in snap.snapshot().into_vec() {
        if format!("{composite_key:?}").contains(name) {
            if let DebugValue::Counter(v) = value {
                return v;
            }
        }
    }
    0
}

#[derive(Debug, Default)]
struct WindowSource {
    inner: Mutex<WindowInner>,
}

#[derive(Debug, Default)]
struct WindowInner {
    chain: BTreeMap<u64, [u8; 32]>,
    latest: u64,
    block_hash_denied_at: Option<u64>,
}

impl WindowSource {
    fn with_chain(through: u64) -> Self {
        let src = Self::default();
        for n in 0..=through {
            src.set_block(n, canonical_hash(n));
        }
        src
    }
    fn set_block(&self, n: u64, hash: [u8; 32]) {
        let mut g = self.inner.lock().expect("lock");
        g.chain.insert(n, hash);
        g.latest = g.latest.max(n);
    }
    fn reorg(&self, from: u64, to: u64, new_hash: [u8; 32]) {
        let mut g = self.inner.lock().expect("lock");
        for n in from..=to {
            g.chain.insert(n, new_hash);
        }
    }
    fn deny_block_hash_at(&self, n: u64) {
        self.inner.lock().expect("lock").block_hash_denied_at = Some(n);
    }
}

fn canonical_hash(n: u64) -> [u8; 32] {
    let mut h = [0xaa_u8; 32];
    h[..8].copy_from_slice(&n.to_le_bytes());
    h
}

#[async_trait]
impl ChainSource for WindowSource {
    async fn latest_block(&self) -> Result<u64> {
        Ok(self.inner.lock().expect("lock").latest)
    }
    async fn events_in_range(&self, _from: u64, _to: u64) -> Result<Vec<RailgunEvent>> {
        Ok(Vec::new())
    }
    async fn root_history(
        &self,
        _tree: u32,
        _root: [u8; 32],
        _at: Option<alloy::eips::BlockId>,
    ) -> Result<bool> {
        Ok(true)
    }
    async fn block_hash(&self, n: u64) -> Result<[u8; 32]> {
        let g = self.inner.lock().expect("lock");
        if g.block_hash_denied_at == Some(n) {
            return Err(IndexerError::Rpc(format!(
                "WindowSource: block_hash({n}) denied"
            )));
        }
        g.chain
            .get(&n)
            .copied()
            .ok_or_else(|| IndexerError::Rpc(format!("block {n} not in mock chain")))
    }
    async fn merkle_root(&self, _at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        Err(IndexerError::Rpc(
            "WindowSource: merkle_root not used by these tests".into(),
        ))
    }
    async fn active_tree_number(&self, _at: Option<alloy::eips::BlockId>) -> Result<u32> {
        Err(IndexerError::Rpc(
            "WindowSource: active_tree_number not used by these tests".into(),
        ))
    }
}

/// Ticks advance a whole chunk, so a window capped at 3 ENTRIES must retain
/// the last three chunk boundaries. Capping by block distance leaves one
/// entry and every later divergence surfaces as `ReorgTooDeep`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn window_retains_entries_when_chunk_span_exceeds_window_depth() {
    let src = Arc::new(WindowSource::with_chain(120));
    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(64);
    let worker = IndexerWorker::new(Arc::clone(&src), tx);
    let cfg = IndexerWorkerConfig {
        start_block: 0,
        poll_interval_secs: 1,
        chunk_blocks: 30,
        reorg_window_depth: 3,
        ..IndexerWorkerConfig::default()
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut caught_up = false;
    while tokio::time::Instant::now() < deadline && !caught_up {
        match tokio::time::timeout(Duration::from_millis(1500), rx.recv()).await {
            Ok(Some(IndexerMessage::Heartbeat {
                scanned_through_block,
                ..
            })) => caught_up = scanned_through_block == 120,
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    assert!(
        caught_up,
        "worker must reach the chain tip before the reorg"
    );

    src.reorg(91, 120, [0xff; 32]);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut got_reorg = None;
    while tokio::time::Instant::now() < deadline && got_reorg.is_none() {
        match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
            Ok(Some(IndexerMessage::Reorg { height })) => got_reorg = Some(height),
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;

    assert_eq!(
        got_reorg,
        Some(90),
        "three retained chunk boundaries (60, 90, 120) must let the walk-back \
         land on the surviving tip 90"
    );
}

/// An uncacheable tip hash leaves a hole the reorg walk-back can never
/// cross, so the cursor must not step over it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cursor_holds_when_tip_hash_is_uncacheable() {
    let s = snap();
    let before = counter_by_name(s, TIP_HASH_FAILED);

    let src = Arc::new(WindowSource::with_chain(120));
    src.deny_block_hash_at(30);
    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(64);
    let worker = IndexerWorker::new(Arc::clone(&src), tx);
    let cfg = IndexerWorkerConfig {
        start_block: 0,
        poll_interval_secs: 1,
        chunk_blocks: 30,
        ..IndexerWorkerConfig::default()
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut watermarks = Vec::new();
    while tokio::time::Instant::now() < deadline && watermarks.len() < 3 {
        match tokio::time::timeout(Duration::from_millis(1500), rx.recv()).await {
            Ok(Some(IndexerMessage::Heartbeat {
                scanned_through_block,
                ..
            })) => watermarks.push(scanned_through_block),
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;

    assert!(
        watermarks.len() >= 3,
        "worker must keep heartbeating while it is stuck; got {watermarks:?}"
    );
    assert!(
        watermarks.iter().all(|&w| w == 0),
        "the scan watermark must not pass block 30 while its hash is uncacheable; \
         got {watermarks:?}"
    );
    let after = counter_by_name(s, TIP_HASH_FAILED);
    assert!(
        after > before,
        "the held tick must be counted; before={before} after={after}"
    );
}

/// A window miss and a divergence are indistinguishable from the walk-back's
/// point of view, so substituting a zero hash turns a miss into a leaf-deleting
/// `Reorg`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detect_reorg_layer1_fails_closed_on_window_miss() {
    let src = WindowSource::with_chain(105);
    let mut cache = BTreeMap::new();
    for n in 100..=104u64 {
        cache.insert(n, canonical_hash(n));
    }

    let outcome = detect_reorg_layer1(&src, &cache, 105).await;

    let err = match outcome {
        Err(e) => e,
        Ok(other) => panic!("a window miss must fail closed; got Ok({other:?})"),
    };
    match err {
        IndexerError::ReorgWindowMiss {
            cursor,
            window_len,
            window_oldest,
            window_newest,
        } => {
            assert_eq!(cursor, 105);
            assert_eq!(window_len, 5);
            assert_eq!(window_oldest, Some(100));
            assert_eq!(window_newest, Some(104));
        }
        other => panic!("expected ReorgWindowMiss; got {other:?}"),
    }
}
