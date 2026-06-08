//! Layer 1 reorg detection tests.
//!
//! Exercises `detect_reorg_layer1` and `IndexerWorker` via a synthetic `ChainSource`.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::needless_continue,
    clippy::match_same_arms
)]

use async_trait::async_trait;
use raven_railgun_core::RailgunEvent;
use raven_railgun_indexer::{
    detect_reorg_layer1, ChainSource, IndexerError, IndexerMessage, IndexerWorker,
    IndexerWorkerConfig, Result, MAX_REORG_BLOCKS,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Debug, Default)]
struct MockChainSource {
    inner: Mutex<MockChainInner>,
}

#[derive(Debug, Default)]
struct MockChainInner {
    chain: BTreeMap<u64, [u8; 32]>,
    events: BTreeMap<u64, Vec<RailgunEvent>>,
    latest: u64,
}

impl MockChainSource {
    fn new() -> Self {
        Self::default()
    }
    fn set_block(&self, number: u64, hash: [u8; 32]) {
        let mut inner = self.inner.lock().expect("lock");
        inner.chain.insert(number, hash);
        inner.latest = inner.latest.max(number);
    }
    fn reorg(&self, from: u64, to: u64, new_hash: [u8; 32]) {
        let mut inner = self.inner.lock().expect("lock");
        for n in from..=to {
            inner.chain.insert(n, new_hash);
        }
    }
}

#[async_trait]
impl ChainSource for MockChainSource {
    async fn latest_block(&self) -> Result<u64> {
        Ok(self.inner.lock().expect("lock").latest)
    }
    async fn events_in_range(&self, from: u64, to: u64) -> Result<Vec<RailgunEvent>> {
        let inner = self.inner.lock().expect("lock");
        let mut out = Vec::new();
        for (n, evs) in inner.events.range(from..=to) {
            for e in evs {
                let _ = n;
                out.push(e.clone());
            }
        }
        Ok(out)
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
        self.inner
            .lock()
            .expect("lock")
            .chain
            .get(&n)
            .copied()
            .ok_or_else(|| IndexerError::Rpc(format!("block {n} not in mock chain")))
    }
    async fn merkle_root(&self, _at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        Err(IndexerError::Rpc(
            "MockChainSource: merkle_root not used by Layer 1 tests".into(),
        ))
    }
    async fn active_tree_number(&self, _at: Option<alloy::eips::BlockId>) -> Result<u32> {
        Err(IndexerError::Rpc(
            "MockChainSource: active_tree_number not used by Layer 1 tests".into(),
        ))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detect_reorg_layer1_returns_none_when_canonical_matches() {
    let src = MockChainSource::new();
    src.set_block(100, [0xaa; 32]);
    src.set_block(101, [0xbb; 32]);

    let mut cache = BTreeMap::new();
    cache.insert(100, [0xaa; 32]);
    cache.insert(101, [0xbb; 32]);

    let result = detect_reorg_layer1(&src, &cache, 101)
        .await
        .expect("detect");
    assert_eq!(result, None, "no divergence => Ok(None)");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detect_reorg_layer1_finds_divergence_point() {
    let src = MockChainSource::new();
    src.set_block(100, [0xaa; 32]);
    src.set_block(101, [0xbb; 32]);
    src.set_block(102, [0xcc; 32]);

    let mut cache = BTreeMap::new();
    cache.insert(100, [0xaa; 32]);
    cache.insert(101, [0xbb; 32]);
    cache.insert(102, [0xcc; 32]);

    src.reorg(102, 102, [0xdd; 32]);

    let result = detect_reorg_layer1(&src, &cache, 102)
        .await
        .expect("detect");
    assert_eq!(
        result,
        Some(101),
        "divergence at 102 => surviving height = 101"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detect_reorg_layer1_walks_back_through_multiple_blocks() {
    let src = MockChainSource::new();
    for n in 100..=110u64 {
        src.set_block(n, [u8::try_from(n & 0xff).expect("byte"); 32]);
    }
    let mut cache = BTreeMap::new();
    for n in 100..=110u64 {
        cache.insert(n, [u8::try_from(n & 0xff).expect("byte"); 32]);
    }

    src.reorg(105, 110, [0xff; 32]);

    let result = detect_reorg_layer1(&src, &cache, 110)
        .await
        .expect("detect");
    assert_eq!(result, Some(104), "surviving prefix is 100..=104");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detect_reorg_layer1_returns_too_deep_when_cache_exhausted() {
    let src = MockChainSource::new();
    src.set_block(100, [0xaa; 32]);
    src.set_block(101, [0xbb; 32]);

    let mut cache = BTreeMap::new();
    cache.insert(100, [0xaa; 32]);
    cache.insert(101, [0xbb; 32]);

    src.reorg(100, 101, [0xff; 32]);

    let err = detect_reorg_layer1(&src, &cache, 101)
        .await
        .expect_err("must error");
    assert!(matches!(err, IndexerError::ReorgTooDeep(_)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_emits_reorg_message_after_simulated_reorg() {
    let src = Arc::new(MockChainSource::new());
    for n in 0..=120u64 {
        src.set_block(n, [u8::try_from(n & 0xff).expect("byte"); 32]);
    }

    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(64);
    let worker = IndexerWorker::new(Arc::clone(&src), tx);

    // chunk_blocks=30 produces a 4-tick catchup (0→30→60→90→120).
    let cfg = IndexerWorkerConfig {
        start_block: 0,
        poll_interval_secs: 1,
        chunk_blocks: 30,
        ..IndexerWorkerConfig::default()
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let mut heartbeat_count = 0u32;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while tokio::time::Instant::now() < deadline && heartbeat_count < 4 {
        match tokio::time::timeout(Duration::from_millis(1500), rx.recv()).await {
            Ok(Some(IndexerMessage::Heartbeat { .. })) => {
                heartbeat_count += 1;
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    assert!(
        heartbeat_count >= 4,
        "worker should have completed catchup (4 heartbeats); got {heartbeat_count}"
    );

    // Block 90 stays canonical; walk-back should find it as the surviving tip.
    src.reorg(91, 120, [0xff; 32]);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut got_reorg = None;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
            Ok(Some(IndexerMessage::Reorg { height })) => {
                got_reorg = Some(height);
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    assert!(
        got_reorg.is_some(),
        "worker must emit IndexerMessage::Reorg after the simulated reorg"
    );
    let height = got_reorg.expect("set");
    assert!(
        height <= 90,
        "Reorg height ({height}) must be the surviving tip (≤ 90)"
    );

    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
}

fn seed_chain_with_depth(depth: u64) -> (MockChainSource, BTreeMap<u64, [u8; 32]>, u64) {
    let src = MockChainSource::new();
    let mut cache: BTreeMap<u64, [u8; 32]> = BTreeMap::new();
    let start: u64 = 1_000_000;
    let top = start + depth;
    for n in start..=top {
        let mut h = [0xaa_u8; 32];
        h[0] = u8::try_from(n & 0xff).expect("byte");
        h[1] = u8::try_from((n >> 8) & 0xff).expect("byte");
        h[2] = u8::try_from((n >> 16) & 0xff).expect("byte");
        src.set_block(n, h);
        cache.insert(n, h);
    }
    (src, cache, top)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detect_reorg_layer1_walks_back_at_depth_32() {
    let (src, cache, top) = seed_chain_with_depth(32);
    src.reorg(top - 31, top, [0xff; 32]);
    let result = detect_reorg_layer1(&src, &cache, top)
        .await
        .expect("detect");
    assert_eq!(
        result,
        Some(top - 32),
        "32-deep reorg must surface the surviving height (top-32)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detect_reorg_layer1_walks_back_at_depth_256() {
    let (src, cache, top) = seed_chain_with_depth(256);
    src.reorg(top - 255, top, [0xff; 32]);
    let result = detect_reorg_layer1(&src, &cache, top)
        .await
        .expect("detect");
    assert_eq!(
        result,
        Some(top - 256),
        "256-deep reorg must walk back to the surviving height (top-256)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detect_reorg_layer1_returns_too_deep_at_max_reorg_blocks_boundary() {
    let (src, cache, top) = seed_chain_with_depth(MAX_REORG_BLOCKS);
    let oldest = top - MAX_REORG_BLOCKS;
    src.reorg(oldest, top, [0xff; 32]);
    let err = detect_reorg_layer1(&src, &cache, top)
        .await
        .expect_err("must error past the boundary");
    match err {
        IndexerError::ReorgTooDeep(h) => {
            assert_eq!(h, top, "ReorgTooDeep must carry the cursor height");
        }
        other => panic!("expected ReorgTooDeep, got {other:?}"),
    }
}
