//! Heartbeats must carry the scan cursor, not the chain tip: lag computed
//! against an applied-event height freezes on a quiet chain, and lag computed
//! against the tip reads zero during a backfill. Both are wrong.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use async_trait::async_trait;
use raven_railgun_core::{CommitmentLeaf, RailgunEvent};
use raven_railgun_indexer::{
    ChainSource, IndexerError, IndexerMessage, IndexerWorker, IndexerWorkerConfig, Result,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Debug, Default)]
struct QuietMockSource {
    inner: Mutex<MockInner>,
}

#[derive(Debug, Default)]
struct MockInner {
    chain: BTreeMap<u64, [u8; 32]>,
    events: BTreeMap<u64, Vec<RailgunEvent>>,
    latest: u64,
}

impl QuietMockSource {
    fn with_blocks(up_to: u64) -> Self {
        let src = Self::default();
        {
            let mut g = src.inner.lock().expect("lock");
            for n in 0..=up_to {
                g.chain
                    .insert(n, [u8::try_from(n & 0xff).expect("byte"); 32]);
            }
            g.latest = up_to;
        }
        src
    }

    fn add_event(&self, n: u64, ev: RailgunEvent) {
        let mut g = self.inner.lock().expect("lock");
        g.events.entry(n).or_default().push(ev);
    }
}

#[async_trait]
impl ChainSource for QuietMockSource {
    async fn latest_block(&self) -> Result<u64> {
        Ok(self.inner.lock().expect("lock").latest)
    }
    async fn events_in_range(&self, from: u64, to: u64) -> Result<Vec<RailgunEvent>> {
        let g = self.inner.lock().expect("lock");
        Ok(g.events
            .range(from..=to)
            .flat_map(|(_, evs)| evs.iter().cloned())
            .collect())
    }
    async fn root_history(
        &self,
        _t: u32,
        _r: [u8; 32],
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
        Err(IndexerError::Rpc("not used".into()))
    }
    async fn active_tree_number(&self, _at: Option<alloy::eips::BlockId>) -> Result<u32> {
        Err(IndexerError::Rpc("not used".into()))
    }
}

fn shield(block: u64) -> RailgunEvent {
    RailgunEvent::Shield {
        block_number: block,
        tx_hash: [u8::try_from(block & 0xff).expect("byte"); 32],
        tree_number: 0,
        start_position: 0,
        leaves: vec![CommitmentLeaf {
            tree_number: 0,
            leaf_index: 0,
            commitment_hash: [0xab; 32],
            ciphertext: Vec::new(),
        }],
    }
}

async fn collect_heartbeats(
    rx: &mut mpsc::Receiver<IndexerMessage>,
    want: usize,
    budget: Duration,
) -> Vec<(u64, u64)> {
    let deadline = tokio::time::Instant::now() + budget;
    let mut beats = Vec::new();
    while beats.len() < want && tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(1500), rx.recv()).await {
            Ok(Some(IndexerMessage::Heartbeat {
                chain_head_block,
                scanned_through_block,
                ..
            })) => beats.push((chain_head_block, scanned_through_block)),
            Ok(None) => break,
            Ok(Some(_)) | Err(_) => {}
        }
    }
    beats
}

/// A chain that produces no Railgun events still reports zero lag: the
/// heartbeat watermark tracks the scanner, which stays at the tip.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quiet_chain_heartbeat_reports_zero_lag() {
    let src = Arc::new(QuietMockSource::with_blocks(300));
    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(64);
    let worker = IndexerWorker::new(Arc::clone(&src), tx);
    let cfg = IndexerWorkerConfig {
        start_block: 0,
        poll_interval_secs: 1,
        chunk_blocks: 500,
        ..IndexerWorkerConfig::default()
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let beats = collect_heartbeats(&mut rx, 3, Duration::from_secs(20)).await;
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;

    assert!(
        beats.len() >= 3,
        "expected >= 3 heartbeats on a quiet chain; got {beats:?}"
    );
    for (head, scanned) in &beats {
        assert_eq!(*head, 300, "mock tip is fixed at 300; got {head}");
        assert_eq!(
            head.saturating_sub(*scanned),
            0,
            "quiet chain must report zero lag; head={head} scanned={scanned}"
        );
    }
}

/// The watermark stays at the tip across a quiet stretch that follows an
/// event: the height of the last applied event is irrelevant to lag.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn heartbeat_watermark_outlives_last_event_block() {
    let src = Arc::new(QuietMockSource::with_blocks(1_000));
    src.add_event(10, shield(10));
    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(64);
    let worker = IndexerWorker::new(Arc::clone(&src), tx);
    let cfg = IndexerWorkerConfig {
        start_block: 0,
        poll_interval_secs: 1,
        chunk_blocks: 5_000,
        ..IndexerWorkerConfig::default()
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let beats = collect_heartbeats(&mut rx, 2, Duration::from_secs(20)).await;
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;

    assert!(!beats.is_empty(), "expected at least one heartbeat");
    for (head, scanned) in &beats {
        assert_eq!(
            *scanned, 1_000,
            "watermark must be the scan cursor (1000), not the last event block (10)"
        );
        assert_eq!(head.saturating_sub(*scanned), 0);
    }
}

/// The inverse failure: a scanner mid-backfill must NOT report zero lag just
/// because the tip is known.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backfill_heartbeat_reports_nonzero_lag() {
    let src = Arc::new(QuietMockSource::with_blocks(10_000));
    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(64);
    let worker = IndexerWorker::new(Arc::clone(&src), tx);
    let cfg = IndexerWorkerConfig {
        start_block: 0,
        poll_interval_secs: 1,
        chunk_blocks: 100,
        ..IndexerWorkerConfig::default()
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let beats = collect_heartbeats(&mut rx, 2, Duration::from_secs(20)).await;
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;

    let (head, scanned) = *beats.first().expect("at least one heartbeat");
    assert_eq!(head, 10_000);
    assert_eq!(
        scanned, 100,
        "first chunk ends at start_block + chunk_blocks"
    );
    assert_eq!(
        head.saturating_sub(scanned),
        9_900,
        "a backfilling scanner must report the true remaining distance"
    );
}
