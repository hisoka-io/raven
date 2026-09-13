//! Reorg-fence and reconnect-backfill coverage for the subscription worker.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::needless_continue,
    clippy::match_same_arms
)]

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use alloy::primitives::{Address as AlloyAddress, B256, U256};
use alloy::sol_types::{SolEvent, SolValue};
use async_trait::async_trait;
use raven_railgun_core::RailgunEvent;
use raven_railgun_indexer::{
    abi, ChainSource, IndexerError, IndexerMessage, LogStreamer, Result, SubscribeStreams,
    SubscribeWorker, SubscribeWorkerConfig,
};
use tokio::sync::mpsc;

fn shield_log(block_number: u64, removed: bool) -> alloy::rpc::types::eth::Log {
    let commitments = vec![abi::CommitmentPreimage {
        npk: B256::from([0x07_u8; 32]),
        token: abi::TokenData {
            tokenType: 0,
            tokenAddress: AlloyAddress::from([0x42; 20]),
            tokenSubID: U256::from(0u64),
        },
        value: alloy::primitives::Uint::<120, 2>::from(1_000u64),
    }];
    let shield_ct = vec![abi::ShieldCiphertext {
        encryptedBundle: [B256::ZERO, B256::ZERO, B256::ZERO],
        shieldKey: B256::ZERO,
    }];
    let fees: Vec<U256> = vec![U256::from(0u64)];
    let data = (
        U256::from(0u64),
        U256::from(0u64),
        commitments,
        shield_ct,
        fees,
    )
        .abi_encode_params();
    alloy::rpc::types::eth::Log {
        inner: alloy::primitives::Log {
            address: AlloyAddress::ZERO,
            data: alloy::primitives::LogData::new_unchecked(
                vec![abi::Shield::SIGNATURE_HASH],
                data.into(),
            ),
        },
        block_number: Some(block_number),
        transaction_hash: Some(B256::ZERO),
        removed,
        ..Default::default()
    }
}

fn malformed_shield_log(block_number: u64) -> alloy::rpc::types::eth::Log {
    let mut log = shield_log(block_number, false);
    log.inner.data = alloy::primitives::LogData::new_unchecked(
        vec![abi::Shield::SIGNATURE_HASH],
        Vec::new().into(),
    );
    log
}

/// Serves a per-open script of (heads, logs); each open consumes one script
/// entry, then the streams close so the worker cycles into its next open.
#[derive(Debug)]
struct ScriptedOpens {
    scripts: Mutex<Vec<OpenScript>>,
    opens: AtomicU64,
}

#[derive(Debug)]
enum OpenScript {
    Fail,
    Frames(Vec<u64>, Vec<alloy::rpc::types::eth::Log>),
    HeldFrames(Vec<u64>, Vec<alloy::rpc::types::eth::Log>, Duration),
}

#[async_trait]
impl LogStreamer for ScriptedOpens {
    async fn open(&self) -> Result<SubscribeStreams> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        let script = {
            let mut g = self.scripts.lock().expect("poison");
            if g.is_empty() {
                OpenScript::Frames(Vec::new(), Vec::new())
            } else {
                g.remove(0)
            }
        };
        let (heads, logs, hold_open) = match script {
            OpenScript::Fail => {
                return Err(IndexerError::Rpc("scripted open failure".into()));
            }
            OpenScript::Frames(heads, logs) => (heads, logs, None),
            OpenScript::HeldFrames(heads, logs, duration) => (heads, logs, Some(duration)),
        };
        let (heads_tx, heads_rx) = mpsc::channel(heads.len() + 1);
        let (logs_tx, logs_rx) = mpsc::channel(logs.len() + 1);
        for n in heads {
            heads_tx.try_send(Ok(n)).expect("heads script fits");
        }
        for log in logs {
            logs_tx.try_send(Ok(log)).expect("logs script fits");
        }
        if let Some(duration) = hold_open {
            tokio::spawn(async move {
                tokio::time::sleep(duration).await;
                drop((heads_tx, logs_tx));
            });
        }
        // Both senders drop here: the streams close once drained, forcing the
        // reconnect path under test.
        Ok(SubscribeStreams {
            heads: heads_rx,
            logs: logs_rx,
        })
    }
}

/// Fallback that can serve real events for the gap the stream missed.
#[derive(Debug)]
struct BackfillFallback {
    tips: Mutex<Vec<u64>>,
    steady_tip: u64,
    events: Vec<RailgunEvent>,
    latest_calls: AtomicU64,
    range_calls: AtomicU64,
    ranges: Mutex<Vec<(u64, u64)>>,
}

#[async_trait]
impl ChainSource for BackfillFallback {
    async fn latest_block(&self) -> Result<u64> {
        self.latest_calls.fetch_add(1, Ordering::SeqCst);
        let mut tips = self.tips.lock().expect("tips lock");
        Ok(if tips.is_empty() {
            self.steady_tip
        } else {
            tips.remove(0)
        })
    }
    async fn events_in_range(&self, from: u64, to: u64) -> Result<Vec<RailgunEvent>> {
        self.range_calls.fetch_add(1, Ordering::SeqCst);
        self.ranges.lock().expect("ranges lock").push((from, to));
        Ok(self
            .events
            .iter()
            .filter(|e| {
                let h = match e {
                    RailgunEvent::Shield { block_number, .. }
                    | RailgunEvent::Transact { block_number, .. }
                    | RailgunEvent::Nullified { block_number, .. }
                    | RailgunEvent::Unshield { block_number, .. } => *block_number,
                };
                (from..=to).contains(&h)
            })
            .cloned()
            .collect())
    }
    async fn root_history(
        &self,
        _tree: u32,
        _root: [u8; 32],
        _at: Option<alloy::eips::BlockId>,
    ) -> Result<bool> {
        Ok(true)
    }
    async fn block_hash(&self, _n: u64) -> Result<[u8; 32]> {
        Ok([0u8; 32])
    }
    async fn merkle_root(&self, _at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        Ok([0u8; 32])
    }
    async fn active_tree_number(&self, _at: Option<alloy::eips::BlockId>) -> Result<u32> {
        Ok(0)
    }
}

#[derive(Debug)]
struct InitialTipFailureFallback {
    latest_calls: AtomicU64,
    range_calls: AtomicU64,
}

#[derive(Debug)]
struct DecodeFailingBackfill {
    latest_calls: AtomicU64,
    range_calls: AtomicU64,
}

#[async_trait]
impl ChainSource for DecodeFailingBackfill {
    async fn latest_block(&self) -> Result<u64> {
        let attempt = self.latest_calls.fetch_add(1, Ordering::SeqCst);
        Ok(if attempt < 2 { 100 } else { 102 })
    }

    async fn events_in_range(&self, _from: u64, _to: u64) -> Result<Vec<RailgunEvent>> {
        self.range_calls.fetch_add(1, Ordering::SeqCst);
        Err(IndexerError::Decode(
            "polling endpoint repeated malformed event".into(),
        ))
    }

    async fn root_history(
        &self,
        _tree: u32,
        _root: [u8; 32],
        _at: Option<alloy::eips::BlockId>,
    ) -> Result<bool> {
        Ok(true)
    }

    async fn block_hash(&self, _n: u64) -> Result<[u8; 32]> {
        Ok([0; 32])
    }

    async fn merkle_root(&self, _at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        Ok([0; 32])
    }

    async fn active_tree_number(&self, _at: Option<alloy::eips::BlockId>) -> Result<u32> {
        Ok(0)
    }
}

#[async_trait]
impl ChainSource for InitialTipFailureFallback {
    async fn latest_block(&self) -> Result<u64> {
        if self.latest_calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Err(IndexerError::Rpc("initial tip unavailable".into()))
        } else {
            Ok(100)
        }
    }

    async fn events_in_range(&self, _from: u64, _to: u64) -> Result<Vec<RailgunEvent>> {
        self.range_calls.fetch_add(1, Ordering::SeqCst);
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

    async fn block_hash(&self, _n: u64) -> Result<[u8; 32]> {
        Ok([0; 32])
    }

    async fn merkle_root(&self, _at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        Ok([0; 32])
    }

    async fn active_tree_number(&self, _at: Option<alloy::eips::BlockId>) -> Result<u32> {
        Ok(0)
    }
}

async fn collect_event_heights(rx: &mut mpsc::Receiver<IndexerMessage>, for_secs: u64) -> Vec<u64> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(for_secs);
    let mut heights = Vec::new();
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(300), rx.recv()).await {
            Ok(Some(IndexerMessage::Event { block_height, .. })) => heights.push(block_height),
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    heights
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removed_log_frame_emits_a_reorg_fence_instead_of_an_event() {
    let streamer = Arc::new(ScriptedOpens {
        scripts: Mutex::new(vec![OpenScript::Frames(
            vec![100],
            vec![shield_log(100, true)],
        )]),
        opens: AtomicU64::new(0),
    });
    let fallback = Arc::new(BackfillFallback {
        tips: Mutex::new(vec![99, 99]),
        steady_tip: 99,
        events: Vec::new(),
        latest_calls: AtomicU64::new(0),
        range_calls: AtomicU64::new(0),
        ranges: Mutex::new(Vec::new()),
    });
    let (tx, mut rx) = mpsc::channel(16);
    let worker = SubscribeWorker::new(streamer, fallback, tx);
    let cfg = SubscribeWorkerConfig {
        heartbeat_secs: 1,
        reconnect_total_secs: 1,
        polling_dwell: Duration::from_millis(100),
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    let mut event_heights = Vec::new();
    let mut reorg_heights = Vec::new();
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(300), rx.recv()).await {
            Ok(Some(IndexerMessage::Event { block_height, .. })) => {
                event_heights.push(block_height);
            }
            Ok(Some(IndexerMessage::Reorg { height })) => reorg_heights.push(height),
            Ok(Some(_)) | Err(_) => continue,
            Ok(None) => break,
        }
    }
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;

    assert!(
        event_heights.is_empty(),
        "removed log events: {event_heights:?}"
    );
    assert_eq!(reorg_heights, [99]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_finalized_between_initial_tip_and_first_open_are_backfilled() {
    let streamer = Arc::new(ScriptedOpens {
        scripts: Mutex::new(vec![OpenScript::HeldFrames(
            vec![102],
            vec![shield_log(102, false)],
            Duration::from_secs(2),
        )]),
        opens: AtomicU64::new(0),
    });
    let event_at = |block_number| RailgunEvent::Unshield {
        block_number,
        tx_hash: [0x33; 32],
        to: [0x11; 20],
        token: [0x22; 32],
        amount: 1,
        fee: 0,
    };
    let fallback = Arc::new(BackfillFallback {
        tips: Mutex::new(vec![100, 102]),
        steady_tip: 102,
        events: vec![event_at(101), event_at(102)],
        latest_calls: AtomicU64::new(0),
        range_calls: AtomicU64::new(0),
        ranges: Mutex::new(Vec::new()),
    });
    let (tx, mut rx) = mpsc::channel(64);
    let worker = SubscribeWorker::new(streamer, fallback, tx);
    let cfg = SubscribeWorkerConfig {
        heartbeat_secs: 1,
        reconnect_total_secs: 20,
        polling_dwell: Duration::from_millis(100),
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let heights = collect_event_heights(&mut rx, 1).await;
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;

    assert!(
        heights.contains(&101),
        "the event that landed during the reconnect gap must be delivered \
         (backfilled from the fallback); got heights {heights:?}"
    );
    assert_eq!(heights.iter().filter(|height| **height == 102).count(), 1);
}

fn unshield(block_number: u64) -> RailgunEvent {
    RailgunEvent::Unshield {
        block_number,
        tx_hash: [0x33; 32],
        to: [0x11; 20],
        token: [0x22; 32],
        amount: 1,
        fee: 0,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_first_open_does_not_lose_polling_gap_events() {
    let streamer = Arc::new(ScriptedOpens {
        scripts: Mutex::new(vec![
            OpenScript::Fail,
            OpenScript::HeldFrames(vec![102], Vec::new(), Duration::from_secs(2)),
        ]),
        opens: AtomicU64::new(0),
    });
    let fallback = Arc::new(BackfillFallback {
        tips: Mutex::new(vec![100, 102]),
        steady_tip: 102,
        events: vec![unshield(101), unshield(102)],
        latest_calls: AtomicU64::new(0),
        range_calls: AtomicU64::new(0),
        ranges: Mutex::new(Vec::new()),
    });
    let (tx, mut rx) = mpsc::channel(64);
    let observed_streamer = Arc::clone(&streamer);
    let worker = SubscribeWorker::new(streamer, fallback, tx);
    let join = tokio::spawn(async move {
        worker
            .run(SubscribeWorkerConfig {
                heartbeat_secs: 1,
                reconnect_total_secs: 2,
                polling_dwell: Duration::from_millis(500),
            })
            .await
    });

    let first = tokio::time::timeout(Duration::from_millis(300), async {
        loop {
            if let Some(IndexerMessage::Event { block_height, .. }) = rx.recv().await {
                break block_height;
            }
        }
    })
    .await
    .expect("polling dwell must deliver before reopen");
    let opens_at_delivery = observed_streamer.opens.load(Ordering::SeqCst);
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    assert_eq!(first, 101);
    assert_eq!(opens_at_delivery, 1, "delivery waited for a second WS open");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlap_removed_frame_is_suppressed_before_reorg_interpretation() {
    let streamer = Arc::new(ScriptedOpens {
        scripts: Mutex::new(vec![
            OpenScript::Frames(vec![100], Vec::new()),
            OpenScript::Frames(
                vec![102],
                vec![shield_log(102, true), shield_log(102, false)],
            ),
        ]),
        opens: AtomicU64::new(0),
    });
    let fallback = Arc::new(BackfillFallback {
        tips: Mutex::new(vec![100, 100, 102]),
        steady_tip: 102,
        events: vec![unshield(101), unshield(102)],
        latest_calls: AtomicU64::new(0),
        range_calls: AtomicU64::new(0),
        ranges: Mutex::new(Vec::new()),
    });
    let (tx, mut rx) = mpsc::channel(64);
    let worker = SubscribeWorker::new(streamer, fallback, tx);
    let join = tokio::spawn(async move {
        worker
            .run(SubscribeWorkerConfig {
                heartbeat_secs: 1,
                reconnect_total_secs: 2,
                polling_dwell: Duration::from_millis(100),
            })
            .await
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut reorgs = Vec::new();
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            Ok(Some(IndexerMessage::Reorg { height })) => reorgs.push(height),
            Ok(Some(_)) | Err(_) => {}
            Ok(None) => break,
        }
    }
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    assert!(
        reorgs.is_empty(),
        "backfill-owned removed frame emitted {reorgs:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removed_then_close_backfills_from_the_reorg_fence() {
    let streamer = Arc::new(ScriptedOpens {
        scripts: Mutex::new(vec![
            OpenScript::Frames(vec![102], vec![shield_log(102, true)]),
            OpenScript::Frames(vec![103], Vec::new()),
        ]),
        opens: AtomicU64::new(0),
    });
    let fallback = Arc::new(BackfillFallback {
        tips: Mutex::new(vec![100, 100]),
        steady_tip: 103,
        events: vec![unshield(102), unshield(103)],
        latest_calls: AtomicU64::new(0),
        range_calls: AtomicU64::new(0),
        ranges: Mutex::new(Vec::new()),
    });
    let (tx, mut rx) = mpsc::channel(64);
    let worker = SubscribeWorker::new(streamer, fallback, tx);
    let join = tokio::spawn(async move {
        worker
            .run(SubscribeWorkerConfig {
                heartbeat_secs: 1,
                reconnect_total_secs: 2,
                polling_dwell: Duration::from_millis(100),
            })
            .await
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut heights = Vec::new();
    let mut reorgs = Vec::new();
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            Ok(Some(IndexerMessage::Event { block_height, .. })) => heights.push(block_height),
            Ok(Some(IndexerMessage::Reorg { height })) => reorgs.push(height),
            Ok(Some(IndexerMessage::ReorgBarrier { height, .. })) => {
                panic!("subscribe worker cannot emit startup Reorg({height})")
            }
            Ok(Some(_)) | Err(_) => {}
            Ok(None) => break,
        }
    }
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    assert!(
        heights.contains(&102),
        "replacement was not reapplied: {heights:?}"
    );
    assert!(
        reorgs.contains(&100),
        "missing canonical rewind: {reorgs:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn log_without_head_is_reconciled_from_the_canonical_watermark() {
    let streamer = Arc::new(ScriptedOpens {
        scripts: Mutex::new(vec![
            OpenScript::Frames(Vec::new(), vec![shield_log(101, false)]),
            OpenScript::Frames(Vec::new(), Vec::new()),
        ]),
        opens: AtomicU64::new(0),
    });
    let fallback = Arc::new(BackfillFallback {
        tips: Mutex::new(vec![100, 100]),
        steady_tip: 101,
        events: vec![unshield(101)],
        latest_calls: AtomicU64::new(0),
        range_calls: AtomicU64::new(0),
        ranges: Mutex::new(Vec::new()),
    });
    let (tx, mut rx) = mpsc::channel(64);
    let worker = SubscribeWorker::new(streamer, fallback, tx);
    let join = tokio::spawn(async move {
        worker
            .run(SubscribeWorkerConfig {
                heartbeat_secs: 1,
                reconnect_total_secs: 2,
                polling_dwell: Duration::from_millis(100),
            })
            .await
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut heights = Vec::new();
    let mut reorgs = Vec::new();
    let mut scanned = Vec::new();
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            Ok(Some(IndexerMessage::Event { block_height, .. })) => heights.push(block_height),
            Ok(Some(IndexerMessage::Reorg { height })) => reorgs.push(height),
            Ok(Some(IndexerMessage::ReorgBarrier { height, .. })) => {
                panic!("subscribe worker cannot emit startup Reorg({height})")
            }
            Ok(Some(IndexerMessage::Heartbeat {
                scanned_through_block,
                ..
            })) => scanned.push(scanned_through_block),
            Err(_) => {}
            Ok(None) => break,
        }
    }
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    assert_eq!(heights.iter().filter(|height| **height == 101).count(), 2);
    assert!(reorgs.contains(&100), "missing overlay rewind: {reorgs:?}");
    assert!(
        scanned.contains(&100),
        "stream head became scan proof: {scanned:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exhausted_reconnect_budget_keeps_ingesting_via_polling() {
    let streamer = Arc::new(ScriptedOpens {
        scripts: Mutex::new(vec![OpenScript::Fail]),
        opens: AtomicU64::new(0),
    });
    let fallback = Arc::new(BackfillFallback {
        tips: Mutex::new(vec![100, 101]),
        steady_tip: 101,
        events: vec![unshield(101)],
        latest_calls: AtomicU64::new(0),
        range_calls: AtomicU64::new(0),
        ranges: Mutex::new(Vec::new()),
    });
    let (tx, mut rx) = mpsc::channel(16);
    let worker = SubscribeWorker::new(streamer, fallback, tx);
    let join = tokio::spawn(async move {
        worker
            .run(SubscribeWorkerConfig {
                heartbeat_secs: 1,
                reconnect_total_secs: 0,
                polling_dwell: Duration::ZERO,
            })
            .await
    });

    let heights = collect_event_heights(&mut rx, 2).await;
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    assert!(
        heights.contains(&101),
        "polling lost event 101: {heights:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fallback_backfill_obeys_the_chain_source_chunk_limit() {
    let streamer = Arc::new(ScriptedOpens {
        scripts: Mutex::new(vec![OpenScript::Frames(Vec::new(), Vec::new())]),
        opens: AtomicU64::new(0),
    });
    let fallback = Arc::new(BackfillFallback {
        tips: Mutex::new(vec![100, 1_100]),
        steady_tip: 1_100,
        events: Vec::new(),
        latest_calls: AtomicU64::new(0),
        range_calls: AtomicU64::new(0),
        ranges: Mutex::new(Vec::new()),
    });
    let observed = Arc::clone(&fallback);
    let (tx, rx) = mpsc::channel(32);
    let worker = SubscribeWorker::new(streamer, fallback, tx);
    let join = tokio::spawn(async move {
        worker
            .run(SubscribeWorkerConfig {
                heartbeat_secs: 1,
                reconnect_total_secs: 1,
                polling_dwell: Duration::ZERO,
            })
            .await
    });

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if observed.range_calls.load(Ordering::SeqCst) >= 3 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("three bounded range calls");
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let ranges = observed.ranges.lock().expect("ranges lock").clone();
    assert_eq!(ranges, [(101, 599), (600, 1_098), (1_099, 1_100)]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_initial_watermark_fails_closed_without_historical_replay() {
    let streamer = Arc::new(ScriptedOpens {
        scripts: Mutex::new(vec![OpenScript::Frames(Vec::new(), Vec::new())]),
        opens: AtomicU64::new(0),
    });
    let fallback = Arc::new(InitialTipFailureFallback {
        latest_calls: AtomicU64::new(0),
        range_calls: AtomicU64::new(0),
    });
    let observed_streamer = Arc::clone(&streamer);
    let observed_fallback = Arc::clone(&fallback);
    let (tx, _rx) = mpsc::channel(8);
    let worker = SubscribeWorker::new(streamer, fallback, tx);

    let error = tokio::time::timeout(
        Duration::from_millis(300),
        worker.run(SubscribeWorkerConfig::default()),
    )
    .await
    .expect("initial tip failure must stop before opening a stream")
    .expect_err("unknown live-tail boundary must fail closed");
    assert!(error.to_string().contains("initial tip unavailable"));
    assert_eq!(observed_streamer.opens.load(Ordering::SeqCst), 0);
    assert_eq!(observed_fallback.range_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decode_error_fences_the_overlay_then_recovers_from_polling() {
    let streamer = Arc::new(ScriptedOpens {
        scripts: Mutex::new(vec![OpenScript::HeldFrames(
            Vec::new(),
            vec![shield_log(101, false), malformed_shield_log(102)],
            Duration::from_secs(2),
        )]),
        opens: AtomicU64::new(0),
    });
    let fallback = Arc::new(BackfillFallback {
        tips: Mutex::new(vec![100, 100]),
        steady_tip: 102,
        events: [101, 102]
            .map(|block_number| RailgunEvent::Shield {
                block_number,
                tx_hash: [0; 32],
                tree_number: 0,
                start_position: 0,
                leaves: Vec::new(),
            })
            .to_vec(),
        latest_calls: AtomicU64::new(0),
        range_calls: AtomicU64::new(0),
        ranges: Mutex::new(Vec::new()),
    });
    let (tx, mut rx) = mpsc::channel(16);
    let worker = SubscribeWorker::new(streamer, fallback, tx);
    let join = tokio::spawn(async move {
        worker
            .run(SubscribeWorkerConfig {
                heartbeat_secs: 1,
                reconnect_total_secs: 1,
                polling_dwell: Duration::from_millis(50),
            })
            .await
    });

    let mut sequence = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while sequence.len() < 4 && tokio::time::Instant::now() < deadline {
        let Some(message) = tokio::time::timeout(Duration::from_millis(300), rx.recv())
            .await
            .ok()
            .flatten()
        else {
            continue;
        };
        match message {
            IndexerMessage::Event { block_height, .. } => sequence.push(("event", block_height)),
            IndexerMessage::Reorg { height } => sequence.push(("reorg", height)),
            IndexerMessage::ReorgBarrier { height, .. } => {
                panic!("subscribe worker cannot emit startup Reorg({height})")
            }
            IndexerMessage::Heartbeat { .. } => {}
        }
    }
    assert_eq!(
        sequence,
        [
            ("event", 101),
            ("reorg", 100),
            ("event", 101),
            ("event", 102)
        ]
    );
    drop(rx);
    let outcome = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .expect("worker exits after its consumer closes")
        .expect("worker join");
    assert!(
        outcome.is_ok(),
        "polling recovery must keep the worker alive"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_decode_error_keeps_the_fence_and_fails_closed() {
    let streamer = Arc::new(ScriptedOpens {
        scripts: Mutex::new(vec![OpenScript::HeldFrames(
            Vec::new(),
            vec![shield_log(101, false), malformed_shield_log(102)],
            Duration::from_secs(2),
        )]),
        opens: AtomicU64::new(0),
    });
    let fallback = Arc::new(DecodeFailingBackfill {
        latest_calls: AtomicU64::new(0),
        range_calls: AtomicU64::new(0),
    });
    let observed_fallback = Arc::clone(&fallback);
    let (tx, mut rx) = mpsc::channel(16);
    let worker = SubscribeWorker::new(streamer, fallback, tx);
    let join = tokio::spawn(async move {
        worker
            .run(SubscribeWorkerConfig {
                heartbeat_secs: 1,
                reconnect_total_secs: 1,
                polling_dwell: Duration::from_millis(50),
            })
            .await
    });

    let outcome = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .expect("repeated polling decode must stop the worker")
        .expect("worker join");
    assert!(matches!(outcome, Err(IndexerError::Decode(_))));
    assert_eq!(observed_fallback.range_calls.load(Ordering::SeqCst), 1);

    let mut sequence = Vec::new();
    while let Ok(message) = rx.try_recv() {
        match message {
            IndexerMessage::Event { block_height, .. } => sequence.push(("event", block_height)),
            IndexerMessage::Reorg { height } => sequence.push(("reorg", height)),
            IndexerMessage::ReorgBarrier { height, .. } => {
                panic!("subscribe worker cannot emit startup Reorg({height})")
            }
            IndexerMessage::Heartbeat { .. } => {}
        }
    }
    assert_eq!(sequence, [("event", 101), ("reorg", 100)]);
}
