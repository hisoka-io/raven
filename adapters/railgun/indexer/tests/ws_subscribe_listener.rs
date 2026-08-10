//! Integration tests for `SubscribeWorker` using synthetic streamers.
//!
//! Happy path, heartbeat-watchdog hang detection, open-failure budget exhaustion.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::needless_continue,
    clippy::indexing_slicing,
    clippy::doc_lazy_continuation,
    clippy::items_after_statements,
    clippy::cast_possible_truncation,
    clippy::manual_assert,
    clippy::manual_contains,
    clippy::match_same_arms
)]

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use alloy::primitives::{Address as AlloyAddress, B256, U256};
use alloy::sol_types::SolValue;
use async_trait::async_trait;
use raven_railgun_core::RailgunEvent;
use raven_railgun_indexer::{
    abi, ChainSource, ChainSourceMode, IndexerError, IndexerMessage, LogStreamer, Result,
    SubscribeStreams, SubscribeWorker, SubscribeWorkerConfig,
};
use tokio::sync::mpsc;

fn synthetic_shield_log(block_number: u64, leaf_index: u32) -> alloy::rpc::types::eth::Log {
    let tree = U256::from(0u64);
    let start = U256::from(u64::from(leaf_index));
    let token_address: [u8; 20] = [0x42; 20];
    let token = abi::TokenData {
        tokenType: 0,
        tokenAddress: AlloyAddress::from(token_address),
        tokenSubID: U256::from(0u64),
    };
    let mut npk_be = [0u8; 32];
    npk_be[24..].copy_from_slice(&u64::from(leaf_index + 1).to_be_bytes());
    let npk_b256 = B256::from(npk_be);
    let commitments = vec![abi::CommitmentPreimage {
        npk: npk_b256,
        token,
        value: alloy::primitives::Uint::<120, 2>::from(1_000u64),
    }];
    let shield_ct = vec![abi::ShieldCiphertext {
        encryptedBundle: [B256::ZERO, B256::ZERO, B256::ZERO],
        shieldKey: B256::ZERO,
    }];
    let fees: Vec<U256> = vec![U256::from(0u64)];

    use alloy::sol_types::SolEvent;
    let data = (tree, start, commitments, shield_ct, fees).abi_encode_params();
    let log_data =
        alloy::primitives::LogData::new_unchecked(vec![abi::Shield::SIGNATURE_HASH], data.into());

    alloy::rpc::types::eth::Log {
        inner: alloy::primitives::Log {
            address: AlloyAddress::ZERO,
            data: log_data,
        },
        block_number: Some(block_number),
        transaction_hash: Some(B256::ZERO),
        ..Default::default()
    }
}

#[derive(Debug)]
struct ScriptedStreamer {
    heads: std::sync::Mutex<Option<Vec<u64>>>,
    logs: std::sync::Mutex<Option<Vec<alloy::rpc::types::eth::Log>>>,
    opens: AtomicU64,
    heads_tx: std::sync::Mutex<Option<mpsc::Sender<Result<u64>>>>,
    logs_tx: std::sync::Mutex<Option<mpsc::Sender<Result<alloy::rpc::types::eth::Log>>>>,
}

impl ScriptedStreamer {
    fn new(heads: Vec<u64>, logs: Vec<alloy::rpc::types::eth::Log>) -> Self {
        Self {
            heads: std::sync::Mutex::new(Some(heads)),
            logs: std::sync::Mutex::new(Some(logs)),
            opens: AtomicU64::new(0),
            heads_tx: std::sync::Mutex::new(None),
            logs_tx: std::sync::Mutex::new(None),
        }
    }
    fn opens(&self) -> u64 {
        self.opens.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl LogStreamer for ScriptedStreamer {
    async fn open(&self) -> Result<SubscribeStreams> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        let heads = self
            .heads
            .lock()
            .expect("poison")
            .take()
            .unwrap_or_default();
        let logs = self.logs.lock().expect("poison").take().unwrap_or_default();
        let (heads_tx, heads_rx) = mpsc::channel(heads.len() + 1);
        let (logs_tx, logs_rx) = mpsc::channel(logs.len() + 1);
        // Enqueued before the worker sees either receiver, and sized to the
        // script so no send can block.
        for n in heads {
            heads_tx.try_send(Ok(n)).expect("heads script fits");
        }
        for log in logs {
            logs_tx.try_send(Ok(log)).expect("logs script fits");
        }
        // The script is one-shot, so a reconnect replays nothing. Either stream
        // closing tears down the pair, dropping whatever the other had left, so
        // both senders stay alive and the heartbeat window ends the connection.
        *self.heads_tx.lock().expect("poison") = Some(heads_tx);
        *self.logs_tx.lock().expect("poison") = Some(logs_tx);
        Ok(SubscribeStreams {
            heads: heads_rx,
            logs: logs_rx,
        })
    }
}

#[derive(Debug, Default)]
struct SilentStreamer {
    opens: AtomicU64,
    _heads: std::sync::Mutex<Option<mpsc::Sender<Result<u64>>>>,
    _logs: std::sync::Mutex<Option<mpsc::Sender<Result<alloy::rpc::types::eth::Log>>>>,
}

#[async_trait]
impl LogStreamer for SilentStreamer {
    async fn open(&self) -> Result<SubscribeStreams> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        let (heads_tx, heads_rx) = mpsc::channel(1);
        let (logs_tx, logs_rx) = mpsc::channel(1);
        // Hold sender halves alive on the streamer so the channels
        // never close; the worker's heartbeat must trip on its own.
        *self._heads.lock().expect("poison") = Some(heads_tx);
        *self._logs.lock().expect("poison") = Some(logs_tx);
        Ok(SubscribeStreams {
            heads: heads_rx,
            logs: logs_rx,
        })
    }
}

#[derive(Debug, Default)]
struct AlwaysFailStreamer {
    attempts: AtomicU64,
}

#[async_trait]
impl LogStreamer for AlwaysFailStreamer {
    async fn open(&self) -> Result<SubscribeStreams> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Err(IndexerError::Rpc("ws connect: synthetic failure".into()))
    }
}

#[derive(Debug, Default)]
struct FlappingStreamer {
    opens: AtomicU64,
}

#[async_trait]
impl LogStreamer for FlappingStreamer {
    async fn open(&self) -> Result<SubscribeStreams> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        let (heads_tx, heads_rx) = mpsc::channel(4);
        let (_logs_tx, logs_rx) = mpsc::channel::<Result<alloy::rpc::types::eth::Log>>(4);
        tokio::spawn(async move {
            let _ = heads_tx.send(Ok(1u64)).await;
        });
        Ok(SubscribeStreams {
            heads: heads_rx,
            logs: logs_rx,
        })
    }
}

#[derive(Debug, Default)]
struct HalfOpenStreamer {
    opens: AtomicU64,
}

#[async_trait]
impl LogStreamer for HalfOpenStreamer {
    async fn open(&self) -> Result<SubscribeStreams> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        let (heads_tx, heads_rx) = mpsc::channel(4);
        // Logs close at once while heads keep arriving: the half-open transport.
        let (logs_tx, logs_rx) = mpsc::channel::<Result<alloy::rpc::types::eth::Log>>(1);
        drop(logs_tx);
        tokio::spawn(async move {
            let mut n = 1u64;
            while heads_tx.send(Ok(n)).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(20)).await;
                n += 1;
            }
        });
        Ok(SubscribeStreams {
            heads: heads_rx,
            logs: logs_rx,
        })
    }
}

#[derive(Debug)]
struct StaticFallback(u64);

#[async_trait]
impl ChainSource for StaticFallback {
    async fn latest_block(&self) -> Result<u64> {
        Ok(self.0)
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

async fn collect_messages(
    rx: &mut mpsc::Receiver<IndexerMessage>,
    for_secs: u64,
) -> (Vec<RailgunEvent>, Vec<u64>, Vec<u64>) {
    use tokio::time::{timeout, Duration as TD};
    let mut events = Vec::new();
    let mut heartbeats = Vec::new();
    let mut reorgs = Vec::new();
    let deadline = std::time::Instant::now() + TD::from_secs(for_secs);
    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;
        match timeout(remaining, rx.recv()).await {
            Ok(Some(IndexerMessage::Event { event, .. })) => events.push(event),
            Ok(Some(IndexerMessage::Heartbeat {
                chain_head_block, ..
            })) => heartbeats.push(chain_head_block),
            Ok(Some(IndexerMessage::Reorg { height })) => reorgs.push(height),
            Ok(None) => break,
            Err(_) => break,
        }
    }
    (events, heartbeats, reorgs)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn happy_path_emits_events_and_heartbeats_then_falls_back() {
    const N_HEADS: usize = 3;
    const M_LOGS: usize = 4;

    let heads: Vec<u64> = (1..=N_HEADS as u64).collect();
    let logs: Vec<_> = (0..M_LOGS as u32)
        .map(|i| synthetic_shield_log(100 + u64::from(i), i))
        .collect();

    let streamer = Arc::new(ScriptedStreamer::new(heads, logs));
    let fallback = Arc::new(StaticFallback(2_000));
    let (tx, mut rx) = mpsc::channel(256);

    let worker = Arc::new(SubscribeWorker::new(
        Arc::clone(&streamer),
        Arc::clone(&fallback),
        tx,
    ));

    assert_eq!(worker.current_mode(), ChainSourceMode::Subscribe);

    let cfg = SubscribeWorkerConfig {
        heartbeat_secs: 2,
        reconnect_total_secs: 8,
        polling_dwell: Duration::from_millis(800),
    };

    let worker_handle = {
        let w = Arc::clone(&worker);
        tokio::spawn(async move { w.run(cfg).await })
    };

    let (events, heartbeats, reorgs) = collect_messages(&mut rx, 10).await;

    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), worker_handle).await;

    assert_eq!(
        events.len(),
        M_LOGS,
        "expected one Event per synthetic log, got {events:?}"
    );
    assert!(
        heartbeats.len() >= N_HEADS,
        "expected at least N={N_HEADS} heartbeats from heads, got {}",
        heartbeats.len()
    );
    assert!(reorgs.is_empty(), "no reorgs expected; got {reorgs:?}");

    for ev in &events {
        match ev {
            RailgunEvent::Shield { .. } => {}
            other => panic!("expected Shield events; got {other:?}"),
        }
    }

    assert!(
        streamer.opens() >= 1,
        "streamer should have been opened at least once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_stream_trips_heartbeat_within_budget() {
    let streamer = Arc::new(SilentStreamer::default());
    let fallback = Arc::new(StaticFallback(1_500));
    let (tx, mut rx) = mpsc::channel(256);

    let worker = Arc::new(SubscribeWorker::new(
        Arc::clone(&streamer),
        Arc::clone(&fallback),
        tx,
    ));
    let mode_flag = worker.mode_flag();

    let cfg = SubscribeWorkerConfig {
        heartbeat_secs: 1,
        reconnect_total_secs: 6,
        polling_dwell: Duration::from_millis(500),
    };

    let worker_handle = {
        let w = Arc::clone(&worker);
        tokio::spawn(async move { w.run(cfg).await })
    };

    let started = std::time::Instant::now();
    loop {
        if mode_flag.get() == ChainSourceMode::Polling {
            break;
        }
        if started.elapsed() > Duration::from_secs(5) {
            panic!(
                "worker stuck in Subscribe mode {} s after start; expected heartbeat trip < 2 s",
                started.elapsed().as_secs()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "heartbeat trip should occur within ~heartbeat_secs (=1s); took {}ms",
        started.elapsed().as_millis()
    );

    let (events, heartbeats, _) = collect_messages(&mut rx, 2).await;
    assert!(
        events.is_empty(),
        "no events should be emitted when streamer is silent"
    );
    let _ = heartbeats;

    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), worker_handle).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_failure_budget_latches_into_polling() {
    let streamer = Arc::new(AlwaysFailStreamer::default());
    let fallback = Arc::new(StaticFallback(7_777));
    let (tx, mut rx) = mpsc::channel(256);

    let worker = Arc::new(SubscribeWorker::new(
        Arc::clone(&streamer),
        Arc::clone(&fallback),
        tx,
    ));
    let mode_flag = worker.mode_flag();

    let cfg = SubscribeWorkerConfig {
        heartbeat_secs: 1,
        reconnect_total_secs: 2,
        polling_dwell: Duration::from_millis(300),
    };

    let worker_handle = {
        let w = Arc::clone(&worker);
        tokio::spawn(async move { w.run(cfg).await })
    };

    let started = std::time::Instant::now();
    loop {
        if mode_flag.get() == ChainSourceMode::Polling
            && streamer.attempts.load(Ordering::SeqCst) >= 1
        {
            break;
        }
        if started.elapsed() > Duration::from_secs(5) {
            panic!("worker never reached polling mode within 5 s");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let (events, heartbeats, _) = collect_messages(&mut rx, 1).await;
    assert!(events.is_empty(), "polling fallback yields no events here");
    assert!(
        heartbeats.iter().any(|&h| h == 7_777),
        "fallback's static latest_block (7777) should appear in heartbeats; got {heartbeats:?}"
    );

    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), worker_handle).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flapping_streamer_exhausts_cumulative_budget() {
    let streamer = Arc::new(FlappingStreamer::default());
    let fallback = Arc::new(StaticFallback(9_999));
    let (tx, mut rx) = mpsc::channel(256);

    let worker = Arc::new(SubscribeWorker::new(
        Arc::clone(&streamer),
        Arc::clone(&fallback),
        tx,
    ));

    let cfg = SubscribeWorkerConfig {
        heartbeat_secs: 1,
        reconnect_total_secs: 1,
        polling_dwell: Duration::from_millis(200),
    };

    let worker_handle = {
        let w = Arc::clone(&worker);
        tokio::spawn(async move { w.run(cfg).await })
    };

    tokio::time::sleep(Duration::from_secs(2)).await;
    let opens_after_budget = streamer.opens.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(800)).await;
    let opens_after_grace = streamer.opens.load(Ordering::SeqCst);

    assert_eq!(
        opens_after_budget, opens_after_grace,
        "after the cumulative reconnect budget elapses the worker must \
         stop calling streamer.open(); pre-fix this would keep climbing \
         (saw {opens_after_budget} -> {opens_after_grace})"
    );
    assert!(
        opens_after_budget >= 2,
        "the worker must flap at least twice before the budget exhausts; \
         got {opens_after_budget}"
    );

    let (_events, heartbeats, _) = collect_messages(&mut rx, 1).await;
    assert!(
        heartbeats.iter().any(|&h| h == 9_999),
        "indefinite-polling mode must surface the static fallback's \
         latest_block (9999) on its heartbeats; got {heartbeats:?}"
    );

    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), worker_handle).await;
}

/// A cold worker whose first WS open fails must not report the whole chain as lag.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_first_open_floors_the_scan_watermark_at_the_tip() {
    let streamer = Arc::new(AlwaysFailStreamer::default());
    let fallback = Arc::new(StaticFallback(23_000_000));
    let (tx, mut rx) = mpsc::channel(256);

    let worker = Arc::new(SubscribeWorker::new(
        Arc::clone(&streamer),
        Arc::clone(&fallback),
        tx,
    ));

    let cfg = SubscribeWorkerConfig {
        heartbeat_secs: 1,
        reconnect_total_secs: 1,
        polling_dwell: Duration::from_millis(300),
    };

    let worker_handle = {
        let w = Arc::clone(&worker);
        tokio::spawn(async move { w.run(cfg).await })
    };

    let mut beats: Vec<(u64, u64)> = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(6);
    while beats.len() < 2 && std::time::Instant::now() < deadline {
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

    assert!(
        streamer.attempts.load(Ordering::SeqCst) >= 1,
        "the streamer must have been tried and failed"
    );
    assert!(!beats.is_empty(), "expected at least one polling heartbeat");
    for (head, scanned) in &beats {
        assert_eq!(*scanned, 23_000_000, "watermark floors at the tip on entry");
        assert_eq!(
            head.saturating_sub(*scanned),
            0,
            "a worker that never scanned must not claim 23M blocks of lag"
        );
    }

    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), worker_handle).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closed_logs_stream_reconnects_even_while_heads_flow() {
    let streamer = Arc::new(HalfOpenStreamer::default());
    let fallback = Arc::new(StaticFallback(9_999));
    let (tx, _rx) = mpsc::channel(256);

    let worker = Arc::new(SubscribeWorker::new(
        Arc::clone(&streamer),
        Arc::clone(&fallback),
        tx,
    ));

    // Heartbeat far exceeds the observation window, so surviving on heads alone
    // would never trip it and open() would stay at 1.
    let cfg = SubscribeWorkerConfig {
        heartbeat_secs: 300,
        reconnect_total_secs: 300,
        polling_dwell: Duration::from_millis(50),
    };

    let worker_handle = {
        let w = Arc::clone(&worker);
        tokio::spawn(async move { w.run(cfg).await })
    };

    tokio::time::sleep(Duration::from_secs(2)).await;
    let opens = streamer.opens.load(Ordering::SeqCst);
    worker_handle.abort();

    assert!(
        opens > 1,
        "a clean logs close is a transport break; the worker must reconnect \
         rather than ride the heads stream reporting zero lag (saw {opens} open(s))"
    );
}
