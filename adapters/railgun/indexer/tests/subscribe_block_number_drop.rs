//! `handle_log_frame` must DROP malformed log frames whose
//! `block_number` is `None` rather than fabricate a height from the
//! observed chain head. Routing the event with a fabricated height
//! breaks downstream reorg-truncate semantics; the operator-visible
//! `raven_railgun_indexer_dropped_logs_total` counter makes the drop
//! observable.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::needless_continue,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::match_same_arms,
    clippy::let_unit_value,
    clippy::ignored_unit_patterns,
    clippy::items_after_statements
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
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use raven_railgun_core::RailgunEvent;
use raven_railgun_indexer::{
    abi, ChainSource, IndexerMessage, LogStreamer, Result, SubscribeStreams, SubscribeWorker,
    SubscribeWorkerConfig,
};
use std::sync::OnceLock;
use tokio::sync::mpsc;

/// Single global snapshotter shared across every test in this binary:
/// `metrics::set_global_recorder` rejects the second installation, so
/// attempting it per-test silently leaves the counter unobservable.
fn snap() -> &'static Snapshotter {
    static SNAP: OnceLock<Snapshotter> = OnceLock::new();
    SNAP.get_or_init(|| {
        let recorder = DebuggingRecorder::new();
        let s = recorder.snapshotter();
        let _ = metrics::set_global_recorder(recorder);
        s
    })
}

/// Build a synthetic Shield log. `block_number = None` simulates the
/// malformed RPC response the production fix drops.
fn synthetic_shield_log(block_number: Option<u64>, leaf_index: u32) -> alloy::rpc::types::eth::Log {
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
        block_number,
        transaction_hash: Some(B256::ZERO),
        ..Default::default()
    }
}

#[derive(Debug)]
struct ScriptedStreamer {
    heads: std::sync::Mutex<Option<Vec<u64>>>,
    logs: std::sync::Mutex<Option<Vec<alloy::rpc::types::eth::Log>>>,
    opens: AtomicU64,
}

impl ScriptedStreamer {
    fn new(heads: Vec<u64>, logs: Vec<alloy::rpc::types::eth::Log>) -> Self {
        Self {
            heads: std::sync::Mutex::new(Some(heads)),
            logs: std::sync::Mutex::new(Some(logs)),
            opens: AtomicU64::new(0),
        }
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
        let (heads_tx, heads_rx) = mpsc::channel(64);
        let (logs_tx, logs_rx) = mpsc::channel(64);
        tokio::spawn(async move {
            for n in heads {
                if heads_tx.send(Ok(n)).await.is_err() {
                    return;
                }
            }
        });
        tokio::spawn(async move {
            for log in logs {
                if logs_tx.send(Ok(log)).await.is_err() {
                    return;
                }
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

async fn collect_events(
    rx: &mut mpsc::Receiver<IndexerMessage>,
    expected: usize,
    deadline_secs: u64,
) -> Vec<RailgunEvent> {
    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(deadline_secs);
    while out.len() < expected {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        match tokio::time::timeout(Duration::from_millis(800), rx.recv()).await {
            Ok(Some(IndexerMessage::Event { event, .. })) => out.push(event),
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    out
}

/// Extract the dropped-log counter via a substring scan over the
/// snapshot's debug-formatted keys. `metrics-util`'s exact CompositeKey
/// shape varies between versions; the counter name is unique to the
/// indexer crate so a substring match is robust.
fn dropped_counter_by_name(snap: &Snapshotter) -> u64 {
    let dump = snap.snapshot();
    let entries = dump.into_vec();
    for (composite_key, _, _, value) in entries {
        let key_str = format!("{composite_key:?}");
        if key_str.contains("raven_railgun_indexer_dropped_logs_total") {
            if let DebugValue::Counter(v) = value {
                return v;
            }
        }
    }
    0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscribe_handle_log_drops_log_when_block_number_none() {
    let _ = snap();

    // Three logs: one valid + one with block_number = None + one valid.
    // The valid pair must surface as Events; the malformed entry must
    // be silently dropped.
    let logs = vec![
        synthetic_shield_log(Some(100), 0),
        synthetic_shield_log(None, 1),
        synthetic_shield_log(Some(102), 2),
    ];
    let streamer = Arc::new(ScriptedStreamer::new(vec![1, 2, 3], logs));
    let fallback = Arc::new(StaticFallback(2_000));
    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(256);

    let worker = Arc::new(SubscribeWorker::new(
        Arc::clone(&streamer),
        Arc::clone(&fallback),
        tx,
    ));
    let cfg = SubscribeWorkerConfig {
        heartbeat_secs: 4,
        reconnect_total_secs: 6,
        polling_dwell: Duration::from_millis(500),
    };
    let handle = {
        let w = Arc::clone(&worker);
        tokio::spawn(async move { w.run(cfg).await })
    };

    let events = collect_events(&mut rx, 2, 6).await;
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;

    assert_eq!(
        events.len(),
        2,
        "two valid logs must yield exactly two Events; got {events:?}"
    );
    for ev in &events {
        match ev {
            RailgunEvent::Shield { block_number, .. } => {
                assert!(
                    *block_number == 100 || *block_number == 102,
                    "valid logs carry concrete block heights; got {block_number}"
                );
            }
            other => panic!("expected Shield events; got {other:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscribe_dropped_logs_metric_increments_on_drop() {
    let s = snap();

    let before = dropped_counter_by_name(s);

    // Single malformed log: forces exactly one drop.
    let logs = vec![
        synthetic_shield_log(Some(50), 0),
        synthetic_shield_log(None, 1),
    ];
    let streamer = Arc::new(ScriptedStreamer::new(vec![10], logs));
    let fallback = Arc::new(StaticFallback(2_000));
    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(256);

    let worker = Arc::new(SubscribeWorker::new(
        Arc::clone(&streamer),
        Arc::clone(&fallback),
        tx,
    ));
    let cfg = SubscribeWorkerConfig {
        heartbeat_secs: 4,
        reconnect_total_secs: 6,
        polling_dwell: Duration::from_millis(500),
    };
    let handle = {
        let w = Arc::clone(&worker);
        tokio::spawn(async move { w.run(cfg).await })
    };

    let events = collect_events(&mut rx, 1, 6).await;
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;

    assert_eq!(events.len(), 1, "exactly one valid event must survive");
    let after = dropped_counter_by_name(s);
    assert!(
        after > before,
        "drop counter must advance; before={before} after={after}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscribe_handle_log_succeeds_when_block_number_present() {
    let _ = snap();

    let logs = vec![synthetic_shield_log(Some(200), 0)];
    let streamer = Arc::new(ScriptedStreamer::new(vec![1], logs));
    let fallback = Arc::new(StaticFallback(2_000));
    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(256);

    let worker = Arc::new(SubscribeWorker::new(
        Arc::clone(&streamer),
        Arc::clone(&fallback),
        tx,
    ));
    let cfg = SubscribeWorkerConfig {
        heartbeat_secs: 4,
        reconnect_total_secs: 6,
        polling_dwell: Duration::from_millis(500),
    };
    let handle = {
        let w = Arc::clone(&worker);
        tokio::spawn(async move { w.run(cfg).await })
    };

    let events = collect_events(&mut rx, 1, 6).await;
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;

    assert_eq!(events.len(), 1);
    match &events[0] {
        RailgunEvent::Shield { block_number, .. } => {
            assert_eq!(*block_number, 200);
        }
        other => panic!("expected Shield; got {other:?}"),
    }
}
