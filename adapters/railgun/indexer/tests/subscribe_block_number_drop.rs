//! Every log-ingest path must DROP malformed logs whose `block_number`
//! is `None` rather than fabricate a height. Routing the event with a
//! fabricated height breaks downstream reorg-truncate semantics; the
//! operator-visible `raven_railgun_indexer_dropped_logs_total` counter
//! makes the drop observable.
//!
//! Covers the WS frame path (`handle_log_frame`) and the polling
//! `events_in_range` paths served over a mock JSON-RPC endpoint.

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

use alloy::primitives::{address, Address as AlloyAddress, B256, U256};
use alloy::sol_types::SolValue;
use async_trait::async_trait;
use axum::{extract::State as AxumState, http::StatusCode, routing::post, Json, Router};
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use raven_railgun_core::RailgunEvent;
use raven_railgun_indexer::rpc_pool::{
    EndpointConfig, PoolConfig, PoolStrategy, PooledRpcChainSource, RpcEndpointPool,
};
use raven_railgun_indexer::{
    abi, ChainSource, IndexerMessage, LogStreamer, Result, RpcChainSource, SubscribeStreams,
    SubscribeWorker, SubscribeWorkerConfig,
};
use serde_json::json;
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

const MOCK_CHAIN_ID: u64 = 1;

/// `blockNumber: null` is what an `eth_getLogs` window overlapping the
/// pending block returns; alloy rejects an omitted key outright, so null
/// is the only shape that reaches the decoder as `None`.
fn shield_log_json(block_number: Option<u64>) -> serde_json::Value {
    use alloy::sol_types::SolEvent;
    let log = synthetic_shield_log(block_number, 0);
    json!({
        "address": "0x0000000000000000000000000000000000000000",
        "topics": [format!("0x{}", alloy::hex::encode(abi::Shield::SIGNATURE_HASH))],
        "data": format!("0x{}", alloy::hex::encode(&log.inner.data.data)),
        "blockHash": "0x0000000000000000000000000000000000000000000000000000000000000001",
        "blockNumber": block_number.map(|n| format!("0x{n:x}")),
        "transactionHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": false,
    })
}

#[derive(Clone, Debug)]
struct LogsMockState {
    logs: Arc<Vec<serde_json::Value>>,
}

#[derive(serde::Deserialize, Debug)]
struct JsonRpcRequest {
    method: String,
    #[serde(default)]
    id: serde_json::Value,
}

async fn logs_mock_handler(
    AxumState(state): AxumState<LogsMockState>,
    Json(req): Json<JsonRpcRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let result = match req.method.as_str() {
        "eth_chainId" => json!(format!("0x{MOCK_CHAIN_ID:x}")),
        "eth_getLogs" => serde_json::Value::Array(state.logs.as_ref().clone()),
        other => {
            return (
                StatusCode::OK,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": req.id,
                    "error": { "code": -32601, "message": format!("unexpected method: {other}") }
                })),
            );
        }
    };
    (
        StatusCode::OK,
        Json(json!({ "jsonrpc": "2.0", "id": req.id, "result": result })),
    )
}

async fn spawn_logs_mock(logs: Vec<serde_json::Value>) -> (String, tokio::task::JoinHandle<()>) {
    let state = LogsMockState {
        logs: Arc::new(logs),
    };
    let app = Router::new()
        .route("/", post(logs_mock_handler))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}/"), handle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn polling_events_in_range_drops_log_when_block_number_none() {
    let s = snap();
    let before = dropped_counter_by_name(s);

    let (url, _server) = spawn_logs_mock(vec![
        shield_log_json(Some(100)),
        shield_log_json(None),
        shield_log_json(Some(102)),
    ])
    .await;

    let proxy = address!("fa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9");
    let source = RpcChainSource::new(url, proxy, 0, MOCK_CHAIN_ID);
    let events = source.events_in_range(1, 200).await.expect("events");

    let heights: Vec<u64> = events
        .iter()
        .map(|e| match e {
            RailgunEvent::Shield { block_number, .. } => *block_number,
            other => panic!("expected Shield; got {other:?}"),
        })
        .collect();
    assert_eq!(
        heights,
        vec![100, 102],
        "the heightless log must be dropped, not fabricated at 0"
    );
    let after = dropped_counter_by_name(s);
    assert!(
        after > before,
        "drop counter must advance; before={before} after={after}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pooled_events_in_range_drops_log_when_block_number_none() {
    let s = snap();
    let before = dropped_counter_by_name(s);

    let (url, _server) = spawn_logs_mock(vec![
        shield_log_json(Some(300)),
        shield_log_json(None),
        shield_log_json(Some(301)),
    ])
    .await;

    let pool = Arc::new(
        RpcEndpointPool::new(
            vec![EndpointConfig {
                url,
                rps: 100,
                burst: 100,
            }],
            PoolConfig {
                strategy: PoolStrategy::RoundRobin,
                ..PoolConfig::default()
            },
        )
        .expect("pool builds"),
    );
    let proxy = address!("fa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9");
    let source = PooledRpcChainSource::new(Arc::clone(&pool), proxy, MOCK_CHAIN_ID);
    let events = source.events_in_range(1, 400).await.expect("events");

    let heights: Vec<u64> = events
        .iter()
        .map(|e| match e {
            RailgunEvent::Shield { block_number, .. } => *block_number,
            other => panic!("expected Shield; got {other:?}"),
        })
        .collect();
    assert_eq!(
        heights,
        vec![300, 301],
        "the heightless log must be dropped, not fabricated at 0"
    );
    let after = dropped_counter_by_name(s);
    assert!(
        after > before,
        "drop counter must advance; before={before} after={after}"
    );
}
