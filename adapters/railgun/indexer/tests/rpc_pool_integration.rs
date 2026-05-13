//! `RpcEndpointPool` failure-injection tests: per-endpoint rate limiting, round-robin rotation,
//! 5xx-triggered cooldown, and recovery after cooldown elapses.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::address;
use axum::{extract::State as AxumState, http::StatusCode, routing::post, Json, Router};
use raven_railgun_indexer::rpc_pool::{
    EndpointConfig, EndpointHealth, PoolConfig, PoolStrategy, PooledRpcChainSource, RpcEndpointPool,
};
use raven_railgun_indexer::ChainSource;
use serde_json::json;

#[test]
fn rapid_fire_requests_hit_per_endpoint_rate_limit_and_rotate() {
    let cfgs = vec![
        EndpointConfig {
            url: "http://endpoint-0.test/".to_owned(),
            rps: 50,
            burst: 50,
        },
        EndpointConfig {
            url: "http://endpoint-1.test/".to_owned(),
            rps: 50,
            burst: 50,
        },
    ];
    let pool = RpcEndpointPool::new(
        cfgs,
        PoolConfig {
            strategy: PoolStrategy::RoundRobin,
            ..PoolConfig::default()
        },
    )
    .expect("pool builds");

    let mut counts = [0u32; 2];
    let mut exhausted = 0u32;
    for _ in 0..200 {
        match pool.select_for_request() {
            Ok(endpoint) => {
                for (i, e) in pool.endpoints().iter().enumerate() {
                    if Arc::ptr_eq(e, &endpoint) {
                        if let Some(slot) = counts.get_mut(i) {
                            *slot += 1;
                        }
                    }
                }
                pool.release_in_flight(&endpoint);
            }
            Err(_) => exhausted += 1,
        }
    }

    let total = counts[0] + counts[1] + exhausted;
    assert_eq!(total, 200, "every iteration must be accounted for");
    assert!(
        counts[0] >= 1 && counts[1] >= 1,
        "both endpoints must be selected at least once for rotation \
         to be observable; counts={counts:?}, exhausted={exhausted}"
    );
    assert!(
        counts[0] <= 50,
        "endpoint 0 served {} requests, exceeds burst=50",
        counts[0]
    );
    assert!(
        counts[1] <= 50,
        "endpoint 1 served {} requests, exceeds burst=50",
        counts[1]
    );
    assert!(
        exhausted >= 1,
        "expected at least one Exhausted once both buckets drain; \
         counts={counts:?}, exhausted={exhausted}"
    );
    assert_eq!(
        u32::from(counts[0] >= 1) + u32::from(counts[1] >= 1),
        2,
        "both endpoints must have been hit before exhaustion"
    );
}

#[derive(Debug, Clone)]
struct MockState {
    fail_block_by_number: Arc<AtomicBool>,
    block_by_number_calls: Arc<AtomicU64>,
}

#[derive(serde::Deserialize, Debug)]
struct JsonRpcRequest {
    method: String,
    #[serde(default)]
    id: serde_json::Value,
}

async fn mock_handler(
    AxumState(state): AxumState<MockState>,
    Json(req): Json<JsonRpcRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    match req.method.as_str() {
        "eth_chainId" => (
            StatusCode::OK,
            Json(json!({
                "jsonrpc": "2.0",
                "id": req.id,
                "result": "0x1"
            })),
        ),
        "eth_getBlockByNumber" => {
            state.block_by_number_calls.fetch_add(1, Ordering::SeqCst);
            if state.fail_block_by_number.load(Ordering::SeqCst) {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": req.id,
                        "error": { "code": -32000, "message": "mock 503" }
                    })),
                )
            } else {
                let header = json!({
                    "number": "0xdeadbeef",
                    "hash": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                    "logsBloom": format!("0x{}", "0".repeat(512)),
                    "transactionsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "stateRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "receiptsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "miner": "0x0000000000000000000000000000000000000000",
                    "difficulty": "0x0",
                    "totalDifficulty": "0x0",
                    "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "nonce": "0x0000000000000000",
                    "extraData": "0x",
                    "size": "0x0",
                    "gasLimit": "0x0",
                    "gasUsed": "0x0",
                    "timestamp": "0x0",
                    "transactions": [],
                    "uncles": [],
                    "baseFeePerGas": "0x0",
                });
                (
                    StatusCode::OK,
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": req.id,
                        "result": header
                    })),
                )
            }
        }
        _ => (
            StatusCode::OK,
            Json(json!({
                "jsonrpc": "2.0",
                "id": req.id,
                "error": { "code": -32601, "message": format!("unknown method: {}", req.method) }
            })),
        ),
    }
}

async fn spawn_mock_server() -> (String, tokio::task::JoinHandle<()>, MockState) {
    let state = MockState {
        fail_block_by_number: Arc::new(AtomicBool::new(false)),
        block_by_number_calls: Arc::new(AtomicU64::new(0)),
    };
    let app = Router::new()
        .route("/", post(mock_handler))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("local_addr");
    let url = format!("http://{addr}/");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, handle, state)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persistent_5xx_on_endpoint_0_triggers_cooldown_and_recovery() {
    let (url0, _h0, state0) = spawn_mock_server().await;
    let (url1, _h1, state1) = spawn_mock_server().await;

    state0.fail_block_by_number.store(true, Ordering::SeqCst);
    state1.fail_block_by_number.store(false, Ordering::SeqCst);

    let cfgs = vec![
        EndpointConfig {
            url: url0.clone(),
            rps: 100,
            burst: 100,
        },
        EndpointConfig {
            url: url1.clone(),
            rps: 100,
            burst: 100,
        },
    ];
    let pool = Arc::new(
        RpcEndpointPool::new(
            cfgs,
            PoolConfig {
                strategy: PoolStrategy::RoundRobin,
                cooldown_secs_on_error: 1,
                ..PoolConfig::default()
            },
        )
        .expect("pool builds"),
    );
    let proxy = address!("fa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9");
    let source = PooledRpcChainSource::new(Arc::clone(&pool), proxy, 1);

    let mut ok_count = 0u32;
    for _ in 0..6 {
        if source.latest_block().await.is_ok() {
            ok_count += 1;
        }
    }
    assert!(
        ok_count >= 5,
        "expected most latest_block calls to succeed via failover; got {ok_count}/6"
    );

    let snapshot = pool.health_snapshot();
    assert_eq!(snapshot.len(), 2, "snapshot should have 2 entries");
    let e0 = snapshot.first().expect("endpoint 0 snapshot");
    let e1 = snapshot.get(1).expect("endpoint 1 snapshot");
    assert!(
        matches!(e0.health, EndpointHealth::CoolingDown { .. }),
        "endpoint 0 must be in cooldown after persistent 503; got {:?}",
        e0.health
    );
    assert!(
        matches!(
            e1.health,
            EndpointHealth::Healthy | EndpointHealth::Degraded
        ),
        "endpoint 1 must be healthy or degraded; got {:?}",
        e1.health
    );

    let calls_before = state0.block_by_number_calls.load(Ordering::SeqCst);
    for _ in 0..5 {
        let _ = source.latest_block().await;
    }
    let calls_after = state0.block_by_number_calls.load(Ordering::SeqCst);
    assert_eq!(
        calls_before, calls_after,
        "endpoint 0 must not be hit while in cooldown"
    );

    state0.fail_block_by_number.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let calls_pre_recovery = state0.block_by_number_calls.load(Ordering::SeqCst);
    for _ in 0..6 {
        let _ = source.latest_block().await;
    }
    let calls_post_recovery = state0.block_by_number_calls.load(Ordering::SeqCst);
    assert!(
        calls_post_recovery > calls_pre_recovery,
        "endpoint 0 must rejoin rotation after cooldown elapses; \
         pre={calls_pre_recovery}, post={calls_post_recovery}"
    );
}
