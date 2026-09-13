//! Decode provenance controls retry and endpoint selection.

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use alloy::primitives::address;
use axum::{
    extract::State as AxumState,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use raven_railgun_indexer::{
    rpc_pool::{EndpointConfig, PoolConfig, PoolStrategy, PooledRpcChainSource, RpcEndpointPool},
    ChainSource, IndexerError, RpcChainSource, MAX_RPC_RETRIES,
};
use serde_json::{json, Value};

const CHAIN_ID: u64 = 1;

#[derive(Clone, Debug)]
struct RpcState {
    malformed_log_responses: u64,
    malformed_call_responses: u64,
    log_error_code: Option<i64>,
    log_calls: Arc<AtomicU64>,
    call_calls: Arc<AtomicU64>,
}

fn rpc_result(id: Value, result: Value) -> Response {
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response()
}

fn malformed_json() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        "{",
    )
        .into_response()
}

async fn rpc_handler(
    AxumState(state): AxumState<RpcState>,
    Json(request): Json<Value>,
) -> Response {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    match request.get("method").and_then(Value::as_str) {
        Some("eth_chainId") => rpc_result(id, json!(format!("0x{CHAIN_ID:x}"))),
        Some("eth_getLogs") => {
            let attempt = state.log_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(code) = state.log_error_code {
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": code, "message": "fixture error" }
                }))
                .into_response()
            } else if attempt < state.malformed_log_responses {
                malformed_json()
            } else {
                rpc_result(id, json!([]))
            }
        }
        Some("eth_call") => {
            let attempt = state.call_calls.fetch_add(1, Ordering::SeqCst);
            let encoded = if attempt < state.malformed_call_responses {
                "0x".to_owned()
            } else {
                format!("0x{}01", "00".repeat(31))
            };
            rpc_result(id, json!(encoded))
        }
        method => Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32601,
                "message": format!("unexpected method: {method:?}")
            }
        }))
        .into_response(),
    }
}

async fn spawn_rpc(
    malformed_log_responses: u64,
    malformed_call_responses: u64,
) -> (String, RpcState, tokio::task::JoinHandle<()>) {
    spawn_rpc_with_log_error(malformed_log_responses, malformed_call_responses, None).await
}

async fn spawn_rpc_with_log_error(
    malformed_log_responses: u64,
    malformed_call_responses: u64,
    log_error_code: Option<i64>,
) -> (String, RpcState, tokio::task::JoinHandle<()>) {
    let state = RpcState {
        malformed_log_responses,
        malformed_call_responses,
        log_error_code,
        log_calls: Arc::new(AtomicU64::new(0)),
        call_calls: Arc::new(AtomicU64::new(0)),
    };
    let app = Router::new()
        .route("/", post(rpc_handler))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local RPC fixture");
    let address = listener.local_addr().expect("read fixture address");
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{address}/"), state, server)
}

fn endpoint(url: String) -> EndpointConfig {
    EndpointConfig {
        url,
        rps: 100,
        burst: 100,
    }
}

fn pool(urls: impl IntoIterator<Item = String>) -> Arc<RpcEndpointPool> {
    Arc::new(
        RpcEndpointPool::new(
            urls.into_iter().map(endpoint).collect(),
            PoolConfig {
                strategy: PoolStrategy::PrimaryWithFailover,
                ..PoolConfig::default()
            },
        )
        .expect("build endpoint pool"),
    )
}

fn proxy() -> alloy::primitives::Address {
    address!("fa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_source_retries_a_remote_malformed_response() {
    let (url, state, _server) = spawn_rpc(1, 0).await;
    let source = RpcChainSource::new(url, proxy(), 0, CHAIN_ID);

    let events = source
        .events_in_range(1, 1)
        .await
        .expect("second complete response must succeed");
    assert!(events.is_empty());
    assert_eq!(state.log_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_source_bounds_persistent_remote_malformed_responses() {
    let (url, state, _server) = spawn_rpc(u64::MAX, 0).await;
    let source = RpcChainSource::new(url, proxy(), 0, CHAIN_ID);

    let error = source
        .events_in_range(1, 1)
        .await
        .expect_err("persistent malformed responses must fail closed");
    assert!(matches!(
        error,
        IndexerError::Provider {
            source: alloy::transports::RpcError::DeserError { .. },
            ..
        }
    ));
    assert_eq!(
        state.log_calls.load(Ordering::SeqCst),
        u64::from(MAX_RPC_RETRIES)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_source_never_retries_application_decode() {
    let (url, state, _server) = spawn_rpc(0, 1).await;
    let source = RpcChainSource::new(url, proxy(), 0, CHAIN_ID);

    let error = source
        .root_history(0, [0; 32], None)
        .await
        .expect_err("complete but invalid ABI bytes must fail fast");
    assert!(matches!(error, IndexerError::Decode(_)));
    assert_eq!(state.call_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pool_retries_remote_malformed_response_on_an_independent_endpoint() {
    let (bad_url, bad_state, _bad_server) = spawn_rpc(u64::MAX, 0).await;
    let (good_url, good_state, _good_server) = spawn_rpc(0, 0).await;
    let source = PooledRpcChainSource::new(pool([bad_url, good_url]), proxy(), CHAIN_ID);

    let events = source
        .events_in_range(1, 1)
        .await
        .expect("second endpoint must supply a complete response");
    assert!(events.is_empty());
    assert_eq!(bad_state.log_calls.load(Ordering::SeqCst), 1);
    assert_eq!(good_state.log_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pinned_application_decode_never_selects_a_second_endpoint() {
    let (bad_url, bad_state, _bad_server) = spawn_rpc(0, 1).await;
    let (good_url, good_state, _good_server) = spawn_rpc(0, 0).await;
    let source = PooledRpcChainSource::new(pool([bad_url, good_url]), proxy(), CHAIN_ID);
    let at = alloy::eips::BlockId::Number(alloy::eips::BlockNumberOrTag::Latest);

    let error = source
        .root_history(0, [0; 32], Some(at))
        .await
        .expect_err("pinned ABI failure must not change endpoint");
    assert!(matches!(error, IndexerError::Decode(_)));
    assert_eq!(bad_state.call_calls.load(Ordering::SeqCst), 1);
    assert_eq!(good_state.call_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pooled_json_rpc_parse_error_fails_fast_without_selecting_an_alternate() {
    let (bad_url, bad_state, _bad_server) = spawn_rpc_with_log_error(0, 0, Some(-32700)).await;
    let (good_url, good_state, _good_server) = spawn_rpc(0, 0).await;
    let source = PooledRpcChainSource::new(pool([bad_url, good_url]), proxy(), CHAIN_ID);

    let error = source
        .events_in_range(1, 1)
        .await
        .expect_err("an invalid request must fail without endpoint failover");
    assert!(matches!(
        error,
        IndexerError::Provider {
            source: alloy::transports::RpcError::ErrorResp(payload),
            ..
        } if payload.code == -32700
    ));
    assert_eq!(bad_state.log_calls.load(Ordering::SeqCst), 1);
    assert_eq!(good_state.log_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unpinned_application_decode_uses_one_distinct_alternate() {
    let (bad_url, bad_state, _bad_server) = spawn_rpc(0, u64::MAX).await;
    let (good_url, good_state, _good_server) = spawn_rpc(0, 0).await;
    let source = PooledRpcChainSource::new(pool([bad_url, good_url]), proxy(), CHAIN_ID);

    assert!(
        source
            .root_history(0, [0; 32], None)
            .await
            .expect("the independent endpoint must recover the ABI decode"),
        "the healthy endpoint returns ABI true"
    );
    assert_eq!(bad_state.call_calls.load(Ordering::SeqCst), 1);
    assert_eq!(good_state.call_calls.load(Ordering::SeqCst), 1);
}
