//! `PooledRpcChainSource` must verify `eth_chainId` on EVERY endpoint, not on whichever
//! one `select_for_request` happened to return first.
//!
//! `run_with_pool` round-robins every later call across the whole pool, so a single
//! unverified foreign endpoint answers its share of `events_in_range` with `Ok(vec![])`
//! and the worker executes `cursor = to` over the range it never saw. Roughly half the
//! commitments vanish, then the tree wedges on the first contiguity gap.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;

use alloy::primitives::address;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use raven_railgun_indexer::rpc_pool::{
    EndpointConfig, PoolConfig, PoolStrategy, PooledRpcChainSource, RpcEndpointPool,
};
use raven_railgun_indexer::{ChainSource, IndexerError};
use serde_json::{json, Value};
use tokio::sync::oneshot;

const HONEST_CHAIN: u64 = 1;
const FOREIGN_CHAIN: u64 = 11_155_111;

async fn spawn_rpc(reported_chain_id: u64) -> SocketAddr {
    let app = Router::new().route(
        "/",
        post(move |Json(req): Json<Value>| async move {
            let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
            let id = req.get("id").cloned().unwrap_or(Value::Null);
            if method == "eth_chainId" {
                return (
                    StatusCode::OK,
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": format!("0x{reported_chain_id:x}"),
                    })),
                );
            }
            (
                StatusCode::OK,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32601, "message": "only eth_chainId implemented" }
                })),
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = tx.send(());
        let _ = axum::serve(listener, app).await;
    });
    rx.await.expect("ready");
    addr
}

fn pool_over(addrs: &[SocketAddr]) -> Arc<RpcEndpointPool> {
    let cfgs = addrs
        .iter()
        .map(|a| EndpointConfig {
            url: format!("http://{a}"),
            rps: 100,
            burst: 100,
        })
        .collect();
    Arc::new(
        RpcEndpointPool::new(
            cfgs,
            PoolConfig {
                strategy: PoolStrategy::RoundRobin,
                ..PoolConfig::default()
            },
        )
        .expect("pool builds"),
    )
}

fn source(pool: &Arc<RpcEndpointPool>) -> PooledRpcChainSource {
    PooledRpcChainSource::new(
        Arc::clone(pool),
        address!("fa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"),
        HONEST_CHAIN,
    )
}

/// The defect: endpoint 0 is honest, endpoint 1 is on another chain. Round-robin
/// verification probes index 0 and latches, so the foreign endpoint is never checked.
#[tokio::test]
async fn a_foreign_endpoint_anywhere_in_the_pool_is_refused() {
    let honest = spawn_rpc(HONEST_CHAIN).await;
    let foreign = spawn_rpc(FOREIGN_CHAIN).await;
    let pool = pool_over(&[honest, foreign]);

    let err = source(&pool)
        .latest_block()
        .await
        .expect_err("a foreign endpoint in the pool must refuse the first call");
    match err {
        IndexerError::ChainIdMismatch { expected, actual } => {
            assert_eq!(expected, HONEST_CHAIN);
            assert_eq!(
                actual, FOREIGN_CHAIN,
                "the foreign endpoint must be the one named"
            );
        }
        other => panic!("expected ChainIdMismatch, got {other:?}"),
    }
}

/// Order must not matter: the foreign endpoint first is the case the old code DID catch,
/// so keeping it green proves the fix did not trade one direction for the other.
#[tokio::test]
async fn a_foreign_endpoint_first_is_still_refused() {
    let foreign = spawn_rpc(FOREIGN_CHAIN).await;
    let honest = spawn_rpc(HONEST_CHAIN).await;
    let pool = pool_over(&[foreign, honest]);

    let err = source(&pool).latest_block().await.expect_err("must refuse");
    assert!(
        matches!(err, IndexerError::ChainIdMismatch { .. }),
        "got {err:?}"
    );
}

/// An all-honest pool must pass the chain-id gate and fail later, on the unimplemented
/// method - otherwise the fix would refuse every legitimate multi-endpoint pool.
#[tokio::test]
async fn an_all_honest_pool_passes_the_chain_id_gate() {
    let a = spawn_rpc(HONEST_CHAIN).await;
    let b = spawn_rpc(HONEST_CHAIN).await;
    let pool = pool_over(&[a, b]);

    let err = source(&pool)
        .latest_block()
        .await
        .expect_err("the mock implements only eth_chainId");
    assert!(
        !matches!(err, IndexerError::ChainIdMismatch { .. }),
        "an all-honest pool must clear the chain-id gate; got {err:?}"
    );
}
