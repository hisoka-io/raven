//! Regression: `RpcChainSource` must surface `ChainIdMismatch` when the RPC's
//! `eth_chainId` differs from the configured value, not silently index foreign-chain commits.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::SocketAddr;

use alloy::primitives::address;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use raven_railgun_indexer::{ChainSource, IndexerError, RpcChainSource};
use serde_json::{json, Value};
use tokio::sync::oneshot;

async fn spawn_mock_rpc(reported_chain_id: u64) -> SocketAddr {
    let app = Router::new().route(
        "/",
        post(move |Json(req): Json<Value>| async move {
            let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
            let id = req.get("id").cloned().unwrap_or(Value::Null);
            if method == "eth_chainId" {
                (
                    StatusCode::OK,
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": format!("0x{:x}", reported_chain_id),
                    })),
                )
            } else {
                (
                    StatusCode::OK,
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32601,
                            "message": format!("mock rejects method {method}; only eth_chainId implemented"),
                        }
                    })),
                )
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock RPC");
    let addr = listener.local_addr().expect("local addr");
    let (ready_tx, ready_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = ready_tx.send(());
        let _ = axum::serve(listener, app).await;
    });
    ready_rx.await.expect("mock ready");
    addr
}

#[tokio::test]
async fn rpc_chain_source_surfaces_chain_id_mismatch_on_first_use() {
    let addr = spawn_mock_rpc(11_155_111).await;
    let url = format!("http://{addr}");
    let proxy = address!("fa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9");
    let source = RpcChainSource::new(url, proxy, 18_514_200, 1);

    let err = source
        .latest_block()
        .await
        .expect_err("chain id mismatch must surface as Err");

    match err {
        IndexerError::ChainIdMismatch { expected, actual } => {
            assert_eq!(expected, 1, "expected chain id");
            assert_eq!(actual, 11_155_111, "actual chain id from mock");
        }
        other => panic!("expected ChainIdMismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn rpc_chain_source_passes_chain_id_check_when_match() {
    let addr = spawn_mock_rpc(1).await;
    let url = format!("http://{addr}");
    let proxy = address!("fa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9");
    let source = RpcChainSource::new(url, proxy, 18_514_200, 1);

    let err = source
        .latest_block()
        .await
        .expect_err("mock rejects eth_getBlockByNumber");
    assert!(
        !matches!(err, IndexerError::ChainIdMismatch { .. }),
        "chain id check must pass; got ChainIdMismatch unexpectedly: {err:?}"
    );
}
