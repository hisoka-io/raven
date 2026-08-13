//! A gateway that accepts the connection and never answers must fail, not hang.
//!
//! Before this, neither `PooledRpcChainSource` nor `WsChainSource` had any timeout, and
//! alloy's `connect_http` builds a reqwest client with no default. The tick awaited
//! forever, so `send_heartbeat` was never reached again - and because
//! `ConsumerEvent::Heartbeat` is the ONLY writer of `indexer_lag_blocks`, the gauge FROZE
//! at its last healthy value instead of growing. Ingestion dead, every operator signal
//! green, readiness 200.
//!
//! Every one of the six `ChainSource` methods is exercised, because the WS impl has no
//! single chokepoint: its timeout is applied per method, and a guard applied per method is
//! one rename away from covering five of six.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::primitives::address;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use raven_railgun_indexer::rpc_pool::{
    EndpointConfig, PoolConfig, PoolStrategy, PooledRpcChainSource, RpcEndpointPool,
};
use raven_railgun_indexer::{ChainSource, RPC_TIMEOUT_SECS};
use serde_json::{json, Value};
use tokio::sync::oneshot;

/// Accepts TCP, reads nothing, answers nothing, and holds the socket open.
async fn spawn_black_hole() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = tx.send(());
        let mut held = Vec::new();
        loop {
            match listener.accept().await {
                Ok((sock, _)) => held.push(sock), // never read, never write, never close
                Err(_) => return,
            }
        }
    });
    rx.await.expect("ready");
    addr
}

fn pooled(addr: std::net::SocketAddr) -> PooledRpcChainSource {
    let pool = Arc::new(
        RpcEndpointPool::new(
            vec![EndpointConfig {
                url: format!("http://{addr}"),
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
    PooledRpcChainSource::new(
        pool,
        address!("fa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"),
        1,
    )
}

/// Generous ceiling: the point is that it RETURNS, not that it returns fast. A pooled call
/// retries across the pool, so allow several attempt budgets.
fn ceiling() -> Duration {
    Duration::from_secs(RPC_TIMEOUT_SECS * 12 + 20)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pooled_call_against_a_black_hole_returns_an_error() {
    let addr = spawn_black_hole().await;
    let src = pooled(addr);
    let started = Instant::now();
    let out = tokio::time::timeout(ceiling(), src.latest_block()).await;
    let elapsed = started.elapsed();
    let inner = out.unwrap_or_else(|_| {
        panic!("latest_block never returned within {elapsed:?}; the hang is unfixed")
    });
    let err = inner.expect_err("a black-holing endpoint cannot produce a block number");
    assert!(
        format!("{err}").to_lowercase().contains("timeout"),
        "the error must say timeout so classify_indexer_error routes it to Network and the \
         pool cools the endpoint down; got: {err}"
    );
}

/// Every ChainSource method, not just the one that is easy to call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_pooled_chain_source_method_fails_closed_against_a_black_hole() {
    let addr = spawn_black_hole().await;
    let src = pooled(addr);
    let c = ceiling();

    macro_rules! must_return {
        ($label:literal, $call:expr) => {{
            let started = Instant::now();
            let outcome = tokio::time::timeout(c, $call).await;
            assert!(
                outcome.is_ok(),
                concat!(
                    $label,
                    " never returned within the ceiling ({:?}); it hangs"
                ),
                started.elapsed()
            );
            assert!(
                outcome.expect("returned").is_err(),
                concat!($label, " must be an error against a black hole")
            );
        }};
    }

    must_return!("latest_block", src.latest_block());
    must_return!("events_in_range", src.events_in_range(1, 2));
    must_return!("block_hash", src.block_hash(1));
    must_return!("merkle_root", src.merkle_root(None));
    must_return!("active_tree_number", src.active_tree_number(None));
    must_return!("root_history", src.root_history(0, [0u8; 32], None));
}

/// Answers `eth_chainId` honestly, then never replies to anything else.
///
/// This is the DISCRIMINATING fixture. A pure black hole hangs at the chain-id probe, so it
/// exercises only that timeout - removing the `run_with_pool` bound still passes against it.
/// Getting past verification is what puts the pooled op under test.
async fn spawn_chain_id_then_black_hole() -> std::net::SocketAddr {
    let app = Router::new().route(
        "/",
        post(|Json(req): Json<Value>| async move {
            let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
            let id = req.get("id").cloned().unwrap_or(Value::Null);
            if method == "eth_chainId" {
                return (
                    StatusCode::OK,
                    Json(json!({"jsonrpc": "2.0", "id": id, "result": "0x1"})),
                );
            }
            // Never resolves: the connection stays open with no reply.
            std::future::pending::<()>().await;
            unreachable!("pending never completes")
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

/// The pooled-op chokepoint, isolated: chain-id verification succeeds, then the call hangs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pooled_op_that_hangs_after_chain_id_verification_still_fails_closed() {
    let addr = spawn_chain_id_then_black_hole().await;
    let src = pooled(addr);
    let started = Instant::now();
    let out = tokio::time::timeout(ceiling(), src.latest_block()).await;
    let elapsed = started.elapsed();
    let inner = out.unwrap_or_else(|_| {
        panic!(
            "latest_block hung for {elapsed:?} AFTER chain-id verification passed; the \
             run_with_pool attempt is unbounded"
        )
    });
    let err = inner.expect_err("a black-holed op cannot produce a block number");
    assert!(
        format!("{err}").to_lowercase().contains("timeout"),
        "got: {err}"
    );
}
