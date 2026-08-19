//! The Chainalysis walk must attribute the health of the endpoint it pinned.
//!
//! It is the one non-test path in the repo that reaches an `RpcEndpointPool` provider and
//! drives raw RPC calls itself instead of going through `run_with_pool` / `run_pinned`,
//! which are what the pool documents as the paths that mark both outcomes. A full walk is
//! ~1.5k `eth_getLogs` round trips; unattributed failures teach the pool nothing, so the next
//! consumer of the same process-local pool picks the same dead endpoint.
//!
//! ERRORS ONLY, with a test below for the other half: a cached `verified_provider` hit
//! observes no network at all, so attributing health to it makes the breaker unreachable.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use raven_railgun_cli::bootstrap_chainalysis::ChainalysisOnChainOracleSource;
use raven_railgun_cli::bootstrap_subsquid::PpoiEventsSource;
use raven_railgun_indexer::rpc_pool::{
    EndpointConfig, EndpointHealth, ErrorKind, PoolConfig, PoolStrategy, RpcEndpointPool,
};
use serde_json::{json, Value};

const CHAIN: u64 = 1;
const LIST_KEY: [u8; 32] = [0x11; 32];

/// Answers `eth_chainId` honestly so verification passes, then refuses `eth_getLogs`. That
/// ordering is the point: an endpoint that fails verification never reaches the walk.
async fn spawn_logs_refuser() -> SocketAddr {
    let app = Router::new().route(
        "/",
        post(|Json(req): Json<Value>| async move {
            let method = req.get("method").and_then(Value::as_str).unwrap_or("");
            let id = req.get("id").cloned().unwrap_or(Value::Null);
            if method == "eth_chainId" {
                return (
                    StatusCode::OK,
                    Json(json!({"jsonrpc":"2.0","id":id,"result":format!("0x{CHAIN:x}")})),
                );
            }
            (
                StatusCode::OK,
                Json(json!({
                    "jsonrpc":"2.0","id":id,
                    "error":{"code":-32000,"message":"log query refused"}
                })),
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

/// Answers `eth_chainId` AND returns an empty log set successfully, so the walk completes
/// without any failure of its own. That isolation is what makes the promotion test below
/// discriminating: any later error mark would overwrite the observable.
async fn spawn_empty_logs_ok() -> SocketAddr {
    let app = Router::new().route(
        "/",
        post(|Json(req): Json<Value>| async move {
            let method = req.get("method").and_then(Value::as_str).unwrap_or("");
            let id = req.get("id").cloned().unwrap_or(Value::Null);
            let result = if method == "eth_chainId" {
                json!(format!("0x{CHAIN:x}"))
            } else {
                json!([])
            };
            (
                StatusCode::OK,
                Json(json!({"jsonrpc":"2.0","id":id,"result":result})),
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

fn pool_over(addr: SocketAddr) -> Arc<RpcEndpointPool> {
    Arc::new(
        RpcEndpointPool::new(
            vec![EndpointConfig {
                url: format!("http://{addr}"),
                rps: 1000,
                burst: 1000,
            }],
            PoolConfig {
                strategy: PoolStrategy::PrimaryWithFailover,
                ..PoolConfig::default()
            },
        )
        .expect("pool builds"),
    )
}

#[tokio::test]
async fn a_failed_log_walk_marks_the_endpoint_it_pinned() {
    let addr = spawn_logs_refuser().await;
    let pool = pool_over(addr);

    let source = ChainalysisOnChainOracleSource::new_live(
        Arc::clone(&pool),
        CHAIN,
        alloy::primitives::address!("40c57923924b5c5c5455c48d93317139addac8fb"),
        100,
        // Pinned end, so the walk goes straight to eth_getLogs without a head probe.
        Some(200),
    );

    let err = source
        .fetch_all_events(LIST_KEY)
        .await
        .expect_err("the endpoint refuses eth_getLogs, so the walk must fail");
    assert!(
        format!("{err:?}").contains("getLogs") || format!("{err:?}").contains("Unreachable"),
        "premise: the failure is the log walk, got {err:?}"
    );

    assert_eq!(
        pool.endpoints()[0].health(),
        EndpointHealth::Degraded,
        "a completed round trip that FAILED is evidence about this endpoint. Asserted as the \
         exact state, not merely not-Healthy: a complement also passes if the kind changes or \
         the breaker arithmetic moves, and one Other-kind error degrades without tripping"
    );
}

/// The other half, and the one that must not regress: a cached `verified_provider` hit is
/// not evidence, so nothing on this path may promote a degraded endpoint back to Healthy.
///
/// The walk must SUCCEED here: a failing one overwrites the observable with its own error
/// mark, so the assertion would hold for the wrong reason.
///
/// This does pin current policy: a SUCCESSFUL walk does not mark success either, because
/// whether a completed `eth_getLogs` should promote a shared pool endpoint is an owner
/// decision that has not been taken. If it is taken, this test is where it surfaces.
#[tokio::test]
async fn the_walk_never_promotes_a_degraded_endpoint() {
    let addr = spawn_empty_logs_ok().await;
    let pool = pool_over(addr);

    // Populate the cell, so the walk's `verified_provider` call is a pure cache hit.
    pool.endpoints()[0]
        .verified_provider(CHAIN)
        .await
        .expect("dial and verify");
    pool.mark_endpoint_error(&pool.endpoints()[0], ErrorKind::Other);
    assert_eq!(
        pool.endpoints()[0].health(),
        EndpointHealth::Degraded,
        "premise: one Other-kind error degrades without tripping the breaker"
    );

    let source = ChainalysisOnChainOracleSource::new_live(
        Arc::clone(&pool),
        CHAIN,
        alloy::primitives::address!("40c57923924b5c5c5455c48d93317139addac8fb"),
        100,
        Some(200),
    );
    source
        .fetch_all_events(LIST_KEY)
        .await
        .expect("the walk completes: an empty sanctioned set is a legitimate result");

    assert_eq!(
        pool.endpoints()[0].health(),
        EndpointHealth::Degraded,
        "nothing on this path observed evidence that promotes: the provider came from a \
         populated cell that touched no network. Reporting recovery here is what made the \
         circuit breaker unreachable before"
    );
}
