//! Reaching an endpoint outside `PooledRpcChainSource` must not reach an unverified one.
//!
//! `verify_chain_id_once` lives on `PooledRpcChainSource`; `pinned_session` lives on
//! `RpcEndpointPool`. Anything holding the pool directly therefore bypassed verification
//! by construction, and one production caller did: the Chainalysis oracle pinned a session
//! and ran `eth_getLogs` on it with no chain check ever. A foreign chain answers that with
//! `Ok(vec![])`, which is indistinguishable from an empty range.
//!
//! Nothing in this repo asserted the negative before this file: `is_chain_id_verified` had
//! exactly one reader, inside `rpc_pool.rs`, and appeared in no test.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use raven_railgun_indexer::rpc_pool::{EndpointConfig, PoolConfig, PoolStrategy, RpcEndpointPool};
use raven_railgun_indexer::IndexerError;
use serde_json::{json, Value};
use tokio::sync::oneshot;

const HONEST_CHAIN: u64 = 1;
const FOREIGN_CHAIN: u64 = 11_155_111;

/// A server whose reported chain id can change, so a repointed endpoint is expressible.
async fn spawn_switchable(initial: u64) -> (SocketAddr, Arc<std::sync::atomic::AtomicU64>) {
    let chain = Arc::new(std::sync::atomic::AtomicU64::new(initial));
    let reported = Arc::clone(&chain);
    let app = Router::new().route(
        "/",
        post(move |Json(req): Json<Value>| {
            let reported = Arc::clone(&reported);
            async move {
                let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
                let id = req.get("id").cloned().unwrap_or(Value::Null);
                if method == "eth_chainId" {
                    let c = reported.load(Ordering::SeqCst);
                    return (
                        StatusCode::OK,
                        Json(json!({
                            "jsonrpc": "2.0", "id": id, "result": format!("0x{c:x}")
                        })),
                    );
                }
                (
                    StatusCode::OK,
                    Json(json!({ "jsonrpc": "2.0", "id": id, "result": "0x2710" })),
                )
            }
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
    (addr, chain)
}

/// Counts `eth_chainId` so a per-request probe is distinguishable from a per-connection one.
async fn spawn_rpc(reported_chain_id: u64) -> (SocketAddr, Arc<AtomicUsize>) {
    let probes = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&probes);
    let app = Router::new().route(
        "/",
        post(move |Json(req): Json<Value>| {
            let counter = Arc::clone(&counter);
            async move {
                let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
                let id = req.get("id").cloned().unwrap_or(Value::Null);
                let result = match method {
                    "eth_chainId" => {
                        counter.fetch_add(1, Ordering::SeqCst);
                        json!(format!("0x{reported_chain_id:x}"))
                    }
                    "eth_blockNumber" => json!("0x2710"),
                    _ => {
                        return (
                            StatusCode::OK,
                            Json(json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "error": { "code": -32601, "message": "unsupported in fixture" }
                            })),
                        );
                    }
                };
                (
                    StatusCode::OK,
                    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })),
                )
            }
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
    (addr, probes)
}

fn pool_over(addrs: &[SocketAddr]) -> Arc<RpcEndpointPool> {
    let cfgs = addrs
        .iter()
        .map(|a| EndpointConfig {
            url: format!("http://{a}"),
            rps: 1000,
            burst: 1000,
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

/// The bypass, closed at the leaf: a pinned session hands back an endpoint, and the only
/// route from that endpoint to a provider refuses a foreign chain.
#[tokio::test]
async fn a_pinned_session_cannot_reach_a_foreign_endpoints_provider() {
    let (addr, _probes) = spawn_rpc(FOREIGN_CHAIN).await;
    let pool = pool_over(&[addr]);

    let session = pool.pinned_session().expect("pin");
    let Err(err) = session.endpoint().verified_provider(HONEST_CHAIN).await else {
        panic!("a foreign endpoint must not yield a provider")
    };

    match err {
        IndexerError::ChainIdMismatch { expected, actual } => {
            assert_eq!(expected, HONEST_CHAIN);
            assert_eq!(actual, FOREIGN_CHAIN);
        }
        other => panic!("expected ChainIdMismatch, got {other:?}"),
    }
}

/// And the honest case still yields a usable provider, so the refusal is not blanket.
#[tokio::test]
async fn a_pinned_session_reaches_an_honest_endpoints_provider() {
    let (addr, probes) = spawn_rpc(HONEST_CHAIN).await;
    let pool = pool_over(&[addr]);

    let session = pool.pinned_session().expect("pin");
    let provider = session
        .endpoint()
        .verified_provider(HONEST_CHAIN)
        .await
        .expect("an honest endpoint must yield a provider");
    let block = alloy::providers::Provider::get_block_number(provider)
        .await
        .expect("the verified provider is usable");
    assert_eq!(block, 0x2710);
    assert_eq!(
        probes.load(Ordering::SeqCst),
        1,
        "verification belongs to the connection, so it happens once"
    );
}

/// Verification is bound to the connection, not to the call. A per-request probe would
/// both cost a round trip per call and reopen the window a lease was meant to close.
#[tokio::test]
async fn the_chain_id_is_probed_once_per_endpoint_not_once_per_request() {
    let (addr, probes) = spawn_rpc(HONEST_CHAIN).await;
    let pool = pool_over(&[addr]);
    let endpoint = Arc::clone(&pool.endpoints()[0]);

    for _ in 0..25 {
        endpoint
            .verified_provider(HONEST_CHAIN)
            .await
            .expect("verified");
    }

    assert_eq!(
        probes.load(Ordering::SeqCst),
        1,
        "25 acquisitions must cost exactly one eth_chainId"
    );
}

/// A handle verified for one chain must never be handed back for another. Without this,
/// a second caller expecting a different chain would silently reuse the cached provider.
#[tokio::test]
async fn a_handle_verified_for_one_chain_is_refused_for_another() {
    let (addr, probes) = spawn_rpc(HONEST_CHAIN).await;
    let pool = pool_over(&[addr]);
    let endpoint = Arc::clone(&pool.endpoints()[0]);

    endpoint
        .verified_provider(HONEST_CHAIN)
        .await
        .expect("first acquisition verifies");

    let Err(err) = endpoint.verified_provider(137).await else {
        panic!("the cached handle must not satisfy a different chain")
    };
    assert!(
        matches!(err, IndexerError::ChainIdMismatch { .. }),
        "expected ChainIdMismatch, got {err:?}"
    );
    assert_eq!(
        probes.load(Ordering::SeqCst),
        1,
        "and it must be refused from the cached identity, without a second probe"
    );
}

/// A refusal must not be cached. Storing the foreign identity in the cell would refuse
/// from cache forever, so an endpoint the operator repoints back onto the right chain
/// could never recover without a restart. Refusing inside the constructor leaves the cell
/// empty, which is what makes the next call re-dial and re-probe.
#[tokio::test]
async fn a_refused_endpoint_re_probes_and_recovers_when_it_is_repointed() {
    let (addr, reported_chain) = spawn_switchable(FOREIGN_CHAIN).await;
    let pool = pool_over(&[addr]);
    let endpoint = Arc::clone(&pool.endpoints()[0]);

    let Err(err) = endpoint.verified_provider(HONEST_CHAIN).await else {
        panic!("a foreign endpoint must be refused")
    };
    assert!(
        matches!(err, IndexerError::ChainIdMismatch { .. }),
        "expected ChainIdMismatch, got {err:?}"
    );

    // The operator repoints the URL back onto the configured chain.
    reported_chain.store(HONEST_CHAIN, Ordering::SeqCst);

    let provider = endpoint
        .verified_provider(HONEST_CHAIN)
        .await
        .expect("a repointed endpoint must be usable again without a restart");
    let block = alloy::providers::Provider::get_block_number(provider)
        .await
        .expect("usable");
    assert_eq!(block, 0x2710);
}
