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

/// Verifying a CACHED endpoint is not evidence that it is healthy.
///
/// Once the provider cell is populated, `verified_provider` returns from cache without
/// touching the network. The verification sweep walks EVERY endpoint before every pooled
/// request, so treating that cached hit as a success promoted endpoints the request never
/// touched: `consecutive_errors` reset to zero on no evidence, which makes the Other-kind
/// circuit breaker unreachable, and `Degraded` flipped back to `Healthy`, so `/status`
/// reported a failing endpoint as good.
///
/// The observable has to be an endpoint the request does NOT select. `run_with_pool` marks
/// the selected endpoint itself, which overwrites the sweep's damage and hides it.
#[tokio::test]
async fn the_verification_sweep_does_not_promote_an_endpoint_the_request_never_touched() {
    use raven_railgun_indexer::rpc_pool::{EndpointHealth, ErrorKind, PooledRpcChainSource};
    use raven_railgun_indexer::ChainSource;

    // Two honest endpoints. Primary-with-failover always picks index 0, so index 1 is never
    // selected while index 0 works - it is the endpoint with no evidence about it.
    let (addr_a, _pa) = spawn_rpc(HONEST_CHAIN).await;
    let (addr_b, _pb) = spawn_rpc(HONEST_CHAIN).await;
    let pool = Arc::new(
        raven_railgun_indexer::rpc_pool::RpcEndpointPool::new(
            vec![
                raven_railgun_indexer::rpc_pool::EndpointConfig {
                    url: format!("http://{addr_a}"),
                    rps: 1000,
                    burst: 1000,
                },
                raven_railgun_indexer::rpc_pool::EndpointConfig {
                    url: format!("http://{addr_b}"),
                    rps: 1000,
                    burst: 1000,
                },
            ],
            raven_railgun_indexer::rpc_pool::PoolConfig {
                strategy: raven_railgun_indexer::rpc_pool::PoolStrategy::PrimaryWithFailover,
                ..raven_railgun_indexer::rpc_pool::PoolConfig::default()
            },
        )
        .expect("pool builds"),
    );

    let secondary = Arc::clone(&pool.endpoints()[1]);
    // Populate its provider cell so every later verification of it is a cached hit.
    secondary
        .verified_provider(HONEST_CHAIN)
        .await
        .expect("dial and verify the secondary");

    // A real call against the secondary failed at some point and degraded it.
    pool.mark_endpoint_error(&secondary, ErrorKind::Other);
    assert_eq!(
        secondary.health(),
        EndpointHealth::Degraded,
        "premise: one Other-kind error degrades without tripping the breaker"
    );

    // Drive a pooled request. It selects the PRIMARY, so nothing legitimate observes the
    // secondary - but the verification sweep still walks it.
    let source = PooledRpcChainSource::new(
        Arc::clone(&pool),
        alloy::primitives::address!("fa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"),
        HONEST_CHAIN,
    );
    let _ = source.latest_block().await;

    assert_eq!(
        secondary.health(),
        EndpointHealth::Degraded,
        "the sweep read the secondary from cache and learned nothing about it, so it must \
         not report it recovered"
    );
}

const ZERO32: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

/// A minimally-complete block, so `latest_block` DESERIALIZES rather than failing. That
/// matters here: a failing call retries onto the second endpoint and marks an error there,
/// which would be the request degrading the observable rather than the sweep.
fn block_at(number: u64) -> Value {
    json!({
        "hash": ZERO32,
        "parentHash": ZERO32,
        "sha3Uncles": ZERO32,
        "miner": "0x0000000000000000000000000000000000000000",
        "stateRoot": ZERO32,
        "transactionsRoot": ZERO32,
        "receiptsRoot": ZERO32,
        "logsBloom": format!("0x{}", "0".repeat(512)),
        "difficulty": "0x0",
        "number": format!("0x{number:x}"),
        "gasLimit": "0x1c9c380",
        "gasUsed": "0x0",
        "timestamp": "0x65000000",
        "extraData": "0x",
        "mixHash": ZERO32,
        "nonce": "0x0000000000000000",
        "baseFeePerGas": "0x7",
        "size": "0x220",
        "transactions": [],
        "uncles": []
    })
}

/// An honest endpoint that also answers `eth_getBlockByNumber`, so a pooled `latest_block`
/// SUCCEEDS on it.
async fn spawn_block_rpc(reported_chain_id: u64) -> SocketAddr {
    let app = Router::new().route(
        "/",
        post(move |Json(req): Json<Value>| async move {
            let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
            let id = req.get("id").cloned().unwrap_or(Value::Null);
            let result = match method {
                "eth_chainId" => json!(format!("0x{reported_chain_id:x}")),
                "eth_getBlockByNumber" => block_at(0x2710),
                _ => json!("0x2710"),
            };
            (
                StatusCode::OK,
                Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })),
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

/// The circuit breaker must survive a pooled request landing between two errors.
///
/// This is the HEADLINE of the defect the test above covers, and a strictly stronger
/// property. That one asserts the `/status` symptom - a `Degraded` endpoint not reported
/// `Healthy`. This asserts the consequence that costs an operator money:
/// `mark_endpoint_success` sets `consecutive_errors = 0`, the sweep runs before EVERY
/// pooled request, and one call contributes at most `MAX_RETRY_FACTOR` errors per endpoint -
/// so a sweep that attributes health to a cached endpoint makes the Other-kind threshold
/// unreachable however often that endpoint fails. A dead endpoint is then never cooled
/// down: it stays in rotation and is retried forever instead of being failed over.
///
/// Errors are marked directly rather than provoked: what is under test is whether the count
/// SURVIVES an intervening request, not how an error is classified. The intervening request is
/// the load-bearing part - without one between the marks, nothing here can observe the sweep.
#[tokio::test]
async fn a_pooled_request_between_errors_does_not_reset_the_circuit_breaker() {
    use raven_railgun_indexer::rpc_pool::{EndpointHealth, ErrorKind, PooledRpcChainSource};
    use raven_railgun_indexer::ChainSource;

    const THRESHOLD: u32 = 3;

    let addr_a = spawn_block_rpc(HONEST_CHAIN).await;
    let addr_b = spawn_block_rpc(HONEST_CHAIN).await;
    let pool = Arc::new(
        RpcEndpointPool::new(
            vec![
                EndpointConfig {
                    url: format!("http://{addr_a}"),
                    rps: 1000,
                    burst: 1000,
                },
                EndpointConfig {
                    url: format!("http://{addr_b}"),
                    rps: 1000,
                    burst: 1000,
                },
            ],
            PoolConfig {
                strategy: PoolStrategy::PrimaryWithFailover,
                circuit_breaker_threshold: THRESHOLD,
                ..PoolConfig::default()
            },
        )
        .expect("pool builds"),
    );

    let secondary = Arc::clone(&pool.endpoints()[1]);
    // Populate the cell so every later sweep of it is a cached hit, which is the exact
    // condition under which the sweep has no evidence to attribute.
    secondary
        .verified_provider(HONEST_CHAIN)
        .await
        .expect("dial and verify the secondary");

    let source = PooledRpcChainSource::new(
        Arc::clone(&pool),
        alloy::primitives::address!("fa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"),
        HONEST_CHAIN,
    );

    for i in 1..=THRESHOLD {
        pool.mark_endpoint_error(&secondary, ErrorKind::Other);
        // Must SUCCEED, and on the primary: a failure would retry onto the secondary and
        // mark it, making the request rather than the sweep the thing under test.
        source
            .latest_block()
            .await
            .expect("the primary answers, so the pooled call never reaches the secondary");
        if i < THRESHOLD {
            assert_eq!(
                secondary.health(),
                EndpointHealth::Degraded,
                "below the threshold the endpoint degrades but must not trip yet (error {i})"
            );
        }
    }

    assert!(
        matches!(secondary.health(), EndpointHealth::CoolingDown { .. }),
        "after {THRESHOLD} Other-kind errors the breaker must trip even though a pooled \
         request ran between each of them; got {:?}. A sweep that attributes health to a \
         cached endpoint resets the count and makes this threshold unreachable, so a dead \
         endpoint is retried forever instead of cooled down",
        secondary.health()
    );
}
