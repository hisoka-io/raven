//! Extended concurrency stress on `RpcEndpointPool` (1000 tasks, 5 endpoints).
//!
//! Scales up `rpc_pool_concurrency_stress.rs` to cover concurrent token-bucket
//! saturation and circuit-breaker trips under multi-task contention.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss
)]

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use raven_railgun_indexer::rpc_pool::{
    EndpointConfig, EndpointHealth, ErrorKind, PoolConfig, PoolError, PoolStrategy, RpcEndpointPool,
};

const N_ENDPOINTS: usize = 5;
const N_TASKS: usize = 1_000;
const CALLS_PER_TASK: usize = 10;

fn build_high_throughput_pool() -> Arc<RpcEndpointPool> {
    let cfgs: Vec<_> = (0..N_ENDPOINTS)
        .map(|i| EndpointConfig {
            url: format!("http://endpoint-{i}.test/"),
            rps: 100_000,
            burst: 100_000,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn round_robin_distributes_across_5_endpoints_under_1000_concurrent_tasks() {
    let pool = build_high_throughput_pool();
    let counts: Arc<Vec<AtomicU32>> =
        Arc::new((0..N_ENDPOINTS).map(|_| AtomicU32::new(0)).collect());

    let mut handles = Vec::with_capacity(N_TASKS);
    for _ in 0..N_TASKS {
        let pool = Arc::clone(&pool);
        let counts = Arc::clone(&counts);
        handles.push(tokio::spawn(async move {
            for _ in 0..CALLS_PER_TASK {
                let endpoint = pool.select_for_request().expect("select");
                let mut matched = false;
                for (i, e) in pool.endpoints().iter().enumerate() {
                    if Arc::ptr_eq(e, &endpoint) {
                        counts
                            .get(i)
                            .expect("count slot")
                            .fetch_add(1, Ordering::SeqCst);
                        matched = true;
                        break;
                    }
                }
                pool.release_in_flight(&endpoint);
                assert!(matched, "endpoint pointer must match a pool slot");
            }
        }));
    }
    for h in handles {
        h.await.expect("task joined");
    }

    let totals: Vec<u32> = counts.iter().map(|c| c.load(Ordering::SeqCst)).collect();
    let total: u32 = totals.iter().sum();
    assert_eq!(
        total as usize,
        N_TASKS * CALLS_PER_TASK,
        "every selection must land in exactly one endpoint slot"
    );

    // ±25% window; Relaxed cursor produces small deviations under task interleave.
    let expected_per = (N_TASKS * CALLS_PER_TASK) as u32 / N_ENDPOINTS as u32;
    let lower = expected_per - expected_per / 4;
    let upper = expected_per + expected_per / 4;
    for (i, c) in totals.iter().enumerate() {
        assert!(
            *c >= lower && *c <= upper,
            "endpoint {i} got {c} selections, outside [{lower}, {upper}] balanced window; totals={totals:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn token_bucket_blocks_under_1000_concurrent_saturation_attempts() {
    let cfgs = vec![EndpointConfig {
        url: "http://saturate.test/".to_owned(),
        rps: 10,
        burst: 10,
    }];
    let pool = Arc::new(RpcEndpointPool::new(cfgs, PoolConfig::default()).expect("pool"));

    let accepted = Arc::new(AtomicU64::new(0));
    let refused = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::with_capacity(N_TASKS);
    for _ in 0..N_TASKS {
        let pool = Arc::clone(&pool);
        let accepted = Arc::clone(&accepted);
        let refused = Arc::clone(&refused);
        handles.push(tokio::spawn(async move {
            match pool.select_for_request() {
                Ok(endpoint) => {
                    accepted.fetch_add(1, Ordering::Relaxed);
                    pool.release_in_flight(&endpoint);
                }
                Err(PoolError::Exhausted) => {
                    refused.fetch_add(1, Ordering::Relaxed);
                }
                Err(other) => panic!("unexpected pool error: {other:?}"),
            }
        }));
    }
    for h in handles {
        h.await.expect("task joined");
    }

    let acc = accepted.load(Ordering::Relaxed);
    let ref_ = refused.load(Ordering::Relaxed);
    assert_eq!(
        acc + ref_,
        N_TASKS as u64,
        "every task must either accept or refuse (no panics, no drops)"
    );
    // burst=10; tolerance up to ~30 for refill tokens during the test window.
    assert!(
        acc <= 30,
        "burst=10 / rps=10 must NOT accept >30 calls under 1000 concurrent saturation; \
         accepted={acc}, refused={ref_}. A regression that bypasses governor::check() \
         would surface here as accepted >> burst."
    );
    assert!(
        ref_ >= u64::from(N_TASKS as u32 - 30),
        "the bulk of saturation calls MUST surface Exhausted; refused={ref_}, accepted={acc}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn circuit_breaker_trips_under_concurrent_errors_then_recovers_after_cooldown() {
    let cfgs = vec![EndpointConfig {
        url: "http://breaker.test/".to_owned(),
        rps: 100_000,
        burst: 100_000,
    }];
    let pool = Arc::new(
        RpcEndpointPool::new(
            cfgs,
            PoolConfig {
                strategy: PoolStrategy::RoundRobin,
                cooldown_secs_on_error: 1,
                circuit_breaker_threshold: 5,
            },
        )
        .expect("pool"),
    );

    let endpoint = pool.endpoints().first().expect("endpoint").clone();

    let mut handles = Vec::with_capacity(N_TASKS);
    for i in 0..N_TASKS {
        let pool = Arc::clone(&pool);
        let endpoint = Arc::clone(&endpoint);
        handles.push(tokio::spawn(async move {
            let kind = match i % 4 {
                0 => ErrorKind::RateLimited,
                1 => ErrorKind::ServerError,
                2 => ErrorKind::Network,
                _ => ErrorKind::Other,
            };
            pool.mark_endpoint_error(&endpoint, kind);
        }));
    }
    for h in handles {
        h.await.expect("task joined");
    }

    let snapshot = pool.health_snapshot();
    let h0 = snapshot.first().expect("snapshot").health;
    assert!(
        matches!(h0, EndpointHealth::CoolingDown { .. }),
        "endpoint must be CoolingDown after concurrent error storm; got {h0:?}"
    );

    let res = pool.select_for_request();
    assert!(
        matches!(res, Err(PoolError::Exhausted)),
        "selection must refuse single endpoint in CoolingDown; got {res:?}"
    );

    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let endpoint = pool.select_for_request().expect("post-cooldown select");
    pool.release_in_flight(&endpoint);
    pool.mark_endpoint_success(&endpoint);

    let snapshot_after = pool.health_snapshot();
    let h_after = snapshot_after.first().expect("snapshot").health;
    assert!(
        matches!(h_after, EndpointHealth::Healthy),
        "after cooldown elapses + a successful call, endpoint must be Healthy; got {h_after:?}"
    );
}
