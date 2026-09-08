//! Concurrency stress on `RpcEndpointPool`.
//!
//! Round-robin fairness under 1000 concurrent selectors, token-bucket
//! exhaustion (tight-loop and concurrent saturation), and circuit-breaker
//! trip + recovery (sequential threshold walk and concurrent error storm).
//!
//! Merged from the former `rpc_pool_concurrency_stress_extended.rs`; the
//! 100-task/4-endpoint round-robin variant was dropped after a
//! pinned-selection mutation reddened both it and the 1000-task test.

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

    // +/-25% window; Relaxed cursor produces small deviations under task interleave.
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

#[test]
fn token_bucket_drains_under_tight_loop_and_surfaces_exhausted() {
    let cfgs = vec![EndpointConfig {
        url: "http://endpoint-only.test/".to_owned(),
        rps: 10,
        burst: 5,
    }];
    let pool = RpcEndpointPool::new(cfgs, PoolConfig::default()).expect("pool builds");

    let mut accepted = 0u32;
    let mut refused = 0u32;
    for _ in 0..50 {
        match pool.select_for_request() {
            Ok(endpoint) => {
                accepted += 1;
                pool.release_in_flight(&endpoint);
            }
            Err(PoolError::Exhausted) => refused += 1,
            Err(other) => panic!("unexpected pool error: {other:?}"),
        }
    }
    // burst=5 => first 5 accepted; rest must be Exhausted (test window << 1s replenishment).
    assert!(
        (5..=6).contains(&accepted),
        "burst=5 must accept exactly 5 (allow ±1 for token-bucket clock granularity); accepted={accepted}, refused={refused}"
    );
    assert!(
        refused >= 40,
        "post-burst calls must surface Exhausted; refused={refused}, accepted={accepted}"
    );
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

#[test]
fn circuit_breaker_trips_after_threshold_other_errors_then_recovers() {
    let cfgs = vec![
        EndpointConfig {
            url: "http://endpoint-0.test/".to_owned(),
            rps: 1_000,
            burst: 1_000,
        },
        EndpointConfig {
            url: "http://endpoint-1.test/".to_owned(),
            rps: 1_000,
            burst: 1_000,
        },
    ];
    let pool = RpcEndpointPool::new(
        cfgs,
        PoolConfig {
            strategy: PoolStrategy::PrimaryWithFailover,
            cooldown_secs_on_error: 1,
            circuit_breaker_threshold: 3,
        },
    )
    .expect("pool builds");

    let endpoint_0 = pool.endpoints().first().expect("endpoint 0").clone();

    let pick = pool.select_for_request().expect("first select");
    assert!(
        Arc::ptr_eq(&pick, &endpoint_0),
        "PrimaryWithFailover must prefer index 0 before any errors"
    );
    pool.release_in_flight(&pick);

    pool.mark_endpoint_error(&endpoint_0, ErrorKind::Other);
    pool.mark_endpoint_error(&endpoint_0, ErrorKind::Other);
    let snapshot_before_trip = pool.health_snapshot();
    let h0 = snapshot_before_trip.first().expect("e0 snapshot").health;
    assert!(
        matches!(h0, EndpointHealth::Degraded),
        "endpoint 0 must be Degraded before threshold; got {h0:?}"
    );

    pool.mark_endpoint_error(&endpoint_0, ErrorKind::Other);
    let snapshot_after_trip = pool.health_snapshot();
    let h0 = snapshot_after_trip.first().expect("e0 snapshot").health;
    assert!(
        matches!(h0, EndpointHealth::CoolingDown { .. }),
        "endpoint 0 must be CoolingDown after threshold; got {h0:?}"
    );

    let endpoint_1 = pool.endpoints().get(1).expect("endpoint 1").clone();
    let pick = pool.select_for_request().expect("post-trip select");
    assert!(
        Arc::ptr_eq(&pick, &endpoint_1),
        "selector must skip CoolingDown endpoint 0 and pick endpoint 1"
    );
    pool.release_in_flight(&pick);

    std::thread::sleep(Duration::from_millis(1_200));
    let pick = pool.select_for_request().expect("post-cooldown select");
    assert!(
        Arc::ptr_eq(&pick, &endpoint_0),
        "after cooldown elapses, PrimaryWithFailover must re-prefer endpoint 0"
    );
    pool.release_in_flight(&pick);
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
