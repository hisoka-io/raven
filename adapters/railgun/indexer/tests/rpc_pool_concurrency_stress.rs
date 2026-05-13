//! Concurrency stress on `RpcEndpointPool` under 100 simultaneous selectors.
//!
//! Round-robin fairness, token-bucket exhaustion, and circuit-breaker trip + recovery.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use raven_railgun_indexer::rpc_pool::{
    EndpointConfig, EndpointHealth, ErrorKind, PoolConfig, PoolError, PoolStrategy, RpcEndpointPool,
};

const N_ENDPOINTS: usize = 4;
const N_TASKS: usize = 100;
const CALLS_PER_TASK: usize = 25;

fn build_balanced_pool() -> Arc<RpcEndpointPool> {
    let cfgs: Vec<_> = (0..N_ENDPOINTS)
        .map(|i| EndpointConfig {
            url: format!("http://endpoint-{i}.test/"),
            rps: 10_000,
            burst: 10_000,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn round_robin_distribution_stays_balanced_under_100_concurrent_selectors() {
    let pool = build_balanced_pool();
    // Index → AtomicU32 selection count. Reuses indexer-side helper:
    // identify the picked endpoint by `Arc::ptr_eq` against
    // `pool.endpoints()`.
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

    // ±25% window: the Relaxed cursor is racy under task interleaving so tighter
    // bounds cannot be guaranteed without a barrier-locked cursor.
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
    // burst=5 ⇒ first 5 accepted; rest must be Exhausted (test window << 1s replenishment).
    assert!(
        (5..=6).contains(&accepted),
        "burst=5 must accept exactly 5 (allow ±1 for token-bucket clock granularity); accepted={accepted}, refused={refused}"
    );
    assert!(
        refused >= 40,
        "post-burst calls must surface Exhausted; refused={refused}, accepted={accepted}"
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
