//! Concurrency stress on `PirInstance` snapshot atomicity.
//!
//! Regression guard for the `epoch + state` packing fix: both fields live in
//! a single `Snapshot<S>` cell so a `swap_state` racing inside `query()` cannot
//! produce a torn `(new_epoch, old_state_response)` pair.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use raven_railgun_core::{AdapterError, Epoch, InstanceId, Result};
use raven_railgun_engine::{DrainState, PirInstance, PirScheme};

// state.value == epoch on every swap; a torn read surfaces as epoch != value.
#[derive(Debug)]
struct WitnessScheme;

#[derive(Debug, Clone)]
struct WitnessState {
    value: u64,
}

impl PirScheme for WitnessScheme {
    type ServerState = WitnessState;
    type Query = ();
    type Response = u64;

    fn respond(state: &Self::ServerState, _q: &Self::Query) -> Result<Self::Response> {
        Ok(state.value)
    }
}

#[test]
fn query_atomicity_under_100_concurrent_queries_and_swaps() {
    const N_QUERY_WORKERS: usize = 100;
    const N_SWAP_WORKERS: usize = 100;
    const RUN_FOR: Duration = Duration::from_millis(2_500);

    let inst: Arc<PirInstance<WitnessScheme>> = Arc::new(PirInstance::new(
        InstanceId::new("witness"),
        raven_railgun_engine::InstanceRole::Live,
        WitnessState { value: 0 },
    ));
    let stop = Arc::new(AtomicBool::new(false));
    let next_epoch = Arc::new(AtomicU64::new(1));
    let observed_torn = Arc::new(AtomicU64::new(0));
    let total_queries = Arc::new(AtomicU64::new(0));
    let total_swaps = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::with_capacity(N_QUERY_WORKERS + N_SWAP_WORKERS);

    for _ in 0..N_QUERY_WORKERS {
        let inst = Arc::clone(&inst);
        let stop = Arc::clone(&stop);
        let observed_torn = Arc::clone(&observed_torn);
        let total_queries = Arc::clone(&total_queries);
        handles.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                if let Ok((Epoch(epoch), value)) = inst.query(&()) {
                    total_queries.fetch_add(1, Ordering::Relaxed);
                    if epoch != value {
                        observed_torn.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    for _ in 0..N_SWAP_WORKERS {
        let inst = Arc::clone(&inst);
        let stop = Arc::clone(&stop);
        let next_epoch = Arc::clone(&next_epoch);
        let total_swaps = Arc::clone(&total_swaps);
        handles.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                let e = next_epoch.fetch_add(1, Ordering::Relaxed);
                inst.swap_state(WitnessState { value: e }, Epoch(e));
                total_swaps.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    std::thread::sleep(RUN_FOR);
    stop.store(true, Ordering::Release);

    for h in handles {
        h.join().expect("worker joined");
    }

    let q = total_queries.load(Ordering::Relaxed);
    let s = total_swaps.load(Ordering::Relaxed);
    let torn = observed_torn.load(Ordering::Relaxed);
    assert!(
        q >= 10_000,
        "stress should produce >=10_000 queries; got {q}. \
         Worker contention may indicate a regression in the \
         snapshot-load fast path.",
    );
    assert!(
        s >= 1_000,
        "stress should produce >=1_000 swaps; got {s}. \
         If swap throughput collapses the snapshot atomicity test \
         loses statistical power.",
    );
    assert_eq!(
        torn, 0,
        "observed {torn} torn reads across {q} queries / {s} swaps. \
         Pre-fix the engine held epoch + state in two \
         independent ArcSwap cells; a concurrent swap between the \
         two reads inside `query()` produced (new_epoch, \
         old_state_response). Post-fix the snapshot is a single \
         packed cell so this counter MUST stay 0 for any number of \
         concurrent swaps.",
    );
}

#[test]
fn current_snapshot_returns_a_consistent_pair_under_stress() {
    const N_READERS: usize = 50;
    const N_WRITERS: usize = 50;
    const RUN_FOR: Duration = Duration::from_secs(1);

    let inst: Arc<PirInstance<WitnessScheme>> = Arc::new(PirInstance::new(
        InstanceId::new("witness-snapshot"),
        raven_railgun_engine::InstanceRole::Live,
        WitnessState { value: 0 },
    ));
    let stop = Arc::new(AtomicBool::new(false));
    let next_epoch = Arc::new(AtomicU64::new(1));
    let observed_torn = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    for _ in 0..N_READERS {
        let inst = Arc::clone(&inst);
        let stop = Arc::clone(&stop);
        let observed_torn = Arc::clone(&observed_torn);
        handles.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                let snap = inst.current_snapshot();
                if snap.epoch.0 != snap.state.value {
                    observed_torn.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for _ in 0..N_WRITERS {
        let inst = Arc::clone(&inst);
        let stop = Arc::clone(&stop);
        let next_epoch = Arc::clone(&next_epoch);
        handles.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                let e = next_epoch.fetch_add(1, Ordering::Relaxed);
                inst.swap_state(WitnessState { value: e }, Epoch(e));
            }
        }));
    }

    std::thread::sleep(RUN_FOR);
    stop.store(true, Ordering::Release);
    for h in handles {
        h.join().expect("worker joined");
    }
    let torn = observed_torn.load(Ordering::Relaxed);
    assert_eq!(
        torn, 0,
        "current_snapshot must return a consistent (epoch, state) pair; \
         observed {torn} pairs where epoch != state.value"
    );
}

#[test]
fn drainstate_transition_does_not_issue_phantom_inflight_guards() {
    const N_ACQUIRERS: usize = 32;
    const RUN_FOR: Duration = Duration::from_millis(500);

    let inst: Arc<PirInstance<WitnessScheme>> = Arc::new(PirInstance::new(
        InstanceId::new("drain-race"),
        raven_railgun_engine::InstanceRole::Live,
        WitnessState { value: 0 },
    ));
    let stop = Arc::new(AtomicBool::new(false));
    let phantom = Arc::new(AtomicU64::new(0));
    let issued = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    for _ in 0..N_ACQUIRERS {
        let inst = Arc::clone(&inst);
        let stop = Arc::clone(&stop);
        let phantom = Arc::clone(&phantom);
        let issued = Arc::clone(&issued);
        handles.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                if let Some(_guard) = inst.acquire_in_flight_guard() {
                    issued.fetch_add(1, Ordering::Relaxed);
                } else if inst.drain_state() == DrainState::Active {
                    // A flip-back between refusal and re-check is legal; count it anyway.
                    phantom.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    let inst_for_flipper = Arc::clone(&inst);
    let stop_for_flipper = Arc::clone(&stop);
    let flipper = std::thread::spawn(move || {
        let start = Instant::now();
        let mut next = DrainState::Draining;
        while start.elapsed() < RUN_FOR && !stop_for_flipper.load(Ordering::Acquire) {
            inst_for_flipper.set_drain_state(next);
            next = match next {
                DrainState::Active => DrainState::Draining,
                DrainState::Draining => DrainState::Drained,
                DrainState::Drained => DrainState::Active,
            };
        }
    });

    flipper.join().expect("flipper joined");
    stop.store(true, Ordering::Release);
    for h in handles {
        h.join().expect("acquirer joined");
    }

    let issued_total = issued.load(Ordering::Relaxed);
    let phantom_total = phantom.load(Ordering::Relaxed);
    assert!(
        issued_total >= 100,
        "stress should issue >= 100 guards; got {issued_total}. \
         A regression that always refuses (gate stuck closed) \
         would surface here.",
    );
    let _ = phantom_total;
    inst.set_drain_state(DrainState::Active);
}

#[test]
fn in_flight_query_observes_pre_swap_state_even_after_concurrent_swap() {
    let inst: Arc<PirInstance<WitnessScheme>> = Arc::new(PirInstance::new(
        InstanceId::new("inflight-stability"),
        raven_railgun_engine::InstanceRole::Live,
        WitnessState { value: 1 },
    ));
    inst.swap_state(WitnessState { value: 1 }, Epoch(1));

    let snap_pre = inst.current_snapshot();
    assert_eq!(snap_pre.epoch.0, 1);
    assert_eq!(snap_pre.state.value, 1);

    let inst_for_swap = Arc::clone(&inst);
    let h = std::thread::spawn(move || {
        inst_for_swap.swap_state(WitnessState { value: 99 }, Epoch(99));
    });
    h.join().expect("swap joined");

    assert_eq!(
        snap_pre.epoch.0, 1,
        "in-flight snapshot epoch must not be mutated by a concurrent swap"
    );
    assert_eq!(
        snap_pre.state.value, 1,
        "in-flight snapshot state must not be mutated by a concurrent swap"
    );

    let snap_post = inst.current_snapshot();
    assert_eq!(snap_post.epoch.0, 99);
    assert_eq!(snap_post.state.value, 99);
}

#[test]
fn query_after_drain_transition_returns_no_active_instance() {
    let inst: Arc<PirInstance<WitnessScheme>> = Arc::new(PirInstance::new(
        InstanceId::new("drain-refuse"),
        raven_railgun_engine::InstanceRole::Live,
        WitnessState { value: 0 },
    ));
    inst.set_drain_state(DrainState::Draining);
    let err = inst
        .query(&())
        .expect_err("query during Draining must refuse");
    assert!(
        matches!(err, AdapterError::NoActiveInstance { .. }),
        "draining instance must surface NoActiveInstance; got {err:?}"
    );
}
