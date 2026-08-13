//! Two writers read-modify-write the same instance. A writer that derived its
//! state from a snapshot another writer has already superseded must be refused,
//! never silently published on top of the update it dropped.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use raven_core::server_error::Result;
use raven_core::{Epoch, InstanceId, ServerError};
use raven_server::{InstanceRole, PirInstance, PirScheme, Snapshot, StateShape};

/// Two generations carried by one server state: `encoded` advances when a shard
/// is re-encoded, `sessions` advances when the session store is reset.
#[derive(Clone, Copy, Debug)]
struct TwoWriterState {
    encoded: u64,
    sessions: u64,
}

struct TwoWriterScheme;

impl PirScheme for TwoWriterScheme {
    type ServerState = TwoWriterState;
    type Query = ();
    type Response = (u64, u64);

    fn respond(state: &Self::ServerState, _query: &Self::Query) -> Result<Self::Response> {
        Ok((state.encoded, state.sessions))
    }

    fn state_shape(_state: &Self::ServerState) -> StateShape {
        StateShape {
            entry_size_bytes: 1,
            rows_per_shard: u64::MAX,
        }
    }
}

fn fresh_instance(label: &str) -> Arc<PirInstance<TwoWriterScheme>> {
    Arc::new(PirInstance::new(
        InstanceId::new(label),
        InstanceRole::Live,
        TwoWriterState {
            encoded: 0,
            sessions: 0,
        },
    ))
}

/// Re-encode writer: derive from one captured snapshot, publish at its successor.
fn re_encode_from(snap: &Snapshot<TwoWriterScheme>) -> (TwoWriterState, Epoch) {
    (
        TwoWriterState {
            encoded: snap.state.encoded + 1,
            sessions: snap.state.sessions,
        },
        snap.epoch.next(),
    )
}

/// Session-eviction writer: carry the captured snapshot forward with a fresh
/// session generation.
fn evict_sessions_from(snap: &Snapshot<TwoWriterScheme>) -> (TwoWriterState, Epoch) {
    (
        TwoWriterState {
            encoded: snap.state.encoded,
            sessions: snap.state.sessions + 1,
        },
        snap.epoch.next(),
    )
}

/// Per-writer witness that is NOT a function the epoch already carries, so a state
/// published under someone else's epoch is observable.
fn writer_witness(epoch: u64) -> u64 {
    epoch.wrapping_mul(2_654_435_761).rotate_left(17) | 1
}

#[test]
fn concurrent_writers_never_publish_a_superseded_state() {
    const TRIALS: usize = 4096;

    let mut lost_updates = 0usize;
    let mut collisions = 0usize;
    let mut first_failure = String::new();

    for trial in 0..TRIALS {
        let inst = fresh_instance(&format!("rmw-{trial}"));
        let barrier = Arc::new(Barrier::new(2));
        let accepted = Arc::new(AtomicU64::new(0));

        let handles: Vec<thread::JoinHandle<()>> = [
            re_encode_from as fn(&Snapshot<TwoWriterScheme>) -> (TwoWriterState, Epoch),
            evict_sessions_from,
        ]
        .into_iter()
        .map(|derive| {
            let inst = Arc::clone(&inst);
            let barrier = Arc::clone(&barrier);
            let accepted = Arc::clone(&accepted);
            thread::spawn(move || {
                let snap = inst.current_snapshot();
                let (new_state, new_epoch) = derive(&snap);
                barrier.wait();
                if inst.swap_state(new_state, new_epoch).is_ok() {
                    accepted.fetch_add(1, Ordering::AcqRel);
                }
            })
        })
        .collect();

        for handle in handles {
            handle.join().expect("writer joined");
        }

        let accepted = accepted.load(Ordering::Acquire);
        let snap = inst.current_snapshot();
        let applied = snap.state.encoded + snap.state.sessions;

        if accepted < 2 {
            collisions += 1;
        }
        if applied != accepted || snap.epoch != Epoch(accepted) {
            lost_updates += 1;
            if first_failure.is_empty() {
                first_failure = format!(
                    "trial {trial}: {accepted} swap(s) returned Ok but the published state \
                     carries {applied} of them at epoch {}",
                    snap.epoch
                );
            }
        }
    }

    assert_eq!(
        lost_updates, 0,
        "{lost_updates}/{TRIALS} trials published a state that dropped an accepted swap \
         while the epoch still advanced. {first_failure}"
    );
    assert_eq!(
        collisions, TRIALS,
        "both writers derive from the same snapshot before the barrier, so every trial must \
         refuse exactly one of them; only {collisions}/{TRIALS} did"
    );
}

/// Writers that carry their own distinct epochs (a re-preprocess pipeline hands
/// `swap_state` an epoch it computed elsewhere) must still leave the instance on
/// the highest accepted epoch, with the state that epoch names.
#[test]
fn distinct_epoch_writers_leave_the_highest_accepted_epoch_published() {
    const WRITERS: u64 = 8;
    const TRIALS: usize = 256;

    for trial in 0..TRIALS {
        let inst = fresh_instance(&format!("distinct-{trial}"));
        let barrier = Arc::new(Barrier::new(usize::try_from(WRITERS).expect("fits")));
        let highest_accepted = Arc::new(AtomicU64::new(0));

        let handles: Vec<thread::JoinHandle<()>> = (1..=WRITERS)
            .map(|epoch| {
                let inst = Arc::clone(&inst);
                let barrier = Arc::clone(&barrier);
                let highest_accepted = Arc::clone(&highest_accepted);
                thread::spawn(move || {
                    let state = TwoWriterState {
                        encoded: epoch,
                        // A witness the epoch does not determine. Asserting only
                        // `encoded == highest` is a tautology when `encoded` IS the
                        // epoch: it cannot distinguish "this writer's state was
                        // published" from "some state at this epoch was".
                        sessions: writer_witness(epoch),
                    };
                    barrier.wait();
                    if inst.swap_state(state, Epoch(epoch)).is_ok() {
                        highest_accepted.fetch_max(epoch, Ordering::AcqRel);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("writer joined");
        }

        let highest = highest_accepted.load(Ordering::Acquire);
        let snap = inst.current_snapshot();
        assert_eq!(
            snap.epoch,
            Epoch(highest),
            "trial {trial}: published epoch must be the highest accepted one"
        );
        assert_eq!(
            snap.state.encoded, highest,
            "trial {trial}: published state must be the one its epoch names"
        );
        assert_eq!(
            snap.state.sessions,
            writer_witness(highest),
            "trial {trial}: the published state must be the one the winning writer \
             built, not another writer's state wearing the winning epoch"
        );
    }
}

#[test]
fn a_writer_that_derived_from_a_superseded_snapshot_is_refused() {
    let inst = fresh_instance("superseded");

    let stale = inst.current_snapshot();
    let (evicted_state, evicted_epoch) = evict_sessions_from(&stale);

    let (re_encoded_state, re_encoded_epoch) = re_encode_from(&inst.current_snapshot());
    inst.swap_state(re_encoded_state, re_encoded_epoch)
        .expect("first writer publishes");

    let err = inst
        .swap_state(evicted_state, evicted_epoch)
        .expect_err("a swap that does not advance the published epoch must be refused");
    assert!(matches!(err, ServerError::Internal(_)), "got {err:?}");
    let message = err.to_string();
    assert!(
        message.contains("published epoch 1") && message.contains("attempted epoch 1"),
        "refusal must name both epochs; got {message}"
    );

    let snap = inst.current_snapshot();
    assert_eq!(snap.epoch, Epoch(1));
    assert_eq!(
        snap.state.encoded, 1,
        "the re-encoded state must survive the superseded writer"
    );
    assert_eq!(snap.state.sessions, 0);
}

#[test]
fn a_backwards_epoch_is_refused() {
    let inst = fresh_instance("backwards");
    let (state, epoch) = re_encode_from(&inst.current_snapshot());
    inst.swap_state(state, epoch).expect("first publish");
    inst.swap_state(
        TwoWriterState {
            encoded: 9,
            sessions: 9,
        },
        Epoch(2),
    )
    .expect("second publish");

    let err = inst
        .swap_state(
            TwoWriterState {
                encoded: 0,
                sessions: 0,
            },
            Epoch(1),
        )
        .expect_err("republishing under an already-retired epoch must be refused");
    assert!(matches!(err, ServerError::Internal(_)), "got {err:?}");
    assert_eq!(inst.current_snapshot().epoch, Epoch(2));
}

#[test]
fn sequential_writers_both_land() {
    let inst = fresh_instance("sequential");
    let (state, epoch) = re_encode_from(&inst.current_snapshot());
    inst.swap_state(state, epoch).expect("re-encode publishes");
    let (state, epoch) = evict_sessions_from(&inst.current_snapshot());
    inst.swap_state(state, epoch).expect("eviction publishes");

    let snap = inst.current_snapshot();
    assert_eq!(snap.epoch, Epoch(2));
    assert_eq!((snap.state.encoded, snap.state.sessions), (1, 1));
}
