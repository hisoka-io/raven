//! A CAS on the snapshot pointer is not a CAS on the derivation.
//!
//! `swap_state`'s compare-and-swap proves the cell did not move between its own load
//! and its store - nanoseconds. It says nothing about whether the state the caller
//! built is still current. The epoch is what carries that, and only if the caller
//! derives it from the same load as the state: reading `current_state()` and then
//! `current_epoch()` lets a commit land in between, producing a stale state wearing a
//! fresh epoch, which sails through the monotonicity guard.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::{Epoch, InstanceId};
use raven_railgun_engine::inspire::{setup_state, InspireServerState, RavenInspireScheme};
use raven_railgun_engine::{InstanceRole, PirInstance};

const ENTRIES: usize = 256;
const ENTRY_SIZE: usize = 32;

fn instance() -> (PirInstance<RavenInspireScheme>, InspireParams) {
    let params = InspireParams::secure_128_d2048();
    let db: Vec<u8> = (0..ENTRIES)
        .flat_map(|i| (0..ENTRY_SIZE).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
        .collect();
    let (state, _sk) =
        setup_state(&params, &db, ENTRY_SIZE, InspireVariant::TwoPacking).expect("setup");
    let inst = PirInstance::new(
        InstanceId::new("stale-derivation"),
        InstanceRole::Live,
        state,
    );
    (inst, params)
}

/// Same shape, distinguishable session store, so a republish is observable.
fn derive_from(donor: &InspireServerState) -> InspireServerState {
    InspireServerState {
        crs: Arc::clone(&donor.crs),
        encoded_db: Arc::clone(&donor.encoded_db),
        cache: Arc::clone(&donor.cache),
        session_store: Arc::clone(&donor.session_store),
        variant: donor.variant,
        entry_size: donor.entry_size,
    }
}

/// The defect, made deterministic: capture a snapshot, let another writer publish, then
/// try to swap the state derived from the captured one. It must be refused.
#[test]
fn a_state_derived_from_a_superseded_snapshot_is_refused() {
    let (inst, _params) = instance();

    // Writer A captures the snapshot it will derive from.
    let captured = inst.current_snapshot();
    let derived = derive_from(&captured.state);

    // Writer B commits in between and publishes.
    let interloper = derive_from(&inst.current_snapshot().state);
    inst.swap_state(interloper, inst.current_snapshot().epoch.next())
        .expect("the interloping writer publishes normally");
    let after_interloper = inst.current_snapshot().epoch;

    // Writer A now swaps, carrying the epoch of the snapshot it derived from.
    let err = inst
        .swap_state(derived, captured.epoch.next())
        .expect_err("a state derived from a superseded snapshot must be refused");
    let msg = format!("{err}");
    assert!(
        msg.contains("stale state swap"),
        "the refusal must name the staleness, got: {msg}"
    );
    assert_eq!(
        inst.current_snapshot().epoch,
        after_interloper,
        "the refused swap must leave the interloper's state published"
    );
}

/// Deriving the epoch from a SECOND read is what defeats the guard: the stale state
/// then wears an epoch above the published one and is accepted. This pins the caller
/// contract, so a future caller reintroducing the split read fails here.
#[test]
fn deriving_the_epoch_from_a_second_read_would_defeat_the_guard() {
    let (inst, _params) = instance();

    let captured = inst.current_snapshot();
    let stale = derive_from(&captured.state);

    let interloper = derive_from(&inst.current_snapshot().state);
    inst.swap_state(interloper, inst.current_snapshot().epoch.next())
        .expect("interloper publishes");

    // The split read: epoch taken AFTER the interloper, state from before it.
    let epoch_from_a_second_read = inst.current_epoch().next();
    assert!(
        epoch_from_a_second_read > captured.epoch.next(),
        "the second read must yield a higher epoch than the derivation, which is \
         exactly why it defeats the monotonicity guard"
    );
    inst.swap_state(stale, epoch_from_a_second_read)
        .expect("this is accepted, and that acceptance is the defect");

    // Documented, not endorsed: no production caller may take this path. Both
    // `heartbeat_session_eviction` and `drive_commit` derive from one snapshot.
    assert_eq!(inst.current_snapshot().epoch, epoch_from_a_second_read);
}

/// A correctly derived swap still succeeds, so the guard has not become a wall.
#[test]
fn a_freshly_derived_swap_still_publishes() {
    let (inst, _params) = instance();
    for _ in 0..4 {
        let snap = inst.current_snapshot();
        let next = derive_from(&snap.state);
        inst.swap_state(next, snap.epoch.next())
            .expect("an uncontended derivation publishes");
    }
    assert_eq!(inst.current_snapshot().epoch, Epoch(4));
}
