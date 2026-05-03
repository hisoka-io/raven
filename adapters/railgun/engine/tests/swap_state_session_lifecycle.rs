//! H11 regression guards for the session-store lifecycle divergence:
//! admin-path `inspire::swap_state` resets the session store; the
//! consumer-task `drive_commit` re-encode path carries it via
//! `Arc::clone`.

#![allow(clippy::expect_used)]

use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::ServerSessionStore;
use raven_railgun_core::{Epoch, InstanceId};
use raven_railgun_engine::inspire::{
    build_client_session, register_client_session, setup_state, InspireServerState,
    RavenInspireScheme,
};
use raven_railgun_engine::{inspire, InstanceRole, PirInstance};

const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_SIZE: usize = 32;

fn build_toy_state(params: &InspireParams) -> InspireServerState {
    let db: Vec<u8> = (0..TOY_ENTRIES)
        .flat_map(|i| {
            (0..TOY_ENTRY_SIZE).map(move |j| u8::try_from((i + j) % 251).expect("< 251"))
        })
        .collect();
    let (state, _sk) = setup_state(params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking)
        .expect("toy setup_state");
    state
}

fn register_one_session(instance: &Arc<PirInstance<RavenInspireScheme>>, params: &InspireParams) {
    let snap = instance.current_state();
    let crs_clone = (*snap.crs).clone();
    // Synthesize a matching sk via a sibling setup_state call; sk is
    // independent of server state contents and we only need a
    // structurally-valid RlweSecretKey for the session.
    let (_off_state, sk) = {
        let db: Vec<u8> = (0..TOY_ENTRIES)
            .flat_map(|i| {
                (0..TOY_ENTRY_SIZE).map(move |j| u8::try_from((i + j) % 251).expect("< 251"))
            })
            .collect();
        setup_state(params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking).expect("sibling")
    };
    let mut session = build_client_session(crs_clone, sk, params).expect("client session");
    register_client_session(&mut session, snap.as_ref()).expect("register session");
}

// H11.a: admin-path `inspire::swap_state` clears session_store.

#[test]
fn admin_swap_state_clears_session_store() {
    let params = InspireParams::secure_128_d2048();
    let initial_state = build_toy_state(&params);
    let instance: Arc<PirInstance<RavenInspireScheme>> = Arc::new(PirInstance::new(
        InstanceId::new("h11-admin-swap-clears"),
        InstanceRole::Live,
        initial_state,
    ));

    register_one_session(&instance, &params);
    let pre_swap_len = {
        let snap = instance.current_state();
        snap.session_store.len()
    };
    assert!(
        pre_swap_len >= 1,
        "donor session_store must be non-empty before the admin swap (got len={pre_swap_len})"
    );

    // Capture the donor's Arc pointer so we can assert post-swap the
    // store is a DIFFERENT Arc (not just equal-by-content).
    let donor_session_store_ptr: *const ServerSessionStore = {
        let snap = instance.current_state();
        Arc::as_ptr(&snap.session_store)
    };

    let (crs_clone, db_clone, variant, entry_size, next_epoch) = {
        let donor = instance.current_state();
        (
            (*donor.crs).clone(),
            donor.encoded_db.clone(),
            donor.variant,
            donor.entry_size,
            instance.current_epoch().next(),
        )
    };
    inspire::swap_state(
        &instance, crs_clone, db_clone, variant, entry_size, next_epoch,
    )
    .expect("admin swap_state");

    let post_swap_len = {
        let snap = instance.current_state();
        snap.session_store.len()
    };
    assert_eq!(
        post_swap_len, 0,
        "admin swap_state MUST install a fresh empty ServerSessionStore (documented contract); \
         got post-swap len={post_swap_len}"
    );

    // Must be a DIFFERENT Arc — guards against a future "always carry"
    // regression that would type-check but leak donor sessions.
    let post_swap_session_store_ptr: *const ServerSessionStore = {
        let snap = instance.current_state();
        Arc::as_ptr(&snap.session_store)
    };
    assert!(
        !std::ptr::eq(donor_session_store_ptr, post_swap_session_store_ptr),
        "admin swap_state MUST install a fresh ServerSessionStore Arc, not carry the donor's"
    );

    assert!(
        instance.current_epoch() > Epoch::ZERO,
        "swap_state must bump the epoch"
    );
}

// H11.b: re-encode path preserves session_store via Arc::clone.

#[test]
fn drive_commit_path_preserves_session_store() {
    let params = InspireParams::secure_128_d2048();
    let initial_state = build_toy_state(&params);
    let instance: Arc<PirInstance<RavenInspireScheme>> = Arc::new(PirInstance::new(
        InstanceId::new("h11-drive-commit-preserves"),
        InstanceRole::Live,
        initial_state,
    ));

    register_one_session(&instance, &params);
    let pre_swap_len = {
        let snap = instance.current_state();
        snap.session_store.len()
    };
    assert!(
        pre_swap_len >= 1,
        "donor session_store must be non-empty before the drive_commit-shaped swap"
    );
    let donor_session_store_ptr: *const ServerSessionStore = {
        let snap = instance.current_state();
        Arc::as_ptr(&snap.session_store)
    };

    // Mirror `Engine::drive_commit`'s new_state shape. encoded_db is
    // cloned without re-encoding (no dirty shards) because the property
    // under test is session lifecycle, not re-encode correctness.
    let new_state = {
        let current = instance.current_state();
        InspireServerState {
            crs: Arc::clone(&current.crs),
            encoded_db: current.encoded_db.clone(),
            cache: Arc::clone(&current.cache),
            session_store: Arc::clone(&current.session_store),
            variant: current.variant,
            entry_size: current.entry_size,
        }
    };
    let next_epoch = instance.current_epoch().next();
    instance.swap_state(new_state, next_epoch);

    let post_swap_len = {
        let snap = instance.current_state();
        snap.session_store.len()
    };
    assert_eq!(
        post_swap_len, pre_swap_len,
        "drive_commit-shaped swap MUST preserve the session_store contents (Arc::clone pattern); \
         pre={pre_swap_len} post={post_swap_len}"
    );
    let post_swap_session_store_ptr: *const ServerSessionStore = {
        let snap = instance.current_state();
        Arc::as_ptr(&snap.session_store)
    };
    assert!(
        std::ptr::eq(donor_session_store_ptr, post_swap_session_store_ptr),
        "drive_commit-shaped swap MUST carry the donor's ServerSessionStore Arc unchanged"
    );

    assert!(
        instance.current_epoch() > Epoch::ZERO,
        "swap_state must bump the epoch"
    );
}
