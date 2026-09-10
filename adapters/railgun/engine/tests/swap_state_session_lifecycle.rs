//! Session-store lifecycle: admin-path `inspire::swap_state` resets the
//! session store; the `drive_commit` re-encode path carries it via `Arc::clone`.

#![allow(clippy::expect_used)]

use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::{Epoch, InstanceId};
use raven_railgun_engine::inspire::{
    build_client_session, register_client_session, setup_state, InspireServerState,
    RavenInspireScheme,
};
use raven_railgun_engine::session_pool::BoundedSessionStore;
use raven_railgun_engine::{inspire, InstanceRole, PirInstance};

const TOY_ENTRY_SIZE: usize = 32;

fn build_toy_state(params: &InspireParams) -> InspireServerState {
    // Uncached deliberately: this file asserts Arc identity and refcount, so it must own its
    // state outright. Only the DB formula is shared.
    let db = raven_railgun_testkit::toy_db(raven_railgun_testkit::TOY_ENTRIES, TOY_ENTRY_SIZE);
    let (state, _sk) = setup_state(params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking)
        .expect("toy setup_state");
    state
}

fn register_one_session(instance: &Arc<PirInstance<RavenInspireScheme>>, params: &InspireParams) {
    let snap = instance.current_state();
    let crs_clone = (*snap.crs).clone();
    // The key is independent of state contents, so a sibling setup suffices.
    // Only the key is wanted here; building a whole state to throw it away cost a
    // full setup. Key generation is milliseconds.
    let sk = raven_railgun_testkit::toy_secret_key(params);
    let mut session = build_client_session(crs_clone, sk, params).expect("client session");
    register_client_session(&mut session, snap.as_ref()).expect("register session");
}

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

    // Compare Arc identity, not content.
    let donor_session_store_ptr: *const BoundedSessionStore = {
        let snap = instance.current_state();
        Arc::as_ptr(&snap.session_store)
    };

    let (crs_clone, db_clone, variant, entry_size, next_epoch) = {
        let donor = instance.current_state();
        (
            (*donor.crs).clone(),
            (*donor.encoded_db).clone(),
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
        "admin swap_state MUST install a fresh empty BoundedSessionStore (documented contract); \
         got post-swap len={post_swap_len}"
    );

    // An always-carry regression would type-check but leak donor sessions.
    let post_swap_session_store_ptr: *const BoundedSessionStore = {
        let snap = instance.current_state();
        Arc::as_ptr(&snap.session_store)
    };
    assert!(
        !std::ptr::eq(donor_session_store_ptr, post_swap_session_store_ptr),
        "admin swap_state MUST install a fresh BoundedSessionStore Arc, not carry the donor's"
    );

    assert!(
        instance.current_epoch() > Epoch::ZERO,
        "swap_state must bump the epoch"
    );
}
