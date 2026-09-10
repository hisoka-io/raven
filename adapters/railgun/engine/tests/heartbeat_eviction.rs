//! Heartbeat session eviction: the store resets while CRS, `EncodedDatabase` and
//! cache are carried by `Arc::clone`, never deep-cloned.

#![allow(clippy::expect_used)]

use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::{EncodedDatabase, ServerInspiringCache};
use raven_railgun_core::{Epoch, InstanceId};
use raven_railgun_engine::inspire::{
    build_client_session, heartbeat_session_eviction, register_client_session, setup_state,
    InspireServerState, RavenInspireScheme,
};
use raven_railgun_engine::session_pool::BoundedSessionStore;
use raven_railgun_engine::{InstanceRole, PirInstance};

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
    // Only the key is wanted here; building a whole state to throw it away cost a
    // full setup. Key generation is milliseconds.
    let sk = raven_railgun_testkit::toy_secret_key(params);
    let mut session = build_client_session(crs_clone, sk, params).expect("client session");
    register_client_session(&mut session, snap.as_ref()).expect("register session");
}

#[test]
fn heartbeat_swap_state_drops_inner_session_store() {
    let params = InspireParams::secure_128_d2048();
    let initial_state = build_toy_state(&params);
    let instance: Arc<PirInstance<RavenInspireScheme>> = Arc::new(PirInstance::new(
        InstanceId::new("heartbeat-drops-inner"),
        InstanceRole::Live,
        initial_state,
    ));

    for _ in 0..3 {
        register_one_session(&instance, &params);
    }
    let (pre_len, donor_store_ptr): (usize, *const BoundedSessionStore) = {
        let snap = instance.current_state();
        (snap.session_store.len(), Arc::as_ptr(&snap.session_store))
    };
    assert!(
        pre_len >= 3,
        "donor session_store must hold the registered sessions before heartbeat \
         (got len={pre_len})"
    );

    heartbeat_session_eviction(&instance).expect("heartbeat");

    let (post_len, post_store_ptr): (usize, *const BoundedSessionStore) = {
        let snap = instance.current_state();
        (snap.session_store.len(), Arc::as_ptr(&snap.session_store))
    };
    assert_eq!(
        post_len, 0,
        "heartbeat MUST install a fresh empty BoundedSessionStore; got post len={post_len}"
    );
    // Reusing the donor's Arc would make eviction a no-op for in-flight queries
    // still holding it.
    assert!(
        !std::ptr::eq(donor_store_ptr, post_store_ptr),
        "heartbeat MUST install a fresh BoundedSessionStore Arc; the donor's \
         Arc must not survive into the new state"
    );

    assert!(
        instance.current_epoch() > Epoch::ZERO,
        "heartbeat MUST bump the epoch (so wallets re-handshake)"
    );
}

#[test]
fn heartbeat_swap_state_preserves_cache_across_swap() {
    // Cache rebuild is ~3.7 s at production cell, so it must be carried, not rebuilt.
    let params = InspireParams::secure_128_d2048();
    let initial_state = build_toy_state(&params);
    let instance: Arc<PirInstance<RavenInspireScheme>> = Arc::new(PirInstance::new(
        InstanceId::new("heartbeat-preserves-cache"),
        InstanceRole::Live,
        initial_state,
    ));

    let donor_cache_ptr: *const ServerInspiringCache = {
        let snap = instance.current_state();
        Arc::as_ptr(&snap.cache)
    };

    heartbeat_session_eviction(&instance).expect("heartbeat");

    let post_cache_ptr: *const ServerInspiringCache = {
        let snap = instance.current_state();
        Arc::as_ptr(&snap.cache)
    };
    assert!(
        std::ptr::eq(donor_cache_ptr, post_cache_ptr),
        "heartbeat MUST carry the donor's ServerInspiringCache Arc unchanged \
         (Arc::clone). A non-equal pointer here means the cache rebuilt - the \
         hourly tick would stall the server for seconds."
    );
}

// A deep clone per fire is ~128 MiB at production cell and would OOM under
// hourly ticks.

/// Across N fires the `Arc<EncodedDatabase>` allocation address must stay stable.
#[test]
fn heartbeat_eviction_does_not_clone_encoded_db_under_steady_load() {
    let params = InspireParams::secure_128_d2048();
    let initial_state = build_toy_state(&params);
    let instance: Arc<PirInstance<RavenInspireScheme>> = Arc::new(PirInstance::new(
        InstanceId::new("heartbeat-no-encoded-db-clone"),
        InstanceRole::Live,
        initial_state,
    ));

    let initial_db_ptr: *const EncodedDatabase = {
        let snap = instance.current_state();
        Arc::as_ptr(&snap.encoded_db)
    };

    for fire in 0..10 {
        heartbeat_session_eviction(&instance).expect("heartbeat fire");
        let post_db_ptr: *const EncodedDatabase = {
            let snap = instance.current_state();
            Arc::as_ptr(&snap.encoded_db)
        };
        assert!(
            std::ptr::eq(initial_db_ptr, post_db_ptr),
            "fire {fire}: encoded_db Arc pointer changed across heartbeat. \
             A deep clone has regressed; this is the heartbeat OOM path."
        );
    }

    let final_strong_count = {
        let snap = instance.current_state();
        Arc::strong_count(&snap.encoded_db)
    };
    assert!(
        final_strong_count <= 2,
        "encoded_db strong_count = {final_strong_count} after 10 heartbeats; \
         expected <= 2 (current state + the local snap guard). A larger value \
         means heartbeat is leaking Arcs (e.g. forgetting to drop the donor \
         swap-out)."
    );
}
