//! Heartbeat session-eviction tests. The heartbeat resets the inner
//! `ServerSessionStore` while carrying the heavy CRS / `EncodedDatabase`
//! / `ServerInspiringCache` by `Arc::clone`; the trailing tests guard
//! against re-introducing a deep clone of `encoded_db`.

#![allow(clippy::expect_used)]

use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::{EncodedDatabase, ServerInspiringCache, ServerSessionStore};
use raven_railgun_core::{Epoch, InstanceId};
use raven_railgun_engine::inspire::{
    build_client_session, heartbeat_session_eviction, register_client_session, setup_state,
    InspireServerState, RavenInspireScheme,
};
use raven_railgun_engine::{InstanceRole, PirInstance};

const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_SIZE: usize = 32;

fn build_toy_state(params: &InspireParams) -> InspireServerState {
    let db: Vec<u8> = (0..TOY_ENTRIES)
        .flat_map(|i| (0..TOY_ENTRY_SIZE).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
        .collect();
    let (state, _sk) = setup_state(params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking)
        .expect("toy setup_state");
    state
}

fn register_one_session(instance: &Arc<PirInstance<RavenInspireScheme>>, params: &InspireParams) {
    let snap = instance.current_state();
    let crs_clone = (*snap.crs).clone();
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
    let pre_len = {
        let snap = instance.current_state();
        snap.session_store.len()
    };
    assert!(
        pre_len >= 3,
        "donor session_store must hold the registered sessions before heartbeat \
         (got len={pre_len})"
    );

    heartbeat_session_eviction(&instance).expect("heartbeat");

    let post_len = {
        let snap = instance.current_state();
        snap.session_store.len()
    };
    assert_eq!(
        post_len, 0,
        "heartbeat MUST install a fresh empty ServerSessionStore; got post len={post_len}"
    );

    assert!(
        instance.current_epoch() > Epoch::ZERO,
        "heartbeat MUST bump the epoch (so wallets re-handshake)"
    );
}

#[test]
fn heartbeat_swap_state_preserves_cache_across_swap() {
    // Cache is the heaviest field (~3.7 s rebuild at production cell);
    // heartbeat must carry it by Arc::clone, not rebuild.
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

#[test]
fn heartbeat_swap_state_drops_session_store_arc_pointer_too() {
    // A fresh session_store Arc; reusing the donor's would make eviction
    // a no-op for in-flight queries still holding the donor.
    let params = InspireParams::secure_128_d2048();
    let initial_state = build_toy_state(&params);
    let instance: Arc<PirInstance<RavenInspireScheme>> = Arc::new(PirInstance::new(
        InstanceId::new("heartbeat-fresh-store"),
        InstanceRole::Live,
        initial_state,
    ));

    register_one_session(&instance, &params);

    let donor_store_ptr: *const ServerSessionStore = {
        let snap = instance.current_state();
        Arc::as_ptr(&snap.session_store)
    };

    heartbeat_session_eviction(&instance).expect("heartbeat");

    let post_store_ptr: *const ServerSessionStore = {
        let snap = instance.current_state();
        Arc::as_ptr(&snap.session_store)
    };
    assert!(
        !std::ptr::eq(donor_store_ptr, post_store_ptr),
        "heartbeat MUST install a fresh ServerSessionStore Arc; the donor's \
         Arc must not survive into the new state"
    );
}

/// Operator opt-out (CLI `interval == 0`): heartbeat fn never called,
/// so the bootstrap session_store Arc must persist unchanged.
#[test]
fn heartbeat_interval_disabled_when_zero() {
    let params = InspireParams::secure_128_d2048();
    let initial_state = build_toy_state(&params);
    let instance: Arc<PirInstance<RavenInspireScheme>> = Arc::new(PirInstance::new(
        InstanceId::new("heartbeat-disabled-zero"),
        InstanceRole::Live,
        initial_state,
    ));

    let initial_store_ptr: *const ServerSessionStore = {
        let snap = instance.current_state();
        Arc::as_ptr(&snap.session_store)
    };

    register_one_session(&instance, &params);

    let post_store_ptr: *const ServerSessionStore = {
        let snap = instance.current_state();
        Arc::as_ptr(&snap.session_store)
    };
    assert!(
        std::ptr::eq(initial_store_ptr, post_store_ptr),
        "with the CLI guard at zero (heartbeat_session_eviction never \
         called), the donor session_store Arc MUST persist; the test \
         observed a swap (different Arc) - guard logic regressed?"
    );
    assert_eq!(
        instance.current_epoch(),
        Epoch::ZERO,
        "epoch MUST remain at zero when the heartbeat fn is never \
         called (operator opt-out branch)"
    );
}

#[test]
fn heartbeat_swap_state_metric_increments_per_swap() {
    // One epoch bump per call stands in for the per-call swap metric.
    let params = InspireParams::secure_128_d2048();
    let initial_state = build_toy_state(&params);
    let instance: Arc<PirInstance<RavenInspireScheme>> = Arc::new(PirInstance::new(
        InstanceId::new("heartbeat-per-call"),
        InstanceRole::Live,
        initial_state,
    ));

    let e0 = instance.current_epoch();
    heartbeat_session_eviction(&instance).expect("heartbeat 1");
    let e1 = instance.current_epoch();
    heartbeat_session_eviction(&instance).expect("heartbeat 2");
    let e2 = instance.current_epoch();
    heartbeat_session_eviction(&instance).expect("heartbeat 3");
    let e3 = instance.current_epoch();

    assert!(e1 > e0, "epoch MUST advance after first heartbeat");
    assert!(e2 > e1, "epoch MUST advance after second heartbeat");
    assert!(e3 > e2, "epoch MUST advance after third heartbeat");
}

// encoded_db is carried by Arc::clone; a deep clone per fire (~128 MiB
// memcpy at production cell) would OOM the server under hourly ticks.

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

/// 1-ms ceiling on the toy cell: covers allocation jitter yet catches a
/// 100 ms+ deep-clone regression (production-cell setup is too heavy to use).
#[test]
fn heartbeat_eviction_arc_clone_constant_time_at_production_cell() {
    let params = InspireParams::secure_128_d2048();
    let initial_state = build_toy_state(&params);
    let instance: Arc<PirInstance<RavenInspireScheme>> = Arc::new(PirInstance::new(
        InstanceId::new("heartbeat-arc-clone-timing"),
        InstanceRole::Live,
        initial_state,
    ));

    // Warm-up: first fire pays metrics-recorder + arc_swap lazy-init.
    heartbeat_session_eviction(&instance).expect("warmup");

    let mut over_budget = 0usize;
    for _ in 0..100 {
        let started = std::time::Instant::now();
        heartbeat_session_eviction(&instance).expect("sampled fire");
        let elapsed = started.elapsed();
        if elapsed > std::time::Duration::from_millis(1) {
            over_budget = over_budget.saturating_add(1);
        }
    }

    assert!(
        over_budget <= 5,
        "{over_budget}/100 heartbeat fires exceeded 1 ms. The fix carries \
         encoded_db via Arc::clone (sub-microsecond); a regression to \
         Vec memcpy would put every fire over budget."
    );
}

/// `Arc::make_mut` (drive_commit's re-encode path) is a no-op when the
/// Arc is uniquely owned and copies exactly once when a sibling (an
/// in-flight query) is alive.
#[test]
fn drive_commit_arc_make_mut_only_copies_under_inflight_query() {
    let params = InspireParams::secure_128_d2048();
    let state = build_toy_state(&params);

    let original_arc = Arc::clone(&state.encoded_db);
    let original_ptr: *const EncodedDatabase = Arc::as_ptr(&original_arc);

    // Path A: uniquely-owned Arc -> make_mut does not allocate.
    {
        let solo = Arc::clone(&original_arc);
        let mut unique = Arc::new(EncodedDatabase {
            shards: Vec::new(),
            config: solo.config.clone(),
        });
        let unique_ptr: *const EncodedDatabase = Arc::as_ptr(&unique);
        let _ = Arc::make_mut(&mut unique);
        assert!(
            std::ptr::eq(unique_ptr, Arc::as_ptr(&unique)),
            "Arc::make_mut on a uniquely-owned Arc must not allocate"
        );
        drop(solo);
    }

    // Path B: shared Arc -> make_mut performs CoW into a fresh allocation.
    {
        let mut writer = Arc::clone(&original_arc);
        let pre_writer_ptr: *const EncodedDatabase = Arc::as_ptr(&writer);
        assert!(
            std::ptr::eq(pre_writer_ptr, original_ptr),
            "writer Arc must initially point at the original allocation"
        );
        let pre_strong = Arc::strong_count(&original_arc);
        assert!(
            pre_strong >= 2,
            "test setup requires shared Arc (strong_count >= 2); got {pre_strong}"
        );

        let _ = Arc::make_mut(&mut writer);

        let post_writer_ptr: *const EncodedDatabase = Arc::as_ptr(&writer);
        assert!(
            !std::ptr::eq(pre_writer_ptr, post_writer_ptr),
            "Arc::make_mut on a shared Arc MUST allocate a fresh buffer (CoW)"
        );
        // Sibling Arc (an in-flight query) must not see the writer's mutation.
        assert!(
            std::ptr::eq(Arc::as_ptr(&original_arc), original_ptr),
            "sibling Arc must remain pinned to the original allocation"
        );
    }
}
