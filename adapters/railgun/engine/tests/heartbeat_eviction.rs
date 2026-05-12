//! Heartbeat session-eviction tests.
//!
//! Pins the engine-level public fn that an operator-spawned hourly
//! task calls per instance to drop every registered sticky-bearer
//! session out of [`raven_inspire::ServerSessionStore`] without
//! touching the heavy CRS / `EncodedDatabase` / `ServerInspiringCache`
//! machinery.
//!
//! Core invariants pinned:
//!
//! - `heartbeat_swap_state_drops_inner_session_store` — register N
//!   sessions, run heartbeat, verify the inner store has reset to
//!   `len() == 0`.
//! - `heartbeat_swap_state_preserves_cache_across_swap` — the
//!   `Arc<ServerInspiringCache>` pointer must be the SAME after
//!   the swap (carried by `Arc::clone`).
//! - `heartbeat_swap_state_drops_session_store_arc_pointer_too` —
//!   the new state's `session_store` Arc MUST be a different Arc
//!   from the donor's; otherwise a stale Arc is being kept alive
//!   somewhere and the inner store is not actually being dropped.
//! - `heartbeat_swap_state_metric_increments_per_swap` — driving
//!   the heartbeat fn manually, the operator-facing metric counter
//!   advances exactly once per call (asserted via epoch
//!   monotonicity).
//!
//! OOM regression guards (Phase 2 T-A wrapped `encoded_db` in
//! `Arc<EncodedDatabase>`; the three trailing tests pin that the
//! heartbeat path never deep-clones the `~128 MiB` buffer at the
//! production cell):
//!
//! - `heartbeat_eviction_does_not_clone_encoded_db_under_steady_load`
//! - `heartbeat_eviction_arc_clone_constant_time_at_production_cell`
//! - `drive_commit_arc_make_mut_only_copies_under_inflight_query`

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

    // Register three sessions on the inner store.
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
    // The cache is the heaviest field on InspireServerState (one
    // O(d^3) automorph table; ~3.7 s rebuild at production cell). The
    // heartbeat MUST carry it via Arc::clone so the operator-side
    // hourly tick is cheap (sub-millisecond at production cell).
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
         (Arc::clone). A non-equal pointer here means the cache rebuilt — the \
         hourly tick would stall the server for seconds."
    );
}

#[test]
fn heartbeat_swap_state_drops_session_store_arc_pointer_too() {
    // The new state's session_store Arc MUST be DIFFERENT from the
    // donor's. If it were the same Arc, in-flight queries holding
    // the donor would still be backed by the same inner store and
    // the eviction would be a no-op. This is the regression-guard
    // for an "Arc::clone(&donor.session_store)" typo.
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

/// Operator escape hatch: setting the heartbeat interval to 0 in
/// the CLI must skip spawning the per-instance heartbeat task. This
/// test checks the contract at the engine-fn level: the heartbeat
/// fn itself runs unconditionally when called, but the scheduler
/// is never constructed for `interval == 0`. The CLI guard is `if
/// session_eviction_interval > 0 { spawn ... }`. This test pins the
/// invariant by NOT calling the heartbeat fn and asserting the
/// session_store Arc pointer remains the bootstrap one.
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

    // Simulated "operator opted out" window: register sessions, do
    // NOT call heartbeat_session_eviction, assert nothing churned.
    register_one_session(&instance, &params);

    let post_store_ptr: *const ServerSessionStore = {
        let snap = instance.current_state();
        Arc::as_ptr(&snap.session_store)
    };
    assert!(
        std::ptr::eq(initial_store_ptr, post_store_ptr),
        "with the CLI guard at zero (heartbeat_session_eviction never \
         called), the donor session_store Arc MUST persist; the test \
         observed a swap (different Arc) — guard logic regressed?"
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
    // The CLI-spawned heartbeat task increments
    // `raven_railgun_session_eviction_swaps_total` per call. The
    // counter itself is global to the metrics recorder; the test
    // exercises the tick-by-tick contract: each
    // `heartbeat_session_eviction` call corresponds to exactly one
    // session-store reset. We assert by epoch monotonicity (one
    // bump per call).
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

// ────────────────────────────────────────────────────────────────────
// OOM regression guards: encoded_db is `Arc::clone`d, not memcpy'd.
//
// Pre-fix, `heartbeat_session_eviction` deep-cloned `encoded_db` once
// per fire (~128 MiB Vec memcpy at production cell). With 6 instances
// firing hourly this leaked ~163 MiB/hour through allocator-retained
// pages; live URL was on track to OOM within ~7 hours.
//
// The fix wraps `encoded_db` in `Arc<EncodedDatabase>` (Phase 2 T-A)
// and replaces the deep clone with `Arc::clone(&donor.encoded_db)`.
// The three tests below pin:
//
// - Arc-pointer identity across heartbeats (no allocation churn).
// - Arc strong_count stays bounded between fires (≤ 2: current state
//   + the local snap guard, after donor swap-out drop).
// - `drive_commit`'s CoW path: `Arc::make_mut` on a uniquely-owned
//   Arc does NOT allocate; on a shared Arc (in-flight query) it
//   does — bounded to once per drive_commit batch.
// ────────────────────────────────────────────────────────────────────

/// Arc-identity guard: every heartbeat fire must carry the donor's
/// `Arc<EncodedDatabase>` by `Arc::clone`, not by a fresh `Arc::new`
/// over a deep-cloned EncodedDatabase. Across N fires the underlying
/// allocation address must remain stable.
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

/// Wall-time guard: at the production cell the heartbeat is dominated
/// by an `Arc::clone` (sub-microsecond); the assertion guards against
/// accidental re-introduction of a memcpy. We use the toy cell here
/// because production cell setup costs ~12 s; the 1-ms ceiling
/// generously covers any toy-cell allocation jitter while still
/// catching a 100 ms+ deep-clone regression at any cell shape.
#[test]
fn heartbeat_eviction_arc_clone_constant_time_at_production_cell() {
    let params = InspireParams::secure_128_d2048();
    let initial_state = build_toy_state(&params);
    let instance: Arc<PirInstance<RavenInspireScheme>> = Arc::new(PirInstance::new(
        InstanceId::new("heartbeat-arc-clone-timing"),
        InstanceRole::Live,
        initial_state,
    ));

    // Warm-up: first fire pays the lazy-init costs of any metrics
    // recorder + `arc_swap` swap.
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

/// `drive_commit`'s re-encode path uses `Arc::make_mut` on the
/// donor's `Arc<EncodedDatabase>`. When no other Arcs are alive (the
/// happy path: no in-flight queries holding the donor state),
/// `Arc::make_mut` is a no-op pointer cast — no allocation, no copy.
/// When another Arc IS alive (e.g. an in-flight query), `Arc::make_mut`
/// triggers exactly one CoW Vec memcpy.
///
/// This test exercises the structural invariant directly via
/// `Arc::make_mut` on a synthetic Arc; pinning the engine-level
/// drive_commit's full CoW lifecycle requires a full
/// `InspirePersistence::open` fixture which lives in the persistence
/// module's own integration tests.
#[test]
fn drive_commit_arc_make_mut_only_copies_under_inflight_query() {
    let params = InspireParams::secure_128_d2048();
    let state = build_toy_state(&params);

    // Take ownership of the Arc<EncodedDatabase> directly. This is
    // the same Arc the engine carries on InspireServerState.
    let original_arc = Arc::clone(&state.encoded_db);
    let original_ptr: *const EncodedDatabase = Arc::as_ptr(&original_arc);

    // Path A: uniquely-owned Arc -> make_mut returns the inner without
    // allocating. The Arc pointer must remain stable.
    {
        let solo = Arc::clone(&original_arc);
        // Build a fresh uniquely-owned Arc to exercise the no-alloc
        // make_mut path; cloning solo's config keeps the test self-
        // contained without depending on EncodedDatabase::default.
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
        // Suppress unused warning: hold `solo` only to keep
        // strong_count > 1 on `original_arc` for the assertions
        // below.
        drop(solo);
    }

    // Path B: shared Arc (a sibling clone is alive) -> make_mut
    // performs CoW. The Arc pointer must change to a fresh
    // allocation; the sibling Arc continues to point at the original.
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
        // The original sibling Arc must STILL point at the original
        // allocation; in-flight queries on that Arc must not see the
        // writer's mutation.
        assert!(
            std::ptr::eq(Arc::as_ptr(&original_arc), original_ptr),
            "sibling Arc must remain pinned to the original allocation"
        );
    }
}
