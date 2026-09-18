//! The session store stays under its cap on the production
//! `register_client_session` / `respond` path, and a retired handle fails closed.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::rgsw::GadgetVector;
use raven_inspire::{ServerInspiringCache, ServerSessionHandle};
use raven_railgun_engine::inspire::{
    build_client_session, build_seeded_query, extract_response, register_client_session,
    setup_state, InspireServerState, RavenInspireScheme,
};
use raven_railgun_engine::session_pool::{BoundedSessionStore, SessionStoreLimits};
use raven_railgun_engine::PirScheme;

const ENTRY_SIZE: usize = 32;
const ENTRIES: usize = 256;
const CAP: usize = 2;

fn database() -> Vec<u8> {
    (0..ENTRIES)
        .flat_map(|i| (0..ENTRY_SIZE).map(move |j| u8::try_from((i * 5 + j) % 251).expect("< 251")))
        .collect()
}

/// Server state whose session store is capped low enough to exercise the
/// backstop without registering 64 production-sized key sets.
fn capped_state() -> (
    InspireParams,
    InspireServerState,
    raven_inspire::ClientSession,
    Vec<u8>,
) {
    let params = InspireParams::secure_128_d2048();
    let db = database();
    let (base, sk) =
        setup_state(&params, &db, ENTRY_SIZE, InspireVariant::TwoPacking).expect("setup_state");
    let cache = ServerInspiringCache::new(base.crs.as_ref(), base.encoded_db.as_ref())
        .expect("cache rebuild");
    let state = InspireServerState {
        crs: Arc::clone(&base.crs),
        encoded_db: Arc::clone(&base.encoded_db),
        cache: Arc::new(cache),
        session_store: Arc::new(BoundedSessionStore::with_limits(SessionStoreLimits {
            max_sessions: CAP,
            ttl: Duration::from_secs(3600),
        })),
        variant: base.variant,
        entry_size: base.entry_size,
    };
    let crs = (*state.crs).clone();
    let session = build_client_session(crs, sk, &params).expect("client session");
    (params, state, session, db)
}

#[test]
fn occupancy_stays_under_the_cap_across_repeated_registration() {
    let (_params, state, mut session, _db) = capped_state();
    for i in 0..12u32 {
        register_client_session(&mut session, &state).expect("register");
        assert!(
            state.session_store.len() <= CAP,
            "occupancy {} exceeded cap {CAP} after {} registrations; the pre-fix \
             store grew to the registration count",
            state.session_store.len(),
            i + 1
        );
    }
    assert!(
        state.session_store.flushes_total() >= 1,
        "12 registrations at cap {CAP} must have hit the backstop at least once"
    );
    assert!(
        state.session_store.evicted_total() >= 10,
        "evictions must be counted; got {}",
        state.session_store.evicted_total()
    );
}

#[test]
fn a_retired_handle_is_refused_instead_of_served() {
    let (params, state, mut session, _db) = capped_state();
    register_client_session(&mut session, &state).expect("register 1");
    register_client_session(&mut session, &state).expect("register 2");
    let retired = session.session_handle().expect("handle after register 2");

    // Third registration trips the backstop; core handle allocation remains monotonic.
    register_client_session(&mut session, &state).expect("register 3");
    assert!(state.session_store.flushes_total() >= 1);
    assert!(
        retired.0 > 0,
        "the second handle must be above the reissue window for this assertion to bite"
    );

    let (_client_state, mut query) =
        build_seeded_query(&session, state.shard_config(), 1, &params).expect("build query");
    query.session_handle = Some(retired);
    let err = <RavenInspireScheme as PirScheme>::respond(&state, &query)
        .expect_err("a retired handle must not be served");
    let msg = format!("{err}");
    assert!(
        msg.contains("not registered") && msg.contains("handshake"),
        "the refusal must tell the caller to re-handshake: {msg}"
    );
}

#[test]
fn an_unknown_handle_never_reaches_the_inner_store() {
    let (params, state, mut session, _db) = capped_state();
    register_client_session(&mut session, &state).expect("register");
    let (_client_state, mut query) =
        build_seeded_query(&session, state.shard_config(), 0, &params).expect("build query");
    query.session_handle = Some(ServerSessionHandle(u64::MAX));
    let err = <RavenInspireScheme as PirScheme>::respond(&state, &query)
        .expect_err("unknown handle must be refused");
    assert!(
        matches!(
            err,
            raven_railgun_core::AdapterError::SessionHandleRejected { .. }
        ),
        "an unknown handle must retain its typed session refusal: {err:?}"
    );
}

#[test]
fn live_adapter_refuses_a_legacy_three_row_query_before_expansion() {
    let (params, state, mut session, _db) = capped_state();
    register_client_session(&mut session, &state).expect("register");
    let (_client_state, mut query) =
        build_seeded_query(&session, state.shard_config(), 0, &params).expect("build query");
    let row = query
        .rgsw_ciphertext
        .rows
        .first()
        .expect("current query has one row")
        .clone();
    query.rgsw_ciphertext.rows = vec![row.clone(), row.clone(), row];
    query.rgsw_ciphertext.gadget = GadgetVector::new(params.gadget_base, 3, params.q);

    let error = <RavenInspireScheme as PirScheme>::respond(&state, &query)
        .expect_err("the live adapter must reject the legacy query shape");
    let message = error.to_string();
    assert!(
        message.contains("RGSW gadget mismatch")
            && message.contains("got len=3")
            && message.contains("expected len=1"),
        "legacy query reached expansion or returned the wrong refusal: {message}"
    );
}

/// A wire client holds the same process-global handle that keys the core store.
#[test]
fn a_wire_handle_is_the_core_handle_the_store_is_keyed_on() {
    let (params, state, mut session, db) = capped_state();
    let wire_handle = state
        .session_store
        .register_client_session_at(&mut session, std::time::Instant::now())
        .expect("register")
        .expect("the session carries packing keys");
    let inner = session
        .session_handle()
        .expect("the session baked a handle");
    assert_eq!(
        wire_handle.0, inner.0,
        "the adapter must not translate the process-global core handle into another namespace"
    );

    let (client_state, mut query) =
        build_seeded_query(&session, state.shard_config(), 3, &params).expect("build query");
    query.session_handle = Some(wire_handle);
    let response = <RavenInspireScheme as PirScheme>::respond(&state, &query)
        .expect("a handle in the form a wire client holds must serve");
    let plaintext = extract_response(state.crs.as_ref(), &client_state, &response, ENTRY_SIZE)
        .expect("extract");
    assert_eq!(
        plaintext,
        db.get(3 * ENTRY_SIZE..4 * ENTRY_SIZE).expect("record"),
        "the handle must resolve to the caller's OWN packing keys, not merely to some \
         entry that happens to exist"
    );

    // The in-process wrapper installs the same core-issued handle.
    register_client_session(&mut session, &state).expect("register via the production wrapper");
    let (wrapped_state, wrapped_query) =
        build_seeded_query(&session, state.shard_config(), 3, &params).expect("build query");
    let wrapped_response = <RavenInspireScheme as PirScheme>::respond(&state, &wrapped_query)
        .expect("live session serves");
    let wrapped_plaintext = extract_response(
        state.crs.as_ref(),
        &wrapped_state,
        &wrapped_response,
        ENTRY_SIZE,
    )
    .expect("extract");
    assert_eq!(
        wrapped_plaintext,
        db.get(3 * ENTRY_SIZE..4 * ENTRY_SIZE).expect("record"),
        "bounding must not disturb a live session's answers"
    );
}

/// A flushed handle stays unique because allocation is process-global in the core store.
#[test]
fn a_flushed_core_handle_is_refused_and_never_reissued() {
    let (_params, state, mut session, _db) = capped_state();
    let now = std::time::Instant::now();

    let stale = state
        .session_store
        .register_client_session_at(&mut session, now)
        .expect("first registration")
        .expect("the session carries packing keys");

    // Fill to the cap so the backstop replaces the store.
    for _ in 0..=CAP {
        let _ = state
            .session_store
            .register_client_session_at(&mut session, now);
    }

    let reissued = state
        .session_store
        .register_client_session_at(&mut session, now)
        .expect("post-flush registration")
        .expect("the session carries packing keys");

    assert!(
        state.session_store.flushes_total() >= 1,
        "premise: the cap was reached and a flush happened"
    );
    assert_ne!(
        stale.0, reissued.0,
        "a core handle must never be reused when the bounded store is replaced"
    );

    let err = state
        .session_store
        .resolve(Some(stale), now)
        .expect_err("a handle from a superseded generation must fail closed");
    let msg = err.to_string();
    assert!(
        msg.contains("not registered"),
        "the replacement store must not contain the flushed core handle; got: {msg}"
    );

    let (_store, inner) = state
        .session_store
        .resolve(Some(reissued), now)
        .expect("the live handle still resolves");
    assert!(
        inner.is_some(),
        "a resolved wire handle must reach the core store"
    );
}
