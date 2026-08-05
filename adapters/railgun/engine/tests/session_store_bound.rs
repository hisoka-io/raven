//! The session store stays under its cap on the production
//! `register_client_session` / `respond` path, and a retired handle fails closed.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use raven_inspire::params::{InspireParams, InspireVariant};
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

    // Third registration trips the backstop; the fresh generation restarts
    // numbering, so only the lowest handle is reissued.
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
        matches!(err, raven_railgun_core::AdapterError::InvalidQuery(_)),
        "an unknown handle is a caller defect, not a scheme failure: {err:?}"
    );
}

#[test]
fn a_live_session_still_serves_its_own_queries() {
    let (params, state, mut session, db) = capped_state();
    register_client_session(&mut session, &state).expect("register");
    let (client_state, query) =
        build_seeded_query(&session, state.shard_config(), 3, &params).expect("build query");
    let response =
        <RavenInspireScheme as PirScheme>::respond(&state, &query).expect("live session serves");
    let plaintext = extract_response(state.crs.as_ref(), &client_state, &response, ENTRY_SIZE)
        .expect("extract");
    assert_eq!(
        plaintext,
        db.get(3 * ENTRY_SIZE..4 * ENTRY_SIZE).expect("record"),
        "bounding must not disturb a live session's answers"
    );
}
