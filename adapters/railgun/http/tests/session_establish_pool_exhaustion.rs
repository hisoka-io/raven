//! `POST /v1/instance/:id/session` carries no credential, so the pool it fills is a
//! resource an anonymous caller can spend. These pin that spending it never retires a
//! session some other caller established.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, PoisonError};
use std::time::Instant;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Method, Request, StatusCode},
};
use raven_inspire::inspiring::ClientPackingKeys;
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::{SeededClientQuery, ServerSessionHandle};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{heartbeat_session_eviction, setup_state, RavenInspireScheme};
use raven_railgun_engine::session_pool::{
    BoundedSessionStore, SessionStoreLimits, DEFAULT_MAX_SESSIONS,
};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
use raven_railgun_http::{inspire_router, write_versioned, AppState, HttpConfig};
use tower::ServiceExt;

const READ_TOKEN: &str = "BEARER-POOL-EXHAUSTION-padded-min-ab";
const INSTANCE_ID: &str = "session-pool-instance";
const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_BYTES: usize = 256;
const VICTIM_CLIENT: &str = "11111111111111111111111111111111";

static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Fixture {
    router: axum::Router,
    instance: Arc<PirInstance<RavenInspireScheme>>,
    victim_keys: Vec<u8>,
    attacker_keys: Vec<u8>,
    query: SeededClientQuery,
}

fn fixture() -> Fixture {
    fixture_with(HttpConfig::demo(READ_TOKEN), None)
}

/// `store_limits` stands in for the operator wiring that opens each instance's store from the
/// same config; `None` keeps the store at its compiled defaults.
fn fixture_with(config: HttpConfig, store_limits: Option<SessionStoreLimits>) -> Fixture {
    let params = InspireParams::secure_128_d2048();
    let db = raven_railgun_testkit::toy_db(TOY_ENTRIES, TOY_ENTRY_BYTES);
    let (mut state, sk) =
        setup_state(&params, &db, TOY_ENTRY_BYTES, InspireVariant::TwoPacking).expect("toy state");
    if let Some(limits) = store_limits {
        state.session_store = Arc::new(BoundedSessionStore::with_limits(limits));
    }

    let pack_params = state.cache.pack_params();
    let mut victim_sampler = GaussianSampler::with_seed(params.sigma, 11);
    let victim_keys = write_versioned(&ClientPackingKeys::generate(
        &sk,
        pack_params,
        state.crs.inspiring_w_seed,
        &mut victim_sampler,
    ))
    .expect("serialize victim keys");
    let mut attacker_sampler = GaussianSampler::with_seed(params.sigma, 12);
    let attacker_keys = write_versioned(&ClientPackingKeys::generate(
        &sk,
        pack_params,
        state.crs.inspiring_w_seed,
        &mut attacker_sampler,
    ))
    .expect("serialize attacker keys");

    let mut query_sampler = GaussianSampler::with_seed(params.sigma, 13);
    let (_client_state, query) = raven_inspire::query_seeded(
        state.crs.as_ref(),
        0,
        state.shard_config(),
        &sk,
        &mut query_sampler,
    )
    .expect("query template");

    let instance_id = InstanceId::new(INSTANCE_ID);
    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    engine
        .add_instance(PirInstance::new(
            instance_id.clone(),
            InstanceRole::Live,
            state,
        ))
        .expect("register instance");
    let instance = engine.instance(&instance_id).expect("instance just added");
    let app_state = {
        let _g = APPSTATE_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        AppState::new(engine, config).expect("appstate")
    };
    Fixture {
        router: inspire_router(app_state).expect("router build"),
        instance,
        victim_keys,
        attacker_keys,
        query,
    }
}

/// No `Authorization` header at all: `required_scope` leaves this route public, and the
/// attack is only interesting if it needs nothing.
fn anonymous_request(route: &str, client_id: &str, body: Vec<u8>) -> Request<Body> {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/instance/{INSTANCE_ID}/{route}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header("x-raven-client-id", client_id)
        .body(Body::from(body))
        .expect("build request");
    request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        12_345,
    )));
    request
}

fn client_id_of(index: usize) -> String {
    format!("{:032x}", 0xa000_0000_u64 + index as u64)
}

async fn establish(router: &axum::Router, client_id: &str, body: Vec<u8>) -> (StatusCode, u64) {
    let response = router
        .clone()
        .oneshot(anonymous_request("session", client_id, body))
        .await
        .expect("session dispatch");
    let status = response.status();
    let handle = response
        .headers()
        .get("x-raven-session")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_default();
    (status, handle)
}

async fn query_status(
    router: &axum::Router,
    client_id: &str,
    query: &SeededClientQuery,
    handle: u64,
) -> StatusCode {
    let mut bound = query.clone();
    bound.session_handle = Some(ServerSessionHandle(handle));
    bound.inspiring_packing_keys = None;
    router
        .clone()
        .oneshot(anonymous_request(
            "query",
            client_id,
            write_versioned(&bound).expect("query body"),
        ))
        .await
        .expect("query dispatch")
        .status()
}

#[tokio::test]
async fn an_anonymous_establish_storm_cannot_retire_another_callers_session() {
    let Fixture {
        router,
        instance,
        victim_keys,
        attacker_keys,
        query,
    } = fixture();

    let (victim_status, victim_handle) = establish(&router, VICTIM_CLIENT, victim_keys).await;
    assert_eq!(
        victim_status,
        StatusCode::OK,
        "premise: the victim establishes with no credential at all"
    );
    assert_eq!(
        query_status(&router, VICTIM_CLIENT, &query, victim_handle).await,
        StatusCode::OK,
        "premise: the victim's session serves a query before the storm"
    );

    // One request per pool slot, all anonymous, all from one peer, well inside the
    // 200 rps / 400 burst the route is limited to.
    let mut refused = 0usize;
    for index in 0..DEFAULT_MAX_SESSIONS {
        let (status, _) = establish(&router, &client_id_of(index), attacker_keys.clone()).await;
        if status != StatusCode::OK {
            refused += 1;
        }
    }

    let store = instance.current_state();
    let flushes = store.session_store.flushes_total();
    assert_eq!(
        query_status(&router, VICTIM_CLIENT, &query, victim_handle).await,
        StatusCode::OK,
        "the victim's next query must still be served after {DEFAULT_MAX_SESSIONS} anonymous \
         establishes ({refused} refused, {flushes} whole-generation reclamations)"
    );
    assert!(
        store
            .session_store
            .resolve(Some(ServerSessionHandle(victim_handle)), Instant::now())
            .is_ok(),
        "the victim's packing keys must survive the storm"
    );
    assert_eq!(flushes, 0, "no establish may reclaim a whole generation");

    // A session the operator genuinely retires still dies.
    heartbeat_session_eviction(&instance).expect("evict session generation");
    assert_eq!(
        query_status(&router, VICTIM_CLIENT, &query, victim_handle).await,
        StatusCode::CONFLICT,
        "an operator-retired generation must still refuse the handle"
    );
}

#[tokio::test]
async fn re_establishing_under_one_identity_costs_the_pool_one_slot() {
    let Fixture {
        router,
        instance,
        victim_keys,
        ..
    } = fixture();

    let mut last: Option<u64> = None;
    for round in 0..4 {
        let (status, handle) = establish(&router, VICTIM_CLIENT, victim_keys.clone()).await;
        assert_eq!(status, StatusCode::OK, "re-establish {round} must succeed");
        assert_ne!(
            Some(handle),
            last,
            "each handshake must mint a fresh handle (round {round})"
        );
        last = Some(handle);
        assert_eq!(
            instance.current_state().session_store.len(),
            1,
            "one identity must never hold more than one slot (round {round})"
        );
    }

    let last = last.expect("four rounds ran");
    assert!(
        instance
            .current_state()
            .session_store
            .resolve(Some(ServerSessionHandle(last)), Instant::now())
            .is_ok(),
        "the surviving slot must be the newest handshake"
    );
}

#[tokio::test]
async fn a_full_pool_refuses_a_new_identity_instead_of_retiring_an_old_one() {
    let Fixture {
        router,
        instance,
        attacker_keys,
        ..
    } = fixture();

    let mut first_handle = None;
    for index in 0..DEFAULT_MAX_SESSIONS {
        let (status, handle) =
            establish(&router, &client_id_of(index), attacker_keys.clone()).await;
        assert_eq!(status, StatusCode::OK, "slot {index} must be admitted");
        first_handle.get_or_insert(handle);
    }
    let first_handle = first_handle.expect("at least one slot");

    let (status, _) = establish(
        &router,
        &client_id_of(DEFAULT_MAX_SESSIONS),
        attacker_keys.clone(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a full pool must refuse rather than reclaim"
    );
    assert!(
        instance
            .current_state()
            .session_store
            .resolve(Some(ServerSessionHandle(first_handle)), Instant::now())
            .is_ok(),
        "the refusal must leave the oldest live session serving"
    );
}

/// The storm again, at a pool the operator sized rather than the compiled default: the
/// configured ceiling is what refuses, and it still refuses instead of retiring the victim.
#[tokio::test]
async fn an_anonymous_storm_at_a_configured_pool_size_cannot_retire_a_session() {
    const SEATS: usize = 4;
    let mut config = HttpConfig::demo(READ_TOKEN);
    config.max_sessions_per_instance = SEATS;
    let limits = config.session_store_limits();
    let Fixture {
        router,
        instance,
        victim_keys,
        attacker_keys,
        query,
    } = fixture_with(config, Some(limits));

    let (victim_status, victim_handle) = establish(&router, VICTIM_CLIENT, victim_keys).await;
    assert_eq!(
        victim_status,
        StatusCode::OK,
        "premise: the victim holds a seat"
    );

    let mut admitted = 0usize;
    for index in 0..SEATS * 2 {
        let (status, _) = establish(&router, &client_id_of(index), attacker_keys.clone()).await;
        match status {
            StatusCode::OK => admitted += 1,
            StatusCode::SERVICE_UNAVAILABLE => {}
            other => panic!("establish {index}: {other} is neither a seat nor a refusal"),
        }
    }

    assert_eq!(
        admitted,
        SEATS - 1,
        "the configured {SEATS}-seat pool, not the {DEFAULT_MAX_SESSIONS}-seat default, must bound \
         the storm"
    );
    let store = instance.current_state();
    assert_eq!(store.session_store.len(), SEATS);
    assert_eq!(store.session_store.flushes_total(), 0);
    assert_eq!(
        query_status(&router, VICTIM_CLIENT, &query, victim_handle).await,
        StatusCode::OK,
        "the victim must still be served once the configured pool is full"
    );
}

/// A binding that lapses before its seat strands the seat: the re-handshake finds nothing to
/// take, and one identity then holds two seats until the store's own expiry.
#[tokio::test]
async fn a_binding_lives_as_long_as_its_seat_not_the_http_lifetime() {
    let mut config = HttpConfig::demo(READ_TOKEN);
    config.session_ttl_secs = 1;
    let Fixture {
        router,
        instance,
        victim_keys,
        query,
        ..
    } = fixture_with(config, None);

    let (status, handle) = establish(&router, VICTIM_CLIENT, victim_keys.clone()).await;
    assert_eq!(status, StatusCode::OK);
    tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;

    assert_eq!(
        query_status(&router, VICTIM_CLIENT, &query, handle).await,
        StatusCode::OK,
        "the seat is still live, so its binding must be too"
    );
    let (status, _) = establish(&router, VICTIM_CLIENT, victim_keys).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        instance.current_state().session_store.len(),
        1,
        "a re-handshake must release the seat it replaces"
    );
}
