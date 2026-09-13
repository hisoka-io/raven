//! `/v1/instance/:id/session`: the happy path and the epoch-swap refusal.
//!
//! The pin needs an epoch swap to land inside the handler's capture-then-register
//! window. `session_establish_handler` has no `.await` in its body, so no other
//! task on the thread can preempt it - but production itself calls out inside the
//! window: `BoundedSessionStore::register_server_side_at` publishes the occupancy
//! gauges after the handle is serviceable and before returning to the handler.
//! A thread-local `metrics` recorder is therefore enough to order the swap
//! deterministically, with no sleep, no second thread, and no test-only hook in
//! production code. The swap itself goes through the public
//! `heartbeat_session_eviction` -> `PirInstance::swap_state` path.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::Instant;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use metrics::{Counter, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit};
use raven_inspire::inspiring::ClientPackingKeys;
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::{
    ClientState, SeededClientQuery, ServerCrs, ServerResponse, ServerSessionHandle,
};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{heartbeat_session_eviction, setup_state, RavenInspireScheme};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
use raven_railgun_http::{
    inspire_router, read_batch_response_versioned, read_versioned, write_versioned, AppState,
    FanoutRequest, HttpConfig, SessionEstablishResponse,
};
use tower::ServiceExt;

const READ_TOKEN: &str = "BEARER-SESSION-TEST-padded-min-len-ab";
const INSTANCE_ID: &str = "session-route-instance";
const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_BYTES: usize = 256;
const CLIENT_ID: &str = "00112233445566778899aabbccddeeff";

/// Published by `BoundedSessionStore::register_server_side_at` after the freshly
/// minted handle is serviceable and before the handler checks its captured epoch.
const OCCUPANCY_GAUGE: &str = "raven_railgun_session_store_occupancy";

static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// One booted instance behind a router, plus the `Arc` the swap path needs.
struct Fixture {
    router: axum::Router,
    instance: Arc<PirInstance<RavenInspireScheme>>,
    body: Vec<u8>,
    query: SeededClientQuery,
    client_state: ClientState,
    crs: Arc<ServerCrs>,
    expected: Vec<u8>,
    ttl_secs: u64,
}

fn fixture() -> Fixture {
    let params = InspireParams::secure_128_d2048();
    let db = raven_railgun_testkit::toy_db(TOY_ENTRIES, TOY_ENTRY_BYTES);
    let (state, sk) =
        setup_state(&params, &db, TOY_ENTRY_BYTES, InspireVariant::TwoPacking).expect("toy state");

    // Client-side half of the handshake, from the same CRS the server serves.
    let keys = {
        let pack_params = state.cache.pack_params();
        let mut sampler = GaussianSampler::with_seed(params.sigma, 7);
        ClientPackingKeys::generate(&sk, pack_params, state.crs.inspiring_w_seed, &mut sampler)
    };
    let body = write_versioned(&keys).expect("serialize ClientPackingKeys");
    let mut query_sampler = GaussianSampler::with_seed(params.sigma, 8);
    let (client_state, query) = raven_inspire::query_seeded(
        state.crs.as_ref(),
        0,
        state.shard_config(),
        &sk,
        &mut query_sampler,
    )
    .expect("query template");

    let instance_id = InstanceId::new(INSTANCE_ID);
    let crs = Arc::clone(&state.crs);
    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    engine
        .add_instance(PirInstance::new(
            instance_id.clone(),
            InstanceRole::Live,
            state,
        ))
        .expect("register instance");
    // Taken before the engine moves into the AppState; it is the same `Arc` the
    // handler resolves, so a swap through it is visible to the handler.
    let instance = engine.instance(&instance_id).expect("instance just added");
    let mut cfg = HttpConfig::demo(READ_TOKEN);
    cfg.enable_fanout = true;
    let ttl_secs = cfg.session_ttl_secs;
    let app_state = {
        let _g = APPSTATE_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        AppState::new(engine, cfg).expect("appstate")
    };
    Fixture {
        router: inspire_router(app_state).expect("router build"),
        instance,
        body,
        query,
        client_state,
        crs,
        expected: db.get(..TOY_ENTRY_BYTES).expect("first record").to_vec(),
        ttl_secs,
    }
}

fn query_request(route: &str, client_id: Option<&str>, body: Vec<u8>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/instance/{INSTANCE_ID}/{route}"))
        .header(header::AUTHORIZATION, format!("Bearer {READ_TOKEN}"))
        .header(header::CONTENT_TYPE, "application/octet-stream");
    if let Some(client_id) = client_id {
        builder = builder.header("x-raven-client-id", client_id);
    }
    let mut request = builder.body(Body::from(body)).expect("build query request");
    request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        12_345,
    )));
    request
}

fn session_request(body: Vec<u8>) -> Request<Body> {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/instance/{INSTANCE_ID}/session"))
        .header(header::AUTHORIZATION, format!("Bearer {READ_TOKEN}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header("x-raven-client-id", CLIENT_ID)
        .body(Body::from(body))
        .expect("build session req");
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        12_345,
    )));
    req
}

#[tokio::test]
async fn session_establishment_requires_a_valid_client_id() {
    let Fixture {
        router,
        instance,
        body,
        ..
    } = fixture();
    let mut missing = session_request(body.clone());
    missing.headers_mut().remove("x-raven-client-id");
    let missing_response = router
        .clone()
        .oneshot(missing)
        .await
        .expect("missing dispatch");
    assert_eq!(missing_response.status(), StatusCode::BAD_REQUEST);

    let mut malformed = session_request(body);
    malformed.headers_mut().insert(
        "x-raven-client-id",
        "not-a-client-id".parse().expect("header"),
    );
    let malformed_response = router.oneshot(malformed).await.expect("malformed dispatch");
    assert_eq!(malformed_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        instance.current_state().session_store.len(),
        0,
        "invalid identity must be refused before key registration"
    );
}

#[tokio::test]
async fn valid_packing_keys_establish_a_session_with_handle_and_expiry() {
    let Fixture {
        router,
        body,
        ttl_secs,
        ..
    } = fixture();
    let req = session_request(body);

    let before_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let resp = router.oneshot(req).await.expect("dispatch");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a valid session establish must 200"
    );
    let session_header = resp
        .headers()
        .get("x-raven-session")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .expect("x-raven-session header must carry the numeric handle");

    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec();
    let decoded: SessionEstablishResponse =
        serde_json::from_slice(&bytes).expect("decode SessionEstablishResponse");
    assert_eq!(
        decoded.handle, session_header,
        "body handle and x-raven-session header must agree"
    );
    assert!(
        decoded.expires_at_unix_secs >= before_unix + ttl_secs - 2,
        "expires_at must reflect the configured TTL ({ttl_secs}s); got {} at now {before_unix}",
        decoded.expires_at_unix_secs
    );
}

#[tokio::test]
async fn every_handle_route_is_bound_to_the_establishing_client() {
    let Fixture {
        router,
        body,
        mut query,
        client_state,
        crs,
        expected,
        instance,
        ..
    } = fixture();
    let session_response = router
        .clone()
        .oneshot(session_request(body))
        .await
        .expect("session dispatch");
    let handle = session_response
        .headers()
        .get("x-raven-session")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .expect("session handle");
    let inline_query = query.clone();
    query.session_handle = Some(ServerSessionHandle(handle));
    query.inspiring_packing_keys = None;

    assert_handle_identity_matrix(&router, &query).await;
    assert_single_successes(
        &router,
        &inline_query,
        &query,
        &crs,
        &client_state,
        &expected,
    )
    .await;
    assert_batch_and_fanout_successes(&router, &query, &crs, &client_state, &expected).await;
    assert_wrong_client_refusals(&router, &query).await;

    heartbeat_session_eviction(&instance).expect("evict session generation");
    let retired_status = router
        .oneshot(query_request(
            "query",
            Some(CLIENT_ID),
            write_versioned(&query).expect("retired body"),
        ))
        .await
        .expect("retired dispatch")
        .status();
    assert_eq!(retired_status, StatusCode::CONFLICT);
}

async fn assert_handle_identity_matrix(router: &axum::Router, query: &SeededClientQuery) {
    for (client_id, expected_status) in [
        (None, StatusCode::BAD_REQUEST),
        (Some("malformed"), StatusCode::BAD_REQUEST),
    ] {
        let status = router
            .clone()
            .oneshot(query_request(
                "query",
                client_id,
                write_versioned(query).expect("identity body"),
            ))
            .await
            .expect("identity dispatch")
            .status();
        assert_eq!(status, expected_status);
    }
}

async fn assert_single_successes(
    router: &axum::Router,
    inline_query: &SeededClientQuery,
    handle_query: &SeededClientQuery,
    crs: &ServerCrs,
    client_state: &ClientState,
    expected: &[u8],
) {
    for (client_id, query) in [(None, inline_query), (Some(CLIENT_ID), handle_query)] {
        let response = router
            .clone()
            .oneshot(query_request(
                "query",
                client_id,
                write_versioned(query).expect("single body"),
            ))
            .await
            .expect("single dispatch");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("single response body")
            .to_bytes();
        let decoded: ServerResponse = read_versioned(&bytes).expect("single response");
        let plaintext = raven_railgun_engine::inspire::extract_response(
            crs,
            client_state,
            &decoded,
            TOY_ENTRY_BYTES,
        )
        .expect("single extract");
        assert_eq!(plaintext, expected);
    }
}

async fn assert_batch_and_fanout_successes(
    router: &axum::Router,
    query: &SeededClientQuery,
    crs: &ServerCrs,
    client_state: &ClientState,
    expected: &[u8],
) {
    let bodies = [
        (
            "batch",
            write_versioned(&vec![query.clone()]).expect("batch body"),
        ),
        (
            "fanout",
            write_versioned(&FanoutRequest {
                query: query.clone(),
                shard_ids: vec![0],
            })
            .expect("fanout body"),
        ),
    ];
    for (route, body) in bodies {
        let response = router
            .clone()
            .oneshot(query_request(route, Some(CLIENT_ID), body))
            .await
            .expect("multi-response dispatch");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("multi-response body")
            .to_bytes();
        let decoded: Vec<ServerResponse> =
            read_batch_response_versioned(&bytes).expect("multi-response decode");
        let first = decoded.first().expect("one response");
        let plaintext = raven_railgun_engine::inspire::extract_response(
            crs,
            client_state,
            first,
            TOY_ENTRY_BYTES,
        )
        .expect("multi-response extract");
        assert_eq!(plaintext, expected);
    }
}

async fn assert_wrong_client_refusals(router: &axum::Router, query: &SeededClientQuery) {
    let wrong_client = "ffeeddccbbaa99887766554433221100";
    let bodies = [
        ("query", write_versioned(query).expect("single body")),
        (
            "batch",
            write_versioned(&vec![query.clone()]).expect("batch body"),
        ),
        (
            "fanout",
            write_versioned(&FanoutRequest {
                query: query.clone(),
                shard_ids: vec![0],
            })
            .expect("fanout body"),
        ),
    ];
    for (route, body) in bodies {
        let status = router
            .clone()
            .oneshot(query_request(route, Some(wrong_client), body))
            .await
            .expect("wrong-client dispatch")
            .status();
        assert_eq!(status, StatusCode::CONFLICT);
    }
}

/// Fires one epoch swap when registration publishes its occupancy after the handle becomes
/// serviceable and before the handler checks the captured epoch.
struct SwapOnFirstOccupancyPublish {
    instance: Arc<PirInstance<RavenInspireScheme>>,
    fired: Arc<AtomicBool>,
}

impl Recorder for SwapOnFirstOccupancyPublish {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}

    fn register_counter(&self, _: &Key, _: &Metadata<'_>) -> Counter {
        Counter::noop()
    }

    fn register_gauge(&self, key: &Key, _: &Metadata<'_>) -> Gauge {
        if key.name() == OCCUPANCY_GAUGE && !self.fired.swap(true, Ordering::SeqCst) {
            // The public operator-flush path: same geometry, empty session store,
            // epoch + 1. It reads only the donor's crs/db/cache.
            heartbeat_session_eviction(&self.instance).expect("epoch swap must succeed");
        }
        Gauge::noop()
    }

    fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
        Histogram::noop()
    }
}

#[test]
fn an_epoch_swap_inside_registration_is_refused_and_removes_the_handle() {
    let Fixture {
        router,
        instance,
        body,
        ..
    } = fixture();

    let fired = Arc::new(AtomicBool::new(false));
    let recorder = SwapOnFirstOccupancyPublish {
        instance: Arc::clone(&instance),
        fired: Arc::clone(&fired),
    };

    let pre_epoch = instance.current_epoch();
    let pre_swap_state = instance.current_state();

    // current_thread, so the whole dispatch stays on the thread the local
    // recorder is installed on.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let resp = metrics::with_local_recorder(&recorder, || {
        rt.block_on(router.oneshot(session_request(body)))
    })
    .expect("dispatch");

    // Three non-vacuity guards, each of which fails LOUDLY rather than quietly
    // weakening the pin into a restatement of the happy path.
    assert!(
        fired.load(Ordering::SeqCst),
        "the occupancy publish inside register_server_side_at must have fired the swap"
    );
    assert_ne!(
        instance.current_epoch(),
        pre_epoch,
        "the swap must have landed on the instance the router serves"
    );

    let status = resp.status();
    let post_swap_verdict = if status == StatusCode::OK {
        let bytes = rt
            .block_on(resp.into_body().collect())
            .expect("body")
            .to_bytes()
            .to_vec();
        let decoded: SessionEstablishResponse =
            serde_json::from_slice(&bytes).expect("decode SessionEstablishResponse");
        let handle = ServerSessionHandle(decoded.handle);
        // Guard 3, the one that pins WHERE the handle was minted: it must be
        // serviceable in the state captured before the request. Without this the
        // refusal below would also be produced by a handle minted somewhere else
        // entirely, and the pin would be asserting nothing about this handler.
        assert!(
            pre_swap_state
                .session_store
                .resolve(Some(handle), Instant::now())
                .is_ok(),
            "handle {} must be serviceable in the RETIRED store the handler captured",
            decoded.handle
        );
        match instance
            .current_state()
            .session_store
            .resolve(Some(handle), Instant::now())
        {
            Ok(_) => panic!(
                "fixture: handle {} still resolves against the post-swap store, so the swap \
                 did not retire it and there is no defect to pin",
                decoded.handle
            ),
            Err(err) => format!("handle {} is already dead: {err}", decoded.handle),
        }
    } else {
        String::new()
    };

    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "the handler must not hand out a session handle it can already see is retired; \
         {post_swap_verdict}"
    );
    assert_eq!(
        pre_swap_state.session_store.len(),
        0,
        "the refused handshake must remove its packing keys from the retired store"
    );
}
