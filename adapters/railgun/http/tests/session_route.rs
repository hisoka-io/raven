//! `/v1/instance/:id/session`: the happy path, and the epoch-swap race as a
//! red-with-trigger pin.
//!
//! The pin needs an epoch swap to land inside the handler's capture-then-register
//! window. `session_establish_handler` has no `.await` in its body, so no other
//! task on the thread can preempt it - but production itself calls out inside the
//! window: `BoundedSessionStore::register_server_side_at` publishes the occupancy
//! gauges while still holding the store's write lock, after the handle is minted.
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
use raven_inspire::ServerSessionHandle;
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{heartbeat_session_eviction, setup_state, RavenInspireScheme};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
use raven_railgun_http::{
    inspire_router, write_versioned, AppState, HttpConfig, SessionEstablishResponse,
};
use tower::ServiceExt;

const READ_TOKEN: &str = "BEARER-SESSION-TEST-padded-min-len-ab";
const INSTANCE_ID: &str = "session-route-instance";
const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_BYTES: usize = 256;

/// Published by `BoundedSessionStore::register_server_side_at` while the store's
/// write lock is held and the freshly minted handle is already serviceable.
const OCCUPANCY_GAUGE: &str = "raven_railgun_session_store_occupancy";

static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// One booted instance behind a router, plus the `Arc` the swap path needs.
struct Fixture {
    router: axum::Router,
    instance: Arc<PirInstance<RavenInspireScheme>>,
    body: Vec<u8>,
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

    let instance_id = InstanceId::new(INSTANCE_ID);
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
    let cfg = HttpConfig::demo(READ_TOKEN);
    let ttl_secs = cfg.session_ttl_secs;
    let app_state = {
        let _g = APPSTATE_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        AppState::new(engine, cfg).expect("appstate")
    };
    Fixture {
        router: inspire_router(app_state).expect("router build"),
        instance,
        body,
        ttl_secs,
    }
}

fn session_request(body: Vec<u8>) -> Request<Body> {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/instance/{INSTANCE_ID}/session"))
        .header(header::AUTHORIZATION, format!("Bearer {READ_TOKEN}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(body))
        .expect("build session req");
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        12_345,
    )));
    req
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

/// Fires one epoch swap the first time the session store publishes its occupancy
/// gauge - which `register_server_side_at` does with the store's write lock held,
/// after the handle is minted and before it returns.
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
            // epoch + 1. It reads only the donor's crs/db/cache, never the store
            // whose write lock the caller is holding.
            heartbeat_session_eviction(&self.instance).expect("epoch swap must succeed");
        }
        Gauge::noop()
    }

    fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
        Histogram::noop()
    }
}

#[test]
#[ignore = "DH-L2-9 race half. session_establish_handler captures instance.current_state() at \
            admin.rs:171 and never re-checks the epoch, so a swap landing before the response is \
            produced still returns 200 at admin.rs:242-249 carrying a handle the current snapshot \
            refuses as retired. RED until the handler re-checks the captured epoch AFTER \
            register_server_side returns (admin.rs:191) and refuses instead of returning 200. \
            Trigger: that re-check landing anywhere in admin.rs:191-249 un-ignores this test."]
fn an_epoch_swap_inside_register_still_returns_200_with_a_dead_handle() {
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

    assert_ne!(
        status,
        StatusCode::OK,
        "the handler must not hand out a session handle it can already see is retired; \
         {post_swap_verdict}"
    );
}
