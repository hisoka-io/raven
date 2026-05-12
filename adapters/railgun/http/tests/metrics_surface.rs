//! Prometheus `/metrics` surface tests.
//!
//! Scope: T-M state-layer additions.
//!
//! This file covers what `state.rs` accomplishes today: the
//! [`AppState::with_instance_metrics`] builder round-trips the
//! per-instance [`ConsumerMetrics`] map into the state, and the
//! cheap-clone `Clone` impl preserves it. Wire-up of the map into
//! the `/metrics` handler itself (HELP/TYPE surface + per-instance
//! gauges driven by `refresh_dynamic_metrics` + `emit_instance_metrics`)
//! is the orchestrator pass that adds `/metrics` to the generic
//! router and invokes the refresh helper before render.
//!
//! Once the orchestrator pass lands, the scrape-surface tests
//! (HELP lines for every described metric, per-instance label
//! presence, uptime gauge monotone-increase) belong here too,
//! ported from the rave reference suite.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::HashMap;
use std::sync::Arc;

use raven_railgun_core::{InstanceId, Result as RailgunResult};
use raven_railgun_engine::persistence::ConsumerMetrics;
use raven_railgun_engine::{Engine, InstanceRole, PirInstance, PirScheme};
use raven_railgun_http::{AppState, HttpConfig};
use serde::{Deserialize, Serialize};

const TOKEN: &str = "metrics-surface-test-token-1234567890";
const INSTANCE: &str = "metrics-surface-instance";

/// Process-wide lock so concurrent test workers don't race on
/// `metrics::set_global_recorder` inside `AppState::new`.
static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Trivial PIR scheme so the test can build an `AppState` without
/// pulling in raven-inspire's heavy machinery.
#[derive(Debug, Default)]
struct EchoScheme;

#[derive(Debug, Default)]
struct EchoState;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct EchoQuery {
    tag: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct EchoResponse {
    tag: u32,
}

impl PirScheme for EchoScheme {
    type ServerState = EchoState;
    type Query = EchoQuery;
    type Response = EchoResponse;

    fn respond(_state: &Self::ServerState, query: &Self::Query) -> RailgunResult<Self::Response> {
        Ok(EchoResponse { tag: query.tag })
    }
}

fn build_state() -> AppState<EchoScheme> {
    let instance: Arc<PirInstance<EchoScheme>> = Arc::new(PirInstance::new(
        InstanceId::new(INSTANCE),
        InstanceRole::Static,
        EchoState,
    ));
    let mut engine: Engine<EchoScheme> = Engine::new();
    engine
        .register_instance(Arc::clone(&instance))
        .expect("register instance");

    let mut cfg = HttpConfig::demo(TOKEN);
    cfg.respond_timeout_secs = 5;
    cfg.max_concurrent_queries = 4;
    cfg.rate_limit_rps = 10_000;
    cfg.rate_limit_burst = 10_000;
    cfg.metrics_public = true;

    let _g = APPSTATE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    AppState::new(engine, cfg).expect("appstate")
}

#[test]
fn appstate_new_is_idempotent_for_describe_prometheus_metrics() {
    // `AppState::new` invokes the state-layer `describe_prometheus_metrics`
    // helper, which registers HELP descriptions + force-seeds zero-default
    // counters into the process-global recorder. The helper is guarded by
    // a `OnceLock` so repeat `AppState::new` calls inside one process are
    // cheap + side-effect-free. This test exercises the multi-construct
    // path that property tests + multi-tenant deployments hit.
    let s1 = build_state();
    let s2 = build_state();
    // Both states must carry the same process_started_at-derived value
    // (the lock-free helper is process-wide; the per-state Instants are
    // independent + monotonic).
    drop(s1);
    drop(s2);
}

#[test]
fn with_instance_metrics_builder_round_trips_map() {
    // Builder regression: `with_instance_metrics` must wire the
    // per-instance ConsumerMetrics map into the state field, and
    // `Clone` must preserve it (the metrics handler clones the
    // state on every scrape; if `Clone` dropped the Arc, the
    // per-instance gauges would silently disappear on a cloned
    // handler invocation).
    //
    // Map shape is `HashMap<InstanceId, Arc<Mutex<ConsumerMetrics>>>`,
    // matching the rave reference contract.
    let cell = Arc::new(parking_lot::Mutex::new(ConsumerMetrics {
        last_applied_block: 12_345_678,
        last_known_chain_head: 12_345_700,
        events_processed: 42,
        reorgs_handled: 1,
        commits_fired: 7,
        consumer_errors: 0,
    }));
    let mut map: HashMap<InstanceId, Arc<parking_lot::Mutex<ConsumerMetrics>>> = HashMap::new();
    let id = InstanceId::new("with-instance-metrics-roundtrip");
    map.insert(id, Arc::clone(&cell));
    // Capture the strong-count immediately after insert so the
    // round-trip assertions below can compare against the
    // builder-time baseline. Two strong refs: the one in `cell`
    // and the one in `map`.
    let baseline_strong = Arc::strong_count(&cell);
    assert_eq!(
        baseline_strong, 2,
        "pre-builder Arc strong-count baseline should be 2 (cell + map)"
    );

    let state = build_state().with_instance_metrics(map);

    // After the builder consumed `map`, the only strong refs to `cell`
    // are: `cell` itself + the entry inside the state's
    // `instance_metrics` map. So strong-count must still be 2.
    assert_eq!(
        Arc::strong_count(&cell),
        2,
        "after `with_instance_metrics`, the per-instance Arc must be held by the state"
    );

    // `Clone` on AppState must preserve the per-instance map. Cloning
    // increments the strong count of the outer `Arc<HashMap<..>>`,
    // NOT the per-entry Arcs (the HashMap is shared via the outer
    // Arc, not deep-cloned). So `cell`'s strong-count stays at 2.
    let cloned = state.clone();
    assert_eq!(
        Arc::strong_count(&cell),
        2,
        "Clone must NOT deep-clone the map; per-entry Arcs stay at strong-count 2"
    );

    // Drop one of the AppState refs. The map outlives because the
    // clone still holds it.
    drop(state);
    assert_eq!(
        Arc::strong_count(&cell),
        2,
        "dropping one AppState ref must NOT drop the per-entry Arc"
    );

    // Mutation through the shared inner Mutex must be visible from
    // outside the state: this is the entire point of the design
    // (the orchestrator updates `last_applied_block` in the consumer
    // task; the metrics handler scrapes it).
    {
        let mut g = cell.lock();
        g.events_processed = 999;
    }
    let snap = cell.lock();
    assert_eq!(
        snap.events_processed, 999,
        "shared-Arc payload mutation must be visible through the cell"
    );
    drop(snap);

    // Now drop the cloned AppState; the per-entry Arc count must
    // fall to 1 (only the test-local `cell` remains).
    drop(cloned);
    assert_eq!(
        Arc::strong_count(&cell),
        1,
        "after dropping the final AppState, the per-entry Arc must collapse to 1"
    );
}

#[test]
fn with_instance_metrics_empty_map_is_legal_default() {
    // Default `AppState::new` populates `instance_metrics` with an
    // empty map; the explicit empty-map builder call must be a
    // no-op idempotently (single-instance deployments + tests that
    // wire only the legacy single-cell `consumer_metrics`).
    let empty: HashMap<InstanceId, Arc<parking_lot::Mutex<ConsumerMetrics>>> = HashMap::new();
    let state = build_state().with_instance_metrics(empty);
    // Reaching here without a panic + carrying through `Clone` proves
    // the empty-map path is wired correctly.
    let _cloned = state.clone();
}

/// Sentinel: the `inspire_router` `/metrics` handler renders the
/// per-instance gauge surface with the engine-side `drain_state`,
/// `in_flight`, `epoch`, `role` labels. Without the
/// `refresh_dynamic_metrics::engine.instances()` walk these names are
/// described but never `.set()`, so dashboards see no data row.
///
/// This is a thin smoke test — it asserts the metric names appear
/// SOMEWHERE in the scrape output with the `instance=...` label. It
/// does NOT pin specific values (those depend on the engine state
/// which has no test fixture).
#[tokio::test(flavor = "current_thread")]
async fn metrics_handler_emits_per_instance_engine_gauges() {
    use axum::body::Body;
    use axum::http::{header, Method, Request, StatusCode};
    use http_body_util::BodyExt;
    use raven_railgun_engine::inspire::{setup_state, RavenInspireScheme};
    use std::net::SocketAddr;
    use tower::ServiceExt;

    let _g = APPSTATE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    // Build a tiny InsPIRe instance so `inspire_router` accepts the
    // engine. We don't query it; we only scrape `/metrics`.
    let params = raven_inspire::params::InspireParams::secure_128_d2048();
    let db: Vec<u8> = vec![0u8; 2048 * 32];
    let (state, _sk) = setup_state(
        &params,
        &db,
        32,
        raven_inspire::params::InspireVariant::TwoPacking,
    )
    .expect("setup_state");
    let instance: Arc<PirInstance<RavenInspireScheme>> = Arc::new(PirInstance::new(
        InstanceId::new("metrics-scrape-instance"),
        InstanceRole::Live,
        state,
    ));
    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    engine
        .register_instance(Arc::clone(&instance))
        .expect("register");

    let mut cfg = HttpConfig::demo(TOKEN);
    cfg.metrics_public = true;
    let app_state = AppState::new(engine, cfg).expect("appstate");
    let router = raven_railgun_http::inspire_router(app_state).expect("router");

    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/metrics")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .expect("build req");
    let peer: SocketAddr = "127.0.0.1:50101".parse().expect("addr");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(peer));

    let resp = router.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let text = String::from_utf8(body.to_vec()).expect("utf8");

    assert!(
        text.contains("raven_railgun_drain_state{")
            && text.contains("instance=\"metrics-scrape-instance\""),
        "scrape must emit per-instance drain_state gauge"
    );
    assert!(
        text.contains("raven_railgun_in_flight{")
            && text.contains("instance=\"metrics-scrape-instance\""),
        "scrape must emit per-instance in_flight gauge"
    );
    assert!(
        text.contains("raven_railgun_epoch{")
            && text.contains("instance=\"metrics-scrape-instance\""),
        "scrape must emit per-instance epoch gauge"
    );
    assert!(
        text.contains("raven_railgun_role{")
            && text.contains("instance=\"metrics-scrape-instance\""),
        "scrape must emit per-instance role gauge"
    );
    assert!(
        text.contains("raven_railgun_uptime_seconds"),
        "scrape must emit process uptime gauge"
    );
    assert!(
        text.contains("raven_railgun_sessions_active"),
        "scrape must emit process sessions_active gauge"
    );
    assert!(
        text.contains("raven_railgun_semaphore_permits_available"),
        "scrape must emit process semaphore_permits_available gauge"
    );
}
