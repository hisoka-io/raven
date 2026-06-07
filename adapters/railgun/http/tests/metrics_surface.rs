//! Prometheus `/metrics` surface tests: the
//! [`AppState::with_instance_metrics`] builder round-trips the per-instance
//! [`ConsumerMetrics`] map, `Clone` preserves it, and the `/metrics` handler
//! renders the per-instance gauge surface.

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
    // Repeat `AppState::new` must be cheap + side-effect-free (OnceLock-guarded
    // `describe_prometheus_metrics`).
    let s1 = build_state();
    let s2 = build_state();
    drop(s1);
    drop(s2);
}

#[test]
fn with_instance_metrics_builder_round_trips_map() {
    // `with_instance_metrics` must wire the map in and `Clone` must preserve it
    // (the handler clones state per scrape; a dropped Arc loses the gauges).
    let cell = Arc::new(parking_lot::Mutex::new(ConsumerMetrics {
        last_applied_block: 12_345_678,
        last_applied_leaf_block: 12_345_678,
        last_known_chain_head: 12_345_700,
        events_processed: 42,
        reorgs_handled: 1,
        commits_fired: 7,
        consumer_errors: 0,
    }));
    let mut map: HashMap<InstanceId, Arc<parking_lot::Mutex<ConsumerMetrics>>> = HashMap::new();
    let id = InstanceId::new("with-instance-metrics-roundtrip");
    map.insert(id, Arc::clone(&cell));
    // Baseline: two strong refs (`cell` + the entry in `map`).
    let baseline_strong = Arc::strong_count(&cell);
    assert_eq!(
        baseline_strong, 2,
        "pre-builder Arc strong-count baseline should be 2 (cell + map)"
    );

    let state = build_state().with_instance_metrics(map);

    // Builder consumed `map`; refs are now `cell` + the state's entry.
    assert_eq!(
        Arc::strong_count(&cell),
        2,
        "after `with_instance_metrics`, the per-instance Arc must be held by the state"
    );

    // `Clone` shares the map via the outer Arc, not a per-entry deep clone.
    let cloned = state.clone();
    assert_eq!(
        Arc::strong_count(&cell),
        2,
        "Clone must NOT deep-clone the map; per-entry Arcs stay at strong-count 2"
    );

    // Map outlives this drop because the clone still holds it.
    drop(state);
    assert_eq!(
        Arc::strong_count(&cell),
        2,
        "dropping one AppState ref must NOT drop the per-entry Arc"
    );

    // Mutation through the shared Mutex must be visible outside the state:
    // the consumer task updates it while the handler scrapes it.
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

    // Final drop: only the test-local `cell` ref remains.
    drop(cloned);
    assert_eq!(
        Arc::strong_count(&cell),
        1,
        "after dropping the final AppState, the per-entry Arc must collapse to 1"
    );
}

#[test]
fn with_instance_metrics_empty_map_is_legal_default() {
    // The explicit empty-map builder call must be a no-op.
    let empty: HashMap<InstanceId, Arc<parking_lot::Mutex<ConsumerMetrics>>> = HashMap::new();
    let state = build_state().with_instance_metrics(empty);
    let _cloned = state.clone();
}

/// Sentinel: the `inspire_router` `/metrics` handler renders the
/// per-instance gauge surface with the engine-side `drain_state`,
/// `in_flight`, `epoch`, `role` labels. Without the
/// `refresh_dynamic_metrics::engine.instances()` walk these names are
/// described but never `.set()`, so dashboards see no data row.
///
/// This is a thin smoke test: it asserts the metric names appear
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

    // Hold the lock ONLY during AppState::new (the
    // `metrics::set_global_recorder` race window); release before any
    // .await so clippy's `await_holding_lock` lint stays clean.
    let router = {
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
        raven_railgun_http::inspire_router(app_state).expect("router")
    };

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

/// Every increment of
/// `raven_railgun_queries_total` must carry the `instance` label so
/// operator dashboards can filter per-instance QPS. Pre-fix the counter
/// was emitted with only `kind` (single|batch), making per-instance
/// query throughput unobservable in the 6-instance topology even
/// though the sibling `respond_seconds` + `batch_size` metrics emitted
/// in the same handler did carry the label.
#[tokio::test(flavor = "current_thread")]
async fn queries_total_carries_instance_label_for_single_query() {
    use axum::body::Body;
    use axum::http::{header, Method, Request, StatusCode};
    use http_body_util::BodyExt;
    use raven_railgun_http::{router, write_versioned};
    use std::net::SocketAddr;
    use tower::ServiceExt;

    const QUERIES_INSTANCE: &str = "queries-total-instance";

    let router_built = {
        let _g = APPSTATE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let instance: Arc<PirInstance<EchoScheme>> = Arc::new(PirInstance::new(
            InstanceId::new(QUERIES_INSTANCE),
            InstanceRole::Static,
            EchoState,
        ));
        let mut engine: Engine<EchoScheme> = Engine::new();
        engine
            .register_instance(Arc::clone(&instance))
            .expect("register");

        let mut cfg = HttpConfig::demo(TOKEN);
        cfg.respond_timeout_secs = 5;
        cfg.max_concurrent_queries = 4;
        cfg.rate_limit_rps = 10_000;
        cfg.rate_limit_burst = 10_000;
        cfg.metrics_public = true;
        let state = AppState::new(engine, cfg).expect("appstate");
        router::<EchoScheme>(state).expect("router")
    };

    let q = EchoQuery { tag: 7 };
    let body_bytes = write_versioned(&q).expect("serialize");
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/instance/{QUERIES_INSTANCE}/query"))
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::from(body_bytes))
        .expect("build req");
    let peer: SocketAddr = "127.0.0.1:50102".parse().expect("addr");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(peer));
    let resp = router_built.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "single-query must succeed before scraping the counter"
    );

    let mut scrape_req = Request::builder()
        .method(Method::GET)
        .uri("/metrics")
        .body(Body::empty())
        .expect("scrape req");
    let scrape_peer: SocketAddr = "127.0.0.1:50103".parse().expect("scrape addr");
    scrape_req
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(scrape_peer));
    let scrape_resp = router_built.oneshot(scrape_req).await.expect("scrape");
    assert_eq!(scrape_resp.status(), StatusCode::OK);
    let body = scrape_resp
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let text = String::from_utf8(body.to_vec()).expect("utf8");

    let expected = format!("instance=\"{QUERIES_INSTANCE}\"");
    let line = text
        .lines()
        .find(|l| l.starts_with("raven_railgun_queries_total{") && l.contains(&expected));
    assert!(
        line.is_some(),
        "raven_railgun_queries_total must carry {expected} after a query lands\n\
         FULL OUTPUT:\n{text}"
    );
    let line = line.expect("queries_total line present");
    assert!(
        line.contains("kind=\"single\""),
        "queries_total line must also carry kind=\"single\": {line}"
    );
}
