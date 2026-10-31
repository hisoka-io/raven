//! `X-Raven-Freshness` is the only per-response attestation of how stale the served
//! tree is. Its value is a parsed key=value string, so a field that silently changes
//! name, order or scale is a wire break for every reader of it.

#![allow(
    dead_code,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Method, Request, StatusCode},
};
use raven_railgun_core::{InstanceId, Result as RailgunResult};
use raven_railgun_engine::persistence::ConsumerMetrics;
use raven_railgun_engine::{Engine, InstanceRole, PirInstance, PirScheme};
use raven_railgun_http::{router, write_versioned, AppState, HttpConfig};
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

const TOKEN: &str = "freshness-header-test-token-123456";
const INSTANCE: &str = "freshness-instance";
const FRESHNESS: &str = "x-raven-freshness";

static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug)]
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
    fn state_shape(_state: &Self::ServerState) -> raven_railgun_engine::StateShape {
        raven_railgun_engine::StateShape {
            entry_size_bytes: 1,
            rows_per_shard: u64::MAX,
        }
    }
}

/// `applied` is deliberately not `scanned`: the header reports the lag from the SCAN
/// watermark and the height from the APPLY watermark, and a fixture that made them
/// equal could not tell the two fields apart.
fn metrics_cell(scanned: u64, applied: u64, head: u64) -> Arc<parking_lot::Mutex<ConsumerMetrics>> {
    Arc::new(parking_lot::Mutex::new(ConsumerMetrics {
        last_applied_block: applied,
        last_scanned_block: scanned,
        last_applied_leaf_block: applied,
        last_known_chain_head: head,
        ..ConsumerMetrics::default()
    }))
}

fn build_router(cell: Option<Arc<parking_lot::Mutex<ConsumerMetrics>>>) -> axum::Router {
    let mut engine: Engine<EchoScheme> = Engine::new();
    engine
        .register_instance(Arc::new(PirInstance::new(
            InstanceId::new(INSTANCE),
            InstanceRole::Live,
            EchoState,
        )))
        .expect("register instance");

    let mut cfg = HttpConfig::demo(TOKEN);
    cfg.respond_timeout_secs = 5;
    cfg.rate_limit_rps = 10_000;
    cfg.rate_limit_burst = 10_000;

    let state = {
        let _g = APPSTATE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        AppState::new(engine, cfg).expect("appstate")
    };
    let state = match cell {
        Some(c) => state.with_consumer_metrics(c),
        None => state,
    };
    router::<EchoScheme>(state).expect("router")
}

type Cell = Arc<parking_lot::Mutex<ConsumerMetrics>>;

/// A node serving `ids`, wired as production wires one: a cell per instance in the map.
/// `single` additionally installs the legacy single cell, as production once did with the
/// first instance's.
fn build_node(ids: &[&str], cells: &[(&str, &Cell)], single: Option<&Cell>) -> axum::Router {
    let mut engine: Engine<EchoScheme> = Engine::new();
    for id in ids {
        engine
            .register_instance(Arc::new(PirInstance::new(
                InstanceId::new(*id),
                InstanceRole::Live,
                EchoState,
            )))
            .expect("register instance");
    }
    let mut cfg = HttpConfig::demo(TOKEN);
    cfg.respond_timeout_secs = 5;
    cfg.rate_limit_rps = 10_000;
    cfg.rate_limit_burst = 10_000;
    let state = {
        let _g = APPSTATE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        AppState::new(engine, cfg).expect("appstate")
    };
    let state = match single {
        Some(c) => state.with_consumer_metrics(Arc::clone(c)),
        None => state,
    };
    let state = state.with_instance_metrics(
        cells
            .iter()
            .map(|(id, c)| (InstanceId::new(*id), Arc::clone(c)))
            .collect(),
    );
    router::<EchoScheme>(state).expect("router")
}

fn request(route: &str, body: Vec<u8>) -> Request<Body> {
    request_to(INSTANCE, route, body)
}

fn request_to(instance: &str, route: &str, body: Vec<u8>) -> Request<Body> {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/instance/{instance}/{route}"))
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(body))
        .expect("build req");
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        12_345,
    )));
    req
}

fn single_body() -> Vec<u8> {
    write_versioned(&EchoQuery { tag: 7 }).expect("serialize query")
}

fn batch_body() -> Vec<u8> {
    write_versioned(&vec![EchoQuery { tag: 7 }]).expect("serialize batch")
}

async fn freshness_of(router: axum::Router, route: &str, body: Vec<u8>) -> String {
    freshness_from(router, request(route, body), route).await
}

async fn freshness_from(router: axum::Router, req: Request<Body>, route: &str) -> String {
    let resp = router.oneshot(req).await.expect("dispatch");
    assert_eq!(resp.status(), StatusCode::OK, "{route} must be served");
    resp.headers()
        .get(FRESHNESS)
        .unwrap_or_else(|| panic!("{route} response carries no {FRESHNESS} header"))
        .to_str()
        .expect("ascii freshness header")
        .to_owned()
}

/// The whole value, pinned. `confidence = 1 - lag/256` at three decimals is what a
/// wallet thresholds on, so a changed scale is as breaking as a changed field name.
#[tokio::test]
async fn single_query_freshness_header_pins_every_documented_field() {
    let cell = metrics_cell(21_000_000, 20_999_990, 21_000_010);
    let value = freshness_of(build_router(Some(cell)), "query", single_body()).await;
    assert_eq!(
        value, "lag_blocks=10 applied_height=20999990 epoch=0 confidence=0.961",
        "X-Raven-Freshness is a parsed wire value"
    );
}

/// The batch route builds its headers separately; a regression can drop one call site
/// while the other keeps passing.
#[tokio::test]
async fn batch_freshness_header_matches_the_single_query_one() {
    let cell = metrics_cell(21_000_000, 20_999_990, 21_000_010);
    let value = freshness_of(build_router(Some(cell)), "batch", batch_body()).await;
    assert_eq!(
        value,
        "lag_blocks=10 applied_height=20999990 epoch=0 confidence=0.961"
    );
}

/// Past the 256-block horizon confidence floors at zero rather than going negative,
/// which would read as "fresher than fresh" to a naive numeric comparison.
#[tokio::test]
async fn freshness_confidence_clamps_at_zero_past_the_lag_horizon() {
    let cell = metrics_cell(21_000_000, 21_000_000, 21_000_300);
    let value = freshness_of(build_router(Some(cell)), "query", single_body()).await;
    assert_eq!(
        value,
        "lag_blocks=300 applied_height=21000000 epoch=0 confidence=0.000"
    );
}

/// A deployment with no consumer wired must still emit the header. Dropping it would
/// leave readers unable to distinguish "no signal" from "header not supported".
#[tokio::test]
async fn freshness_header_is_still_emitted_without_consumer_metrics() {
    let value = freshness_of(build_router(None), "query", single_body()).await;
    assert_eq!(
        value,
        "lag_blocks=0 applied_height=0 epoch=0 confidence=1.000"
    );
}

const SEALED: &str = "freshness-sealed-block";
const LIVE: &str = "freshness-live-block";
const UNWIRED: &str = "freshness-unwired-block";

/// A sealed first block whose consumer stopped long ago, beside a live one at the tip.
fn sealed_and_live() -> (Cell, Cell) {
    (
        metrics_cell(20_000_000, 19_999_000, 21_000_010),
        metrics_cell(21_000_000, 20_999_990, 21_000_010),
    )
}

/// The response came from one instance's snapshot, so its freshness is that instance's, on
/// both routes, even with the old first-instance single cell still installed beside the map.
#[tokio::test]
async fn freshness_describes_the_instance_that_answered() {
    let (sealed, live) = sealed_and_live();
    let node = || {
        build_node(
            &[SEALED, LIVE],
            &[(SEALED, &sealed), (LIVE, &live)],
            Some(&sealed),
        )
    };
    let live_reading = "lag_blocks=10 applied_height=20999990 epoch=0 confidence=0.961";
    for (route, body) in [("query", single_body()), ("batch", batch_body())] {
        let value = freshness_from(node(), request_to(LIVE, route, body.clone()), route).await;
        assert_eq!(value, live_reading, "{route} served by the live block");
        let value = freshness_from(node(), request_to(SEALED, route, body), route).await;
        assert_eq!(
            value, "lag_blocks=1000010 applied_height=19999000 epoch=0 confidence=0.000",
            "{route} served by the sealed block"
        );
    }
}

/// An instance with no cell of its own reports the node view `/v1/status` gives: the worst
/// lag and the highest applied height, not a clean zero and not another instance's numbers.
#[tokio::test]
async fn an_instance_without_its_own_cell_reports_the_node_view() {
    let (sealed, live) = sealed_and_live();
    let node = build_node(
        &[SEALED, LIVE, UNWIRED],
        &[(SEALED, &sealed), (LIVE, &live)],
        None,
    );
    let value = freshness_from(node, request_to(UNWIRED, "query", single_body()), "query").await;
    assert_eq!(
        value,
        "lag_blocks=1000010 applied_height=20999990 epoch=0 confidence=0.000"
    );
}
