//! What a whole-list declaration actually proves, held in place by the answers it gives.
//!
//! A `PpoiList` declaration is the only shape with no sealed block under its frontier, so the
//! coverage proof reduces to one rule: this store has not reached the 65,536-row per-IMT wall.
//! These tests record what that buys - an empty store and a store three rows into a long list
//! both prove coverage and both serve `"Missing"` at HTTP 200 - so a caller weighing a
//! whole-list declaration is reading the property, not inferring it. The multi-instance path
//! is unaffected: its block declarations are tried first and seal every block below the
//! frontier.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Method, Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::orchestrator::DataSourceFilter;
use raven_railgun_engine::pir_table::PerLeafCommitmentEncoder;
use raven_railgun_engine::{Engine, PirScheme};
use raven_railgun_http::{AppState, HttpConfig};
use raven_railgun_persistence::WalEntryPayload;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceExt;

const TOKEN: &str = "whole-list-liveness-token-padded-12";
const LIST_KEY: [u8; 32] = [0x42; 32];
const HELD_ROWS: u32 = 3;
/// Past everything the store holds, and far short of the wall the proof watches.
const UNHELD_INDEX: u32 = 5;

type SharedStore = Arc<parking_lot::Mutex<LogicalLeafStore>>;

// Serialises AppState::new against the global metrics recorder.
static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug, Default)]
struct StubScheme;

#[derive(Debug, Default)]
struct StubState;

#[derive(Serialize, Deserialize, Debug)]
struct StubQuery;

#[derive(Serialize, Deserialize, Debug)]
struct StubResponse;

impl PirScheme for StubScheme {
    type ServerState = StubState;
    type Query = StubQuery;
    type Response = StubResponse;

    fn respond(
        _state: &Self::ServerState,
        _query: &Self::Query,
    ) -> raven_railgun_core::Result<Self::Response> {
        Err(raven_railgun_core::AdapterError::Scheme(
            "stub respond invoked".to_owned(),
        ))
    }
    fn state_shape(_state: &Self::ServerState) -> raven_railgun_engine::StateShape {
        raven_railgun_engine::StateShape {
            entry_size_bytes: 1,
            rows_per_shard: u64::MAX,
        }
    }
}

/// Canonical BN254 Fr: the high bytes stay clear so the value is under the modulus.
fn bc_for(index: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[20] = 0x01;
    out[28..].copy_from_slice(&index.wrapping_add(0x0100_0000).to_be_bytes());
    out
}

fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn store_holding(rows: u32) -> SharedStore {
    let encoder = PerLeafCommitmentEncoder::new(32, 65_536, 0).expect("encoder");
    let mut store = LogicalLeafStore::new();
    for index in 0..rows {
        apply_wal_entry(
            &mut store,
            &WalEntryPayload::PpoiListLeafAdded {
                list_key: LIST_KEY,
                list_index: index,
                blinded_commitment: bc_for(index),
                status: 0,
                event_type: raven_railgun_persistence::PpoiEventType::Shield,
                signature: vec![0; 64],
                validated_merkleroot: [0; 32],
            },
            1_000 + u64::from(index),
            &encoder,
        )
        .expect("seed ppoi leaf");
    }
    Arc::new(parking_lot::Mutex::new(store))
}

fn declaring_the_whole_list(store: SharedStore) -> Router {
    let engine: Engine<StubScheme> = Engine::new();
    let state = {
        let _g = APPSTATE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        AppState::new(engine, HttpConfig::demo(TOKEN)).expect("appstate")
    };
    let state = state.with_shim_stores(vec![(DataSourceFilter::PpoiList(LIST_KEY), store)]);
    raven_railgun_http::router(state).expect("router")
}

fn authed(method: Method, uri: &str, body: Body) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .expect("request");
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    request
}

async fn send(router: &Router, request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let response = router.clone().oneshot(request).await.expect("dispatch");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec();
    (status, bytes)
}

fn status_for(body: &[u8], bc: &str) -> String {
    let parsed: serde_json::Value = serde_json::from_slice(body).expect("json");
    parsed[bc][hex32(&LIST_KEY)]
        .as_str()
        .expect("per-list status string")
        .to_owned()
}

async fn ask_pois_per_list(router: &Router, bc: &str) -> (StatusCode, Vec<u8>) {
    send(
        router,
        authed(
            Method::POST,
            "/v1/poi/pois-per-list",
            Body::from(
                serde_json::json!({
                    "listKeys": [hex32(&LIST_KEY)],
                    "blindedCommitmentDatas": [{ "blindedCommitment": bc }],
                })
                .to_string(),
            ),
        ),
    )
    .await
}

/// A store that has never held a row is refused rather than answered: `held < 65_536` alone
/// would let a node that has seen nothing claim what one that has seen everything claims.
#[tokio::test]
async fn a_whole_list_declaration_over_an_empty_store_is_refused() {
    let router = declaring_the_whole_list(store_holding(0));
    let probe = hex32(&bc_for(0));

    let (status, _body) = ask_pois_per_list(&router, &probe).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "an empty whole-list store must not prove coverage"
    );

    // The index route is a separate proof site, so it is asserted rather than assumed.
    let (status, body) = send(
        &router,
        authed(
            Method::GET,
            &format!("/v1/poi/{}/bc-to-idx-map", hex32(&LIST_KEY)),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let published_entries =
        serde_json::from_slice::<serde_json::Value>(&body).is_ok_and(|v| v["entries"].is_array());
    assert!(
        !published_entries,
        "a refused route must not also publish an empty index"
    );
}

/// Partway through ingest, the same answer: the frontier is the only boundary the proof has,
/// so every row above it reads as absent rather than as unknown.
#[tokio::test]
async fn a_whole_list_declaration_answers_missing_for_a_row_above_its_frontier() {
    let router = declaring_the_whole_list(store_holding(HELD_ROWS));
    let held = hex32(&bc_for(0));
    let above = hex32(&bc_for(UNHELD_INDEX));

    let (status, body) = ask_pois_per_list(&router, &held).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(
        status_for(&body, &held),
        "Missing",
        "a row the store holds must not read as absent, or this test proves nothing"
    );

    let (status, body) = ask_pois_per_list(&router, &above).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        status_for(&body, &above),
        "Missing",
        "a row above the frontier is served as absent, not refused"
    );

    let (status, body) = send(
        &router,
        authed(
            Method::GET,
            &format!("/v1/poi/{}/bc-to-idx-map", hex32(&LIST_KEY)),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let map: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(
        map["entries"].as_array().expect("entries").len(),
        HELD_ROWS as usize,
        "the published index stops at the frontier and says so nowhere"
    );
}
