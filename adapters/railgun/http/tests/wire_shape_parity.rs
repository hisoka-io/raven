//! Wire-shape parity vs upstream `shared-models/src/models/proof-of-innocence.ts`.

#![allow(
    dead_code,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::redundant_closure_for_method_calls
)]

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::orchestrator::DataSourceFilter;
use raven_railgun_engine::pir_table::PerLeafCommitmentEncoder;
use raven_railgun_engine::{Engine, PirScheme};
use raven_railgun_http::status::{MirrorFeedState, MirrorFeedView};
use raven_railgun_http::{poi_shim, AppState, HttpConfig};
use raven_railgun_persistence::WalEntryPayload;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower::ServiceExt;

const TOKEN: &str = "test-token-padded-long-enough-1234";
const ENTRIES_PER_SHARD: u32 = 65_536;

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
        Err(raven_railgun_core::AdapterError::Scheme("stub".to_owned()))
    }
    fn state_shape(_state: &Self::ServerState) -> raven_railgun_engine::StateShape {
        raven_railgun_engine::StateShape {
            entry_size_bytes: 1,
            rows_per_shard: u64::MAX,
        }
    }
}

fn fr_canonical(tag: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for byte in out.iter_mut().skip(16) {
        *byte = tag;
    }
    out
}

/// One declared block of `list_key` holding `bc_tags` in order, at upstream's count.
fn build_router(list_key: [u8; 32], bc_tags: &[u8]) -> Router {
    let mut store = LogicalLeafStore::new();
    let enc = PerLeafCommitmentEncoder::new(32, ENTRIES_PER_SHARD, 0).expect("encoder");
    for (idx, tag) in (0u32..).zip(bc_tags) {
        apply_wal_entry(
            &mut store,
            &WalEntryPayload::PpoiListLeafAdded {
                list_key,
                list_index: idx,
                blinded_commitment: fr_canonical(*tag),
                event_type: raven_railgun_persistence::PpoiEventType::Shield,
                validated_merkleroot: [0; 32],
            },
            200 + u64::from(idx),
            &enc,
        )
        .expect("seed ppoi leaf");
    }

    let rows = u64::try_from(bc_tags.len()).expect("row count");
    let upstream = MirrorFeedView {
        list_key: hex_encode_bytes(&list_key),
        state: MirrorFeedState::Syncing,
        rows_held: rows,
        upstream_rows: Some(rows),
        next_index: rows,
        consecutive_failures: 0,
        last_failure: None,
        seconds_since_answer: Some(0),
    };
    let cfg = HttpConfig::demo(TOKEN);
    let engine: Engine<StubScheme> = Engine::new();
    let state = {
        let _g = APPSTATE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        AppState::new(engine, cfg).expect("appstate")
    }
    .with_shim_stores([(
        DataSourceFilter::PpoiListBlock { list_key, block: 0 },
        Arc::new(parking_lot::Mutex::new(store)),
    )])
    .with_mirror_feeds(Arc::new(move || vec![upstream.clone()]));
    poi_shim::poi_shim_routes(state)
}

fn hex_encode_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    resp.into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec()
}

#[tokio::test]
async fn merkle_proof_json_keys_match_upstream_shape() {
    let lk = fr_canonical(0x42);
    let bc_tag = 0x11;
    let bc_hex = hex_encode_bytes(&fr_canonical(bc_tag));
    let lk_hex = hex_encode_bytes(&lk);
    let router = build_router(lk, &[bc_tag]);
    let payload = serde_json::json!({
        "listKey": lk_hex,
        "blindedCommitments": [bc_hex],
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/poi/merkle-proofs")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string()))
        .expect("build req");
    let resp = router.oneshot(req).await.expect("dispatch");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("decode");

    let arr = json.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    let entry = &arr[0];
    let obj = entry.as_object().expect("object");
    let keys: std::collections::BTreeSet<&str> =
        obj.keys().map(std::string::String::as_str).collect();
    let expected: std::collections::BTreeSet<&str> = ["leaf", "elements", "indices", "root"]
        .iter()
        .copied()
        .collect();
    assert_eq!(
        keys, expected,
        "MerkleProof JSON keys MUST match upstream shape exactly: {keys:?} vs {expected:?}"
    );
    assert!(entry["leaf"].is_string(), "leaf must be string");
    assert!(entry["elements"].is_array(), "elements must be array");
    assert!(entry["indices"].is_string(), "indices must be string");
    assert!(entry["root"].is_string(), "root must be string");
    for e in entry["elements"].as_array().expect("elements") {
        assert!(e.is_string(), "every element must be string");
    }
}
