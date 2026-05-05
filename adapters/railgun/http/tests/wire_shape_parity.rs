//! Wire-shape parity vs upstream Railgun JSON (`proof-of-innocence.ts`).
//!
//! Source of truth: `shared-models/src/models/proof-of-innocence.ts:28-33, 138-152`.

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
use raven_railgun_engine::pir_table::PerLeafCommitmentEncoder;
use raven_railgun_engine::{Engine, PirScheme};
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
}

fn fr_canonical(tag: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for byte in out.iter_mut().skip(16) {
        *byte = tag;
    }
    out
}

fn build_router_with_seed(
    leaves: &[(u32, u32, u8)],
    list_leaves: &[([u8; 32], u32, u8, u8)],
) -> Router {
    let mut store = LogicalLeafStore::new();
    let enc = PerLeafCommitmentEncoder::new(32, ENTRIES_PER_SHARD).expect("encoder");
    for (tree, idx, tag) in leaves {
        apply_wal_entry(
            &mut store,
            &WalEntryPayload::AppendLeaf {
                tree_number: *tree,
                leaf_index: *idx,
                commitment: fr_canonical(*tag),
            },
            100 + u64::from(*idx),
            &enc,
        )
        .expect("seed leaf");
    }
    for (lk, idx, tag, status) in list_leaves {
        apply_wal_entry(
            &mut store,
            &WalEntryPayload::PpoiListLeafAdded {
                list_key: *lk,
                list_index: *idx,
                blinded_commitment: fr_canonical(*tag),
                status: *status,
            },
            200 + u64::from(*idx),
            &enc,
        )
        .expect("seed ppoi leaf");
    }

    let store_arc = Arc::new(parking_lot::Mutex::new(store));
    let cfg = HttpConfig::demo(TOKEN);
    let engine: Engine<StubScheme> = Engine::new();
    let state = {
        let _g = APPSTATE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        AppState::new(engine, cfg).expect("appstate")
    }
    .with_logical_store(Arc::clone(&store_arc));
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
    let router = build_router_with_seed(&[], &[(lk, 0, bc_tag, 0)]);
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

#[tokio::test]
async fn pois_per_list_status_values_use_pascal_case_enum_names() {
    let lk = fr_canonical(0x42);
    let lk_hex = hex_encode_bytes(&lk);
    let bc_a = hex_encode_bytes(&fr_canonical(0x11));
    let bc_b = hex_encode_bytes(&fr_canonical(0x22));
    let bc_c = hex_encode_bytes(&fr_canonical(0x33));
    // 0=Valid, 1=ShieldBlocked, 2=ProofSubmitted
    let router =
        build_router_with_seed(&[], &[(lk, 0, 0x11, 0), (lk, 1, 0x22, 1), (lk, 2, 0x33, 2)]);
    let payload = serde_json::json!({
        "txidVersion": "V2_PoseidonMerkle",
        "listKeys": [lk_hex],
        "blindedCommitmentDatas": [
            { "blindedCommitment": bc_a, "type": "Shield" },
            { "blindedCommitment": bc_b, "type": "Shield" },
            { "blindedCommitment": bc_c, "type": "Shield" },
        ],
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/poi/pois-per-list")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string()))
        .expect("build req");
    let resp = router.oneshot(req).await.expect("dispatch");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("decode");
    assert_eq!(json[&bc_a][&lk_hex].as_str(), Some("Valid"));
    assert_eq!(json[&bc_b][&lk_hex].as_str(), Some("ShieldBlocked"));
    assert_eq!(json[&bc_c][&lk_hex].as_str(), Some("ProofSubmitted"));
}

#[tokio::test]
async fn bc_to_idx_map_json_envelope_shape() {
    let lk = fr_canonical(0x42);
    let lk_hex = hex_encode_bytes(&lk);
    let router =
        build_router_with_seed(&[], &[(lk, 0, 0x11, 0), (lk, 1, 0x22, 1), (lk, 2, 0x33, 2)]);
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/v1/poi/{lk_hex}/bc-to-idx-map"))
        .body(Body::empty())
        .expect("build req");
    let resp = router.oneshot(req).await.expect("dispatch");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("decode");
    let obj = json.as_object().expect("object");
    let keys: std::collections::BTreeSet<&str> =
        obj.keys().map(std::string::String::as_str).collect();
    let expected: std::collections::BTreeSet<&str> =
        ["epoch", "listKey", "entries"].iter().copied().collect();
    assert_eq!(keys, expected, "envelope must be exactly {{ epoch, listKey, entries }}");
    assert!(json["epoch"].is_number());
    assert_eq!(json["listKey"].as_str(), Some(lk_hex.as_str()));
    let entries = json["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 3);
    for e in entries {
        let inner = e.as_object().expect("entry object");
        let entry_keys: std::collections::BTreeSet<&str> =
            inner.keys().map(std::string::String::as_str).collect();
        assert_eq!(entry_keys, ["bc", "idx"].iter().copied().collect(), "entry must be {{ bc, idx }}");
        assert!(inner["bc"].is_string());
        assert!(inner["idx"].is_number());
    }
}

/// Empty POST must 4xx (client error), not 5xx.
#[tokio::test]
async fn empty_pois_per_list_post_returns_client_error_not_server_error() {
    let router = build_router_with_seed(&[], &[]);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/poi/pois-per-list")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::empty())
        .expect("build req");
    let resp = router.oneshot(req).await.expect("dispatch");
    assert!(
        resp.status().is_client_error(),
        "empty body POST must return 4xx, not {}",
        resp.status()
    );
}
