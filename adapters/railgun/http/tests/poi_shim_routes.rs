//! Integration tests for the wallet-shim + index-channel routes.

#![allow(
    dead_code,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
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

fn encoder() -> PerLeafCommitmentEncoder {
    PerLeafCommitmentEncoder::new(32, ENTRIES_PER_SHARD, 0).expect("encoder")
}

/// `tag` in byte 1 and the low 16, zero elsewhere, so the value stays below the BN254 modulus
/// and the six-byte prefix still tells two tags apart.
fn fr_canonical(tag: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[1] = tag;
    for byte in out.iter_mut().skip(16) {
        *byte = tag;
    }
    out
}

fn seeded_store() -> (LogicalLeafStore, [u8; 32]) {
    let mut store = LogicalLeafStore::new();
    let enc = encoder();
    let list_key = fr_canonical(0x42);

    apply_wal_entry(
        &mut store,
        &WalEntryPayload::AppendLeaf {
            tree_number: 0,
            leaf_index: 0,
            commitment: fr_canonical(0x01),
        },
        100,
        &enc,
    )
    .expect("seed leaf 0");
    apply_wal_entry(
        &mut store,
        &WalEntryPayload::AppendLeaf {
            tree_number: 0,
            leaf_index: 1,
            commitment: fr_canonical(0x02),
        },
        101,
        &enc,
    )
    .expect("seed leaf 1");

    let bcs = [fr_canonical(0x11), fr_canonical(0x22), fr_canonical(0x33)];
    for (i, bc) in bcs.iter().enumerate() {
        apply_wal_entry(
            &mut store,
            &WalEntryPayload::PpoiListLeafAdded {
                list_key,
                list_index: i as u32,
                blinded_commitment: *bc,
                event_type: raven_railgun_persistence::PpoiEventType::Shield,
                validated_merkleroot: [0; 32],
            },
            200 + i as u64,
            &enc,
        )
        .expect("seed ppoi leaf");
    }

    (store, list_key)
}

fn build_router() -> (Router, [u8; 32]) {
    let (routes, list_key, _store) = build_router_with_store();
    (routes, list_key)
}

/// Variant that also hands back the store behind the router, so proof-serving
/// tests can compare served content against the store's own proof. The one store is declared
/// as commit tree 0 and as block 0 of the list, with upstream counting its three rows.
fn build_router_with_store() -> (Router, [u8; 32], Arc<parking_lot::Mutex<LogicalLeafStore>>) {
    let (store, list_key) = seeded_store();
    let store_arc = Arc::new(parking_lot::Mutex::new(store));
    let engine: Engine<StubScheme> = Engine::new();
    let cfg = HttpConfig::demo(TOKEN);
    let upstream = MirrorFeedView {
        list_key: hex_encode_bytes(&list_key),
        state: MirrorFeedState::Syncing,
        rows_held: 3,
        upstream_rows: Some(3),
        next_index: 3,
        consecutive_failures: 0,
        last_failure: None,
        seconds_since_answer: Some(0),
    };
    let state = {
        let _g = APPSTATE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        AppState::new(engine, cfg).expect("appstate")
    }
    .with_shim_stores([
        (DataSourceFilter::ChainTreeNumber(0), Arc::clone(&store_arc)),
        (
            DataSourceFilter::PpoiListBlock { list_key, block: 0 },
            Arc::clone(&store_arc),
        ),
    ])
    .with_mirror_feeds(Arc::new(move || vec![upstream.clone()]));
    let routes = poi_shim::poi_shim_routes(state);
    (routes, list_key, store_arc)
}

/// A proof of the right SHAPE with the wrong CONTENT is the failure mode that
/// matters here (the proofs are consumed off-tree): pin every serialized field
/// of the served proof to the store's own proof for that slot.
fn assert_served_proof_matches_store(
    entry: &serde_json::Value,
    core: &raven_railgun_core::MerkleProof,
) {
    let elements = entry["elements"].as_array().expect("elements array");
    assert_eq!(elements.len(), 16, "Merkle proof must have 16 siblings");
    for (level, (served, expected)) in elements.iter().zip(core.elements.iter()).enumerate() {
        assert_eq!(
            served.as_str().expect("element hex"),
            hex_encode_bytes(expected),
            "sibling at level {level} must be the store's sibling, not filler"
        );
    }
    assert_eq!(
        entry["root"].as_str().expect("root hex"),
        hex_encode_bytes(&core.root),
        "served root must be the store's root"
    );
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
        .expect("body collect")
        .to_bytes()
        .to_vec()
}

#[tokio::test]
async fn merkle_proofs_route_returns_proof_per_blinded_commitment() {
    let (router, list_key, store) = build_router_with_store();
    let lk_hex = hex_encode_bytes(&list_key);
    let bc = fr_canonical(0x22);
    let bc_hex = hex_encode_bytes(&bc);
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
    assert_eq!(entry["leaf"].as_str(), Some(bc_hex.as_str()));

    let expected = {
        let guard = store.lock();
        let idx = guard
            .ppoi_index_of(&list_key, &bc)
            .expect("seeded bc must have an index");
        assert_eq!(idx, 1, "0x22 was seeded at list index 1");
        guard
            .ppoi_merkle_proof(&list_key, idx)
            .expect("store proof for seeded slot")
    };
    assert_served_proof_matches_store(entry, &expected);
}

/// Wallets send keys and commitments with or without `0x`; both must reach the same slot.
#[tokio::test]
async fn merkle_proofs_route_answers_a_0x_prefixed_list_key_and_commitment() {
    let (router, list_key, store) = build_router_with_store();
    let bc = fr_canonical(0x22);
    let payload = serde_json::json!({
        "listKey": format!("0x{}", hex_encode_bytes(&list_key)),
        "blindedCommitments": [format!("0x{}", hex_encode_bytes(&bc).to_uppercase())],
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/poi/merkle-proofs")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string()))
        .expect("build req");
    let resp = router.oneshot(req).await.expect("dispatch");
    assert_eq!(resp.status(), StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).expect("decode");
    let entry = &json.as_array().expect("array")[0];
    let expected = {
        let guard = store.lock();
        let idx = guard.ppoi_index_of(&list_key, &bc).expect("seeded");
        guard
            .ppoi_merkle_proof(&list_key, idx)
            .expect("store proof")
    };
    assert_served_proof_matches_store(entry, &expected);
}

#[tokio::test]
async fn merkle_proofs_route_404s_unknown_blinded_commitment() {
    let (router, list_key) = build_router();
    let lk_hex = hex_encode_bytes(&list_key);
    let bc_hex = hex_encode_bytes(&fr_canonical(0xff));
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
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn commit_tree_merkle_proof_route_returns_path() {
    let (router, _list_key, store) = build_router_with_store();
    let payload = serde_json::json!({ "leafIndex": 0u32 });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/commit-tree/0/merkle-proof")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string()))
        .expect("build req");
    let resp = router.oneshot(req).await.expect("dispatch");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("decode");

    let expected = {
        let guard = store.lock();
        assert_eq!(
            guard.leaf(0, 0),
            Some(&fr_canonical(0x01)),
            "leaf 0 of tree 0 was seeded as 0x01"
        );
        guard
            .merkle_proof(0, 0)
            .expect("store proof for seeded leaf")
    };
    assert_served_proof_matches_store(&json, &expected);
}

#[tokio::test]
async fn six_byte_prefix_channel_is_binary_and_index_ordered() {
    let (router, list_key) = build_router();
    let lk_hex = hex_encode_bytes(&list_key);
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/poi/{lk_hex}/bc-prefixes"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("dispatch");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/octet-stream")
    );
    let body = body_bytes(response).await;
    let expected: Vec<u8> = [0x11, 0x22, 0x33]
        .into_iter()
        .flat_map(|tag| {
            fr_canonical(tag)
                .into_iter()
                .take(raven_railgun_http::poi_shim::BC_INDEX_PREFIX_BYTES)
        })
        .collect();
    assert_eq!(
        body, expected,
        "row i is the prefix of the commitment seeded at index i"
    );
}

async fn post_json(router: Router, uri: &str, payload: &serde_json::Value) -> StatusCode {
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string()))
        .expect("build req");
    router.oneshot(req).await.expect("dispatch").status()
}

#[tokio::test]
async fn merkle_proofs_rejects_more_blinded_commitments_than_the_cap() {
    let (router, list_key) = build_router();
    let bcs: Vec<String> = (0..1025u64)
        .map(|i| {
            let mut bc = [0u8; 32];
            bc[16..24].copy_from_slice(&i.to_be_bytes());
            hex_encode_bytes(&bc)
        })
        .collect();
    let payload = serde_json::json!({
        "listKey": hex_encode_bytes(&list_key),
        "blindedCommitments": bcs,
    });
    assert_eq!(
        post_json(router, "/v1/poi/merkle-proofs", &payload).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "1025 blinded commitments must be refused before the store lock is taken; \
         uncapped this body walks every entry and answers 404 on the first unknown BC"
    );
}

/// The ETag is the digest of the body that was served, so a same-epoch rewrite
/// cannot reuse it. A 304 still has to say where to resume, or a caught-up client that
/// revalidates loses its cursor.
#[tokio::test]
async fn index_channel_etag_is_the_body_digest_and_a_304_still_says_where_to_resume() {
    use sha2::{Digest, Sha256};

    let (router, list_key) = build_router();
    let lk_hex = hex_encode_bytes(&list_key);
    let uri = format!("/v1/poi/{lk_hex}/bc-prefixes");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("dispatch");
    assert_eq!(response.status(), StatusCode::OK);
    let etag = response
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .expect("etag")
        .to_owned();
    let next = response
        .headers()
        .get("x-raven-index-next")
        .and_then(|v| v.to_str().ok())
        .expect("next")
        .to_owned();
    let body = body_bytes(response).await;

    let digest = Sha256::digest(&body);
    let expected = {
        use std::fmt::Write as _;
        let mut s = String::from("\"");
        for b in digest.iter().take(16) {
            let _ = write!(s, "{b:02x}");
        }
        s.push('"');
        s
    };
    assert_eq!(etag, expected, "the ETag must be the served body's digest");
    assert_eq!(
        body.len(),
        3 * raven_railgun_http::poi_shim::BC_INDEX_PREFIX_BYTES
    );

    let revalidated = router
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&uri)
                .header("if-none-match", &etag)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("dispatch");
    assert_eq!(revalidated.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(
        revalidated
            .headers()
            .get("x-raven-index-next")
            .and_then(|v| v.to_str().ok()),
        Some(next.as_str()),
        "a 304 must still carry the resume cursor"
    );
}
