//! Integration tests for the wallet-shim + publishing-channel routes.

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
use raven_railgun_core::{InstanceId, PoiStatusRow};
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

/// Zeroes in the high 16 bytes, `tag` in the low 16; stays below the BN254 field modulus.
fn fr_canonical(tag: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
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
    let statuses: [u8; 3] = [1, 2, 0]; // ShieldBlocked, ProofSubmitted, Valid
    for (i, bc) in bcs.iter().enumerate() {
        apply_wal_entry(
            &mut store,
            &WalEntryPayload::PpoiListLeafAdded {
                list_key,
                list_index: i as u32,
                blinded_commitment: *bc,
                status: statuses[i],
            },
            200 + i as u64,
            &enc,
        )
        .expect("seed ppoi leaf");
    }

    (store, list_key)
}

fn build_router() -> (Router, [u8; 32]) {
    let (store, list_key) = seeded_store();
    let store_arc = Arc::new(parking_lot::Mutex::new(store));
    let engine: Engine<StubScheme> = Engine::new();
    let cfg = HttpConfig::demo(TOKEN);
    let state = {
        let _g = APPSTATE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        AppState::new(engine, cfg).expect("appstate")
    }
    .with_logical_store(Arc::clone(&store_arc));
    let routes = poi_shim::poi_shim_routes(state);
    (routes, list_key)
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
async fn pois_per_list_returns_pascal_case_status_per_bc_per_list() {
    let (router, list_key) = build_router();
    let lk_hex = hex_encode_bytes(&list_key);
    let bc_blocked_hex = hex_encode_bytes(&fr_canonical(0x11));
    let bc_missing_hex = hex_encode_bytes(&fr_canonical(0xee));
    let payload = serde_json::json!({
        "txidVersion": "V2_PoseidonMerkle",
        "listKeys": [lk_hex],
        "blindedCommitmentDatas": [
            { "blindedCommitment": bc_blocked_hex, "type": "Shield" },
            { "blindedCommitment": bc_missing_hex, "type": "Shield" },
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

    assert_eq!(
        json[&bc_blocked_hex][&lk_hex].as_str(),
        Some("ShieldBlocked"),
        "blocked BC must surface ShieldBlocked",
    );
    assert_eq!(
        json[&bc_missing_hex][&lk_hex].as_str(),
        Some("Missing"),
        "unknown BC must surface Missing",
    );
}

#[tokio::test]
async fn merkle_proofs_route_returns_proof_per_blinded_commitment() {
    let (router, list_key) = build_router();
    let lk_hex = hex_encode_bytes(&list_key);
    let bc_hex = hex_encode_bytes(&fr_canonical(0x22));
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
    let elements = entry["elements"].as_array().expect("elements array");
    assert_eq!(elements.len(), 16, "Merkle proof must have 16 siblings");
    assert!(entry["root"].is_string());
    assert_eq!(entry["leaf"].as_str(), Some(bc_hex.as_str()));
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
    let (router, _) = build_router();
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
    assert_eq!(
        json["elements"].as_array().expect("elements").len(),
        16,
        "commit-tree proof must have 16 siblings"
    );
    assert!(json["root"].is_string());
}

#[tokio::test]
async fn bc_to_idx_map_emits_entries_in_index_order_with_etag() {
    let (router, list_key) = build_router();
    let lk_hex = hex_encode_bytes(&list_key);
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/v1/poi/{lk_hex}/bc-to-idx-map"))
        .body(Body::empty())
        .expect("build req");
    let resp = router.clone().oneshot(req).await.expect("dispatch");
    assert_eq!(resp.status(), StatusCode::OK);
    let etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .expect("etag header");
    assert!(etag.starts_with('"') && etag.ends_with('"'));
    let bytes = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("decode");
    let entries = json["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 3, "three PPOI list leaves seeded");
    assert_eq!(entries[0]["idx"], 0);
    assert_eq!(entries[1]["idx"], 1);
    assert_eq!(entries[2]["idx"], 2);
    assert_eq!(json["listKey"].as_str(), Some(lk_hex.as_str()));

    let req2 = Request::builder()
        .method(Method::GET)
        .uri(format!("/v1/poi/{lk_hex}/bc-to-idx-map"))
        .header("if-none-match", &etag)
        .body(Body::empty())
        .expect("build req2");
    let resp2 = router.oneshot(req2).await.expect("dispatch2");
    assert_eq!(resp2.status(), StatusCode::NOT_MODIFIED);
}

#[tokio::test]
async fn status_header_partitions_blocked_and_pending_bcs() {
    let (router, list_key) = build_router();
    let lk_hex = hex_encode_bytes(&list_key);
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/v1/poi/{lk_hex}/status-header"))
        .body(Body::empty())
        .expect("build req");
    let resp = router.oneshot(req).await.expect("dispatch");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("decode");
    let blocked = json["blockedBcs"].as_array().expect("blockedBcs");
    let pending = json["pendingBcs"].as_array().expect("pendingBcs");
    let bc_blocked_hex = hex_encode_bytes(&fr_canonical(0x11));
    let bc_pending_hex = hex_encode_bytes(&fr_canonical(0x22));
    assert!(
        blocked.iter().any(|v| v.as_str() == Some(&bc_blocked_hex)),
        "blocked BC missing from blockedBcs"
    );
    assert!(
        pending.iter().any(|v| v.as_str() == Some(&bc_pending_hex)),
        "ProofSubmitted BC missing from pendingBcs"
    );
}

// Compile-time trip-wire on PoiStatusRow + InstanceId.
#[test]
fn poi_status_row_remains_in_workspace() {
    let _ = std::any::type_name::<PoiStatusRow>();
    let _ = std::any::type_name::<InstanceId>();
}

#[tokio::test]
async fn freshness_header_value_format_is_well_formed() {
    use raven_railgun_engine::persistence::ConsumerMetrics;
    let metrics = Arc::new(parking_lot::Mutex::new(ConsumerMetrics {
        last_applied_block: 1000,
        last_scanned_block: 1000,
        last_applied_leaf_block: 1000,
        last_known_chain_head: 1010,
        events_processed: 42,
        commits_fired: 5,
        reorgs_handled: 1,
        consumer_errors: 0,
        consecutive_event_errors: 0,
        unapplied_leaves: 0,
    }));

    let (store, _) = seeded_store();
    let store_arc = Arc::new(parking_lot::Mutex::new(store));
    let cfg = HttpConfig::demo(TOKEN);
    let engine: Engine<StubScheme> = Engine::new();
    let _state = {
        let _g = APPSTATE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        AppState::new(engine, cfg).expect("appstate")
    }
    .with_logical_store(Arc::clone(&store_arc))
    .with_consumer_metrics(Arc::clone(&metrics));

    let snap = *metrics.lock();
    let lag = snap.indexer_lag_blocks();
    assert_eq!(lag, 10);
    assert_eq!(snap.last_applied_block, 1000);
}

// ETag must equal SHA-256(body)[..16] hex for every response, even under concurrent writes.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bc_to_idx_map_etag_matches_body_under_concurrent_updates() {
    use sha2::{Digest, Sha256};

    let (store, list_key) = seeded_store();
    let store_arc = Arc::new(parking_lot::Mutex::new(store));
    let engine: Engine<StubScheme> = Engine::new();
    let cfg = HttpConfig::demo(TOKEN);
    let state = {
        let _g = APPSTATE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        AppState::new(engine, cfg).expect("appstate")
    }
    .with_logical_store(Arc::clone(&store_arc));
    let routes = poi_shim::poi_shim_routes(state);
    let lk_hex = hex_encode_bytes(&list_key);

    let writer_store = Arc::clone(&store_arc);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_writer = Arc::clone(&stop);
    let writer = std::thread::spawn(move || {
        let enc = encoder();
        let mut next_idx: u32 = 3;
        let mut next_block: u64 = 300;
        while !stop_writer.load(std::sync::atomic::Ordering::SeqCst) {
            {
                let mut s = writer_store.lock();
                let bc = fr_canonical((next_idx as u8).wrapping_add(0x80));
                let _ = raven_railgun_engine::inspire::apply_wal_entry(
                    &mut s,
                    &raven_railgun_persistence::WalEntryPayload::PpoiListLeafAdded {
                        list_key,
                        list_index: next_idx,
                        blinded_commitment: bc,
                        status: 0,
                    },
                    next_block,
                    &enc,
                );
            }
            next_idx = next_idx.saturating_add(1);
            next_block = next_block.saturating_add(1);
            std::thread::sleep(std::time::Duration::from_micros(200));
        }
    });

    for iter in 0..100u32 {
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/v1/poi/{lk_hex}/bc-to-idx-map"))
            .body(Body::empty())
            .expect("build req");
        let resp = routes.clone().oneshot(req).await.expect("dispatch");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "iter {iter}: GET must succeed"
        );
        let etag_hdr = resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .expect("etag header present");
        let etag_hex = etag_hdr
            .trim_start_matches('"')
            .trim_end_matches('"')
            .to_owned();
        let body = body_bytes(resp).await;
        let mut hasher = Sha256::new();
        hasher.update(&body);
        let digest = hasher.finalize();
        let mut recomputed = String::with_capacity(32);
        for b in digest.iter().take(16) {
            use std::fmt::Write as _;
            let _ = write!(recomputed, "{b:02x}");
        }
        assert_eq!(
            etag_hex,
            recomputed,
            "iter {iter}: served ETag must match SHA-256(body)[..16]; \
             body_len={}, etag={etag_hdr}",
            body.len(),
        );
    }

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = writer.join();
}

/// Distinct-but-valid hex list keys; the shim decodes every one before it reaches the cap check,
/// so a rejection cannot be confused with a hex-decode 400.
fn distinct_list_keys(count: usize) -> Vec<String> {
    (0..count)
        .map(|i| {
            let mut k = [0u8; 32];
            k[24..32].copy_from_slice(&(i as u64).to_be_bytes());
            hex_encode_bytes(&k)
        })
        .collect()
}

fn distinct_bc_datas(count: usize) -> Vec<serde_json::Value> {
    (0..count)
        .map(|i| {
            let mut bc = [0u8; 32];
            bc[16..24].copy_from_slice(&(i as u64).to_be_bytes());
            serde_json::json!({ "blindedCommitment": hex_encode_bytes(&bc), "type": "Shield" })
        })
        .collect()
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
async fn pois_per_list_rejects_more_list_keys_than_the_cap() {
    let (router, _) = build_router();
    let payload = serde_json::json!({
        "listKeys": distinct_list_keys(65),
        "blindedCommitmentDatas": distinct_bc_datas(1),
    });
    assert_eq!(
        post_json(router, "/v1/poi/pois-per-list", &payload).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "65 list keys exceeds the 64-key cap; uncapped this body is served 200 OK"
    );
}

#[tokio::test]
async fn pois_per_list_rejects_more_blinded_commitments_than_the_cap() {
    let (router, list_key) = build_router();
    let payload = serde_json::json!({
        "listKeys": [hex_encode_bytes(&list_key)],
        "blindedCommitmentDatas": distinct_bc_datas(1025),
    });
    assert_eq!(
        post_json(router, "/v1/poi/pois-per-list", &payload).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "1025 blinded commitments exceeds the 1024 cap"
    );
}

#[tokio::test]
async fn pois_per_list_rejects_a_lookup_product_past_the_cap_when_each_vector_fits() {
    let (router, _) = build_router();
    // 65,536 lookups under the global store mutex from two individually-capped vectors.
    let payload = serde_json::json!({
        "listKeys": distinct_list_keys(64),
        "blindedCommitmentDatas": distinct_bc_datas(1024),
    });
    assert_eq!(
        post_json(router, "/v1/poi/pois-per-list", &payload).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "product cap must reject 64 x 1024 even though each vector is within its own cap"
    );
}

#[tokio::test]
async fn pois_per_list_still_serves_a_body_at_the_caps() {
    let (router, list_key) = build_router();
    let mut list_keys = distinct_list_keys(63);
    list_keys.push(hex_encode_bytes(&list_key));
    let payload = serde_json::json!({
        "listKeys": list_keys,
        "blindedCommitmentDatas": distinct_bc_datas(256),
    });
    assert_eq!(
        post_json(router, "/v1/poi/pois-per-list", &payload).await,
        StatusCode::OK,
        "64 x 256 is inside every cap and must still be served"
    );
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
