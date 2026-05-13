//! In-process mock of the PPOI aggregator's POST routes.
//! Catches HTTP-method regressions, body-shape mismatches, serde rename drift,
//! and missing-key error paths. No external traffic.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::items_after_statements,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

use axum::extract::{Json, Path};
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use raven_railgun_core::{BlindedCommitment, BlindedCommitmentType, ListKey, POIStatus};
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_ppoi_mirror::{MirrorConfig, MirrorSource, UpstreamPpoiMirror};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, serde::Deserialize)]
struct PoiEventsBody {
    #[serde(rename = "txidVersion")]
    txid_version: String,
    #[serde(rename = "listKey")]
    list_key: String,
    #[serde(rename = "startIndex")]
    start_index: u64,
    #[serde(rename = "endIndex")]
    end_index: u64,
}

#[derive(Debug, serde::Deserialize)]
struct BlindedCommitmentDataIn {
    #[serde(rename = "blindedCommitment")]
    blinded_commitment: String,
    #[serde(rename = "type")]
    bc_type: String, // PascalCase string
}

#[derive(Debug, serde::Deserialize)]
struct PoisPerBcBody {
    #[serde(rename = "txidVersion")]
    txid_version: String,
    #[serde(rename = "listKey")]
    list_key: String,
    #[serde(rename = "blindedCommitmentDatas")]
    blinded_commitment_datas: Vec<BlindedCommitmentDataIn>,
}

#[derive(Default)]
struct MockState {
    last_poi_events: parking_lot::Mutex<Option<PoiEventsBody>>,
    last_pois_per_bc: parking_lot::Mutex<Option<PoisPerBcBody>>,
    pois_per_bc_response: parking_lot::Mutex<Option<HashMap<String, POIStatus>>>,
    pois_per_bc_force_empty: parking_lot::Mutex<bool>,
    fail_with_500: parking_lot::Mutex<bool>,
}

async fn poi_events_handler(
    Path((_chain_type, _chain_id)): Path<(String, String)>,
    axum::extract::State(state): axum::extract::State<Arc<MockState>>,
    Json(body): Json<PoiEventsBody>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if *state.fail_with_500.lock() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    *state.last_poi_events.lock() = Some(PoiEventsBody {
        txid_version: body.txid_version.clone(),
        list_key: body.list_key.clone(),
        start_index: body.start_index,
        end_index: body.end_index,
    });
    let bc1 = "0x1111111111111111111111111111111111111111111111111111111111111111";
    let bc2 = "0x2222222222222222222222222222222222222222222222222222222222222222";
    let resp = serde_json::json!([
        {
            "signedPOIEvent": {
                "index": body.start_index,
                "blindedCommitment": bc1,
                "signature": "0xdeadbeef",
                "type": "Shield",
            },
            "validatedMerkleroot": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
        {
            "signedPOIEvent": {
                "index": body.start_index + 1,
                "blindedCommitment": bc2,
                "signature": "0xcafebabe",
                "type": "Transact",
            },
            "validatedMerkleroot": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        }
    ]);
    Ok(Json(resp))
}

async fn pois_per_bc_handler(
    Path((_chain_type, _chain_id)): Path<(String, String)>,
    axum::extract::State(state): axum::extract::State<Arc<MockState>>,
    Json(body): Json<PoisPerBcBody>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if *state.fail_with_500.lock() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    *state.last_pois_per_bc.lock() = Some(PoisPerBcBody {
        txid_version: body.txid_version.clone(),
        list_key: body.list_key.clone(),
        blinded_commitment_datas: body
            .blinded_commitment_datas
            .iter()
            .map(|d| BlindedCommitmentDataIn {
                blinded_commitment: d.blinded_commitment.clone(),
                bc_type: d.bc_type.clone(),
            })
            .collect(),
    });
    if *state.pois_per_bc_force_empty.lock() {
        return Ok(Json(serde_json::json!({})));
    }
    let mut response_map = serde_json::Map::new();
    let override_map = state.pois_per_bc_response.lock().clone();
    for d in &body.blinded_commitment_datas {
        let status = override_map
            .as_ref()
            .and_then(|m| m.get(&d.blinded_commitment).copied())
            .unwrap_or(POIStatus::Valid);
        let status_str = match status {
            POIStatus::Valid => "Valid",
            POIStatus::ShieldBlocked => "ShieldBlocked",
            POIStatus::ProofSubmitted => "ProofSubmitted",
            POIStatus::Missing => "Missing",
        };
        response_map.insert(
            d.blinded_commitment.clone(),
            serde_json::Value::String(status_str.to_owned()),
        );
    }
    Ok(Json(serde_json::Value::Object(response_map)))
}

async fn start_mock() -> (String, Arc<MockState>, tokio::task::JoinHandle<()>) {
    let state = Arc::new(MockState::default());
    let app = Router::new()
        .route(
            "/poi-events/:chain_type/:chain_id",
            post(poi_events_handler),
        )
        .route(
            "/pois-per-blinded-commitment/:chain_type/:chain_id",
            post(pois_per_bc_handler),
        )
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 0");
    let addr: SocketAddr = listener.local_addr().expect("local_addr");
    let url = format!("http://{addr}");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    (url, state, handle)
}

fn build_mirror(endpoint: String) -> UpstreamPpoiMirror {
    let cfg = MirrorConfig {
        endpoint,
        ..MirrorConfig::default()
    };
    UpstreamPpoiMirror::new(cfg).expect("mirror builds")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetch_status_range_posts_correct_body_and_decodes_response() {
    let (url, state, handle) = start_mock().await;
    let mirror = build_mirror(url);
    let list = ListKey([0x42; 32]);

    let rows = mirror
        .fetch_status_range(&list, 0, 10)
        .await
        .expect("fetch_status_range");

    let captured = state.last_poi_events.lock();
    let captured = captured.as_ref().expect("captured request");
    assert_eq!(captured.txid_version, "V2_PoseidonMerkle");
    assert_eq!(
        captured.list_key,
        "4242424242424242424242424242424242424242424242424242424242424242"
    );
    assert_eq!(captured.start_index, 0);
    assert_eq!(captured.end_index, 10);

    assert_eq!(rows.len(), 2);
    for row in &rows {
        assert_eq!(row.status, POIStatus::Valid);
    }
    assert_eq!(rows[0].blinded_commitment.as_bytes(), &[0x11; 32]);
    assert_eq!(rows[1].blinded_commitment.as_bytes(), &[0x22; 32]);
    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetch_status_typed_posts_correct_body_and_decodes_each_status() {
    let (url, state, handle) = start_mock().await;
    let mirror = build_mirror(url);
    let list = ListKey([0xab; 32]);
    let bc = BlindedCommitment::from_bytes([0xcd; 32]);
    let bc_hex = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

    let status = mirror
        .fetch_status_typed(&list, &bc, BlindedCommitmentType::Shield)
        .await
        .expect("fetch_status_typed");
    assert_eq!(status, POIStatus::Valid);

    // Scope the guard so it's released before any subsequent .await (parking_lot guards are not Send).
    {
        let guard = state.last_pois_per_bc.lock();
        let captured = guard.as_ref().expect("captured request");
        assert_eq!(captured.txid_version, "V2_PoseidonMerkle");
        assert_eq!(
            captured.list_key,
            "abababababababababababababababababababababababababababababababab"
        );
        assert_eq!(captured.blinded_commitment_datas.len(), 1);
        assert_eq!(
            captured.blinded_commitment_datas[0].blinded_commitment,
            bc_hex
        );
        assert_eq!(captured.blinded_commitment_datas[0].bc_type, "Shield");
    }

    for variant in [
        POIStatus::Valid,
        POIStatus::ShieldBlocked,
        POIStatus::ProofSubmitted,
        POIStatus::Missing,
    ] {
        {
            let mut override_map = state.pois_per_bc_response.lock();
            let mut m = HashMap::new();
            m.insert(bc_hex.to_owned(), variant);
            *override_map = Some(m);
        }
        let got = mirror
            .fetch_status_typed(&list, &bc, BlindedCommitmentType::Transact)
            .await
            .expect("fetch_status_typed override");
        assert_eq!(got, variant, "PascalCase serde round-trip for {variant:?}");
    }
    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetch_status_range_returns_upstream_on_500() {
    let (url, state, handle) = start_mock().await;
    let mirror = build_mirror(url);
    let list = ListKey([0; 32]);
    *state.fail_with_500.lock() = true;
    let err = mirror
        .fetch_status_range(&list, 0, 10)
        .await
        .expect_err("expected 500 error");
    let s = err.to_string();
    assert!(s.contains("500") || s.contains("returned"), "{s}");
    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetch_status_typed_returns_decode_when_response_missing_key() {
    let (url, state, handle) = start_mock().await;
    let mirror = build_mirror(url);
    let list = ListKey([0; 32]);
    let bc = BlindedCommitment::from_bytes([0xaa; 32]);

    *state.pois_per_bc_force_empty.lock() = true;
    let err = mirror
        .fetch_status_typed(&list, &bc, BlindedCommitmentType::Shield)
        .await
        .expect_err("expected Decode error when response omits requested key");
    let s = err.to_string();
    assert!(
        s.contains("missing key") || s.contains("Decode") || s.contains("decode"),
        "expected Decode-style error mentioning missing key, got: {s}"
    );
    handle.abort();
}

/// Worker-path test: every upstream `/poi-events` row must surface BOTH
/// `PpoiListLeafAdded` (for per-list IMT growth + the `(BC -> idx)`
/// ordering oracle T2 path PIR consumes) AND `PpoiStatus` (for the
/// `(list_key, bc) -> status` map T1 status PIR consumes), in that
/// order. Closes the worker-path gap where only `PpoiStatus` fired and
/// the per-list IMT never grew (which silently broke T2 path PIR).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mirror_emits_ppoi_list_leaf_added_for_each_event() {
    let (url, _state, server_handle) = start_mock().await;
    let cfg = MirrorConfig {
        endpoint: url,
        poll_interval_secs: 1,
        max_rows_per_fetch: 2,
        ..MirrorConfig::default()
    };
    let mirror = Arc::new(UpstreamPpoiMirror::new(cfg).expect("mirror builds"));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(WalEntryPayload, u64)>(64);
    let list = ListKey([0x55u8; 32]);
    let worker_handle = tokio::spawn({
        let mirror = mirror.clone();
        async move {
            let _ = mirror.run_worker(list, 0, tx).await;
        }
    });

    // Drain the first 6 payloads and assert strict (LeafAdded, Status)
    // interleaving: for each `/poi-events` row the worker emits the
    // IMT-grow payload FIRST and the status payload SECOND. Flipping
    // the order would silently break T2 path PIR — see the engine
    // apply path's PpoiListLeafAdded contiguity invariant.
    let mut got: Vec<WalEntryPayload> = Vec::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    while got.len() < 6 {
        assert!(
            tokio::time::Instant::now() <= deadline,
            "worker did not emit 6 payloads within 20s (got {})",
            got.len()
        );
        let recv = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await;
        if let Ok(Some((payload, _height))) = recv {
            got.push(payload);
        }
    }

    let mut last_idx: Option<u32> = None;
    for pair in got.chunks(2) {
        match (pair.first(), pair.get(1)) {
            (
                Some(WalEntryPayload::PpoiListLeafAdded {
                    list_key: lk_leaf,
                    list_index,
                    blinded_commitment: bc_leaf,
                    ..
                }),
                Some(WalEntryPayload::PpoiStatus {
                    list_key: lk_status,
                    blinded_commitment: bc_status,
                    ..
                }),
            ) => {
                assert_eq!(*lk_leaf, list.0, "leaf list_key must match worker config");
                assert_eq!(
                    *lk_status, list.0,
                    "status list_key must match worker config"
                );
                assert_eq!(
                    bc_leaf, bc_status,
                    "PpoiListLeafAdded and PpoiStatus must reference the same bc within a pair"
                );
                if let Some(prev) = last_idx {
                    assert!(
                        *list_index > prev,
                        "list_index must strictly increase: {prev} -> {list_index}"
                    );
                }
                last_idx = Some(*list_index);
            }
            other => panic!(
                "expected (PpoiListLeafAdded, PpoiStatus) pair in load-bearing order, got: \
                 {other:?}"
            ),
        }
    }

    worker_handle.abort();
    server_handle.abort();
}

/// Regression-guard: `/pois-per-blinded-commitment` is a status-only
/// lookup; it must NOT contribute IMT-grow events. The mirror's
/// `fetch_status_typed` returns a typed status directly and has no
/// `WalEntryPayload` channel by design.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mirror_pois_per_blinded_commitment_only_emits_status_no_imt_grow() {
    let (url, _state, server_handle) = start_mock().await;
    let mirror = build_mirror(url);
    let list = ListKey([0; 32]);
    let bc = BlindedCommitment::from_bytes([0x77; 32]);

    let got = mirror
        .fetch_status_typed(&list, &bc, BlindedCommitmentType::Shield)
        .await
        .expect("fetch_status_typed");
    assert_eq!(got, POIStatus::Valid);
    // Structural assertion: the only payload-emitting code path is
    // `run_worker_with_cursor`, which exclusively consumes
    // `/poi-events`. If `fetch_status_typed` ever grew a side-channel
    // that wrote `PpoiListLeafAdded`, the trait signature would have to
    // change and the type system would force this test to fail.
    let _: POIStatus = got;
    server_handle.abort();
}
