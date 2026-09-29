//! In-process mock of the PPOI aggregator's JSON-RPC route.
//! Catches body-shape mismatches, serde rename drift, and what the feed hands the engine for
//! each row. No external traffic.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use axum::extract::Json;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use raven_railgun_core::ListKey;
use raven_railgun_persistence::{PpoiEventType, WalEntryPayload};
use raven_railgun_ppoi_mirror::test_signer::TestListSigner;
use raven_railgun_ppoi_mirror::{FeedStatus, MirrorConfig, MirrorError, UpstreamPpoiMirror};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

fn provider() -> TestListSigner {
    TestListSigner::new(0x55)
}

#[derive(Default)]
struct MockState {
    requests: parking_lot::Mutex<Vec<Value>>,
}

/// Two rows per page, a Shield then a Transact, starting at the requested index.
async fn json_rpc_handler(
    axum::extract::State(state): axum::extract::State<Arc<MockState>>,
    Json(request): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    state.requests.lock().push(request.clone());
    if request["method"] != "ppoi_poi_events" {
        return Err(StatusCode::NOT_FOUND);
    }
    let start = request["params"]["startIndex"]
        .as_u64()
        .ok_or(StatusCode::BAD_REQUEST)?;
    let row = |index, commitment: &str, event_type, root: &str| {
        provider()
            .row(
                index,
                &format!("0x{}", commitment.repeat(32)),
                event_type,
                &format!("0x{}", root.repeat(32)),
            )
            .expect("signs")
    };
    let result = json!([
        row(start, "11", "Shield", "aa"),
        row(start + 1, "22", "Transact", "bb"),
    ]);
    Ok(Json(
        json!({ "jsonrpc": "2.0", "id": request["id"], "result": result }),
    ))
}

async fn start_mock() -> (String, Arc<MockState>) {
    let state = Arc::new(MockState::default());
    let app = Router::new()
        .route("/", post(json_rpc_handler))
        .with_state(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 0");
    let url = format!("http://{}", listener.local_addr().expect("local_addr"));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (url, state)
}

/// Two pages of two rows, then the span ends: each row reaches the engine as exactly one
/// `PpoiListLeafAdded` at height 0, carrying the upstream fields the WAL keeps, and nothing else
/// is sent for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_row_reaches_the_engine_as_one_leaf_carrying_its_upstream_fields() {
    let (url, state) = start_mock().await;
    let mirror = Arc::new(
        UpstreamPpoiMirror::new(MirrorConfig {
            endpoint: url,
            poll_interval_secs: 1,
            max_rows_per_fetch: 2,
            ..MirrorConfig::default()
        })
        .expect("mirror builds"),
    );
    let list = ListKey(provider().list_key());
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(WalEntryPayload, u64)>(64);
    let stopped = tokio::time::timeout(
        Duration::from_secs(30),
        mirror.run_feed(list, 0, |cursor| cursor..4, FeedStatus::default(), tx),
    )
    .await
    .expect("the feed stops at the end of its span");
    assert!(
        matches!(stopped, Err(MirrorError::Unheld { list_index: 4 })),
        "{stopped:?}"
    );

    {
        let requests = state.requests.lock();
        assert_eq!(requests.len(), 2, "{requests:?}");
        for (request, start) in requests.iter().zip([0u64, 2]) {
            assert_eq!(request["jsonrpc"], "2.0");
            assert_eq!(request["method"], "ppoi_poi_events");
            let params = &request["params"];
            assert_eq!(params["chainType"], "0");
            assert_eq!(params["chainID"], "1");
            assert_eq!(params["txidVersion"], "V2_PoseidonMerkle");
            assert_eq!(params["listKey"], provider().list_key_hex());
            assert_eq!(params["startIndex"], start);
            assert_eq!(params["endIndex"], start + 1);
        }
    }

    let mut sent = Vec::new();
    while let Ok(item) = rx.try_recv() {
        sent.push(item);
    }
    assert_eq!(
        sent.len(),
        4,
        "one payload per row and no status row beside it: {sent:?}"
    );
    for (index, (payload, height)) in (0u32..).zip(&sent) {
        assert_eq!(*height, 0, "reorg unwinds must never reach a mirrored row");
        let WalEntryPayload::PpoiListLeafAdded {
            list_key,
            list_index,
            blinded_commitment,
            event_type,
            validated_merkleroot,
        } = payload
        else {
            panic!("row {index} reached the engine as {payload:?}");
        };
        let second = index % 2 == 1;
        assert_eq!(*list_key, list.0);
        assert_eq!(*list_index, index);
        assert_eq!(*blinded_commitment, [if second { 0x22 } else { 0x11 }; 32]);
        assert_eq!(
            *event_type,
            if second {
                PpoiEventType::Transact
            } else {
                PpoiEventType::Shield
            }
        );
        assert_eq!(
            *validated_merkleroot,
            [if second { 0xbb } else { 0xaa }; 32]
        );
    }
}

/// Binds the crate doc's membership statement to the code it describes. A change that makes a
/// verdict nameable in the mirror reds here even when no mock row exercises it, so the statement
/// cannot drift away from the code while every other gate passes.
#[test]
fn the_membership_statement_matches_a_mirror_that_names_no_verdict() {
    let lib_src = include_str!("../src/lib.rs");
    for sentence in [
        "`ppoi_poi_events` carries membership, not a verdict.",
        "So a row this mirror delivers carries no status",
    ] {
        assert!(
            lib_src.contains(sentence),
            "the crate doc must still state what a mirrored row says; missing: {sentence}"
        );
    }
    let code = &lib_src[..lib_src.find("#[cfg(test)]").expect("test module")];
    assert_eq!(
        code.matches("POIStatus").count(),
        0,
        "the mirror names a POIStatus: it is emitting a verdict from a response that carries only \
         membership. Settle it against upstream and update the crate doc's membership statement \
         before changing this"
    );
}
