//! Records today's behaviour when a consumer refuses one row: the cursor has
//! already moved past it, so the list stops and never recovers. This is a
//! wedge, and the test exists to make it reproducible, not to approve it. A
//! green run here is a green run over a defect.
//!
//! The mirror advances and persists its cursor on SEND
//! (`ppoi-mirror/src/lib.rs:493-514`), with no apply or ack from the consumer.
//! Upstream instead derives its start index from the store's own event count on
//! every poll — `packages/node/src/sync/round-robin-syncer.ts:209-213` reads
//! `POIEventList.getOverallEventsLength` before each page — so a row it fails to
//! store is simply requested again.
//!
//! The consumer here is a local stand-in: this crate cannot depend on the
//! engine, so the contiguity rule at
//! `engine/src/inspire/logical_store.rs:110-112` is restated in
//! `WedgedConsumer`. The load-bearing assertions are the mirror's own
//! observables — which start indices the upstream was asked for, and what the
//! sidecar holds; the applied count only makes the consequence visible.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::items_after_statements,
    clippy::indexing_slicing,
    clippy::missing_panics_doc
)]

use axum::extract::Json;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use raven_railgun_core::ListKey;
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_ppoi_mirror::{
    MirrorConfig, MirrorCursor, MirrorKind, UpstreamPpoiMirror, MIRROR_CURSOR_SIDECAR_BYTES,
};
use std::net::SocketAddr;
use std::sync::Arc;

const PAGE: u64 = 4;
/// The row the consumer refuses. Stands for any consumer-side refusal: a root
/// divergence, a non-canonical leaf, or a transport corruption.
const REFUSED: u32 = 1;

#[derive(Default)]
struct MockState {
    starts: parking_lot::Mutex<Vec<u64>>,
}

async fn poi_events_handler(
    axum::extract::State(state): axum::extract::State<Arc<MockState>>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let body = request.get("params").ok_or(StatusCode::BAD_REQUEST)?;
    let start = body
        .get("startIndex")
        .and_then(serde_json::Value::as_u64)
        .ok_or(StatusCode::BAD_REQUEST)?;
    state.starts.lock().push(start);
    let events: Vec<serde_json::Value> = (0..PAGE).map(|off| row(start + off)).collect();
    Ok(Json(serde_json::json!({
        "jsonrpc": "2.0",
        "id": request["id"],
        "result": events
    })))
}

fn row(index: u64) -> serde_json::Value {
    serde_json::json!({
        "signedPOIEvent": {
            "index": index,
            "blindedCommitment": format!("0x{:064x}", index + 1),
            "signature": "00".repeat(64),
            "type": "Shield",
        },
        "validatedMerkleroot": format!("{:064x}", index + 1),
    })
}

async fn start_mock() -> (String, Arc<MockState>, tokio::task::JoinHandle<()>) {
    let state = Arc::new(MockState::default());
    let app = Router::new()
        .route("/", post(poi_events_handler))
        .with_state(Arc::clone(&state));
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

/// Restates the engine's per-list contiguity rule: a leaf whose index is not the
/// next expected one is refused, and a refusal drops the row rather than
/// stalling the feed.
#[derive(Default)]
struct WedgedConsumer {
    expected: u32,
    applied: Vec<u32>,
}

impl WedgedConsumer {
    fn offer(&mut self, list_index: u32) {
        if list_index == REFUSED || list_index != self.expected {
            return;
        }
        self.applied.push(list_index);
        self.expected += 1;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_row_the_consumer_refuses_is_never_requested_again_and_the_list_stops() {
    let (url, mock, server) = start_mock().await;
    let mirror = Arc::new(
        UpstreamPpoiMirror::new(MirrorConfig {
            endpoint: url,
            poll_interval_secs: 1,
            max_rows_per_fetch: PAGE,
            ..MirrorConfig::default()
        })
        .expect("mirror builds"),
    );
    let scratch = tempfile::tempdir().expect("tempdir");
    let cursor = MirrorCursor::new(scratch.path().to_path_buf(), MirrorKind::Path, 0);
    let sidecar = cursor.sidecar_path();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<(WalEntryPayload, u64)>(128);
    let worker = tokio::spawn({
        let mirror = Arc::clone(&mirror);
        async move {
            let _ = mirror
                .run_worker_with_cursor(ListKey([0x41; 32]), 0, Some(cursor), tx)
                .await;
        }
    });

    let mut consumer = WedgedConsumer::default();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    while mock.starts.lock().len() < 3 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "mock did not serve 3 pages within 30s"
        );
        if let Ok(Some((WalEntryPayload::PpoiListLeafAdded { list_index, .. }, _))) =
            tokio::time::timeout(std::time::Duration::from_millis(250), rx.recv()).await
        {
            consumer.offer(list_index);
        }
    }
    worker.abort();
    let _ = worker.await;
    server.abort();

    let starts = mock.starts.lock().clone();
    assert_eq!(starts[0], 0, "first page starts at the fallback cursor");
    assert!(
        starts[1..].iter().all(|s| *s > u64::from(REFUSED)),
        "index {REFUSED} is never asked for again: {starts:?}"
    );
    assert!(
        starts.windows(2).all(|w| w[1] > w[0]),
        "the cursor only moves forward: {starts:?}"
    );

    let bytes = std::fs::read(&sidecar).expect("sidecar written after the first page");
    assert_eq!(bytes.len(), MIRROR_CURSOR_SIDECAR_BYTES);
    let persisted = u64::from_le_bytes(bytes.try_into().expect("sidecar width"));
    assert!(
        persisted > u64::from(REFUSED),
        "the persisted cursor is already past the refused row ({persisted}), so a restart \
         resumes past it too"
    );

    assert_eq!(
        consumer.applied,
        vec![0],
        "one refusal stops the list at the row before it, for every later row"
    );
}
