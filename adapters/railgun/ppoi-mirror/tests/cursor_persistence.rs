//! Cursor persistence integration tests for `UpstreamPpoiMirror`.
//!
//! Closes the operator-observed bug where every restart re-emitted
//! upstream events from index 0 because the worker held its cursor on
//! the stack. The mirror now writes a per-(list_key, kind) sidecar
//! into the operator-supplied data_dir on every successful upstream
//! batch and resumes from it on the next worker spawn.
//!
//! Failure-injection coverage:
//!
//! - status / path kinds round-trip independently across a restart.
//! - missing sidecar falls back to caller-supplied LLS-derived value.
//! - missing sidecar AND zero LLS falls back to 0 cleanly.
//! - torn-temp at the rename step never produces a half-decoded
//!   cursor; the worker either reads the prior valid sidecar OR the
//!   fallback.

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
use raven_railgun_core::ListKey;
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_ppoi_mirror::{
    MirrorConfig, MirrorCursor, MirrorKind, UpstreamPpoiMirror, MIRROR_CURSOR_SIDECAR_BYTES,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Mock upstream that hands back exactly `start_index..start_index +
/// MOCK_BATCH` events on every poll, with monotone `index` fields. The
/// bug is observable only when `index` is monotone-increasing across
/// restart boundaries: a non-resuming worker re-fires from 0 every
/// boot, and the engine's contiguity check (`expected list_index N,
/// got 0..N-1`) tells us we regressed.
const MOCK_BATCH: u64 = 4;

#[derive(Default)]
struct MockState {
    /// Highest `start_index` the mock has seen so a test can audit
    /// "did the worker resume from a non-zero cursor?"
    highest_start: AtomicU64,
}

async fn poi_events_handler(
    Path((_chain_type, _chain_id)): Path<(String, String)>,
    axum::extract::State(state): axum::extract::State<Arc<MockState>>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let start = body
        .get("startIndex")
        .and_then(serde_json::Value::as_u64)
        .ok_or(StatusCode::BAD_REQUEST)?;
    state.highest_start.fetch_max(start, Ordering::SeqCst);
    let mut events = Vec::with_capacity(usize::try_from(MOCK_BATCH).unwrap_or(0));
    for off in 0..MOCK_BATCH {
        let idx = start + off;
        let bc = format!("0x{:064x}", idx + 1);
        events.push(serde_json::json!({
            "signedPOIEvent": {
                "index": idx,
                "blindedCommitment": bc,
                "signature": "0xdead",
                "type": "Shield",
            },
            "validatedMerkleroot": "0x00",
        }));
    }
    Ok(Json(serde_json::Value::Array(events)))
}

async fn pois_per_bc_handler(
    Path((_chain_type, _chain_id)): Path<(String, String)>,
    Json(_body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({}))
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

fn build_mirror(endpoint: String) -> Arc<UpstreamPpoiMirror> {
    let cfg = MirrorConfig {
        endpoint,
        poll_interval_secs: 1,
        max_rows_per_fetch: MOCK_BATCH,
        ..MirrorConfig::default()
    };
    Arc::new(UpstreamPpoiMirror::new(cfg).expect("mirror builds"))
}

/// Spawn a worker with a sidecar-cursor wired and let it process at
/// least `min_events` upstream rows before returning. Returns the
/// last cursor value observed in the sidecar.
async fn run_until_n_events(
    mirror: Arc<UpstreamPpoiMirror>,
    list: ListKey,
    cursor: MirrorCursor,
    min_events: usize,
) -> u64 {
    let (tx, mut rx) =
        tokio::sync::mpsc::channel::<(WalEntryPayload, u64)>(min_events.saturating_mul(4) + 8);
    let sidecar = cursor.sidecar_path();
    let worker = tokio::spawn({
        let mirror = mirror.clone();
        async move {
            let _ = mirror
                .run_worker_with_cursor(list, 0, Some(cursor), tx)
                .await;
        }
    });
    let mut leaf_added = 0usize;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    while leaf_added < min_events {
        assert!(
            tokio::time::Instant::now() < deadline,
            "worker did not produce {min_events} PpoiListLeafAdded events within 30s"
        );
        let recv = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await;
        if let Ok(Some((payload, _height))) = recv {
            if matches!(payload, WalEntryPayload::PpoiListLeafAdded { .. }) {
                leaf_added += 1;
            }
        }
    }
    worker.abort();
    let _ = worker.await;
    let bytes = std::fs::read(&sidecar).expect("sidecar must exist after successful batches");
    assert_eq!(bytes.len(), MIRROR_CURSOR_SIDECAR_BYTES);
    let mut arr = [0u8; MIRROR_CURSOR_SIDECAR_BYTES];
    arr.copy_from_slice(&bytes);
    u64::from_le_bytes(arr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mirror_cursor_persists_across_restart_for_status_kind() {
    let (url, mock, server) = start_mock().await;
    let mirror = build_mirror(url);
    let list = ListKey([0x55; 32]);
    let scratch = tempfile::tempdir().expect("tempdir");
    let data_dir = scratch.path().to_path_buf();

    let cursor1 = MirrorCursor::new(data_dir.clone(), MirrorKind::Status, 0);
    let after_first = run_until_n_events(Arc::clone(&mirror), list, cursor1, 8).await;
    assert!(
        after_first >= 8,
        "first run advanced cursor past at least 8 events, got {after_first}"
    );

    // Second worker spawn: fallback set to nonsense (99_999); the
    // sidecar must win. Also resets the mock's highest_start to
    // confirm the second worker did NOT request startIndex=0.
    mock.highest_start.store(0, Ordering::SeqCst);
    let cursor2 = MirrorCursor::new(data_dir.clone(), MirrorKind::Status, 99_999);
    let after_second = run_until_n_events(Arc::clone(&mirror), list, cursor2, 4).await;
    assert!(
        after_second > after_first,
        "second run advanced past first ({after_first} -> {after_second})"
    );
    let observed_start = mock.highest_start.load(Ordering::SeqCst);
    assert!(
        observed_start >= after_first,
        "second-run worker must have requested startIndex >= {after_first}; saw {observed_start}"
    );
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mirror_cursor_persists_across_restart_for_path_kind() {
    let (url, _mock, server) = start_mock().await;
    let mirror = build_mirror(url);
    let list = ListKey([0x77; 32]);
    let scratch = tempfile::tempdir().expect("tempdir");
    let data_dir = scratch.path().to_path_buf();
    let cursor1 = MirrorCursor::new(data_dir.clone(), MirrorKind::Path, 0);
    let after_first = run_until_n_events(Arc::clone(&mirror), list, cursor1, 8).await;
    assert!(after_first >= 8);

    let path_sidecar = data_dir.join(MirrorKind::Path.sidecar_filename());
    let status_sidecar = data_dir.join(MirrorKind::Status.sidecar_filename());
    assert!(path_sidecar.exists(), "path sidecar must be written");
    assert!(
        !status_sidecar.exists(),
        "status sidecar must not exist when only path worker ran"
    );

    let cursor2 = MirrorCursor::new(data_dir.clone(), MirrorKind::Path, 0);
    let after_second = run_until_n_events(Arc::clone(&mirror), list, cursor2, 4).await;
    assert!(
        after_second > after_first,
        "path-kind worker resumed from sidecar ({after_first} -> {after_second})"
    );
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mirror_cursor_falls_back_to_logical_leaf_store_on_missing_sidecar() {
    let (url, mock, server) = start_mock().await;
    let mirror = build_mirror(url);
    let list = ListKey([0x33; 32]);
    let scratch = tempfile::tempdir().expect("tempdir");
    let data_dir = scratch.path().to_path_buf();

    // Sidecar absent; LLS-derived fallback is 64. Worker must request
    // startIndex >= 64 on first poll.
    let cursor = MirrorCursor::new(data_dir, MirrorKind::Status, 64);
    let _final = run_until_n_events(Arc::clone(&mirror), list, cursor, 4).await;
    let observed_start = mock.highest_start.load(Ordering::SeqCst);
    assert!(
        observed_start >= 64,
        "worker must have used LLS-derived fallback=64; saw startIndex={observed_start}"
    );
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mirror_cursor_falls_back_to_zero_when_both_sidecar_and_lls_empty() {
    let (url, mock, server) = start_mock().await;
    let mirror = build_mirror(url);
    let list = ListKey([0x11; 32]);
    let scratch = tempfile::tempdir().expect("tempdir");
    let data_dir = scratch.path().to_path_buf();
    let cursor = MirrorCursor::new(data_dir, MirrorKind::Status, 0);
    let _final = run_until_n_events(Arc::clone(&mirror), list, cursor, 4).await;
    let observed_start = mock.highest_start.load(Ordering::SeqCst);
    assert_eq!(
        observed_start, 0,
        "first-bootstrap worker must have requested startIndex=0; saw {observed_start}"
    );
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mirror_cursor_atomic_write_survives_kill_at_temp_step() {
    // Failure injection: write a stale sidecar (cursor=200), drop a
    // separate `.tmp` file with a TORN payload (5 bytes — short of the
    // expected 8), then spawn a worker. The torn `.tmp` is invisible
    // to the resume path: the worker reads the canonical sidecar
    // (cursor=200) and proceeds. After the next batch, the canonical
    // sidecar is replaced atomically — the `.tmp` remnant is either
    // overwritten or left on disk but never observed as cursor data.
    let (url, mock, server) = start_mock().await;
    let mirror = build_mirror(url);
    let list = ListKey([0x88; 32]);
    let scratch = tempfile::tempdir().expect("tempdir");
    let data_dir = scratch.path().to_path_buf();
    let kind = MirrorKind::Status;
    let sidecar = data_dir.join(kind.sidecar_filename());
    let mut tmp_name = sidecar.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp_name);
    std::fs::create_dir_all(&data_dir).expect("mkdir data_dir");
    std::fs::write(&sidecar, 200u64.to_le_bytes()).expect("write sidecar");
    std::fs::write(&tmp, [0xAA; 5]).expect("write torn tmp");

    let cursor = MirrorCursor::new(data_dir.clone(), kind, 7);
    let _final = run_until_n_events(Arc::clone(&mirror), list, cursor, 4).await;
    let observed_start = mock.highest_start.load(Ordering::SeqCst);
    assert!(
        observed_start >= 200,
        "torn .tmp must be ignored; worker must resume from canonical sidecar=200 (saw {observed_start})"
    );

    // After the run, the canonical sidecar is a clean 8-byte LE u64.
    let after = std::fs::read(&sidecar).expect("sidecar still readable");
    assert_eq!(
        after.len(),
        MIRROR_CURSOR_SIDECAR_BYTES,
        "canonical sidecar size must be 8 bytes after atomic writes"
    );
    server.abort();
}

/// Unit-style: write a cursor, resolve it back, then tamper with the
/// sidecar (write garbage) — `resolve_start` falls back to the
/// configured fallback.
#[test]
fn mirror_cursor_persist_then_resolve_round_trips_and_tamper_falls_back() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let data_dir = scratch.path().to_path_buf();
    let cursor = MirrorCursor::new(data_dir.clone(), MirrorKind::Status, 9_999);

    cursor.persist(42).expect("persist");
    let path = cursor.sidecar_path();
    let bytes = std::fs::read(&path).expect("read");
    assert_eq!(bytes.len(), MIRROR_CURSOR_SIDECAR_BYTES);
    let mut arr = [0u8; MIRROR_CURSOR_SIDECAR_BYTES];
    arr.copy_from_slice(&bytes);
    assert_eq!(u64::from_le_bytes(arr), 42);
    assert_eq!(cursor.resolve_start(), 42, "sidecar present and decodable");

    // Tamper: short write that's not 8 bytes.
    std::fs::write(&path, [0xFF; 5]).expect("tamper");
    assert_eq!(
        cursor.resolve_start(),
        9_999,
        "torn sidecar must fall back to the configured fallback"
    );
}
