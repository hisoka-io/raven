#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use axum::{extract::State, routing::post, Json, Router};
use raven_railgun_core::ListKey;
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_ppoi_mirror::{
    MirrorConfig, MirrorCursor, MirrorError, MirrorKind, MirrorSource, UpstreamPpoiMirror,
};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Default)]
struct CapturedRequest(parking_lot::Mutex<Option<Value>>);

async fn json_rpc(
    State(captured): State<Arc<CapturedRequest>>,
    Json(request): Json<Value>,
) -> Json<Value> {
    *captured.0.lock() = Some(request.clone());
    let params = request.get("params").expect("params");
    let start = params
        .get("startIndex")
        .and_then(Value::as_u64)
        .expect("startIndex");
    let end = params
        .get("endIndex")
        .and_then(Value::as_u64)
        .expect("endIndex");
    if end.saturating_sub(start) > 500 {
        return Json(json!({
            "jsonrpc": "2.0",
            "id": request.get("id").cloned().unwrap_or(Value::Null),
            "error": {"code": -32602, "message": "range exceeds 501 rows"}
        }));
    }
    let drop_index_250 = params
        .get("listKey")
        .and_then(Value::as_str)
        .is_some_and(|list| list.starts_with("43"));
    let events = (start..=end)
        .filter(|index| !(drop_index_250 && *index == 250))
        .map(|index| {
            json!({
                "signedPOIEvent": {
                    "index": index,
                    "blindedCommitment": format!("{index:064x}"),
                    "signature": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "type": "Shield"
                },
                "validatedMerkleroot": format!("{:064x}", index + 1)
            })
        })
        .collect::<Vec<_>>();
    Json(json!({
        "jsonrpc": "2.0",
        "id": request.get("id").cloned().unwrap_or(Value::Null),
        "result": events
    }))
}

async fn start_json_rpc() -> (String, Arc<CapturedRequest>, tokio::task::JoinHandle<()>) {
    let captured = Arc::new(CapturedRequest::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let endpoint = format!("http://{}", listener.local_addr().expect("local address"));
    let server = tokio::spawn({
        let captured = Arc::clone(&captured);
        async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/", post(json_rpc))
                    .with_state(captured),
            )
            .await
            .expect("serve");
        }
    });
    (endpoint, captured, server)
}

#[tokio::test]
async fn json_rpc_inclusive_boundary_returns_the_501st_row() {
    let (endpoint, captured, server) = start_json_rpc().await;
    let mirror = UpstreamPpoiMirror::new(MirrorConfig {
        endpoint,
        ..MirrorConfig::default()
    })
    .expect("mirror");

    let rows = mirror
        .fetch_status_range(&ListKey([0x42; 32]), 0, 500)
        .await
        .expect("inclusive JSON-RPC page");

    assert_eq!(rows.len(), 501);
    let request = captured.0.lock();
    let request = request.as_ref().expect("captured request");
    assert_eq!(request.get("jsonrpc"), Some(&json!("2.0")));
    assert_eq!(request.get("method"), Some(&json!("ppoi_poi_events")));
    let params = request.get("params").expect("params");
    assert_eq!(params.get("chainType"), Some(&json!("0")));
    assert_eq!(params.get("chainID"), Some(&json!("1")));
    assert_eq!(params.get("startIndex"), Some(&json!(0)));
    assert_eq!(params.get("endIndex"), Some(&json!(500)));
    server.abort();
}

#[tokio::test]
async fn worker_default_page_emits_index_500_without_exceeding_the_cap() {
    let (endpoint, captured, server) = start_json_rpc().await;
    let mirror = Arc::new(
        UpstreamPpoiMirror::new(MirrorConfig {
            endpoint,
            poll_interval_secs: 1,
            ..MirrorConfig::default()
        })
        .expect("mirror"),
    );
    let (tx, mut rx) = tokio::sync::mpsc::channel(1_100);
    let worker = tokio::spawn(async move { mirror.run_worker(ListKey([0x43; 32]), 0, tx).await });

    let last_index = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (payload, _) = rx.recv().await.expect("worker channel");
            if let WalEntryPayload::PpoiListLeafAdded { list_index, .. } = payload {
                if list_index == 500 {
                    break list_index;
                }
            }
        }
    })
    .await
    .expect("worker must emit the inclusive 501st row");

    assert_eq!(last_index, 500);
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let request = captured.0.lock();
    let params = request
        .as_ref()
        .and_then(|request| request.get("params"))
        .expect("captured params");
    assert_eq!(params.get("startIndex"), Some(&json!(501)));
    assert_eq!(params.get("endIndex"), Some(&json!(1001)));
    worker.abort();
    server.abort();
}

#[test]
fn production_defaults_name_the_live_endpoint_and_inclusive_page_size() {
    let config = MirrorConfig::default();
    assert_eq!(config.endpoint, "https://ppoi.fdi.network");
    assert_eq!(config.max_rows_per_fetch, 501);
}

#[tokio::test]
async fn malformed_json_rpc_envelopes_fail_closed() {
    for response in [
        json!({"id": 1, "result": []}),
        json!({"jsonrpc": "2.0", "id": 999, "result": []}),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": [{
                "signedPOIEvent": {"index": 0, "blindedCommitment": format!("{:064x}", 1)},
                "validatedMerkleroot": format!("{:064x}", 2)
            }]
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": [{
                "signedPOIEvent": {
                    "index": 1,
                    "blindedCommitment": format!("{:064x}", 1)
                },
                "validatedMerkleroot": format!("{:064x}", 2)
            }]
        }),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("local address"));
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(
                    "/",
                    post(move || {
                        let response = response.clone();
                        async move { Json(response) }
                    }),
                ),
            )
            .await
            .expect("serve");
        });
        let mirror = UpstreamPpoiMirror::new(MirrorConfig {
            endpoint,
            ..MirrorConfig::default()
        })
        .expect("mirror");

        let error = mirror
            .fetch_status_range(&ListKey([0x42; 32]), 0, 0)
            .await
            .expect_err("malformed envelope");

        assert!(matches!(error, MirrorError::Decode(_)), "{error}");
        server.abort();
    }
}

/// Upstream serves a stored tree root or omits the row. The engine applies an all-zero root
/// uncompared, so one arriving here would skip the only check on the row's bytes.
#[tokio::test]
async fn an_all_zero_validated_merkleroot_is_refused_at_decode() {
    for (root, accepted) in [(format!("{:064x}", 7), true), ("0".repeat(64), false)] {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": [{
                "signedPOIEvent": {
                    "index": 0,
                    "blindedCommitment": format!("{:064x}", 1),
                    "signature": "00".repeat(64),
                    "type": "Shield"
                },
                "validatedMerkleroot": root
            }]
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("local address"));
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(
                    "/",
                    post(move || {
                        let response = response.clone();
                        async move { Json(response) }
                    }),
                ),
            )
            .await
            .expect("serve");
        });
        let mirror = UpstreamPpoiMirror::new(MirrorConfig {
            endpoint,
            ..MirrorConfig::default()
        })
        .expect("mirror");

        let result = mirror.fetch_status_range(&ListKey([0x42; 32]), 0, 0).await;
        if accepted {
            assert_eq!(result.expect("a real root decodes").len(), 1);
        } else {
            let error = result.expect_err("an all-zero root must not decode");
            assert!(
                matches!(&error, MirrorError::Decode(detail) if detail.contains("all-zero")),
                "{error}"
            );
        }
        server.abort();
    }
}

#[tokio::test]
async fn worker_short_tail_resumes_at_the_last_consumed_index() {
    let max_index = Arc::new(AtomicU64::new(2));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let endpoint = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn({
        let max_index = Arc::clone(&max_index);
        async move {
            let app = Router::new().route(
                "/",
                post(move |Json(request): Json<Value>| {
                    let max_index = Arc::clone(&max_index);
                    async move {
                        let params = request.get("params").expect("params");
                        let start = params.get("startIndex").and_then(Value::as_u64).expect("start");
                        let end = params.get("endIndex").and_then(Value::as_u64).expect("end");
                        let max = max_index.load(Ordering::SeqCst);
                        let events = if start > max {
                            Vec::new()
                        } else {
                            (start..=end.min(max))
                                .map(|index| json!({
                                    "signedPOIEvent": {"index": index, "blindedCommitment": format!("{index:064x}"), "signature": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "type": "Shield"},
                                    "validatedMerkleroot": format!("{:064x}", index + 1)
                                }))
                                .collect()
                        };
                        Json(json!({"jsonrpc": "2.0", "id": 1, "result": events}))
                    }
                }),
            );
            axum::serve(listener, app).await.expect("serve");
        }
    });
    let mirror = Arc::new(
        UpstreamPpoiMirror::new(MirrorConfig {
            endpoint,
            poll_interval_secs: 1,
            max_rows_per_fetch: 4,
            ..MirrorConfig::default()
        })
        .expect("mirror"),
    );
    let scratch = tempfile::tempdir().expect("tempdir");
    let cursor = MirrorCursor::new(scratch.path().to_path_buf(), MirrorKind::Path, 0);
    let sidecar = cursor.sidecar_path();
    let (tx, mut rx) = tokio::sync::mpsc::channel(32);
    let worker = tokio::spawn(async move {
        mirror
            .run_worker_with_cursor(ListKey([0x44; 32]), 0, Some(cursor), tx)
            .await
    });
    while let Some((payload, _)) = rx.recv().await {
        if matches!(
            payload,
            WalEntryPayload::PpoiListLeafAdded { list_index: 2, .. }
        ) {
            break;
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        std::fs::read(&sidecar).expect("sidecar"),
        3u64.to_le_bytes()
    );
    max_index.store(3, Ordering::SeqCst);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while let Some((payload, _)) = rx.recv().await {
            if matches!(
                payload,
                WalEntryPayload::PpoiListLeafAdded { list_index: 3, .. }
            ) {
                return;
            }
        }
        panic!("worker channel closed before appended row");
    })
    .await
    .expect("worker must fetch the append after a short tail");
    worker.abort();
    server.abort();
}
