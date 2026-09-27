//! Page bounds and envelope checks on the feed's `ppoi_poi_events` exchange: upstream's range is
//! inclusive and capped at 501 rows, and a reply the feed cannot trust is refused whole.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use axum::{extract::State, routing::post, Json, Router};
use raven_railgun_core::ListKey;
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_ppoi_mirror::{FeedStatus, MirrorConfig, PreflightFailure, UpstreamPpoiMirror};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Default)]
struct CapturedRequests(parking_lot::Mutex<Vec<Value>>);

impl CapturedRequests {
    fn params(&self, ordinal: usize) -> Option<Value> {
        self.0
            .lock()
            .get(ordinal)
            .map(|request| request["params"].clone())
    }
}

fn row(index: u64) -> Value {
    json!({
        "signedPOIEvent": {
            "index": index,
            "blindedCommitment": format!("{index:064x}"),
            "signature": "00".repeat(64),
            "type": "Shield"
        },
        "validatedMerkleroot": format!("{:064x}", index + 1)
    })
}

/// Refuses a range over 501 rows, as upstream does. A list key starting `43` leaves out row 250.
async fn json_rpc(
    State(captured): State<Arc<CapturedRequests>>,
    Json(request): Json<Value>,
) -> Json<Value> {
    captured.0.lock().push(request.clone());
    let params = &request["params"];
    let start = params["startIndex"].as_u64().expect("startIndex");
    let end = params["endIndex"].as_u64().expect("endIndex");
    if end.saturating_sub(start) > 500 {
        return Json(json!({
            "jsonrpc": "2.0",
            "id": request["id"],
            "error": {"code": -32602, "message": "range exceeds 501 rows"}
        }));
    }
    let drop_index_250 = params["listKey"]
        .as_str()
        .is_some_and(|list| list.starts_with("43"));
    let events: Vec<Value> = (start..=end)
        .filter(|index| !(drop_index_250 && *index == 250))
        .map(row)
        .collect();
    Json(json!({ "jsonrpc": "2.0", "id": request["id"], "result": events }))
}

async fn start_json_rpc() -> (String, Arc<CapturedRequests>) {
    let captured = Arc::new(CapturedRequests::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let endpoint = format!("http://{}", listener.local_addr().expect("local address"));
    let app = Router::new()
        .route("/", post(json_rpc))
        .with_state(Arc::clone(&captured));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (endpoint, captured)
}

fn feed_mirror(endpoint: String) -> Arc<UpstreamPpoiMirror> {
    Arc::new(
        UpstreamPpoiMirror::new(MirrorConfig {
            endpoint,
            poll_interval_secs: 1,
            ..MirrorConfig::default()
        })
        .expect("mirror"),
    )
}

async fn requests_made(captured: &CapturedRequests, count: usize) {
    tokio::time::timeout(Duration::from_secs(30), async {
        while captured.0.lock().len() < count {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the feed kept asking");
}

/// The default page is the inclusive range `0..=500`, which delivers the 501st row, and the next
/// page starts right after it without exceeding the cap.
#[tokio::test]
async fn the_default_page_takes_501_rows_and_the_next_starts_after_them() {
    let (endpoint, captured) = start_json_rpc().await;
    let (tx, mut rx) = tokio::sync::mpsc::channel(1_100);
    let worker = tokio::spawn(feed_mirror(endpoint).run_feed(
        ListKey([0x45; 32]),
        0,
        |cursor| cursor..u64::MAX,
        FeedStatus::default(),
        tx,
    ));

    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let (payload, _) = rx.recv().await.expect("feed channel");
            if matches!(
                payload,
                WalEntryPayload::PpoiListLeafAdded {
                    list_index: 500,
                    ..
                }
            ) {
                break;
            }
        }
    })
    .await
    .expect("the feed must deliver the inclusive 501st row");
    requests_made(&captured, 2).await;
    worker.abort();

    let request = captured.0.lock()[0].clone();
    assert_eq!(request["jsonrpc"], "2.0");
    assert_eq!(request["method"], "ppoi_poi_events");
    let first = &request["params"];
    assert_eq!(
        (
            &first["chainType"],
            &first["chainID"],
            &first["startIndex"],
            &first["endIndex"]
        ),
        (&json!("0"), &json!("1"), &json!(0), &json!(500))
    );
    let second = captured.params(1).expect("second page");
    assert_eq!(
        (&second["startIndex"], &second["endIndex"]),
        (&json!(501), &json!(1001))
    );
}

/// A default page missing row 250 is taken through 249 only, and the next page starts at 250,
/// still within the 501-row cap.
#[tokio::test]
async fn a_default_page_missing_a_row_is_asked_again_from_that_row() {
    let (endpoint, captured) = start_json_rpc().await;
    let (tx, mut rx) = tokio::sync::mpsc::channel(1_100);
    let worker = tokio::spawn(feed_mirror(endpoint).run_feed(
        ListKey([0x43; 32]),
        0,
        |cursor| cursor..u64::MAX,
        FeedStatus::default(),
        tx,
    ));

    requests_made(&captured, 2).await;
    worker.abort();
    let mut emitted = Vec::new();
    while let Ok((payload, _)) = rx.try_recv() {
        if let WalEntryPayload::PpoiListLeafAdded { list_index, .. } = payload {
            emitted.push(list_index);
        }
    }
    assert_eq!(
        emitted,
        (0..250).collect::<Vec<u32>>(),
        "only the rows below the missing one are sent"
    );
    let second = captured.params(1).expect("second page");
    assert_eq!(
        (&second["startIndex"], &second["endIndex"]),
        (&json!(250), &json!(750))
    );
}

#[test]
fn production_defaults_name_the_live_endpoint_and_inclusive_page_size() {
    let config = MirrorConfig::default();
    assert_eq!(config.endpoint, "https://ppoi.fdi.network");
    assert_eq!(config.max_rows_per_fetch, 501);
}

async fn serve_one(response: Value) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let endpoint = format!("http://{}", listener.local_addr().expect("local address"));
    let app = Router::new().route(
        "/",
        post(move || {
            let response = response.clone();
            async move { Json(response) }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    endpoint
}

async fn preflight(endpoint: String) -> Result<(), PreflightFailure> {
    UpstreamPpoiMirror::new(MirrorConfig {
        endpoint,
        ..MirrorConfig::default()
    })
    .expect("mirror")
    .preflight(&ListKey([0x42; 32]), Duration::from_secs(5))
    .await
    .map_err(|error| error.failure)
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
    ] {
        assert_eq!(
            preflight(serve_one(response.clone()).await).await,
            Err(PreflightFailure::MalformedEnvelope),
            "{response}"
        );
    }
}

/// Upstream serves a stored tree root or omits the row. The engine applies an all-zero root
/// uncompared, so one arriving here would skip the only check on the row's bytes.
#[tokio::test]
async fn an_all_zero_validated_merkleroot_is_refused_at_decode() {
    for (root, accepted) in [(format!("{:064x}", 7), true), ("0".repeat(64), false)] {
        let mut page = row(0);
        page["validatedMerkleroot"] = json!(root);
        let outcome =
            preflight(serve_one(json!({"jsonrpc": "2.0", "id": 1, "result": [page]})).await).await;
        if accepted {
            assert_eq!(outcome, Ok(()), "a real root decodes");
        } else {
            assert_eq!(outcome, Err(PreflightFailure::UndecodableRows));
        }
    }
}

async fn leaf_arrives(rx: &mut tokio::sync::mpsc::Receiver<(WalEntryPayload, u64)>, want: u32) {
    tokio::time::timeout(Duration::from_secs(30), async {
        while let Some((payload, _)) = rx.recv().await {
            if matches!(payload, WalEntryPayload::PpoiListLeafAdded { list_index, .. } if list_index == want) {
                return;
            }
        }
        panic!("feed channel closed before row {want}");
    })
    .await
    .unwrap_or_else(|_| panic!("row {want} never arrived"));
}

/// A page shorter than asked for is upstream's tip. The rows it held are taken, and the next page
/// starts right after the last of them, so a row appended later is picked up.
#[tokio::test]
async fn a_short_tail_resumes_at_the_row_after_the_last_taken() {
    let max_index = Arc::new(AtomicU64::new(2));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let endpoint = format!("http://{}", listener.local_addr().expect("address"));
    let app = Router::new().route(
        "/",
        post({
            let max_index = Arc::clone(&max_index);
            move |Json(request): Json<Value>| {
                let max_index = Arc::clone(&max_index);
                async move {
                    let start = request["params"]["startIndex"].as_u64().expect("start");
                    let end = request["params"]["endIndex"].as_u64().expect("end");
                    let events: Vec<Value> = (start..=end.min(max_index.load(Ordering::SeqCst)))
                        .map(row)
                        .collect();
                    Json(json!({"jsonrpc": "2.0", "id": 1, "result": events}))
                }
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
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
    let status = FeedStatus::default();
    let (tx, mut rx) = tokio::sync::mpsc::channel(32);
    let worker = tokio::spawn(mirror.run_feed(
        ListKey([0x44; 32]),
        0,
        |cursor| cursor..u64::MAX,
        status.clone(),
        tx,
    ));
    leaf_arrives(&mut rx, 2).await;
    let tip = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let progress = status.snapshot();
            if progress.upstream_rows.is_some() {
                return progress;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the short page states the tip");
    assert_eq!((tip.next_index, tip.upstream_rows), (3, Some(3)));
    max_index.store(3, Ordering::SeqCst);
    leaf_arrives(&mut rx, 3).await;
    worker.abort();
}
