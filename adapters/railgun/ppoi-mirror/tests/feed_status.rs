//! What a feed records of upstream, and the rows it steps over.
//!
//! An operator surface reads [`FeedStatus`] to tell a feed at upstream's tip from one upstream is
//! refusing, so every request has to land there. A feed told that a run of rows is already held
//! everywhere it can be held must not ask for those rows again.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use raven_railgun_core::ListKey;
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_ppoi_mirror::{
    FeedProgress, FeedStatus, MirrorConfig, MirrorError, PreflightFailure, UpstreamPpoiMirror,
};
use serde_json::{json, Value};
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

const LIST: ListKey = ListKey([0x52; 32]);

struct Upstream {
    /// Rows `0..rows` exist.
    rows: u64,
    /// 1-based ordinals of the requests answered HTTP 500.
    failing: Vec<usize>,
    asked: parking_lot::Mutex<Vec<(u64, u64)>>,
}

async fn serve(rows: u64, failing: &[usize]) -> (String, Arc<Upstream>) {
    let upstream = Arc::new(Upstream {
        rows,
        failing: failing.to_vec(),
        asked: parking_lot::Mutex::new(Vec::new()),
    });
    let state = Arc::clone(&upstream);
    let app = Router::new().route(
        "/",
        post(move |Json(request): Json<Value>| {
            let upstream = Arc::clone(&state);
            async move {
                let param = |name: &str| {
                    request
                        .pointer(&format!("/params/{name}"))
                        .and_then(Value::as_u64)
                        .expect("page bound")
                };
                let (start, end) = (param("startIndex"), param("endIndex"));
                let ordinal = {
                    let mut asked = upstream.asked.lock();
                    asked.push((start, end));
                    asked.len()
                };
                if upstream.failing.contains(&ordinal) {
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
                let rows: Vec<Value> = (start..=end.min(upstream.rows.saturating_sub(1)))
                    .map(|index| {
                        json!({
                            "signedPOIEvent": {
                                "index": index,
                                "blindedCommitment": format!("{:064x}", index + 1),
                                "signature": "00".repeat(64),
                                "type": "Shield"
                            },
                            "validatedMerkleroot": format!("{:064x}", index + 1)
                        })
                    })
                    .collect();
                Ok(Json(json!({ "jsonrpc": "2.0", "id": 1, "result": rows })))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let endpoint = format!("http://{}", listener.local_addr().expect("local addr"));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (endpoint, upstream)
}

fn mirror(endpoint: &str, max_rows_per_fetch: u64) -> Arc<UpstreamPpoiMirror> {
    Arc::new(
        UpstreamPpoiMirror::new(MirrorConfig {
            endpoint: endpoint.to_owned(),
            poll_interval_secs: 1,
            max_rows_per_fetch,
            ..MirrorConfig::default()
        })
        .expect("mirror")
        .with_backfill_interval(Duration::ZERO),
    )
}

fn leaves(rx: &mut mpsc::Receiver<(WalEntryPayload, u64)>) -> Vec<u32> {
    let mut seen = Vec::new();
    while let Ok((payload, _)) = rx.try_recv() {
        if let WalEntryPayload::PpoiListLeafAdded { list_index, .. } = payload {
            seen.push(list_index);
        }
    }
    seen
}

async fn until(status: &FeedStatus, done: impl Fn(&FeedProgress) -> bool) -> FeedProgress {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let progress = status.snapshot();
        if done(&progress) {
            return progress;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "never reached: {progress:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Two runs of rows some consumer lacks, `20..25` and `30..35`, and nothing past `35` held.
fn two_runs(cursor: u64) -> Range<u64> {
    match cursor {
        0..=24 => cursor.max(20)..25,
        25..=34 => cursor.max(30)..35,
        _ => 35..35,
    }
}

#[tokio::test]
async fn a_feed_asks_only_for_the_runs_its_span_names_and_stops_after_the_last() {
    let (endpoint, upstream) = serve(1_000, &[]).await;
    let (tx, mut rx) = mpsc::channel(256);
    let status = FeedStatus::default();
    let stopped = tokio::time::timeout(
        Duration::from_secs(10),
        mirror(&endpoint, 3).run_feed(LIST, 0, two_runs, status.clone(), tx),
    )
    .await
    .expect("the feed must stop after the last run");
    assert!(
        matches!(stopped, Err(MirrorError::Unheld { list_index: 35 })),
        "{stopped:?}"
    );
    assert_eq!(
        upstream.asked.lock().clone(),
        [(20, 22), (23, 24), (30, 32), (33, 34)],
        "nothing outside the two runs is asked for"
    );
    assert_eq!(
        leaves(&mut rx),
        (20..25).chain(30..35).collect::<Vec<u32>>()
    );
    let progress = status.snapshot();
    assert_eq!((progress.next_index, progress.rows_delivered), (35, 10));
    assert!(
        progress
            .stopped
            .as_deref()
            .is_some_and(|reason| reason.contains("35")),
        "{progress:?}"
    );
}

/// Failures are counted and classed until an answer clears them; a full page leaves upstream's
/// size unknown and a short one states it.
#[tokio::test]
async fn the_status_counts_failures_until_an_answer_and_knows_the_tip_only_from_a_short_page() {
    let (endpoint, upstream) = serve(15, &[1, 2]).await;
    let (tx, mut rx) = mpsc::channel(256);
    let status = FeedStatus::default();
    let worker = tokio::spawn(mirror(&endpoint, 10).run_feed(
        LIST,
        0,
        |cursor| cursor..u64::MAX,
        status.clone(),
        tx,
    ));

    let refused = until(&status, |progress| progress.consecutive_failures == 2).await;
    assert_eq!(
        (
            refused.last_failure,
            refused.last_answer,
            refused.upstream_rows
        ),
        (Some(PreflightFailure::HttpStatus(500)), None, None)
    );
    let caught_up = until(&status, |progress| progress.upstream_rows.is_some()).await;
    assert_eq!(
        (
            caught_up.consecutive_failures,
            caught_up.last_failure,
            caught_up.upstream_rows,
            caught_up.next_index,
            caught_up.rows_delivered
        ),
        (0, None, Some(15), 15, 15),
        "the short second page states upstream's size"
    );
    assert!(caught_up.last_answer.is_some() && caught_up.stopped.is_none());
    assert_eq!(
        upstream.asked.lock()[..4],
        [(0, 9), (0, 9), (0, 9), (10, 19)],
        "a failed page is asked for again, not skipped"
    );
    assert_eq!(leaves(&mut rx), (0..15).collect::<Vec<u32>>());
    worker.abort();
}
