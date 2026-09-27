//! The mirror's client MUST carry a request-level timeout; without it a silent upstream (TCP
//! accepted, never written to) hangs the feed forever. The bound is injected, so the proof takes
//! a fraction of a second instead of waiting out the production ten.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_railgun_core::ListKey;
use raven_railgun_ppoi_mirror::{
    FeedStatus, MirrorConfig, MirrorError, PreflightFailure, UpstreamPpoiMirror, REQUEST_TIMEOUT,
};
use std::sync::Arc;
use std::time::Duration;

const BOUND: Duration = Duration::from_millis(150);

async fn silent_upstream() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind silent listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _hold = stream;
                std::future::pending::<()>().await;
            });
        }
    });
    format!("http://{addr}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_feed_request_to_a_silent_upstream_ends_at_the_configured_timeout() {
    let mirror = Arc::new(
        UpstreamPpoiMirror::new(MirrorConfig {
            endpoint: silent_upstream().await,
            request_timeout: BOUND,
            ..MirrorConfig::default()
        })
        .expect("mirror builds"),
    );
    let status = FeedStatus::default();
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    let worker = tokio::spawn(mirror.run_feed(
        ListKey([0u8; 32]),
        0,
        |cursor| cursor..u64::MAX,
        status.clone(),
        tx,
    ));
    // Far above the bound and far below the production timeout, so only the injected bound can
    // end the request in time.
    let failed = tokio::time::timeout(REQUEST_TIMEOUT / 2, async {
        loop {
            let progress = status.snapshot();
            if progress.consecutive_failures > 0 {
                return progress;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the request was not bounded by the configured timeout");
    worker.abort();
    assert_eq!(failed.last_failure, Some(PreflightFailure::Timeout(BOUND)));
    assert_eq!(failed.rows_delivered, 0);
}

#[test]
fn the_default_bound_is_the_production_timeout_and_zero_is_refused() {
    assert_eq!(MirrorConfig::default().request_timeout, REQUEST_TIMEOUT);
    let refused = UpstreamPpoiMirror::new(MirrorConfig {
        request_timeout: Duration::ZERO,
        ..MirrorConfig::default()
    })
    .expect_err("a zero timeout fails every request");
    assert!(
        matches!(refused, MirrorError::InvalidConfig(_)),
        "{refused}"
    );
}
