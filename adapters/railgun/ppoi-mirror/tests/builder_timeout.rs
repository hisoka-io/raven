//! Regression-guard: the `UpstreamPpoiMirror` constructor MUST build a
//! `reqwest::Client` with an explicit request-level timeout. Without
//! it, a silent upstream (TCP accepted, never written to) hangs the
//! mirror's `fetch_status_*` calls indefinitely.
//!
//! The configured timeout (per `lib.rs`) is `Duration::from_secs(10)`.
//! This test brackets the call with 45s; the configured 10s timeout
//! must fire well within the bracket. If the builder's `.timeout(..)`
//! call is ever removed, the request never returns and this test
//! hits the outer 45s timeout and fails, surfacing the regression.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_railgun_core::ListKey;
use raven_railgun_ppoi_mirror::{MirrorConfig, MirrorSource, UpstreamPpoiMirror};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ppoi_mirror_builder_carries_request_timeout() {
    // Bind a TCP listener that accepts connections but never writes
    // back. The mirror's HTTP request will hang at the response read
    // until the request-level timeout fires.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind silent listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                // Hold the stream forever; never write a byte.
                let _hold = stream;
                std::future::pending::<()>().await;
            });
        }
    });

    let cfg = MirrorConfig {
        endpoint: format!("http://{addr}"),
        ..MirrorConfig::default()
    };
    let mirror = UpstreamPpoiMirror::new(cfg).expect("mirror builds");
    let list = ListKey([0u8; 32]);

    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(45),
        mirror.fetch_status_range(&list, 0, 1),
    )
    .await
    .expect("must error inside 45s when 10s timeout is wired");
    let elapsed = started.elapsed();

    let err = outcome.expect_err("silent server must produce an Upstream error");
    let s = err.to_string();
    assert!(
        s.contains("upstream") || s.contains("timeout") || s.contains("operation timed out"),
        "expected an upstream/timeout error, got: {s}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(45),
        "elapsed {elapsed:?} > 45s suggests the 10s request timeout did not fire"
    );
}
