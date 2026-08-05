//! The mirror's `reqwest::Client` MUST carry a request-level timeout; without
//! it a silent upstream (TCP accepted, never written to) hangs `fetch_status_*`
//! forever. The outer 45s bracket fails if the configured 10s timeout is gone.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_railgun_core::ListKey;
use raven_railgun_ppoi_mirror::{MirrorConfig, MirrorSource, UpstreamPpoiMirror};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ppoi_mirror_builder_carries_request_timeout() {
    // Accepts connections but never writes, so the request hangs at the response
    // read until the request-level timeout fires.
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
