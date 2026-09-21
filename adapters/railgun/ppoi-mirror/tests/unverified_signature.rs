//! The mirror accepts a row whatever its signature bytes are. That is a weakness, and it is pinned
//! here so the published trust statement cannot drift away from it: whoever adds a verifier turns
//! this red, and has to rewrite the statement in the same change.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use axum::http::header::CONTENT_TYPE;
use axum::routing::post;
use axum::Router;
use raven_railgun_core::{ListKey, POIStatus};
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_ppoi_mirror::{
    poi_status_to_byte, MirrorConfig, MirrorSource, UpstreamPpoiMirror, TRUST_STATEMENT,
};
use std::sync::Arc;
use std::time::Duration;

/// S = 0xF0.. exceeds the ed25519 group order, so no verifier accepts this under any key.
const FORGED_SIGNATURE: [u8; 64] = [0xF0; 64];

const STALE_STATEMENT: &str = "the mirror refused a row over its signature. If a verifier now \
    exists, TRUST_STATEMENT and the crate's `# Trust` section are stale: rewrite them, and the \
    operator config comments that repeat them, then replace this test with one pinning the verifier";

async fn serve_one_forged_row() -> String {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":[{{"signedPOIEvent":{{"index":0,"blindedCommitment":"0x{bc}","signature":"{signature}","type":"Shield"}},"validatedMerkleroot":"{root}"}}]}}"#,
        bc = "11".repeat(32),
        signature = "f0".repeat(64),
        root = "aa".repeat(32),
    );
    let app = Router::new().route(
        "/",
        post(move || {
            let body = body.clone();
            async move { ([(CONTENT_TYPE, "application/json")], body) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    url
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_signature_is_accepted_and_the_trust_statement_says_so() {
    let mirror = Arc::new(
        UpstreamPpoiMirror::new(MirrorConfig {
            endpoint: serve_one_forged_row().await,
            poll_interval_secs: 1,
            max_rows_per_fetch: 1,
            ..MirrorConfig::default()
        })
        .expect("mirror builds"),
    );
    let list = ListKey([0x55; 32]);

    let rows = mirror
        .fetch_status_range(&list, 0, 0)
        .await
        .unwrap_or_else(|error| panic!("{STALE_STATEMENT} ({error})"));
    let statuses: Vec<POIStatus> = rows.iter().map(|row| row.status).collect();
    assert_eq!(statuses, [POIStatus::Valid]);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<(WalEntryPayload, u64)>(4);
    let worker = tokio::spawn({
        let mirror = Arc::clone(&mirror);
        async move {
            let _ = mirror.run_worker(list, 0, tx).await;
        }
    });
    // A verifying worker would warn and retry, never emitting: silence here is the refusal.
    let emitted = tokio::time::timeout(Duration::from_secs(20), rx.recv())
        .await
        .unwrap_or_else(|_| panic!("{STALE_STATEMENT} (worker emitted nothing)"));
    worker.abort();
    match emitted {
        Some((
            WalEntryPayload::PpoiListLeafAdded {
                signature, status, ..
            },
            _,
        )) => {
            assert_eq!(
                signature, FORGED_SIGNATURE,
                "signature bytes pass through verbatim"
            );
            assert_eq!(status, poi_status_to_byte(POIStatus::Valid));
        }
        other => panic!("expected the forged row as PpoiListLeafAdded, got {other:?}"),
    }

    // The other direction: the code still verifies nothing, so the statement may not claim it does.
    assert!(
        TRUST_STATEMENT.contains("TLS") && TRUST_STATEMENT.contains("not verified"),
        "the mirror verifies no signature, and its trust statement must keep saying so: \
         {TRUST_STATEMENT}"
    );
}
