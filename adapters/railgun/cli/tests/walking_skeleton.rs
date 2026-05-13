//! Walking-skeleton E2E: full HTTP stack against a 256 × 256 B InsPIRe instance.
//! Verifies PIR round-trip byte-equality, status, and auth header semantics.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_railgun_cli::toy_server::{build_toy_pieces, ToyDbConfig, SCHEME_NAME, TOY_INSTANCE_ID};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{build_seeded_query, extract_response, InspireServerState};
use std::sync::Arc;
use tokio::sync::oneshot;

const BEARER_TOKEN: &str = "walking-skeleton-test-token";

#[tokio::test(flavor = "current_thread")]
#[allow(clippy::too_many_lines)]
async fn pir_query_round_trip_recovers_planted_row() {
    let pieces = build_toy_pieces(BEARER_TOKEN.to_owned(), ToyDbConfig::default())
        .expect("toy stack should build");

    let server_state_arc: Arc<InspireServerState> = pieces
        .app_state
        .engine
        .instance(&InstanceId::new(TOY_INSTANCE_ID))
        .expect("toy instance present")
        .current_state();

    let router = raven_railgun_http::inspire_router(pieces.app_state.clone()).expect("router");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let (ready_tx, ready_rx) = oneshot::channel::<()>();
    let server_handle = tokio::spawn(async move {
        let _ = ready_tx.send(());
        // `into_make_service_with_connect_info` is required for the rate-limiter peer-IP extractor.
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    ready_rx.await.expect("server ready signal");

    let target_index: u64 = 42;
    let (client_state, query) = build_seeded_query(
        &pieces.client_session,
        server_state_arc.shard_config(),
        target_index,
        &pieces.params,
    )
    .expect("build seeded PIR query");
    let query_bytes = raven_railgun_http::write_versioned(&query)
        .expect("serialize SeededClientQuery (versioned)");

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/v1/instance/{TOY_INSTANCE_ID}/query");
    let response = client
        .post(&url)
        .bearer_auth(BEARER_TOKEN)
        .body(query_bytes)
        .send()
        .await
        .expect("POST query");
    assert_eq!(response.status(), 200, "HTTP status");

    let server_epoch = response
        .headers()
        .get("x-raven-epoch")
        .expect("X-Raven-Epoch header present")
        .to_str()
        .expect("header is utf-8")
        .to_owned();
    assert_eq!(server_epoch, "0");

    let scheme_header = response
        .headers()
        .get("x-raven-scheme")
        .expect("X-Raven-Scheme header present")
        .to_str()
        .expect("header is utf-8")
        .to_owned();
    assert_eq!(scheme_header, SCHEME_NAME);

    let body = response.bytes().await.expect("body bytes");
    let server_response: raven_inspire::ServerResponse =
        raven_railgun_http::read_versioned(&body).expect("deserialize ServerResponse (versioned)");

    let plaintext = extract_response(
        &server_state_arc.crs,
        &client_state,
        &server_response,
        pieces.config.entry_bytes,
    )
    .expect("extract response");

    let target_idx_usize = usize::try_from(target_index).expect("target_index fits in usize");
    let expected_start = target_idx_usize * pieces.config.entry_bytes;
    let expected_end = expected_start + pieces.config.entry_bytes;
    let expected = pieces
        .db
        .get(expected_start..expected_end)
        .expect("planted slice in range");
    let recovered = plaintext
        .get(..pieces.config.entry_bytes)
        .expect("plaintext at least entry_bytes");
    assert_eq!(
        recovered, expected,
        "decoded plaintext must match planted byte"
    );

    let status_url = format!("http://{addr}/v1/status");
    let status_resp = client
        .get(&status_url)
        .bearer_auth(BEARER_TOKEN)
        .send()
        .await
        .expect("GET status");
    assert_eq!(status_resp.status(), 200);
    let status_json: raven_railgun_http::StatusResponse =
        status_resp.json().await.expect("status json");
    assert_eq!(status_json.scheme, SCHEME_NAME);
    assert_eq!(status_json.instances.len(), 1);
    let only = status_json
        .instances
        .first()
        .expect("status_json instances non-empty");
    assert_eq!(only.id, TOY_INSTANCE_ID);
    assert_eq!(only.epoch, 0);

    // 10. Auth: missing bearer token must be rejected.
    let no_auth_resp = client
        .post(&url)
        .body(Vec::<u8>::new())
        .send()
        .await
        .expect("POST without auth");
    assert_eq!(no_auth_resp.status(), 401);

    // 11. Cleanup.
    server_handle.abort();
    let _ = server_handle.await;
}
