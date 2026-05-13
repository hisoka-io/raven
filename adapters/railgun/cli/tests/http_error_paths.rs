//! HTTP layer error-path tests: 401 wrong-bearer, 401 missing-bearer, 401 malformed-prefix,
//! 404 unknown-instance, 400 malformed body, 400 empty batch, 200 metrics, 200 status.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_railgun_cli::toy_server::{build_toy_pieces, ToyDbConfig, TOY_INSTANCE_ID};
use std::net::SocketAddr;
use tokio::sync::oneshot;

const BEARER_TOKEN: &str = "http-error-paths-test-token";

async fn spawn_toy_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let pieces =
        build_toy_pieces(BEARER_TOKEN.to_owned(), ToyDbConfig::default()).expect("toy stack");
    let router = raven_railgun_http::inspire_router(pieces.app_state).expect("router");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let (ready_tx, ready_rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let _ = ready_tx.send(());
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    ready_rx.await.expect("ready");
    (addr, handle)
}

#[tokio::test(flavor = "current_thread")]
async fn wrong_bearer_token_rejected_with_401() {
    let (addr, h) = spawn_toy_server().await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/v1/instance/{TOY_INSTANCE_ID}/query");
    let resp = client
        .post(&url)
        .bearer_auth("not-the-real-token")
        .body(Vec::<u8>::new())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
    h.abort();
    let _ = h.await;
}

#[tokio::test(flavor = "current_thread")]
async fn missing_authorization_header_rejected_with_401() {
    let (addr, h) = spawn_toy_server().await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/v1/instance/{TOY_INSTANCE_ID}/query");
    let resp = client
        .post(&url)
        .body(Vec::<u8>::new())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
    h.abort();
    let _ = h.await;
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_authorization_prefix_rejected_with_401() {
    let (addr, h) = spawn_toy_server().await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/v1/instance/{TOY_INSTANCE_ID}/query");
    let resp = client
        .post(&url)
        .header("Authorization", "Basic foo:bar")
        .body(Vec::<u8>::new())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
    h.abort();
    let _ = h.await;
}

#[tokio::test(flavor = "current_thread")]
async fn unknown_instance_returns_404() {
    let (addr, h) = spawn_toy_server().await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/v1/instance/no-such-instance/query");
    let resp = client
        .post(&url)
        .bearer_auth(BEARER_TOKEN)
        .body(b"some-bytes".to_vec())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
    h.abort();
    let _ = h.await;
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_query_body_returns_400() {
    let (addr, h) = spawn_toy_server().await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/v1/instance/{TOY_INSTANCE_ID}/query");
    let resp = client
        .post(&url)
        .bearer_auth(BEARER_TOKEN)
        .body(vec![0xff_u8; 32])
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
    h.abort();
    let _ = h.await;
}

#[tokio::test(flavor = "current_thread")]
async fn empty_batch_body_returns_400() {
    let (addr, h) = spawn_toy_server().await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/v1/instance/{TOY_INSTANCE_ID}/batch");
    let empty_batch: Vec<u8> =
        raven_railgun_http::write_versioned::<Vec<()>>(&Vec::new()).expect("ser");
    let resp = client
        .post(&url)
        .bearer_auth(BEARER_TOKEN)
        .body(empty_batch)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
    h.abort();
    let _ = h.await;
}

#[tokio::test(flavor = "current_thread")]
async fn metrics_endpoint_default_requires_bearer() {
    // `/metrics` is default-deny (`HttpConfig.metrics_public = false`).
    // Unauthenticated scrape -> 401; authenticated scrape -> 200 with
    // a non-empty Prometheus body. Operators opt in to public scrape
    // via `--metrics-public`.
    let (addr, h) = spawn_toy_server().await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/metrics");

    let resp = client.get(&url).send().await.expect("send");
    assert_eq!(
        resp.status(),
        401,
        "/metrics must return 401 without bearer when metrics_public=false"
    );

    let resp = client
        .get(&url)
        .bearer_auth(BEARER_TOKEN)
        .send()
        .await
        .expect("send authed");
    assert_eq!(
        resp.status(),
        200,
        "/metrics must return 200 with bearer regardless of metrics_public"
    );
    let body = resp.text().await.expect("body");
    assert!(
        !body.is_empty(),
        "/metrics body must be non-empty under bearer auth"
    );

    h.abort();
    let _ = h.await;
}

#[tokio::test(flavor = "current_thread")]
async fn status_endpoint_returns_instance_list() {
    let (addr, h) = spawn_toy_server().await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/v1/status");
    let resp = client
        .get(&url)
        .bearer_auth(BEARER_TOKEN)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let json: raven_railgun_http::StatusResponse = resp.json().await.expect("json");
    assert_eq!(json.instances.len(), 1);
    h.abort();
    let _ = h.await;
}
