//! The worker logs these errors and retries, so their text is what an operator has to act on.
//! Each one must keep naming the method, the endpoint and the upstream's own answer.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::routing::post;
use axum::Router;
use raven_railgun_core::ListKey;
use raven_railgun_ppoi_mirror::{MirrorConfig, MirrorSource, UpstreamPpoiMirror};

async fn serve_fixed(
    status: StatusCode,
    body: &'static str,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/",
        post(move || async move { (status, [(CONTENT_TYPE, "application/json")], body) }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (url, task)
}

async fn fetch_error_text(endpoint: &str) -> String {
    let mirror = UpstreamPpoiMirror::new(MirrorConfig {
        endpoint: endpoint.to_owned(),
        ..MirrorConfig::default()
    })
    .expect("mirror builds");
    mirror
        .fetch_status_range(&ListKey([0x42; 32]), 0, 0)
        .await
        .expect_err("upstream answer must be refused")
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_status_text_names_method_endpoint_and_status() {
    let (url, task) = serve_fixed(StatusCode::INTERNAL_SERVER_ERROR, "{}").await;
    assert_eq!(
        fetch_error_text(&url).await,
        format!(
            "upstream error: JSON-RPC ppoi_poi_events POST {url} returned 500 Internal Server Error"
        )
    );
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn envelope_mismatch_text_names_version_and_id() {
    let (url, task) = serve_fixed(StatusCode::OK, r#"{"jsonrpc":"1.0","id":7,"result":[]}"#).await;
    assert_eq!(
        fetch_error_text(&url).await,
        "decode error: JSON-RPC ppoi_poi_events response envelope mismatch: version 1.0, id 7"
    );
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rpc_error_text_carries_upstream_code_and_message() {
    let (url, task) = serve_fixed(
        StatusCode::OK,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"unknown listKey"}}"#,
    )
    .await;
    assert_eq!(
        fetch_error_text(&url).await,
        "upstream error: JSON-RPC ppoi_poi_events error -32602: unknown listKey"
    );
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn result_and_error_together_are_refused() {
    let (url, task) = serve_fixed(
        StatusCode::OK,
        r#"{"jsonrpc":"2.0","id":1,"result":[],"error":{"code":1,"message":"m"}}"#,
    )
    .await;
    assert_eq!(
        fetch_error_text(&url).await,
        "decode error: JSON-RPC ppoi_poi_events response contains both result and error"
    );
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn neither_result_nor_error_is_refused() {
    let (url, task) = serve_fixed(StatusCode::OK, r#"{"jsonrpc":"2.0","id":1}"#).await;
    assert_eq!(
        fetch_error_text(&url).await,
        "decode error: JSON-RPC ppoi_poi_events response contains neither result nor error"
    );
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_json_body_text_names_the_method() {
    let (url, task) = serve_fixed(StatusCode::OK, "<html>gateway</html>").await;
    let text = fetch_error_text(&url).await;
    assert!(
        text.starts_with("decode error: JSON-RPC ppoi_poi_events response: "),
        "{text}"
    );
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_connection_text_names_method_and_endpoint() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    drop(listener);
    let text = fetch_error_text(&url).await;
    assert!(
        text.starts_with(&format!(
            "upstream error: JSON-RPC ppoi_poi_events POST {url}: "
        )),
        "{text}"
    );
}
