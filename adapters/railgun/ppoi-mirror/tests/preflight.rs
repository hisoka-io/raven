//! A configured endpoint that cannot feed the worker must be refused by one bounded request,
//! with a class an operator can act on. The worker alone would warn and retry forever.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use axum::body::Bytes;
use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::routing::post;
use axum::Router;
use raven_railgun_core::ListKey;
use raven_railgun_ppoi_mirror::{
    MirrorConfig, PreflightError, PreflightFailure, UpstreamPpoiMirror,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LIST: ListKey = ListKey([0x42; 32]);
const BOUND: Duration = Duration::from_millis(250);
/// Below the client's own 10 s timeout, so a preflight that ignores its bound overruns it.
const HANG_GUARD: Duration = Duration::from_secs(5);

const ONE_ROW: &str = r#"{"jsonrpc":"2.0","id":1,"result":[{"signedPOIEvent":{"index":0,"blindedCommitment":"0x1111111111111111111111111111111111111111111111111111111111111111","signature":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","type":"Shield"},"validatedMerkleroot":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}"#;

type Requests = Arc<parking_lot::Mutex<Vec<serde_json::Value>>>;

async fn serve_fixed(status: StatusCode, body: &'static str) -> (String, Requests) {
    let requests = Requests::default();
    let seen = Arc::clone(&requests);
    let app = Router::new().route(
        "/",
        post(move |raw: Bytes| {
            let seen = Arc::clone(&seen);
            async move {
                seen.lock()
                    .push(serde_json::from_slice(&raw).expect("request is JSON"));
                (status, [(CONTENT_TYPE, "application/json")], body)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (url, requests)
}

/// Accepts, reads the request, writes `preamble`, then holds the socket open in silence.
/// Answering before the request arrives is a protocol error, which is a different failure.
async fn serve_silence_after(preamble: &'static [u8]) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = [0u8; 2048];
                let _ = stream.read(&mut request).await;
                let _ = stream.write_all(preamble).await;
                std::future::pending::<()>().await;
            });
        }
    });
    url
}

async fn preflight(endpoint: &str, bound: Duration) -> Result<(), PreflightError> {
    let mirror = UpstreamPpoiMirror::new(MirrorConfig {
        endpoint: endpoint.to_owned(),
        ..MirrorConfig::default()
    })
    .expect("mirror builds");
    tokio::time::timeout(HANG_GUARD, mirror.preflight(&LIST, bound))
        .await
        .expect("preflight overran its bound and hit the hang guard")
}

async fn refusal(endpoint: &str) -> PreflightError {
    let error = preflight(endpoint, BOUND)
        .await
        .expect_err("endpoint must be refused");
    assert_eq!(error.endpoint, endpoint);
    assert!(
        error.to_string().contains(endpoint),
        "refusal must name the endpoint: {error}"
    );
    error
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answering_endpoint_passes_with_exactly_one_index_zero_request() {
    let (url, requests) = serve_fixed(StatusCode::OK, ONE_ROW).await;
    preflight(&url, Duration::from_secs(5))
        .await
        .expect("an answering endpoint passes");

    let requests = requests.lock();
    assert_eq!(
        requests.len(),
        1,
        "preflight must cost upstream one request"
    );
    let request = requests.first().expect("one request");
    let field = |pointer: &str| request.pointer(pointer).cloned();
    assert_eq!(field("/method"), Some("ppoi_poi_events".into()));
    assert_eq!(field("/params/startIndex"), Some(0.into()));
    assert_eq!(field("/params/endIndex"), Some(0.into()));
    assert_eq!(
        field("/params/listKey"),
        Some("4242424242424242424242424242424242424242424242424242424242424242".into())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_list_is_an_answer() {
    let (url, _) = serve_fixed(StatusCode::OK, r#"{"jsonrpc":"2.0","id":1,"result":[]}"#).await;
    preflight(&url, Duration::from_secs(5))
        .await
        .expect("an upstream with no rows yet still answers");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn endpoint_that_accepts_and_never_answers_is_refused_inside_the_bound() {
    let url = serve_silence_after(b"").await;
    assert_eq!(
        refusal(&url).await.failure,
        PreflightFailure::Timeout(BOUND)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn endpoint_that_stalls_mid_body_is_a_timeout_not_a_malformed_reply() {
    let url = serve_silence_after(
        b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 4096\r\n\r\n{",
    )
    .await;
    assert_eq!(
        refusal(&url).await.failure,
        PreflightFailure::Timeout(BOUND)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_connection_is_classed_connect() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    drop(listener);
    assert_eq!(refusal(&url).await.failure, PreflightFailure::Connect);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unresolvable_host_is_classed_dns() {
    // RFC 6761 reserves `.invalid` to never resolve.
    let error = preflight("http://raven-preflight.invalid", Duration::from_secs(4))
        .await
        .expect_err("a reserved-invalid host must be refused");
    assert_eq!(error.failure, PreflightFailure::Dns, "{error}");
    assert_eq!(error.endpoint, "http://raven-preflight.invalid");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_success_status_is_classed_by_its_code() {
    let (url, _) = serve_fixed(StatusCode::BAD_GATEWAY, "{}").await;
    assert_eq!(
        refusal(&url).await.failure,
        PreflightFailure::HttpStatus(502)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn success_status_with_a_foreign_body_is_a_malformed_envelope() {
    for body in [
        "<html>gateway</html>",
        r#"{"status":"ok"}"#,
        r#"{"jsonrpc":"1.0","id":1,"result":[]}"#,
        r#"{"jsonrpc":"2.0","id":2,"result":[]}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":[],"error":{"code":1,"message":"m"}}"#,
    ] {
        let (url, _) = serve_fixed(StatusCode::OK, body).await;
        assert_eq!(
            refusal(&url).await.failure,
            PreflightFailure::MalformedEnvelope,
            "{body}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn json_rpc_error_is_classed_by_its_code() {
    let (url, _) = serve_fixed(
        StatusCode::OK,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"unknown listKey"}}"#,
    )
    .await;
    let error = refusal(&url).await;
    assert_eq!(error.failure, PreflightFailure::Rpc(-32602));
    assert_eq!(error.detail, "unknown listKey");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rows_the_worker_would_refuse_fail_the_preflight() {
    let (url, _) = serve_fixed(
        StatusCode::OK,
        r#"{"jsonrpc":"2.0","id":1,"result":[{"signedPOIEvent":{"index":0,"blindedCommitment":"0x1111111111111111111111111111111111111111111111111111111111111111","signature":"not-hex","type":"Shield"},"validatedMerkleroot":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}"#,
    )
    .await;
    assert_eq!(
        refusal(&url).await.failure,
        PreflightFailure::UndecodableRows
    );
}
