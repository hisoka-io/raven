//! A bearer rejection abandons the unread request body, so the connection is
//! not reusable. The 401 must say so, or a pooled peer reuses the socket the
//! server is closing and its next request fails as a transport error instead of
//! a 401.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Method, Request, StatusCode},
};
use raven_railgun_core::{InstanceId, Result as RailgunResult};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance, PirScheme};
use raven_railgun_http::{router, write_versioned, AppState, HttpConfig};
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

const TOKEN: &str = "auth-reject-close-token-padded-1234";
const WRONG_TOKEN: &str = "auth-reject-close-WRONG-padded-1234";
const INSTANCE: &str = "auth-reject-close-instance";

static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug)]
struct EchoScheme;

#[derive(Debug, Default)]
struct EchoState;

#[derive(Serialize, Deserialize, Debug)]
struct EchoQuery {
    nonce: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct EchoResponse {
    echo_nonce: u64,
}

impl PirScheme for EchoScheme {
    type ServerState = EchoState;
    type Query = EchoQuery;
    type Response = EchoResponse;
    fn respond(_state: &Self::ServerState, query: &Self::Query) -> RailgunResult<Self::Response> {
        Ok(EchoResponse {
            echo_nonce: query.nonce,
        })
    }
    fn state_shape(_state: &Self::ServerState) -> raven_railgun_engine::StateShape {
        raven_railgun_engine::StateShape {
            entry_size_bytes: 1,
            rows_per_shard: u64::MAX,
        }
    }
}

fn build_router() -> axum::Router {
    let mut engine: Engine<EchoScheme> = Engine::new();
    engine
        .register_instance(Arc::new(PirInstance::new(
            InstanceId::new(INSTANCE),
            InstanceRole::Static,
            EchoState,
        )))
        .expect("register instance");
    let mut cfg = HttpConfig::demo(TOKEN);
    cfg.rate_limit_rps = 10_000;
    cfg.rate_limit_burst = 10_000;
    let state = {
        let _g = APPSTATE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        AppState::new(engine, cfg).expect("appstate")
    };
    router::<EchoScheme>(state).expect("router")
}

async fn spawn_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let r = build_router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            r.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    tokio::task::yield_now().await;
    (addr, handle)
}

fn query_body(nonce: u64) -> Vec<u8> {
    write_versioned(&EchoQuery { nonce }).expect("encode versioned query")
}

fn query_request(token: &str, nonce: u64) -> Request<Body> {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/instance/{INSTANCE}/query"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(query_body(nonce)))
        .expect("build query req");
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        12_345,
    )));
    req
}

#[tokio::test]
async fn rejected_bearer_marks_the_connection_unreusable() {
    let router = build_router();

    let rejected = router
        .clone()
        .oneshot(query_request(WRONG_TOKEN, 1))
        .await
        .expect("dispatch wrong token");
    assert_eq!(
        rejected.status(),
        StatusCode::UNAUTHORIZED,
        "a wrong bearer must be refused"
    );
    let connection = rejected
        .headers()
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(
        connection.contains("close"),
        "the reject path abandons the unread body, so the 401 MUST carry \
         `Connection: close`; got {connection:?}"
    );

    let accepted = router
        .oneshot(query_request(TOKEN, 2))
        .await
        .expect("dispatch right token");
    assert_eq!(
        accepted.status(),
        StatusCode::OK,
        "a valid bearer must still be served"
    );
    assert!(
        accepted.headers().get(header::CONNECTION).is_none(),
        "an authorized response consumed its body and must stay keep-alive"
    );
}

/// `oneshot` never touches hyper's encoder, so the header could be dropped on
/// the wire without the router test noticing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_401_carries_connection_close_on_the_wire() {
    let (addr, h) = spawn_server().await;
    let body = query_body(7);

    let head = tokio::task::spawn_blocking(move || {
        let mut sock = std::net::TcpStream::connect(addr).expect("connect");
        let request = format!(
            "POST /v1/instance/{INSTANCE}/query HTTP/1.1\r\n\
             Host: {addr}\r\n\
             Authorization: Bearer {WRONG_TOKEN}\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Length: {}\r\n\r\n",
            body.len()
        );
        sock.write_all(request.as_bytes()).expect("write head");
        sock.write_all(&body).expect("write body");
        sock.flush().expect("flush");
        // A server that keeps the socket open would block `read_to_end` forever,
        // which is itself the failure this test is about.
        sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("set read timeout");
        let mut raw = Vec::new();
        let _ = sock.read_to_end(&mut raw);
        String::from_utf8_lossy(&raw).to_ascii_lowercase()
    })
    .await
    .expect("join raw socket task");

    assert!(
        head.starts_with("http/1.1 401"),
        "raw request with a wrong bearer must answer 401; got {head:?}"
    );
    assert!(
        head.contains("connection: close"),
        "hyper must emit `Connection: close` on the reject path so a pooled \
         peer evicts the socket instead of reusing it; got {head:?}"
    );

    h.abort();
    let _ = h.await;
}

/// The wallet-facing consequence: a pooled client whose token rotated mid-session
/// must see a 401, not a `BrokenPipe` from reusing the socket the server closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pooled_client_sees_401_then_serves_the_next_request() {
    let (addr, h) = spawn_server().await;
    let url = format!("http://{addr}/v1/instance/{INSTANCE}/query");
    let client = reqwest::Client::new();

    for attempt in 0..8u64 {
        let rejected = client
            .post(&url)
            .bearer_auth(WRONG_TOKEN)
            // Must exceed the socket buffer, or the body is fully written before the
            // server can reject and the race this test names never opens. Auth runs
            // as a layer above the handler, so the bytes are never decoded. 256 KiB
            // against a reported production query of ~148 KB, under the 8 MiB cap.
            .body(vec![0u8; 256 * 1024])
            .send()
            .await
            .unwrap_or_else(|e| panic!("attempt {attempt}: wrong-token send failed: {e}"));
        assert_eq!(
            rejected.status().as_u16(),
            401,
            "attempt {attempt}: wrong bearer must be refused"
        );

        let accepted = client
            .post(&url)
            .bearer_auth(TOKEN)
            .body(query_body(attempt))
            .send()
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "attempt {attempt}: the request after a 401 must reach the \
                     server, not fail in transport: {e}"
                )
            });
        assert_eq!(
            accepted.status().as_u16(),
            200,
            "attempt {attempt}: valid bearer must be served after a 401"
        );
    }

    h.abort();
    let _ = h.await;
}
