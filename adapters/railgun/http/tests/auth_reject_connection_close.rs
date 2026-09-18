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
use std::net::SocketAddr;
use std::sync::Arc;

use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, TestRunner};
use raven_railgun_core::{InstanceId, Result as RailgunResult};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance, PirScheme};
use raven_railgun_http::{router, write_versioned, AppState, HttpConfig};
use serde::{Deserialize, Serialize};

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_non_exact_authorization_value_returns_401() {
    let (addr, handle) = spawn_server().await;
    let url = format!("http://{addr}/v1/instance/{INSTANCE}/query");
    let exact = format!("Bearer {TOKEN}");
    let strategy = proptest::collection::vec(0x21u8..=0x7e, 0..128)
        .prop_map(|bytes| String::from_utf8(bytes).expect("printable ASCII"))
        .prop_filter("exclude the exact credential", {
            let exact = exact.clone();
            move |candidate| candidate != &exact
        });
    let generated = std::cell::RefCell::new(Vec::new());
    let mut runner = TestRunner::new(ProptestConfig {
        cases: 256,
        failure_persistence: None,
        ..ProptestConfig::default()
    });
    runner
        .run(&strategy, |candidate| {
            generated.borrow_mut().push(Some(candidate));
            Ok(())
        })
        .expect("authorization strategy");
    let mut generated = generated.into_inner();
    generated.extend([
        None,
        Some(format!("bearer {TOKEN}")),
        Some(format!("BEARER {TOKEN}")),
        Some(format!("Bearer  {TOKEN}")),
        Some(format!("Bearer {TOKEN}x")),
        Some(format!("xBearer {TOKEN}")),
        Some(format!("Bearer {}", TOKEN.to_ascii_uppercase())),
        Some(format!("Basic {TOKEN}")),
    ]);

    let client = reqwest::Client::new();
    for authorization in generated {
        let mut request = client.post(&url).body(query_body(9));
        if let Some(value) = &authorization {
            request = request.header(http::header::AUTHORIZATION, value);
        }
        let response = request
            .send()
            .await
            .expect("rejection must complete over HTTP");
        assert_eq!(
            response.status().as_u16(),
            401,
            "authorization={authorization:?}"
        );
    }

    let accepted = client
        .post(&url)
        .header(http::header::AUTHORIZATION, exact)
        .body(query_body(10))
        .send()
        .await
        .expect("exact credential request");
    assert_eq!(accepted.status().as_u16(), 200);

    handle.abort();
    let _ = handle.await;
}

/// `oneshot` never touches hyper's encoder, so a router-level check could pass
/// while the header is dropped on the wire; both halves (401 closes, 200 stays
/// keep-alive) are asserted against the live encoder here.
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

    // Keep-alive half: an authorized response consumed its body and must NOT
    // carry a Connection header on the wire.
    let body = query_body(8);
    let ok_head = tokio::task::spawn_blocking(move || {
        let mut sock = std::net::TcpStream::connect(addr).expect("connect ok");
        let request = format!(
            "POST /v1/instance/{INSTANCE}/query HTTP/1.1\r\n\
             Host: {addr}\r\n\
             Authorization: Bearer {TOKEN}\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Length: {}\r\n\r\n",
            body.len()
        );
        sock.write_all(request.as_bytes()).expect("write ok head");
        sock.write_all(&body).expect("write ok body");
        sock.flush().expect("flush ok");
        // The server keeps this socket open (that is the property), so read
        // with a short timeout and take whatever arrived: the head is enough.
        sock.set_read_timeout(Some(std::time::Duration::from_millis(750)))
            .expect("set read timeout");
        let mut raw = Vec::new();
        let _ = sock.read_to_end(&mut raw);
        String::from_utf8_lossy(&raw).to_ascii_lowercase()
    })
    .await
    .expect("join authorized raw socket task");

    assert!(
        ok_head.starts_with("http/1.1 200"),
        "authorized raw request must answer 200; got {ok_head:?}"
    );
    assert!(
        !ok_head.contains("connection:"),
        "an authorized response must stay keep-alive (no Connection header \
         on the wire); got {ok_head:?}"
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
            // against the 15,491-byte production query, under the 8 MiB cap.
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
