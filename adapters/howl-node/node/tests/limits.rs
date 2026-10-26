//! The node's bounds through the routes: request and session rates, seats, body sizes, body
//! places and times, and the operator's status route. Each refusal is set against the same calls under bounds that admit
//! them, so a test that cannot fail does not pass.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

#[path = "../../../howl/indexer/tests/support/mod.rs"]
mod chain;
mod support;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body as HttpBody;
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::Router;
use chain::Fixture;
use howl_node::engine::Engine;
use howl_node::http::{router, Served};
use howl_node::limit::{Limits, Rate};
use howl_node::NodeConfig;
use http_body_util::BodyExt;
use raven_inspire_session::SessionStoreLimits;
use support::{request, FakeChain, Http, Reader};
use tower::ServiceExt;

const TOKEN: &str = "an-operator-token-of-32-bytes-ok";

struct Node {
    engine: Arc<Engine>,
    _dir: tempfile::TempDir,
}

async fn node(max_sessions: usize) -> Node {
    let fixture = Fixture::load();
    let dir = tempfile::tempdir().expect("tempdir");
    let config = NodeConfig {
        data_dir: dir.path().to_path_buf(),
        chain_id: fixture.chain_id,
        pool: fixture.pool,
        deployment_block: fixture.first_block,
        max_range: 1_000,
        sessions: SessionStoreLimits {
            max_sessions,
            ttl: Duration::from_secs(3_600),
        },
        param_set: howl_wire::PARAM_SET_D2048_CELL256,
        seed: Some([7; 32]),
    };
    let chain = FakeChain::new(
        fixture.pool,
        fixture.first_block,
        fixture.logs.clone(),
        fixture.head,
    );
    let (mut follower, engine) = howl_node::open(&config, chain).expect("open");
    for _ in 0..1_000 {
        let step = follower.step().await.expect("step");
        howl_node::publish(&follower, &engine, &step).expect("publish");
        if matches!(step, howl_node::follow::Step::Idle { .. }) {
            return Node { engine, _dir: dir };
        }
    }
    panic!("never caught up");
}

fn app(node: &Node, limits: Limits) -> Router {
    router(Served::with_limits(Arc::clone(&node.engine), limits))
}

async fn call(app: &Router, request: Request<HttpBody>) -> (StatusCode, HeaderMap, String) {
    let response = app.clone().oneshot(request).await.expect("infallible");
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

async fn get(app: &Router, path: &str) -> (StatusCode, HeaderMap, String) {
    call(
        app,
        Request::get(path).body(HttpBody::empty()).expect("request"),
    )
    .await
}

async fn status_with(app: &Router, authorization: Option<&str>) -> (StatusCode, String) {
    let mut request = Request::get("/howl/v1/status");
    if let Some(value) = authorization {
        request = request.header(header::AUTHORIZATION, value);
    }
    let (status, _, body) = call(app, request.body(HttpBody::empty()).expect("request")).await;
    (status, body)
}

fn with_requests(per_sec: u32, burst: u32) -> Limits {
    Limits {
        requests: Rate { per_sec, burst },
        ..Limits::new(2)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn requests_past_the_burst_are_answered_429_with_a_retry_and_health_stays_up() {
    let node = node(8).await;
    let limited = app(&node, with_requests(1, 3));
    for _ in 0..3 {
        assert_eq!(get(&limited, "/howl/v1/params").await.0, StatusCode::OK);
    }
    let (status, headers, _) = get(&limited, "/howl/v1/params").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = headers[header::RETRY_AFTER]
        .to_str()
        .expect("ascii")
        .parse()
        .expect("whole seconds");
    assert!((1..=2).contains(&retry), "retry after {retry}");
    assert_eq!(headers[header::CONNECTION], "close");
    // The platform's health check and the operator are never limited.
    for _ in 0..10 {
        assert_eq!(get(&limited, "/howl/v1/health").await.0, StatusCode::OK);
    }
    // One second refills one request.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert_eq!(get(&limited, "/howl/v1/params").await.0, StatusCode::OK);
    assert_eq!(
        get(&limited, "/howl/v1/params").await.0,
        StatusCode::TOO_MANY_REQUESTS
    );

    // Control: the same calls under the default bounds are all served.
    let open = app(&node, Limits::new(2));
    for _ in 0..5 {
        assert_eq!(get(&open, "/howl/v1/params").await.0, StatusCode::OK);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_past_their_rate_are_refused_and_the_refusals_are_counted() {
    let node = node(8).await;
    let limits = |burst| Limits {
        sessions: Rate { per_sec: 1, burst },
        operator_token: Some(TOKEN.to_owned()),
        ..Limits::new(2)
    };
    let limited = app(&node, limits(1));
    let http = Http(limited.clone());
    let mut first = Reader::new(&http, 1).await;
    first.register(&http).await;
    let second = Reader::new(&http, 2).await;
    let (status, headers, _) = call(
        &limited,
        Request::post("/howl/v1/session")
            .body(HttpBody::from(second.key_upload()))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(headers.contains_key(header::RETRY_AFTER));
    let (status, body) = status_with(&limited, Some(&format!("Bearer {TOKEN}"))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("sessions=1 "), "{body}");
    assert!(body.contains("refused_session_rate=1 "), "{body}");
    assert!(body.contains("refused_rate=0 "), "{body}");

    // Control: a burst of two seats both.
    let open = Http(app(&node, limits(2)));
    for seed in 3..5 {
        Reader::new(&open, seed).await.register(&open).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn full_seats_refuse_a_session_but_never_a_private_read() {
    let node = node(1).await;
    let http = Http(app(&node, Limits::new(2)));
    let mut seated = Reader::new(&http, 1).await;
    seated.register(&http).await;
    let mut unseated = Reader::new(&http, 2).await;
    let (status, body) = http.post("/howl/v1/session", unseated.key_upload()).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        String::from_utf8_lossy(&body)
    );
    // The key goes with the batch instead, and the read is answered.
    let leaves = node.engine.view().leaf_count;
    let (_, inline) = unseated.fetch(&http, &[0, 1], leaves).await;
    let (_, by_session) = seated.fetch(&http, &[0, 1], leaves).await;
    assert_eq!(inline, by_session);
}

#[tokio::test(flavor = "multi_thread")]
async fn bodies_past_a_routes_cap_are_refused_before_they_are_decoded() {
    let node = node(8).await;
    let http = Http(app(&node, Limits::new(2)));
    let key = node.engine.pir().key_upload_limit();
    let at_cap = request(&vec![0u8; key]);
    let (status, _) = http.post("/howl/v1/session", at_cap).await;
    // Control: a body at the cap is read, and refused only as a key that does not decode.
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let past_cap = request(&vec![0u8; key + 1]);
    let (status, _) = http.post("/howl/v1/session", past_cap).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_status_route_opens_only_to_the_operator_token() {
    let node = node(8).await;
    let closed = app(&node, Limits::new(2));
    for header in [None, Some("Bearer "), Some(&*format!("Bearer {TOKEN}"))] {
        assert_eq!(
            status_with(&closed, header).await.0,
            StatusCode::UNAUTHORIZED,
            "no token configured: {header:?}"
        );
    }
    let open = app(
        &node,
        Limits {
            operator_token: Some(TOKEN.to_owned()),
            ..Limits::new(2)
        },
    );
    let wrong_last = format!("Bearer {}x", &TOKEN[..TOKEN.len() - 1]);
    let short = format!("Bearer {}", &TOKEN[..TOKEN.len() - 1]);
    let long = format!("Bearer {TOKEN}x");
    let scheme = format!("Basic {TOKEN}");
    for header in [
        None,
        Some("Bearer "),
        Some(&*wrong_last),
        Some(&*short),
        Some(&*long),
        Some(&*scheme),
        Some(TOKEN),
    ] {
        let (status, body) = status_with(&open, header).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{header:?}");
        assert!(!body.contains("sessions"), "{header:?}: {body}");
    }
    let (status, body) = status_with(&open, Some(&format!("Bearer {TOKEN}"))).await;
    assert_eq!(status, StatusCode::OK);
    for field in ["sessions=0 ", "seats=8 ", "queued=0 ", "refused_wait=0"] {
        assert!(body.contains(field), "{field}: {body}");
    }
    // The public health answer says nothing about load.
    let (status, _, health) = get(&open, "/howl/v1/health").await;
    assert_eq!(status, StatusCode::OK);
    assert!(health.starts_with("ok leaves="), "{health}");
    assert!(!health.contains("sessions"), "{health}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_flood_of_one_route_refuses_only_that_route() {
    let node = node(8).await;
    let limited = app(&node, with_requests(1, 3));
    let http = Http(limited.clone());
    let mut reader = Reader::new(&http, 1).await;
    reader.register(&http).await;
    while get(&limited, "/howl/v1/params").await.0 == StatusCode::OK {}
    assert_eq!(
        get(&limited, "/howl/v1/params").await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Every other route still has its own burst.
    let leaves = node.engine.view().leaf_count;
    // A private read is still answered (fetch asserts 200).
    reader.fetch(&http, &[0, 1], leaves).await;
    for path in [
        "/howl/v1/sync?since=0&upper=0",
        "/howl/v1/prefixes?since=0",
        "/howl/v1/upper?since=0",
        "/howl/v1/block/0",
    ] {
        assert_eq!(get(&limited, path).await.0, StatusCode::OK, "{path}");
    }
    // Each of those buckets is spent in turn, and its refusal stays its own.
    while get(&limited, "/howl/v1/block/0").await.0 == StatusCode::OK {}
    assert_eq!(
        get(&limited, "/howl/v1/sync?since=0&upper=0").await.0,
        StatusCode::OK
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cross_origin_caller_may_read_retry_after() {
    let node = node(8).await;
    let limited = app(&node, with_requests(1, 1));
    let from_origin = || {
        Request::get("/howl/v1/params")
            .header(header::ORIGIN, "https://wallet.example")
            .body(HttpBody::empty())
            .expect("request")
    };
    assert_eq!(call(&limited, from_origin()).await.0, StatusCode::OK);
    let (status, headers, _) = call(&limited, from_origin()).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(headers.contains_key(header::RETRY_AFTER));
    assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    let exposed = headers[header::ACCESS_CONTROL_EXPOSE_HEADERS]
        .to_str()
        .expect("ascii")
        .to_ascii_lowercase();
    assert!(exposed.contains("retry-after"), "{exposed}");
}

/// The router on a real socket, so a body can stall part-way.
async fn serve(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, router).await.expect("serve") });
    addr
}

/// A batch post that declares `declared` bytes and sends `sent` of them, then waits.
fn stalled_post(addr: SocketAddr, declared: usize, sent: usize) -> TcpStream {
    let mut stream = TcpStream::connect(addr).expect("connect");
    write!(
        stream,
        "POST /howl/v1/notes HTTP/1.1\r\nHost: node\r\nContent-Length: {declared}\r\n\r\n"
    )
    .expect("head");
    stream.write_all(&vec![0u8; sent]).expect("body");
    stream
}

/// The status line and headers of the answer on `stream`, or `None` if none comes in `within`.
fn answer_head(stream: &mut TcpStream, within: Duration) -> Option<String> {
    stream.set_read_timeout(Some(within)).expect("timeout");
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    (!head.is_empty()).then(|| String::from_utf8_lossy(&head).to_ascii_lowercase())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_that_stalls_is_cut_off_and_holds_its_place_only_until_then() {
    let node = node(8).await;
    let limits = Limits {
        bodies: 1,
        body_timeout: Duration::from_millis(600),
        operator_token: Some(TOKEN.to_owned()),
        ..Limits::new(2)
    };
    let router = app(&node, limits);
    let addr = serve(router.clone()).await;
    let start = Instant::now();
    let mut stalled = stalled_post(addr, 4_096, 100);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The one place is held by the stalled body: the next one is refused at once, to retry.
    let mut second = stalled_post(addr, 4_096, 4_096);
    let refused =
        tokio::task::spawn_blocking(move || answer_head(&mut second, Duration::from_secs(5)))
            .await
            .expect("joins")
            .expect("an answer");
    assert!(refused.starts_with("http/1.1 503"), "{refused}");
    assert!(refused.contains("retry-after: 1"), "{refused}");
    assert!(refused.contains("connection: close"), "{refused}");

    let cut =
        tokio::task::spawn_blocking(move || answer_head(&mut stalled, Duration::from_secs(5)))
            .await
            .expect("joins")
            .expect("an answer");
    let took = start.elapsed();
    assert!(cut.starts_with("http/1.1 408"), "{cut}");
    assert!(took < Duration::from_secs(3), "cut after {took:?}");

    // The place is back: a whole body is read and answered on its merits.
    let mut whole = stalled_post(addr, 64, 64);
    let answered =
        tokio::task::spawn_blocking(move || answer_head(&mut whole, Duration::from_secs(5)))
            .await
            .expect("joins")
            .expect("an answer");
    assert!(answered.starts_with("http/1.1 400"), "{answered}");
    let (_, body) = status_with(&router, Some(&format!("Bearer {TOKEN}"))).await;
    assert!(body.contains("refused_bodies=1 "), "{body}");
    assert!(body.contains("refused_body_timeout=1 "), "{body}");
}
