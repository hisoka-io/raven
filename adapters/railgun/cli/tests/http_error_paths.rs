//! HTTP layer error paths: auth, unknown instance, malformed body, empty batch.
//!
//! Every case here asserts a status the router decides before it consults a session, so the
//! fixture registers none: `build_client_session` measured 4.2 s on top of `setup_state`'s
//! 8.1 s at the toy cell, and nothing below reads it.
//!
//! nextest gives each test its own process, so a fixture shared through a `static` saves
//! nothing across tests - only grouping cases into one test function does. The two groups
//! below pay one `setup_state` each; every case still issues its own request, and the table
//! records all mismatches rather than stopping at the first, so grouping costs no detail.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_cli::toy_server::{
    build_toy_database, SCHEME_NAME, TOY_DB_ENTRIES, TOY_ENTRY_BYTES, TOY_INSTANCE_ID,
};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{setup_state, RavenInspireScheme};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
use raven_railgun_http::{AppState, HttpConfig};
use std::net::SocketAddr;
use tokio::sync::oneshot;

const BEARER_TOKEN: &str = "http-error-paths-test-token";

fn build_state() -> AppState<RavenInspireScheme> {
    let params = InspireParams::secure_128_d2048();
    let db = build_toy_database(TOY_DB_ENTRIES, TOY_ENTRY_BYTES);
    let (server_state, _sk) =
        setup_state(&params, &db, TOY_ENTRY_BYTES, InspireVariant::TwoPacking)
            .expect("setup_state");

    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    engine
        .add_instance(PirInstance::new(
            InstanceId::new(TOY_INSTANCE_ID),
            InstanceRole::Static,
            server_state,
        ))
        .expect("add instance");

    let mut config = HttpConfig::demo(BEARER_TOKEN.to_owned());
    SCHEME_NAME.clone_into(&mut config.scheme_name);
    AppState::new(engine, config).expect("app state")
}

async fn spawn_toy_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let router = raven_railgun_http::inspire_router(build_state()).expect("router");
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

/// One rejected request: how it is addressed and authorized, and the status it must draw.
struct ErrorCase {
    name: &'static str,
    path: String,
    /// `None` sends no `Authorization` header at all.
    authorization: Option<&'static str>,
    body: Vec<u8>,
    expect: u16,
}

#[tokio::test(flavor = "current_thread")]
async fn error_paths_return_their_status_codes() {
    let query_path = format!("/v1/instance/{TOY_INSTANCE_ID}/query");
    let batch_path = format!("/v1/instance/{TOY_INSTANCE_ID}/batch");
    let empty_batch: Vec<u8> =
        raven_railgun_http::write_versioned::<Vec<()>>(&Vec::new()).expect("ser");

    let cases = vec![
        ErrorCase {
            name: "wrong bearer token",
            path: query_path.clone(),
            authorization: Some("Bearer not-the-real-token"),
            body: Vec::new(),
            expect: 401,
        },
        ErrorCase {
            name: "no authorization header",
            path: query_path.clone(),
            authorization: None,
            body: Vec::new(),
            expect: 401,
        },
        // The token is the configured one; only the scheme word is wrong, so a gate that
        // searched the header for the token instead of parsing `Bearer ` would serve this.
        ErrorCase {
            name: "non-bearer authorization scheme",
            path: query_path.clone(),
            authorization: Some("Basic http-error-paths-test-token"),
            body: Vec::new(),
            expect: 401,
        },
        ErrorCase {
            name: "unknown instance",
            path: "/v1/instance/no-such-instance/query".to_owned(),
            authorization: Some("Bearer http-error-paths-test-token"),
            body: b"some-bytes".to_vec(),
            expect: 404,
        },
        ErrorCase {
            name: "malformed query body",
            path: query_path,
            authorization: Some("Bearer http-error-paths-test-token"),
            body: vec![0xff_u8; 32],
            expect: 400,
        },
        ErrorCase {
            name: "empty batch body",
            path: batch_path,
            authorization: Some("Bearer http-error-paths-test-token"),
            body: empty_batch,
            expect: 400,
        },
    ];

    let (addr, h) = spawn_toy_server().await;
    let client = reqwest::Client::new();

    // Collected, not asserted per case: one wrong status must not hide the other five.
    let mut mismatches: Vec<String> = Vec::new();
    for case in cases {
        let mut req = client
            .post(format!("http://{addr}{}", case.path))
            .body(case.body.clone());
        if let Some(value) = case.authorization {
            req = req.header("Authorization", value);
        }
        match req.send().await {
            Ok(resp) => {
                let got = resp.status().as_u16();
                if got != case.expect {
                    mismatches.push(format!(
                        "{}: expected {}, got {got}",
                        case.name, case.expect
                    ));
                }
            }
            Err(e) => mismatches.push(format!("{}: transport error {e}", case.name)),
        }
    }

    h.abort();
    let _ = h.await;

    assert!(
        mismatches.is_empty(),
        "error-path status mismatches: {}",
        mismatches.join("; ")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn metrics_is_bearer_gated_and_status_lists_the_instance() {
    let (addr, h) = spawn_toy_server().await;
    let client = reqwest::Client::new();

    // `/metrics` is default-deny; `--metrics-public` opts into unauthed scrape
    let metrics_url = format!("http://{addr}/metrics");
    let resp = client.get(&metrics_url).send().await.expect("send");
    assert_eq!(
        resp.status(),
        401,
        "/metrics must return 401 without bearer when metrics_public=false"
    );

    let resp = client
        .get(&metrics_url)
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

    let resp = client
        .get(format!("http://{addr}/v1/status"))
        .bearer_auth(BEARER_TOKEN)
        .send()
        .await
        .expect("send status");
    assert_eq!(resp.status(), 200);
    let json: raven_railgun_http::StatusResponse = resp.json().await.expect("json");
    assert_eq!(json.instances.len(), 1);

    h.abort();
    let _ = h.await;
}
