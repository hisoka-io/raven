//! The PPOI read path answers a caller that holds no credential; the default-deny
//! `/metrics` does not.
//!
//! Both halves run against ONE router in ONE test, because they are the same property:
//! a router that refused everything and a router that served everything each pass half
//! of this and fail the other.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, PoisonError};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use raven_inspire::inspiring::ClientPackingKeys;
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::{
    ClientState, SeededClientQuery, ServerCrs, ServerResponse, ServerSessionHandle,
};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{setup_state, RavenInspireScheme};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
use raven_railgun_http::{
    inspire_router, read_batch_response_versioned, read_versioned, write_versioned, AppState,
    HttpConfig, InstanceParams, SessionEstablishResponse,
};
use tower::ServiceExt;

const INSTANCE_ID: &str = "unauthenticated-read-instance";
const CLIENT_ID: &str = "0f0e0d0c0b0a09080706050403020100";
const READ_TOKEN: &str = "unauth-read-scrape-token-padded-123";
const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_BYTES: usize = 256;

/// `AppState::new` installs the process-global Prometheus recorder.
static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Fixture {
    router: axum::Router,
    session_body: Vec<u8>,
    query: SeededClientQuery,
    client_state: ClientState,
    crs: Arc<ServerCrs>,
    expected: Vec<u8>,
}

fn fixture() -> Fixture {
    let params = InspireParams::secure_128_d2048();
    let db = raven_railgun_testkit::toy_db(TOY_ENTRIES, TOY_ENTRY_BYTES);
    let (state, sk) =
        setup_state(&params, &db, TOY_ENTRY_BYTES, InspireVariant::TwoPacking).expect("toy state");

    let keys = {
        let pack_params = state.cache.pack_params();
        let mut sampler = GaussianSampler::with_seed(params.sigma, 7);
        ClientPackingKeys::generate(&sk, pack_params, state.crs.inspiring_w_seed, &mut sampler)
    };
    let session_body = write_versioned(&keys).expect("serialize ClientPackingKeys");
    let mut query_sampler = GaussianSampler::with_seed(params.sigma, 8);
    let (client_state, query) = raven_inspire::query_seeded(
        state.crs.as_ref(),
        0,
        state.shard_config(),
        &sk,
        &mut query_sampler,
    )
    .expect("query template");

    let crs = Arc::clone(&state.crs);
    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    engine
        .add_instance(PirInstance::new(
            InstanceId::new(INSTANCE_ID),
            InstanceRole::Live,
            state,
        ))
        .expect("register instance");

    let cfg = HttpConfig::demo(READ_TOKEN);
    let app_state = {
        let _g = APPSTATE_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        AppState::new(engine, cfg).expect("appstate")
    };

    Fixture {
        router: inspire_router(app_state).expect("router build"),
        session_body,
        query,
        client_state,
        crs,
        expected: db.get(..TOY_ENTRY_BYTES).expect("first record").to_vec(),
    }
}

/// A third party's request: no `Authorization` header is ever set on it.
fn anonymous(method: Method, uri: &str, body: Vec<u8>) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header("x-raven-client-id", CLIENT_ID)
        .body(Body::from(body))
        .expect("build anonymous request");
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        12_345,
    )));
    assert!(
        req.headers().get(header::AUTHORIZATION).is_none(),
        "the whole point of this fixture is that it carries no credential"
    );
    req
}

fn bearer(method: Method, uri: &str, token: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("build bearer request");
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        12_345,
    )));
    req
}

async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    resp.into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec()
}

/// `GET /v1/instance/{id}/params`, with no credential.
async fn anonymous_params(router: &axum::Router) -> InstanceParams {
    let resp = router
        .clone()
        .oneshot(anonymous(
            Method::GET,
            &format!("/v1/instance/{INSTANCE_ID}/params"),
            Vec::new(),
        ))
        .await
        .expect("params dispatch");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET params must answer with no credential"
    );
    read_versioned(&body_bytes(resp).await).expect("params envelope")
}

/// `POST /v1/instance/{id}/session`, with no credential. The handle it mints is bound to
/// `x-raven-client-id` alone.
async fn anonymous_session(router: &axum::Router, session_body: Vec<u8>) -> u64 {
    let resp = router
        .clone()
        .oneshot(anonymous(
            Method::POST,
            &format!("/v1/instance/{INSTANCE_ID}/session"),
            session_body,
        ))
        .await
        .expect("session dispatch");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "POST session must answer with no credential"
    );
    let handle = resp
        .headers()
        .get("x-raven-session")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .expect("x-raven-session handle");
    let established: SessionEstablishResponse =
        serde_json::from_slice(&body_bytes(resp).await).expect("session body");
    assert_eq!(established.handle, handle);
    handle
}

/// Decrypting is the check that matters: a route that 200s with an empty body would pass
/// a status assertion and serve nothing.
fn assert_decrypts(fixture: &Fixture, response: &ServerResponse) {
    let plaintext = raven_railgun_engine::inspire::extract_response(
        &fixture.crs,
        &fixture.client_state,
        response,
        TOY_ENTRY_BYTES,
    )
    .expect("extract");
    assert_eq!(
        plaintext, fixture.expected,
        "an uncredentialed read must return the real row, not an empty 200"
    );
}

async fn anonymous_read(router: &axum::Router, route: &str, body: Vec<u8>) -> Vec<u8> {
    let resp = router
        .clone()
        .oneshot(anonymous(
            Method::POST,
            &format!("/v1/instance/{INSTANCE_ID}/{route}"),
            body,
        ))
        .await
        .expect("read dispatch");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "POST {route} must answer with no credential"
    );
    body_bytes(resp).await
}

#[tokio::test]
async fn the_four_read_routes_answer_with_no_authorization_header_while_the_scrape_refuses_one() {
    let mut fixture = fixture();
    let router = fixture.router.clone();

    let params = anonymous_params(&router).await;
    assert_eq!(params.entry_size, TOY_ENTRY_BYTES);

    let handle = anonymous_session(&router, std::mem::take(&mut fixture.session_body)).await;
    fixture.query.session_handle = Some(ServerSessionHandle(handle));
    fixture.query.inspiring_packing_keys = None;

    let single = anonymous_read(
        &router,
        "query",
        write_versioned(&fixture.query).expect("query body"),
    )
    .await;
    assert_decrypts(
        &fixture,
        &read_versioned::<ServerResponse>(&single).expect("query response"),
    );

    let batched = anonymous_read(
        &router,
        "batch",
        write_versioned(&vec![fixture.query.clone()]).expect("batch body"),
    )
    .await;
    let decoded: Vec<ServerResponse> =
        read_batch_response_versioned(&batched).expect("batch response");
    assert_decrypts(&fixture, decoded.first().expect("one batch response"));

    // Same run, same router: the scrape is still shut, and only the header opens it.
    for (name, request) in [
        ("no header", anonymous(Method::GET, "/metrics", Vec::new())),
        (
            "a query-parameter token",
            anonymous(
                Method::GET,
                &format!("/metrics?token={READ_TOKEN}"),
                Vec::new(),
            ),
        ),
        ("the empty bearer", bearer(Method::GET, "/metrics", "")),
    ] {
        let status = router
            .clone()
            .oneshot(request)
            .await
            .expect("metrics dispatch")
            .status();
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{name} must not open /metrics"
        );
    }

    // Non-vacuity: the scrape is alive and the credential is the only thing gating it.
    let status = router
        .oneshot(bearer(Method::GET, "/metrics", READ_TOKEN))
        .await
        .expect("metrics bearer dispatch")
        .status();
    assert_eq!(
        status,
        StatusCode::OK,
        "the read token must still open /metrics; otherwise the refusals above prove nothing"
    );
}
