//! Session-handle refusal has a wire status distinct from generic malformed requests.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, PoisonError};

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use raven_railgun_core::{AdapterError, InstanceId, Result};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance, PirScheme, StateShape};
use raven_railgun_http::{router, write_versioned, AppState, HttpConfig, WIRE_SCHEMA_VERSION};
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

const TOKEN: &str = "session-refusal-status-token-123456";
const INSTANCE: &str = "session-refusal-status";

static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug)]
struct RefusalScheme;

#[derive(Debug)]
struct RefusalState;

#[derive(Clone, Debug, Serialize, Deserialize)]
enum RefusalQuery {
    Session,
    Generic,
    Ok,
}

#[derive(Debug, Serialize, Deserialize)]
struct RefusalResponse;

impl PirScheme for RefusalScheme {
    type ServerState = RefusalState;
    type Query = RefusalQuery;
    type Response = RefusalResponse;

    fn respond(_state: &Self::ServerState, query: &Self::Query) -> Result<Self::Response> {
        match query {
            RefusalQuery::Session => Err(AdapterError::SessionHandleRejected {
                detail: "session handle 7 is not registered; re-run the session handshake"
                    .to_owned(),
            }),
            RefusalQuery::Generic => {
                Err(AdapterError::InvalidQuery("generic slot defect".to_owned()))
            }
            RefusalQuery::Ok => Ok(RefusalResponse),
        }
    }

    fn state_shape(_state: &Self::ServerState) -> StateShape {
        StateShape {
            entry_size_bytes: 1,
            rows_per_shard: 1,
        }
    }
}

fn app() -> axum::Router {
    let mut engine = Engine::<RefusalScheme>::new();
    engine
        .register_instance(Arc::new(PirInstance::new(
            InstanceId::new(INSTANCE),
            InstanceRole::Live,
            RefusalState,
        )))
        .expect("register instance");
    let mut config = HttpConfig::demo(TOKEN);
    config.rate_limit_rps = 10_000;
    config.rate_limit_burst = 10_000;
    let state = {
        let _guard = APPSTATE_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        AppState::new(engine, config).expect("app state")
    };
    router(state).expect("router")
}

fn request(route: &str, body: Vec<u8>) -> Request<Body> {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/instance/{INSTANCE}/{route}"))
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(body))
        .expect("request");
    request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        12_345,
    )));
    request
}

#[tokio::test]
async fn single_and_batch_signal_only_typed_session_refusal() {
    for (route, query, expected) in [
        ("query", RefusalQuery::Session, StatusCode::CONFLICT),
        ("query", RefusalQuery::Generic, StatusCode::BAD_REQUEST),
        ("batch", RefusalQuery::Session, StatusCode::CONFLICT),
        ("batch", RefusalQuery::Generic, StatusCode::BAD_REQUEST),
    ] {
        let body = if route == "batch" {
            write_versioned(&vec![query]).expect("batch body")
        } else {
            write_versioned(&query).expect("query body")
        };
        let response = app().oneshot(request(route, body)).await.expect("dispatch");
        assert_eq!(response.status(), expected, "route={route}");
        assert_eq!(
            response
                .headers()
                .get("x-raven-schema-version")
                .unwrap()
                .to_str()
                .unwrap(),
            WIRE_SCHEMA_VERSION.to_string(),
            "middleware stamps every response, so status is the discriminating signal"
        );
    }
}

#[tokio::test]
async fn malformed_and_off_ladder_batches_remain_generic_400() {
    let mut malformed_body = WIRE_SCHEMA_VERSION.to_be_bytes().to_vec();
    malformed_body.push(0xff);
    let malformed = app()
        .oneshot(request("batch", malformed_body))
        .await
        .expect("malformed dispatch");
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);

    let off_ladder = write_versioned(&vec![RefusalQuery::Ok; 3]).expect("off-ladder body");
    let response = app()
        .oneshot(request("batch", off_ladder))
        .await
        .expect("off-ladder dispatch");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
