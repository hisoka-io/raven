//! The parameter set picks the wire schema: an exact instance speaks 8 with the bytes it always
//! had, an instance with the approximate packing gadget speaks 9. A client or body of one set is
//! refused by the other at the first decode, with the instance's own schema in the header, and a
//! client of the new set completes a handshake and a private read.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

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
use raven_inspire::params::{InspireParams, InspireVariant, ShardConfig};
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::{ServerCrs, ServerResponse, ServerSessionHandle};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{setup_state, InspireServerState, RavenInspireScheme};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
use raven_railgun_http::{
    inspire_router, read_batch_response_versioned_as, read_versioned, read_versioned_as,
    wire_schema_for, write_versioned, write_versioned_as, AppState, HttpConfig, InstanceParams,
    WIRE_SCHEMA_VERSION, WIRE_SCHEMA_VERSION_APPROXIMATE_GADGET,
};
use tower::ServiceExt;

const READ_TOKEN: &str = "approximate-gadget-wire-token-0123456789";
const EXACT: &str = "exact-set";
const APPROXIMATE: &str = "approximate-set";
const CLIENT_ID: &str = "0123456789abcdef0123456789abcdef";
const ENTRIES: usize = 256;
const ENTRY_BYTES: usize = 32;

static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Served {
    params: InspireParams,
    crs: Arc<ServerCrs>,
    shard: ShardConfig,
    secret: RlweSecretKey,
}

struct Fixture {
    router: axum::Router,
    exact: Served,
    approximate: Served,
    db: Vec<u8>,
}

fn state(params: &InspireParams, db: &[u8]) -> (InspireServerState, RlweSecretKey) {
    setup_state(params, db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("toy state")
}

fn fixture() -> Fixture {
    let db = raven_railgun_testkit::toy_db(ENTRIES, ENTRY_BYTES);
    let (exact_state, exact_secret) = state(&InspireParams::d2048(), &db);
    let (approximate_state, approximate_secret) =
        state(&InspireParams::d2048_approximate_gadget(), &db);
    let exact = Served {
        params: exact_state.crs.params.clone(),
        crs: Arc::clone(&exact_state.crs),
        shard: exact_state.shard_config().clone(),
        secret: exact_secret,
    };
    let approximate = Served {
        params: approximate_state.crs.params.clone(),
        crs: Arc::clone(&approximate_state.crs),
        shard: approximate_state.shard_config().clone(),
        secret: approximate_secret,
    };
    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    for (id, state) in [(EXACT, exact_state), (APPROXIMATE, approximate_state)] {
        engine
            .add_instance(PirInstance::new(
                InstanceId::new(id),
                InstanceRole::Live,
                state,
            ))
            .expect("register instance");
    }
    let app_state = {
        let _g = APPSTATE_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        AppState::new(engine, HttpConfig::demo(READ_TOKEN)).expect("appstate")
    };
    Fixture {
        router: inspire_router(app_state).expect("router"),
        exact,
        approximate,
        db,
    }
}

fn request(method: Method, instance: &str, route: &str, body: Vec<u8>) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(format!("/v1/instance/{instance}/{route}"))
        .header(header::AUTHORIZATION, format!("Bearer {READ_TOKEN}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header("x-raven-client-id", CLIENT_ID)
        .body(Body::from(body))
        .expect("request");
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        12_345,
    )));
    req
}

/// Status, the advertised schema, and the body.
async fn send(router: &axum::Router, req: Request<Body>) -> (StatusCode, u16, Vec<u8>) {
    let response = router.clone().oneshot(req).await.expect("dispatch");
    let status = response.status();
    let schema = response
        .headers()
        .get("x-raven-schema-version")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .expect("every response advertises a schema");
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec();
    (status, schema, body)
}

fn keys_for(served: &Served) -> ClientPackingKeys {
    let mut sampler = GaussianSampler::with_seed(served.params.sigma, 0x6b65);
    ClientPackingKeys::generate(
        &served.secret,
        &served.params,
        served.crs.inspiring_num_columns,
        served.crs.inspiring_w_seed,
        &mut sampler,
    )
    .expect("packing keys")
}

#[tokio::test]
async fn each_set_serves_its_params_under_its_own_schema() {
    let Fixture {
        router,
        exact,
        approximate,
        ..
    } = fixture();
    assert_eq!(wire_schema_for(&exact.params), WIRE_SCHEMA_VERSION);
    assert_eq!(
        wire_schema_for(&approximate.params),
        WIRE_SCHEMA_VERSION_APPROXIMATE_GADGET
    );
    assert_eq!(
        (WIRE_SCHEMA_VERSION, WIRE_SCHEMA_VERSION_APPROXIMATE_GADGET),
        (8, 9)
    );

    // GET /params: the exact instance's body is what the schema-8 writer emits.
    let (status, schema, exact_params) =
        send(&router, request(Method::GET, EXACT, "params", Vec::new())).await;
    assert_eq!((status, schema), (StatusCode::OK, 8));
    assert_eq!(&exact_params[..2], &[0, 8]);
    let decoded: InstanceParams = read_versioned(&exact_params).expect("schema-8 reader");
    assert_eq!(decoded.wire_schema_version, 8);
    assert_eq!(&decoded.crs_bincode[..16], ServerCrs::MAGIC.as_slice());
    assert_eq!(
        write_versioned(&decoded).expect("re-encode"),
        exact_params,
        "the exact instance's params are the schema-8 writer's bytes"
    );

    let (status, schema, approximate_params) = send(
        &router,
        request(Method::GET, APPROXIMATE, "params", Vec::new()),
    )
    .await;
    assert_eq!((status, schema), (StatusCode::OK, 9));
    assert_eq!(&approximate_params[..2], &[0, 9]);
    let old_reader = read_versioned::<InstanceParams>(&approximate_params)
        .expect_err("a schema-8 client refuses the approximate set at the envelope");
    assert!(
        old_reader
            .to_string()
            .contains("server expects v8, client sent v9"),
        "{old_reader}"
    );
    let decoded: InstanceParams = read_versioned_as(&approximate_params, 9).expect("schema 9");
    assert_eq!(decoded.wire_schema_version, 9);
    assert_eq!(
        &decoded.crs_bincode[..16],
        ServerCrs::APPROXIMATE_GADGET_MAGIC.as_slice()
    );
    let wire_crs = ServerCrs::from_versioned_bytes(&decoded.crs_bincode).expect("crs");
    assert!(wire_crs.params.approximate_packing_gadget);
}

#[tokio::test]
async fn a_body_of_the_other_set_is_refused_with_the_instances_schema() {
    let Fixture {
        router,
        exact,
        approximate,
        ..
    } = fixture();
    // A schema-8 body never reaches the approximate instance's key check, and the refusal names
    // the instance's schema; the same holds the other way round.
    let exact_keys = keys_for(&exact);
    let approximate_keys = keys_for(&approximate);
    assert_eq!(
        (exact_keys.y_body.len(), approximate_keys.y_body.len()),
        (3, 2)
    );
    for (instance, body, advertised) in [
        (APPROXIMATE, write_versioned(&exact_keys).unwrap(), 9),
        (APPROXIMATE, write_versioned(&approximate_keys).unwrap(), 9),
        (EXACT, write_versioned_as(&exact_keys, 9).unwrap(), 8),
    ] {
        let (status, schema, _) =
            send(&router, request(Method::POST, instance, "session", body)).await;
        assert_eq!(
            (status, schema),
            (StatusCode::BAD_REQUEST, advertised),
            "{instance}"
        );
    }
    // Control: the right schema with the wrong key shape is refused by the key check instead.
    let (status, _, _) = send(
        &router,
        request(
            Method::POST,
            APPROXIMATE,
            "session",
            write_versioned_as(&exact_keys, 9).unwrap(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn a_client_of_the_approximate_set_completes_a_handshake_and_a_private_read() {
    let Fixture {
        router,
        approximate,
        db,
        ..
    } = fixture();
    let approximate_keys = keys_for(&approximate);
    let (status, _, _) = send(
        &router,
        request(
            Method::POST,
            APPROXIMATE,
            "session",
            write_versioned_as(&approximate_keys, 9).unwrap(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let handle = {
        let response = router
            .clone()
            .oneshot(request(
                Method::POST,
                APPROXIMATE,
                "session",
                write_versioned_as(&approximate_keys, 9).unwrap(),
            ))
            .await
            .expect("re-handshake");
        assert_eq!(response.status(), StatusCode::OK);
        response
            .headers()
            .get("x-raven-session")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .expect("handle")
    };
    let target = 41u64;
    let mut sampler = GaussianSampler::with_seed(approximate.params.sigma, 0x7172);
    let (client_state, mut query) = raven_inspire::query_seeded(
        approximate.crs.as_ref(),
        target,
        &approximate.shard,
        &approximate.secret,
        &mut sampler,
    )
    .expect("query");
    query.session_handle = Some(ServerSessionHandle(handle));
    query.inspiring_packing_keys = None;

    let (status, schema, _) = send(
        &router,
        request(
            Method::POST,
            APPROXIMATE,
            "batch",
            write_versioned(&vec![query.clone()]).unwrap(),
        ),
    )
    .await;
    assert_eq!((status, schema), (StatusCode::BAD_REQUEST, 9));

    let (status, schema, body) = send(
        &router,
        request(
            Method::POST,
            APPROXIMATE,
            "batch",
            write_versioned_as(&vec![query], 9).unwrap(),
        ),
    )
    .await;
    assert_eq!((status, schema), (StatusCode::OK, 9));
    assert_eq!(&body[..2], &[0, 9]);
    let responses: Vec<ServerResponse> = read_batch_response_versioned_as(&body, 9).expect("batch");
    let plaintext = raven_railgun_engine::inspire::extract_response(
        &approximate.crs,
        &client_state,
        responses.first().expect("one"),
        ENTRY_BYTES,
    )
    .expect("extract");
    let at = usize::try_from(target).unwrap() * ENTRY_BYTES;
    assert_eq!(plaintext, db[at..at + ENTRY_BYTES]);
}
