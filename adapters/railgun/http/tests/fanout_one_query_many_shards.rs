//! One versioned query fans out over 13 shards without multiplying upload bytes.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "HTTP integration fixture and byte-oracle diagnostics"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, InspireVariant, SecurityLevel};
use raven_inspire::{query_seeded, ClientState, SeededClientQuery, ServerCrs, ServerResponse};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{extract_response, setup_state, RavenInspireScheme};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
use raven_railgun_http::{
    inspire_router, read_batch_response_versioned, write_versioned, AppState, FanoutRequest,
    HttpConfig, WIRE_SCHEMA_VERSION,
};
use tower::ServiceExt;

const TOKEN: &str = "fanout-thirteen-shards-test-token-123456";
const INSTANCE: &str = "fanout-thirteen-shards";
const SHARDS: usize = 13;
const RING_DIM: usize = 256;
const ENTRY_BYTES: usize = 2;
const LOCAL_INDEX: usize = 37;
const REQUEST_ORDER: [u32; SHARDS] = [12, 0, 6, 1, 11, 2, 10, 3, 9, 4, 8, 5, 7];

struct Fixture {
    router: axum::Router,
    crs: Arc<ServerCrs>,
    client_state: ClientState,
    query: SeededClientQuery,
    database: Vec<u8>,
}

fn params() -> InspireParams {
    InspireParams {
        ring_dim: RING_DIM,
        q: 1_152_921_504_606_830_593,
        crt_moduli: vec![1_152_921_504_606_830_593],
        p: 65_537,
        sigma: 6.4,
        gadget_base: 1 << 20,
        gadget_len: 3,
        security_level: SecurityLevel::Bits128,
    }
}

fn database() -> Vec<u8> {
    (0..SHARDS * RING_DIM)
        .flat_map(|row| {
            (0..ENTRY_BYTES).map(move |byte| {
                u8::try_from((row * 131 + byte * 17 + 19) % 251).expect("value is below 251")
            })
        })
        .collect()
}

fn fixture() -> Fixture {
    let params = params();
    let database = database();
    let (state, secret_key) =
        setup_state(&params, &database, ENTRY_BYTES, InspireVariant::TwoPacking)
            .expect("13-shard state");
    assert_eq!(state.encoded_db.shards.len(), SHARDS, "fixture shard count");

    let mut sampler = GaussianSampler::with_seed(params.sigma, 0x13);
    let (client_state, query) = query_seeded(
        &state.crs,
        LOCAL_INDEX as u64,
        state.shard_config(),
        &secret_key,
        &mut sampler,
    )
    .expect("single seeded query");
    let crs = Arc::clone(&state.crs);

    let instance = Arc::new(PirInstance::new(
        InstanceId::new(INSTANCE),
        InstanceRole::Static,
        state,
    ));
    let engine: Engine<RavenInspireScheme> = Engine::new();
    engine.add_live(instance).expect("register instance");
    let mut config = HttpConfig::demo(TOKEN);
    config.enable_fanout = true;
    config.max_fanout_shards = SHARDS;
    config.max_concurrent_queries = 4;
    let app = AppState::new(engine, config).expect("app state");

    Fixture {
        router: inspire_router(app).expect("router"),
        crs,
        client_state,
        query,
        database,
    }
}

fn request(path: &str, body: Vec<u8>) -> Request<Body> {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(path)
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

async fn post(router: &axum::Router, path: &str, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
    let response = router
        .clone()
        .oneshot(request(path, body))
        .await
        .expect("route dispatch");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes()
        .to_vec();
    (status, body)
}

fn fanout_body(query: &SeededClientQuery, shard_ids: Vec<u32>) -> Vec<u8> {
    write_versioned(&FanoutRequest {
        query: query.clone(),
        shard_ids,
    })
    .expect("versioned fanout request")
}

fn expected_plaintext(database: &[u8], shard_id: u32) -> &[u8] {
    let global_index = shard_id as usize * RING_DIM + LOCAL_INDEX;
    let start = global_index * ENTRY_BYTES;
    &database[start..start + ENTRY_BYTES]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_uploaded_query_serves_thirteen_shards_in_request_order() {
    let fixture = fixture();
    let single_upload = write_versioned(&fixture.query).expect("single query upload");
    let fanout_upload = fanout_body(&fixture.query, REQUEST_ORDER.to_vec());
    assert_eq!(
        fanout_upload.len(),
        single_upload.len() + 8 + SHARDS * size_of::<u32>(),
        "fanout upload must add only bincode's vector length and one u32 per shard"
    );

    let fanout_path = format!("/v1/instance/{INSTANCE}/fanout");
    let (status, body) = post(&fixture.router, &fanout_path, fanout_upload).await;
    assert_eq!(status, StatusCode::OK, "13-shard fanout");
    let responses: Vec<ServerResponse> =
        read_batch_response_versioned(&body).expect("versioned fanout response");
    assert_eq!(responses.len(), SHARDS);

    let query_path = format!("/v1/instance/{INSTANCE}/query");
    for (position, shard_id) in REQUEST_ORDER.into_iter().enumerate() {
        let mut single_query = fixture.query.clone();
        single_query.shard_id = shard_id;
        let (single_status, single_body) = post(
            &fixture.router,
            &query_path,
            write_versioned(&single_query).expect("versioned single query"),
        )
        .await;
        assert_eq!(single_status, StatusCode::OK, "single shard {shard_id}");
        let fanout_slot = write_versioned(&responses[position]).expect("versioned slot response");
        assert!(
            fanout_slot == single_body,
            "fanout position {position} must byte-match shard {shard_id}'s single response"
        );
        let plaintext = extract_response(
            &fixture.crs,
            &fixture.client_state,
            &responses[position],
            ENTRY_BYTES,
        )
        .expect("extract fanout response");
        assert_eq!(
            plaintext,
            expected_plaintext(&fixture.database, shard_id),
            "fanout position {position} must serve shard {shard_id}'s independent plaintext"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fanout_wire_policy_is_versioned_bounded_and_duplicate_preserving() {
    let fixture = fixture();
    let path = format!("/v1/instance/{INSTANCE}/fanout");

    let (empty, _) = post(
        &fixture.router,
        &path,
        fanout_body(&fixture.query, Vec::new()),
    )
    .await;
    assert_eq!(empty, StatusCode::BAD_REQUEST);

    let (out_of_range, _) = post(
        &fixture.router,
        &path,
        fanout_body(
            &fixture.query,
            vec![u32::try_from(SHARDS).expect("13 fits u32")],
        ),
    )
    .await;
    assert_eq!(out_of_range, StatusCode::BAD_REQUEST);

    let (over_cap, _) = post(
        &fixture.router,
        &path,
        fanout_body(&fixture.query, vec![0; SHARDS + 1]),
    )
    .await;
    assert_eq!(over_cap, StatusCode::BAD_REQUEST);

    let (short, _) = post(&fixture.router, &path, vec![0]).await;
    assert_eq!(short, StatusCode::BAD_REQUEST);
    let mut future = fanout_body(&fixture.query, vec![0]);
    future[..2].copy_from_slice(&WIRE_SCHEMA_VERSION.saturating_add(1).to_be_bytes());
    let (future_status, _) = post(&fixture.router, &path, future).await;
    assert_eq!(future_status, StatusCode::BAD_REQUEST);

    let duplicate_ids = vec![4, 4, 1];
    let (duplicates, body) = post(
        &fixture.router,
        &path,
        fanout_body(&fixture.query, duplicate_ids.clone()),
    )
    .await;
    assert_eq!(duplicates, StatusCode::OK, "duplicates are served verbatim");
    let responses: Vec<ServerResponse> =
        read_batch_response_versioned(&body).expect("duplicate responses");
    assert_eq!(responses.len(), duplicate_ids.len());
    assert_eq!(
        bincode::serialize(&responses[0]).expect("slot 0"),
        bincode::serialize(&responses[1]).expect("slot 1"),
        "duplicate shard ids must retain duplicate ordered responses"
    );
}
