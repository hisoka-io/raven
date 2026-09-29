//! A fanout reaches every declared shard of a cell that holds no rows yet, although such a cell
//! encodes one shard that serves for all of them.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "HTTP integration fixture"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::ServerResponse;
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{
    build_client_session, build_seeded_query, extract_response, setup_unfilled_state,
    RavenInspireScheme,
};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
use raven_railgun_http::{
    inspire_router, read_batch_response_versioned, write_versioned, AppState, FanoutRequest,
    HttpConfig,
};
use tower::ServiceExt;

const TOKEN: &str = "fanout-unfilled-cell-test-token-0123456";
const INSTANCE: &str = "fanout-unfilled-cell";
const ENTRY: usize = 32;
const ROWS_PER_SHARD: usize = 2048;
const SHARDS: u32 = 32;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fanout_reaches_every_declared_shard_of_an_unfilled_cell() {
    let params = InspireParams::secure_128_d2048();
    let state = setup_unfilled_state(
        &params,
        &vec![0x11; ROWS_PER_SHARD * ENTRY],
        u64::from(SHARDS) * ROWS_PER_SHARD as u64,
        ENTRY,
        InspireVariant::TwoPacking,
        None,
    )
    .expect("unfilled cell");
    assert_eq!(state.encoded_db.shards.len(), 1, "one shard serves for all");

    let mut sampler = GaussianSampler::new(params.sigma);
    let secret = RlweSecretKey::generate(&params, &mut sampler);
    let session = build_client_session((*state.crs).clone(), secret, &params).expect("session");
    let (client_state, query) =
        build_seeded_query(&session, state.shard_config(), 9, &params).expect("query");
    let crs = Arc::clone(&state.crs);

    let engine: Engine<RavenInspireScheme> = Engine::new();
    engine
        .add_live(Arc::new(PirInstance::new(
            InstanceId::new(INSTANCE),
            InstanceRole::Static,
            state,
        )))
        .expect("register instance");
    let mut config = HttpConfig::demo(TOKEN);
    config.enable_fanout = true;
    config.max_fanout_shards = SHARDS as usize;
    let router = inspire_router(AppState::new(engine, config).expect("app state")).expect("router");

    let shard_ids = vec![SHARDS - 1, 0, 5];
    let body = write_versioned(&FanoutRequest {
        query,
        shard_ids: shard_ids.clone(),
    })
    .expect("fanout request");
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/instance/{INSTANCE}/fanout"))
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(body))
        .expect("request");
    request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        12_345,
    )));
    let response = router.oneshot(request).await.expect("route dispatch");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let responses: Vec<ServerResponse> =
        read_batch_response_versioned(&bytes).expect("fanout response");
    assert_eq!(responses.len(), shard_ids.len());
    for (slot, shard) in responses.iter().zip(&shard_ids) {
        assert_eq!(
            extract_response(&crs, &client_state, slot, ENTRY).expect("extract"),
            vec![0x11; ENTRY],
            "shard {shard}"
        );
    }
}
