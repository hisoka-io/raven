//! A commit whose retention pass fails still publishes, so nothing else reports it, and every
//! repeat leaves one more superseded snapshot on disk. `/v1/health/ready` counts them per
//! instance for a disk alert.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Method, Request},
};
use http_body_util::BodyExt;
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{setup_state, LogicalLeafStore, RavenInspireScheme};
use raven_railgun_engine::persistence::{InspirePersistence, RetentionPolicy, SnapshotPolicy};
use raven_railgun_engine::pir_table::PerLeafCommitmentEncoder;
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
use raven_railgun_http::{inspire_router, AppState, HealthReadyResponse, HttpConfig};
use raven_railgun_persistence::StoreLayout;
use tower::ServiceExt;

const INSTANCE: &str = "retention-failure-health";
const ENTRY_BYTES: usize = 256;
const ROWS_PER_SHARD: u32 = 2048;

#[tokio::test]
async fn a_failed_retention_pass_is_counted_in_readiness() {
    let params = InspireParams::secure_128_d2048();
    let db = raven_railgun_testkit::toy_db(raven_railgun_testkit::TOY_ENTRIES, ENTRY_BYTES);
    let (state, _sk) =
        setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("toy state");

    let dir = std::env::temp_dir().join(format!("{INSTANCE}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("data dir");
    let opened = InspirePersistence::open(
        StoreLayout::open(&dir).expect("layout"),
        "retention-health-test",
        InstanceId::new(INSTANCE),
        SnapshotPolicy {
            max_appends_per_snapshot: usize::MAX,
            max_seconds_between_snapshots: u64::MAX,
            retention: RetentionPolicy {
                archived_wals_retain: usize::MAX,
                snapshots_retain: 0,
            },
        },
        Arc::new(PerLeafCommitmentEncoder::new(ENTRY_BYTES, ROWS_PER_SHARD, 0).expect("encoder")),
    )
    .expect("open");
    // A file where retention expects a snapshot directory: the pass fails after the publish.
    let obstacle = opened
        .persistence
        .layout()
        .root()
        .join("snapshots")
        .join("snap-999999");
    std::fs::write(&obstacle, b"not a snapshot directory").expect("plant obstacle");
    opened
        .persistence
        .commit_v6(&state, &LogicalLeafStore::new(), 1)
        .expect("the commit itself succeeds");

    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    engine
        .add_instance(PirInstance::new(
            InstanceId::new(INSTANCE),
            InstanceRole::Live,
            state,
        ))
        .expect("register instance");
    let router = inspire_router(
        AppState::new(engine, HttpConfig::demo("retention-health-read-token")).expect("appstate"),
    )
    .expect("router");
    let mut request = Request::builder()
        .method(Method::GET)
        .uri("/v1/health/ready")
        .body(Body::empty())
        .expect("request");
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let body = router
        .oneshot(request)
        .await
        .expect("dispatch")
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let _ = std::fs::remove_dir_all(&dir);

    let health: HealthReadyResponse = serde_json::from_slice(&body).expect("health json");
    assert_eq!(
        health.retention_failures.get(INSTANCE),
        Some(&1),
        "{}",
        String::from_utf8_lossy(&body)
    );
}
