//! An auto-spawned instance publishes its consumer cell into the map the handlers read.
//!
//! Production requires consumer telemetry for every served instance, so a successor spawned
//! without a published cell would hold readiness at 503 from the moment it went live, and
//! `/v1/status` and `/metrics` would never report what it ingests.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use raven_inspire::params::InspireParams;
use raven_railgun_cli::auto_spawn::instance_id_for_tree;
use raven_railgun_cli::auto_spawn_driver::{pre_spawn_for_tree, AutoSpawnRuntime, SpawnRegistry};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::RavenInspireScheme;
use raven_railgun_engine::orchestrator::ChainTreeRoutes;
use raven_railgun_engine::persistence::ConsumerEvent;
use raven_railgun_engine::Engine;
use raven_railgun_http::{router, AppState, HealthReadyResponse, HttpConfig, StatusResponse};

const TOKEN: &str = "auto-spawn-metrics-cell-token-123456";
const CELL_ROWS: usize = 65_536;
const TREE: u32 = 1;

fn runtime(tmp: &std::path::Path) -> AutoSpawnRuntime {
    AutoSpawnRuntime {
        data_dir_template: tmp
            .join("auto-tree-{tree_number}")
            .to_string_lossy()
            .into_owned(),
        encoder: "per-leaf-bc".to_owned(),
        scheme_tag: "raven-inspire-twopacking-inspiring-v1".to_owned(),
        entries: CELL_ROWS,
        entry_bytes: 32,
        channel_capacity: 8,
        verification_cadence_n: 0,
        max_instance_count: None,
        cooldown: None,
        session_limits: raven_railgun_engine::session_pool::SessionStoreLimits::default(),
    }
}

async fn get_json<T: serde::de::DeserializeOwned>(addr: SocketAddr, path: &str) -> (u16, T) {
    let response = reqwest::Client::new()
        .get(format!("http://{addr}{path}"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .expect("request");
    let code = response.status().as_u16();
    (code, response.json().await.expect("json body"))
}

/// Spawns tree `TREE` into a production-shaped state and returns what the handlers see.
async fn spawn_and_probe(
    registry_for: impl FnOnce(&AppState<RavenInspireScheme>) -> SpawnRegistry,
) -> (HealthReadyResponse, StatusResponse) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state = AppState::new(Engine::new(), HttpConfig::demo(TOKEN))
        .expect("appstate")
        .require_consumer_metrics();
    let registry = Arc::new(registry_for(&state));
    let routes: ChainTreeRoutes = Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new()));
    let spawned = pre_spawn_for_tree(
        &runtime(tmp.path()),
        &InspireParams::d2048(),
        &state.engine,
        &routes,
        &registry,
        tmp.path().to_path_buf(),
        None,
        TREE,
    )
    .expect("pre_spawn_for_tree");
    assert!(spawned, "tree {TREE} must spawn");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = router::<RavenInspireScheme>(state).expect("router");
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    });
    let (_, ready) = get_json::<HealthReadyResponse>(addr, "/v1/health/ready").await;
    let (code, status) = get_json::<StatusResponse>(addr, "/v1/status").await;
    assert_eq!(code, 200, "status must be served");
    server.abort();

    // Quiesce the consumer before the tempdir drops.
    for handle in registry.drain_auto_spawned() {
        handle
            .consumer_sender
            .send(ConsumerEvent::Shutdown)
            .await
            .expect("send shutdown");
        tokio::time::timeout(Duration::from_secs(120), handle.consumer_join)
            .await
            .expect("consumer stopped")
            .expect("consumer task joined")
            .expect("final commit");
    }
    (ready, status)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_auto_spawned_instance_reports_its_own_consumer() {
    let spawned = InstanceId::new(instance_id_for_tree(TREE)).to_string();

    let (ready, status) = spawn_and_probe(|state| {
        SpawnRegistry::publishing_metrics_to(state.instance_metrics_registry())
    })
    .await;
    assert!(
        !ready.stalled_consumer_instances.contains(&spawned),
        "a freshly spawned successor must not read as a stalled consumer: {ready:?}"
    );
    let row = status
        .instances
        .iter()
        .find(|row| row.id == spawned)
        .expect("spawned row in /v1/status");
    assert!(
        row.consumer.is_some(),
        "the spawned row must carry its consumer"
    );
    assert!(status.consumer.is_some(), "the node block must include it");

    // Planted control: a registry that publishes nowhere, as before, fails the same checks.
    let (ready, status) = spawn_and_probe(|_| SpawnRegistry::new()).await;
    assert_eq!(ready.stalled_consumer_instances, vec![spawned.clone()]);
    let row = status
        .instances
        .iter()
        .find(|row| row.id == spawned)
        .expect("spawned row in /v1/status");
    assert!(row.consumer.is_none());
}
