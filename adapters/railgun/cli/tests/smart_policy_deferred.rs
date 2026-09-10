//! SIGHUP hot-reload, PPOI list-template parsing, `tree_fill_threshold`
//! pre-spawn, and admin-drain x auto-spawn interactions.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::too_many_lines,
    clippy::indexing_slicing,
    unsafe_code
)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use raven_inspire::params::InspireParams;
use raven_railgun_cli::auto_spawn_driver::{
    pre_spawn_for_tree, run_driver_dynamic, AutoSpawnRuntime, SpawnRegistry,
};
use raven_railgun_cli::serve_production_multi::load_options_from_toml;
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{InspireServerState, RavenInspireScheme};
use raven_railgun_engine::orchestrator::ChainTreeRoutes;
use raven_railgun_engine::persistence::ConsumerEvent;
use raven_railgun_engine::{DrainState, Engine, InstanceRole, PirInstance};

const TOY_ENTRY_BYTES: usize = 256;

/// Rows the AUTO-SPAWNED cell must hold.
///
/// Distinct from the harness's own bootstrap fixture size. Every leaf-keyed
/// encoder declares `min_total_entries() == LEAVES_PER_TREE`, and `pre_spawn_for_tree` enforces it
/// (`auto_spawn_driver.rs`). A spawn requested at 256 rows is refused, the successor never appears,
/// and the test times out waiting for a count that can never rise - which is what nine of these
/// tests were doing.
const AUTO_SPAWN_CELL_ROWS: usize = 65_536;

/// Wall-clock budget per auto-spawned tree.
///
/// Each spawn now builds a real `AUTO_SPAWN_CELL_ROWS` cell, measured at 16-22 s. The previous
/// flat 60 s deadlines were calibrated when the spawn was refused instantly for an illegal cell
/// shape, so they timed out as soon as spawning started working. This is a hang-breaker, not an
/// SLO: it must be generous enough that a slow runner does not red a correct run.
const SPAWN_BUDGET_PER_TREE: Duration = Duration::from_secs(45);
const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-cache-session";

struct TestHarness {
    engine: Arc<Engine<RavenInspireScheme>>,
    chain_tree_routes: ChainTreeRoutes,
    registry: Arc<SpawnRegistry>,
    bootstrap_dir: std::path::PathBuf,
    bootstrap_instance: Arc<PirInstance<RavenInspireScheme>>,
}

fn build_toy_state() -> InspireServerState {
    raven_railgun_testkit::toy_state(TOY_ENTRY_BYTES)
}

fn fresh_harness(tmp: &Path) -> TestHarness {
    let bootstrap_dir = tmp.join("commit-tree-0");
    std::fs::create_dir_all(&bootstrap_dir).expect("create bootstrap tree dir");

    let engine: Arc<Engine<RavenInspireScheme>> = Arc::new(Engine::new());
    let bootstrap_instance: Arc<PirInstance<RavenInspireScheme>> =
        Arc::new(PirInstance::<RavenInspireScheme>::new(
            InstanceId::new("commit-tree-0"),
            InstanceRole::Live,
            build_toy_state(),
        ));
    engine
        .add_live(Arc::clone(&bootstrap_instance))
        .expect("seed bootstrap tree-0");

    let (bootstrap_tx, _bootstrap_rx) = tokio::sync::mpsc::channel::<ConsumerEvent>(64);
    let chain_tree_routes: ChainTreeRoutes =
        Arc::new(arc_swap::ArcSwap::from_pointee(vec![(0u32, bootstrap_tx)]));

    let registry = Arc::new(SpawnRegistry::new());
    {
        use raven_railgun_engine::inspire::LogicalLeafStore;
        use raven_railgun_engine::orchestrator::{InstanceConfig, PerInstanceHandles};
        use raven_railgun_engine::persistence::{
            ConsumerMetrics, InspirePersistence, SnapshotPolicy,
        };
        use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
        use raven_railgun_persistence::StoreLayout;

        let layout = StoreLayout::open(&bootstrap_dir).expect("layout");
        let encoder: Arc<dyn PirTableEncoder> = EncoderKind::PerLeafBc { tree_number: 0 }
            .build(TOY_ENTRY_BYTES, 256)
            .expect("build encoder");
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("commit-tree-0"),
            SnapshotPolicy::default(),
            encoder,
        )
        .expect("open persistence");
        let pers = Arc::new(opened.persistence);

        let cfg = InstanceConfig::commit_tree(
            "commit-tree-0",
            bootstrap_dir.clone(),
            0,
            InstanceRole::Live,
        );
        let (sender, _rx) = tokio::sync::mpsc::channel::<ConsumerEvent>(64);
        let handle = PerInstanceHandles {
            config: cfg,
            instance: Arc::clone(&bootstrap_instance),
            persistence: pers,
            consumer: tokio::spawn(async { Ok(()) }),
            sender,
            metrics: Arc::new(parking_lot::Mutex::new(ConsumerMetrics::default())),
            logical_store: Arc::new(parking_lot::Mutex::new(LogicalLeafStore::new())),
        };
        registry.seed_from_bootstrap(&[handle]);
    }

    TestHarness {
        engine,
        chain_tree_routes,
        registry,
        bootstrap_dir,
        bootstrap_instance,
    }
}

fn toy_runtime(tmp: &Path) -> AutoSpawnRuntime {
    AutoSpawnRuntime {
        data_dir_template: tmp
            .join("auto-tree-{tree_number}")
            .to_string_lossy()
            .into_owned(),
        encoder: "per-leaf-bc".to_owned(),
        scheme_tag: SCHEME_TAG.to_owned(),
        entries: AUTO_SPAWN_CELL_ROWS,
        entry_bytes: TOY_ENTRY_BYTES,
        channel_capacity: 64,
        verification_cadence_n: 0,
        max_instance_count: None,
        cooldown: None,
    }
}

async fn wait_for_chain_tree_count(
    registry: &Arc<SpawnRegistry>,
    expected: usize,
    deadline: Duration,
) {
    let started = tokio::time::Instant::now();
    while started.elapsed() < deadline {
        if registry.chain_tree_count() >= expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "timed out waiting for chain_tree_count >= {expected}; got {}",
        registry.chain_tree_count()
    );
}

#[test]
fn multi_list_ppoi_auto_spawn_on_new_list_key() {
    use std::io::Write;

    let body = r#"
[global]
bind = "127.0.0.1:0"
token = "ppoi-template-toml-token-padded"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"

[[ppoi_list_template]]
template_id = "ppoi-status-templ"
list_key = "0000000000000000000000000000000000000000000000000000000000000001"
encoder = "per-list-status"
data_dir_template = "/var/lib/raven-railgun/ppoi-status-{list_key}"
k_concurrency = 16

[[ppoi_list_template]]
template_id = "ppoi-node-templ"
list_key = "0000000000000000000000000000000000000000000000000000000000000002"
encoder = "per-list-node"
data_dir_template = "/var/lib/raven-railgun/ppoi-node-{list_key}"
k_concurrency = 32

[[instance]]
id = "commit-tree-0"
role = "static"
encoder = "per-leaf-bc"
tree_number = 0
data_dir = "/tmp/raven-ppoi-templates-tree-0"
verification_mode = "chain-root-history"
data_source = { kind = "indexer", filter = { tree_number = 0 } }
"#;
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(body.as_bytes()).expect("write");
    let opts = load_options_from_toml(f.path()).expect("parse ppoi templates");
    assert_eq!(opts.ppoi_list_templates.len(), 2);
    assert_eq!(opts.ppoi_list_templates[0].template_id, "ppoi-status-templ");
    assert_eq!(opts.ppoi_list_templates[0].encoder, "per-list-status");
    assert_eq!(opts.ppoi_list_templates[1].encoder, "per-list-node");

    let bad_body = r#"
[global]
bind = "127.0.0.1:0"
token = "ppoi-template-toml-token-padded"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"

[[ppoi_list_template]]
template_id = "ppoi-bad-templ"
list_key = "0000000000000000000000000000000000000000000000000000000000000003"
encoder = "per-list-status"
data_dir_template = "/var/lib/raven-railgun/no-placeholder"

[[instance]]
id = "commit-tree-0"
role = "static"
encoder = "per-leaf-bc"
tree_number = 0
data_dir = "/tmp/raven-ppoi-bad-tree-0"
verification_mode = "chain-root-history"
data_source = { kind = "indexer", filter = { tree_number = 0 } }
"#;
    let mut bad_f = tempfile::NamedTempFile::new().expect("tempfile bad");
    bad_f.write_all(bad_body.as_bytes()).expect("write bad");
    let err = load_options_from_toml(bad_f.path()).expect_err("must reject missing placeholder");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("{list_key}"),
        "expected missing-placeholder error; got: {msg}"
    );

    let wrong_encoder = r#"
[global]
bind = "127.0.0.1:0"
token = "ppoi-template-toml-token-padded"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"

[[ppoi_list_template]]
template_id = "ppoi-wrong"
list_key = "0000000000000000000000000000000000000000000000000000000000000004"
encoder = "per-leaf-bc"
data_dir_template = "/var/lib/raven-railgun/x-{list_key}"

[[instance]]
id = "commit-tree-0"
role = "static"
encoder = "per-leaf-bc"
tree_number = 0
data_dir = "/tmp/raven-ppoi-wrong-tree-0"
verification_mode = "chain-root-history"
data_source = { kind = "indexer", filter = { tree_number = 0 } }
"#;
    let mut wrong_f = tempfile::NamedTempFile::new().expect("tempfile wrong");
    wrong_f
        .write_all(wrong_encoder.as_bytes())
        .expect("write wrong");
    let err =
        load_options_from_toml(wrong_f.path()).expect_err("must reject non-PPOI encoder label");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("not a") && msg.contains("PPOI encoder"),
        "expected not-a-PPOI-encoder error; got: {msg}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "~7 s per PIR instance stood up, ~99% of it PackParams::try_new (the deterministic \
            d=2048 packing table) built twice per setup_state; the keygen proper is ~60 ms. \
            Trigger: changing SIGHUP template reload, fill-threshold pre-spawn, or admin drain \
            during auto-spawn."]
async fn tree_fill_threshold_pre_spawns_at_95_percent() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let harness = fresh_harness(tmp.path());
    let runtime = toy_runtime(tmp.path());
    let params = InspireParams::secure_128_d2048();

    assert_eq!(harness.registry.chain_tree_count(), 1);
    assert!(!harness.registry.known().contains(&1u32));

    let landed = pre_spawn_for_tree(
        &runtime,
        &params,
        &harness.engine,
        &harness.chain_tree_routes,
        &harness.registry,
        harness.bootstrap_dir.clone(),
        None,
        1,
    )
    .expect("pre_spawn_for_tree");
    assert!(landed, "pre_spawn_for_tree must land the successor");

    assert_eq!(harness.registry.chain_tree_count(), 2);
    assert!(harness.registry.known().contains(&1u32));
    assert!(harness
        .engine
        .instance(&InstanceId::new("commit-tree-1"))
        .is_some());
    let tree1_dir = tmp.path().join("auto-tree-1");
    assert!(
        tree1_dir.is_dir(),
        "auto-spawn data_dir for tree-1 missing at {}",
        tree1_dir.display(),
    );

    // A flapping fill metric must not respawn a known tree each tick.
    let again = pre_spawn_for_tree(
        &runtime,
        &params,
        &harness.engine,
        &harness.chain_tree_routes,
        &harness.registry,
        harness.bootstrap_dir.clone(),
        None,
        1,
    )
    .expect("re-pre-spawn");
    assert!(!again, "re-pre-spawn for known tree must short-circuit");
    assert_eq!(
        harness.registry.chain_tree_count(),
        2,
        "registry must NOT grow on idempotent pre-spawn",
    );

    let trigger_at =
        raven_railgun_cli::serve_production_multi::compute_trigger_threshold(0.95_f32, 65_536_u32);
    assert_eq!(trigger_at, 62_259);
    assert_eq!(
        raven_railgun_cli::serve_production_multi::compute_trigger_threshold(0.0, 65_536),
        0
    );
    assert_eq!(
        raven_railgun_cli::serve_production_multi::compute_trigger_threshold(1.0, 65_536),
        65_536
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "~7 s per PIR instance stood up, ~99% of it PackParams::try_new (the deterministic \
            d=2048 packing table) built twice per setup_state; the keygen proper is ~60 ms. \
            Trigger: changing SIGHUP template reload, fill-threshold pre-spawn, or admin drain \
            during auto-spawn."]
async fn admin_drain_concurrent_with_auto_spawn_routes_consistently() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let harness = fresh_harness(tmp.path());
    let runtime = toy_runtime(tmp.path());
    let params = InspireParams::secure_128_d2048();

    harness
        .bootstrap_instance
        .set_drain_state(DrainState::Draining);
    assert_eq!(
        harness.bootstrap_instance.drain_state(),
        DrainState::Draining
    );

    let live_runtime: Arc<arc_swap::ArcSwap<AutoSpawnRuntime>> =
        Arc::new(arc_swap::ArcSwap::from_pointee(runtime));
    let (tx, rx) = tokio::sync::broadcast::channel::<u32>(8);
    let log_dir = harness.bootstrap_dir.clone();

    let registry_for_task = Arc::clone(&harness.registry);
    let engine_for_task = Arc::clone(&harness.engine);
    let routes_for_task = Arc::clone(&harness.chain_tree_routes);
    let driver = tokio::spawn(async move {
        run_driver_dynamic(
            live_runtime,
            params,
            engine_for_task,
            routes_for_task,
            registry_for_task,
            log_dir,
            None,
            rx,
        )
        .await;
    });

    tx.send(1u32).expect("broadcast tree-1");
    wait_for_chain_tree_count(&harness.registry, 2, SPAWN_BUDGET_PER_TREE * 2).await;

    let successor = harness
        .engine
        .instance(&InstanceId::new("commit-tree-1"))
        .expect("successor present");
    assert_eq!(successor.drain_state(), DrainState::Active);

    assert_eq!(
        harness.bootstrap_instance.drain_state(),
        DrainState::Drained,
        "predecessor must promote from Draining to Drained when a successor lands"
    );

    let active_ids: Vec<String> = harness
        .engine
        .active_instances()
        .iter()
        .map(|i| i.id.to_string())
        .collect();
    assert!(
        !active_ids.iter().any(|id| id == "commit-tree-0"),
        "drained predecessor must NOT appear in active_instances; got: {active_ids:?}"
    );
    assert!(
        active_ids.iter().any(|id| id == "commit-tree-1"),
        "successor must appear in active_instances; got: {active_ids:?}"
    );

    let routes = harness.chain_tree_routes.load();
    assert!(
        routes.iter().any(|(t, _)| *t == 1u32),
        "successor route for tree-1 missing from chain_tree_routes after auto-spawn"
    );

    drop(tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), driver).await;
}
