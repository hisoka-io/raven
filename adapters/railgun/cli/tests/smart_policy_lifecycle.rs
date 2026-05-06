//! Smart-policy lifecycle tests for the auto-spawn driver.
//! Drives `run_driver` through a synthetic broadcast channel and
//! exercises `max_instance_count` and `cooldown` gates on the live path.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::indexing_slicing
)]

use std::sync::Arc;
use std::time::Duration;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_cli::auto_spawn_driver::{run_driver, AutoSpawnRuntime, SpawnRegistry};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{setup_state, RavenInspireScheme};
use raven_railgun_engine::orchestrator::ChainTreeRoutes;
use raven_railgun_engine::persistence::ConsumerEvent;
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};

const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_BYTES: usize = 256;

struct PolicyHarness {
    engine: Arc<Engine<RavenInspireScheme>>,
    chain_tree_routes: ChainTreeRoutes,
    registry: Arc<SpawnRegistry>,
    bootstrap_tree_dir: std::path::PathBuf,
}

fn build_toy_state() -> raven_railgun_core::Result<raven_railgun_engine::inspire::InspireServerState>
{
    let params = InspireParams::secure_128_d2048();
    let db: Vec<u8> = (0..TOY_ENTRIES)
        .flat_map(|i| {
            (0..TOY_ENTRY_BYTES).map(move |j| u8::try_from((i + j) % 251).expect("< 251"))
        })
        .collect();
    let (state, _sk) = setup_state(&params, &db, TOY_ENTRY_BYTES, InspireVariant::TwoPacking)?;
    Ok(state)
}

fn fresh_harness(tmp: &std::path::Path) -> PolicyHarness {
    let bootstrap_tree_dir = tmp.join("commit-tree-0");
    std::fs::create_dir_all(&bootstrap_tree_dir).expect("create bootstrap tree dir");

    let engine: Arc<Engine<RavenInspireScheme>> = Arc::new(Engine::new());
    let bootstrap_state = build_toy_state().expect("toy state");
    let bootstrap_instance: Arc<PirInstance<RavenInspireScheme>> =
        Arc::new(PirInstance::<RavenInspireScheme>::new(
            InstanceId::new("commit-tree-0"),
            InstanceRole::Live,
            bootstrap_state,
        ));
    engine
        .add_live(Arc::clone(&bootstrap_instance))
        .expect("seed bootstrap tree-0");

    let (bootstrap_tx, _bootstrap_rx) = tokio::sync::mpsc::channel::<ConsumerEvent>(64);
    let chain_tree_routes: ChainTreeRoutes =
        Arc::new(arc_swap::ArcSwap::from_pointee(vec![(0u32, bootstrap_tx)]));

    let registry = Arc::new(SpawnRegistry::new());
    {
        use raven_railgun_engine::orchestrator::{InstanceConfig, PerInstanceHandles};
        use raven_railgun_engine::persistence::{
            ConsumerMetrics, InspirePersistence, SnapshotPolicy,
        };
        use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
        use raven_railgun_persistence::StoreLayout;

        let layout = StoreLayout::open(&bootstrap_tree_dir).expect("layout");
        let encoder: Arc<dyn PirTableEncoder> = EncoderKind::PerLeafBc
            .build(TOY_ENTRY_BYTES, 256)
            .expect("build encoder");
        let opened = InspirePersistence::open(
            layout,
            "raven-inspire-twopacking-inspiring-wp3-cache-session",
            InstanceId::new("commit-tree-0"),
            SnapshotPolicy::default(),
            encoder,
        )
        .expect("open persistence");
        let pers = Arc::new(opened.persistence);

        let cfg = InstanceConfig::commit_tree(
            "commit-tree-0",
            bootstrap_tree_dir.clone(),
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
            logical_store: Arc::new(parking_lot::Mutex::new(
                raven_railgun_engine::inspire::LogicalLeafStore::new(),
            )),
        };
        registry.seed_from_bootstrap(&[handle]);
    }

    PolicyHarness {
        engine,
        chain_tree_routes,
        registry,
        bootstrap_tree_dir,
    }
}

fn toy_runtime(tmp: &std::path::Path) -> AutoSpawnRuntime {
    AutoSpawnRuntime {
        data_dir_template: tmp
            .join("auto-tree-{tree_number}")
            .to_string_lossy()
            .into_owned(),
        encoder: "per-leaf-bc".to_owned(),
        scheme_tag: "raven-inspire-twopacking-inspiring-wp3-cache-session".to_owned(),
        entries: TOY_ENTRIES,
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

async fn wait_for_refused_spawns(registry: &Arc<SpawnRegistry>, expected: u64, deadline: Duration) {
    let started = tokio::time::Instant::now();
    while started.elapsed() < deadline {
        if registry.refused_spawns() >= expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "timed out waiting for refused_spawns >= {expected}; got {}",
        registry.refused_spawns()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn synthetic_chain_drives_template_based_spawn_to_5_trees() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let harness = fresh_harness(tmp.path());

    let runtime = toy_runtime(tmp.path());
    let params = InspireParams::secure_128_d2048();
    let (tx, rx) = tokio::sync::broadcast::channel::<u32>(16);
    let log_dir = harness.bootstrap_tree_dir.clone();

    let registry_for_task = Arc::clone(&harness.registry);
    let engine_for_task = Arc::clone(&harness.engine);
    let routes_for_task = Arc::clone(&harness.chain_tree_routes);
    let driver = tokio::spawn(async move {
        run_driver(
            runtime,
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

    for t in 1u32..=4 {
        tx.send(t).expect("broadcast send");
    }

    wait_for_chain_tree_count(&harness.registry, 5, Duration::from_secs(60)).await;

    assert_eq!(
        harness.registry.refused_spawns(),
        0,
        "smart-policy disabled must not refuse any spawn",
    );

    assert_eq!(
        harness.engine.instances().len(),
        5,
        "engine must hold 5 instances after 4 spawns",
    );

    for t in 1u32..=4 {
        let dir = tmp.path().join(format!("auto-tree-{t}"));
        assert!(
            dir.is_dir(),
            "auto-spawned tree-{t} data_dir missing at {}",
            dir.display(),
        );
    }

    drop(tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), driver).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn max_instance_count_4_refuses_5th_spawn_loud() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let harness = fresh_harness(tmp.path());

    let mut runtime = toy_runtime(tmp.path());
    runtime.max_instance_count = Some(4); // 1 bootstrap + 3 successors = ceiling
    let params = InspireParams::secure_128_d2048();
    let (tx, rx) = tokio::sync::broadcast::channel::<u32>(16);
    let log_dir = harness.bootstrap_tree_dir.clone();

    let registry_for_task = Arc::clone(&harness.registry);
    let engine_for_task = Arc::clone(&harness.engine);
    let routes_for_task = Arc::clone(&harness.chain_tree_routes);
    let driver = tokio::spawn(async move {
        run_driver(
            runtime,
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

    for t in 1u32..=5 {
        tx.send(t).expect("broadcast send");
    }

    wait_for_chain_tree_count(&harness.registry, 4, Duration::from_secs(60)).await;
    wait_for_refused_spawns(&harness.registry, 2, Duration::from_secs(15)).await;

    assert_eq!(
        harness.registry.chain_tree_count(),
        4,
        "registry must hold exactly 4 chain-tree instances at ceiling",
    );
    assert_eq!(
        harness.engine.instances().len(),
        4,
        "engine must hold exactly 4 instances at ceiling",
    );
    assert_eq!(
        harness.registry.refused_spawns(),
        2,
        "spawns past the ceiling must increment refused_spawns",
    );

    for t in 4u32..=5 {
        let dir = tmp.path().join(format!("auto-tree-{t}"));
        assert!(
            !dir.exists(),
            "smart-policy refusal must NOT create data_dir at {}",
            dir.display(),
        );
    }
    for t in 1u32..=3 {
        let dir = tmp.path().join(format!("auto-tree-{t}"));
        assert!(
            dir.is_dir(),
            "below-ceiling spawn for tree-{t} must produce data_dir at {}",
            dir.display(),
        );
    }

    drop(tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), driver).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cooldown_seconds_refuses_back_to_back_spawns() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let harness = fresh_harness(tmp.path());

    let cooldown = Duration::from_millis(750);
    let mut runtime = toy_runtime(tmp.path());
    runtime.cooldown = Some(cooldown);
    let params = InspireParams::secure_128_d2048();
    let (tx, rx) = tokio::sync::broadcast::channel::<u32>(16);
    let log_dir = harness.bootstrap_tree_dir.clone();

    let registry_for_task = Arc::clone(&harness.registry);
    let engine_for_task = Arc::clone(&harness.engine);
    let routes_for_task = Arc::clone(&harness.chain_tree_routes);
    let driver = tokio::spawn(async move {
        run_driver(
            runtime,
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

    tx.send(1).expect("send tree-1");
    wait_for_chain_tree_count(&harness.registry, 2, Duration::from_secs(60)).await;
    assert_eq!(harness.registry.refused_spawns(), 0);

    tx.send(2).expect("send tree-2");
    wait_for_refused_spawns(&harness.registry, 1, Duration::from_secs(5)).await;
    assert_eq!(
        harness.registry.chain_tree_count(),
        2,
        "tree-2 spawn must NOT have landed within cooldown window",
    );
    let tree2_dir = tmp.path().join("auto-tree-2");
    assert!(
        !tree2_dir.exists(),
        "cooldown refusal must NOT create data_dir at {}",
        tree2_dir.display(),
    );

    tokio::time::sleep(cooldown + Duration::from_millis(250)).await;

    // Send tree-3 (not 2) so the watcher's monotonicity invariant is
    // unambiguous: a resend of 2 would interact with the previous
    // refusal's advanced state.
    tx.send(3).expect("send tree-3 post-cooldown");
    wait_for_chain_tree_count(&harness.registry, 3, Duration::from_secs(60)).await;
    let tree3_dir = tmp.path().join("auto-tree-3");
    assert!(
        tree3_dir.is_dir(),
        "post-cooldown spawn must produce data_dir at {}",
        tree3_dir.display(),
    );

    drop(tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), driver).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn max_count_and_cooldown_compose() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let harness = fresh_harness(tmp.path());

    let cooldown = Duration::from_millis(500);
    let mut runtime = toy_runtime(tmp.path());
    runtime.max_instance_count = Some(3); // bootstrap + 2 successors
    runtime.cooldown = Some(cooldown);
    let params = InspireParams::secure_128_d2048();
    let (tx, rx) = tokio::sync::broadcast::channel::<u32>(16);
    let log_dir = harness.bootstrap_tree_dir.clone();

    let registry_for_task = Arc::clone(&harness.registry);
    let engine_for_task = Arc::clone(&harness.engine);
    let routes_for_task = Arc::clone(&harness.chain_tree_routes);
    let driver = tokio::spawn(async move {
        run_driver(
            runtime,
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

    tx.send(1).expect("send 1");
    wait_for_chain_tree_count(&harness.registry, 2, Duration::from_secs(60)).await;

    // Tree 2 hits cooldown immediately.
    tx.send(2).expect("send 2");
    wait_for_refused_spawns(&harness.registry, 1, Duration::from_secs(5)).await;

    // Past the cooldown, tree 3 lands and takes us to the ceiling.
    tokio::time::sleep(cooldown + Duration::from_millis(250)).await;
    tx.send(3).expect("send 3");
    wait_for_chain_tree_count(&harness.registry, 3, Duration::from_secs(60)).await;
    assert_eq!(
        harness.registry.chain_tree_count(),
        3,
        "registry at ceiling after 2 spawns",
    );

    // Past cooldown, tree 4 hits the ceiling instead.
    tokio::time::sleep(cooldown + Duration::from_millis(250)).await;
    tx.send(4).expect("send 4");
    wait_for_refused_spawns(&harness.registry, 2, Duration::from_secs(5)).await;
    assert_eq!(
        harness.registry.chain_tree_count(),
        3,
        "tree-4 spawn must NOT land past ceiling",
    );
    let tree4_dir = tmp.path().join("auto-tree-4");
    assert!(
        !tree4_dir.exists(),
        "cap refusal must NOT create data_dir at {}",
        tree4_dir.display(),
    );

    drop(tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), driver).await;
}

#[test]
fn toml_instance_template_and_max_instance_count_round_trip() {
    use raven_railgun_cli::serve_production_multi::load_options_from_toml;
    use std::io::Write;

    let body = r#"
[global]
bind = "127.0.0.1:0"
token = "smart-policy-toml-token-pad-long"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"
max_instance_count = 8

[[instance_template]]
template_id = "commit-tree-template"
encoder = "per-node"
scheme_tag = "raven-inspire-twopacking-inspiring-wp3-cache-session"
data_dir_template = "/var/lib/raven-railgun/commit-tree-{tree_number}"
k_concurrency = 16
max_instance_count = 5
cooldown_seconds = 30

[[instance]]
id = "commit-tree-0"
role = "static"
encoder = "per-node"
tree_number = 0
data_dir = "/var/lib/raven-railgun/commit-tree-0"
verification_mode = "chain-root-history"
data_source = { kind = "indexer", filter = { tree_number = 0 } }
"#;

    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(body.as_bytes()).expect("write toml");
    let opts = load_options_from_toml(f.path()).expect("parse");

    let auto_spawn = opts
        .auto_spawn
        .as_ref()
        .expect("instance_template must synthesize auto_spawn");
    assert_eq!(auto_spawn.encoder, "per-node");
    assert_eq!(
        auto_spawn.data_dir_template,
        "/var/lib/raven-railgun/commit-tree-{tree_number}"
    );
    // Per-template smart-policy gate (5) overrides the global cap (8).
    assert_eq!(
        auto_spawn.max_instance_count,
        Some(5),
        "per-template max_instance_count must override [global]",
    );
    assert_eq!(
        auto_spawn.cooldown_seconds,
        Some(30),
        "per-template cooldown_seconds must surface",
    );
}

#[test]
fn legacy_auto_spawn_inherits_global_max_instance_count() {
    use raven_railgun_cli::serve_production_multi::load_options_from_toml;
    use std::io::Write;

    let body = r#"
[global]
bind = "127.0.0.1:0"
token = "smart-policy-legacy-token-padded"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"
max_instance_count = 7

[auto_spawn]
enabled = true
data_dir_template = "/var/lib/raven-railgun/commit-tree-{tree_number}"
encoder = "per-node"
scheme_tag = "raven-inspire-twopacking-inspiring-wp3-cache-session"
entries = 65536
entry_bytes = 512
cooldown_seconds = 15

[[instance]]
id = "commit-tree-0"
role = "static"
encoder = "per-node"
tree_number = 0
data_dir = "/var/lib/raven-railgun/commit-tree-0"
verification_mode = "chain-root-history"
data_source = { kind = "indexer", filter = { tree_number = 0 } }
"#;

    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(body.as_bytes()).expect("write toml");
    let opts = load_options_from_toml(f.path()).expect("parse");

    let auto_spawn = opts.auto_spawn.expect("legacy [auto_spawn] enabled");
    assert_eq!(
        auto_spawn.max_instance_count,
        Some(7),
        "[auto_spawn] section must inherit [global].max_instance_count when not overriding",
    );
    assert_eq!(auto_spawn.cooldown_seconds, Some(15));
}
