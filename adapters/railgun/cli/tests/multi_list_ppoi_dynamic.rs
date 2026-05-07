//! Multi-list PPOI dynamic-discovery lifecycle tests.
//! Cross-validates the discovery driver wired on top of the engine's
//! `Arc<ArcSwap>`-promoted `ppoi_list_routes` and `list_observed` tap.

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
use raven_railgun_cli::auto_spawn_driver::{
    replay_ppoi_list_spawn_log, run_ppoi_list_driver, PpoiListSpawnRegistry,
    PpoiListTemplateRuntime,
};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{setup_state, InspireServerState, RavenInspireScheme};
use raven_railgun_engine::orchestrator::PpoiListRoutes;
use raven_railgun_engine::persistence::ConsumerEvent;
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};

const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_BYTES: usize = 256;
const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-cache-session";

const TEST_LIST_KEY: [u8; 32] = [
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
];

struct TestHarness {
    engine: Arc<Engine<RavenInspireScheme>>,
    ppoi_list_routes: PpoiListRoutes,
    bootstrap_dir: std::path::PathBuf,
}

fn build_toy_state() -> InspireServerState {
    let params = InspireParams::secure_128_d2048();
    let db: Vec<u8> = (0..TOY_ENTRIES)
        .flat_map(|i| {
            (0..TOY_ENTRY_BYTES).map(move |j| u8::try_from((i + j) % 251).expect("< 251"))
        })
        .collect();
    let (state, _sk) =
        setup_state(&params, &db, TOY_ENTRY_BYTES, InspireVariant::TwoPacking).expect("toy state");
    state
}

fn fresh_harness(tmp: &std::path::Path) -> TestHarness {
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
    let ppoi_list_routes: PpoiListRoutes = Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new()));
    TestHarness {
        engine,
        ppoi_list_routes,
        bootstrap_dir,
    }
}

fn template_runtime(
    tmp: &std::path::Path,
    template_id: &str,
    encoder: &str,
    list_key: [u8; 32],
) -> PpoiListTemplateRuntime {
    PpoiListTemplateRuntime {
        template_id: template_id.to_owned(),
        list_key,
        encoder: encoder.to_owned(),
        scheme_tag: SCHEME_TAG.to_owned(),
        data_dir_template: tmp
            .join(format!("ppoi-{template_id}-{{list_key}}"))
            .to_string_lossy()
            .into_owned(),
        entries: TOY_ENTRIES,
        entry_bytes: TOY_ENTRY_BYTES,
        channel_capacity: 64,
    }
}

async fn wait_for_pair_count(
    registry: &Arc<PpoiListSpawnRegistry>,
    expected: usize,
    deadline: Duration,
) {
    let started = tokio::time::Instant::now();
    while started.elapsed() < deadline {
        if registry.pair_count() >= expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "timed out waiting for ppoi pair_count >= {expected}; got {}",
        registry.pair_count()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn synthetic_upstream_emits_new_list_key_spawns_two_instances() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let harness = fresh_harness(tmp.path());

    let templates = vec![
        template_runtime(tmp.path(), "ppoi-status", "per-list-status", TEST_LIST_KEY),
        template_runtime(tmp.path(), "ppoi-path", "per-list-path", TEST_LIST_KEY),
    ];

    let params = InspireParams::secure_128_d2048();
    let registry = Arc::new(PpoiListSpawnRegistry::new());
    let (tx, rx) = tokio::sync::broadcast::channel::<[u8; 32]>(16);
    let log_dir = harness.bootstrap_dir.clone();

    let registry_for_task = Arc::clone(&registry);
    let engine_for_task = Arc::clone(&harness.engine);
    let routes_for_task = Arc::clone(&harness.ppoi_list_routes);
    let driver = tokio::spawn(async move {
        run_ppoi_list_driver(
            templates,
            params,
            engine_for_task,
            routes_for_task,
            registry_for_task,
            log_dir,
            rx,
        )
        .await;
    });

    tx.send(TEST_LIST_KEY).expect("broadcast list_key");

    wait_for_pair_count(&registry, 2, Duration::from_secs(60)).await;

    let known = registry.known_pairs();
    assert_eq!(known.len(), 2, "expected exactly 2 spawned pairs");
    let template_ids: Vec<String> = known.iter().map(|(t, _)| t.clone()).collect();
    assert!(
        template_ids.contains(&"ppoi-status".to_owned()),
        "ppoi-status template must spawn; got {template_ids:?}"
    );
    assert!(
        template_ids.contains(&"ppoi-path".to_owned()),
        "ppoi-path template must spawn; got {template_ids:?}"
    );
    for (_, lk) in &known {
        assert_eq!(
            lk, &TEST_LIST_KEY,
            "every spawn must match the test list_key"
        );
    }

    let routes = harness.ppoi_list_routes.load();
    let matching: Vec<_> = routes.iter().filter(|(k, _)| *k == TEST_LIST_KEY).collect();
    assert_eq!(
        matching.len(),
        2,
        "route table must hold one sender per template (got {})",
        matching.len()
    );

    let engine_ids: Vec<String> = harness
        .engine
        .instances()
        .iter()
        .map(|i| i.id.to_string())
        .collect();
    assert_eq!(
        engine_ids.len(),
        3,
        "engine must hold 1 bootstrap + 2 PPOI = 3 instances; got: {engine_ids:?}"
    );

    drop(tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), driver).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_list_observed_bursts_dedupe_to_one_spawn_per_template_per_list_key() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let harness = fresh_harness(tmp.path());

    let templates = vec![
        template_runtime(tmp.path(), "ppoi-status", "per-list-status", TEST_LIST_KEY),
        template_runtime(tmp.path(), "ppoi-node", "per-list-node", TEST_LIST_KEY),
    ];

    let params = InspireParams::secure_128_d2048();
    let registry = Arc::new(PpoiListSpawnRegistry::new());
    // Capacity well above the burst size so no broadcast value is
    // dropped before the driver consumes it; the dedup gate must do
    // the work, not the channel.
    let (tx, rx) = tokio::sync::broadcast::channel::<[u8; 32]>(64);
    let log_dir = harness.bootstrap_dir.clone();

    let registry_for_task = Arc::clone(&registry);
    let engine_for_task = Arc::clone(&harness.engine);
    let routes_for_task = Arc::clone(&harness.ppoi_list_routes);
    let driver = tokio::spawn(async move {
        run_ppoi_list_driver(
            templates,
            params,
            engine_for_task,
            routes_for_task,
            registry_for_task,
            log_dir,
            rx,
        )
        .await;
    });

    let mut firing = Vec::new();
    for _ in 0..10 {
        let tx_clone = tx.clone();
        firing.push(tokio::spawn(async move {
            // tokio broadcast::Sender::send is sync; the spawn just
            // gives us parallel firing across worker threads.
            tx_clone.send(TEST_LIST_KEY).expect("broadcast burst");
        }));
    }
    for jh in firing {
        jh.await.expect("burst sender join");
    }

    wait_for_pair_count(&registry, 2, Duration::from_secs(60)).await;

    // Allow time for any rogue duplicate spawn to surface.
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(
        registry.pair_count(),
        2,
        "concurrent bursts must dedupe to one spawn per template (got {})",
        registry.pair_count()
    );
    assert_eq!(
        registry.auto_spawned_len(),
        2,
        "auto_spawned shutdown handles must mirror pair_count exactly"
    );

    let routes = harness.ppoi_list_routes.load();
    let matching: Vec<_> = routes.iter().filter(|(k, _)| *k == TEST_LIST_KEY).collect();
    assert_eq!(
        matching.len(),
        2,
        "route table must hold exactly one sender per template after dedup"
    );

    drop(tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), driver).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_replay_picks_up_auto_spawned_ppoi_list_instances_from_spawn_log() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let harness = fresh_harness(tmp.path());

    let templates = vec![
        template_runtime(tmp.path(), "ppoi-status", "per-list-status", TEST_LIST_KEY),
        template_runtime(tmp.path(), "ppoi-path", "per-list-path", TEST_LIST_KEY),
    ];

    let params = InspireParams::secure_128_d2048();
    let registry_v1 = Arc::new(PpoiListSpawnRegistry::new());
    let (tx, rx) = tokio::sync::broadcast::channel::<[u8; 32]>(16);
    let log_dir = harness.bootstrap_dir.clone();

    let templates_for_task = templates.clone();
    let registry_for_task = Arc::clone(&registry_v1);
    let engine_for_task = Arc::clone(&harness.engine);
    let routes_for_task = Arc::clone(&harness.ppoi_list_routes);
    let log_dir_for_task = log_dir.clone();
    let driver_v1 = tokio::spawn(async move {
        run_ppoi_list_driver(
            templates_for_task,
            params.clone(),
            engine_for_task,
            routes_for_task,
            registry_for_task,
            log_dir_for_task,
            rx,
        )
        .await;
    });

    tx.send(TEST_LIST_KEY).expect("broadcast list_key");
    wait_for_pair_count(&registry_v1, 2, Duration::from_secs(60)).await;

    // Tear down v1 to simulate a process restart; the on-disk JSONL
    // spawn log is the durable state.
    drop(tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), driver_v1).await;
    drop(registry_v1);

    let engine_v2: Arc<Engine<RavenInspireScheme>> = Arc::new(Engine::new());
    let bootstrap_v2: Arc<PirInstance<RavenInspireScheme>> =
        Arc::new(PirInstance::<RavenInspireScheme>::new(
            InstanceId::new("commit-tree-0"),
            InstanceRole::Live,
            build_toy_state(),
        ));
    engine_v2
        .add_live(Arc::clone(&bootstrap_v2))
        .expect("seed bootstrap v2");
    let routes_v2: PpoiListRoutes = Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new()));
    let registry_v2 = Arc::new(PpoiListSpawnRegistry::new());

    let params_v2 = InspireParams::secure_128_d2048();
    let restored = replay_ppoi_list_spawn_log(
        &templates,
        &params_v2,
        &engine_v2,
        &routes_v2,
        &registry_v2,
        log_dir.clone(),
    )
    .expect("replay ppoi spawn log");

    assert_eq!(
        restored.len(),
        2,
        "replay must re-bootstrap both instances from the spawn log"
    );
    let template_ids_restored: Vec<String> = restored.iter().map(|(t, _)| t.clone()).collect();
    assert!(template_ids_restored.contains(&"ppoi-status".to_owned()));
    assert!(template_ids_restored.contains(&"ppoi-path".to_owned()));

    assert_eq!(
        registry_v2.pair_count(),
        2,
        "v2 registry must hold both replayed pairs"
    );

    let routes_after = routes_v2.load();
    let matching: Vec<_> = routes_after
        .iter()
        .filter(|(k, _)| *k == TEST_LIST_KEY)
        .collect();
    assert_eq!(
        matching.len(),
        2,
        "v2 route table must hold both replayed senders"
    );

    let engine_ids: Vec<String> = engine_v2
        .instances()
        .iter()
        .map(|i| i.id.to_string())
        .collect();
    assert_eq!(
        engine_ids.len(),
        3,
        "v2 engine must hold 1 bootstrap + 2 replayed PPOI = 3 instances; got: {engine_ids:?}"
    );

    let auto_spawned = registry_v2.drain_auto_spawned();
    for handle in auto_spawned {
        let _ = handle.consumer_sender.send(ConsumerEvent::Shutdown).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), handle.consumer_join).await;
    }
}
