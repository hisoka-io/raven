//! CLI-level auto-spawn race + atomicity tests.

#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::panic,
        clippy::unwrap_used,
        clippy::cast_possible_truncation,
        clippy::too_many_lines,
        clippy::indexing_slicing,
        clippy::assigning_clones
    )
)]

use raven_railgun_engine::tree_fill_watcher::TreeFillWatcher;

#[test]
fn concurrent_chain_event_floods_dedupe_to_one_spawn() {
    let mut watcher = TreeFillWatcher::new(0);
    let observations: Vec<u32> = std::iter::repeat_n(1u32, 32).collect();
    let mut spawn_signals = 0usize;
    for v in observations {
        if watcher.observe_tree_number(v).is_some() {
            spawn_signals += 1;
        }
    }
    assert_eq!(spawn_signals, 1, "32 duplicate events => 1 spawn signal");
    assert_eq!(watcher.last_known(), 1);

    assert!(watcher.observe_tree_number(0).is_none());
    assert!(watcher.observe_tree_number(1).is_none());
    assert_eq!(watcher.last_known(), 1);

    assert_eq!(watcher.observe_tree_number(2), Some(2));
    assert!(watcher.observe_tree_number(2).is_none());
}

use raven_railgun_cli::auto_spawn::{append_spawn_record, load_spawn_log, SpawnRecord};

#[test]
fn spawn_log_jsonl_atomicity_under_torn_write() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();

    let r0 = SpawnRecord {
        tree_number: 1,
        instance_id: "commit-tree-1".to_owned(),
        data_dir: dir.join("tree-1"),
        spawned_at_secs: 1_700_000_000,
    };
    let r1 = SpawnRecord {
        tree_number: 2,
        instance_id: "commit-tree-2".to_owned(),
        data_dir: dir.join("tree-2"),
        spawned_at_secs: 1_700_000_005,
    };
    let r2 = SpawnRecord {
        tree_number: 3,
        instance_id: "commit-tree-3".to_owned(),
        data_dir: dir.join("tree-3"),
        spawned_at_secs: 1_700_000_010,
    };

    append_spawn_record(dir, &r0).expect("append r0");
    append_spawn_record(dir, &r1).expect("append r1");

    {
        use std::io::Write;
        let path = dir.join("spawn_log.jsonl");
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("reopen");
        writeln!(f, "{{\"tree_number\":99,\"instance_id\":\"").expect("write torn line");
    }

    append_spawn_record(dir, &r2).expect("append r2");

    let restored = load_spawn_log(dir).expect("load");
    assert_eq!(
        restored.len(),
        3,
        "torn line skipped; valid records around it survive"
    );
    assert_eq!(restored[0].tree_number, 1);
    assert_eq!(restored[1].tree_number, 2);
    assert_eq!(restored[2].tree_number, 3);
}

#[cfg(unix)]
mod kill_during_spawn {
    use std::io::{BufRead, BufReader};
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use raven_inspire::params::{InspireParams, InspireVariant};
    use raven_railgun_cli::auto_spawn::{instance_id_for_tree, load_spawn_log};
    use raven_railgun_core::InstanceId;
    use raven_railgun_engine::inspire::{setup_state, RavenInspireScheme};
    use raven_railgun_engine::persistence::{bootstrap_inspire_instance, SnapshotPolicy};
    use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
    use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
    use raven_railgun_persistence::{Manifest, StoreLayout};

    const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-auto-spawn-chaos-child";
    const TOY_ENTRIES: usize = 256;
    const TOY_ENTRY_SIZE: usize = 32;
    const ENTRIES_PER_SHARD: u32 = 256;
    const SENTINEL_TIMEOUT: Duration = Duration::from_secs(120);
    const POST_KILL_WAIT: Duration = Duration::from_secs(10);

    fn build_toy_state() -> raven_railgun_engine::inspire::InspireServerState {
        let params = InspireParams::secure_128_d2048();
        let db: Vec<u8> = (0..TOY_ENTRIES)
            .flat_map(|i| {
                (0..TOY_ENTRY_SIZE).map(move |j| u8::try_from((i + j) % 251).expect("< 251"))
            })
            .collect();
        let (state, _sk) = setup_state(&params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking)
            .expect("setup_state");
        state
    }

    fn build_encoder() -> Arc<dyn PirTableEncoder> {
        EncoderKind::PerLeafBc
            .build(TOY_ENTRY_SIZE, ENTRIES_PER_SHARD)
            .expect("build per-leaf-bc encoder")
    }

    fn spawn_park_kill(
        data_dir: &Path,
        spawn_log_dir: &Path,
        tree_number: u32,
        pause_at: &str,
    ) -> String {
        let bin = env!("CARGO_BIN_EXE_auto_spawn_chaos_child");
        let mut child: Child = Command::new(bin)
            .arg("--data-dir")
            .arg(data_dir)
            .arg("--spawn-log-dir")
            .arg(spawn_log_dir)
            .arg("--tree-number")
            .arg(tree_number.to_string())
            .arg("--pause-at")
            .arg(pause_at)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn auto_spawn_chaos_child");

        let stdout = child.stdout.take().expect("captured stdout");
        let mut reader = BufReader::new(stdout);

        let deadline = Instant::now() + SENTINEL_TIMEOUT;
        let mut found = String::new();
        let mut line = String::new();
        while Instant::now() < deadline {
            line.clear();
            let n = reader.read_line(&mut line).expect("read child stdout");
            if n == 0 {
                break;
            }
            let trimmed = line.trim();
            if trimmed.contains("\"paused_at\"") {
                found = trimmed.to_owned();
                break;
            }
        }

        assert!(
            !found.is_empty(),
            "child did not emit paused_at sentinel within {SENTINEL_TIMEOUT:?} for pause_at={pause_at}"
        );
        let expected_fragment = format!("\"paused_at\":\"{pause_at}\"");
        assert!(
            found.contains(&expected_fragment),
            "sentinel must name the requested pause point; got: {found}"
        );

        child.kill().expect("kill child");
        let _ = child.wait().expect("wait child");
        std::thread::sleep(POST_KILL_WAIT.min(Duration::from_millis(250)));
        found
    }

    #[test]
    fn before_add_live_kill_leaves_orphan_data_dir_no_log() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().join("tree-7");
        let spawn_log_dir = tmp.path().join("spawn-log");
        std::fs::create_dir_all(&spawn_log_dir).expect("mkdir spawn log dir");

        let _sentinel = spawn_park_kill(&data_dir, &spawn_log_dir, 7, "before-add-live");

        assert!(data_dir.exists(), "data_dir must survive child kill");
        let layout = StoreLayout::open(&data_dir).expect("re-open layout");
        let manifest = Manifest::load(&layout)
            .expect("manifest load")
            .expect("manifest must be present after bootstrap_inspire_instance returned");
        assert_eq!(
            manifest.scheme_tag, SCHEME_TAG,
            "manifest scheme_tag must match the chaos child's tag"
        );

        let records = load_spawn_log(&spawn_log_dir).expect("load spawn log");
        assert!(
            records.is_empty(),
            "append-LAST: no log entry before engine.add_live; got: {records:?}"
        );

        let engine: Arc<Engine<RavenInspireScheme>> = Arc::new(Engine::new());
        assert_eq!(
            engine.instances().len(),
            0,
            "orphan data_dir requires operator reconcile; fresh engine starts empty"
        );
    }

    #[test]
    fn after_add_live_before_log_kill_leaves_orphan_engine_no_log() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().join("tree-8");
        let spawn_log_dir = tmp.path().join("spawn-log");
        std::fs::create_dir_all(&spawn_log_dir).expect("mkdir spawn log dir");

        let _sentinel = spawn_park_kill(&data_dir, &spawn_log_dir, 8, "after-add-live-before-log");

        assert!(data_dir.exists(), "data_dir must survive child kill");
        let layout = StoreLayout::open(&data_dir).expect("re-open layout");
        let manifest = Manifest::load(&layout)
            .expect("manifest load")
            .expect("manifest must be present after bootstrap_inspire_instance returned");
        assert_eq!(manifest.scheme_tag, SCHEME_TAG);

        let records = load_spawn_log(&spawn_log_dir).expect("load spawn log");
        assert!(
            records.is_empty(),
            "append-LAST: no log entry before append_spawn_record; got: {records:?}"
        );

        let engine: Arc<Engine<RavenInspireScheme>> = Arc::new(Engine::new());
        assert_eq!(
            engine.instances().len(),
            0,
            "in-memory add_live died with the process; fresh engine starts empty"
        );
    }

    #[test]
    fn after_log_kill_recovers_via_log_replay() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().join("tree-9");
        let spawn_log_dir = tmp.path().join("spawn-log");
        std::fs::create_dir_all(&spawn_log_dir).expect("mkdir spawn log dir");

        let _sentinel = spawn_park_kill(&data_dir, &spawn_log_dir, 9, "after-log");

        let records = load_spawn_log(&spawn_log_dir).expect("load spawn log");
        assert_eq!(
            records.len(),
            1,
            "after-log kill: exactly one spawn record fsynced before the kill"
        );
        assert_eq!(records[0].tree_number, 9);
        assert_eq!(records[0].instance_id, instance_id_for_tree(9));
        assert_eq!(records[0].data_dir, data_dir);

        let layout = StoreLayout::open(&records[0].data_dir).expect("re-open layout");
        let encoder = build_encoder();
        let instance_id = InstanceId::new(records[0].instance_id.clone());
        let factory = || -> raven_railgun_core::Result<_> { Ok(build_toy_state()) };
        let (instance, _persistence) = bootstrap_inspire_instance(
            layout,
            SCHEME_TAG,
            instance_id.clone(),
            InstanceRole::Live,
            SnapshotPolicy::default(),
            Arc::clone(&encoder),
            factory,
        )
        .expect("replay bootstrap_inspire_instance");

        let engine: Arc<Engine<RavenInspireScheme>> = Arc::new(Engine::new());
        let instance_arc: Arc<PirInstance<RavenInspireScheme>> = Arc::new(instance);
        engine
            .add_live(Arc::clone(&instance_arc))
            .expect("replay add_live");
        assert_eq!(engine.instances().len(), 1);
        assert!(
            engine.instance(&instance_id).is_some(),
            "engine resolves the recovered instance by id after log replay"
        );
    }
}

#[test]
#[ignore = "slow: cold-start PIR keygen; run with --ignored"]
fn crash_between_append_and_flip_recovers_with_doubly_live_tolerated() {
    use std::sync::Arc;

    use raven_inspire::params::{InspireParams, InspireVariant};
    use raven_railgun_core::InstanceId;
    use raven_railgun_engine::inspire::{setup_state, RavenInspireScheme};
    use raven_railgun_engine::{Engine, InstanceRole, PirInstance};

    const TOY_ENTRIES: usize = 256;
    const TOY_ENTRY_SIZE: usize = 32;

    let tmp = tempfile::tempdir().expect("tempdir");
    let spawn_log_dir = tmp.path().to_path_buf();
    let new_data_dir = tmp.path().join("tree-successor");

    let predecessor_role_before_crash = InstanceRole::Live;

    let new_record = SpawnRecord {
        tree_number: 42,
        instance_id: "commit-tree-successor".to_owned(),
        data_dir: new_data_dir.clone(),
        spawned_at_secs: 1_700_000_042,
    };
    append_spawn_record(&spawn_log_dir, &new_record).expect("append durable before crash");

    let restored = load_spawn_log(&spawn_log_dir).expect("load");
    assert_eq!(
        restored.len(),
        1,
        "append-before-flip: log entry survives the crash window"
    );
    assert_eq!(restored[0].tree_number, 42);
    assert_eq!(restored[0].instance_id, "commit-tree-successor");
    assert_eq!(restored[0].data_dir, new_data_dir);

    let build_toy_state = || -> raven_railgun_engine::inspire::InspireServerState {
        let params = InspireParams::secure_128_d2048();
        let db: Vec<u8> = (0..TOY_ENTRIES)
            .flat_map(|i| {
                (0..TOY_ENTRY_SIZE).map(move |j| u8::try_from((i + j) % 251).expect("< 251"))
            })
            .collect();
        let (state, _sk) = setup_state(&params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking)
            .expect("setup_state");
        state
    };

    let engine: Arc<Engine<RavenInspireScheme>> = Arc::new(Engine::new());

    let pred_instance = PirInstance::<RavenInspireScheme>::new(
        InstanceId::new("commit-tree-predecessor".to_owned()),
        predecessor_role_before_crash,
        build_toy_state(),
    );
    let pred_arc = Arc::new(pred_instance);
    engine.add_live(Arc::clone(&pred_arc)).expect("re-add pred");

    let new_instance = PirInstance::<RavenInspireScheme>::new(
        InstanceId::new(restored[0].instance_id.clone()),
        InstanceRole::Live,
        build_toy_state(),
    );
    let new_arc = Arc::new(new_instance);
    engine.add_live(Arc::clone(&new_arc)).expect("re-add new");

    assert_eq!(engine.instances().len(), 2, "both spawns survived restart");
    assert_eq!(pred_arc.role(), InstanceRole::Live);
    assert_eq!(new_arc.role(), InstanceRole::Live);

    pred_arc.set_role(InstanceRole::Static);
    assert_eq!(
        pred_arc.role(),
        InstanceRole::Static,
        "predecessor role flip is recoverable on the next spawn cycle (idempotent)"
    );
    pred_arc.set_role(InstanceRole::Static);
    assert_eq!(pred_arc.role(), InstanceRole::Static);
    assert_eq!(new_arc.role(), InstanceRole::Live);
}
