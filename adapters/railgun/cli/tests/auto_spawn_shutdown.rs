//! CLI-level tests: auto-spawned consumers receive `ConsumerEvent::Shutdown` on graceful exit,
//! and a stop whose final commit fails is the serve loop's error.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::indexing_slicing
)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use raven_railgun_cli::auto_spawn::load_spawn_log;
use raven_railgun_cli::serve_production_multi::{
    run_with_listener, AutoSpawnConfigToml, BootstrapObserver, BootstrapView, MultiServeOptions,
};
use raven_railgun_core::{CommitmentLeaf, InstanceId, RailgunEvent};
use raven_railgun_engine::orchestrator::{DataSourceFilter, InstanceConfig};
use raven_railgun_engine::persistence::SnapshotPolicy;
use raven_railgun_engine::pir_table::EncoderKind;
use raven_railgun_engine::InstanceRole;
use raven_railgun_indexer::IndexerMessage;
use raven_railgun_persistence::{Manifest, SnapshotId, StoreLayout};
use tokio::sync::oneshot;

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-v1";
const TOY_ENTRY_BYTES: usize = 256;

/// Rows every per-leaf-bc cell here must hold - the bootstrap instance as well as the spawned one.
///
/// Distinct from the harness's own bootstrap fixture size. Every leaf-keyed
/// encoder declares `min_total_entries() == LEAVES_PER_TREE`, and `pre_spawn_for_tree` enforces it
/// (`auto_spawn_driver.rs`). A spawn requested at 256 rows is refused, the successor never appears,
/// and the test times out waiting for a count that can never rise - which is what nine of these
/// tests were doing.
const AUTO_SPAWN_CELL_ROWS: usize = 65_536;

fn shield_event(tree: u32, leaf: u32, height: u64) -> IndexerMessage {
    let mut commitment = [0u8; 32];
    commitment[..4].copy_from_slice(&leaf.to_be_bytes());
    commitment[31] = u8::try_from(tree.min(255)).unwrap_or(255);
    IndexerMessage::Event {
        event: RailgunEvent::Shield {
            block_number: height,
            tx_hash: [0u8; 32],
            tree_number: tree,
            start_position: leaf,
            leaves: vec![CommitmentLeaf {
                tree_number: tree,
                leaf_index: leaf,
                commitment_hash: commitment,
                ciphertext: Vec::new(),
            }],
        },
        block_height: height,
    }
}

fn bootstrap_tree_zero_cfg(data_dir: PathBuf) -> InstanceConfig {
    InstanceConfig {
        instance_id: InstanceId::new("commit-tree-0"),
        role: InstanceRole::Live,
        data_dir,
        encoder: EncoderKind::PerLeafBc { tree_number: 0 },
        record_size: TOY_ENTRY_BYTES,
        // Must equal ring_dim: one entry per ring coefficient is the shard geometry the PIR
        // scheme assumes, and 65_536 / 2_048 = 32 shards.
        entries_per_shard: 2_048,
        data_source: DataSourceFilter::ChainTreeNumber(0),
        use_flock: false,
        snapshot_policy: SnapshotPolicy::default(),
        scheme_tag: SCHEME_TAG.to_owned(),
        channel_capacity: 256,
        max_concurrent_queries: None,
        verification_cadence_n: 0,
        chain_source: None,
    }
}

/// Wait for bootstrap, and surface the server's error instead of a timeout if it failed.
///
/// The observer is populated immediately after `bootstrap_instances(..)?` and is not gated by
/// `skip_chain_workers`, so "never populated" means bootstrap RETURNED AN ERROR - and the server
/// runs in a spawned task whose `Result` nothing reads. The previous version polled for 180 s and
/// then reported the empty observer, discarding the cause. That is a symptom masking a diagnosis:
/// the run takes three minutes to tell you nothing.
async fn wait_for_observer(
    observer: &BootstrapObserver,
    server: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
) -> BootstrapView {
    for _ in 0..3600u32 {
        if let Some(view) = observer.lock().clone() {
            return view;
        }
        // If the server has already finished, bootstrap failed. Say what it said.
        if server.is_finished() {
            match server.await {
                Ok(Ok(())) => panic!(
                    "server returned Ok before the bootstrap observer was populated; \
                     bootstrap completed without publishing a view"
                ),
                Ok(Err(e)) => panic!("bootstrap failed: {e:#}"),
                Err(join) => panic!("server task panicked during bootstrap: {join}"),
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "bootstrap observer never populated within 180s and the server is still running; \
         bootstrap is hung rather than failed"
    );
}

async fn wait_for_data_dir(path: &std::path::Path, deadline: Duration) {
    let started = tokio::time::Instant::now();
    while started.elapsed() < deadline {
        if path.is_dir() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("auto-spawn data_dir {} never appeared", path.display());
}

async fn wait_for_manifest(path: &std::path::Path, deadline: Duration) {
    let started = tokio::time::Instant::now();
    while started.elapsed() < deadline {
        if path.is_file() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("auto-spawn manifest {} never appeared", path.display());
}

async fn wait_for_snapshot_dir(data_dir: &std::path::Path, id: u64, deadline: Duration) {
    let snap_dir = data_dir.join("snapshots").join(format!("snap-{id:06}"));
    let started = tokio::time::Instant::now();
    while started.elapsed() < deadline {
        if snap_dir.is_dir() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "snapshot dir {} never appeared (bootstrap commit may have failed)",
        snap_dir.display()
    );
}

/// The spawn record is appended only after the consumer handle is registered for the
/// shutdown drain. The snapshot dir appears seconds earlier, mid-bootstrap.
async fn wait_for_spawn_record(registry_dir: &std::path::Path, tree: u32, deadline: Duration) {
    let started = tokio::time::Instant::now();
    while started.elapsed() < deadline {
        let records = load_spawn_log(registry_dir).expect("load spawn log");
        if records.iter().any(|record| record.tree_number == tree) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("auto-spawn of tree {tree} never reached the spawn log");
}

/// Bytes in the instance's live WAL segment; zero before the first append.
fn wal_len(data_dir: &std::path::Path) -> u64 {
    let layout = StoreLayout::open(data_dir).expect("open StoreLayout");
    std::fs::metadata(layout.wal_current_path()).map_or(0, |meta| meta.len())
}

/// Gives a spawned instance a leaf and waits for its WAL append, so the Shutdown queued behind
/// it in the same channel has something to drain.
async fn apply_one_leaf(
    chain: &tokio::sync::mpsc::Sender<IndexerMessage>,
    data_dir: &std::path::Path,
    tree: u32,
    height: u64,
) {
    let before = wal_len(data_dir);
    chain
        .send(shield_event(tree, 0, height))
        .await
        .expect("send leaf to the spawned instance");
    let started = tokio::time::Instant::now();
    while wal_len(data_dir) <= before {
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "tree {tree}'s spawned instance never appended its first leaf"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

// The spawn writes snap-000001; a stop with something to drain adds snap-000002.
fn count_snapshots(data_dir: &std::path::Path) -> usize {
    let snap_dir = data_dir.join("snapshots");
    if !snap_dir.is_dir() {
        return 0;
    }
    std::fs::read_dir(&snap_dir)
        .expect("read snapshots dir")
        .filter_map(std::result::Result::ok)
        .filter(|de| de.file_name().to_string_lossy().starts_with("snap-"))
        .count()
}

/// Every option that the stop tests leave at its default.
fn serve_options(
    bind: SocketAddr,
    instances: Vec<InstanceConfig>,
    observer: &BootstrapObserver,
    auto_spawn: Option<AutoSpawnConfigToml>,
) -> MultiServeOptions {
    MultiServeOptions {
        bind,
        token: "auto-spawn-shutdown-test-token-pad".to_owned(),
        rpc_url: "http://127.0.0.1:1".to_owned(),
        railgun_proxy: "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9".to_owned(),
        chain_id: 1,
        start_block: 0,
        mirror_endpoint: "http://127.0.0.1:1".to_owned(),
        mirror_backfill_interval_secs: None,
        max_concurrent_queries: 4,
        respond_timeout_secs: 30,
        instances,
        skip_chain_workers: true,
        skip_mirror_workers: true,
        entries: AUTO_SPAWN_CELL_ROWS,
        instance_entries: std::collections::HashMap::new(),
        bootstrap_observer: Some(Arc::clone(observer)),
        auto_spawn,
        rpc_pool: None,
        instance_templates: vec![],
        tree_fill_threshold: None,
        reload_config_path: None,
        ws_endpoint: None,
        rate_limit_rps: None,
        rate_limit_burst: None,
        cors_allowed_origins: None,
        trust_proxy_header: None,
        trusted_proxy_cidrs: None,
        metrics_public: None,
        session_eviction_interval_secs: None,
        respond_permit_wait_ms: None,
        reorg_window_path: None,
        session_capacity: raven_railgun_cli::serve_production_multi::SessionCapacity::default(),
    }
}

/// A final commit that cannot be written is the serve loop's error, so the process exits
/// non-zero, and the manifest keeps naming the snapshot it named before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_final_commit_is_the_serve_loops_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .expect("bind ephemeral");
    let data_dir = tmp.path().join("commit-tree-0");
    let observer: BootstrapObserver = Arc::new(parking_lot::Mutex::new(None));
    let opts = serve_options(
        bind,
        vec![bootstrap_tree_zero_cfg(data_dir.clone())],
        &observer,
        None,
    );

    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let mut server = tokio::spawn(async move {
        run_with_listener(opts, listener, async move {
            let _ = stop_rx.await;
        })
        .await
    });
    let view = wait_for_observer(&observer, &mut server).await;
    apply_one_leaf(&view.channels.indexer_tx, &data_dir, 0, 150).await;

    // A file where the next snapshot is staged: the save fails for any user, root included.
    let layout = StoreLayout::open(&data_dir).expect("open StoreLayout");
    let before = Manifest::load(&layout)
        .expect("load manifest")
        .expect("bootstrap manifest")
        .current_snapshot_id;
    let staged = layout.snapshot_dir(before.next()).with_extension("tmp");
    std::fs::write(&staged, b"not a directory").expect("plant the staging path");

    let _ = stop_tx.send(());
    let outcome = tokio::time::timeout(Duration::from_secs(60), server)
        .await
        .expect("serve loop must return within the stop budget")
        .expect("serve task join");
    let error = outcome.expect_err("a failed final commit must fail the stop");
    let message = error.to_string();
    assert!(
        message.contains("stop incomplete") && message.contains("and 1 failed"),
        "{message}"
    );

    let after = Manifest::load(&layout)
        .expect("load manifest")
        .expect("manifest")
        .current_snapshot_id;
    assert_eq!(after, before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "~7 s per PIR instance stood up, ~99% of it PackParams::try_new (the deterministic \
            d=2048 packing table) built twice per setup_state; the keygen proper is ~60 ms. \
            Trigger: changing SIGTERM drain for auto-spawned consumers."]
async fn auto_spawned_consumers_drain_wal_on_sigterm() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let tmp = tempfile::tempdir().expect("tempdir");
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .expect("bind ephemeral");

    let bootstrap_dir = tmp.path().join("commit-tree-0");
    let auto_spawn_template = tmp
        .path()
        .join("auto-tree-{tree_number}")
        .to_string_lossy()
        .into_owned();

    let observer: BootstrapObserver = Arc::new(parking_lot::Mutex::new(None));

    let opts = serve_options(
        bind,
        vec![bootstrap_tree_zero_cfg(bootstrap_dir)],
        &observer,
        Some(AutoSpawnConfigToml {
            enabled: true,
            data_dir_template: auto_spawn_template,
            encoder: "per-leaf-bc".to_owned(),
            scheme_tag: SCHEME_TAG.to_owned(),
            entries: AUTO_SPAWN_CELL_ROWS,
            entry_bytes: TOY_ENTRY_BYTES,
            max_instance_count: None,
            cooldown_seconds: None,
        }),
    );

    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let mut server = tokio::spawn(async move {
        run_with_listener(opts, listener, async move {
            let _ = stop_rx.await;
        })
        .await
    });

    let view = wait_for_observer(&observer, &mut server).await;
    let chain = view.channels.indexer_tx.clone();

    // Gate each spawn on its spawn record: the data dir and snap-000001 both appear
    // before the handle is registered, and a stop sent in that window drains nothing.
    let tree1_dir = tmp.path().join("auto-tree-1");
    let tree2_dir = tmp.path().join("auto-tree-2");

    chain
        .send(shield_event(1, 0, 100))
        .await
        .expect("send tree-1 shield (auto-spawn trigger)");
    wait_for_data_dir(&tree1_dir, Duration::from_secs(180)).await;
    wait_for_snapshot_dir(&tree1_dir, 1, Duration::from_secs(180)).await;
    wait_for_spawn_record(tmp.path(), 1, Duration::from_secs(180)).await;
    apply_one_leaf(&chain, &tree1_dir, 1, 150).await;

    chain
        .send(shield_event(2, 0, 200))
        .await
        .expect("send tree-2 shield (auto-spawn trigger)");
    wait_for_data_dir(&tree2_dir, Duration::from_secs(180)).await;
    wait_for_snapshot_dir(&tree2_dir, 1, Duration::from_secs(180)).await;
    wait_for_spawn_record(tmp.path(), 2, Duration::from_secs(180)).await;

    let _ = stop_tx.send(());

    tokio::time::timeout(Duration::from_secs(60), server)
        .await
        .expect("serve loop must return within shutdown timeout (no deadlock)")
        .expect("serve task join")
        .expect("serve loop returned Ok");

    // Tree 1 applied a leaf after its spawn commit, so its stop commits it. Tree 2 applied
    // nothing, and a stop with nothing to publish writes no snapshot.
    for (tree_dir, snapshots) in [(&tree1_dir, 2), (&tree2_dir, 1)] {
        let layout = StoreLayout::open(tree_dir).expect("open StoreLayout");
        wait_for_manifest(&layout.manifest_path(), Duration::from_secs(5)).await;

        assert_eq!(
            u64::try_from(count_snapshots(tree_dir)).expect("snapshot count"),
            snapshots,
            "snapshots at {} after the stop",
            tree_dir.display(),
        );
        let manifest = Manifest::load(&layout)
            .expect("load manifest")
            .unwrap_or_else(|| panic!("no manifest at {}", tree_dir.display()));
        assert_eq!(
            manifest.current_snapshot_id,
            SnapshotId(snapshots),
            "manifest at {}",
            tree_dir.display(),
        );

        let wal_floor = manifest.current_snapshot_seq.checked_sub(1);
        let wal = raven_railgun_persistence::Wal::open(&layout, wal_floor).expect("reopen wal");
        let replay = wal.replay().expect("replay wal");
        let unreplayed: Vec<u64> = replay
            .entries
            .iter()
            .filter(|e| e.seq >= manifest.current_snapshot_seq)
            .map(|e| e.seq)
            .collect();
        assert!(
            unreplayed.is_empty(),
            "auto-spawned instance at {} has {} WAL entries past the \
             snapshot floor (current_snapshot_seq={}, unreplayed seqs={:?}); \
             the Shutdown-arm drive_commit did not advance the snapshot \
             past every applied event.",
            tree_dir.display(),
            unreplayed.len(),
            manifest.current_snapshot_seq,
            unreplayed,
        );
    }
}
