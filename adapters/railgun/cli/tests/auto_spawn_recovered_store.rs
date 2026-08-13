//! An auto-spawned consumer restarted from the spawn log must run against the
//! store `bootstrap_inspire_instance` recovered, not a fresh one: the recovered
//! encoded DB and the logical store share a leaf-index contiguity invariant, so
//! a fresh store behind a recovered DB refuses every subsequent append.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use raven_inspire::params::InspireParams;
use raven_railgun_cli::auto_spawn::{data_dir_for_tree, instance_id_for_tree};
use raven_railgun_cli::auto_spawn_driver::{
    pre_spawn_for_tree, replay_spawn_log, AutoSpawnRuntime, SpawnRegistry,
};
use raven_railgun_core::{CommitmentLeaf, InstanceId, RailgunEvent};
use raven_railgun_engine::inspire::RavenInspireScheme;
use raven_railgun_engine::orchestrator::ChainTreeRoutes;
use raven_railgun_engine::persistence::{ConsumerEvent, InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_engine::Engine;
use raven_railgun_persistence::{Manifest, StoreLayout};

/// Per-leaf-bc rows are keyed by global leaf position, so a one-tree cell only
/// hosts tree 0; a higher tree dirties shard ids past the allocated database.
const TREE: u32 = 0;
const ENTRY_BYTES: usize = 32;
const CELL_ROWS: usize = 65_536;
const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-cache-session";
const PRE_RESTART_BLOCK: u64 = 100;
const POST_RESTART_BLOCK: u64 = 200;

fn commitment(leaf_index: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[28..32].copy_from_slice(&(leaf_index + 1).to_be_bytes());
    out
}

fn runtime(tmp: &std::path::Path) -> AutoSpawnRuntime {
    AutoSpawnRuntime {
        data_dir_template: tmp
            .join("auto-tree-{tree_number}")
            .to_string_lossy()
            .into_owned(),
        encoder: "per-leaf-bc".to_owned(),
        scheme_tag: SCHEME_TAG.to_owned(),
        entries: CELL_ROWS,
        entry_bytes: ENTRY_BYTES,
        channel_capacity: 64,
        verification_cadence_n: 0,
        max_instance_count: None,
        cooldown: None,
    }
}

fn shield(leaf_indices: std::ops::Range<u32>, block: u64) -> ConsumerEvent {
    let leaves: Vec<CommitmentLeaf> = leaf_indices
        .map(|leaf_index| CommitmentLeaf {
            tree_number: TREE,
            leaf_index,
            commitment_hash: commitment(leaf_index),
            ciphertext: Vec::new(),
        })
        .collect();
    ConsumerEvent::Chain(
        RailgunEvent::Shield {
            block_number: block,
            tx_hash: [9u8; 32],
            tree_number: TREE,
            start_position: 0,
            leaves,
        },
        block,
    )
}

async fn drain_one_and_run(registry: &Arc<SpawnRegistry>, event: ConsumerEvent) {
    let mut handles = registry.drain_auto_spawned();
    assert_eq!(handles.len(), 1, "exactly one auto-spawned consumer");
    let handle = handles.remove(0);
    handle
        .consumer_sender
        .send(event)
        .await
        .expect("send chain event");
    // Shutdown drives the final commit, so the join point is also the durability point.
    handle
        .consumer_sender
        .send(ConsumerEvent::Shutdown)
        .await
        .expect("send shutdown");
    handle.consumer_join.await.expect("consumer task joined");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawn_log_restart_appends_onto_the_recovered_leaf_prefix() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::ERROR)
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let params = InspireParams::secure_128_d2048();
    let rt = runtime(tmp.path());
    let data_dir = data_dir_for_tree(&rt.data_dir_template, TREE);

    {
        let engine: Arc<Engine<RavenInspireScheme>> = Arc::new(Engine::new());
        let routes: ChainTreeRoutes = Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new()));
        let registry = Arc::new(SpawnRegistry::new());
        let spawned = pre_spawn_for_tree(
            &rt,
            &params,
            &engine,
            &routes,
            &registry,
            tmp.path().to_path_buf(),
            None,
            TREE,
        )
        .expect("pre_spawn_for_tree");
        assert!(spawned, "tree {TREE} must spawn");
        drain_one_and_run(&registry, shield(0..3, PRE_RESTART_BLOCK)).await;
    }

    {
        let engine: Arc<Engine<RavenInspireScheme>> = Arc::new(Engine::new());
        let routes: ChainTreeRoutes = Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new()));
        let registry = Arc::new(SpawnRegistry::new());
        let restored = replay_spawn_log(
            &rt,
            &params,
            &engine,
            &routes,
            &registry,
            tmp.path().to_path_buf(),
            None,
        )
        .expect("replay_spawn_log");
        assert_eq!(
            restored,
            vec![TREE],
            "the spawn log record written before the restart must restore tree {TREE}"
        );
        drain_one_and_run(&registry, shield(3..4, POST_RESTART_BLOCK)).await;
    }

    let manifest = Manifest::load(&StoreLayout::open(&data_dir).expect("layout"))
        .expect("manifest load")
        .expect("manifest present after two runs");
    assert_eq!(
        manifest.current_marker, POST_RESTART_BLOCK,
        "the post-restart leaf must have been applied and committed; a marker \
         still at {PRE_RESTART_BLOCK} means the append was refused and the \
         indexer resume floor never advanced"
    );

    let encoder: Arc<dyn PirTableEncoder> = EncoderKind::PerLeafBc { tree_number: 0 }
        .build(
            ENTRY_BYTES,
            u32::try_from(params.ring_dim).expect("ring_dim fits u32"),
        )
        .expect("build encoder");
    let reopened = InspirePersistence::open(
        StoreLayout::open(&data_dir).expect("layout reopen"),
        SCHEME_TAG,
        InstanceId::new(instance_id_for_tree(TREE)),
        SnapshotPolicy::default(),
        encoder,
    )
    .expect("reopen after the restart run");
    assert_eq!(
        reopened.recovered_logical_store.imt_leaf_count_for(TREE),
        4,
        "leaves 0..=2 from the first run plus leaf 3 from the restart; 3 means \
         the restart ran against a fresh store and dropped leaf 3 permanently"
    );
}
