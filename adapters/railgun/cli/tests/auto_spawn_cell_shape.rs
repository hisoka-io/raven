//! Auto-spawn at the production cell shape.
//!
//! `LEAVES` exceeds `ring_dim` so the oracle window spans slots 0 and 1: a
//! per-shard row count below `ring_dim` under-fills slot 0 and shifts every later
//! row, which a window confined to one shard's prefix cannot see.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use std::sync::Arc;
use std::time::Duration;

use raven_inspire::params::InspireParams;
use raven_railgun_cli::auto_spawn::instance_id_for_tree;
use raven_railgun_cli::auto_spawn_driver::{pre_spawn_for_tree, AutoSpawnRuntime, SpawnRegistry};
use raven_railgun_core::{CommitmentLeaf, InstanceId, RailgunEvent};
use raven_railgun_engine::inspire::RavenInspireScheme;
use raven_railgun_engine::orchestrator::ChainTreeRoutes;
use raven_railgun_engine::persistence::ConsumerEvent;
use raven_railgun_engine::Engine;

const CELL_ROWS: usize = 131_072;
const ENTRY_BYTES: usize = 32;
const TREE: u32 = 1;
const LEAVES: u32 = 2_100;
const COMMIT_DEADLINE: Duration = Duration::from_secs(120);
/// Byte pair 30..32 of a commitment is 16-bit column 15 of its row.
const TAGGED_COLUMN: usize = 15;

fn commitment(leaf: u32) -> [u8; 32] {
    let tag = leaf + 1;
    let mut out = [0u8; 32];
    out[30] = ((tag >> 8) & 0xff) as u8;
    out[31] = (tag & 0xff) as u8;
    out
}

fn tagged_column_value(leaf: u32) -> u64 {
    let c = commitment(leaf);
    u64::from(c[30]) | (u64::from(c[31]) << 8)
}

/// Rows past `leaf_count` hold the IMT empty-subtree constant, not zero, so only a
/// slot's populated prefix is a row-identity oracle.
fn assert_slot_carries_leaves(
    coeffs: &[u64],
    shard_id: u32,
    leaves: std::ops::Range<u32>,
    rows_per_shard: u32,
) {
    for leaf in leaves {
        let row = leaf - shard_id * rows_per_shard;
        assert_eq!(
            coeffs[row as usize],
            tagged_column_value(leaf),
            "slot {shard_id} row {row} must carry leaf {leaf}'s commitment: global row \
             {leaf} / {rows_per_shard} selects shard {shard_id}"
        );
    }
}

fn runtime(tmp: &std::path::Path) -> AutoSpawnRuntime {
    AutoSpawnRuntime {
        data_dir_template: tmp
            .join("auto-tree-{tree_number}")
            .to_string_lossy()
            .into_owned(),
        encoder: "per-node".to_owned(),
        scheme_tag: "raven-inspire-twopacking-inspiring-wp3-cache-session".to_owned(),
        entries: CELL_ROWS,
        entry_bytes: ENTRY_BYTES,
        channel_capacity: 64,
        verification_cadence_n: 0,
        max_instance_count: None,
        cooldown: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawned_instance_re_encodes_slot_zero_with_first_window_rows() {
    // The consumer swallows a failed commit into a tracing line, so surface it.
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::ERROR)
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let params = InspireParams::secure_128_d2048();
    let engine: Arc<Engine<RavenInspireScheme>> = Arc::new(Engine::new());
    let chain_tree_routes: ChainTreeRoutes = Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new()));
    let registry = Arc::new(SpawnRegistry::new());
    let rt = runtime(tmp.path());

    let spawned = pre_spawn_for_tree(
        &rt,
        &params,
        &engine,
        &chain_tree_routes,
        &registry,
        tmp.path().to_path_buf(),
        None,
        TREE,
    )
    .expect("pre_spawn_for_tree");
    assert!(spawned, "tree {TREE} must spawn");

    let instance_id = InstanceId::new(instance_id_for_tree(TREE));
    let instance = engine
        .instance(&instance_id)
        .expect("spawned instance registered with the engine");
    assert_eq!(
        instance.current_state().shard_config().entries_per_shard(),
        params.ring_dim as u64,
        "a shard holds exactly ring_dim rows"
    );

    let leaves: Vec<CommitmentLeaf> = (0..LEAVES)
        .map(|leaf| CommitmentLeaf {
            tree_number: TREE,
            leaf_index: leaf,
            commitment_hash: commitment(leaf),
            ciphertext: Vec::new(),
        })
        .collect();
    let event = RailgunEvent::Shield {
        block_number: 100,
        tx_hash: [7u8; 32],
        tree_number: TREE,
        start_position: 0,
        leaves,
    };

    let mut handles = registry.drain_auto_spawned();
    assert_eq!(handles.len(), 1, "one auto-spawned consumer");
    let handle = handles.remove(0);
    handle
        .consumer_sender
        .send(ConsumerEvent::Chain(event, 100))
        .await
        .expect("send shield event");

    let started = tokio::time::Instant::now();
    while instance.current_epoch() == raven_railgun_core::Epoch::ZERO {
        assert!(
            started.elapsed() < COMMIT_DEADLINE,
            "instance never advanced past Epoch::ZERO: the commit that re-encodes the \
             dirty shards never succeeded"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Quiesce before the tempdir drops, else a commit races the directory removal.
    handle
        .consumer_sender
        .send(ConsumerEvent::Shutdown)
        .await
        .expect("send shutdown");
    handle.consumer_join.await.expect("consumer task joined");

    let state = instance.current_state();
    let rows_per_shard = u32::try_from(params.ring_dim).expect("ring_dim fits u32");
    assert!(
        LEAVES > rows_per_shard,
        "LEAVES {LEAVES} must exceed rows_per_shard {rows_per_shard} or the oracle window \
         never crosses a shard boundary and any per-shard row count below {rows_per_shard} \
         still satisfies it"
    );
    let tagged_column = |shard_id: u32| -> Vec<u64> {
        state
            .encoded_db
            .shards
            .iter()
            .find(|s| s.id == shard_id)
            .unwrap_or_else(|| panic!("shard {shard_id} present"))
            .polynomials[TAGGED_COLUMN]
            .coeffs()
            .to_vec()
    };

    assert_slot_carries_leaves(&tagged_column(0), 0, 0..rows_per_shard, rows_per_shard);
    assert_slot_carries_leaves(&tagged_column(1), 1, rows_per_shard..LEAVES, rows_per_shard);
}
