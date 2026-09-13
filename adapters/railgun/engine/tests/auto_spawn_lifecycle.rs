//! Engine-level auto-spawn lifecycle tests (no CLI driver task).

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use raven_inspire::params::InspireParams;
use raven_railgun_core::{CommitmentLeaf, InstanceId, RailgunEvent};
use raven_railgun_engine::inspire::{InspireServerState, RavenInspireScheme};
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine_multi, DataSourceFilter, InstanceConfig, VerificationMode,
};
use raven_railgun_engine::persistence::{ConsumerEvent, SnapshotPolicy};
use raven_railgun_engine::pir_table::EncoderKind;
use raven_railgun_engine::{InstanceRole, PirInstance};
use raven_railgun_indexer::IndexerMessage;

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-cache-session";
const TOY_ENTRY_SIZE: usize = 256;
const TOY_ENTRIES_PER_SHARD: u32 = 2048;

fn build_toy_state() -> raven_railgun_core::Result<InspireServerState> {
    raven_railgun_testkit::try_toy_state(TOY_ENTRY_SIZE)
}

fn commit_tree_cfg(
    id: &str,
    dir: std::path::PathBuf,
    t: u32,
    role: InstanceRole,
) -> InstanceConfig {
    InstanceConfig {
        instance_id: InstanceId::new(id),
        role,
        data_dir: dir,
        encoder: EncoderKind::PerLeafBc { tree_number: 0 },
        record_size: TOY_ENTRY_SIZE,
        entries_per_shard: TOY_ENTRIES_PER_SHARD,
        verification_mode: VerificationMode::ChainRootHistory,
        data_source: DataSourceFilter::ChainTreeNumber(t),
        use_flock: false,
        snapshot_policy: SnapshotPolicy::default(),
        scheme_tag: SCHEME_TAG.to_owned(),
        channel_capacity: 256,
        max_concurrent_queries: None,
        verification_cadence_n: 0,
        chain_source: None,
    }
}

fn shield_event(tree: u32, leaf: u32) -> RailgunEvent {
    let mut commitment = [0u8; 32];
    commitment[..4].copy_from_slice(&leaf.to_be_bytes());
    RailgunEvent::Shield {
        block_number: u64::from(leaf) + 100,
        tx_hash: [0u8; 32],
        tree_number: tree,
        start_position: leaf,
        leaves: vec![CommitmentLeaf {
            tree_number: tree,
            leaf_index: leaf,
            commitment_hash: commitment,
            ciphertext: Vec::new(),
        }],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn synthetic_chain_drives_auto_spawn_to_tree_n_plus_one() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfgs = vec![commit_tree_cfg(
        "tree-0",
        tmp.path().join("tree-0"),
        0,
        InstanceRole::Live,
    )];
    let params = InspireParams::secure_128_d2048();
    let mut handle =
        bootstrap_railgun_engine_multi(cfgs, params, |_| build_toy_state()).expect("bootstrap");
    let mut observer = handle.tree_observed.subscribe();
    handle
        .channels
        .indexer_tx
        .send(IndexerMessage::Event {
            event: shield_event(1, 0),
            block_height: 200,
        })
        .await
        .ok();
    let next = tokio::time::timeout(std::time::Duration::from_secs(2), observer.recv())
        .await
        .expect("tap fires within 2s")
        .expect("broadcast value");
    assert_eq!(next, 1, "tree_observed surfaces the new tree number");
    drop(handle.channels);
    for h in handle.instances.drain(..) {
        let _ = h.sender.send(ConsumerEvent::Shutdown).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), h.consumer).await;
    }
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle.router).await;
}

/// Named for what it proves: the role flip is performed BY HAND here, and the
/// static-default policy values are pinned against literals. The spawn-driven
/// demotion itself (auto_spawn_driver's flip_predecessor_to_static) lives in the
/// cli crate, which this binary does not link; its coverage is the in-src test
/// `registry_seed_then_flip_marks_predecessor_static` in the cli package.
#[tokio::test]
async fn manual_role_flip_works_and_static_default_policy_is_pinned() {
    let live_state = build_toy_state().expect("toy");
    let inst = Arc::new(PirInstance::<RavenInspireScheme>::new(
        InstanceId::new("commit-tree-0"),
        InstanceRole::Live,
        live_state,
    ));
    assert_eq!(inst.role(), InstanceRole::Live);
    inst.set_role(InstanceRole::Static);
    assert_eq!(inst.role(), InstanceRole::Static);

    let tmp = tempfile::tempdir().expect("tempdir");
    let layout = raven_railgun_persistence::StoreLayout::open(tmp.path()).expect("layout");
    let encoder: Arc<dyn raven_railgun_engine::pir_table::PirTableEncoder> =
        EncoderKind::PerLeafBc { tree_number: 0 }
            .build(TOY_ENTRY_SIZE, TOY_ENTRIES_PER_SHARD)
            .expect("enc");
    let opened = raven_railgun_engine::persistence::InspirePersistence::open(
        layout,
        SCHEME_TAG,
        InstanceId::new("commit-tree-0"),
        SnapshotPolicy::default(),
        encoder,
    )
    .expect("open");
    let pers = opened.persistence;
    let before = pers.snapshot_policy();
    assert_eq!(before.max_appends_per_snapshot, 1000);
    assert_eq!(before.max_seconds_between_snapshots, 300);

    pers.set_snapshot_policy(SnapshotPolicy::static_default());
    let after = pers.snapshot_policy();
    // Pinned against literals, not against `static_default()` itself: comparing the
    // getter to the same constructor the setter was handed is an oracle the code under
    // test builds, and any pair of values at all satisfies it.
    assert_eq!(
        after.max_appends_per_snapshot,
        usize::MAX,
        "a static commit tree must be snapshot-once: an append budget below usize::MAX \
         puts a sealed tree back on the per-append snapshot cadence"
    );
    assert_eq!(
        after.max_seconds_between_snapshots,
        u64::MAX,
        "a static commit tree must not snapshot on a timer either"
    );
    assert_eq!(after.retention.archived_wals_retain, 4);
    assert_eq!(after.retention.snapshots_retain, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn five_tree_progression_full_lifecycle() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfgs = vec![commit_tree_cfg(
        "tree-0",
        tmp.path().join("tree-0"),
        0,
        InstanceRole::Live,
    )];
    let params = InspireParams::secure_128_d2048();
    let mut handle =
        bootstrap_railgun_engine_multi(cfgs, params, |_| build_toy_state()).expect("bootstrap");

    let mut receivers: Vec<(u32, tokio::sync::mpsc::Receiver<ConsumerEvent>)> = Vec::new();
    for t in 1u32..=4 {
        let (tx, rx) = tokio::sync::mpsc::channel::<ConsumerEvent>(64);
        receivers.push((t, rx));
        handle.chain_tree_routes.rcu(|cur| {
            let mut next: Vec<(u32, tokio::sync::mpsc::Sender<ConsumerEvent>)> = (**cur).clone();
            next.push((t, tx.clone()));
            next
        });
    }
    for t in 1u32..=4 {
        handle
            .channels
            .indexer_tx
            .send(IndexerMessage::Event {
                event: shield_event(t, t),
                block_height: u64::from(t) + 200,
            })
            .await
            .expect("send");
    }

    for (t, mut rx) in receivers.drain(..) {
        let got = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("tree {t} consumer did not receive within 3s"))
            .unwrap_or_else(|| panic!("tree {t} consumer channel closed"));
        match got {
            ConsumerEvent::Chain(RailgunEvent::Shield { tree_number, .. }, _) => {
                assert_eq!(tree_number, t, "router routed event to correct receiver");
            }
            other => panic!("tree {t}: expected Chain Shield, got {other:?}"),
        }
    }

    drop(handle.channels);
    for h in handle.instances.drain(..) {
        let _ = h.sender.send(ConsumerEvent::Shutdown).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), h.consumer).await;
    }
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle.router).await;
}
