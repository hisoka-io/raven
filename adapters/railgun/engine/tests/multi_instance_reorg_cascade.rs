//! Multi-instance reorg cascade closure.
//!
//! Verifies broadcast routing: chain-tree instances see `Reorg` and
//! truncate leaves; PPOI instances are unaffected.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::indexing_slicing
)]

use std::time::Duration;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::{CommitmentLeaf, RailgunEvent};
use raven_railgun_engine::inspire::{setup_state, InspireServerState};
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine_multi, DataSourceFilter, InstanceConfig, OrchestratorChannels,
    PerInstanceHandles, VerificationMode,
};
use raven_railgun_engine::persistence::ConsumerEvent;
use raven_railgun_engine::InstanceRole;
use raven_railgun_indexer::IndexerMessage;
use raven_railgun_persistence::WalEntryPayload;

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-multi-reorg-cascade-test";
const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_SIZE: usize = 256;
const TOY_ENTRIES_PER_SHARD: u32 = 2048;

fn build_toy_state() -> raven_railgun_core::Result<InspireServerState> {
    let params = InspireParams::secure_128_d2048();
    let db: Vec<u8> = (0..TOY_ENTRIES)
        .flat_map(|i| (0..TOY_ENTRY_SIZE).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
        .collect();
    let (state, _sk) = setup_state(&params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking)?;
    Ok(state)
}

fn canonical_commit(seed: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = seed.max(1);
    b
}

fn list_key(seed: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = seed;
    k
}

fn build_three_configs(root: &std::path::Path) -> Vec<InstanceConfig> {
    use raven_railgun_engine::pir_table::EncoderKind;

    let lk_a = list_key(0xA1);

    let mk = |id: &str,
              sub: &str,
              encoder: EncoderKind,
              ds: DataSourceFilter,
              mode: VerificationMode,
              role: InstanceRole|
     -> InstanceConfig {
        InstanceConfig {
            instance_id: raven_railgun_core::InstanceId::new(id),
            role,
            data_dir: root.join(sub),
            encoder,
            record_size: TOY_ENTRY_SIZE,
            entries_per_shard: TOY_ENTRIES_PER_SHARD,
            verification_mode: mode,
            data_source: ds,
            use_flock: false,
            snapshot_policy: raven_railgun_engine::persistence::SnapshotPolicy::default(),
            scheme_tag: SCHEME_TAG.to_owned(),
            channel_capacity: 256,
            max_concurrent_queries: None,
            verification_cadence_n: 0,
            chain_source: None,
        }
    };

    vec![
        mk(
            "tree-0",
            "tree-0",
            EncoderKind::PerLeafBc,
            DataSourceFilter::ChainTreeNumber(0),
            VerificationMode::ChainRootHistory,
            InstanceRole::Live,
        ),
        mk(
            "tree-1",
            "tree-1",
            EncoderKind::PerLeafBc,
            DataSourceFilter::ChainTreeNumber(1),
            VerificationMode::ChainRootHistory,
            InstanceRole::Live,
        ),
        mk(
            "ppoi-list-a",
            "ppoi-a",
            EncoderKind::PerLeafBc,
            DataSourceFilter::PpoiList(lk_a),
            VerificationMode::UpstreamSignature,
            InstanceRole::Live,
        ),
    ]
}

async fn drain_for_apply() {
    tokio::time::sleep(Duration::from_millis(400)).await;
}

async fn shutdown_all(handles: Vec<PerInstanceHandles>, channels: OrchestratorChannels) {
    drop(channels);
    for h in handles {
        let _ = h.sender.send(ConsumerEvent::Shutdown).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), h.consumer).await;
    }
}

struct Parts {
    instances: Vec<PerInstanceHandles>,
    channels: OrchestratorChannels,
    router: tokio::task::JoinHandle<()>,
}

fn split(mh: raven_railgun_engine::orchestrator::MultiOrchestratorHandle) -> Parts {
    let raven_railgun_engine::orchestrator::MultiOrchestratorHandle {
        instances,
        channels,
        router,
        chain_tree_routes: _,
        ppoi_list_routes: _,
        tree_observed: _,
        list_observed: _,
    } = mh;
    Parts {
        instances,
        channels,
        router,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stands up 3 InsPIRe instances; ~5s wall on Zen 5"]
async fn reorg_cascade_truncates_chain_instances_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let configs = build_three_configs(dir.path());
    let lk_a = list_key(0xA1);

    let params = InspireParams::secure_128_d2048();
    let factory = |_cfg: &InstanceConfig| -> raven_railgun_core::Result<InspireServerState> {
        build_toy_state()
    };
    let mh = bootstrap_railgun_engine_multi(configs, params, factory).expect("bootstrap multi");
    assert_eq!(mh.instances.len(), 3);

    for tree in 0u32..2 {
        for i in 0u32..5 {
            let bc =
                canonical_commit(u8::try_from(tree).unwrap_or(0).wrapping_mul(8) + i as u8 + 1);
            mh.channels
                .indexer_tx
                .send(IndexerMessage::Event {
                    event: RailgunEvent::Transact {
                        block_number: 100 + u64::from(i),
                        tx_hash: [0u8; 32],
                        tree_number: tree,
                        start_position: i,
                        leaves: vec![CommitmentLeaf {
                            tree_number: tree,
                            leaf_index: i,
                            commitment_hash: bc,
                            ciphertext: vec![],
                        }],
                    },
                    block_height: 100 + u64::from(i),
                })
                .await
                .expect("send chain event");
        }
    }

    for i in 0u32..3 {
        let bc = canonical_commit(0xA1u8.wrapping_add(i as u8).max(1));
        mh.channels
            .mirror_tx
            .send((
                WalEntryPayload::PpoiListLeafAdded {
                    list_key: lk_a,
                    list_index: i,
                    blinded_commitment: bc,
                    status: 0,
                },
                0,
            ))
            .await
            .expect("send mirror event");
    }

    drain_for_apply().await;

    let mut pre_chain: Vec<(u32, usize)> = Vec::new();
    let mut pre_ppoi: usize = 0;
    for h in &mh.instances {
        let store = h.logical_store.lock();
        match h.config.data_source {
            DataSourceFilter::ChainTreeNumber(t) => {
                pre_chain.push((t, store.imt_leaf_count_for(t)));
            }
            DataSourceFilter::PpoiList(_) => {
                pre_ppoi = store.ppoi_list_leaves_iter(&lk_a).count();
            }
        }
    }
    assert_eq!(pre_chain.len(), 2, "two chain-tree instances seeded");
    assert_eq!(pre_ppoi, 3, "PPOI seeded with 3 leaves");
    for (_t, count) in &pre_chain {
        assert_eq!(*count, 5, "each chain tree should hold 5 leaves pre-reorg");
    }

    mh.channels
        .indexer_tx
        .send(IndexerMessage::Reorg { height: 102 })
        .await
        .expect("send reorg");

    drain_for_apply().await;

    for h in &mh.instances {
        let store = h.logical_store.lock();
        match h.config.data_source {
            DataSourceFilter::ChainTreeNumber(t) => {
                let post = store.imt_leaf_count_for(t);
                assert_eq!(
                    post, 3,
                    "tree-{t} must have 3 leaves post-reorg (heights 100..=102 survive); had {post}"
                );
            }
            DataSourceFilter::PpoiList(lk) => {
                assert_eq!(lk, lk_a, "expected the only PPOI instance to be list-a");
                let post = store.ppoi_list_leaves_iter(&lk_a).count();
                assert_eq!(
                    post, 3,
                    "PPOI list must retain all 3 leaves; chain reorg is not chain-anchored"
                );
            }
        }
    }

    let Parts {
        instances,
        channels,
        router,
    } = split(mh);
    shutdown_all(instances, channels).await;
    router.abort();
}
