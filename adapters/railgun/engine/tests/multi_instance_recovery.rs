//! Multi-instance bootstrap routing + recovery tests.
//!
//! `#[ignore]`-gated; each test stands up six InsPIRe instances and
//! only runs in the production-cell sweep.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::indexing_slicing,
    clippy::map_unwrap_or
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

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-multi-instance-test";
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

fn build_six_configs(root: &std::path::Path) -> Vec<InstanceConfig> {
    use raven_railgun_engine::pir_table::EncoderKind;

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

    let lk_a = list_key(0xA1);
    let lk_b = list_key(0xB2);
    vec![
        mk(
            "tree-0",
            "tree-0",
            raven_railgun_engine::pir_table::EncoderKind::PerLeafBc,
            DataSourceFilter::ChainTreeNumber(0),
            VerificationMode::ChainRootHistory,
            InstanceRole::Static,
        ),
        mk(
            "tree-1",
            "tree-1",
            raven_railgun_engine::pir_table::EncoderKind::PerLeafBc,
            DataSourceFilter::ChainTreeNumber(1),
            VerificationMode::ChainRootHistory,
            InstanceRole::Static,
        ),
        mk(
            "tree-2",
            "tree-2",
            raven_railgun_engine::pir_table::EncoderKind::PerLeafBc,
            DataSourceFilter::ChainTreeNumber(2),
            VerificationMode::ChainRootHistory,
            InstanceRole::Static,
        ),
        mk(
            "tree-3-live",
            "tree-3",
            raven_railgun_engine::pir_table::EncoderKind::PerLeafBc,
            DataSourceFilter::ChainTreeNumber(3),
            VerificationMode::ChainRootHistory,
            InstanceRole::Live,
        ),
        mk(
            "ppoi-list-a",
            "ppoi-a",
            raven_railgun_engine::pir_table::EncoderKind::PerLeafBc,
            DataSourceFilter::PpoiList(lk_a),
            VerificationMode::UpstreamSignature,
            InstanceRole::Live,
        ),
        mk(
            "ppoi-list-b",
            "ppoi-b",
            raven_railgun_engine::pir_table::EncoderKind::PerLeafBc,
            DataSourceFilter::PpoiList(lk_b),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stands up 6 InsPIRe instances; ~7s wall on Zen 5"]
async fn multi_instance_bootstrap_routes_events_per_instance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let configs = build_six_configs(dir.path());

    let lk_a = list_key(0xA1);
    let lk_b = list_key(0xB2);
    let params = InspireParams::secure_128_d2048();

    let factory = |_cfg: &InstanceConfig| -> raven_railgun_core::Result<InspireServerState> {
        build_toy_state()
    };
    let mh = bootstrap_railgun_engine_multi(configs, params, factory).expect("bootstrap multi");

    assert_eq!(mh.instances.len(), 6);

    let planted_tree2 = canonical_commit(0x07);
    let chain_event = RailgunEvent::Transact {
        block_number: 100,
        tx_hash: [0u8; 32],
        tree_number: 2,
        start_position: 0,
        leaves: vec![CommitmentLeaf {
            tree_number: 2,
            leaf_index: 0,
            commitment_hash: planted_tree2,
            ciphertext: vec![],
        }],
    };
    mh.channels
        .indexer_tx
        .send(IndexerMessage::Event {
            event: chain_event,
            block_height: 100,
        })
        .await
        .expect("send indexer event");

    let planted_bc_a = canonical_commit(0x09);
    let ppoi_payload = WalEntryPayload::PpoiListLeafAdded {
        list_key: lk_a,
        list_index: 0,
        blinded_commitment: planted_bc_a,
        status: 0,
    };
    mh.channels
        .mirror_tx
        .send((ppoi_payload, 0))
        .await
        .expect("send mirror event");

    drain_for_apply().await;

    for h in &mh.instances {
        let store = h.logical_store.lock();
        match h.config.data_source {
            DataSourceFilter::ChainTreeNumber(2) => {
                assert_eq!(
                    store.leaf(2, 0).copied(),
                    Some(planted_tree2),
                    "tree-2 instance should have the planted leaf"
                );
            }
            DataSourceFilter::ChainTreeNumber(t) => {
                assert!(
                    store.leaf(t, 0).is_none(),
                    "tree-{t} instance must NOT see tree-2 leaf"
                );
            }
            DataSourceFilter::PpoiList(_) => {
                assert!(
                    store.leaves_iter().next().is_none(),
                    "PPOI instance must NOT see chain leaves"
                );
            }
        }
    }

    for h in &mh.instances {
        let store = h.logical_store.lock();
        match h.config.data_source {
            DataSourceFilter::PpoiList(k) if k == lk_a => {
                assert_eq!(
                    store.ppoi_bc_at(&lk_a, 0),
                    Some(planted_bc_a),
                    "ppoi-list-a instance should have the planted PPOI leaf"
                );
            }
            DataSourceFilter::PpoiList(k) if k == lk_b => {
                assert!(
                    store.ppoi_bc_at(&lk_b, 0).is_none(),
                    "ppoi-list-b instance must NOT see list-a leaf"
                );
            }
            DataSourceFilter::PpoiList(_) | DataSourceFilter::ChainTreeNumber(_) => {
                assert_eq!(
                    store.ppoi_count(),
                    0,
                    "non-list-a instance must have empty PPOI store"
                );
            }
        }
    }

    let MultiOrchestratorHandleParts {
        instances,
        channels,
        router,
    } = split_handle(mh);
    shutdown_all(instances, channels).await;
    router.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "6 instances + restart cycle; ~14s wall on Zen 5"]
async fn multi_instance_recovery_byte_identity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let lk_a = list_key(0xA1);
    let lk_b = list_key(0xB2);
    let params = InspireParams::secure_128_d2048();

    let configs1 = build_six_configs(dir.path());
    let factory1 = |_cfg: &InstanceConfig| -> raven_railgun_core::Result<InspireServerState> {
        build_toy_state()
    };
    let mh1 =
        bootstrap_railgun_engine_multi(configs1, params.clone(), factory1).expect("bootstrap1");

    let mut want_chain: Vec<(u32, u32, [u8; 32])> = Vec::new();
    for tree in 0u32..4 {
        for i in 0u32..3 {
            let bc =
                canonical_commit(u8::try_from(tree).unwrap_or(0).wrapping_mul(8) + i as u8 + 1);
            want_chain.push((tree, i, bc));
            mh1.channels
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

    let mut want_ppoi: Vec<([u8; 32], u32, [u8; 32])> = Vec::new();
    for (lk_seed, lk) in [(0xA1u8, lk_a), (0xB2u8, lk_b)] {
        for i in 0u32..3 {
            let bc = canonical_commit(lk_seed.wrapping_add(i as u8).max(1));
            want_ppoi.push((lk, i, bc));
            mh1.channels
                .mirror_tx
                .send((
                    WalEntryPayload::PpoiListLeafAdded {
                        list_key: lk,
                        list_index: i,
                        blinded_commitment: bc,
                        status: 0,
                    },
                    0,
                ))
                .await
                .expect("send ppoi event");
        }
    }

    drain_for_apply().await;

    let mut chain_roots_pre: Vec<(u32, Option<[u8; 32]>)> = Vec::new();
    let mut chain_counts_pre: Vec<(u32, usize)> = Vec::new();
    let mut ppoi_roots_pre: Vec<([u8; 32], Option<[u8; 32]>)> = Vec::new();
    let mut ppoi_counts_pre: Vec<([u8; 32], usize)> = Vec::new();
    for h in &mh1.instances {
        let store = h.logical_store.lock();
        match h.config.data_source {
            DataSourceFilter::ChainTreeNumber(t) => {
                chain_roots_pre.push((t, store.imt_root(t)));
                chain_counts_pre.push((t, store.imt_leaf_count_for(t)));
            }
            DataSourceFilter::PpoiList(lk) => {
                ppoi_roots_pre.push((lk, store.ppoi_imt_root(&lk)));
                ppoi_counts_pre.push((lk, store.ppoi_list_leaves_iter(&lk).count()));
            }
        }
    }

    // Hard-abort rather than graceful Shutdown so WAL entries past
    // current_snapshot_seq survive for replay to reconstruct the
    // LogicalLeafStore on restart.
    let MultiOrchestratorHandleParts {
        instances,
        channels,
        router,
    } = split_handle(mh1);
    drop(channels);
    for h in instances {
        h.consumer.abort();
        let _ = tokio::time::timeout(Duration::from_secs(5), h.consumer).await;
    }
    router.abort();

    let configs2 = build_six_configs(dir.path());
    let factory2 = |_cfg: &InstanceConfig| -> raven_railgun_core::Result<InspireServerState> {
        build_toy_state()
    };
    let mh2 =
        bootstrap_railgun_engine_multi(configs2, params.clone(), factory2).expect("bootstrap2");

    drain_for_apply().await;

    for h in &mh2.instances {
        let store = h.logical_store.lock();
        match h.config.data_source {
            DataSourceFilter::ChainTreeNumber(t) => {
                let pre_root = chain_roots_pre
                    .iter()
                    .find(|(tt, _)| *tt == t)
                    .and_then(|(_, r)| *r);
                let pre_count = chain_counts_pre
                    .iter()
                    .find(|(tt, _)| *tt == t)
                    .map_or(0, |(_, c)| *c);
                assert_eq!(
                    store.imt_root(t),
                    pre_root,
                    "tree-{t} root must match pre-shutdown after restart"
                );
                assert_eq!(
                    store.imt_leaf_count_for(t),
                    pre_count,
                    "tree-{t} leaf count must match pre-shutdown after restart"
                );
                for (tt, idx, bc) in &want_chain {
                    if *tt != t {
                        continue;
                    }
                    assert_eq!(
                        store.leaf(*tt, *idx).copied(),
                        Some(*bc),
                        "tree-{tt} leaf {idx} must match pre-shutdown after restart"
                    );
                }
            }
            DataSourceFilter::PpoiList(lk) => {
                let pre_root = ppoi_roots_pre
                    .iter()
                    .find(|(k, _)| *k == lk)
                    .and_then(|(_, r)| *r);
                let pre_count = ppoi_counts_pre
                    .iter()
                    .find(|(k, _)| *k == lk)
                    .map_or(0, |(_, c)| *c);
                assert_eq!(
                    store.ppoi_imt_root(&lk),
                    pre_root,
                    "list root must match pre-shutdown after restart"
                );
                assert_eq!(
                    store.ppoi_list_leaves_iter(&lk).count(),
                    pre_count,
                    "list leaf count must match pre-shutdown after restart"
                );
                for (kk, idx, bc) in &want_ppoi {
                    if *kk != lk {
                        continue;
                    }
                    assert_eq!(
                        store.ppoi_bc_at(kk, *idx),
                        Some(*bc),
                        "ppoi list leaf must match pre-shutdown after restart"
                    );
                }
            }
        }
    }

    let MultiOrchestratorHandleParts {
        instances,
        channels,
        router,
    } = split_handle(mh2);
    shutdown_all(instances, channels).await;
    router.abort();
}

struct MultiOrchestratorHandleParts {
    instances: Vec<PerInstanceHandles>,
    channels: OrchestratorChannels,
    router: tokio::task::JoinHandle<()>,
}

fn split_handle(
    mh: raven_railgun_engine::orchestrator::MultiOrchestratorHandle,
) -> MultiOrchestratorHandleParts {
    let raven_railgun_engine::orchestrator::MultiOrchestratorHandle {
        instances,
        channels,
        router,
        chain_tree_routes: _,
        ppoi_list_routes: _,
        tree_observed: _,
        list_observed: _,
    } = mh;
    MultiOrchestratorHandleParts {
        instances,
        channels,
        router,
    }
}
