//! Chain-tree routing must reach every instance bound to a tree number,
//! matching the mirror path's list_key fan-out.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::{CommitmentLeaf, InstanceId, RailgunEvent};
use raven_railgun_engine::inspire::{setup_state, InspireServerState};
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine_multi, DataSourceFilter, InstanceConfig, VerificationMode,
};
use raven_railgun_engine::persistence::{ConsumerEvent, SnapshotPolicy};
use raven_railgun_engine::pir_table::EncoderKind;
use raven_railgun_engine::InstanceRole;
use raven_railgun_indexer::IndexerMessage;
use tokio::sync::mpsc;

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-chain-fanout-test";
const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_SIZE: usize = 256;
const TOY_ENTRIES_PER_SHARD: u32 = 2048;
const SHARED_TREE: u32 = 0;

fn build_toy_state() -> raven_railgun_core::Result<InspireServerState> {
    let params = InspireParams::secure_128_d2048();
    let db: Vec<u8> = (0..TOY_ENTRIES)
        .flat_map(|i| (0..TOY_ENTRY_SIZE).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
        .collect();
    let (state, _sk) = setup_state(&params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking)?;
    Ok(state)
}

fn commit_tree_cfg(id: &str, dir: std::path::PathBuf, tree_number: u32) -> InstanceConfig {
    InstanceConfig {
        instance_id: InstanceId::new(id),
        role: InstanceRole::Live,
        data_dir: dir,
        encoder: EncoderKind::PerLeafBc,
        record_size: TOY_ENTRY_SIZE,
        entries_per_shard: TOY_ENTRIES_PER_SHARD,
        verification_mode: VerificationMode::ChainRootHistory,
        data_source: DataSourceFilter::ChainTreeNumber(tree_number),
        use_flock: false,
        snapshot_policy: SnapshotPolicy::default(),
        scheme_tag: SCHEME_TAG.to_owned(),
        channel_capacity: 256,
        max_concurrent_queries: None,
        verification_cadence_n: 0,
        chain_source: None,
    }
}

fn shield_event(tree_number: u32, leaf_index: u32) -> RailgunEvent {
    let mut commitment_hash = [0u8; 32];
    commitment_hash[..4].copy_from_slice(&leaf_index.to_be_bytes());
    RailgunEvent::Shield {
        block_number: u64::from(leaf_index) + 100,
        tx_hash: [0u8; 32],
        tree_number,
        start_position: leaf_index,
        leaves: vec![CommitmentLeaf {
            tree_number,
            leaf_index,
            commitment_hash,
            ciphertext: Vec::new(),
        }],
    }
}

/// Two instances may share a `tree_number` with different encoders (the
/// bootstrap dedup key is `(data_source, encoder_label)`), so a chain event
/// must reach both route entries, not just the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chain_event_reaches_every_instance_bound_to_the_same_tree_number() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfgs = vec![commit_tree_cfg(
        "chain-fanout-host",
        tmp.path().join("host"),
        SHARED_TREE,
    )];
    let params = InspireParams::secure_128_d2048();
    let mut handle =
        bootstrap_railgun_engine_multi(cfgs, params, |_| build_toy_state()).expect("bootstrap");

    let (tx_leaf_bc, mut rx_leaf_bc) = mpsc::channel::<ConsumerEvent>(8);
    let (tx_leaf_path, mut rx_leaf_path) = mpsc::channel::<ConsumerEvent>(8);
    handle.chain_tree_routes.store(Arc::new(vec![
        (SHARED_TREE, tx_leaf_bc),
        (SHARED_TREE, tx_leaf_path),
    ]));

    let event = shield_event(SHARED_TREE, 0);
    handle
        .channels
        .indexer_tx
        .send(IndexerMessage::Event {
            event: event.clone(),
            block_height: 200,
        })
        .await
        .expect("router inbound open");

    let first = tokio::time::timeout(Duration::from_secs(2), rx_leaf_bc.recv())
        .await
        .expect("first route timed out")
        .expect("first route closed");
    let second = tokio::time::timeout(Duration::from_secs(2), rx_leaf_path.recv())
        .await
        .expect("second route bound to the same tree_number never received the event")
        .expect("second route closed");
    for (label, got) in [("first", first), ("second", second)] {
        match got {
            ConsumerEvent::Chain(delivered, height) => {
                assert_eq!(delivered, event, "{label} route got a different event");
                assert_eq!(height, 200, "{label} route got a different block height");
            }
            other => panic!("{label} route expected Chain, got {other:?}"),
        }
    }

    drop(handle.channels);
    for h in handle.instances.drain(..) {
        let _ = h.sender.send(ConsumerEvent::Shutdown).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), h.consumer).await;
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), handle.router).await;
}
