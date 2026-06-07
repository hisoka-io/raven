//! Orchestrator end-to-end smoke test.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::{CommitmentLeaf, RailgunEvent};
use raven_railgun_engine::inspire::{setup_state, InspireServerState};
use raven_railgun_engine::orchestrator::{bootstrap_railgun_engine, OrchestratorConfig};
use raven_railgun_engine::persistence::ConsumerEvent;
use raven_railgun_engine::InstanceRole;
use std::time::Duration;

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-test";

fn build_toy_state() -> raven_railgun_core::Result<InspireServerState> {
    let params = InspireParams::secure_128_d2048();
    let entries = 256usize;
    let entry_size = 256usize;
    let db: Vec<u8> = (0..entries)
        .flat_map(|i| (0..entry_size).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
        .collect();
    let (state, _sk) = setup_state(&params, &db, entry_size, InspireVariant::TwoPacking)?;
    Ok(state)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn orchestrator_bootstraps_and_consumer_applies_events() {
    let dir = tempfile::tempdir().expect("tempdir");

    // use_flock=false: a process-lifetime lock would leak across tests in one `cargo test` run
    let mut config = OrchestratorConfig::demo(dir.path().to_path_buf(), "toy");
    config.use_flock = false;
    config.role = InstanceRole::Live;
    config.scheme_tag = SCHEME_TAG.to_owned();
    let params = InspireParams::secure_128_d2048();
    let handle = bootstrap_railgun_engine(config, params, build_toy_state).expect("bootstrap");

    for i in 0..3u32 {
        let event = RailgunEvent::Transact {
            block_number: 100 + u64::from(i),
            tx_hash: [0u8; 32],
            tree_number: 0,
            start_position: i,
            leaves: vec![CommitmentLeaf {
                tree_number: 0,
                leaf_index: i,
                commitment_hash: [u8::try_from(i & 0xff).expect("low byte"); 32],
                ciphertext: vec![],
            }],
        };
        handle
            .sender
            .send(ConsumerEvent::Chain(event, 100 + u64::from(i)))
            .await
            .expect("send");
    }

    handle
        .sender
        .send(ConsumerEvent::Heartbeat(200))
        .await
        .expect("send heartbeat");

    tokio::time::sleep(Duration::from_millis(200)).await;

    let m = *handle.metrics.lock();
    assert!(
        m.events_processed >= 3,
        "consumer should have applied >= 3 events; got {}",
        m.events_processed
    );
    assert_eq!(m.last_known_chain_head, 200);
    assert_eq!(m.last_applied_block, 102);

    // snapshot fields out: don't hold the parking_lot guard across the await below
    let (count, has_0, has_1, has_2) = {
        let store = handle.logical_store.lock();
        (
            store.leaf_count(),
            store.leaf(0, 0).is_some(),
            store.leaf(0, 1).is_some(),
            store.leaf(0, 2).is_some(),
        )
    };
    assert_eq!(count, 3, "3 single-leaf Transacts -> 3 leaves");
    assert!(has_0 && has_1 && has_2);

    handle
        .sender
        .send(ConsumerEvent::Shutdown)
        .await
        .expect("send shutdown");
    let join_result = tokio::time::timeout(Duration::from_secs(5), handle.consumer)
        .await
        .expect("consumer task did not exit within 5s")
        .expect("join");
    assert!(
        join_result.is_ok(),
        "consumer returned error: {join_result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn orchestrator_reorg_truncates_leaves_past_height() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = OrchestratorConfig::demo(dir.path().to_path_buf(), "toy-reorg");
    config.use_flock = false;
    config.scheme_tag = SCHEME_TAG.to_owned();
    let params = InspireParams::secure_128_d2048();
    let handle = bootstrap_railgun_engine(config, params, build_toy_state).expect("bootstrap");

    for i in 0..3u32 {
        let event = RailgunEvent::Transact {
            block_number: 100 + u64::from(i),
            tx_hash: [0u8; 32],
            tree_number: 0,
            start_position: i,
            leaves: vec![CommitmentLeaf {
                tree_number: 0,
                leaf_index: i,
                commitment_hash: [u8::try_from(i & 0xff).expect("low byte"); 32],
                ciphertext: vec![],
            }],
        };
        handle
            .sender
            .send(ConsumerEvent::Chain(event, 100 + u64::from(i)))
            .await
            .expect("send");
    }
    // poll the store, not a fixed sleep: default policy yields no commit_notify at 3 events, and a sleep races the consumer under load
    let drain_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let count = handle.logical_store.lock().leaf_count();
        if count == 3 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < drain_deadline,
            "consumer did not drain 3 events within 5 s (count = {count})"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // register the notification before sending the reorg, else the wake is missed
    let commit_fut = handle.persistence.commit_notify().notified();
    tokio::pin!(commit_fut);
    commit_fut.as_mut().enable();
    handle
        .sender
        .send(ConsumerEvent::Reorg(100))
        .await
        .expect("send reorg");
    tokio::time::timeout(Duration::from_secs(5), commit_fut)
        .await
        .expect("reorg-driven commit did not fire within 5s");

    // snapshot fields out: don't hold the parking_lot guards across the await below
    let (count, has_0, has_1, has_2) = {
        let store = handle.logical_store.lock();
        (
            store.leaf_count(),
            store.leaf(0, 0).is_some(),
            store.leaf(0, 1).is_some(),
            store.leaf(0, 2).is_some(),
        )
    };
    assert_eq!(
        count, 1,
        "after reorg(100), only the leaf at block 100 should survive"
    );
    assert!(has_0);
    assert!(!has_1);
    assert!(!has_2);

    let m = *handle.metrics.lock();
    assert_eq!(m.reorgs_handled, 1);
    assert!(m.commits_fired >= 1, "reorg should drive a commit");

    handle
        .sender
        .send(ConsumerEvent::Shutdown)
        .await
        .expect("shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(5), handle.consumer).await;
}
