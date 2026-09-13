//! Orchestrator end-to-end smoke test.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_inspire::params::InspireParams;
use raven_railgun_core::{CommitmentLeaf, RailgunEvent};
use raven_railgun_engine::inspire::InspireServerState;
use raven_railgun_engine::orchestrator::{bootstrap_railgun_engine, OrchestratorConfig};
use raven_railgun_engine::persistence::{ConsumerEvent, ConsumerMetrics};
use raven_railgun_engine::InstanceRole;
use std::time::Duration;

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-test";
/// Row width of [`build_toy_state`]'s cell; the configured encoder must emit it.
const TOY_ENTRY_SIZE: usize = 256;

/// Distinct per leaf, and never the all-zero empty-leaf sentinel: the fixture used to
/// hand leaf 0 `[0u8; 32]`, so leaf 0 never exercised the occupied-leaf path at all.
fn leaf_commitment(leaf_index: u32) -> [u8; 32] {
    raven_railgun_testkit::canonical(
        u8::try_from(leaf_index & 0x7f)
            .expect("low byte")
            .saturating_add(1),
    )
}

fn build_toy_state() -> raven_railgun_core::Result<InspireServerState> {
    raven_railgun_testkit::try_toy_state(TOY_ENTRY_SIZE)
}

async fn wait_for_consumer_progress(
    metrics: &parking_lot::Mutex<ConsumerMetrics>,
    min_events: u64,
    scanned_through: u64,
) {
    let observed = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let ready = {
                let current = *metrics.lock();
                current.events_processed >= min_events
                    && current.last_known_chain_head == scanned_through
                    && current.last_scanned_block == scanned_through
            };
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        observed.is_ok(),
        "consumer did not reach head/scan {scanned_through} with {min_events} events within 30s"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn orchestrator_bootstraps_and_consumer_applies_events() {
    let dir = tempfile::tempdir().expect("tempdir");

    // use_flock=false: a process-lifetime lock would leak across tests in one `cargo test` run
    let mut config = OrchestratorConfig::demo(dir.path().to_path_buf(), "toy");
    config.record_size = TOY_ENTRY_SIZE;
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
                commitment_hash: leaf_commitment(i),
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
        .send(ConsumerEvent::Heartbeat {
            chain_head: 200,
            scanned_through: 200,
        })
        .await
        .expect("send heartbeat");

    wait_for_consumer_progress(&handle.metrics, 3, 200).await;

    let m = *handle.metrics.lock();
    assert!(
        m.events_processed >= 3,
        "consumer should have applied >= 3 events; got {}",
        m.events_processed
    );
    assert_eq!(m.last_known_chain_head, 200);
    assert_eq!(m.last_applied_block, 102);
    assert_eq!(m.last_scanned_block, 200);
    assert_eq!(
        m.indexer_lag_blocks(),
        0,
        "scanner caught up to the tip: lag must be 0 even though the last \
         event landed at 102"
    );
    assert_eq!(m.blocks_since_last_applied_event(), 98);

    // 98 quiet blocks later: lag holds at zero, event distance keeps growing.
    handle
        .sender
        .send(ConsumerEvent::Heartbeat {
            chain_head: 298,
            scanned_through: 298,
        })
        .await
        .expect("send quiet heartbeat");
    wait_for_consumer_progress(&handle.metrics, 3, 298).await;

    let quiet = *handle.metrics.lock();
    assert_eq!(quiet.indexer_lag_blocks(), 0);
    assert_eq!(quiet.blocks_since_last_applied_event(), 196);
    assert_eq!(
        quiet.last_applied_leaf_block, 102,
        "resume floor must not move on heartbeats"
    );

    // snapshot fields out: don't hold the parking_lot guard across the await below
    let (count, applied) = {
        let store = handle.logical_store.lock();
        let applied: Vec<Option<[u8; 32]>> = (0..3u32).map(|i| store.leaf(0, i).copied()).collect();
        (store.leaf_count(), applied)
    };
    assert_eq!(count, 3, "3 single-leaf Transacts -> 3 leaves");
    // `leaf()` is a BTreeMap probe: `is_some()` proves the KEY landed and says nothing
    // about the value, so a consumer that applies every leaf as zeros passes it.
    for (i, got) in applied.iter().enumerate() {
        let leaf_index = u32::try_from(i).expect("index fits u32");
        assert_eq!(
            *got,
            Some(leaf_commitment(leaf_index)),
            "leaf {leaf_index} must carry the commitment the chain event delivered"
        );
    }

    handle
        .sender
        .send(ConsumerEvent::Shutdown)
        .await
        .expect("send shutdown");
    // 5 s reddened here purely from sibling load; every other shutdown join in this
    // suite allows 30 s and the property asserted is that it exits at all.
    let join_result = tokio::time::timeout(Duration::from_secs(30), handle.consumer)
        .await
        .expect("consumer task did not exit within 30s")
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
    config.record_size = TOY_ENTRY_SIZE;
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
                commitment_hash: leaf_commitment(i),
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
    // 30 s, matching the sibling suites: this is a deadlock detector, and a 5 s budget
    // reds on how many other test binaries share the box.
    let drain_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let count = handle.logical_store.lock().leaf_count();
        if count == 3 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < drain_deadline,
            "consumer did not drain 3 events within 30 s (count = {count})"
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
    tokio::time::timeout(Duration::from_secs(30), commit_fut)
        .await
        .expect("reorg-driven commit did not fire within 30s");

    // snapshot fields out: don't hold the parking_lot guards across the await below
    let (count, leaf_0, has_1, has_2) = {
        let store = handle.logical_store.lock();
        (
            store.leaf_count(),
            store.leaf(0, 0).copied(),
            store.leaf(0, 1).is_some(),
            store.leaf(0, 2).is_some(),
        )
    };
    assert_eq!(
        count, 1,
        "after reorg(100), only the leaf at block 100 should survive"
    );
    assert_eq!(
        leaf_0,
        Some(leaf_commitment(0)),
        "the survivor must keep its commitment bytes; a rewritten row still \
         satisfies `is_some`"
    );
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
