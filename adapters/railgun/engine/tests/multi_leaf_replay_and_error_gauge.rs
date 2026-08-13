//! A block re-read after a partial apply redelivers the whole multi-leaf event.
//! The already-applied prefix must not abort the tail, a redelivered leaf whose
//! commitment differs must still be refused, and an event that genuinely failed
//! must not advance the applied-block gauge operators read.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::time::Duration;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::{CommitmentLeaf, RailgunEvent};
use raven_railgun_engine::inspire::{setup_state, InspireServerState};
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine, OrchestratorConfig, OrchestratorHandle, VerificationMode,
};
use raven_railgun_engine::persistence::{ConsumerEvent, ConsumerMetrics, SnapshotPolicy};
use raven_railgun_engine::InstanceRole;

const SCHEME_TAG: &str = "raven-inspire-twopacking-leaf-replay";
const TOY_ENTRY_SIZE: usize = 256;
const TREE: u32 = 0;

fn build_toy_state() -> raven_railgun_core::Result<InspireServerState> {
    let params = InspireParams::secure_128_d2048();
    let entries = 256usize;
    let db: Vec<u8> = (0..entries)
        .flat_map(|i| (0..TOY_ENTRY_SIZE).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
        .collect();
    let (state, _sk) = setup_state(&params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking)?;
    Ok(state)
}

/// Keeps the value Fr-canonical for the IMT's Poseidon hash.
fn canonical_commitment(byte: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = byte;
    b
}

fn leaf_commitment(leaf_index: u32) -> [u8; 32] {
    canonical_commitment(u8::try_from(leaf_index & 0x3f).expect("byte") | 0x40)
}

fn leaf_at(leaf_index: u32, commitment: [u8; 32]) -> CommitmentLeaf {
    CommitmentLeaf {
        tree_number: TREE,
        leaf_index,
        commitment_hash: commitment,
        ciphertext: vec![],
    }
}

fn event_with(leaves: Vec<CommitmentLeaf>, height: u64) -> RailgunEvent {
    RailgunEvent::Transact {
        block_number: height,
        tx_hash: [0u8; 32],
        tree_number: TREE,
        start_position: leaves.first().map_or(0, |l| l.leaf_index),
        leaves,
    }
}

fn event_over(indices: &[u32], height: u64) -> RailgunEvent {
    event_with(
        indices
            .iter()
            .map(|&i| leaf_at(i, leaf_commitment(i)))
            .collect(),
        height,
    )
}

fn quiet_config(dir: &std::path::Path, instance_id: &str) -> OrchestratorConfig {
    let mut config = OrchestratorConfig::demo(dir.to_path_buf(), instance_id);
    config.record_size = TOY_ENTRY_SIZE;
    config.use_flock = false;
    config.role = InstanceRole::Live;
    SCHEME_TAG.clone_into(&mut config.scheme_tag);
    config.snapshot_policy = SnapshotPolicy {
        max_appends_per_snapshot: 1,
        ..SnapshotPolicy::default()
    };
    config.verification_mode = VerificationMode::UpstreamSignature;
    config.verification_cadence_n = 0;
    config.chain_source = None;
    config
}

async fn settle<F: Fn(&ConsumerMetrics) -> bool>(
    handle: &OrchestratorHandle,
    label: &str,
    done: F,
) -> ConsumerMetrics {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let snap = *handle.metrics.lock();
        if done(&snap) {
            return snap;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{label}: consumer never settled; events_processed = {}, \
             consumer_errors = {}, last_applied_block = {}, \
             last_applied_leaf_block = {}",
            snap.events_processed,
            snap.consumer_errors,
            snap.last_applied_block,
            snap.last_applied_leaf_block,
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn leaf_count(handle: &OrchestratorHandle) -> usize {
    handle.logical_store.lock().imt_leaf_count_for(TREE)
}

async fn shutdown(handle: OrchestratorHandle) {
    handle
        .sender
        .send(ConsumerEvent::Shutdown)
        .await
        .expect("shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(30), handle.consumer).await;
}

/// A kill between two leaves of one event leaves the resume floor at that block,
/// so the indexer re-reads it and redelivers every leaf. The applied prefix is
/// work already done; aborting the event on it strands the tail forever, and no
/// later restart can heal it because every restart replays the same prefix.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_redelivered_applied_prefix_must_not_strand_the_tail() {
    let dir = tempfile::tempdir().expect("tempdir");
    let params = InspireParams::secure_128_d2048();
    let handle = bootstrap_railgun_engine(
        quiet_config(dir.path(), "leaf-replay"),
        params,
        build_toy_state,
    )
    .expect("bootstrap");

    handle
        .sender
        .send(ConsumerEvent::Chain(event_over(&[0, 1], 100), 100))
        .await
        .expect("send partial apply");
    settle(&handle, "partial apply", |m| {
        m.events_processed + m.consumer_errors >= 1
    })
    .await;
    assert_eq!(leaf_count(&handle), 2, "prefix must be applied");

    handle
        .sender
        .send(ConsumerEvent::Chain(event_over(&[0, 1, 2], 100), 100))
        .await
        .expect("redeliver full event");
    let after = settle(&handle, "redelivery", |m| {
        m.events_processed + m.consumer_errors >= 2
    })
    .await;

    assert_eq!(
        leaf_count(&handle),
        3,
        "the redelivered tail leaf must be applied; a replayed prefix leaf is \
         work already done, not a reason to abort the event"
    );
    assert_eq!(
        after.consumer_errors, 0,
        "replaying an applied leaf is not a consumer error"
    );

    shutdown(handle).await;
}

/// Skipping a replayed index must stay a replay screen, not a divergence
/// swallower: the same index carrying different commitment bytes is a different
/// leaf and the event must fail closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replayed_index_with_different_bytes_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let params = InspireParams::secure_128_d2048();
    let handle = bootstrap_railgun_engine(
        quiet_config(dir.path(), "leaf-divergence"),
        params,
        build_toy_state,
    )
    .expect("bootstrap");

    handle
        .sender
        .send(ConsumerEvent::Chain(event_over(&[0, 1], 100), 100))
        .await
        .expect("send leaves");
    settle(&handle, "initial leaves", |m| {
        m.events_processed + m.consumer_errors >= 1
    })
    .await;

    let divergent = event_with(
        vec![
            leaf_at(0, canonical_commitment(0x11)),
            leaf_at(2, leaf_commitment(2)),
        ],
        100,
    );
    handle
        .sender
        .send(ConsumerEvent::Chain(divergent, 100))
        .await
        .expect("send divergent redelivery");
    let after = settle(&handle, "divergent redelivery", |m| {
        m.events_processed + m.consumer_errors >= 2
    })
    .await;

    assert_eq!(
        after.consumer_errors, 1,
        "a redelivered index whose bytes differ must be refused, not skipped"
    );
    assert_eq!(
        handle.logical_store.lock().leaf(TREE, 0),
        Some(&leaf_commitment(0)),
        "the refused event must leave the applied leaf untouched"
    );
    assert_eq!(
        leaf_count(&handle),
        2,
        "a refused event must not apply its tail"
    );

    shutdown(handle).await;
}

/// The gauge operators alert on measures applied events. Advancing it on an
/// event that failed makes a permanently wedged consumer read as caught up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_errored_event_must_not_advance_the_applied_gauge() {
    let dir = tempfile::tempdir().expect("tempdir");
    let params = InspireParams::secure_128_d2048();
    let handle = bootstrap_railgun_engine(
        quiet_config(dir.path(), "error-gauge"),
        params,
        build_toy_state,
    )
    .expect("bootstrap");

    handle
        .sender
        .send(ConsumerEvent::Chain(event_over(&[0, 1], 100), 100))
        .await
        .expect("send leaves");
    let applied = settle(&handle, "initial leaves", |m| {
        m.events_processed + m.consumer_errors >= 1
    })
    .await;
    assert_eq!(applied.last_applied_block, 100);
    assert_eq!(applied.consecutive_event_errors, 0);

    handle
        .sender
        .send(ConsumerEvent::Chain(event_over(&[5, 6], 200), 200))
        .await
        .expect("send gapped event");
    let errored = settle(&handle, "gapped event", |m| {
        m.events_processed + m.consumer_errors >= 2
    })
    .await;

    assert_eq!(
        errored.consumer_errors, 1,
        "a leaf above the expected index is a real gap and must fail"
    );
    assert_eq!(
        errored.last_applied_block, 100,
        "an errored event must not advance the applied-block gauge"
    );
    assert_eq!(
        errored.consecutive_event_errors, 1,
        "the wedge signal must be readable without guessing from a lag gauge"
    );

    handle
        .sender
        .send(ConsumerEvent::Heartbeat {
            chain_head: 300,
            scanned_through: 300,
        })
        .await
        .expect("send heartbeat");
    let heartbeat = settle(&handle, "heartbeat", |m| m.last_known_chain_head >= 300).await;
    assert_eq!(
        heartbeat.blocks_since_last_applied_event(),
        200,
        "the derived gauge must expose the stall, not hide it behind the \
         errored event's height"
    );

    handle
        .sender
        .send(ConsumerEvent::Chain(event_over(&[2, 3], 210), 210))
        .await
        .expect("send recovery event");
    let recovered = settle(&handle, "recovery event", |m| {
        m.events_processed + m.consumer_errors >= 3
    })
    .await;

    assert_eq!(recovered.consumer_errors, 1);
    assert_eq!(
        recovered.last_applied_block, 210,
        "a clean event must advance the gauge again"
    );
    assert_eq!(
        recovered.consecutive_event_errors, 0,
        "the error run must end on the first clean event"
    );

    shutdown(handle).await;
}
