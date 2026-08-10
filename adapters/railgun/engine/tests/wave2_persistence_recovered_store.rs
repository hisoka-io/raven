//! Single-instance restart must carry the recovered logical leaf store into the
//! consumer task. A store that starts empty behind an N-leaf encoded DB rejects
//! every later append as non-contiguous, which no amount of retrying repairs.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::time::Duration;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::{CommitmentLeaf, RailgunEvent};
use raven_railgun_engine::inspire::{setup_state, InspireServerState};
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine, OrchestratorConfig, OrchestratorHandle, VerificationMode,
};
use raven_railgun_engine::persistence::{ConsumerEvent, SnapshotPolicy};
use raven_railgun_engine::InstanceRole;

const SCHEME_TAG: &str = "raven-inspire-twopacking-wave2-recovered-store";
const INSTANCE_ID: &str = "wave2-recovered-store";
const TOY_ENTRY_SIZE: usize = 256;
const SEEDED_LEAVES: u32 = 4;

fn build_toy_state() -> raven_railgun_core::Result<InspireServerState> {
    let params = InspireParams::secure_128_d2048();
    let entries = 256usize;
    let db: Vec<u8> = (0..entries)
        .flat_map(|i| (0..TOY_ENTRY_SIZE).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
        .collect();
    let (state, _sk) = setup_state(&params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking)?;
    Ok(state)
}

fn canonical_commitment(byte: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    // Keeps the value Fr-canonical for the IMT's Poseidon hash.
    b[31] = byte;
    b
}

fn leaf_event(leaf_index: u32, height: u64) -> RailgunEvent {
    RailgunEvent::Transact {
        block_number: height,
        tx_hash: [0u8; 32],
        tree_number: 0,
        start_position: leaf_index,
        leaves: vec![CommitmentLeaf {
            tree_number: 0,
            leaf_index,
            commitment_hash: canonical_commitment(
                u8::try_from((leaf_index & 0xff) | 0x10).expect("byte"),
            ),
            ciphertext: vec![],
        }],
    }
}

fn boot(dir: &std::path::Path) -> OrchestratorHandle {
    let mut config = OrchestratorConfig::demo(dir.to_path_buf(), INSTANCE_ID);
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
    let params = InspireParams::secure_128_d2048();
    bootstrap_railgun_engine(config, params, build_toy_state).expect("bootstrap")
}

async fn drain_until<F: Fn(&raven_railgun_engine::persistence::ConsumerMetrics) -> bool>(
    handle: &OrchestratorHandle,
    label: &str,
    done: F,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let snap = *handle.metrics.lock();
        if done(&snap) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{label}: events_processed = {}, commits_fired = {}, consumer_errors = {}, \
             leaf_count = {}",
            snap.events_processed,
            snap.commits_fired,
            snap.consumer_errors,
            handle.logical_store.lock().leaf_count(),
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn shutdown(handle: OrchestratorHandle) {
    handle
        .sender
        .send(ConsumerEvent::Shutdown)
        .await
        .expect("shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(30), handle.consumer).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_restores_the_logical_store_and_keeps_appends_contiguous() {
    let dir = tempfile::tempdir().expect("tempdir");

    let first = boot(dir.path());
    for i in 0..SEEDED_LEAVES {
        let height = 200 + u64::from(i);
        first
            .sender
            .send(ConsumerEvent::Chain(leaf_event(i, height), height))
            .await
            .expect("send leaf");
    }
    drain_until(&first, "seed", |m| {
        m.events_processed >= u64::from(SEEDED_LEAVES)
    })
    .await;
    assert_eq!(
        first.logical_store.lock().leaf_count(),
        SEEDED_LEAVES as usize,
        "seed phase must apply every leaf",
    );
    shutdown(first).await;

    let second = boot(dir.path());
    assert_eq!(
        second.logical_store.lock().leaf_count(),
        SEEDED_LEAVES as usize,
        "restart must seed the consumer task with the recovered logical store, not \
         an empty one",
    );
    assert_eq!(
        second.logical_store.lock().leaf(0, 0).copied(),
        Some(canonical_commitment(0x10)),
        "the recovered store must carry the leaf bytes, not just a leaf count",
    );

    let next_height = 200 + u64::from(SEEDED_LEAVES);
    second
        .sender
        .send(ConsumerEvent::Chain(
            leaf_event(SEEDED_LEAVES, next_height),
            next_height,
        ))
        .await
        .expect("send post-restart leaf");
    drain_until(&second, "post-restart append", |m| {
        m.events_processed >= 1 || m.consumer_errors >= 1
    })
    .await;

    let after = *second.metrics.lock();
    assert_eq!(
        after.consumer_errors, 0,
        "an append at index {SEEDED_LEAVES} must be contiguous after restart; a \
         reset store rejects it and wedges the tree permanently",
    );
    assert_eq!(
        second.logical_store.lock().leaf_count(),
        (SEEDED_LEAVES + 1) as usize,
    );

    shutdown(second).await;
}
