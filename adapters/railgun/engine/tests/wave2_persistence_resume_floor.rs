//! The restart resume floor under mirror rows and reorgs: a height-0 PPOI row
//! must not collapse it, and a reorg must lower it so Shutdown cannot commit a
//! marker above the rewind point.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::time::Duration;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::{CommitmentLeaf, RailgunEvent};
use raven_railgun_engine::inspire::{setup_state, InspireServerState};
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine, OrchestratorConfig, VerificationMode,
};
use raven_railgun_engine::persistence::{ConsumerEvent, SnapshotPolicy};
use raven_railgun_engine::InstanceRole;
use raven_railgun_persistence::WalEntryPayload;

const SCHEME_TAG: &str = "raven-inspire-twopacking-wave2-resume-floor";
const TOY_ENTRY_SIZE: usize = 256;
const LIST_KEY: [u8; 32] = [0x7c; 32];

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
                u8::try_from((leaf_index & 0xff) | 0x40).expect("byte"),
            ),
            ciphertext: vec![],
        }],
    }
}

fn commit_every_event() -> SnapshotPolicy {
    SnapshotPolicy {
        max_appends_per_snapshot: 1,
        ..SnapshotPolicy::default()
    }
}

fn quiet_config(dir: &std::path::Path, instance_id: &str) -> OrchestratorConfig {
    let mut config = OrchestratorConfig::demo(dir.to_path_buf(), instance_id);
    config.record_size = TOY_ENTRY_SIZE;
    config.use_flock = false;
    config.role = InstanceRole::Live;
    SCHEME_TAG.clone_into(&mut config.scheme_tag);
    config.snapshot_policy = commit_every_event();
    config.verification_mode = VerificationMode::UpstreamSignature;
    config.verification_cadence_n = 0;
    config.chain_source = None;
    config
}

async fn drain_until<F: Fn(&raven_railgun_engine::persistence::ConsumerMetrics) -> bool>(
    metrics: &parking_lot::Mutex<raven_railgun_engine::persistence::ConsumerMetrics>,
    label: &str,
    done: F,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let snap = *metrics.lock();
        if done(&snap) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{label}: consumer never reached the target state; \
             events_processed = {}, commits_fired = {}, reorgs_handled = {}, \
             consumer_errors = {}, last_applied_leaf_block = {}",
            snap.events_processed,
            snap.commits_fired,
            snap.reorgs_handled,
            snap.consumer_errors,
            snap.last_applied_leaf_block,
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// A PPOI row carries mirror height 0. Applying it must not move the chain
/// resume floor, in memory or in the manifest.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ppoi_height_zero_must_not_collapse_the_resume_floor() {
    const LEAVES: u32 = 5;
    const LAST_LEAF_HEIGHT: u64 = 100 + (LEAVES as u64) - 1;

    let dir = tempfile::tempdir().expect("tempdir");
    let config = quiet_config(dir.path(), "wave2-ppoi-floor");
    let params = InspireParams::secure_128_d2048();
    let handle = bootstrap_railgun_engine(config, params, build_toy_state).expect("bootstrap");

    for i in 0..LEAVES {
        let height = 100 + u64::from(i);
        handle
            .sender
            .send(ConsumerEvent::Chain(leaf_event(i, height), height))
            .await
            .expect("send leaf");
    }
    drain_until(&handle.metrics, "chain leaves", |m| {
        m.last_applied_leaf_block >= LAST_LEAF_HEIGHT
    })
    .await;

    let leaves_committed = handle.metrics.lock().commits_fired;

    for byte in 0u8..4 {
        let payload = WalEntryPayload::PpoiStatus {
            list_key: LIST_KEY,
            blinded_commitment: canonical_commitment(0x80 | byte),
            status: 1,
        };
        handle
            .sender
            .send(ConsumerEvent::Ppoi(payload, 0))
            .await
            .expect("send mirror row");
    }
    drain_until(&handle.metrics, "mirror rows", |m| {
        m.commits_fired >= leaves_committed + 4
    })
    .await;

    let after = *handle.metrics.lock();
    assert_eq!(
        after.last_applied_leaf_block, LAST_LEAF_HEIGHT,
        "a mirror row at height 0 must leave the in-memory resume floor at the \
         last applied leaf block"
    );
    assert_eq!(
        handle.persistence.manifest_block_height(),
        LAST_LEAF_HEIGHT,
        "a commit driven by a mirror row must not write a manifest marker of 0; \
         restart would re-scan the chain from the configured start block"
    );

    handle
        .sender
        .send(ConsumerEvent::Shutdown)
        .await
        .expect("shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(30), handle.consumer).await;
}

/// A reorg rewinds applied leaves, so the floor it leaves behind must be the
/// rewind height. Shutdown commits that floor; a stale high-water would skip
/// the re-scan and wedge the tree.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reorg_must_lower_the_shutdown_resume_floor() {
    const LEAVES: u32 = 10;
    const LAST_LEAF_HEIGHT: u64 = 100 + (LEAVES as u64) - 1;
    const REORG_HEIGHT: u64 = 105;
    const DEEP_REORG_HEIGHT: u64 = 400;

    let dir = tempfile::tempdir().expect("tempdir");
    let config = quiet_config(dir.path(), "wave2-reorg-floor");
    let params = InspireParams::secure_128_d2048();
    let handle = bootstrap_railgun_engine(config, params, build_toy_state).expect("bootstrap");

    for i in 0..LEAVES {
        let height = 100 + u64::from(i);
        handle
            .sender
            .send(ConsumerEvent::Chain(leaf_event(i, height), height))
            .await
            .expect("send leaf");
    }
    // `reorgs_handled` is bumped before the commit it drives, so every manifest
    // read gates on `commits_fired` or it races the write it asserts on.
    drain_until(&handle.metrics, "chain leaves", |m| {
        m.last_applied_leaf_block >= LAST_LEAF_HEIGHT && m.commits_fired >= u64::from(LEAVES)
    })
    .await;

    handle
        .sender
        .send(ConsumerEvent::Reorg(REORG_HEIGHT))
        .await
        .expect("send reorg");
    drain_until(&handle.metrics, "reorg", |m| {
        m.reorgs_handled >= 1 && m.commits_fired > u64::from(LEAVES)
    })
    .await;

    assert_eq!(
        handle.metrics.lock().last_applied_leaf_block,
        REORG_HEIGHT,
        "a reorg must lower the resume floor to the rewind height",
    );
    assert_eq!(
        handle.persistence.manifest_block_height(),
        REORG_HEIGHT,
        "the reorg commit must publish the rewind height as the resume floor",
    );

    // A rewind point above everything applied leaves the floor where it is: the
    // engine has still only applied leaves up to REORG_HEIGHT.
    handle
        .sender
        .send(ConsumerEvent::Reorg(DEEP_REORG_HEIGHT))
        .await
        .expect("send reorg above the floor");
    drain_until(&handle.metrics, "reorg above floor", |m| {
        m.reorgs_handled >= 2 && m.commits_fired > u64::from(LEAVES) + 1
    })
    .await;

    assert_eq!(
        handle.metrics.lock().last_applied_leaf_block,
        REORG_HEIGHT,
        "a rewind point above the floor must not raise it to a block whose leaves \
         were never applied",
    );
    assert_eq!(
        handle.persistence.manifest_block_height(),
        REORG_HEIGHT,
        "the reorg commit marker must be the resume floor, not the raw rewind \
         height; blocks {} to {DEEP_REORG_HEIGHT} were never scanned",
        REORG_HEIGHT + 1,
    );

    handle
        .sender
        .send(ConsumerEvent::Shutdown)
        .await
        .expect("shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(30), handle.consumer).await;

    assert_eq!(
        handle.persistence.manifest_block_height(),
        REORG_HEIGHT,
        "the final Shutdown commit must not raise the manifest marker back above \
         the reorg height; blocks {} to {LAST_LEAF_HEIGHT} would never be re-scanned",
        REORG_HEIGHT + 1,
    );
}
