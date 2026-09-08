//! An event for a tree no instance routes is DROPPED. That is the mechanism behind
//! the tree-4 outage, and until `raven_railgun_router_dropped_events_total` existed it
//! was unobservable: the router logged at `trace!` and returned, so no test and no
//! operator could tell a routed event from a lost one.
//!
//! The precedent is two files away and already gated —
//! `engine/src/persistence.rs`'s `consumer_errors` on the analogous drop, tested by
//! `http/tests/readiness_stalled_consumer.rs`.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::OnceLock;
use std::time::Duration;

use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use raven_inspire::params::InspireParams;
use raven_railgun_core::{CommitmentLeaf, InstanceId, RailgunEvent};
use raven_railgun_engine::inspire::InspireServerState;
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine_multi, DataSourceFilter, InstanceConfig, VerificationMode,
};
use raven_railgun_engine::persistence::{ConsumerEvent, SnapshotPolicy};
use raven_railgun_engine::pir_table::EncoderKind;
use raven_railgun_engine::InstanceRole;
use raven_railgun_indexer::IndexerMessage;

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-router-drop-test";
const TOY_ENTRY_SIZE: usize = 256;
const TOY_ENTRIES_PER_SHARD: u32 = 2048;
const ROUTED_TREE: u32 = 0;
const UNROUTED_TREE: u32 = 7;

/// `metrics::set_global_recorder` succeeds once per PROCESS, so a per-test recorder
/// silently leaves the counter unobservable (the trap documented at
/// `indexer/tests/subscribe_block_number_drop.rs:48-59`). One snapshotter for the
/// binary; and `snapshot()` CONSUMES what it reports, so this binary holds exactly
/// ONE counter-reading test. A second one must take a serializing lock first.
fn snap() -> &'static Snapshotter {
    static SNAP: OnceLock<Snapshotter> = OnceLock::new();
    SNAP.get_or_init(|| {
        let recorder = DebuggingRecorder::new();
        let s = recorder.snapshotter();
        let _ = metrics::set_global_recorder(recorder);
        s
    })
}

/// Read the `raven_railgun_router_dropped_events_total` series carrying
/// `reason=<reason>`. `DebuggingRecorder`'s snapshot is cumulative, not consuming,
/// so this is a level read rather than a delta.
fn dropped_with_reason(reason: &str) -> u64 {
    snap()
        .snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(composite, _, _, value)| {
            let (_, key) = composite.into_parts();
            if key.name() != "raven_railgun_router_dropped_events_total" {
                return None;
            }
            if !key
                .labels()
                .any(|l| l.key() == "reason" && l.value() == reason)
            {
                return None;
            }
            match value {
                DebugValue::Counter(c) => Some(c),
                _ => None,
            }
        })
        .sum()
}

fn build_toy_state() -> raven_railgun_core::Result<InspireServerState> {
    raven_railgun_testkit::try_toy_state(TOY_ENTRY_SIZE)
}

fn shield(tree: u32, leaf: u32) -> RailgunEvent {
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

fn cfg(root: &std::path::Path) -> InstanceConfig {
    InstanceConfig {
        instance_id: InstanceId::new("router-drop-host"),
        role: InstanceRole::Live,
        data_dir: root.join("host"),
        encoder: EncoderKind::PerLeafBc {
            tree_number: ROUTED_TREE,
        },
        record_size: TOY_ENTRY_SIZE,
        entries_per_shard: TOY_ENTRIES_PER_SHARD,
        verification_mode: VerificationMode::UpstreamSignature,
        data_source: DataSourceFilter::ChainTreeNumber(ROUTED_TREE),
        use_flock: false,
        snapshot_policy: SnapshotPolicy::default(),
        scheme_tag: SCHEME_TAG.to_owned(),
        channel_capacity: 256,
        max_concurrent_queries: None,
        verification_cadence_n: 0,
        chain_source: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_event_for_a_tree_no_instance_routes_increments_the_dropped_counter() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let params = InspireParams::secure_128_d2048();
    let mut handle =
        bootstrap_railgun_engine_multi(vec![cfg(tmp.path())], params, |_c| build_toy_state())
            .expect("bootstrap");

    // Take the baseline AFTER bootstrap so the router's describe-time increment(0)
    // is already accounted for.
    let before = dropped_with_reason("no_route");

    // Control: a routed tree must NOT be counted, or the counter would just track
    // traffic rather than loss.
    handle
        .channels
        .indexer_tx
        .send(IndexerMessage::Event {
            event: shield(ROUTED_TREE, 0),
            block_height: 100,
        })
        .await
        .expect("router indexer inbound open");

    handle
        .channels
        .indexer_tx
        .send(IndexerMessage::Event {
            event: shield(UNROUTED_TREE, 0),
            block_height: 101,
        })
        .await
        .expect("router indexer inbound open");

    // The router is a separate task; poll until the drop lands rather than sleeping
    // a fixed interval.
    let mut after = before;
    for _ in 0..200 {
        after = dropped_with_reason("no_route");
        if after > before {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    assert_eq!(
        after,
        before + 1,
        "exactly one drop must be counted: the tree-{UNROUTED_TREE} event has no route, \
         the tree-{ROUTED_TREE} event does. Got before={before} after={after}"
    );

    drop(handle.channels);
    for h in handle.instances.drain(..) {
        let _ = h.sender.send(ConsumerEvent::Shutdown).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), h.consumer).await;
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), handle.router).await;
}
