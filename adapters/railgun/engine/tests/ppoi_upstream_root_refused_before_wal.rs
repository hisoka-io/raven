//! Every `PpoiListLeafAdded` on the live consumer path is held to the root it carries: the
//! upstream `validatedMerkleroot` is that tree's root read AFTER the event's own insert, so a
//! row whose root is not the root its append produces is refused before the WAL write.
//!
//! Its own integration binary gets a hermetic Prometheus recorder; sharing one across sibling
//! tests would race the render against the increment flush.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use raven_inspire::params::InspireParams;
use raven_railgun_engine::imt::Imt;
use raven_railgun_engine::inspire::InspireServerState;
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine, OrchestratorConfig, VerificationMode,
};
use raven_railgun_engine::persistence::{ConsumerEvent, ConsumerMetrics, SnapshotPolicy};
use raven_railgun_engine::pir_table::EncoderKind;
use raven_railgun_engine::InstanceRole;
use raven_railgun_persistence::{StoreLayout, Wal, WalEntryPayload};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-ppoi-upstream-root";
const INSTANCE_ID: &str = "ppoi-upstream-root";
const TOY_ENTRY_SIZE: usize = 256;
const ENTRIES_PER_SHARD: u32 = 2048;
const LIST_KEY: [u8; 32] = [0xab; 32];

// Known answers from the upstream node's own tree test
// (private-proof-of-innocence packages/node/src/poi-events/__tests__/poi-merkletree.test.ts,
// "Should update merkle tree correctly"). Upstream hashes arbitrary hex, reducing it mod the
// BN254 scalar field on the way in; this engine refuses a non-canonical leaf, so leaves 0 and
// 2 are upstream's value mod r. The roots are upstream's literals, untouched.
const UPSTREAM_LEAVES: [&str; 4] = [
    "1a02b1c619dfe364c8dc1d21a5fca51030b35bcbd578abd740f4f8e5e7f9ffe2",
    "071f842dbbae18082c04bfd08f4a56d71e1444317bfc6417dae8ac604d9493de",
    "2839c6aa2498c591812cf099910ab15d08b23c3a0ccbf32f10b44498138e9f2b",
    "19889087c2ff4c4a164060a832a3ba11cce0c2e2dbd42da10c57101efb966fcd",
];
const UPSTREAM_ROOT_AFTER_LEAF_0: &str =
    "2b6de07658fdb3b15b7fd96fdcf59d44bdef9eb20dc8beb2b5ac6d8bf9f011b1";
const UPSTREAM_ROOT_AFTER_LEAF_1: &str =
    "141baa90d97e062336fd433ba9ef26f949627b12fcc8849c2c1bd70b8355a489";
const UPSTREAM_ROOT_AFTER_LEAF_3: &str =
    "1cecd47eb0f6ad9d3bf093a36a1dd5a0863530c40dd4adbc637d7450ee50dff1";

fn hex32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "32 bytes of hex");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex digit pair");
    }
    out
}

/// Roots a feed would publish for [`UPSTREAM_LEAVES`], one per row. Upstream's test inserts
/// leaves 2 and 3 in one batch and so never records a root for row 2; that one comes from a
/// tree this test grows by hand, never from the store under test.
fn upstream_roots() -> [[u8; 32]; 4] {
    let mut reference = Imt::new().expect("reference imt");
    let roots: Vec<[u8; 32]> = UPSTREAM_LEAVES
        .iter()
        .enumerate()
        .map(|(i, leaf)| {
            reference
                .insert_leaves(i, &[hex32(leaf)])
                .expect("reference insert");
            reference.root()
        })
        .collect();
    let roots: [[u8; 32]; 4] = roots.try_into().expect("one root per leaf");
    assert_eq!(roots[0], hex32(UPSTREAM_ROOT_AFTER_LEAF_0));
    assert_eq!(roots[1], hex32(UPSTREAM_ROOT_AFTER_LEAF_1));
    assert_eq!(roots[3], hex32(UPSTREAM_ROOT_AFTER_LEAF_3));
    roots
}

fn install_recorder() -> &'static metrics_exporter_prometheus::PrometheusHandle {
    static HANDLE: OnceLock<metrics_exporter_prometheus::PrometheusHandle> = OnceLock::new();
    HANDLE.get_or_init(|| {
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .install_recorder()
            .expect("first-time Prometheus install in this integration binary must succeed")
    })
}

fn build_toy_state() -> raven_railgun_core::Result<InspireServerState> {
    raven_railgun_testkit::try_toy_state(TOY_ENTRY_SIZE)
}

fn list_leaf(list_index: u32, leaf: [u8; 32], validated_merkleroot: [u8; 32]) -> WalEntryPayload {
    WalEntryPayload::PpoiListLeafAdded {
        list_key: LIST_KEY,
        list_index,
        blinded_commitment: leaf,
        status: 0,
        event_type: raven_railgun_persistence::PpoiEventType::Shield,
        signature: vec![0; 64],
        validated_merkleroot,
    }
}

fn list_rows_in_wal(data_dir: &std::path::Path) -> Vec<(u32, [u8; 32])> {
    let layout = StoreLayout::open(data_dir).expect("layout for wal scan");
    let wal = Wal::open(&layout, None).expect("wal open for scan");
    wal.replay()
        .expect("wal replay for scan")
        .entries
        .iter()
        .filter_map(|entry| bincode::deserialize::<WalEntryPayload>(&entry.payload).ok())
        .filter_map(|payload| match payload {
            WalEntryPayload::PpoiListLeafAdded {
                list_index,
                validated_merkleroot,
                ..
            } => Some((list_index, validated_merkleroot)),
            _ => None,
        })
        .collect()
}

fn counter(handle: &metrics_exporter_prometheus::PrometheusHandle, name: &str) -> u64 {
    let rendered = handle.render();
    let prefix = format!("{name} ");
    let value_line = rendered
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("Prometheus render must carry a {name} value line:\n{rendered}"));
    value_line
        .split_whitespace()
        .last()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("counter value must parse as u64 from line {value_line:?}"))
}

async fn settled(
    metrics: &Arc<parking_lot::Mutex<ConsumerMetrics>>,
    outcomes: u64,
) -> ConsumerMetrics {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let m = *metrics.lock();
        if m.events_processed + m.consumer_errors >= outcomes {
            return m;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "consumer settled {} of {outcomes} rows within 30 s (applied {}, refused {})",
            m.events_processed + m.consumer_errors,
            m.events_processed,
            m.consumer_errors,
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_row_whose_root_is_not_its_own_post_append_root_never_reaches_the_wal() {
    let prometheus = install_recorder();
    let dir = tempfile::tempdir().expect("tempdir");

    let mut config = OrchestratorConfig::demo(dir.path().to_path_buf(), INSTANCE_ID);
    config.record_size = TOY_ENTRY_SIZE;
    config.entries_per_shard = ENTRIES_PER_SHARD;
    config.use_flock = false;
    config.role = InstanceRole::Live;
    config.scheme_tag = SCHEME_TAG.to_owned();
    config.encoder = EncoderKind::PerListStatus { list_key: LIST_KEY };
    // A snapshot would archive the log this test reads back.
    config.snapshot_policy = SnapshotPolicy::default();
    config.verification_mode = VerificationMode::UpstreamSignature;
    config.verification_cadence_n = 0;
    config.chain_source = None;

    let params = InspireParams::secure_128_d2048();
    let handle = bootstrap_railgun_engine(config, params, build_toy_state).expect("bootstrap");
    let metrics = Arc::clone(&handle.metrics);

    let leaves = UPSTREAM_LEAVES.map(hex32);
    let roots = upstream_roots();
    // Right leaf, right index, one bit of the root wrong: only a root comparison sees it.
    let mut divergent_root = roots[1];
    divergent_root[31] ^= 0x01;

    handle
        .sender
        .send(ConsumerEvent::Ppoi(list_leaf(0, leaves[0], roots[0]), 0))
        .await
        .expect("send row 0");
    handle
        .sender
        .send(ConsumerEvent::Ppoi(
            list_leaf(1, leaves[1], divergent_root),
            0,
        ))
        .await
        .expect("send divergent row 1");
    let after_divergent = settled(&metrics, 2).await;
    assert_eq!(
        (
            after_divergent.events_processed,
            after_divergent.consumer_errors
        ),
        (1, 1),
        "row 1 carries a validated_merkleroot that is not the root its own append produces, \
         and the consumer applied it anyway (applied, refused) = ({}, {})",
        after_divergent.events_processed,
        after_divergent.consumer_errors,
    );
    assert_eq!(
        handle.logical_store.lock().ppoi_imt_root(&LIST_KEY),
        Some(roots[0]),
        "a refused row must leave the tree where row 0 put it"
    );

    // The refusal holds the tree at index 1; the same index redelivered with upstream's real
    // root is what resumes it, and the rest of the feed follows.
    for (i, (leaf, root)) in leaves.iter().zip(roots).enumerate().skip(1) {
        let list_index = u32::try_from(i).expect("four rows");
        handle
            .sender
            .send(ConsumerEvent::Ppoi(list_leaf(list_index, *leaf, root), 0))
            .await
            .expect("send upstream row");
    }
    let after_feed = settled(&metrics, 5).await;
    assert_eq!(
        (after_feed.events_processed, after_feed.consumer_errors),
        (4, 1),
        "every row carrying upstream's own root must apply"
    );
    assert_eq!(
        handle.logical_store.lock().ppoi_imt_root(&LIST_KEY),
        Some(hex32(UPSTREAM_ROOT_AFTER_LEAF_3)),
        "four upstream leaves must land on upstream's four-leaf root"
    );
    assert_eq!(
        counter(prometheus, "raven_railgun_ppoi_root_divergence_total"),
        1,
        "one divergent row, one count"
    );

    // Closing the channel instead of sending Shutdown: Shutdown drive_commits, which archives
    // the log this reads.
    drop(handle.channels);
    drop(handle.sender);
    let _ = tokio::time::timeout(Duration::from_secs(10), handle.indexer_bridge).await;
    let _ = tokio::time::timeout(Duration::from_secs(10), handle.mirror_bridge).await;
    let _ = tokio::time::timeout(Duration::from_secs(10), handle.consumer).await;
    drop(handle.persistence);

    assert_eq!(
        list_rows_in_wal(dir.path()),
        vec![(0, roots[0]), (1, roots[1]), (2, roots[2]), (3, roots[3])],
        "the divergent row must never have been written; a durable copy replays on every reopen"
    );
}
