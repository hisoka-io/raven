//! A non-contiguous `PpoiListLeafAdded` must be rejected before the WAL write,
//! so it never reaches disk and never trips the replay-skip counter on reopen.
//!
//! Its own integration binary gets a hermetic Prometheus recorder; sharing one
//! across sibling tests would race the render against the increment flush.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{setup_state, InspireServerState};
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine, OrchestratorConfig, VerificationMode,
};
use raven_railgun_engine::persistence::{ConsumerEvent, InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::EncoderKind;
use raven_railgun_engine::InstanceRole;
use raven_railgun_persistence::{StoreLayout, Wal, WalEntryPayload};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-ppoi-validate-before-wal";
const INSTANCE_ID: &str = "ppoi-validate-before-wal";
const TOY_ENTRY_SIZE: usize = 256;
const ENTRIES_PER_SHARD: u32 = 2048;
const LIST_KEY: [u8; 32] = [0xab; 32];
/// An empty list only admits index 0, so this one must be refused.
const POISON_LIST_INDEX: u32 = 3;

fn install_recorder() -> &'static metrics_exporter_prometheus::PrometheusHandle {
    static HANDLE: OnceLock<metrics_exporter_prometheus::PrometheusHandle> = OnceLock::new();
    HANDLE.get_or_init(|| {
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .install_recorder()
            .expect("first-time Prometheus install in this integration binary must succeed")
    })
}

fn build_toy_state() -> raven_railgun_core::Result<InspireServerState> {
    let params = InspireParams::secure_128_d2048();
    let entries = 256usize;
    let db: Vec<u8> = (0..entries)
        .flat_map(|i| (0..TOY_ENTRY_SIZE).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
        .collect();
    let (state, _sk) = setup_state(&params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking)?;
    Ok(state)
}

fn blinded_commitment(byte: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    // Keeps the value Fr-canonical for the per-list IMT's Poseidon hash.
    b[31] = byte;
    b
}

fn list_leaf(list_index: u32, byte: u8) -> WalEntryPayload {
    WalEntryPayload::PpoiListLeafAdded {
        list_key: LIST_KEY,
        list_index,
        blinded_commitment: blinded_commitment(byte),
        status: 1,
    }
}

fn ppoi_list_indexes_in_wal(data_dir: &std::path::Path) -> Vec<u32> {
    let layout = StoreLayout::open(data_dir).expect("layout for wal scan");
    let wal = Wal::open(&layout, None).expect("wal open for scan");
    wal.replay()
        .expect("wal replay for scan")
        .entries
        .iter()
        .filter_map(|entry| bincode::deserialize::<WalEntryPayload>(&entry.payload).ok())
        .filter_map(|payload| match payload {
            WalEntryPayload::PpoiListLeafAdded { list_index, .. } => Some(list_index),
            _ => None,
        })
        .collect()
}

fn replay_skipped_counter(handle: &metrics_exporter_prometheus::PrometheusHandle) -> u64 {
    let rendered = handle.render();
    let value_line = rendered
        .lines()
        .find(|line| {
            line.starts_with("raven_railgun_wal_replay_skipped_total ") && !line.starts_with("# ")
        })
        .unwrap_or_else(|| {
            panic!("Prometheus render must surface the counter VALUE line; got:\n{rendered}")
        });
    value_line
        .split_whitespace()
        .last()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("counter value must parse as u64 from line {value_line:?}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ppoi_non_contiguous_list_leaf_never_reaches_the_wal() {
    let prometheus = install_recorder();
    let dir = tempfile::tempdir().expect("tempdir");

    let mut config = OrchestratorConfig::demo(dir.path().to_path_buf(), INSTANCE_ID);
    config.record_size = TOY_ENTRY_SIZE;
    config.entries_per_shard = ENTRIES_PER_SHARD;
    config.use_flock = false;
    config.role = InstanceRole::Live;
    config.scheme_tag = SCHEME_TAG.to_owned();
    config.encoder = EncoderKind::PerListStatus { list_key: LIST_KEY };
    // Snapshotting would archive the log and float the replay floor above the
    // poisoned seq, hiding the very entry this test inspects.
    config.snapshot_policy = SnapshotPolicy::default();
    config.verification_mode = VerificationMode::UpstreamSignature;
    config.verification_cadence_n = 0;
    config.chain_source = None;

    let params = InspireParams::secure_128_d2048();
    let handle = bootstrap_railgun_engine(config, params, build_toy_state).expect("bootstrap");

    handle
        .sender
        .send(ConsumerEvent::Ppoi(list_leaf(0, 0x11), 100))
        .await
        .expect("send contiguous leaf");
    handle
        .sender
        .send(ConsumerEvent::Ppoi(list_leaf(POISON_LIST_INDEX, 0x33), 101))
        .await
        .expect("send non-contiguous leaf");

    let metrics = Arc::clone(&handle.metrics);
    let drain_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let m = *metrics.lock();
        if m.events_processed >= 1 && m.consumer_errors >= 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < drain_deadline,
            "consumer did not accept one leaf and reject the other within 30 s; \
             events_processed = {}, consumer_errors = {}",
            m.events_processed,
            m.consumer_errors,
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Closing the channel instead of sending Shutdown: Shutdown drive_commits,
    // which archives the log and makes the reopen replay nothing.
    drop(handle.channels);
    drop(handle.sender);
    let _ = tokio::time::timeout(Duration::from_secs(10), handle.indexer_bridge).await;
    let _ = tokio::time::timeout(Duration::from_secs(10), handle.mirror_bridge).await;
    let _ = tokio::time::timeout(Duration::from_secs(10), handle.consumer).await;
    drop(handle.persistence);

    let wal_indexes = ppoi_list_indexes_in_wal(dir.path());

    let reopened = InspirePersistence::open(
        StoreLayout::open(dir.path()).expect("layout for reopen"),
        SCHEME_TAG,
        InstanceId::new(INSTANCE_ID),
        SnapshotPolicy::default(),
        EncoderKind::PerListStatus { list_key: LIST_KEY }
            .build(TOY_ENTRY_SIZE, ENTRIES_PER_SHARD)
            .expect("reopen encoder"),
    )
    .expect("reopen must recover");
    let skipped = replay_skipped_counter(prometheus);

    assert_eq!(
        wal_indexes,
        vec![0],
        "WAL must hold only the validated list_index 0; a non-contiguous \
         list_index {POISON_LIST_INDEX} on disk means apply_ppoi wrote before it \
         validated. replay_skipped_total = {skipped}"
    );
    assert_eq!(
        skipped, 0,
        "reopen must replay a clean WAL; a non-zero replay_skipped_total tells \
         the operator to investigate external disk corruption that does not exist"
    );
    let recovered = &reopened.recovered_logical_store;
    assert!(
        recovered.ppoi_bc_at(&LIST_KEY, 0).is_some(),
        "replay must restore the validated list leaf at index 0"
    );
    assert!(
        recovered.ppoi_bc_at(&LIST_KEY, POISON_LIST_INDEX).is_none(),
        "replay must not surface a list leaf at the rejected index {POISON_LIST_INDEX}"
    );
}
