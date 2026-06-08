//! Process-isolated regression for the poisoned-WAL recovery counter.
//!
//! Its own integration binary gets a hermetic Prometheus recorder; sharing one across sibling
//! tests would race the render against the increment flush and flake to 0.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::OnceLock;

use raven_railgun_core::InstanceId;
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{PerLeafCommitmentEncoder, PirTableEncoder};
use raven_railgun_persistence::{StoreLayout, WalEntryPayload};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-poisoned-wal-counter";

fn install_recorder() -> &'static metrics_exporter_prometheus::PrometheusHandle {
    static HANDLE: OnceLock<metrics_exporter_prometheus::PrometheusHandle> = OnceLock::new();
    HANDLE.get_or_init(|| {
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .install_recorder()
            .expect("first-time Prometheus install in this integration binary must succeed")
    })
}

fn encoder() -> Arc<dyn PirTableEncoder> {
    Arc::new(PerLeafCommitmentEncoder::new(32, 2048).expect("test encoder"))
}

#[test]
fn poisoned_wal_replay_skipped_counter_increments() {
    let handle = install_recorder();
    let dir = tempfile::tempdir().expect("tempdir");
    let commitment = {
        let mut b = [0u8; 32];
        b[31] = 0x07;
        b
    };
    {
        let layout = StoreLayout::open(dir.path()).expect("layout 1");
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("poisoned-wal-counter"),
            SnapshotPolicy::default(),
            encoder(),
        )
        .expect("open 1");
        opened
            .persistence
            .apply_event(
                &WalEntryPayload::AppendLeaf {
                    tree_number: 0,
                    leaf_index: 0,
                    commitment,
                },
                100,
            )
            .expect("apply seq 0");
        opened
            .persistence
            .apply_event(
                &WalEntryPayload::AppendLeaf {
                    tree_number: 0,
                    leaf_index: 9, // sparse - rejected by apply_wal_entry on replay
                    commitment,
                },
                101,
            )
            .expect("apply poisoned seq 1");
    }

    // reopen: WAL replay soft-skips the sparse leaf and drives the counter to >= 1
    let layout2 = StoreLayout::open(dir.path()).expect("layout 2");
    let _opened2 = InspirePersistence::open(
        layout2,
        SCHEME_TAG,
        InstanceId::new("poisoned-wal-counter"),
        SnapshotPolicy::default(),
        encoder(),
    )
    .expect("open 2");

    let rendered = handle.render();
    let value_line = rendered
        .lines()
        .find(|line| {
            line.starts_with("raven_railgun_wal_replay_skipped_total ") && !line.starts_with("# ")
        })
        .unwrap_or_else(|| {
            panic!(
                "Prometheus render must surface the counter VALUE line after \
                 a poisoned-WAL recovery; got render:\n{rendered}"
            )
        });
    let value: u64 = value_line
        .split_whitespace()
        .last()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            panic!(
                "counter value must parse as u64 from line {value_line:?}; got render:\n{rendered}"
            )
        });
    assert!(
        value >= 1,
        "counter value must be >= 1 after poisoned-WAL recovery, got {value}; \
         if 0, the production-path \
         `metrics::counter!(\"raven_railgun_wal_replay_skipped_total\").increment(...)` \
         was never reached. Render:\n{rendered}"
    );
}
