#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use raven_railgun_core::{AdapterError, InstanceId};
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_persistence::{StoreLayout, WalEntryPayload};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-encoder-recovery";
const ENTRIES_PER_SHARD: u32 = 2048;

fn canonical(seed: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = seed.max(1);
    b
}

fn encoder_for(kind: EncoderKind) -> Arc<dyn PirTableEncoder> {
    let record_size = match kind {
        EncoderKind::PerLeafPath { .. } | EncoderKind::PerListPath { .. } => 16 * 32,
        EncoderKind::PerLeafBc
        | EncoderKind::PerNode { .. }
        | EncoderKind::PerListNode { .. }
        | EncoderKind::PerListStatus { .. } => 32,
    };
    kind.build(record_size, ENTRIES_PER_SHARD)
        .expect("build encoder")
}

fn round_trip(kind: EncoderKind, instance: &str) {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");

    {
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new(instance),
            SnapshotPolicy::default(),
            encoder_for(kind),
        )
        .expect("fresh open");

        for i in 0..8u32 {
            let payload = WalEntryPayload::AppendLeaf {
                tree_number: 0,
                leaf_index: i,
                commitment: canonical(u8::try_from(i).unwrap_or(0).saturating_add(1)),
            };
            opened
                .persistence
                .apply_event(&payload, 100 + u64::from(i))
                .expect("apply_event");
        }
    }

    let layout2 = StoreLayout::open(dir.path()).expect("layout reopen");
    let opened2 = InspirePersistence::open(
        layout2,
        SCHEME_TAG,
        InstanceId::new(instance),
        SnapshotPolicy::default(),
        encoder_for(kind),
    )
    .expect("recovery open");

    assert_eq!(
        opened2.recovered_logical_store.imt_leaf_count_for(0),
        8,
        "{kind:?}: replay must restore 8 leaves into the logical store"
    );
}

#[test]
fn per_leaf_bc_round_trip_preserves_logical_store() {
    round_trip(EncoderKind::PerLeafBc, "per-leaf-bc-inst");
}

#[test]
fn per_leaf_path_round_trip_preserves_logical_store() {
    round_trip(
        EncoderKind::PerLeafPath { tree_number: 0 },
        "per-leaf-path-inst",
    );
}

#[test]
fn per_node_round_trip_preserves_logical_store() {
    round_trip(EncoderKind::PerNode { tree_number: 0 }, "per-node-inst");
}

#[test]
fn manifest_encoder_label_mismatch_is_rejected_on_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");

    {
        let _opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("encoder-mismatch"),
            SnapshotPolicy::default(),
            encoder_for(EncoderKind::PerLeafBc),
        )
        .expect("fresh open with PerLeafBc");
    }

    let layout2 = StoreLayout::open(dir.path()).expect("layout reopen");
    let err = InspirePersistence::open(
        layout2,
        SCHEME_TAG,
        InstanceId::new("encoder-mismatch"),
        SnapshotPolicy::default(),
        encoder_for(EncoderKind::PerNode { tree_number: 0 }),
    )
    .expect_err("recovery with mismatched encoder must fail");

    let msg = format!("{err}");
    assert!(
        msg.contains("encoder_label mismatch"),
        "error must surface encoder_label mismatch; got: {msg}"
    );
    assert!(matches!(err, AdapterError::Internal(_)));
}
