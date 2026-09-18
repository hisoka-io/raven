#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use raven_railgun_core::{AdapterError, InstanceId};
use raven_railgun_engine::imt::Imt;
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_persistence::{StoreLayout, WalEntryPayload};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-encoder-recovery";
const ENTRIES_PER_SHARD: u32 = 2048;
const LEAVES: u32 = 8;

use raven_railgun_testkit::canonical;

fn encoder_for(kind: EncoderKind) -> Arc<dyn PirTableEncoder> {
    let record_size = match kind {
        EncoderKind::PerLeafPath { .. }
        | EncoderKind::PerListPath { .. }
        | EncoderKind::PerListPath10 { .. } => 16 * 32,
        EncoderKind::PerLeafBc { .. }
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

        for i in 0..LEAVES {
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

    let recovered = &opened2.recovered_logical_store;
    assert_eq!(
        recovered.imt_leaf_count_for(0),
        LEAVES as usize,
        "{kind:?}: replay must restore {LEAVES} leaves into the logical store"
    );

    // A count alone passes while replay restores the wrong bytes, which is the
    // silent-wrong-value failure this suite exists to catch. Compare against the
    // fixture, not against anything replay produced.
    for i in 0..LEAVES {
        let expected = canonical(u8::try_from(i).unwrap_or(0).saturating_add(1));
        assert_eq!(
            recovered.leaf(0, i).copied(),
            Some(expected),
            "{kind:?}: replayed leaf {i} must byte-equal the commitment that was written"
        );
    }

    // The root folds every internal node, so it also catches corruption that never
    // reaches a leaf slot. Oracle is a standalone Imt over the same fixture.
    let mut oracle = Imt::new().expect("oracle imt");
    let leaves: Vec<[u8; 32]> = (0..LEAVES)
        .map(|i| canonical(u8::try_from(i).unwrap_or(0).saturating_add(1)))
        .collect();
    oracle.insert_leaves(0, &leaves).expect("oracle insert");
    assert_eq!(
        recovered.imt_root(0),
        Some(oracle.root()),
        "{kind:?}: recovered IMT root must equal an independently built tree over the \
         same commitments"
    );
}

#[test]
fn per_leaf_bc_round_trip_preserves_logical_store() {
    round_trip(
        EncoderKind::PerLeafBc { tree_number: 0 },
        "per-leaf-bc-inst",
    );
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
            encoder_for(EncoderKind::PerLeafBc { tree_number: 0 }),
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
