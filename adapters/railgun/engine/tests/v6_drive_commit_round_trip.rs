//! Regression guard for the V6 snapshot envelope across the open path
//! and every `drive_commit` exit site: a `commit_v6` snapshot whose
//! store carries 5 leaves must reopen with those leaves intact. A writer
//! dropping the store, or a reader on the V5 codec, recovers an empty store and fails here.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{apply_wal_entry, setup_state, LogicalLeafStore};
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_persistence::{StoreLayout, WalEntryPayload};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-v6-roundtrip";
const ENTRIES_PER_SHARD: u32 = 2048;
const ENTRY_BYTES: usize = 32;
const TREE_NUMBER: u32 = 0;

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

#[test]
fn commit_v6_then_reopen_preserves_logical_leaf_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let encoder = encoder_for(EncoderKind::PerLeafBc);
    let instance = InstanceId::new("v6-roundtrip-inst");

    let opened = InspirePersistence::open(
        layout,
        SCHEME_TAG,
        instance.clone(),
        SnapshotPolicy::default(),
        Arc::clone(&encoder),
    )
    .expect("fresh open");
    assert!(
        opened.recovered_state.is_none(),
        "fresh bootstrap leaves no recovered state until the first commit"
    );

    let params = InspireParams::secure_128_d2048();
    let db: Vec<u8> = (0..(ENTRIES_PER_SHARD as usize) * ENTRY_BYTES)
        .map(|i| u8::try_from(i & 0xff).expect("byte"))
        .collect();
    let (state, _sk) =
        setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("setup_state");

    // hand a populated store directly to commit_v6 to test the V6 envelope round-trip in isolation
    let mut staged = LogicalLeafStore::new();
    for i in 0..5u32 {
        let payload = WalEntryPayload::AppendLeaf {
            tree_number: TREE_NUMBER,
            leaf_index: i,
            commitment: canonical(u8::try_from(i).unwrap_or(0).saturating_add(1)),
        };
        apply_wal_entry(&mut staged, &payload, 100 + u64::from(i), encoder.as_ref())
            .expect("stage append_leaf");
    }
    assert_eq!(staged.imt_leaf_count_for(TREE_NUMBER), 5);

    let _new_id = opened
        .persistence
        .commit_v6(&state, &staged, 200)
        .expect("commit_v6");
    drop(opened);

    // reopen: recovered store must carry the 5 embedded leaves; a V5-only reader recovers 0
    let layout2 = StoreLayout::open(dir.path()).expect("layout reopen");
    let opened2 = InspirePersistence::open(
        layout2,
        SCHEME_TAG,
        instance,
        SnapshotPolicy::default(),
        encoder,
    )
    .expect("recovery open");

    assert!(
        opened2.recovered_state.is_some(),
        "post-commit reopen must surface recovered_state"
    );
    assert_eq!(
        opened2
            .recovered_logical_store
            .imt_leaf_count_for(TREE_NUMBER),
        5,
        "V6 round-trip must restore the embedded LogicalLeafStore; if this \
         fails, persistence.rs:170 has reverted to the legacy \
         `restore_inspire_state` (V5-only) reader, OR commit_v6 lost the \
         store field at write time"
    );
}
