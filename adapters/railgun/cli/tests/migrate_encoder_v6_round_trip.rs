//! Regression guard: the offline `migrate-encoder` tool must read AND write
//! through the V6 codec so the `LogicalLeafStore` embedded in the snapshot
//! survives the encoder swap.
//!
//! The pre-fix path used `restore_inspire_state` (V5-only) on the reader
//! side, which cannot strip the `SNAPSHOT_V6_MAGIC` prefix that
//! `commit_v6` writes — every post-V6 snapshot would fail to decode (or,
//! if the engine somehow handed back a V5 blob, the store rebuilt from
//! WAL replay would START from `LogicalLeafStore::default()`, dropping
//! the historical leaves already archived past the snapshot floor). The
//! writer side used `snapshot_inspire_state` (V5) while stamping
//! `schema_version: 6` on the manifest — successful migration would
//! produce an internally inconsistent (V6 manifest, V5 body, no
//! embedded store) data dir.
//!
//! This test pre-populates the V6 snapshot with 5 leaves, runs
//! `migrate_encoder::run` end-to-end on a fresh encoder kind, reopens
//! with the new encoder, and asserts the per-tree IMT still carries
//! the original 5 leaves. The pre-fix path fails immediately at the
//! reader (V6 magic confuses the V5 bincode decoder), or — under any
//! scenario where the V5 fallback fires — fails at the post-reopen
//! assertion because the embedded store is gone.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{apply_wal_entry, setup_state, LogicalLeafStore};
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_persistence::{StoreLayout, WalEntryPayload};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-migrate-roundtrip";
const ENTRIES_PER_SHARD: u32 = 2048;
const ENTRY_BYTES: usize = 32;
const TREE_NUMBER: u32 = 0;

fn canonical(seed: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = seed.max(1);
    b
}

fn encoder_for(kind: EncoderKind) -> Arc<dyn PirTableEncoder> {
    kind.build(ENTRY_BYTES, ENTRIES_PER_SHARD)
        .expect("build encoder")
}

#[test]
fn migrate_encoder_round_trip_preserves_logical_leaf_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let from_kind = EncoderKind::PerLeafBc;
    let to_kind = EncoderKind::PerNode {
        tree_number: TREE_NUMBER,
    };
    assert_ne!(
        from_kind.label(),
        to_kind.label(),
        "migrate-encoder requires distinct labels; test fixture invariant"
    );

    // Phase 1: open fresh persistence with the FROM encoder; commit a V6
    // snapshot embedding a `LogicalLeafStore` with 5 leaves.
    let from_encoder = encoder_for(from_kind);
    let instance = InstanceId::new("migrate-roundtrip-inst");

    let layout = StoreLayout::open(dir.path()).expect("layout");
    let opened = InspirePersistence::open(
        layout,
        SCHEME_TAG,
        instance.clone(),
        SnapshotPolicy::default(),
        Arc::clone(&from_encoder),
    )
    .expect("fresh open");
    assert!(
        opened.recovered_state.is_none(),
        "fresh open returns no recovered_state"
    );

    let params = InspireParams::secure_128_d2048();
    let db: Vec<u8> = (0..(ENTRIES_PER_SHARD as usize) * ENTRY_BYTES)
        .map(|i| u8::try_from(i & 0xff).expect("byte"))
        .collect();
    let (state, _sk) =
        setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("setup_state");

    let mut staged = LogicalLeafStore::new();
    for i in 0..5u32 {
        let payload = WalEntryPayload::AppendLeaf {
            tree_number: TREE_NUMBER,
            leaf_index: i,
            commitment: canonical(u8::try_from(i).unwrap_or(0).saturating_add(1)),
        };
        apply_wal_entry(
            &mut staged,
            &payload,
            100 + u64::from(i),
            from_encoder.as_ref(),
        )
        .expect("stage append_leaf");
    }
    assert_eq!(staged.imt_leaf_count_for(TREE_NUMBER), 5);

    let _new_id = opened
        .persistence
        .commit_v6(&state, &staged, 200)
        .expect("commit_v6");
    drop(opened);

    // Phase 2: run the offline migrator. The pre-fix path reads via V5,
    // which either fails to decode the V6 magic bytes OR — in a synthetic
    // scenario where the V5 fallback fires — drops the embedded store
    // and writes back V5 bytes under a V6 manifest. The post-fix path
    // reads via V6 (recovering the embedded store) and writes back V6
    // with the rebuilt store.
    raven_railgun_cli::migrate_encoder::run(dir.path(), to_kind).expect("migrate-encoder run");

    // Phase 3: reopen with the TO encoder. The recovered logical store
    // must still carry the 5 leaves. If migrate-encoder dropped the
    // embedded store at write time, `imt_leaf_count_for(TREE_NUMBER)`
    // would be 0 here.
    let to_encoder = encoder_for(to_kind);
    let layout2 = StoreLayout::open(dir.path()).expect("reopen layout");
    let reopened = InspirePersistence::open(
        layout2,
        SCHEME_TAG,
        instance,
        SnapshotPolicy::default(),
        to_encoder,
    )
    .expect("recovery open with TO encoder");

    assert!(
        reopened.recovered_state.is_some(),
        "post-migration reopen must surface recovered_state"
    );
    assert_eq!(
        reopened
            .recovered_logical_store
            .imt_leaf_count_for(TREE_NUMBER),
        5,
        "migrate-encoder must preserve the embedded LogicalLeafStore across \
         the V6 round-trip; a regression that reverts the reader to \
         `restore_inspire_state` (V5-only) OR the writer to \
         `snapshot_inspire_state` (V5-only) drops the store and this \
         count falls to 0"
    );
}
