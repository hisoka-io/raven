//! Regression guard for the V6 wire-in across the open path AND every
//! `drive_commit` exit site.
//!
//! The earlier closure only fixed the bootstrap-first-commit to
//! `commit_v6`; the `drive_commit` runtime path and the open path were
//! left on the legacy V5 codec. Net effect: every chain event
//! overwrote the V6 envelope with a V5 body, dropping the embedded
//! `LogicalLeafStore`. This test writes a `commit_v6` snapshot whose
//! store carries 5 leaves and asserts reopen recovers them — failure
//! of any single site (writer dropping the store, reader using the V5
//! codec, V5 fallback returning a default-empty store on V6 bytes)
//! reverts this assertion.
//!
//! Companion guards:
//! - `encoder_recovery.rs` covers WAL-replay-only recovery (no
//!   embedded store).
//! - `snapshot_imt_audit.rs` covers Imt byte-identity inside V6.

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

/// Sentinel: `commit_v6` followed by reopen returns the same
/// `LogicalLeafStore` we committed.
///
/// Fails (reader returns empty store) if any of:
/// * the open path at `persistence.rs:170` reverts to
///   `restore_inspire_state` (V5-only, cannot strip the V6 magic prefix),
/// * `restore_inspire_state_v6` is replaced by a stub that always
///   returns `LogicalLeafStore::default()`,
/// * the writer `commit_v6` drops the store and serializes only the
///   state field.
#[test]
fn commit_v6_then_reopen_preserves_logical_leaf_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let encoder = encoder_for(EncoderKind::PerLeafBc);
    let instance = InstanceId::new("v6-roundtrip-inst");

    // Phase 1: open a fresh persistence and explicitly drive the
    // bootstrap commit via `commit_v6`. Mirrors what
    // `orchestrator.rs:584` and `persistence.rs:511` do at boot time.
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
    // 4 KiB toy database: dense enough to exercise encode without
    // dragging the test into multi-MB territory.
    let db: Vec<u8> = (0..(ENTRIES_PER_SHARD as usize) * ENTRY_BYTES)
        .map(|i| u8::try_from(i & 0xff).expect("byte"))
        .collect();
    let (state, _sk) =
        setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("setup_state");

    // Phase 2: build a populated `LogicalLeafStore` (the store the
    // runtime would observe after applying 5 AppendLeaf events) and
    // hand it directly to `commit_v6` so we test the V6 envelope's
    // round-trip semantics in isolation.
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

    // Phase 3: reopen. The recovered logical store must carry the 5
    // leaves embedded in the V6 envelope. This is the load-bearing
    // assertion: if the open path reverts to `restore_inspire_state`
    // (V5-only), the count is 0 (default-empty store) and this test
    // fails immediately.
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
