//! Idempotency, byte-identity, and encoder-label refusal for `migrate-encoder`.
//!
//! Crash coverage lives in `migrate_encoder_real_sigkill.rs` (real SIGKILL at
//! parked checkpoints); the in-process crash simulations that used to live here
//! asserted the behaviour of their own step copies and were deleted after a
//! mutation proof (V5-writer defect reintroduced at migrate_encoder.rs:143:
//! both stayed green; migrate_encoder_v6_round_trip is the honest guard).

#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used,
        clippy::too_many_lines
    )
)]

use std::path::Path;
use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::{AdapterError, InstanceId};
use raven_railgun_engine::inspire::{
    apply_wal_entry, setup_state, InspireServerState, LogicalLeafStore,
};
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{
    EncoderKind, PerLeafCommitmentEncoder, PerListNodeEncoder, PerListPathEncoder, PirTableEncoder,
};
use raven_railgun_persistence::{
    Manifest, Snapshot, SnapshotId, StoreLayout, Wal, WalEntryPayload, SNAPSHOT_MAGIC,
};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-kill-during-migration";
const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_SIZE: usize = 32;
const ENTRIES_PER_SHARD: u32 = 256;
const PATH_RECORD_BYTES: usize = 16 * 32;
const LIST_KEY_OFAC: [u8; 32] = [0xAB; 32];

use raven_railgun_testkit::canonical;

fn build_toy_state() -> InspireServerState {
    let params = InspireParams::secure_128_d2048();
    let db = raven_railgun_testkit::toy_db(TOY_ENTRIES, TOY_ENTRY_SIZE);
    let (state, _sk) =
        setup_state(&params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking).expect("setup_state");
    state
}

fn build_toy_state_with_record_size(record_size: usize) -> InspireServerState {
    let params = InspireParams::secure_128_d2048();
    let db = raven_railgun_testkit::toy_db(TOY_ENTRIES, record_size);
    let (state, _sk) =
        setup_state(&params, &db, record_size, InspireVariant::TwoPacking).expect("setup_state");
    state
}

fn encoder_arc(kind: EncoderKind) -> Arc<dyn PirTableEncoder> {
    let record_size = match kind {
        EncoderKind::PerLeafPath { .. } | EncoderKind::PerListPath { .. } => PATH_RECORD_BYTES,
        _ => TOY_ENTRY_SIZE,
    };
    kind.build(record_size, ENTRIES_PER_SHARD)
        .expect("build encoder")
}

fn seed_with_committed_snapshot(
    dir_path: &Path,
    encoder_kind: EncoderKind,
    leaf_count: u32,
) -> SnapshotId {
    let layout = StoreLayout::open(dir_path).expect("layout");
    let opened = InspirePersistence::open(
        layout,
        SCHEME_TAG,
        InstanceId::new("kill-during-migrate"),
        SnapshotPolicy::default(),
        encoder_arc(encoder_kind),
    )
    .expect("fresh open");

    let state = build_toy_state();
    opened
        .persistence
        .commit(&state, 0)
        .expect("initial commit");

    for i in 0..leaf_count {
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

    opened.persistence.current_snapshot_id()
}

fn seed_ppoi_list_with_committed_snapshot(
    dir_path: &Path,
    encoder_kind: EncoderKind,
    list_key: [u8; 32],
    leaf_count: u32,
) -> SnapshotId {
    let record_size = match encoder_kind {
        EncoderKind::PerListPath { .. } => PATH_RECORD_BYTES,
        _ => TOY_ENTRY_SIZE,
    };
    let layout = StoreLayout::open(dir_path).expect("layout");
    let opened = InspirePersistence::open(
        layout,
        SCHEME_TAG,
        InstanceId::new("kill-during-ppoi"),
        SnapshotPolicy::default(),
        encoder_arc(encoder_kind),
    )
    .expect("fresh open");

    let state = build_toy_state_with_record_size(record_size);
    opened
        .persistence
        .commit(&state, 0)
        .expect("initial commit");

    for i in 0..leaf_count {
        let payload = WalEntryPayload::PpoiListLeafAdded {
            list_key,
            list_index: i,
            blinded_commitment: canonical(u8::try_from(i).unwrap_or(0).saturating_add(1)),
            status: 0,
        };
        opened
            .persistence
            .apply_event(&payload, 100 + u64::from(i))
            .expect("apply_event");
    }
    opened.persistence.current_snapshot_id()
}

fn replay_wal_into_logical_store(layout: &StoreLayout, manifest: &Manifest) -> LogicalLeafStore {
    let noop_encoder: Arc<dyn PirTableEncoder> =
        Arc::new(PerLeafCommitmentEncoder::new(32, 1, 0).expect("noop encoder"));
    let wal_floor = manifest.current_snapshot_seq.checked_sub(1);
    let wal = Wal::open(layout, wal_floor).expect("wal open");
    let replay = wal.replay().expect("wal replay");
    let mut logical_store = LogicalLeafStore::new();
    for entry in &replay.entries {
        if entry.seq < manifest.current_snapshot_seq {
            continue;
        }
        let payload: WalEntryPayload = bincode::deserialize(&entry.payload)
            .expect("wal payload deserialize during migration replay");
        let _ = apply_wal_entry(
            &mut logical_store,
            &payload,
            entry.marker,
            noop_encoder.as_ref(),
        );
    }
    logical_store
}

/// Drives the REAL production migration. The in-process step copies that used
/// to live here diverged from migrate_encoder.rs (V5 reader vs V6); asserting
/// on the real path is the only form that can catch a production regression.
fn run_full_migration(dir_path: &Path, target: EncoderKind) {
    raven_railgun_cli::migrate_encoder::run(dir_path, target).expect("migrate-encoder run");
}

fn read_manifest(dir_path: &Path) -> Manifest {
    let layout = StoreLayout::open(dir_path).expect("layout");
    Manifest::load(&layout)
        .expect("manifest load")
        .expect("manifest present")
}

fn manifest_bytes(dir_path: &Path) -> Vec<u8> {
    let layout = StoreLayout::open(dir_path).expect("layout");
    std::fs::read(layout.manifest_path()).expect("read manifest bytes")
}

fn snapshot_bytes(dir_path: &Path, id: SnapshotId) -> Vec<u8> {
    let layout = StoreLayout::open(dir_path).expect("layout");
    let snap = Snapshot::load(&layout, id, SNAPSHOT_MAGIC).expect("load snap");
    snap.data
}

#[test]
#[ignore = "~7 s per PIR instance stood up, ~99% of it PackParams::try_new (the deterministic \
            d=2048 packing table) built twice per setup_state; the keygen proper is ~60 ms. \
            Trigger: changing InspirePersistence::open's encoder_label refusal. CI runs it in \
            the durability + closure crash-safety lane."]
fn encoder_label_mismatch_refuses_open_until_migration_completes() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed_with_committed_snapshot(dir.path(), EncoderKind::PerLeafBc { tree_number: 0 }, 50);

    // Mid-migration reopen under the not-yet-stamped target label must refuse,
    // not silently serve rows encoded under the other layout.
    let layout_new = StoreLayout::open(dir.path()).expect("layout");
    let err_new = InspirePersistence::open(
        layout_new,
        SCHEME_TAG,
        InstanceId::new("kill-during-migrate"),
        SnapshotPolicy::default(),
        encoder_arc(EncoderKind::PerNode { tree_number: 0 }),
    )
    .expect_err("reopen with mismatched encoder must fail");
    let msg_new = format!("{err_new}");
    assert!(
        msg_new.contains("encoder_label mismatch"),
        "must surface encoder_label mismatch; got: {msg_new}"
    );
    assert!(
        matches!(err_new, AdapterError::Internal(_)),
        "must be Internal-class for operator-visible refusal"
    );

    // The matching label still opens and recovers every leaf.
    let layout_old = StoreLayout::open(dir.path()).expect("layout");
    let opened_old = InspirePersistence::open(
        layout_old,
        SCHEME_TAG,
        InstanceId::new("kill-during-migrate"),
        SnapshotPolicy::default(),
        encoder_arc(EncoderKind::PerLeafBc { tree_number: 0 }),
    )
    .expect("reopen with prior encoder must succeed");
    assert_eq!(
        opened_old.recovered_logical_store.imt_leaf_count_for(0),
        50,
        "WAL replay must restore all 50 leaves"
    );
}

#[test]
#[ignore = "~7 s per PIR instance stood up, ~99% of it PackParams::try_new (the deterministic \
            d=2048 packing table) built twice per setup_state; the keygen proper is ~60 ms. \
            Trigger: changing the encoder-migration step order (pre-snapshot, re-encode, manifest \
            bump) or its idempotence. CI runs it in the durability + closure crash-safety lane."]
fn migration_repeated_three_times_on_same_data_dir_is_byte_identical() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed_with_committed_snapshot(dir.path(), EncoderKind::PerLeafBc { tree_number: 0 }, 16);

    run_full_migration(dir.path(), EncoderKind::PerNode { tree_number: 0 });
    let manifest_after_run1 = read_manifest(dir.path());
    let snap_bytes_after_run1 = snapshot_bytes(dir.path(), manifest_after_run1.current_snapshot_id);
    let manifest_bytes_after_run1 = manifest_bytes(dir.path());

    for run_idx in 2..=3 {
        let err = raven_railgun_cli::migrate_encoder::run(
            dir.path(),
            EncoderKind::PerNode { tree_number: 0 },
        )
        .expect_err("run {run_idx} must be rejected as already-on-target");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("already") || msg.contains("nothing to migrate"),
            "run {run_idx}: error must surface idempotency guard; got: {msg}"
        );

        let manifest_after_attempt = read_manifest(dir.path());
        let snap_bytes_after_attempt =
            snapshot_bytes(dir.path(), manifest_after_attempt.current_snapshot_id);
        let manifest_raw_after_attempt = manifest_bytes(dir.path());
        assert_eq!(
            manifest_after_attempt, manifest_after_run1,
            "run {run_idx}: manifest must equal post-first-run state"
        );
        assert_eq!(
            manifest_raw_after_attempt, manifest_bytes_after_run1,
            "run {run_idx}: manifest bytes must be byte-identical to post-first-run"
        );
        assert_eq!(
            snap_bytes_after_attempt, snap_bytes_after_run1,
            "run {run_idx}: live snapshot bytes must be byte-identical to post-first-run"
        );
    }
}

#[test]
#[ignore = "~7 s per PIR instance stood up, ~99% of it PackParams::try_new (the deterministic \
            d=2048 packing table) built twice per setup_state; the keygen proper is ~60 ms. \
            Trigger: changing the per-list encoder row layouts or the migrate-encoder width \
            refusal. CI runs it in the durability + closure crash-safety lane."]
fn per_list_node_byte_identity_at_levels_0_1_8_and_width_migration_refusal() {
    let dir = tempfile::tempdir().expect("tempdir");

    seed_ppoi_list_with_committed_snapshot(
        dir.path(),
        EncoderKind::PerListPath {
            list_key: LIST_KEY_OFAC,
        },
        LIST_KEY_OFAC,
        32,
    );

    let manifest_pre = read_manifest(dir.path());
    assert_eq!(manifest_pre.encoder_label, "per-list-path");
    assert_eq!(manifest_pre.prev_encoder_label, None);

    let layout_pre = StoreLayout::open(dir.path()).expect("layout pre");
    let store_oracle = replay_wal_into_logical_store(&layout_pre, &manifest_pre);
    let imt_oracle = store_oracle
        .ppoi_imt(&LIST_KEY_OFAC)
        .expect("ppoi imt seeded");
    assert_eq!(
        imt_oracle.leaf_count(),
        32,
        "oracle imt must hold all seeded leaves"
    );

    // Production REFUSES this migration: per-list-node emits 32-byte rows and the
    // stored per-list-path cell is 512 bytes wide. The deleted in-process copy
    // performed it anyway and asserted the labels of a migration that can never
    // happen; the refusal is the real contract.
    let err = raven_railgun_cli::migrate_encoder::run(
        dir.path(),
        EncoderKind::PerListNode {
            list_key: LIST_KEY_OFAC,
        },
    )
    .expect_err("width-changing migration must be refused");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("32") && msg.contains("512"),
        "refusal must name both widths; got: {msg}"
    );

    let manifest_post = read_manifest(dir.path());
    assert_eq!(
        manifest_post, manifest_pre,
        "refused migration must leave the manifest untouched"
    );

    // PerListNode shares PerNode's flat-global-index layout: leaves, level 1, ..., root.
    let path_enc = PerListPathEncoder::new(PATH_RECORD_BYTES, ENTRIES_PER_SHARD, LIST_KEY_OFAC)
        .expect("path encoder");
    let node_enc = PerListNodeEncoder::new(ENTRIES_PER_SHARD, LIST_KEY_OFAC).expect("node encoder");

    // level-0 PerListNode rows must reconstruct the seeded leaf hashes
    let node_shard0 = node_enc.materialize_shard(0, &store_oracle);
    for leaf_idx in 0u32..32 {
        let row_byte_start = (leaf_idx as usize) * 32;
        let row = node_shard0
            .get(row_byte_start..row_byte_start + 32)
            .expect("level-0 row slice");
        let expected = imt_oracle.node(0, leaf_idx as usize);
        assert_eq!(
            row, &expected,
            "per-list-node level 0 row {leaf_idx} must equal IMT leaf hash"
        );
    }

    // a path row's level-0 sibling must equal the PerListNode row at idx^1
    let path_shard0 = path_enc.materialize_shard(0, &store_oracle);
    for leaf_idx in 0usize..16 {
        let path_row_start = leaf_idx * PATH_RECORD_BYTES;
        let path_sibling_l0 = path_shard0
            .get(path_row_start..path_row_start + 32)
            .expect("path level-0 sibling slice");
        let sibling_idx_l0 = leaf_idx ^ 1;
        let node_sibling_row = node_shard0
            .get(sibling_idx_l0 * 32..sibling_idx_l0 * 32 + 32)
            .expect("per-list-node sibling row slice");
        assert_eq!(
            path_sibling_l0, node_sibling_row,
            "level 0 sibling for leaf {leaf_idx}: per-list-path row {leaf_idx}'s sibling \
             must equal per-list-node row at idx {sibling_idx_l0}"
        );
    }

    // the path-row level-1 sibling (bytes [32,64)) must equal IMT.node(1, sibling_idx)
    for leaf_idx in 0u32..16 {
        let path_row_start = (leaf_idx as usize) * PATH_RECORD_BYTES;
        let path_sibling_l1 = path_shard0
            .get(path_row_start + 32..path_row_start + 64)
            .expect("path level-1 sibling slice");
        let idx_at_l1 = leaf_idx >> 1;
        let sibling_idx_at_l1 = idx_at_l1 ^ 1;
        let expected_l1 = imt_oracle.node(1, sibling_idx_at_l1 as usize);
        assert_eq!(
            path_sibling_l1,
            &expected_l1[..],
            "level 1 sibling for leaf {leaf_idx} must match IMT.node(1, {sibling_idx_at_l1})"
        );
    }

    // 32 seeded leaves populate only node(8, 0); it must hash non-zero
    let level8_idx_zero = imt_oracle.node(8, 0);
    assert_ne!(
        level8_idx_zero, [0u8; 32],
        "level-8 node 0 must hash from the seeded leaves"
    );
}
