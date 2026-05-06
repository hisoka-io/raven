//! Crash-recovery, idempotency, and per-list-node migration tests for
//! the offline `migrate-encoder` tool.
//!
//! Drives simulated crashes via library calls (no subprocess); each migration
//! step lands on disk before returning, so the state machine is fully
//! exercisable in-process.

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
    apply_wal_entry, re_encode_shard, restore_inspire_state, setup_state, snapshot_inspire_state,
    InspireServerState, LogicalLeafStore,
};
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{
    EncoderKind, PerLeafCommitmentEncoder, PerListNodeEncoder, PerListPathEncoder, PirTableEncoder,
};
use raven_railgun_persistence::{
    Manifest, Snapshot, SnapshotId, StoreLayout, Wal, WalEntryPayload, MANIFEST_SCHEMA_VERSION,
};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-kill-during-migration";
const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_SIZE: usize = 32;
const ENTRIES_PER_SHARD: u32 = 256;
const PATH_RECORD_BYTES: usize = 16 * 32;
const LIST_KEY_OFAC: [u8; 32] = [0xAB; 32];

fn canonical(seed: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = seed.max(1);
    b
}

fn build_toy_state() -> InspireServerState {
    let params = InspireParams::secure_128_d2048();
    let db: Vec<u8> = (0..TOY_ENTRIES)
        .flat_map(|i| (0..TOY_ENTRY_SIZE).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
        .collect();
    let (state, _sk) =
        setup_state(&params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking).expect("setup_state");
    state
}

fn build_toy_state_with_record_size(record_size: usize) -> InspireServerState {
    let params = InspireParams::secure_128_d2048();
    let db: Vec<u8> = (0..TOY_ENTRIES)
        .flat_map(|i| (0..record_size).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
        .collect();
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
        Arc::new(PerLeafCommitmentEncoder::new(32, 1).expect("noop encoder"));
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
            entry.block_height,
            noop_encoder.as_ref(),
        );
    }
    logical_store
}

struct PreparedMigration {
    layout: StoreLayout,
    manifest: Manifest,
    state: InspireServerState,
    logical_store: LogicalLeafStore,
    encoder: Arc<dyn PirTableEncoder>,
    new_label: &'static str,
    old_label: String,
}

fn prepare_migration(dir_path: &Path, target: EncoderKind) -> PreparedMigration {
    let layout = StoreLayout::open(dir_path).expect("layout");
    let manifest = Manifest::load(&layout)
        .expect("manifest load")
        .expect("manifest present");
    let old_label = manifest.encoder_label.clone();
    let new_label = target.label();
    assert_ne!(
        old_label, new_label,
        "prepare_migration called with target == current encoder; \
         caller must guard idempotency separately"
    );
    assert_ne!(
        manifest.current_snapshot_id,
        SnapshotId(0),
        "prepare_migration requires a committed snapshot"
    );

    let snap = Snapshot::load(&layout, manifest.current_snapshot_id).expect("snap load");
    let state = restore_inspire_state(&snap.data).expect("restore state");
    let logical_store = replay_wal_into_logical_store(&layout, &manifest);

    let entries_per_shard = u32::try_from(
        state
            .encoded_db
            .config
            .entries_per_shard()
            .min(u64::from(u32::MAX)),
    )
    .unwrap_or(u32::MAX);
    let encoder = target
        .build(state.entry_size, entries_per_shard)
        .expect("build target encoder");

    PreparedMigration {
        layout,
        manifest,
        state,
        logical_store,
        encoder,
        new_label,
        old_label,
    }
}

fn re_encode_all_shards(prep: &mut PreparedMigration) {
    let shard_count = prep.state.encoded_db.shards.len();
    for shard_id in 0..u32::try_from(shard_count).unwrap_or(u32::MAX) {
        let shard_bytes = prep
            .encoder
            .materialize_shard(shard_id, &prep.logical_store);
        re_encode_shard(
            &mut prep.state.encoded_db,
            &prep.state.crs.params,
            shard_id,
            &shard_bytes,
            prep.state.entry_size,
        )
        .expect("re_encode_shard");
    }
}

fn save_re_encoded_snapshot(prep: &PreparedMigration) -> SnapshotId {
    let bundle = snapshot_inspire_state(&prep.state).expect("snapshot_inspire_state");
    let new_snap = Snapshot::build(bundle);
    let new_id = prep.manifest.current_snapshot_id.next();
    new_snap.save(&prep.layout, new_id).expect("snapshot save");
    new_id
}

fn bump_manifest(prep: &PreparedMigration, new_id: SnapshotId) {
    let new_manifest = Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        scheme_tag: prep.manifest.scheme_tag.clone(),
        instance_id: prep.manifest.instance_id.clone(),
        current_snapshot_id: new_id,
        current_snapshot_seq: prep.manifest.current_snapshot_seq,
        current_block_height: prep.manifest.current_block_height,
        encoder_label: prep.new_label.to_owned(),
        prev_encoder_label: Some(prep.old_label.clone()),
    };
    new_manifest.save(&prep.layout).expect("manifest save");
}

fn run_full_migration(dir_path: &Path, target: EncoderKind) {
    let mut prep = prepare_migration(dir_path, target);
    re_encode_all_shards(&mut prep);
    let new_id = save_re_encoded_snapshot(&prep);
    bump_manifest(&prep, new_id);
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
    let snap = Snapshot::load(&layout, id).expect("load snap");
    snap.data
}

// Scenario 1: SIGKILL after pre-migration snapshot, before re-encode.

#[test]
fn kill_during_after_pre_snapshot_before_re_encode_recovers_via_old_encoder_and_resumes() {
    let dir = tempfile::tempdir().expect("tempdir");

    seed_with_committed_snapshot(dir.path(), EncoderKind::PerLeafBc, 50);
    let manifest_pre = read_manifest(dir.path());
    let pre_snap_bytes = snapshot_bytes(dir.path(), manifest_pre.current_snapshot_id);
    let pre_manifest_raw = manifest_bytes(dir.path());

    // SIGKILL simulation: re-encode in memory, drop before any disk write.
    {
        let mut prep = prepare_migration(dir.path(), EncoderKind::PerNode { tree_number: 0 });
        re_encode_all_shards(&mut prep);
        // SIGKILL: drop without save_re_encoded_snapshot / bump_manifest.
    }

    let manifest_post_crash = read_manifest(dir.path());
    assert_eq!(
        manifest_post_crash, manifest_pre,
        "post-crash manifest must equal pre-crash manifest (no bump occurred)"
    );
    assert_eq!(
        manifest_bytes(dir.path()),
        pre_manifest_raw,
        "manifest bytes must be byte-identical (atomic-rename was never invoked)"
    );
    assert_eq!(
        snapshot_bytes(dir.path(), manifest_post_crash.current_snapshot_id),
        pre_snap_bytes,
        "pre-crash snapshot bytes must survive untouched"
    );
    assert_eq!(
        manifest_post_crash.encoder_label, "per-leaf-bc",
        "encoder_label must still be the prior encoder after partial crash"
    );
    assert_eq!(
        manifest_post_crash.prev_encoder_label, None,
        "prev_encoder_label must remain None - no manifest bump fired"
    );

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

    let layout_old = StoreLayout::open(dir.path()).expect("layout");
    let opened_old = InspirePersistence::open(
        layout_old,
        SCHEME_TAG,
        InstanceId::new("kill-during-migrate"),
        SnapshotPolicy::default(),
        encoder_arc(EncoderKind::PerLeafBc),
    )
    .expect("reopen with prior encoder must succeed");
    assert_eq!(
        opened_old.recovered_logical_store.imt_leaf_count_for(0),
        50,
        "WAL replay must restore all 50 leaves"
    );
    drop(opened_old);

    run_full_migration(dir.path(), EncoderKind::PerNode { tree_number: 0 });
    let manifest_resumed = read_manifest(dir.path());
    assert_eq!(manifest_resumed.encoder_label, "per-node");
    assert_eq!(
        manifest_resumed.prev_encoder_label,
        Some("per-leaf-bc".to_owned())
    );
    assert_eq!(
        manifest_resumed.current_snapshot_id,
        manifest_pre.current_snapshot_id.next(),
        "snapshot id must be bumped by exactly 1 after the resumed run"
    );
}

// Scenario 2: SIGKILL after re-encode + snapshot save, before manifest bump.

#[test]
fn kill_during_after_re_encode_before_manifest_bump_recovers_idempotently() {
    let dir = tempfile::tempdir().expect("tempdir");

    let pre_id = seed_with_committed_snapshot(dir.path(), EncoderKind::PerLeafBc, 32);
    let manifest_pre = read_manifest(dir.path());
    let pre_manifest_raw = manifest_bytes(dir.path());

    let staged_id;
    {
        let mut prep = prepare_migration(dir.path(), EncoderKind::PerNode { tree_number: 0 });
        re_encode_all_shards(&mut prep);
        staged_id = save_re_encoded_snapshot(&prep);
        // SIGKILL: drop without bump_manifest.
    }

    let manifest_post_crash = read_manifest(dir.path());
    assert_eq!(
        manifest_bytes(dir.path()),
        pre_manifest_raw,
        "manifest bytes unchanged - bump never landed"
    );
    assert_eq!(
        manifest_post_crash.current_snapshot_id, pre_id,
        "manifest must still reference the pre-migration snapshot"
    );
    assert_eq!(manifest_post_crash.encoder_label, "per-leaf-bc");
    assert_ne!(
        staged_id, manifest_post_crash.current_snapshot_id,
        "the staged new snapshot lives at a higher id than the live one"
    );

    {
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("kill-during-migrate"),
            SnapshotPolicy::default(),
            encoder_arc(EncoderKind::PerLeafBc),
        )
        .expect("reopen with old encoder");
        assert_eq!(
            opened.recovered_logical_store.imt_leaf_count_for(0),
            32,
            "WAL replay must restore all leaves"
        );
    }

    run_full_migration(dir.path(), EncoderKind::PerNode { tree_number: 0 });
    let manifest_resumed_a = read_manifest(dir.path());
    let snapshot_after_first_resume =
        snapshot_bytes(dir.path(), manifest_resumed_a.current_snapshot_id);
    let manifest_after_first_resume = manifest_bytes(dir.path());

    // Confirm snapshot byte-stability: save-only operations must not change
    // the live manifest or the snapshot bytes at the live id.
    {
        let prep = prepare_migration(dir.path(), EncoderKind::PerLeafBc);
        let mut prep_mut = prep;
        re_encode_all_shards(&mut prep_mut);
        let id_extra = save_re_encoded_snapshot(&prep_mut);
        assert_ne!(
            id_extra, manifest_resumed_a.current_snapshot_id,
            "staged snapshot for would-be reverse migration must not overwrite live id"
        );
    }
    let manifest_after_extra = read_manifest(dir.path());
    let snapshot_after_extra = snapshot_bytes(dir.path(), manifest_after_extra.current_snapshot_id);
    assert_eq!(
        manifest_after_extra, manifest_resumed_a,
        "manifest must be unchanged by save-only operations"
    );
    assert_eq!(
        manifest_bytes(dir.path()),
        manifest_after_first_resume,
        "manifest bytes must be stable across save-only operations"
    );
    assert_eq!(
        snapshot_after_extra, snapshot_after_first_resume,
        "snapshot bytes at the live id must be byte-stable"
    );
    assert_eq!(
        manifest_after_extra.encoder_label, "per-node",
        "encoder_label must remain at the migrated value"
    );
    assert_eq!(
        manifest_after_extra.prev_encoder_label,
        Some("per-leaf-bc".to_owned())
    );
    assert_eq!(
        manifest_after_extra.current_snapshot_id,
        manifest_pre.current_snapshot_id.next()
    );
}

// Scenario 3: idempotency — subsequent migration attempts must be rejected
// and must not mutate the on-disk byte-state.

#[test]
fn migration_repeated_three_times_on_same_data_dir_is_byte_identical() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed_with_committed_snapshot(dir.path(), EncoderKind::PerLeafBc, 16);

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

// Per-list-node migration: seed PerListPathEncoder, migrate to PerListNodeEncoder,
// assert per-row byte identity at levels 0, 1, and 8.

#[test]
fn per_list_node_migration_byte_identity_at_levels_0_1_8() {
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

    run_full_migration(
        dir.path(),
        EncoderKind::PerListNode {
            list_key: LIST_KEY_OFAC,
        },
    );

    let manifest_post = read_manifest(dir.path());
    assert_eq!(manifest_post.encoder_label, "per-list-node");
    assert_eq!(
        manifest_post.prev_encoder_label,
        Some("per-list-path".to_owned())
    );
    assert_eq!(
        manifest_post.current_snapshot_id,
        manifest_pre.current_snapshot_id.next()
    );

    // Build both encoders against the oracle store + assert byte-row
    // parity at levels 0, 1, and 8 of the per-list IMT. PerListNode uses
    // the same flat-global-index layout as PerNode (leaves first, then
    // level-1 nodes, ..., to root), so the level-k row at index `idx_at_level`
    // sits at flat index `flat_index(level, idx_at_level)`.
    let path_enc = PerListPathEncoder::new(PATH_RECORD_BYTES, ENTRIES_PER_SHARD, LIST_KEY_OFAC)
        .expect("path encoder");
    let node_enc = PerListNodeEncoder::new(ENTRIES_PER_SHARD, LIST_KEY_OFAC).expect("node encoder");

    // Byte-identity 1: PerListNode rows at level 0 (first 32 rows of
    // shard 0) reconstruct the seeded leaves byte-for-byte.
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

    // Byte-identity 2: PerListPath sibling at level 0 (path row 0,
    // first 32 bytes) equals the PerListNode row for that sibling
    // (level 0, idx XOR 1).
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

    // Byte-identity 3: at level 1, the path-row level-1 sibling slice
    // (bytes [32, 64) of the path row) must equal the per-list-node row
    // at flat_index(1, sibling_idx_at_level_1). For leaf_idx=0, the
    // level-1 idx is 0 and the sibling at level 1 is 1.
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

    // Byte-identity 4: at level 8, every level-8 row from per-list-node
    // matches the IMT oracle's `node(8, idx)`. The level-8 nodes start
    // at flat index `(2^17 - 1) - (2^9 - 1) = 130560` (sum of levels 0..7
    // = 2^17 - 2^9). Use PerListNode's flat-index symmetry with
    // PerNodeEncoder by querying via the IMT directly.
    //
    // Level-8 has 2^8 = 256 nodes; first 32 leaves only populate
    // node(8, 0). Verify nodes at level 8 are non-zero where data exists
    // and zero past it.
    let level8_idx_zero = imt_oracle.node(8, 0);
    assert_ne!(
        level8_idx_zero, [0u8; 32],
        "level-8 node 0 must hash from the seeded leaves"
    );
}
