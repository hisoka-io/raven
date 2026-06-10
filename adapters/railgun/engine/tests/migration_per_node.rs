//! Integration tests for the offline encoder migration path.
//!
//! These tests do NOT import `raven-railgun-cli`; they call the engine +
//! persistence primitives directly, exactly as `migrate_encoder::run` does.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{
    apply_wal_entry, re_encode_shard, restore_inspire_state, setup_state, snapshot_inspire_state,
    InspireServerState, LogicalLeafStore,
};
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{EncoderKind, PerLeafCommitmentEncoder, PirTableEncoder};
use raven_railgun_persistence::{
    Manifest, Snapshot, SnapshotId, StoreLayout, Wal, WalEntryPayload, MANIFEST_SCHEMA_VERSION,
    SNAPSHOT_MAGIC,
};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-migration-test";
const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_SIZE: usize = 32;
const ENTRIES_PER_SHARD: u32 = 256;

fn build_toy_state() -> InspireServerState {
    let params = InspireParams::secure_128_d2048();
    let db: Vec<u8> = (0..TOY_ENTRIES)
        .flat_map(|i| (0..TOY_ENTRY_SIZE).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
        .collect();
    let (state, _sk) =
        setup_state(&params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking).expect("setup_state");
    state
}

fn encoder_arc(kind: EncoderKind) -> Arc<dyn PirTableEncoder> {
    let record_size = match kind {
        EncoderKind::PerLeafPath { .. } | EncoderKind::PerListPath { .. } => 16 * 32,
        _ => TOY_ENTRY_SIZE,
    };
    kind.build(record_size, ENTRIES_PER_SHARD)
        .expect("build encoder")
}

fn canonical(seed: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = seed.max(1);
    b
}

fn bootstrap_with_committed_snapshot(
    dir_path: &std::path::Path,
    encoder_kind: EncoderKind,
    leaf_count: u32,
) {
    let layout = StoreLayout::open(dir_path).expect("layout");
    let opened = InspirePersistence::open(
        layout,
        SCHEME_TAG,
        InstanceId::new("migrate-test"),
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
}

fn run_migration(dir_path: &std::path::Path, target: EncoderKind) -> Result<(), String> {
    let layout = StoreLayout::open(dir_path).map_err(|e| format!("open: {e}"))?;

    let manifest = Manifest::load(&layout)
        .map_err(|e| format!("manifest load: {e}"))?
        .ok_or_else(|| "no manifest".to_owned())?;

    let old_label = manifest.encoder_label.clone();
    let new_label = target.label();

    if old_label == new_label {
        return Err(format!(
            "encoder is already '{new_label}'; nothing to migrate"
        ));
    }
    if manifest.current_snapshot_id == SnapshotId(0) {
        return Err("no committed snapshot (id=0)".to_owned());
    }

    let snap = Snapshot::load(&layout, manifest.current_snapshot_id, SNAPSHOT_MAGIC)
        .map_err(|e| format!("snap load: {e}"))?;
    let mut state = restore_inspire_state(&snap.data).map_err(|e| format!("restore: {e}"))?;

    let noop_encoder: Arc<dyn PirTableEncoder> =
        Arc::new(PerLeafCommitmentEncoder::new(32, 1).map_err(|e| format!("noop encoder: {e}"))?);
    let wal_floor = manifest.current_snapshot_seq.checked_sub(1);
    let wal = Wal::open(&layout, wal_floor).map_err(|e| format!("wal open: {e}"))?;
    let replay = wal.replay().map_err(|e| format!("wal replay: {e}"))?;
    let mut logical_store = LogicalLeafStore::new();
    for entry in &replay.entries {
        if entry.seq < manifest.current_snapshot_seq {
            continue;
        }
        let payload: WalEntryPayload = bincode::deserialize(&entry.payload)
            .map_err(|e| format!("wal deser at seq {}: {e}", entry.seq))?;
        let _ = apply_wal_entry(
            &mut logical_store,
            &payload,
            entry.marker,
            noop_encoder.as_ref(),
        );
    }

    let entries_per_shard = u32::try_from(
        state
            .encoded_db
            .config
            .entries_per_shard()
            .min(u64::from(u32::MAX)),
    )
    .unwrap_or(u32::MAX);
    let entry_size = state.entry_size;
    let encoder = target
        .build(entry_size, entries_per_shard)
        .map_err(|e| format!("build encoder '{new_label}': {e}"))?;

    let shard_count = state.encoded_db.shards.len();
    for shard_id in 0..u32::try_from(shard_count).unwrap_or(u32::MAX) {
        let shard_bytes = encoder.materialize_shard(shard_id, &logical_store);
        re_encode_shard(
            Arc::make_mut(&mut state.encoded_db),
            &state.crs.params,
            shard_id,
            &shard_bytes,
            entry_size,
        )
        .map_err(|e| format!("re_encode_shard {shard_id}: {e}"))?;
    }

    let bundle =
        snapshot_inspire_state(&state).map_err(|e| format!("snapshot_inspire_state: {e}"))?;
    let new_snap = Snapshot::build(bundle, SNAPSHOT_MAGIC);
    let new_id = manifest.current_snapshot_id.next();
    new_snap
        .save(&layout, new_id)
        .map_err(|e| format!("snapshot save: {e}"))?;

    let new_manifest = Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        scheme_tag: manifest.scheme_tag.clone(),
        instance_id: manifest.instance_id.clone(),
        current_snapshot_id: new_id,
        current_snapshot_seq: manifest.current_snapshot_seq,
        current_marker: manifest.current_marker,
        encoder_label: new_label.to_owned(),
        prev_encoder_label: Some(old_label.clone()),
    };
    new_manifest
        .save(&layout)
        .map_err(|e| format!("manifest save: {e}"))?;

    Ok(())
}

#[test]
fn migrate_encoder_per_leaf_bc_to_per_node_round_trips() {
    let dir = tempfile::tempdir().expect("tempdir");
    bootstrap_with_committed_snapshot(dir.path(), EncoderKind::PerLeafBc, 32);

    let layout_pre = StoreLayout::open(dir.path()).expect("layout pre");
    let manifest_pre = Manifest::load(&layout_pre)
        .expect("load pre")
        .expect("present pre");
    assert_eq!(manifest_pre.encoder_label, "per-leaf-bc");
    assert_eq!(manifest_pre.prev_encoder_label, None);
    let pre_snap_id = manifest_pre.current_snapshot_id;
    assert_ne!(
        pre_snap_id,
        SnapshotId(0),
        "initial commit must have advanced snapshot_id"
    );

    run_migration(dir.path(), EncoderKind::PerNode { tree_number: 0 }).expect("migrate");

    let layout_post = StoreLayout::open(dir.path()).expect("layout post");
    let manifest_post = Manifest::load(&layout_post)
        .expect("load post")
        .expect("present post");
    assert_eq!(
        manifest_post.encoder_label, "per-node",
        "encoder_label must be 'per-node' after migration"
    );
    assert_eq!(
        manifest_post.prev_encoder_label,
        Some("per-leaf-bc".to_owned()),
        "prev_encoder_label must record the prior label"
    );
    assert_eq!(
        manifest_post.current_snapshot_id,
        pre_snap_id.next(),
        "snapshot id must be bumped by exactly 1"
    );
    assert_eq!(manifest_post.scheme_tag, SCHEME_TAG);
    assert_eq!(manifest_post.instance_id, "migrate-test");
}

#[test]
fn migrate_encoder_idempotent_on_same_label() {
    let dir = tempfile::tempdir().expect("tempdir");
    bootstrap_with_committed_snapshot(dir.path(), EncoderKind::PerLeafBc, 8);

    run_migration(dir.path(), EncoderKind::PerNode { tree_number: 0 }).expect("first migrate");

    let err = run_migration(dir.path(), EncoderKind::PerNode { tree_number: 0 })
        .expect_err("second migrate must fail");
    assert!(
        err.contains("already") || err.contains("nothing to migrate"),
        "error must mention idempotency; got: {err}"
    );
}
