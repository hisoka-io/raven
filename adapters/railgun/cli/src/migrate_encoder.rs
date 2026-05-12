//! Offline encoder migration: re-encode all shards under a new encoder and bump the manifest.
//! The server must be stopped first; mutual exclusion is enforced via `flock(LOCK_EX | LOCK_NB)`.

#![allow(clippy::print_stdout)]

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use raven_railgun_core::AdapterError;
use raven_railgun_engine::inspire::{
    apply_wal_entry, restore_inspire_state_v6, snapshot_inspire_state_v6,
};
use raven_railgun_engine::inspire::re_encode_shard;
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_persistence::{
    Manifest, Snapshot, SnapshotId, StoreLayout, Wal, WalEntryPayload,
};

#[allow(clippy::too_many_lines)]
pub fn run(data_dir: &Path, target: EncoderKind) -> anyhow::Result<()> {
    // open_with_lock acquires flock(LOCK_EX | LOCK_NB); fails with LockHeld if a live server
    // holds the data_dir. Lock guard bound for the function's lifetime.
    let (layout, _data_dir_lock) = StoreLayout::open_with_lock(data_dir).map_err(|e| {
        anyhow::anyhow!(
            "open data_dir {} (with exclusive lock): {e}. \
             A live raven-railgun process holds this data_dir; \
             stop the server before running `migrate-encoder`.",
            data_dir.display()
        )
    })?;

    let manifest = Manifest::load(&layout)
        .map_err(|e| anyhow::anyhow!("manifest load: {e}"))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no manifest at {}; data_dir is empty or uninitialized",
                data_dir.display()
            )
        })?;

    let old_label = manifest.encoder_label.clone();
    let new_label = target.label();

    if old_label == new_label {
        anyhow::bail!(
            "encoder is already '{new_label}'; nothing to migrate \
             (data_dir: {})",
            data_dir.display()
        );
    }

    if manifest.current_snapshot_id == SnapshotId(0) {
        anyhow::bail!(
            "manifest current_snapshot_id is 0 (no committed snapshot yet); \
             boot the server once to take the initial snapshot before migrating"
        );
    }

    let snap = Snapshot::load(&layout, manifest.current_snapshot_id)
        .map_err(|e| anyhow::anyhow!("snapshot load: {e}"))?;

    // V6 dispatcher: returns `(state, embedded_store)` for V6 snapshots and
    // falls back to a default-empty store for legacy V5 bytes (with a
    // `tracing::warn` from the helper). The embedded store seeds the WAL
    // replay base below, mirroring the open path at `InspirePersistence::open`.
    let (mut state, recovered_seed_store) = restore_inspire_state_v6(&snap.data)
        .map_err(|e| anyhow::anyhow!("restore_inspire_state_v6: {e}"))?;

    // Replay WAL entries past the snapshot floor onto the recovered seed
    // store (matches `InspirePersistence::open`). The noop encoder is only
    // needed for `apply_wal_entry`'s dirty-shard tracking, which is
    // irrelevant on the offline migration path.
    let noop_encoder: Arc<dyn PirTableEncoder> = {
        use raven_railgun_engine::pir_table::PerLeafCommitmentEncoder;
        Arc::new(
            PerLeafCommitmentEncoder::new(32, 1)
                .map_err(|e| anyhow::anyhow!("noop encoder: {e}"))?,
        )
    };

    let wal_floor = manifest.current_snapshot_seq.checked_sub(1);
    let wal = Wal::open(&layout, wal_floor).map_err(|e| anyhow::anyhow!("wal open: {e}"))?;
    let replay = wal
        .replay()
        .map_err(|e| anyhow::anyhow!("wal replay: {e}"))?;

    let mut logical_store = recovered_seed_store;
    for entry in &replay.entries {
        if entry.seq < manifest.current_snapshot_seq {
            continue;
        }
        let payload: WalEntryPayload = bincode::deserialize(&entry.payload)
            .map_err(|e| anyhow::anyhow!("wal payload deserialize at seq {}: {e}", entry.seq))?;
        if let Err(AdapterError::InvalidQuery(msg)) = apply_wal_entry(
            &mut logical_store,
            &payload,
            entry.block_height,
            noop_encoder.as_ref(),
        ) {
            tracing::warn!(
                seq = entry.seq,
                "migrate-encoder: skipping invalid wal entry: {msg}"
            );
        }
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
        .map_err(|e| anyhow::anyhow!("build encoder '{new_label}': {e}"))?;

    let shard_count = state.encoded_db.shards.len();
    let t_start = Instant::now();

    for shard_id in 0..u32::try_from(shard_count).unwrap_or(u32::MAX) {
        let shard_bytes = encoder.materialize_shard(shard_id, &logical_store);
        re_encode_shard(
            Arc::make_mut(&mut state.encoded_db),
            &state.crs.params,
            shard_id,
            &shard_bytes,
            entry_size,
        )
        .map_err(|e| anyhow::anyhow!("re_encode_shard {shard_id}: {e}"))?;
    }

    // V6 envelope: re-embed the `LogicalLeafStore` we just rebuilt so the
    // post-migration on-disk state stays internally consistent with the
    // V6 manifest stamped below. The pre-fix writer (`snapshot_inspire_state`)
    // dropped the store, leaving V6 manifest + V5 body + empty store — every
    // subsequent open returned `recovered_logical_store = default::()` and
    // chain events landed against an empty store.
    let bundle = snapshot_inspire_state_v6(&state, &logical_store)
        .map_err(|e| anyhow::anyhow!("snapshot_inspire_state_v6: {e}"))?;
    let new_snap = Snapshot::build(bundle);
    let new_id = manifest.current_snapshot_id.next();
    new_snap
        .save(&layout, new_id)
        .map_err(|e| anyhow::anyhow!("snapshot save: {e}"))?;

    // current_snapshot_seq stays the same: no new WAL events landed since the snapshot we read.
    let new_manifest = Manifest {
        schema_version: raven_railgun_persistence::MANIFEST_SCHEMA_VERSION,
        scheme_tag: manifest.scheme_tag.clone(),
        instance_id: manifest.instance_id.clone(),
        current_snapshot_id: new_id,
        current_snapshot_seq: manifest.current_snapshot_seq,
        current_block_height: manifest.current_block_height,
        encoder_label: new_label.to_owned(),
        prev_encoder_label: Some(old_label.clone()),
    };
    new_manifest
        .save(&layout)
        .map_err(|e| anyhow::anyhow!("manifest save: {e}"))?;

    let elapsed_ms = t_start.elapsed().as_millis();
    let data_dir_display = data_dir.display();
    println!(
        "migrate-encoder: {old_label} -> {new_label} | {shard_count} shards | \
         {elapsed_ms} ms | data_dir: {data_dir_display}"
    );
    Ok(())
}
