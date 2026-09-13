//! Main+sidecar fold and atomic reset. Kept demo-local: `Engine` in `crates/server` is a flat
//! registry, one consumer short of the floor that earns an abstraction.
//!
//! Ordering is load-bearing: the old main serves throughout, the main swap precedes the durable
//! commit, dirty shards clear only after it succeeds, and the sidecar resets LAST. A crash before
//! the commit loses nothing - `recover` rebuilds from the last snapshot plus the WAL replay.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bytes::Bytes;
use raven_core::storage::{Snapshot as _, StorageBackend as _};
use raven_core::{InstanceId, MemoryStore};
use raven_inspire::params::{InspireParams, ShardConfig};
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::{encode_database, EncodedDatabase, ShardData};
use raven_server::{InstanceRole, PirInstance};
use raven_storage::{
    apply_retention, open_recovery, Manifest, ManifestShape, RetentionPolicy, SnapshotId,
    StoreLayout, Wal, MANIFEST_SCHEMA_VERSION,
};

use crate::ingest::BalanceWalPayload;
use crate::{
    build_flat_state, EthStateError, FlatBalanceScheme, FlatServerState, ENTRIES_PER_SHARD,
    ENTRY_SIZE,
};

/// 16-byte version magic for the demo's snapshot payload.
pub const SNAPSHOT_MAGIC: [u8; 16] = *b"RAVEN_ETHSTATE_1";

fn swap_failed(e: raven_core::ServerError) -> EthStateError {
    EthStateError::Setup(format!("swap state: {e}"))
}

const SCHEME_TAG: &str = "inspire-flat-balance";
const ENCODER_LABEL: &str = "flat-balance-v1";
const INSTANCE_ID: &str = "eth-state";

fn validate_entry_size(entry_size: usize) -> Result<(), EthStateError> {
    if entry_size != ENTRY_SIZE {
        return Err(EthStateError::Setup(format!(
            "eth-state entry width mismatch: expected {ENTRY_SIZE} bytes, got {entry_size} bytes"
        )));
    }
    Ok(())
}

/// `shard_id` for a flat leaf index.
///
/// ```
/// assert_eq!(eth_state::fold::shard_of(0), 0);
/// assert_eq!(eth_state::fold::shard_of(2047), 0);
/// assert_eq!(eth_state::fold::shard_of(2048), 1);
/// ```
pub fn shard_of(flat_index: u64) -> u32 {
    (flat_index / ENTRIES_PER_SHARD as u64) as u32
}

/// Main+sidecar pair with the source-of-truth store and the durability seam.
pub struct MainSidecar {
    store: MemoryStore,
    /// Serves the corpus as of the last fold.
    pub main: Arc<PirInstance<FlatBalanceScheme>>,
    /// Serves rows changed since the last fold.
    pub sidecar: Arc<PirInstance<FlatBalanceScheme>>,
    params: InspireParams,
    entry_size: usize,
    dirty: BTreeSet<u32>,
    changed: BTreeMap<u64, Bytes>,
    re_encode_count: usize,
    layout: StoreLayout,
    wal: Wal,
    next_snapshot_id: u64,
    marker: u64,
}

impl MainSidecar {
    /// Seed a Live main from a flat record buffer plus an empty sidecar, opening the store
    /// layout under `data_dir`. Refuses widths other than [`ENTRY_SIZE`] before opening it.
    pub fn seed(
        params: &InspireParams,
        database: &[u8],
        entry_size: usize,
        data_dir: impl Into<std::path::PathBuf>,
        seed: u64,
    ) -> Result<(Self, RlweSecretKey, RlweSecretKey), EthStateError> {
        validate_entry_size(entry_size)?;
        let layout = StoreLayout::open(data_dir.into())
            .map_err(|e| EthStateError::Setup(format!("store layout open: {e}")))?;

        let store = MemoryStore::new();
        let total = database.len() / entry_size;
        let mut txn = store
            .begin()
            .map_err(|e| EthStateError::Setup(format!("store begin: {e}")))?;
        for i in 0..total {
            let off = i * entry_size;
            txn.insert(
                i as u64,
                Bytes::copy_from_slice(&database[off..off + entry_size]),
            )
            .map_err(|e| EthStateError::Setup(format!("store insert: {e}")))?;
        }
        txn.commit()
            .map_err(|e| EthStateError::Setup(format!("store commit: {e}")))?;

        let (main_state, main_sk) = build_flat_state(params, database, entry_size, seed)?;
        // Sidecar mirrors main's full shard structure; a truly-small sidecar would leak which
        // shards it holds. Empty means an all-zero corpus the size of main.
        let empty = vec![0u8; total.max(1) * entry_size];
        let (side_state, side_sk) = build_flat_state(params, &empty, entry_size, seed ^ 0x5ECA)?;

        let main = Arc::new(PirInstance::<FlatBalanceScheme>::new(
            InstanceId::new("main"),
            InstanceRole::Live,
            main_state,
        ));
        let sidecar = Arc::new(PirInstance::<FlatBalanceScheme>::new(
            InstanceId::new("sidecar"),
            InstanceRole::Sidecar,
            side_state,
        ));

        let wal =
            Wal::open(&layout, None).map_err(|e| EthStateError::Setup(format!("wal open: {e}")))?;
        let mut this = Self {
            store,
            main,
            sidecar,
            params: params.clone(),
            entry_size,
            dirty: BTreeSet::new(),
            changed: BTreeMap::new(),
            re_encode_count: 0,
            layout,
            wal,
            next_snapshot_id: 1,
            marker: 0,
        };
        // Base snapshot so a later recover() has something to load.
        this.commit_v6()?;
        Ok((this, main_sk, side_sk))
    }

    /// Fold-time main shard re-encodes so far. A dedup reuse of the sidecar's shard skips the
    /// encode and does not increment this.
    pub fn re_encode_count(&self) -> usize {
        self.re_encode_count
    }

    /// Highest block height applied so far; monotonic.
    pub fn marker(&self) -> u64 {
        self.marker
    }

    /// Store generation; advances once per non-empty update batch.
    pub fn generation(&self) -> u64 {
        self.store.generation()
    }

    /// A consistent snapshot of the source-of-truth store.
    pub fn store_snapshot(&self) -> Result<raven_core::MemorySnapshot, EthStateError> {
        self.store
            .snapshot_concrete()
            .map_err(|e| EthStateError::Setup(format!("store snapshot: {e}")))
    }

    /// Apply in-place balance updates at block height `marker`: write the store, mark dirty
    /// shards, refresh the sidecar so the new values answer queries before the next fold.
    pub fn apply_updates(
        &mut self,
        marker: u64,
        updates: &[(u64, Bytes)],
    ) -> Result<(), EthStateError> {
        if updates.is_empty() {
            return Ok(());
        }
        // Write-ahead: the WAL append MUST precede the resident-store mutation.
        for (leaf, value) in updates {
            let balance_be: [u8; ENTRY_SIZE] = value
                .as_ref()
                .try_into()
                .map_err(|_| EthStateError::RecordTooLarge { got: value.len() })?;
            let payload = BalanceWalPayload::BalanceUpdate {
                flat_index: *leaf,
                balance_be,
            };
            self.wal
                .append(&payload, marker)
                .map_err(|e| EthStateError::Setup(format!("wal append: {e}")))?;
        }
        let mut txn = self
            .store
            .begin()
            .map_err(|e| EthStateError::Setup(format!("store begin: {e}")))?;
        for (leaf, value) in updates {
            txn.insert(*leaf, value.clone())
                .map_err(|e| EthStateError::Setup(format!("store insert: {e}")))?;
            self.dirty.insert(shard_of(*leaf));
            self.changed.insert(*leaf, value.clone());
        }
        txn.commit()
            .map_err(|e| EthStateError::Setup(format!("store commit: {e}")))?;
        self.marker = self.marker.max(marker);

        // Main must cover a newly-appended shard BEFORE the sidecar refresh, or a pre-fold read
        // of that leaf has no main leg to fan out to.
        let touched: BTreeSet<u32> = updates.iter().map(|(l, _)| shard_of(*l)).collect();
        self.ensure_main_covers(&touched)?;
        for shard_id in &touched {
            self.rebuild_sidecar_shard(*shard_id)?;
        }
        Ok(())
    }

    /// Add an all-zero shard to main for each touched shard it lacks, in one swap.
    fn ensure_main_covers(&self, shards: &BTreeSet<u32>) -> Result<(), EthStateError> {
        let snap = self.main.current_snapshot();
        let present: BTreeSet<u32> = snap.state.encoded_db.shards.iter().map(|s| s.id).collect();
        let missing: Vec<u32> = shards
            .iter()
            .copied()
            .filter(|s| !present.contains(s))
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        let mut new_encoded: EncodedDatabase = snap.state.encoded_db.clone();
        let zero = vec![0u8; ENTRIES_PER_SHARD * self.entry_size];
        for shard_id in missing {
            re_encode_shard(
                &mut new_encoded,
                shard_id,
                &zero,
                &self.params,
                self.entry_size,
            )?;
        }
        let new_state = FlatServerState {
            crs: snap.state.crs.clone(),
            encoded_db: new_encoded,
            #[cfg(feature = "cached-respond")]
            cache: snap.state.cache.clone(),
        };
        self.main
            .swap_state(new_state, snap.epoch.next())
            .map_err(swap_failed)?;
        Ok(())
    }

    /// Fold the sidecar into main, then reset. Ordering: re-encode dirty shards -> swap main
    /// (old main keeps serving) -> durable commit -> clear dirty -> reset sidecar LAST.
    pub fn fold(&mut self) -> Result<(), EthStateError> {
        if self.dirty.is_empty() {
            return Ok(());
        }
        let snap = self.main.current_snapshot();
        // Full clone rather than Arc-shared shards: sub-ms at this scale, and pointer-sharing
        // would need EncodedDatabase to change shape.
        let mut new_encoded: EncodedDatabase = snap.state.encoded_db.clone();
        let side_snap = self.sidecar.current_snapshot();

        let store_snap = self
            .store
            .snapshot_concrete()
            .map_err(|e| EthStateError::Setup(format!("store snapshot: {e}")))?;

        let dirty: Vec<u32> = self.dirty.iter().copied().collect();
        for shard_id in &dirty {
            let bytes = materialize_shard_bytes(&store_snap, *shard_id, self.entry_size)?;
            // Encode is deterministic in the bytes, so an identical sidecar shard can be reused
            // verbatim instead of re-encoded.
            if let Some(shard) = reuse_sidecar_shard(
                &side_snap.state.encoded_db,
                *shard_id,
                &self.changed,
                &bytes,
                self.entry_size,
            ) {
                set_shard_slot(&mut new_encoded, shard);
            } else {
                re_encode_shard(
                    &mut new_encoded,
                    *shard_id,
                    &bytes,
                    &self.params,
                    self.entry_size,
                )?;
                self.re_encode_count += 1;
            }
        }

        let new_state = FlatServerState {
            crs: snap.state.crs.clone(),
            encoded_db: new_encoded,
            #[cfg(feature = "cached-respond")]
            cache: snap.state.cache.clone(),
        };
        // Atomic swap: in-flight reads against the old Arc complete unaffected.
        self.main
            .swap_state(new_state, snap.epoch.next())
            .map_err(swap_failed)?;

        // MUST precede the dirty clear: until it lands, recovery is snapshot plus WAL. Its
        // publish also seals the log, so the next recover replays only the post-fold tail.
        self.commit_v6()?;

        self.dirty.clear();
        self.changed.clear();
        // LAST: until the swap is durable the sidecar still serves the un-folded values, so a
        // recently-updated balance is never absent from both engines.
        self.reset_sidecar()?;
        Ok(())
    }

    /// Stops inside the genuine `[swap_state .. commit_v6)` window: no commit, no dirty clear,
    /// no sidecar reset.
    #[cfg(test)]
    pub fn fold_abort_after_swap(&mut self) -> Result<(), EthStateError> {
        if self.dirty.is_empty() {
            return Ok(());
        }
        let snap = self.main.current_snapshot();
        let mut new_encoded: EncodedDatabase = snap.state.encoded_db.clone();
        let store_snap = self
            .store
            .snapshot_concrete()
            .map_err(|e| EthStateError::Setup(format!("store snapshot: {e}")))?;
        for shard_id in self.dirty.iter().copied().collect::<Vec<_>>() {
            let bytes = materialize_shard_bytes(&store_snap, shard_id, self.entry_size)?;
            re_encode_shard(
                &mut new_encoded,
                shard_id,
                &bytes,
                &self.params,
                self.entry_size,
            )?;
        }
        let new_state = FlatServerState {
            crs: snap.state.crs.clone(),
            encoded_db: new_encoded,
            #[cfg(feature = "cached-respond")]
            cache: snap.state.cache.clone(),
        };
        self.main
            .swap_state(new_state, snap.epoch.next())
            .map_err(swap_failed)?;
        Ok(())
    }

    /// Rebuild one sidecar shard from the changed-rows view; unchanged leaves stay zero.
    fn rebuild_sidecar_shard(&self, shard_id: u32) -> Result<(), EthStateError> {
        let snap = self.sidecar.current_snapshot();
        let mut new_encoded: EncodedDatabase = snap.state.encoded_db.clone();
        let buf = sparse_shard_bytes(shard_id, &self.changed, self.entry_size);
        re_encode_shard(
            &mut new_encoded,
            shard_id,
            &buf,
            &self.params,
            self.entry_size,
        )?;
        let new_state = FlatServerState {
            crs: snap.state.crs.clone(),
            encoded_db: new_encoded,
            #[cfg(feature = "cached-respond")]
            cache: snap.state.cache.clone(),
        };
        self.sidecar
            .swap_state(new_state, snap.epoch.next())
            .map_err(swap_failed)?;
        Ok(())
    }

    /// Reset the sidecar to an all-zero (empty) corpus.
    fn reset_sidecar(&self) -> Result<(), EthStateError> {
        let snap = self.sidecar.current_snapshot();
        let mut cleared: EncodedDatabase = snap.state.encoded_db.clone();
        let ids: Vec<u32> = cleared.shards.iter().map(|s| s.id).collect();
        let zero = vec![0u8; ENTRIES_PER_SHARD * self.entry_size];
        for id in ids {
            re_encode_shard(&mut cleared, id, &zero, &self.params, self.entry_size)?;
        }
        let new_state = FlatServerState {
            crs: snap.state.crs.clone(),
            encoded_db: cleared,
            #[cfg(feature = "cached-respond")]
            cache: snap.state.cache.clone(),
        };
        self.sidecar
            .swap_state(new_state, snap.epoch.next())
            .map_err(swap_failed)?;
        Ok(())
    }

    /// Persist the store rows plus manifest. The store already holds the post-update rows, so a
    /// recovery from this snapshot reconstructs the folded state.
    fn commit_v6(&mut self) -> Result<(), EthStateError> {
        let store_snap = self
            .store
            .snapshot_concrete()
            .map_err(|e| EthStateError::Setup(format!("store snapshot: {e}")))?;
        let mut rows: Vec<(u64, Vec<u8>)> = Vec::new();
        for row in store_snap.scan() {
            let (k, v) = row.map_err(|e| EthStateError::Setup(format!("store scan: {e}")))?;
            rows.push((k, v.to_vec()));
        }
        let data = bincode::serialize(&rows)
            .map_err(|e| EthStateError::Setup(format!("snapshot serialize: {e}")))?;
        let snap_id = SnapshotId(self.next_snapshot_id);
        let mut manifest = Manifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            scheme_tag: SCHEME_TAG.to_string(),
            instance_id: INSTANCE_ID.to_string(),
            current_snapshot_id: snap_id,
            current_snapshot_seq: self.wal.next_seq(),
            current_marker: self.marker,
            encoder_label: ENCODER_LABEL.to_string(),
            prev_encoder_label: None,
            entry_size_bytes: Some(ENTRY_SIZE),
            rows_per_shard: Some(ENTRIES_PER_SHARD as u64),
        };
        raven_storage::publish_snapshot(
            &self.layout,
            &self.wal,
            &mut manifest,
            snap_id,
            data,
            SNAPSHOT_MAGIC,
            |m, id, floor| {
                m.current_snapshot_id = id;
                m.current_snapshot_seq = floor;
            },
        )
        .map_err(|e| EthStateError::Setup(format!("publish snapshot: {e}")))?;
        self.next_snapshot_id += 1;
        apply_retention(&self.layout, snap_id, RetentionPolicy::default())
            .map_err(|e| EthStateError::Setup(format!("snapshot retention: {e}")))?;
        Ok(())
    }

    /// Rebuild the store rows and the main engine from the latest snapshot plus WAL replay.
    /// Refuses widths other than [`ENTRY_SIZE`] before opening the store layout.
    pub fn recover(
        params: &InspireParams,
        entry_size: usize,
        data_dir: impl Into<std::path::PathBuf>,
        seed: u64,
    ) -> Result<(Self, RlweSecretKey, RlweSecretKey), EthStateError> {
        validate_entry_size(entry_size)?;
        let layout = StoreLayout::open(data_dir.into())
            .map_err(|e| EthStateError::Setup(format!("store layout open: {e}")))?;
        let recovery = open_recovery(&layout, SNAPSHOT_MAGIC, |manifest| {
            manifest.validate_identity(SCHEME_TAG, INSTANCE_ID, ENCODER_LABEL)?;
            manifest.validate_shape(ManifestShape {
                entry_size_bytes: entry_size,
                rows_per_shard: ENTRIES_PER_SHARD as u64,
            })
        })
        .map_err(|e| EthStateError::Setup(format!("recovery open: {e}")))?
        .ok_or_else(|| EthStateError::Setup("no manifest to recover from".to_string()))?;
        let manifest = recovery.manifest;
        let snap = recovery.snapshot.ok_or_else(|| {
            EthStateError::Setup(
                "manifest snapshot id 0 denotes no committed snapshot; re-seed this data_dir"
                    .to_owned(),
            )
        })?;
        let snapshot_rows: Vec<(u64, Vec<u8>)> = bincode::deserialize(&snap.data)
            .map_err(|e| EthStateError::Setup(format!("snapshot decode: {e}")))?;

        // Replay is an idempotent overwrite, so a re-applied pre-snapshot entry is harmless.
        let mut merged: BTreeMap<u64, [u8; ENTRY_SIZE]> = BTreeMap::new();
        for (k, v) in snapshot_rows {
            let mut rec = [0u8; ENTRY_SIZE];
            let n = v.len().min(ENTRY_SIZE);
            rec[..n].copy_from_slice(&v[..n]);
            merged.insert(k, rec);
        }
        // Open at last-committed-seq so post-recovery appends stay monotonic above any archived
        // range; None at seq 0 means a fresh WAL.
        let wal = recovery.wal;
        let replay = recovery.replay;
        for entry in replay.entries {
            let payload: BalanceWalPayload = bincode::deserialize(&entry.payload)
                .map_err(|e| EthStateError::Setup(format!("wal payload decode: {e}")))?;
            match payload {
                BalanceWalPayload::BalanceUpdate {
                    flat_index,
                    balance_be,
                } => {
                    merged.insert(flat_index, balance_be);
                }
            }
        }

        let max_leaf = merged.keys().last().copied().unwrap_or(0);
        let total = (max_leaf as usize) + 1;
        let mut database = vec![0u8; total * entry_size];
        let store = MemoryStore::new();
        let mut txn = store
            .begin()
            .map_err(|e| EthStateError::Setup(format!("store begin: {e}")))?;
        for (k, rec) in &merged {
            let off = (*k as usize) * entry_size;
            database[off..off + entry_size].copy_from_slice(&rec[..entry_size]);
            txn.insert(*k, Bytes::copy_from_slice(rec))
                .map_err(|e| EthStateError::Setup(format!("store insert: {e}")))?;
        }
        txn.commit()
            .map_err(|e| EthStateError::Setup(format!("store commit: {e}")))?;

        let (main_state, main_sk) = build_flat_state(params, &database, entry_size, seed)?;
        // Full-width sidecar; a truly-small one would leak which shards it holds.
        let empty = vec![0u8; total.max(1) * entry_size];
        let (side_state, side_sk) = build_flat_state(params, &empty, entry_size, seed ^ 0x5ECA)?;
        let main = Arc::new(PirInstance::<FlatBalanceScheme>::new(
            InstanceId::new("main"),
            InstanceRole::Live,
            main_state,
        ));
        let sidecar = Arc::new(PirInstance::<FlatBalanceScheme>::new(
            InstanceId::new("sidecar"),
            InstanceRole::Sidecar,
            side_state,
        ));
        Ok((
            Self {
                store,
                main,
                sidecar,
                params: params.clone(),
                entry_size,
                dirty: BTreeSet::new(),
                changed: BTreeMap::new(),
                re_encode_count: 0,
                layout,
                wal,
                next_snapshot_id: manifest.current_snapshot_id.0 + 1,
                marker: manifest.current_marker,
            },
            main_sk,
            side_sk,
        ))
    }
}

/// One shard's flat bytes, zero-padded in empty slots.
pub fn materialize_shard_bytes(
    snap: &dyn raven_core::storage::Snapshot,
    shard_id: u32,
    entry_size: usize,
) -> Result<Vec<u8>, EthStateError> {
    let shard_start = shard_id as u64 * ENTRIES_PER_SHARD as u64;
    let shard_end = shard_start + ENTRIES_PER_SHARD as u64;
    let mut buf = vec![0u8; ENTRIES_PER_SHARD * entry_size];
    for row in snap.scan_range(shard_start..shard_end) {
        let (k, v) = row.map_err(|e| EthStateError::Setup(format!("store scan: {e}")))?;
        let off = (k - shard_start) as usize * entry_size;
        let n = v.len().min(entry_size);
        buf[off..off + n].copy_from_slice(&v[..n]);
    }
    Ok(buf)
}

/// Re-encode one shard in place, preserving the slot id or growing into a new one.
fn re_encode_shard(
    encoded: &mut EncodedDatabase,
    shard_id: u32,
    shard_bytes: &[u8],
    params: &InspireParams,
    entry_size: usize,
) -> Result<(), EthStateError> {
    let cfg = ShardConfig {
        shard_size_bytes: (params.ring_dim as u64) * (entry_size as u64),
        entry_size_bytes: entry_size,
        total_entries: ENTRIES_PER_SHARD as u64,
    };
    let mut shards = encode_database(shard_bytes, entry_size, params, &cfg)
        .map_err(|e| EthStateError::Setup(format!("re-encode shard {shard_id}: {e}")))?;
    let mut shard = shards
        .pop()
        .ok_or_else(|| EthStateError::Setup(format!("re-encode shard {shard_id}: no shard")))?;
    shard.id = shard_id;
    set_shard_slot(encoded, shard);
    Ok(())
}

/// Shard buffer where only leaves changed since the last fold are non-zero.
fn sparse_shard_bytes(shard_id: u32, changed: &BTreeMap<u64, Bytes>, entry_size: usize) -> Vec<u8> {
    let shard_start = shard_id as u64 * ENTRIES_PER_SHARD as u64;
    let shard_end = shard_start + ENTRIES_PER_SHARD as u64;
    let mut buf = vec![0u8; ENTRIES_PER_SHARD * entry_size];
    for (leaf, value) in changed.range(shard_start..shard_end) {
        let off = (*leaf - shard_start) as usize * entry_size;
        let n = value.len().min(entry_size);
        buf[off..off + n].copy_from_slice(&value[..n]);
    }
    buf
}

/// The sidecar's encoded shard when its sparse source already equals main's materialized bytes.
fn reuse_sidecar_shard(
    side_encoded: &EncodedDatabase,
    shard_id: u32,
    changed: &BTreeMap<u64, Bytes>,
    full_bytes: &[u8],
    entry_size: usize,
) -> Option<ShardData> {
    if sparse_shard_bytes(shard_id, changed, entry_size) != full_bytes {
        return None;
    }
    side_encoded
        .shards
        .iter()
        .find(|s| s.id == shard_id)
        .cloned()
}

/// Replace or insert, keeping `shards` id-sorted.
fn set_shard_slot(encoded: &mut EncodedDatabase, shard: ShardData) {
    if let Some(slot) = encoded.shards.iter_mut().find(|s| s.id == shard.id) {
        *slot = shard;
    } else {
        encoded.shards.push(shard);
        encoded.shards.sort_by_key(|s| s.id);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod entry_size_gate {
    use super::MainSidecar;
    use crate::ENTRY_SIZE;
    use raven_inspire::params::InspireParams;

    const LEGAL_UNSUPPORTED_ENTRY_SIZE: usize = 64;

    fn assert_width_refusal(error: &crate::EthStateError) {
        assert_eq!(
            error.to_string(),
            format!(
                "flat-state setup failed: eth-state entry width mismatch: expected {ENTRY_SIZE} \
                 bytes, got {LEGAL_UNSUPPORTED_ENTRY_SIZE} bytes"
            )
        );
    }

    #[test]
    fn seed_refuses_unsupported_legal_width_before_store_publication() {
        let parent = tempfile::tempdir().expect("tempdir");
        let store_path = parent.path().join("seed-store");
        let params = InspireParams::secure_128_d2048();
        let database = vec![0u8; LEGAL_UNSUPPORTED_ENTRY_SIZE];

        let outcome = MainSidecar::seed(
            &params,
            &database,
            LEGAL_UNSUPPORTED_ENTRY_SIZE,
            &store_path,
            0x0000_6401,
        );

        assert!(
            !store_path.exists(),
            "unsupported width must refuse before creating the store layout"
        );
        let error = outcome
            .err()
            .expect("a legal PIR width unsupported by the fixed record codec must refuse");
        assert_width_refusal(&error);
    }

    #[test]
    fn recover_refuses_unsupported_legal_width_before_store_open() {
        let parent = tempfile::tempdir().expect("tempdir");
        let store_path = parent.path().join("recover-store");
        let params = InspireParams::secure_128_d2048();

        let outcome = MainSidecar::recover(
            &params,
            LEGAL_UNSUPPORTED_ENTRY_SIZE,
            &store_path,
            0x0000_6402,
        );

        assert!(
            !store_path.exists(),
            "unsupported width must refuse before opening the store layout"
        );
        let error = outcome
            .err()
            .expect("recover must reject a width the snapshot codec cannot represent");
        assert_width_refusal(&error);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod kill_mid_fold {
    use super::MainSidecar;
    use crate::ingest::normalize_balance_be;
    use crate::{build_session, ENTRY_SIZE};
    use bytes::Bytes;
    use raven_client::{build_seeded_query_rust, extract_response_rust};
    use raven_inspire::params::InspireParams;
    use raven_inspire::rlwe::RlweSecretKey;
    use serial_test::serial;

    fn read_main(ms: &MainSidecar, sk: RlweSecretKey, leaf: u64) -> Vec<u8> {
        let params = InspireParams::secure_128_d2048();
        let crs = ms.main.current_snapshot().state.crs.clone();
        let shard_cfg = ms.main.current_snapshot().state.encoded_db.config.clone();
        let session = build_session(&crs, sk, params.sigma, 1).expect("session");
        let (state, q) =
            build_seeded_query_rust(&session, &params, &shard_cfg, leaf).expect("query");
        let (_e, resp) = ms.main.query(&q).expect("respond");
        extract_response_rust(&crs, &state, &resp, ENTRY_SIZE).expect("extract")
    }

    #[test]
    #[serial]
    fn swap_commit_window_self_heals() {
        let dir = tempfile::tempdir().expect("tempdir");
        let params = InspireParams::secure_128_d2048();
        let seed = 0x0000_5147u64;
        let n = 64usize;
        let mut db = vec![0u8; n * ENTRY_SIZE];
        for i in 0..n {
            let rec = normalize_balance_be(&((i as u128 + 1) * 7).to_be_bytes()).expect("norm");
            db[i * ENTRY_SIZE..(i + 1) * ENTRY_SIZE].copy_from_slice(&rec);
        }
        {
            let (mut ms, _msk, _ssk) =
                MainSidecar::seed(&params, &db, ENTRY_SIZE, dir.path(), seed).expect("seed");
            let rec3 = normalize_balance_be(&424_242u128.to_be_bytes()).expect("norm");
            ms.apply_updates(5, &[(3, Bytes::copy_from_slice(&rec3))])
                .expect("apply");
            ms.fold_abort_after_swap().expect("abort fold after swap");
        }
        let (ms2, main_sk, _ssk) =
            MainSidecar::recover(&params, ENTRY_SIZE, dir.path(), seed).expect("recover");
        let got = read_main(&ms2, main_sk, 3);
        let expected = normalize_balance_be(&424_242u128.to_be_bytes()).expect("norm");
        assert_eq!(
            &got[..],
            &expected[..],
            "swap..commit window recovers byte-identical"
        );
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod wal_floor {
    use super::MainSidecar;
    use crate::ingest::normalize_balance_be;
    use crate::ENTRY_SIZE;
    use bytes::Bytes;
    use raven_inspire::params::InspireParams;
    use raven_storage::Manifest;
    use serial_test::serial;

    /// The floor `recover` reads back, not an in-memory mirror of it.
    fn published_floor(ms: &MainSidecar) -> u64 {
        Manifest::load(&ms.layout)
            .expect("manifest load")
            .expect("manifest present after commit")
            .current_snapshot_seq
    }

    /// `fold` seals no WAL range of its own because `commit_v6` already published through the
    /// log head. The middle assertion pins the window where an unsealed range does exist.
    #[test]
    #[serial]
    fn commit_v6_advances_the_floor_to_the_log_head() {
        let dir = tempfile::tempdir().expect("tempdir");
        let params = InspireParams::secure_128_d2048();
        let n = 64usize;
        let mut db = vec![0u8; n * ENTRY_SIZE];
        for i in 0..n {
            let rec = normalize_balance_be(&((i as u128 + 1) * 7).to_be_bytes()).expect("norm");
            db[i * ENTRY_SIZE..(i + 1) * ENTRY_SIZE].copy_from_slice(&rec);
        }
        let (mut ms, _msk, _ssk) =
            MainSidecar::seed(&params, &db, ENTRY_SIZE, dir.path(), 0x0000_A5F0).expect("seed");
        assert_eq!(
            published_floor(&ms),
            ms.wal.next_seq(),
            "the base snapshot leaves nothing unsealed"
        );

        let rec = normalize_balance_be(&424_242u128.to_be_bytes()).expect("norm");
        ms.apply_updates(1, &[(3, Bytes::copy_from_slice(&rec))])
            .expect("apply");
        assert!(
            ms.wal.next_seq() > published_floor(&ms),
            "precondition: an applied update leaves seqs {}..{} unsealed",
            published_floor(&ms),
            ms.wal.next_seq()
        );

        ms.commit_v6().expect("commit");
        assert_eq!(
            published_floor(&ms),
            ms.wal.next_seq(),
            "commit_v6 must seal through the log head"
        );
    }

    #[test]
    #[serial]
    fn commit_v6_applies_raven_snapshot_retention() {
        let dir = tempfile::tempdir().expect("tempdir");
        let params = InspireParams::secure_128_d2048();
        let database = vec![0u8; 64 * ENTRY_SIZE];
        let (mut main_sidecar, _main_key, _sidecar_key) =
            MainSidecar::seed(&params, &database, ENTRY_SIZE, dir.path(), 0x0000_A5F1)
                .expect("seed");

        for _ in 0..6 {
            main_sidecar.commit_v6().expect("commit");
        }

        let mut snapshot_names = std::fs::read_dir(main_sidecar.layout.snapshots_dir())
            .expect("read snapshots")
            .map(|entry| {
                entry
                    .expect("snapshot entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        snapshot_names.sort();
        assert_eq!(
            snapshot_names,
            ["snap-000004", "snap-000005", "snap-000006", "snap-000007"],
            "eth-state must delegate its default four-snapshot retention to raven-storage"
        );
    }
}
