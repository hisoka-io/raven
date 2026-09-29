//! Persistence glue for [`PirInstance<RavenInspireScheme>`]: manifest, snapshot,
//! WAL and layout behind a per-instance policy and the commit/archive flow.

use super::inspire::{snapshot_inspire_state, InspireServerState, RavenInspireScheme};
use super::{InstanceRole, PirInstance};
use parking_lot::Mutex;
use raven_inspire::params::rows_per_shard_match_ring_dim;
use raven_railgun_core::{AdapterError, Epoch, InstanceId, Result};
pub use raven_railgun_persistence::RetentionPolicy;
use raven_railgun_persistence::{
    advance_manifest_and_archive, apply_retention, open_recovery, Manifest, ManifestShape,
    Snapshot, SnapshotId, StoreLayout, Wal, WalEntryPayload, MANIFEST_SCHEMA_VERSION,
    SNAPSHOT_MAGIC,
};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn ensure_metrics_described() {
    metrics::describe_counter!(
        "raven_railgun_wal_replay_skipped_total",
        metrics::Unit::Count,
        "Count of WAL entries soft-skipped during recovery replay due to \
         InvalidQuery (e.g. non-contiguous AppendLeaf, non-Fr-canonical \
         leaf bytes). Production-path validate-before-write should keep \
         this at 0; non-zero indicates an external WAL corruption or a \
         pre-validate-floor build that landed entries before the floor \
         was active."
    );
    metrics::counter!("raven_railgun_wal_replay_skipped_total").increment(0);
    metrics::describe_counter!(
        "raven_railgun_retention_failures_total",
        metrics::Unit::Count,
        "Commits whose snapshot was published but whose retention pass failed, labelled by \
         instance. Each one leaves superseded snapshots and archived WAL on disk."
    );
}

/// Snapshot cadence and retention config.
#[derive(Clone, Copy, Debug)]
pub struct SnapshotPolicy {
    /// WAL appends since last snapshot before triggering.
    pub max_appends_per_snapshot: usize,
    /// Seconds since last snapshot before triggering.
    pub max_seconds_between_snapshots: u64,
    /// Raven-owned durability retention policy.
    pub retention: RetentionPolicy,
}

impl Default for SnapshotPolicy {
    fn default() -> Self {
        Self {
            max_appends_per_snapshot: 1000,
            max_seconds_between_snapshots: 300,
            retention: RetentionPolicy::default(),
        }
    }
}

/// Longest the consumer lets an applied row sit outside the served database.
///
/// Every policy's timer is checked only on an append, so for any role this bound, not the timer,
/// is what publishes the rows of a feed that has gone quiet. It also caps a longer timer, such as
/// the static policy's.
const MAX_UNPUBLISHED_SECS: u64 = 300;

impl SnapshotPolicy {
    /// Policy for static instances: no append or timer snapshot trigger.
    ///
    /// A filled tree then does no periodic work. Rows it does receive still reach the served
    /// database within [`SnapshotPolicy::publish_bound`], and the append that fills a tree
    /// publishes at once.
    pub const fn static_default() -> Self {
        Self {
            max_appends_per_snapshot: usize::MAX,
            max_seconds_between_snapshots: u64::MAX,
            retention: RetentionPolicy {
                archived_wals_retain: 4,
                snapshots_retain: 2,
            },
        }
    }

    /// Longest an applied row waits for the consumer to publish it when no append triggers a
    /// snapshot first. Also the retry interval after a failed publish, hence never zero.
    #[must_use]
    pub const fn publish_bound(&self) -> Duration {
        let secs = if self.max_seconds_between_snapshots < MAX_UNPUBLISHED_SECS {
            self.max_seconds_between_snapshots
        } else {
            MAX_UNPUBLISHED_SECS
        };
        Duration::from_secs(if secs == 0 { 1 } else { secs })
    }
}

#[derive(Debug)]
struct SnapshotCounters {
    appends_since_snapshot: usize,
    last_snapshot_at: Instant,
}

/// Scheme tag this build writes into every manifest and requires on reopen: the InsPIRe
/// two-packing variant with InspiRING packing, at version 1 of its persisted layout.
pub const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-v1";

/// Per-instance persistence state. Created via [`InspirePersistence::open`].
pub struct InspirePersistence {
    layout: StoreLayout,
    wal: Wal,
    manifest: Mutex<Manifest>,
    policy: parking_lot::RwLock<SnapshotPolicy>,
    counters: Mutex<SnapshotCounters>,
    scheme_tag: String,
    instance_id: InstanceId,
    commit_notify: tokio::sync::Notify,
    persisted_cache_fingerprint: Mutex<Option<super::inspire::CacheFingerprint>>,
    /// Leaf count of the store the published snapshot carries. The commit driver
    /// refuses to publish a store below it without a dirty shard to explain the
    /// drop.
    committed_leaf_count: std::sync::atomic::AtomicUsize,
    /// See [`InspirePersistence::list_row_refused`].
    list_row_refused: Mutex<Option<u32>>,
    /// See [`InspirePersistence::set_backfilling`].
    backfilling: std::sync::atomic::AtomicBool,
    publish_requested: std::sync::atomic::AtomicBool,
    wake: tokio::sync::Notify,
    #[cfg(test)]
    fail_next_sync: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for InspirePersistence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let manifest = self.manifest.lock();
        f.debug_struct("InspirePersistence")
            .field("instance_id", &self.instance_id)
            .field("scheme_tag", &self.scheme_tag)
            .field("current_snapshot_id", &manifest.current_snapshot_id)
            .field("current_snapshot_seq", &manifest.current_snapshot_seq)
            .field("policy", &*self.policy.read())
            .field("wal_next_seq", &self.wal.next_seq())
            .finish_non_exhaustive()
    }
}

impl InspirePersistence {
    /// Read the current snapshot policy. Cheap copy.
    #[must_use]
    pub fn snapshot_policy(&self) -> SnapshotPolicy {
        *self.policy.read()
    }

    /// Atomically replace the snapshot policy.
    pub fn set_snapshot_policy(&self, new_policy: SnapshotPolicy) {
        *self.policy.write() = new_policy;
    }

    /// Leaf count carried by the currently published snapshot.
    #[must_use]
    pub fn committed_leaf_count(&self) -> usize {
        self.committed_leaf_count
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Mark this instance's tree divergent from the chain, in memory and on disk.
    ///
    /// # Errors
    /// [`AdapterError::Internal`] if the on-disk marker cannot be written; the
    /// in-memory mark is set either way.
    pub fn mark_layer2_divergent(&self) -> Result<()> {
        self::mark_layer2_divergent(self.instance_id.as_str());
        let path = self.layer2_divergent_marker_path();
        // The marker's whole job is to survive a crash, and `open` re-reads it with
        // `Path::exists()`, so what must be durable is the DIRECTORY ENTRY. A bare
        // `fs::write` fsyncs neither the file nor the parent, so a power cut can lose
        // the entry that was just reported as written.
        raven_railgun_persistence::atomic_write(&path, self.instance_id.as_str().as_bytes())
            .map_err(|e| {
                AdapterError::Internal(format!(
                    "layer2 divergence marker write failed at {}: {e}; a restart would \
                     report ready with the tree still unrepaired",
                    path.display()
                ))
            })
    }

    /// Drop this instance's divergence mark, in memory and on disk.
    ///
    /// # Errors
    /// [`AdapterError::Internal`] if the on-disk marker exists and cannot be
    /// removed; the in-memory mark is cleared either way.
    pub fn clear_layer2_divergent(&self) -> Result<()> {
        self::clear_layer2_divergent(self.instance_id.as_str());
        let path = self.layer2_divergent_marker_path();
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(AdapterError::Internal(format!(
                "layer2 divergence marker removal failed at {}: {e}; the next open \
                 will re-mark this instance divergent",
                path.display()
            ))),
        }
    }

    fn mark_divergent_or_log(&self, instance_label: &str) {
        if let Err(e) = self.mark_layer2_divergent() {
            tracing::error!(
                error = %e,
                instance = instance_label,
                "layer2 verifier: divergence mark set in memory only"
            );
        }
    }

    fn layer2_divergent_marker_path(&self) -> std::path::PathBuf {
        self.layout.root().join(LAYER2_DIVERGENT_MARKER)
    }

    fn persist_cache_if_changed(&self, state: &InspireServerState) -> Result<bool> {
        let fingerprint = state.cache_fingerprint();
        let mut persisted = self.persisted_cache_fingerprint.lock();
        if persisted.as_ref() == Some(&fingerprint) {
            return Ok(false);
        }
        state
            .cache
            .validate_for(&state.crs, &state.encoded_db)
            .map_err(|error| {
                AdapterError::Internal(format!(
                    "offline packing cache validation before store: {error}"
                ))
            })?;
        super::inspire::persist_inspiring_cache(self.layout.root(), state)?;
        *persisted = Some(fingerprint);
        Ok(true)
    }
}

/// The tag is compared, never interpreted: a mismatch says only that the operator must choose.
fn scheme_tag_mismatch(
    root: &std::path::Path,
    stored: &str,
    configured: &str,
) -> raven_railgun_persistence::PersistenceError {
    raven_railgun_persistence::PersistenceError::Invariant(format!(
        "data_dir {} was written under scheme tag {stored:?}, and this instance is configured \
         with {configured:?}. If {stored:?} names the same on-disk layout, set this instance's \
         scheme_tag to {stored:?}; otherwise move that data_dir aside and start on an empty \
         one, which the node rebuilds from its source",
        root.display()
    ))
}

/// Store-root file whose presence re-marks an instance divergent on open. A
/// restart is not evidence that the tree was repaired.
const LAYER2_DIVERGENT_MARKER: &str = "layer2-divergent";

/// Result of [`InspirePersistence::open`].
#[derive(Debug)]
pub struct OpenedInstance {
    /// Persistence handle.
    pub persistence: InspirePersistence,
    /// Recovered state; `None` on fresh bootstrap.
    pub recovered_state: Option<InspireServerState>,
    /// Logical leaf store rebuilt from WAL replay. Empty on fresh bootstrap.
    pub recovered_logical_store: super::inspire::LogicalLeafStore,
    /// True when recovery reused the validated on-disk packing cache.
    pub recovered_cache_hit: bool,
}

/// Reject an encoder whose row width or row window diverges from the recovered cell's;
/// `encoder_label` is stable across operator-supplied shapes so it cannot catch either.
///
/// # Errors
/// [`AdapterError::Internal`] when the encoder's row width or rows per shard differ from storage.
fn ensure_encoder_matches_stored_cell(
    stored: &raven_inspire::params::ShardConfig,
    stored_rows_per_shard: u32,
    encoder: &dyn super::pir_table::PirTableEncoder,
) -> Result<()> {
    let stored_width = stored.entry_size_bytes;
    let emitted = encoder.record_size();
    if emitted != stored_width {
        return Err(AdapterError::Internal(format!(
            "manifest encoder width mismatch: stored {stored_width}-byte rows != configured \
             encoder {label} emitting {emitted}-byte rows; encoder_label matches on both \
             sides, so nothing downstream detects this and every re-encoded shard would \
             serve unrelated bytes with no query-path error. The data_dir must be \
             re-bootstrapped at record width {emitted} - reconfiguring the width does not \
             convert existing shards - OR the configuration that produced {stored_width}-byte \
             rows must be restored",
            label = encoder.label(),
        )));
    }
    let encoder_rows = encoder.entries_per_shard();
    if !rows_per_shard_match_ring_dim(u64::from(encoder_rows), stored_rows_per_shard as usize) {
        return Err(AdapterError::Internal(format!(
            "recovered cell holds {stored_rows_per_shard} rows per shard but the configured \
             encoder {label} materializes {encoder_rows}; every shard id above 0 is re-encoded \
             from the wrong row window. The data_dir must be re-bootstrapped at \
             {encoder_rows} rows per shard OR the encoder configuration restored to \
             {stored_rows_per_shard} rows per shard",
            label = encoder.label(),
        )));
    }
    Ok(())
}

fn encoder_manifest_shape(encoder: &dyn super::pir_table::PirTableEncoder) -> ManifestShape {
    ManifestShape {
        entry_size_bytes: encoder.record_size(),
        rows_per_shard: u64::from(encoder.entries_per_shard()),
    }
}

fn recovered_manifest_shape(state: &InspireServerState) -> ManifestShape {
    let config = state.shard_config();
    ManifestShape {
        entry_size_bytes: config.entry_size_bytes,
        rows_per_shard: config.entries_per_shard(),
    }
}

fn manifest_shape_error(
    context: &str,
    error: raven_railgun_persistence::PersistenceError,
) -> AdapterError {
    AdapterError::Internal(format!("manifest cell shape {context}: {error}"))
}

impl InspirePersistence {
    /// Open at `layout`, recovering from an existing manifest or initializing
    /// fresh. Rejects an encoder whose label, row width, or row window diverges
    /// from the recovered cell.
    #[allow(clippy::too_many_lines)]
    pub fn open(
        layout: StoreLayout,
        scheme_tag: impl Into<String>,
        instance_id: InstanceId,
        policy: SnapshotPolicy,
        encoder: Arc<dyn super::pir_table::PirTableEncoder>,
    ) -> Result<OpenedInstance> {
        ensure_metrics_described();
        if layout.root().join(LAYER2_DIVERGENT_MARKER).exists() {
            mark_layer2_divergent(instance_id.as_str());
        }
        let scheme_tag = scheme_tag.into();
        let encoder_label = encoder.label();
        let configured_shape = encoder_manifest_shape(encoder.as_ref());
        let recovered = open_recovery(&layout, SNAPSHOT_MAGIC, |manifest| {
            if manifest.scheme_tag != scheme_tag {
                return Err(scheme_tag_mismatch(
                    layout.root(),
                    &manifest.scheme_tag,
                    &scheme_tag,
                ));
            }
            manifest.validate_identity(&scheme_tag, instance_id.as_str(), encoder_label)?;
            if manifest.cell_shape()?.is_some() {
                manifest.validate_shape(configured_shape)?;
            }
            Ok(())
        })
        .map_err(|e| {
            AdapterError::Internal(format!("recovery open for encoder {encoder_label}: {e}"))
        })?;
        if let Some(recovery) = recovered {
            let mut manifest = recovery.manifest;
            // SnapshotId(0) means no commit yet. V8 seeds the replay base with its
            // embedded store; V5 starts empty and relies wholly on WAL replay.
            let (
                recovered_state,
                recovered_seed_store,
                entries_per_shard,
                recovered_cache_hit,
                recovered_cache_persisted,
            ) = if let Some(snap) = recovery.snapshot.as_ref() {
                let (s, store, cache_hit, cache_persisted) =
                    super::inspire::restore_inspire_state_v6_cached(&snap.data, layout.root())?;
                let eps = u32::try_from(
                    s.encoded_db
                        .config
                        .entries_per_shard()
                        .min(u64::from(u32::MAX)),
                )
                .unwrap_or(u32::MAX);
                (Some(s), store, eps, cache_hit, cache_persisted)
            } else {
                manifest
                    .require_shape()
                    .map_err(|error| manifest_shape_error("without snapshot", error))?;
                (
                    None,
                    super::inspire::LogicalLeafStore::new(),
                    u32::MAX,
                    false,
                    false,
                )
            };
            if let Some(state) = recovered_state.as_ref() {
                let recovered_shape = recovered_manifest_shape(state);
                let migrated = manifest
                    .migrate_shape_from_snapshot(recovered_shape)
                    .map_err(|error| manifest_shape_error("vs recovered snapshot", error))?;
                manifest.validate_shape(configured_shape).map_err(|error| {
                    manifest_shape_error(&format!("vs configured encoder {encoder_label}"), error)
                })?;
                ensure_encoder_matches_stored_cell(
                    state.shard_config(),
                    entries_per_shard,
                    encoder.as_ref(),
                )?;
                if migrated {
                    manifest.save(&layout).map_err(|error| {
                        AdapterError::Internal(format!("manifest shape migration save: {error}"))
                    })?;
                }
            }
            let persisted_cache_fingerprint = recovered_state
                .as_ref()
                .filter(|_| recovered_cache_persisted)
                .map(InspireServerState::cache_fingerprint);
            let wal = recovery.wal;
            let mut logical_store = recovered_seed_store;
            // Derive the addenda from the snapshot's OWN store, BEFORE replay advances it to the
            // WAL tip. `restore_inspire_state_v6_cached` returned this store and
            // `state.encoded_db` out of one bundle, and nothing in the manifest or in
            // `EncodedDatabase` identifies the tree a row was encoded from -- so this is the only
            // instant in the process where the committed pair exists as data rather than as an
            // inference. Deriving after replay records committed provenance for TIP-derived
            // addenda, and `inspire_batch_handler` folds that pair into a wrong Merkle root at
            // HTTP 200 with no log and no counter.
            //
            // A runtime `wal_next_seq() == current_snapshot_seq` test cannot replace this: the
            // fresh-bootstrap arms of `bootstrap_inspire_instance` and
            // `bootstrap_railgun_engine_multi` commit a synthetic state against an EMPTY store
            // while handing the consumer the replayed one, and that commit advances the floor.
            //
            // A store that cannot resolve a shard's proof -- V5, or a never-committed tree --
            // leaves the table empty, which the batch path already refuses.
            if let Some(state) = recovered_state.as_ref() {
                logical_store.refresh_committed_addenda(&state.encoded_db, entries_per_shard);
            }
            let replay = recovery.replay;
            // An unencodable leaf is replay-fatal; every other `InvalidQuery`
            // soft-skips, and Internal/Serialization bubble.
            let mut replay_skipped: u64 = 0;
            let replay_encoder = encoder.as_ref();
            for entry in &replay.entries {
                // `WalEntryPayload` is an enum, so a permissive decode reads a longer variant
                // as a shorter one and silently drops its tail. Refuse the surplus instead.
                let payload: WalEntryPayload =
                    raven_railgun_persistence::decode_no_trailing(&entry.payload).map_err(|e| {
                        AdapterError::Serialization(format!(
                            "wal payload at seq {}: {e}. The frame passed its checksum, so a \
                             build wrote these bytes in a WalEntryPayload layout other than this \
                             one's, such as the retired layout that carried PPOI status rows and \
                             a status byte and signature on each list leaf. No in-place \
                             migration exists, and dropping the entry would lose its rows. \
                             Operator: re-bootstrap this instance.",
                            entry.seq
                        ))
                    })?;
                super::inspire::ensure_canonical_leaf(&payload).map_err(|e| {
                    AdapterError::Internal(format!(
                        "wal replay refused at seq {} (block {}): {e}. Skipping it \
                         would leave the tree short a leaf and discard every later \
                         entry for that tree; repair or truncate the WAL under \
                         {} before reopening",
                        entry.seq,
                        entry.marker,
                        layout.root().display(),
                    ))
                })?;
                if let Err(e) = super::inspire::apply_wal_entry(
                    &mut logical_store,
                    &payload,
                    entry.marker,
                    replay_encoder,
                ) {
                    if matches!(e, AdapterError::InvalidQuery(_)) {
                        tracing::warn!(
                            seq = entry.seq,
                            block_height = entry.marker,
                            error = %e,
                            "wal replay: skipping invalid entry; \
                             production-path validate_apply should have prevented \
                             this - investigate persisted WAL"
                        );
                        replay_skipped = replay_skipped.saturating_add(1);
                        continue;
                    }
                    return Err(e);
                }
            }
            if replay_skipped > 0 {
                tracing::warn!(
                    count = replay_skipped,
                    instance = instance_id.as_str(),
                    "wal replay completed with {replay_skipped} skipped invalid entries"
                );
                metrics::counter!("raven_railgun_wal_replay_skipped_total")
                    .increment(replay_skipped);
                mark_wal_replay_skipped(instance_id.as_str());
            }
            Ok(OpenedInstance {
                persistence: Self {
                    layout,
                    wal,
                    manifest: Mutex::new(manifest),
                    policy: parking_lot::RwLock::new(policy),
                    counters: Mutex::new(SnapshotCounters {
                        appends_since_snapshot: 0,
                        last_snapshot_at: Instant::now(),
                    }),
                    scheme_tag,
                    instance_id,
                    commit_notify: tokio::sync::Notify::new(),
                    persisted_cache_fingerprint: Mutex::new(persisted_cache_fingerprint),
                    committed_leaf_count: std::sync::atomic::AtomicUsize::new(
                        logical_store.leaf_count(),
                    ),
                    list_row_refused: Mutex::new(None),
                    backfilling: std::sync::atomic::AtomicBool::new(false),
                    publish_requested: std::sync::atomic::AtomicBool::new(false),
                    wake: tokio::sync::Notify::new(),
                    #[cfg(test)]
                    fail_next_sync: std::sync::atomic::AtomicBool::new(false),
                },
                recovered_state,
                recovered_logical_store: logical_store,
                recovered_cache_hit,
            })
        } else {
            // No manifest plus a non-empty WAL means ghost entries from a failed bootstrap.
            let current_wal_path = layout.wal_current_path();
            if current_wal_path.exists() {
                let len = std::fs::metadata(&current_wal_path)
                    .map_err(|e| AdapterError::Internal(format!("wal probe: {e}")))?
                    .len();
                if len > 0 {
                    return Err(AdapterError::Internal(format!(
                        "fresh-bootstrap refused: manifest.json missing but \
                         wal/current.log is {len} bytes (likely a prior failed \
                         bootstrap). Operator: clear data_dir + restart, OR \
                         restore from backup. Path: {}",
                        layout.root().display()
                    )));
                }
            }
            let wal = Wal::open(&layout, None)
                .map_err(|e| AdapterError::Internal(format!("wal open: {e}")))?;
            let manifest = Manifest {
                schema_version: MANIFEST_SCHEMA_VERSION,
                scheme_tag: scheme_tag.clone(),
                instance_id: instance_id.to_string(),
                current_snapshot_id: SnapshotId(0),
                current_snapshot_seq: 0,
                current_marker: 0,
                encoder_label: encoder_label.to_owned(),
                prev_encoder_label: None,
                entry_size_bytes: Some(encoder_manifest_shape(encoder.as_ref()).entry_size_bytes),
                rows_per_shard: Some(encoder_manifest_shape(encoder.as_ref()).rows_per_shard),
            };
            // Persist the manifest first so a failed commit() still lands in recovery.
            manifest
                .save(&layout)
                .map_err(|e| AdapterError::Internal(format!("manifest save (fresh): {e}")))?;
            Ok(OpenedInstance {
                persistence: Self {
                    layout,
                    wal,
                    manifest: Mutex::new(manifest),
                    policy: parking_lot::RwLock::new(policy),
                    counters: Mutex::new(SnapshotCounters {
                        appends_since_snapshot: 0,
                        last_snapshot_at: Instant::now(),
                    }),
                    scheme_tag,
                    instance_id,
                    commit_notify: tokio::sync::Notify::new(),
                    persisted_cache_fingerprint: Mutex::new(None),
                    committed_leaf_count: std::sync::atomic::AtomicUsize::new(0),
                    list_row_refused: Mutex::new(None),
                    backfilling: std::sync::atomic::AtomicBool::new(false),
                    publish_requested: std::sync::atomic::AtomicBool::new(false),
                    wake: tokio::sync::Notify::new(),
                    #[cfg(test)]
                    fail_next_sync: std::sync::atomic::AtomicBool::new(false),
                },
                recovered_state: None,
                recovered_logical_store: super::inspire::LogicalLeafStore::new(),
                recovered_cache_hit: false,
            })
        }
    }

    /// V5 commit: snapshot, archive WAL, bump manifest atomically. Prefer
    /// [`InspirePersistence::commit_v6`], which also carries the leaf store.
    pub fn commit(
        &self,
        state: &InspireServerState,
        current_block_height: u64,
    ) -> Result<SnapshotId> {
        self.validate_commit_shape(state)?;
        let bundle = snapshot_inspire_state(state)?;
        let id = self.commit_serialized_bundle(bundle, current_block_height)?;
        if let Err(error) = self.persist_cache_if_changed(state) {
            tracing::warn!(error = %error, "offline packing cache store failed after commit");
        }
        Ok(id)
    }

    /// Snapshot `(state, store)`, archive WAL, bump manifest atomically.
    ///
    /// Writes **V8**; the name is kept because callers and tests reference it, and the snapshot
    /// version is chosen by the writer it calls, not by this name. Two version ladders share the
    /// numerals 5 to 8 here — the manifest's and the snapshot magic's — so a stale numeral in a
    /// doc or an error string costs an operator more than it would elsewhere.
    ///
    /// **Contract: `store` MUST be the logical store `state.encoded_db` was encoded from.**
    /// [`InspirePersistence::open`] re-derives the committed upper-sibling addenda from this pair
    /// on reopen, so a call site that snapshots a store AHEAD of its state serves a wrong Merkle
    /// root at HTTP 200 one reopen later, with no log and no counter. The production call sites
    /// are `drive_commit`'s two arms — which hold the consumer lock across the re-encode, so no
    /// append interleaves — and the two fresh-bootstrap arms, which pair a synthetic state with
    /// an EMPTY store and therefore reopen with an empty table the batch path refuses. Nothing
    /// here enforces the contract; a fifth call site re-creates the defect silently.
    pub fn commit_v6(
        &self,
        state: &InspireServerState,
        store: &super::inspire::LogicalLeafStore,
        current_block_height: u64,
    ) -> Result<SnapshotId> {
        self.validate_commit_shape(state)?;
        let bundle = super::inspire::snapshot_inspire_state_v8(state, store)?;
        let id = self.commit_serialized_bundle(bundle, current_block_height)?;
        if let Err(error) = self.persist_cache_if_changed(state) {
            tracing::warn!(error = %error, "offline packing cache store failed after commit");
        }
        self.committed_leaf_count
            .store(store.leaf_count(), std::sync::atomic::Ordering::Release);
        Ok(id)
    }

    fn commit_serialized_bundle(
        &self,
        bundle: Vec<u8>,
        current_block_height: u64,
    ) -> Result<SnapshotId> {
        let snap = Snapshot::build(bundle, SNAPSHOT_MAGIC);

        // Slow snapshot save runs outside the manifest lock; CAS-checked on re-lock.
        let next_id = {
            let m = self.manifest.lock();
            m.current_snapshot_id.next()
        };

        snap.save(&self.layout, next_id)
            .map_err(|e| AdapterError::Internal(format!("snapshot save: {e}")))?;

        let mut m = self.manifest.lock();
        if m.current_snapshot_id.next() != next_id {
            return Err(AdapterError::Internal(format!(
                "commit() CAS failure: manifest.current_snapshot_id advanced \
                 during snap.save (expected {:?}, found {:?}). Possible \
                 concurrent writer; check flock guard + operator runbook.",
                next_id.0 - 1,
                m.current_snapshot_id
            )));
        }

        advance_manifest_and_archive(
            &self.layout,
            &self.wal,
            &mut m,
            next_id,
            |man, id, floor| {
                man.current_snapshot_id = id;
                man.current_snapshot_seq = floor;
                man.current_marker = current_block_height;
                man.schema_version = MANIFEST_SCHEMA_VERSION;
            },
        )
        .map_err(|e| AdapterError::Internal(format!("publish snapshot: {e}")))?;

        {
            let mut c = self.counters.lock();
            c.appends_since_snapshot = 0;
            c.last_snapshot_at = Instant::now();
        }

        drop(m);
        let retention = self.policy.read().retention;
        if let Err(error) = apply_retention(&self.layout, next_id, retention) {
            record_retention_failure(self.instance_id.as_str());
            tracing::error!(
                snapshot_id = next_id.0,
                error = %error,
                "snapshot committed, but retention failed; superseded snapshots stay on disk"
            );
        }

        Ok(next_id)
    }

    fn validate_commit_shape(&self, state: &InspireServerState) -> Result<()> {
        self.manifest
            .lock()
            .validate_shape(recovered_manifest_shape(state))
            .map_err(|error| manifest_shape_error("before snapshot commit", error))
    }

    /// Notify primitive fired after every successful `commit()`.
    pub fn commit_notify(&self) -> &tokio::sync::Notify {
        &self.commit_notify
    }

    /// Append a WAL entry. Returns `(seq, trigger)`.
    pub fn apply_event(&self, payload: &WalEntryPayload, block_height: u64) -> Result<(u64, bool)> {
        let seq = self
            .wal
            .append(payload, block_height)
            .map_err(|e| AdapterError::Internal(format!("wal append: {e}")))?;
        self.count_append();
        Ok((seq, self.snapshot_due()))
    }

    fn count_append(&self) {
        let mut c = self.counters.lock();
        c.appends_since_snapshot = c.appends_since_snapshot.saturating_add(1);
    }

    /// Write a WAL entry that is durable only once [`Self::sync_rows`] returns. Nothing derived
    /// from it may be shown before then.
    fn append_unsynced(&self, payload: &WalEntryPayload, block_height: u64) -> Result<u64> {
        let seq = self
            .wal
            .append_deferred(payload, block_height)
            .map_err(|e| AdapterError::Internal(format!("wal append: {e}")))?;
        self.count_append();
        Ok(seq)
    }

    /// Make every entry [`Self::append_unsynced`] wrote durable. A failure poisons the WAL until
    /// a reopen.
    fn sync_rows(&self) -> Result<()> {
        #[cfg(test)]
        if self
            .fail_next_sync
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(AdapterError::Internal(
                "wal sync: injected failure".to_owned(),
            ));
        }
        self.wal
            .sync()
            .map_err(|e| AdapterError::Internal(format!("wal sync: {e}")))
    }

    /// Whether the policy asks for a snapshot now. The append count does not count while
    /// [`Self::set_backfilling`] holds, nor while the publish that ends it is pending: the count
    /// a backfill built up would otherwise re-encode the block once more in the middle of the
    /// rows still queued.
    fn snapshot_due(&self) -> bool {
        let c = self.counters.lock();
        let policy = *self.policy.read();
        let appends_due = c.appends_since_snapshot >= policy.max_appends_per_snapshot
            && !self.backfilling.load(std::sync::atomic::Ordering::Acquire)
            && !self
                .publish_requested
                .load(std::sync::atomic::Ordering::Acquire);
        appends_due
            || c.last_snapshot_at.elapsed()
                >= Duration::from_secs(policy.max_seconds_between_snapshots)
    }

    /// While on, the append count triggers no snapshot: a feed catching up would otherwise
    /// re-encode the part-filled block every `max_appends_per_snapshot` rows. The timer, the
    /// publish bound and a filled tree still publish. Turning it off asks the consumer to
    /// publish what it holds as soon as its queue is empty.
    pub fn set_backfilling(&self, on: bool) {
        let was = self
            .backfilling
            .swap(on, std::sync::atomic::Ordering::AcqRel);
        if was && !on {
            self.publish_requested
                .store(true, std::sync::atomic::Ordering::Release);
            self.wake.notify_one();
        }
    }

    /// Index, within its block, of the list row this instance lacks and was refused at or past
    /// since it last applied one. A feed asks for that row again on it, and never on rows that
    /// are merely still queued. `None` again once a list row applies.
    #[must_use]
    pub fn list_row_refused(&self) -> Option<u32> {
        *self.list_row_refused.lock()
    }

    /// Borrow the layout.
    pub fn layout(&self) -> &StoreLayout {
        &self.layout
    }

    /// Current WAL next-seq.
    pub fn wal_next_seq(&self) -> u64 {
        self.wal.next_seq()
    }

    /// Current snapshot id.
    pub fn current_snapshot_id(&self) -> SnapshotId {
        self.manifest.lock().current_snapshot_id
    }

    /// Restart resume floor, advanced on every commit, so restart does not
    /// re-scan applied events.
    #[must_use]
    pub fn manifest_block_height(&self) -> u64 {
        self.manifest.lock().current_marker
    }

    /// Whether a commit at `marker` would publish nothing a reopen does not already recover: a
    /// snapshot exists, no WAL entry was appended after it, and its resume marker is `marker`.
    #[must_use]
    pub fn unchanged_since_commit(&self, marker: u64) -> bool {
        let manifest = self.manifest.lock();
        manifest.current_snapshot_id != SnapshotId(0)
            && manifest.current_snapshot_seq == self.wal.next_seq()
            && manifest.current_marker == marker
    }

    /// Append a `Reorg` WAL marker. Returns the assigned WAL seq.
    pub fn signal_reorg(&self, height: u64) -> Result<u64> {
        let payload = WalEntryPayload::Reorg { height };
        let (seq, _) = self.apply_event(&payload, height)?;
        Ok(seq)
    }
}

/// Construct a [`PirInstance<RavenInspireScheme>`] tied to a persistence handle,
/// recovering from disk when a manifest exists. The packing-key store keeps the
/// compiled session limits; a serving path sizes it with
/// [`bootstrap_inspire_instance_with_session_limits`].
///
/// The returned store MUST be the one the consumer task runs against: the
/// encoded DB and the logical store share a leaf-index contiguity invariant, and
/// a fresh store behind a recovered DB rejects every subsequent append.
pub fn bootstrap_inspire_instance(
    layout: StoreLayout,
    scheme_tag: impl Into<String>,
    instance_id: InstanceId,
    role: InstanceRole,
    policy: SnapshotPolicy,
    encoder: Arc<dyn super::pir_table::PirTableEncoder>,
    fresh_state_factory: impl FnOnce() -> Result<InspireServerState>,
) -> Result<(
    PirInstance<RavenInspireScheme>,
    Arc<InspirePersistence>,
    super::inspire::LogicalLeafStore,
)> {
    bootstrap_inspire_instance_with_session_limits(
        layout,
        scheme_tag,
        instance_id,
        role,
        policy,
        encoder,
        super::session_pool::SessionStoreLimits::default(),
        fresh_state_factory,
    )
}

/// [`bootstrap_inspire_instance`] with the packing-key store opened at `session_limits`.
///
/// # Errors
///
/// A persistence, recovery or fresh-state failure, or a session-store error when
/// `session_limits` admits no session.
#[allow(clippy::too_many_arguments)]
pub fn bootstrap_inspire_instance_with_session_limits(
    layout: StoreLayout,
    scheme_tag: impl Into<String>,
    instance_id: InstanceId,
    role: InstanceRole,
    policy: SnapshotPolicy,
    encoder: Arc<dyn super::pir_table::PirTableEncoder>,
    session_limits: super::session_pool::SessionStoreLimits,
    fresh_state_factory: impl FnOnce() -> Result<InspireServerState>,
) -> Result<(
    PirInstance<RavenInspireScheme>,
    Arc<InspirePersistence>,
    super::inspire::LogicalLeafStore,
)> {
    let session_store = Arc::new(super::session_pool::BoundedSessionStore::open_with_limits(
        layout.root(),
        session_limits,
    )?);
    let opened =
        InspirePersistence::open(layout, scheme_tag, instance_id.clone(), policy, encoder)?;
    let persistence = Arc::new(opened.persistence);
    let recovered_store = opened.recovered_logical_store;
    let mut state = if let Some(s) = opened.recovered_state {
        s
    } else {
        // V6 first commit ships the store with the snapshot; notify so observers
        // waiting on first commit do not deadlock.
        let s = fresh_state_factory()?;
        let empty_store = super::inspire::LogicalLeafStore::default();
        persistence.commit_v6(&s, &empty_store, 0)?;
        persistence.commit_notify().notify_waiters();
        s
    };
    state.session_store = session_store;
    let instance = PirInstance::new(instance_id, role, state);
    let _ = Epoch::ZERO;
    Ok((instance, persistence, recovered_store))
}

/// One unit of work the engine consumer task processes.
#[derive(Debug, Clone)]
pub enum ConsumerEvent {
    /// A decoded chain event from the indexer.
    Chain(raven_railgun_core::RailgunEvent, u64),
    /// A reorg fence.
    Reorg(u64),
    /// A startup fence acknowledged only after its durable commit.
    ReorgBarrier {
        /// Highest block that survives the rewind.
        height: u64,
        /// Receives the durable-commit outcome.
        completion: tokio::sync::mpsc::Sender<std::result::Result<(), String>>,
    },
    /// A PPOI list row from the upstream mirror.
    Ppoi(raven_railgun_persistence::WalEntryPayload, u64),
    /// Heartbeat carrying the chain head and the indexer's scan watermark.
    Heartbeat {
        /// Chain tip observed by the indexer.
        chain_head: u64,
        /// Highest block the indexer has scanned and dispatched events for.
        scanned_through: u64,
    },
    /// Operator-driven shutdown signal.
    Shutdown,
}

/// Consumer-task progress and lag metrics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConsumerMetrics {
    /// Height of the last applied event. Monotonic; measures event flow, not
    /// indexer progress.
    pub last_applied_block: u64,
    /// Highest block scanned, event-bearing or not; the only height lag may be
    /// measured against.
    pub last_scanned_block: u64,
    /// Height of the last leaf-mutating event. Rises only on an applied leaf and
    /// falls only on a reorg rewind, so it is the only height safe to persist as
    /// the resume floor.
    pub last_applied_leaf_block: u64,
    /// Last chain head seen via heartbeat.
    pub last_known_chain_head: u64,
    /// Events processed since startup.
    pub events_processed: u64,
    /// Reorgs handled since startup.
    pub reorgs_handled: u64,
    /// Commit triggers fired since startup.
    pub commits_fired: u64,
    /// Per-event errors (log-and-continue) since startup.
    pub consumer_errors: u64,
    /// Failed events since the last applied one, plus failed deferred publishes since the last
    /// commit. Nonzero means the consumer is stalled on a repeating failure; the lag gauges
    /// cannot say that, because a heartbeat keeps the scan watermark at the tip while nothing
    /// applies.
    pub consecutive_event_errors: u64,
    /// Leaves abandoned when a per-leaf loop broke, and not yet re-applied.
    ///
    /// The error run above is self-healing by design: any applied event clears it, which is
    /// right for a transient failure and wrong for a contiguity gap. A break in the per-leaf
    /// loop leaves the rest of that event's leaves unapplied, and every later leaf then fails
    /// the contiguity guard while unrelated events keep clearing the run. This counter is
    /// what distinguishes the two, so it is deliberately NOT cleared by
    /// [`Self::record_applied_event`]. Only a reorg rewind, which is the path that actually
    /// restores contiguity, clears it.
    pub unapplied_leaves: u64,
    /// Lowest block holding leaves counted by [`Self::unapplied_leaves`], `None` when none are
    /// outstanding.
    ///
    /// The count alone cannot say whether a rewind reaches the gap. The indexer resumes at
    /// `rewind_height + 1`, so only a rewind strictly BELOW this block redelivers those leaves;
    /// clearing on a shallower one discards a gap that can never be re-derived.
    pub first_abandoned_block: Option<u64>,
}

impl ConsumerMetrics {
    /// Blocks the indexer is behind the chain tip. Zero on a quiet chain.
    #[must_use]
    pub fn indexer_lag_blocks(&self) -> u64 {
        self.last_known_chain_head
            .saturating_sub(self.last_scanned_block)
    }

    /// Blocks since the last applied event. Grows on a quiet chain by design;
    /// alert only alongside a nonzero [`Self::indexer_lag_blocks`].
    #[must_use]
    pub fn blocks_since_last_applied_event(&self) -> u64 {
        self.last_known_chain_head
            .saturating_sub(self.last_applied_block)
    }

    /// Record an applied event height. Monotonic; leaves the resume floor alone.
    pub fn record_applied_block(&mut self, height: u64) {
        // `max` is load-bearing: in single-instance mode the PPOI mirror worker shares
        // this struct with the chain bridge and emits every row at height 0, so plain
        // assignment would reset the pointer.
        self.last_applied_block = self.last_applied_block.max(height);
        self.last_scanned_block = self.last_scanned_block.max(height);
    }

    /// Record one successfully applied event: the height, the event count, and
    /// the end of any error run.
    ///
    /// Only for an event that MUTATED the tree. Clearing the error run is what
    /// `/health/ready` gates on, so an event that leaves the tree untouched must use
    /// [`Self::record_applied_non_tree_event`]: otherwise an unrelated log erases the
    /// signal that leaf application is stuck, and the stall reads as resolved while
    /// every later leaf still fails the contiguity guard.
    pub fn record_applied_event(&mut self, height: u64) {
        self.record_applied_block(height);
        self.events_processed = self.events_processed.saturating_add(1);
        self.consecutive_event_errors = 0;
        // `unapplied_leaves` is deliberately untouched: applying one event says nothing
        // about leaves a previous event abandoned, and clearing it here would restore the
        // fail-open this counter exists to close.
    }

    /// Record leaves abandoned by a break in the per-leaf loop at `block`.
    pub fn record_abandoned_leaves(&mut self, count: u64, block: u64) {
        self.unapplied_leaves = self.unapplied_leaves.saturating_add(count);
        self.first_abandoned_block = Some(match self.first_abandoned_block {
            Some(first) => first.min(block),
            None => block,
        });
    }

    /// Contiguity restored: a rewind to `rewound_to` redelivers every abandoned block.
    ///
    /// Scoped to the rewind depth deliberately. The indexer sets its cursor to `rewound_to`
    /// and rescans from `rewound_to + 1`, so a rewind at or above the first abandoned block
    /// redelivers nothing that is missing, and clearing on it would restore the fail-open
    /// [`Self::unapplied_leaves`] exists to close - irreversibly, since a zeroed gap cannot
    /// be re-derived.
    pub fn clear_abandoned_leaves_reopened_by(&mut self, rewound_to: u64) {
        if self
            .first_abandoned_block
            .is_some_and(|first| rewound_to < first)
        {
            self.unapplied_leaves = 0;
            self.first_abandoned_block = None;
        }
    }

    /// Record an event that advanced the chain cursor without touching the tree.
    ///
    /// Counts the event and the height, and deliberately leaves any error run intact.
    pub fn record_applied_non_tree_event(&mut self, height: u64) {
        self.record_applied_block(height);
        self.events_processed = self.events_processed.saturating_add(1);
    }
}

/// Bound on republishing a commit that lost the state swap to a concurrent session
/// eviction. Each attempt is Arc clones plus a CAS, so the bound exists to turn a
/// pathological ticker into a loud error rather than an unbounded spin.
const SWAP_RETRY_ATTEMPTS: u32 = 4;

/// Layer 2 verifier wiring threaded into [`run_consumer_task`].
pub struct Layer2VerifierContext {
    /// Verify every Nth commit. `0` disables.
    pub cadence_n: u32,
    /// Tree number whose IMT root is verified.
    pub tree_number: u32,
    /// Chain source. `None` disables the verifier.
    pub chain_source: Option<Arc<dyn raven_railgun_indexer::ChainSource>>,
}

impl std::fmt::Debug for Layer2VerifierContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Layer2VerifierContext")
            .field("cadence_n", &self.cadence_n)
            .field("tree_number", &self.tree_number)
            .field("chain_source_attached", &self.chain_source.is_some())
            .finish()
    }
}

struct Layer2VerifierState {
    ctx: Layer2VerifierContext,
    commits_since_last_verify: u32,
    /// Only a real InSync verdict sets it; a process-start default of 0 would
    /// truncate every tree to genesis.
    last_in_sync_height: Option<u64>,
    last_seen_commits: u64,
    last_seen_reorgs: u64,
    last_seen_consumer_errors: u64,
}

impl Layer2VerifierState {
    fn new(ctx: Layer2VerifierContext, baseline_metrics: &ConsumerMetrics) -> Self {
        Self {
            ctx,
            commits_since_last_verify: 0,
            last_in_sync_height: None,
            last_seen_commits: baseline_metrics.commits_fired,
            last_seen_reorgs: baseline_metrics.reorgs_handled,
            last_seen_consumer_errors: baseline_metrics.consumer_errors,
        }
    }

    fn is_active(&self) -> bool {
        self.ctx.cadence_n > 0 && self.ctx.chain_source.is_some()
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn maybe_verify_and_act(
        &mut self,
        current_height: u64,
        instance: &Arc<PirInstance<RavenInspireScheme>>,
        persistence: &Arc<InspirePersistence>,
        logical_store: &Arc<parking_lot::Mutex<super::inspire::LogicalLeafStore>>,
        params: &raven_inspire::params::InspireParams,
        encoder: &dyn super::pir_table::PirTableEncoder,
        metrics: &Arc<parking_lot::Mutex<ConsumerMetrics>>,
    ) {
        if !self.is_active() {
            return;
        }

        let (commits, reorgs, consumer_errors) = {
            let m = metrics.lock();
            (m.commits_fired, m.reorgs_handled, m.consumer_errors)
        };

        if commits == self.last_seen_commits {
            if reorgs > self.last_seen_reorgs {
                self.last_seen_reorgs = reorgs;
                self.commits_since_last_verify = 0;
                return;
            }
            // Errors climbing with no commit is a wedge, not a quiet window, and a
            // wedged instance is the one that most needs the divergence verdict.
            if consumer_errors == self.last_seen_consumer_errors {
                return;
            }
            self.last_seen_consumer_errors = consumer_errors;
        } else {
            self.last_seen_commits = commits;
            self.last_seen_consumer_errors = consumer_errors;

            if reorgs > self.last_seen_reorgs {
                self.last_seen_reorgs = reorgs;
                self.commits_since_last_verify = 0;
                tracing::debug!(
                    tree_number = self.ctx.tree_number,
                    "layer2 verifier: skipping cycle; layer1 reorg fired this cycle"
                );
                return;
            }
        }

        self.commits_since_last_verify = self.commits_since_last_verify.saturating_add(1);
        if self.commits_since_last_verify < self.ctx.cadence_n {
            return;
        }
        self.commits_since_last_verify = 0;

        let imt_clone = {
            let store = logical_store.lock();
            store.imt(self.ctx.tree_number).cloned()
        };
        let Some(imt) = imt_clone else {
            tracing::trace!(
                tree_number = self.ctx.tree_number,
                "layer2 verifier: no local IMT for tree; skipping"
            );
            return;
        };

        let Some(source) = self.ctx.chain_source.as_ref() else {
            return;
        };
        let outcome = match crate::layer_two::verify_root_against_chain(
            source.as_ref(),
            self.ctx.tree_number,
            &imt,
        )
        .await
        {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    tree_number = self.ctx.tree_number,
                    "layer2 verifier: transient RPC failure; will retry next cadence"
                );
                return;
            }
        };

        match outcome {
            crate::layer_two::VerifyOutcome::InSync => {
                metrics::counter!("raven_railgun_layer2_in_sync_total").increment(1);
                // The root is proven on chain, so the divergence is resolved even
                // when the verdict carries no usable height.
                if let Err(e) = persistence.clear_layer2_divergent() {
                    tracing::error!(
                        error = %e,
                        instance = instance.id.as_str(),
                        "layer2 verifier: in-sync verdict could not clear the \
                         on-disk divergence marker"
                    );
                }
                if current_height == 0 {
                    // Mirror rows carry height 0; anchoring there would rewind
                    // every tree to genesis on the next out-of-sync verdict.
                    tracing::debug!(
                        tree_number = self.ctx.tree_number,
                        "layer2 verifier: in-sync verdict carries no chain height; \
                         fork anchor left unchanged"
                    );
                } else {
                    self.last_in_sync_height = Some(current_height);
                }
            }
            crate::layer_two::VerifyOutcome::OutOfSync {
                local_root,
                tree_number,
            } => {
                metrics::counter!("raven_railgun_layer2_out_of_sync_total").increment(1);
                let Some(fork_height) = self.last_in_sync_height else {
                    metrics::counter!("raven_railgun_layer2_cascade_suppressed_total").increment(1);
                    persistence.mark_divergent_or_log(instance.id.as_str());
                    tracing::error!(
                        ?local_root,
                        tree_number,
                        instance = instance.id.as_str(),
                        "layer2 verifier: OutOfSync with no chain-anchored in-sync \
                         verdict; refusing to cascade a reorg with no known fork \
                         point, marking the instance divergent"
                    );
                    return;
                };
                tracing::warn!(
                    ?local_root,
                    tree_number,
                    last_in_sync_height = fork_height,
                    "layer2 verifier: OutOfSync; cascading reorg through existing reorg path"
                );
                let payload = WalEntryPayload::Reorg {
                    height: fork_height,
                };
                if let Err(e) = apply_reorg(
                    &payload,
                    fork_height,
                    instance,
                    persistence,
                    logical_store,
                    params,
                    encoder,
                    metrics,
                ) {
                    record_consumer_error(metrics, &e, "Layer2 synthetic reorg apply", fork_height);
                    // Repair failed, so the verdict stands unrepaired: same state as
                    // the arm with no anchor at all.
                    persistence.mark_divergent_or_log(instance.id.as_str());
                } else {
                    self.last_seen_reorgs = {
                        let m = metrics.lock();
                        m.reorgs_handled
                    };
                }
            }
        }
    }
}

/// Instance ids whose local tree is known to disagree with the chain and which
/// the verifier could not repair.
///
/// Process-wide because a readiness probe is process-wide: any divergent
/// instance must take the whole endpoint out of rotation.
static LAYER2_DIVERGENT: Mutex<std::collections::BTreeSet<String>> =
    Mutex::new(std::collections::BTreeSet::new());

/// Instance ids with an unrepaired Layer 2 divergence, sorted. Readiness probes
/// MUST fail closed while this is non-empty.
///
/// ```
/// # use raven_railgun_engine::persistence::layer2_divergent_instances;
/// assert!(
///     layer2_divergent_instances().is_empty(),
///     "no verifier round has run in this process, so nothing can be divergent"
/// );
/// ```
#[must_use]
pub fn layer2_divergent_instances() -> Vec<String> {
    LAYER2_DIVERGENT.lock().iter().cloned().collect()
}

/// Record that `instance_id` holds a tree the verifier proved out of sync and
/// could not repair. In-memory only; use
/// [`InspirePersistence::mark_layer2_divergent`] to survive a restart.
///
/// ```
/// # use raven_railgun_engine::persistence::{mark_layer2_divergent, clear_layer2_divergent, layer2_divergent_instances};
/// mark_layer2_divergent("doc-example-instance");
/// assert!(layer2_divergent_instances().iter().any(|id| id == "doc-example-instance"));
/// clear_layer2_divergent("doc-example-instance");
/// ```
pub fn mark_layer2_divergent(instance_id: &str) {
    LAYER2_DIVERGENT.lock().insert(instance_id.to_owned());
}

/// Drop the divergence mark for `instance_id`. Only a chain-anchored in-sync
/// verdict, or an operator that has repaired the tree, may call this.
/// In-memory only; use [`InspirePersistence::clear_layer2_divergent`] to also
/// drop the on-disk marker.
///
/// ```
/// # use raven_railgun_engine::persistence::{clear_layer2_divergent, layer2_divergent_instances};
/// clear_layer2_divergent("doc-example-never-marked");
/// assert!(!layer2_divergent_instances().iter().any(|id| id == "doc-example-never-marked"));
/// ```
pub fn clear_layer2_divergent(instance_id: &str) {
    LAYER2_DIVERGENT.lock().remove(instance_id);
}

/// Instance ids whose WAL replay could not apply every entry it read.
///
/// Process-wide for the same reason as [`LAYER2_DIVERGENT`]: the tree such an
/// instance would answer from is behind its own WAL.
static WAL_REPLAY_SKIPPED: Mutex<std::collections::BTreeSet<String>> =
    Mutex::new(std::collections::BTreeSet::new());

/// Instance ids whose last open skipped a WAL entry, sorted. Readiness probes
/// MUST fail closed while this is non-empty.
///
/// ```
/// # use raven_railgun_engine::persistence::wal_replay_skipped_instances;
/// assert!(
///     wal_replay_skipped_instances().is_empty(),
///     "no instance has been opened in this process, so no replay can have skipped"
/// );
/// ```
#[must_use]
pub fn wal_replay_skipped_instances() -> Vec<String> {
    WAL_REPLAY_SKIPPED.lock().iter().cloned().collect()
}

/// Record that `instance_id` recovered with at least one unapplied WAL entry.
///
/// ```
/// # use raven_railgun_engine::persistence::{mark_wal_replay_skipped, clear_wal_replay_skipped, wal_replay_skipped_instances};
/// mark_wal_replay_skipped("doc-example-skipped");
/// assert!(wal_replay_skipped_instances().iter().any(|id| id == "doc-example-skipped"));
/// clear_wal_replay_skipped("doc-example-skipped");
/// ```
pub fn mark_wal_replay_skipped(instance_id: &str) {
    WAL_REPLAY_SKIPPED.lock().insert(instance_id.to_owned());
}

/// Drop the replay-skip mark for `instance_id`. Only an operator who has
/// repaired the WAL may call this; a reopen re-derives the mark on its own.
///
/// ```
/// # use raven_railgun_engine::persistence::{clear_wal_replay_skipped, wal_replay_skipped_instances};
/// clear_wal_replay_skipped("doc-example-never-skipped");
/// assert!(!wal_replay_skipped_instances().iter().any(|id| id == "doc-example-never-skipped"));
/// ```
pub fn clear_wal_replay_skipped(instance_id: &str) {
    WAL_REPLAY_SKIPPED.lock().remove(instance_id);
}

/// Per instance, commits whose retention pass failed since process start. Process-wide so
/// `/v1/health/ready` can report it without a handle on each instance's persistence.
static RETENTION_FAILURES: Mutex<std::collections::BTreeMap<String, u64>> =
    Mutex::new(std::collections::BTreeMap::new());

/// Retention failures per instance id since process start; instances without one are absent.
///
/// ```
/// # use raven_railgun_engine::persistence::retention_failures;
/// assert!(retention_failures().is_empty(), "nothing has committed in this process");
/// ```
#[must_use]
pub fn retention_failures() -> std::collections::BTreeMap<String, u64> {
    RETENTION_FAILURES.lock().clone()
}

fn record_retention_failure(instance_id: &str) {
    let mut failures = RETENTION_FAILURES.lock();
    let count = failures.entry(instance_id.to_owned()).or_insert(0);
    *count = count.saturating_add(1);
    drop(failures);
    metrics::counter!(
        "raven_railgun_retention_failures_total",
        "instance" => instance_id.to_owned()
    )
    .increment(1);
}

fn ensure_layer2_metrics_described() {
    metrics::describe_counter!(
        "raven_railgun_layer2_in_sync_total",
        metrics::Unit::Count,
        "Count of Layer 2 verifier rounds that observed an in-sync IMT \
         root against the contract's rootHistory + merkleRoot."
    );
    metrics::counter!("raven_railgun_layer2_in_sync_total").increment(0);
    metrics::describe_counter!(
        "raven_railgun_layer2_out_of_sync_total",
        metrics::Unit::Count,
        "Count of Layer 2 verifier rounds that observed an out-of-sync \
         IMT root."
    );
    metrics::counter!("raven_railgun_layer2_out_of_sync_total").increment(0);
    metrics::describe_counter!(
        "raven_railgun_layer2_cascade_suppressed_total",
        metrics::Unit::Count,
        "Count of out-of-sync Layer 2 verdicts that did NOT cascade a \
         synthetic reorg because no in-sync verdict had established a fork \
         point yet. Non-zero means the local tree disagrees with the chain \
         and the verifier cannot safely repair it; operator action required."
    );
    metrics::counter!("raven_railgun_layer2_cascade_suppressed_total").increment(0);
}

/// Run the engine consumer task until [`ConsumerEvent::Shutdown`] or channel close.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub async fn run_consumer_task(
    instance: Arc<PirInstance<RavenInspireScheme>>,
    persistence: Arc<InspirePersistence>,
    logical_store: Arc<parking_lot::Mutex<super::inspire::LogicalLeafStore>>,
    metrics: Arc<parking_lot::Mutex<ConsumerMetrics>>,
    params: raven_inspire::params::InspireParams,
    encoder: Arc<dyn super::pir_table::PirTableEncoder>,
    mut rx: tokio::sync::mpsc::Receiver<ConsumerEvent>,
    verifier_ctx: Option<Layer2VerifierContext>,
) -> Result<()> {
    use raven_railgun_persistence::WalEntryPayload;

    ensure_layer2_metrics_described();
    crate::ppoi_root::ensure_metrics_described();

    // Seed from the manifest so an idle instance does not reset its resume floor.
    {
        let mut m = metrics.lock();
        if m.last_applied_leaf_block == 0 {
            m.last_applied_leaf_block = persistence.manifest_block_height();
        }
    }

    // No addendum seeding here. Recovery has already advanced `logical_store` to the WAL tip,
    // so deriving from it and recording the committed `encoded_db` as provenance produces a
    // consistent-looking pair that folds to a wrong root. `InspirePersistence::open` seeds the
    // table from the snapshot's own store instead, before replay.

    let mut verifier_state = verifier_ctx.map(|ctx| {
        let baseline = *metrics.lock();
        Layer2VerifierState::new(ctx, &baseline)
    });

    // Snapshot triggers fire only on an append, so a feed that goes quiet, a static policy, or a
    // WAL tail replayed at open would otherwise leave applied rows out of the served database
    // until the next triggering append or shutdown. The shim reads the store and would not show
    // it.
    let mut unpublished_since: Option<tokio::time::Instant> = None;
    let mut commits_seen = metrics.lock().commits_fired;
    // This loop's share of the error run. A complete tree applies no further event to clear it,
    // so the next commit by any path does, or one transient failure holds readiness shut for good.
    let mut failed_publishes: u64 = 0;
    // An event taken off the queue behind a run of list rows, handled before the next receive.
    let mut pending: Option<ConsumerEvent> = None;

    loop {
        let now = tokio::time::Instant::now();
        {
            let mut m = metrics.lock();
            if m.consecutive_event_errors == 0 {
                failed_publishes = 0;
            }
            if m.commits_fired != commits_seen {
                commits_seen = m.commits_fired;
                unpublished_since = None;
                m.consecutive_event_errors =
                    m.consecutive_event_errors.saturating_sub(failed_publishes);
                failed_publishes = 0;
            }
        }
        let behind = !logical_store.lock().dirty_shards().is_empty();
        unpublished_since = if behind {
            unpublished_since.or(Some(now))
        } else {
            None
        };
        let publish_at = unpublished_since.map(|since| {
            since
                .checked_add(persistence.snapshot_policy().publish_bound())
                .unwrap_or(since)
        });
        let idle = pending.is_none() && rx.is_empty();
        let requested = idle
            && persistence
                .publish_requested
                .swap(false, std::sync::atomic::Ordering::AcqRel);
        if publish_at.is_some_and(|at| at <= now) || (requested && behind) {
            // Between events, so the floor names only blocks whose events fully applied.
            let floor = metrics.lock().last_applied_leaf_block;
            if let Err(e) = drive_commit(
                &instance,
                &persistence,
                &logical_store,
                &params,
                encoder.as_ref(),
                floor,
                &metrics,
            ) {
                tracing::error!(
                    error = %e,
                    block_height = floor,
                    "deferred publish failed; the rows stay applied and it is retried after the \
                     publish bound"
                );
                let mut m = metrics.lock();
                m.consumer_errors = m.consumer_errors.saturating_add(1);
                m.consecutive_event_errors = m.consecutive_event_errors.saturating_add(1);
                drop(m);
                failed_publishes = failed_publishes.saturating_add(1);
                unpublished_since = Some(tokio::time::Instant::now());
            }
            continue;
        }
        let received = if let Some(event) = pending.take() {
            Some(event)
        } else {
            let publish_due = async {
                match publish_at {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                received = rx.recv() => received,
                () = persistence.wake.notified() => continue,
                () = publish_due => continue,
            }
        };
        let Some(msg) = received else {
            tracing::info!("consumer channel closed; exiting");
            return Ok(());
        };

        let (payload, height) = match msg {
            ConsumerEvent::Chain(event, height) => {
                match event {
                    raven_railgun_core::RailgunEvent::Shield {
                        tree_number,
                        leaves,
                        ..
                    }
                    | raven_railgun_core::RailgunEvent::Transact {
                        tree_number,
                        leaves,
                        ..
                    } => {
                        let mut had_error = false;
                        for (leaf_idx, leaf) in leaves.iter().enumerate() {
                            match replay_disposition(&logical_store, leaf) {
                                Ok(LeafDisposition::AlreadyApplied) => continue,
                                Ok(LeafDisposition::Pending) => {}
                                Err(e) => {
                                    had_error = true;
                                    record_consumer_error(
                                        &metrics,
                                        &e,
                                        "AppendLeaf replay screen",
                                        height,
                                    );
                                    // This leaf and every one after it are abandoned. The
                                    // error run alone cannot say that: an unrelated event
                                    // clears it while the gap is still there.
                                    metrics.lock().record_abandoned_leaves(
                                        abandoned_from(&leaves, leaf_idx),
                                        height,
                                    );
                                    break;
                                }
                            }
                            let p = WalEntryPayload::AppendLeaf {
                                tree_number: leaf.tree_number,
                                leaf_index: leaf.leaf_index,
                                commitment: leaf.commitment_hash,
                            };
                            if let Err(e) = apply_one_leaf(
                                &p,
                                height,
                                &instance,
                                &persistence,
                                &logical_store,
                                &params,
                                encoder.as_ref(),
                                &metrics,
                            ) {
                                had_error = true;
                                record_consumer_error(&metrics, &e, "AppendLeaf apply", height);
                                metrics.lock().record_abandoned_leaves(
                                    abandoned_from(&leaves, leaf_idx),
                                    height,
                                );
                                break;
                            }
                            if let Some(state) = verifier_state.as_mut() {
                                state
                                    .maybe_verify_and_act(
                                        height,
                                        &instance,
                                        &persistence,
                                        &logical_store,
                                        &params,
                                        encoder.as_ref(),
                                        &metrics,
                                    )
                                    .await;
                            }
                        }
                        // Per-leaf path already committed and recorded metrics.
                        let _ = (tree_number, leaves);
                        if !had_error {
                            let mut m = metrics.lock();
                            // Only now is block `height` fully applied. A chain source
                            // returning a range unsorted delivers a lower block after a
                            // higher one; only a reorg rewind may lower the floor.
                            m.last_applied_leaf_block = m.last_applied_leaf_block.max(height);
                            m.record_applied_event(height);
                        }
                        continue;
                    }
                    raven_railgun_core::RailgunEvent::Nullified { .. } => {
                        // No new leaves, so height only; never advances the resume floor.
                        metrics.lock().record_applied_non_tree_event(height);
                        continue;
                    }
                    raven_railgun_core::RailgunEvent::Unshield { .. } => {
                        // Not a tree mutation, so height only.
                        metrics.lock().record_applied_non_tree_event(height);
                        continue;
                    }
                }
            }
            ConsumerEvent::Reorg(height) => {
                if let Err(e) = apply_indexer_reorg(
                    height,
                    &instance,
                    &persistence,
                    &logical_store,
                    &params,
                    encoder.as_ref(),
                    &metrics,
                ) {
                    record_consumer_error(&metrics, &e, "Reorg apply", height);
                }
                continue;
            }
            ConsumerEvent::ReorgBarrier { height, completion } => {
                let outcome = apply_indexer_reorg(
                    height,
                    &instance,
                    &persistence,
                    &logical_store,
                    &params,
                    encoder.as_ref(),
                    &metrics,
                );
                if let Err(error) = &outcome {
                    record_consumer_error(&metrics, error, "Startup reorg apply", height);
                }
                let _ = completion
                    .send(outcome.map_err(|error| error.to_string()))
                    .await;
                continue;
            }
            ConsumerEvent::Ppoi(payload, height)
                if matches!(payload, WalEntryPayload::PpoiListLeafAdded { .. }) =>
            {
                let mut rows = vec![(payload, height)];
                while rows.len() < MAX_ROWS_PER_SYNC {
                    match rx.try_recv() {
                        Ok(ConsumerEvent::Ppoi(payload, height))
                            if matches!(payload, WalEntryPayload::PpoiListLeafAdded { .. }) =>
                        {
                            rows.push((payload, height));
                        }
                        Ok(other) => {
                            pending = Some(other);
                            break;
                        }
                        Err(_) => break,
                    }
                }
                apply_list_rows(
                    &rows,
                    &instance,
                    &persistence,
                    &logical_store,
                    &params,
                    encoder.as_ref(),
                    &metrics,
                );
                if let Some(state) = verifier_state.as_mut() {
                    state
                        .maybe_verify_and_act(
                            height,
                            &instance,
                            &persistence,
                            &logical_store,
                            &params,
                            encoder.as_ref(),
                            &metrics,
                        )
                        .await;
                }
                continue;
            }
            // Any other payload sent as a mirror row. The mirror sends none, but the channel
            // admits every kind, and each applies as its own.
            ConsumerEvent::Ppoi(payload, height) => (payload, height),
            ConsumerEvent::Heartbeat {
                chain_head,
                scanned_through,
            } => {
                let mut m = metrics.lock();
                m.last_known_chain_head = chain_head;
                // Tracks the cursor verbatim, rewinds included: a reorg does leave
                // those blocks to re-scan.
                m.last_scanned_block = scanned_through;
                let lag = m.indexer_lag_blocks();
                let scanned = m.last_scanned_block;
                drop(m);
                #[allow(clippy::cast_precision_loss)]
                let lag_f64 = lag as f64;
                #[allow(clippy::cast_precision_loss)]
                let head_f64 = chain_head as f64;
                #[allow(clippy::cast_precision_loss)]
                let scanned_f64 = scanned as f64;
                metrics::gauge!("raven_railgun_indexer_lag_blocks").set(lag_f64);
                metrics::gauge!("raven_railgun_indexer_chain_head_block").set(head_f64);
                metrics::gauge!("raven_railgun_indexer_scanned_block").set(scanned_f64);
                continue;
            }
            ConsumerEvent::Shutdown => {
                // Height MUST be the last applied-leaf block, not the chain head:
                // the resume floor reads it, and the tip would skip a lagging leaf
                // and wedge the tree on restart.
                let final_height = {
                    let m = metrics.lock();
                    m.last_applied_leaf_block
                };
                // A snapshot of an unchanged cell rewrites the whole database for nothing.
                if logical_store.lock().dirty_shards().is_empty()
                    && persistence.unchanged_since_commit(final_height)
                {
                    if let Err(error) =
                        persistence.persist_cache_if_changed(instance.current_state().as_ref())
                    {
                        tracing::warn!(%error, "offline packing cache store failed at stop");
                    }
                    tracing::info!(
                        final_height,
                        "nothing applied since the last commit; stopping"
                    );
                    return Ok(());
                }
                if let Err(e) = drive_commit(
                    &instance,
                    &persistence,
                    &logical_store,
                    &params,
                    encoder.as_ref(),
                    final_height,
                    &metrics,
                ) {
                    tracing::error!(
                        error = %e,
                        "final commit on stop failed; the next boot recovers from the last \
                         snapshot and write-ahead log"
                    );
                    return Err(e);
                }
                tracing::info!(final_height, "consumer drained final commit on Shutdown");
                return Ok(());
            }
        };

        if let Err(e) = apply_ppoi(
            &payload,
            height,
            &instance,
            &persistence,
            &logical_store,
            &params,
            encoder.as_ref(),
            &metrics,
        ) {
            record_consumer_error(&metrics, &e, "Ppoi apply", height);
            continue;
        }
        // Per PAYLOAD, not per arm: only an IMT append can close the contiguity gap the error
        // run stands for.
        if super::inspire::appends_to_a_tree(&payload) {
            metrics.lock().record_applied_event(height);
        } else {
            metrics.lock().record_applied_non_tree_event(height);
        }
        if let Some(state) = verifier_state.as_mut() {
            state
                .maybe_verify_and_act(
                    height,
                    &instance,
                    &persistence,
                    &logical_store,
                    &params,
                    encoder.as_ref(),
                    &metrics,
                )
                .await;
        }
    }
}

fn record_consumer_error(
    metrics: &Arc<parking_lot::Mutex<ConsumerMetrics>>,
    err: &AdapterError,
    op: &'static str,
    height: u64,
) {
    tracing::error!(
        error = %err,
        op = op,
        block_height = height,
        "consumer event failed; dropping event and continuing"
    );
    let mut m = metrics.lock();
    m.consumer_errors = m.consumer_errors.saturating_add(1);
    m.consecutive_event_errors = m.consecutive_event_errors.saturating_add(1);
}

/// Leaves from `broke_at` to the end of the event, which the break left unapplied.
///
/// An upper bound, not an exact count: `drive_commit` can fail after the leaf at `broke_at`
/// already reached the WAL and the store. Over-counting holds the readiness gate closed,
/// which is the safe direction.
fn abandoned_from<T>(leaves: &[T], broke_at: usize) -> u64 {
    u64::try_from(leaves.len().saturating_sub(broke_at)).unwrap_or(u64::MAX)
}

enum LeafDisposition {
    AlreadyApplied,
    Pending,
}

// A kill mid-event leaves the resume floor inside that block, so the indexer
// re-reads it and redelivers every leaf; refusing the already-applied prefix
// would abort the event before its unapplied tail, and every restart would
// replay the same prefix. Identical bytes are the only proof an index is a
// replay, so differing bytes stay a hard refusal.
fn replay_disposition(
    logical_store: &Arc<Mutex<super::inspire::LogicalLeafStore>>,
    leaf: &raven_railgun_core::CommitmentLeaf,
) -> Result<LeafDisposition> {
    let store = logical_store.lock();
    match store.leaf(leaf.tree_number, leaf.leaf_index) {
        None => Ok(LeafDisposition::Pending),
        Some(applied) if applied == &leaf.commitment_hash => Ok(LeafDisposition::AlreadyApplied),
        Some(applied) => Err(AdapterError::InvalidQuery(format!(
            "redelivered leaf_index {} on tree {} carries commitment {:02x?}, \
             but {:02x?} is already applied there; the chain source is serving a \
             divergent history and no reorg rewound it",
            leaf.leaf_index, leaf.tree_number, leaf.commitment_hash, applied
        ))),
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_one_leaf(
    p: &raven_railgun_persistence::WalEntryPayload,
    height: u64,
    instance: &Arc<PirInstance<RavenInspireScheme>>,
    persistence: &Arc<InspirePersistence>,
    logical_store: &Arc<parking_lot::Mutex<super::inspire::LogicalLeafStore>>,
    params: &raven_inspire::params::InspireParams,
    encoder: &dyn super::pir_table::PirTableEncoder,
    metrics: &Arc<parking_lot::Mutex<ConsumerMetrics>>,
) -> Result<()> {
    {
        let store = logical_store.lock();
        super::inspire::validate_apply(&store, p)?;
    }
    let (_seq, trigger) = persistence.apply_event(p, height)?;
    let filled = {
        let mut store = logical_store.lock();
        super::inspire::apply_wal_entry(&mut store, p, height, encoder)?;
        filled_its_tree(&store, p)
    };
    // The floor names the last FULLY applied block, so a leaf does not advance it:
    // an event that fails partway would otherwise leave the marker on a block the
    // indexer resumes above, and its remaining leaves are never re-read. The caller
    // advances it once the whole event lands. A commit driven mid-event therefore
    // commits under the previous floor, which is the conservative direction.
    let floor = { metrics.lock().last_applied_leaf_block };
    if trigger || filled {
        drive_commit(
            instance,
            persistence,
            logical_store,
            params,
            encoder,
            floor,
            metrics,
        )?;
    }
    Ok(())
}

/// Whether `payload` was the append that filled its tree. Nothing appends to that tree again, so
/// its last rows are published now rather than a publish bound later.
fn filled_its_tree(
    store: &super::inspire::LogicalLeafStore,
    payload: &raven_railgun_persistence::WalEntryPayload,
) -> bool {
    use raven_railgun_persistence::WalEntryPayload as P;
    let imt = match payload {
        P::AppendLeaf { tree_number, .. } => store.imt(*tree_number),
        P::PpoiListLeafAdded { list_key, .. } => store.ppoi_imt(list_key),
        P::Reorg { .. } | P::Heartbeat { .. } => None,
    };
    imt.is_some_and(|imt| imt.leaf_count() == super::imt::TREE_MAX_ITEMS)
}

#[allow(clippy::too_many_arguments)]
fn apply_indexer_reorg(
    height: u64,
    instance: &Arc<PirInstance<RavenInspireScheme>>,
    persistence: &Arc<InspirePersistence>,
    logical_store: &Arc<parking_lot::Mutex<super::inspire::LogicalLeafStore>>,
    params: &raven_inspire::params::InspireParams,
    encoder: &dyn super::pir_table::PirTableEncoder,
    metrics: &Arc<parking_lot::Mutex<ConsumerMetrics>>,
) -> Result<()> {
    let payload = raven_railgun_persistence::WalEntryPayload::Reorg { height };
    apply_reorg(
        &payload,
        height,
        instance,
        persistence,
        logical_store,
        params,
        encoder,
        metrics,
    )?;
    // Only replacement blocks above the fence can heal an abandoned suffix.
    metrics.lock().clear_abandoned_leaves_reopened_by(height);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_reorg(
    p: &raven_railgun_persistence::WalEntryPayload,
    height: u64,
    instance: &Arc<PirInstance<RavenInspireScheme>>,
    persistence: &Arc<InspirePersistence>,
    logical_store: &Arc<parking_lot::Mutex<super::inspire::LogicalLeafStore>>,
    params: &raven_inspire::params::InspireParams,
    encoder: &dyn super::pir_table::PirTableEncoder,
    metrics: &Arc<parking_lot::Mutex<ConsumerMetrics>>,
) -> Result<()> {
    let (_seq, _trigger) = persistence.apply_event(p, height)?;
    {
        let mut store = logical_store.lock();
        super::inspire::apply_wal_entry(&mut store, p, height, encoder)?;
    }
    // A rewind is the only thing that may lower the floor, and it may never raise
    // it past blocks whose leaves were never applied.
    let floor = {
        let mut m = metrics.lock();
        m.reorgs_handled = m.reorgs_handled.saturating_add(1);
        m.last_applied_leaf_block = m.last_applied_leaf_block.min(height);
        m.last_applied_leaf_block
    };
    drive_commit(
        instance,
        persistence,
        logical_store,
        params,
        encoder,
        floor,
        metrics,
    )
}

#[allow(clippy::too_many_arguments)]
fn apply_ppoi(
    payload: &raven_railgun_persistence::WalEntryPayload,
    height: u64,
    instance: &Arc<PirInstance<RavenInspireScheme>>,
    persistence: &Arc<InspirePersistence>,
    logical_store: &Arc<parking_lot::Mutex<super::inspire::LogicalLeafStore>>,
    params: &raven_inspire::params::InspireParams,
    encoder: &dyn super::pir_table::PirTableEncoder,
    metrics: &Arc<parking_lot::Mutex<ConsumerMetrics>>,
) -> Result<()> {
    {
        let store = logical_store.lock();
        super::inspire::validate_apply(&store, payload)?;
    }
    let (_seq, trigger) = persistence.apply_event(payload, height)?;
    let filled = {
        let mut store = logical_store.lock();
        super::inspire::apply_wal_entry(&mut store, payload, height, encoder)?;
        filled_its_tree(&store, payload)
    };
    // Mirror rows carry height 0, so neither the floor nor the commit marker may
    // be driven from `height`.
    let floor = {
        let mut m = metrics.lock();
        m.last_applied_leaf_block = m.last_applied_leaf_block.max(height);
        m.last_applied_leaf_block
    };
    if trigger || filled {
        drive_commit(
            instance,
            persistence,
            logical_store,
            params,
            encoder,
            floor,
            metrics,
        )?;
    }
    Ok(())
}

/// Most list rows one WAL sync covers: the queued rows the consumer takes at once, capped at
/// the mirror's largest page (upstream's limit). A batch need not align with a page, so
/// recovery stands on the last synced batch, and the feed asks for the rest again.
const MAX_ROWS_PER_SYNC: usize = 501;

/// One list's rows in a batch, screened on a copy of its tree the store does not show yet.
struct ListStage {
    list_key: [u8; 32],
    /// Rows the store held when the copy was taken.
    base: u32,
    tree: crate::imt::Imt,
    rows: Vec<(raven_railgun_persistence::WalEntryPayload, u64)>,
}

enum RowOutcome {
    Applied,
    /// A row the instance already holds, sent again; nothing to do and nothing to count.
    Held,
    Refused {
        error: AdapterError,
        /// The row the instance lacks, when this refusal leaves it waiting on that row.
        lacks: Option<u32>,
    },
}

/// Apply a run of list rows under one WAL sync.
///
/// Each row is screened on a copy of its list's tree and written to the WAL unsynced. Only once
/// the sync returns do the store, the metrics and any publish take the rows, so nothing a reader
/// sees can be lost by a crash: after one, recovery replays up to the last synced run and the
/// feed asks for the rest again.
#[allow(clippy::too_many_arguments)]
fn apply_list_rows(
    rows: &[(raven_railgun_persistence::WalEntryPayload, u64)],
    instance: &Arc<PirInstance<RavenInspireScheme>>,
    persistence: &Arc<InspirePersistence>,
    logical_store: &Arc<parking_lot::Mutex<super::inspire::LogicalLeafStore>>,
    params: &raven_inspire::params::InspireParams,
    encoder: &dyn super::pir_table::PirTableEncoder,
    metrics: &Arc<parking_lot::Mutex<ConsumerMetrics>>,
) {
    let mut stages: Vec<ListStage> = Vec::new();
    let mut outcomes: Vec<RowOutcome> = rows
        .iter()
        .map(|(payload, height)| {
            stage_list_row(&mut stages, payload, *height, persistence, logical_store)
        })
        .collect();

    let written = outcomes
        .iter()
        .any(|outcome| matches!(outcome, RowOutcome::Applied));
    let lists: Vec<[u8; 32]> = stages.iter().map(|stage| stage.list_key).collect();
    let lacks = stages.iter().map(|stage| stage.base).min();
    // A failed sync leaves the rows for the feed to ask for again. Only this consumer writes a
    // list tree, so an install after the sync cannot find it moved; were it to, the rows are
    // durable and asking for them again would write them twice, so they are not asked for.
    let durable = if !written {
        Ok(())
    } else if let Err(error) = persistence.sync_rows() {
        Err((error, lacks))
    } else {
        let mut store = logical_store.lock();
        stages
            .into_iter()
            .try_for_each(|stage| {
                store.apply_staged_list_rows(&stage.list_key, stage.tree, &stage.rows, encoder)
            })
            .map_err(|error| (error, None))
    };
    if let Err((error, lacks)) = durable {
        let reason = error.to_string();
        for outcome in &mut outcomes {
            if matches!(outcome, RowOutcome::Applied) {
                *outcome = RowOutcome::Refused {
                    error: AdapterError::Internal(reason.clone()),
                    lacks,
                };
            }
        }
    }

    let mut applied = false;
    for (outcome, (_, height)) in outcomes.into_iter().zip(rows) {
        match outcome {
            RowOutcome::Applied => {
                applied = true;
                let mut m = metrics.lock();
                // Mirror rows carry height 0, so neither the floor nor the commit marker may
                // be driven from `height`.
                m.last_applied_leaf_block = m.last_applied_leaf_block.max(*height);
                m.record_applied_event(*height);
                drop(m);
                *persistence.list_row_refused.lock() = None;
            }
            RowOutcome::Held => {}
            RowOutcome::Refused { error, lacks } => {
                record_consumer_error(metrics, &error, "Ppoi apply", *height);
                if lacks.is_some() {
                    *persistence.list_row_refused.lock() = lacks;
                }
            }
        }
    }
    if !applied {
        return;
    }
    let filled = {
        let store = logical_store.lock();
        lists.iter().any(|list_key| {
            store
                .ppoi_imt(list_key)
                .is_some_and(|imt| imt.leaf_count() == super::imt::TREE_MAX_ITEMS)
        })
    };
    if filled || persistence.snapshot_due() {
        let floor = metrics.lock().last_applied_leaf_block;
        if let Err(error) = drive_commit(
            instance,
            persistence,
            logical_store,
            params,
            encoder,
            floor,
            metrics,
        ) {
            record_consumer_error(metrics, &error, "Ppoi commit", floor);
        }
    }
}

fn stage_list_row(
    stages: &mut Vec<ListStage>,
    payload: &raven_railgun_persistence::WalEntryPayload,
    height: u64,
    persistence: &InspirePersistence,
    logical_store: &parking_lot::Mutex<super::inspire::LogicalLeafStore>,
) -> RowOutcome {
    let refused = |error, lacks| RowOutcome::Refused { error, lacks };
    let raven_railgun_persistence::WalEntryPayload::PpoiListLeafAdded {
        list_key,
        list_index,
        blinded_commitment,
        ..
    } = payload
    else {
        return refused(
            AdapterError::InvalidQuery("a list row batch holds a non-list payload".to_owned()),
            None,
        );
    };
    let at = if let Some(at) = stages.iter().position(|stage| stage.list_key == *list_key) {
        at
    } else {
        let (tree, base) = {
            let store = logical_store.lock();
            let held = store
                .ppoi_imt(list_key)
                .map_or(0, crate::imt::Imt::leaf_count);
            (store.list_tree_copy(list_key), held)
        };
        let tree = match tree {
            Ok(tree) => tree,
            Err(error) => return refused(error, None),
        };
        stages.push(ListStage {
            list_key: *list_key,
            base: u32::try_from(base).unwrap_or(u32::MAX),
            tree,
            rows: Vec::new(),
        });
        stages.len() - 1
    };
    let Some(stage) = stages.get_mut(at) else {
        return refused(
            AdapterError::Internal("list stage vanished".to_owned()),
            None,
        );
    };
    let staged = stage.tree.leaf_count();
    let lacks = u32::try_from(staged).ok();
    if (*list_index as usize) < staged {
        let same = if *list_index < stage.base {
            logical_store.lock().holds_list_row(payload) == Some(true)
        } else {
            stage
                .rows
                .get((*list_index - stage.base) as usize)
                .is_some_and(|(held, _)| held == payload)
        };
        if same {
            return RowOutcome::Held;
        }
        return refused(
            AdapterError::InvalidQuery(format!(
                "redelivered list_index {list_index} carries commitment \
                 {blinded_commitment:02x?}, which is not the row already applied there; the \
                 upstream is serving a divergent list"
            )),
            None,
        );
    }
    if let Err(error) = super::inspire::LogicalLeafStore::stage_list_row(&mut stage.tree, payload) {
        return refused(error, lacks);
    }
    if let Err(error) = persistence.append_unsynced(payload, height) {
        stage.tree.truncate_to(staged);
        return refused(error, lacks);
    }
    stage.rows.push((payload.clone(), height));
    RowOutcome::Applied
}

/// A rewind that drops leaves always marks their shards dirty, so on the branch
/// with nothing dirty no legitimate cause can have shrunk the store. Publishing
/// anyway archives the WAL that still holds those leaves and no later build
/// recovers the tree.
fn ensure_store_not_shorter_than_published(
    persistence: &InspirePersistence,
    instance_id: &str,
    staged: usize,
    height: u64,
) -> Result<()> {
    let committed = persistence.committed_leaf_count();
    if staged < committed {
        return Err(AdapterError::Internal(format!(
            "commit refused for instance {instance_id}: staging {staged} leaves \
             against a published snapshot of {committed} with no dirty shard to \
             explain the drop (height {height}); publishing would archive the WAL \
             that still holds them"
        )));
    }
    Ok(())
}

/// Publish a re-encoded database, retrying over a concurrent session-store swap.
///
/// The re-encode spans the whole per-shard loop while `heartbeat_session_eviction`
/// publishes on a ticker with a derivation that is only Arc clones, so the eviction
/// almost always wins and the expensive work is the work discarded. Surfacing that lost
/// race as a data error abandons the block's remaining leaves, after which the contiguity
/// guard refuses every later leaf for good.
///
/// # Errors
/// Refuses without retrying when the published database is no longer the one this commit
/// re-encoded from: another COMMIT won, and republishing these rows would drop its update.
/// Refuses after [`SWAP_RETRY_ATTEMPTS`] losses to a session-store-only swap.
fn publish_recommitted_state(
    instance: &Arc<PirInstance<RavenInspireScheme>>,
    derived_from: &Arc<super::Snapshot<RavenInspireScheme>>,
    current: &Arc<super::inspire::InspireServerState>,
    new_db: &Arc<raven_inspire::EncodedDatabase>,
    height: u64,
) -> Result<()> {
    // `swap_state` takes `new_state` by value and drops it on refusal, so each attempt
    // rebuilds it around the same `new_db`.
    let mut published_from = Arc::clone(derived_from);
    let mut attempt = 0u32;
    loop {
        let new_state = super::inspire::InspireServerState {
            crs: Arc::clone(&published_from.state.crs),
            encoded_db: Arc::clone(new_db),
            cache: Arc::clone(&published_from.state.cache),
            session_store: Arc::clone(&published_from.state.session_store),
            variant: current.variant,
            entry_size: current.entry_size,
        };
        match instance.swap_state(new_state, published_from.epoch.next()) {
            Ok(()) => return Ok(()),
            Err(e) => {
                // Classify by the error, not by pointer identity. `swap_state` refuses a
                // shape mismatch before its CAS, so nothing swapped and the pointers stay
                // equal: the identity test reads a geometry refusal as contention and
                // buries it under retries that cannot help.
                if matches!(e, AdapterError::StateShapeMismatch { .. }) {
                    return Err(e);
                }
                let fresh = instance.current_snapshot();
                if !Arc::ptr_eq(&fresh.state.encoded_db, &current.encoded_db) {
                    return Err(e);
                }
                attempt = attempt.saturating_add(1);
                if attempt >= SWAP_RETRY_ATTEMPTS {
                    return Err(AdapterError::Internal(format!(
                        "commit at height {height} lost the state swap {attempt} times to a \
                         concurrent publisher that changed only the session store. The \
                         re-encoded rows are correct but could not be published. Operator: \
                         a session-eviction ticker is contending with every commit on this \
                         instance; raise session_eviction_interval_secs or lower the commit \
                         cadence."
                    )));
                }
                published_from = fresh;
            }
        }
    }
}

fn drive_commit(
    instance: &Arc<PirInstance<RavenInspireScheme>>,
    persistence: &Arc<InspirePersistence>,
    logical_store: &Arc<parking_lot::Mutex<super::inspire::LogicalLeafStore>>,
    params: &raven_inspire::params::InspireParams,
    encoder: &dyn super::pir_table::PirTableEncoder,
    height: u64,
    metrics: &Arc<parking_lot::Mutex<ConsumerMetrics>>,
) -> Result<()> {
    let dirty: Vec<u32> = {
        let store = logical_store.lock();
        store.dirty_shards().iter().copied().collect()
    };

    if dirty.is_empty() {
        let snapshot_state = instance.current_state();
        // Snapshot the store under-lock so it matches the state captured above.
        let store_snapshot = {
            let s = logical_store.lock();
            s.clone()
        };
        ensure_store_not_shorter_than_published(
            persistence,
            instance.id.as_str(),
            store_snapshot.leaf_count(),
            height,
        )?;
        let _new_id = persistence.commit_v6(snapshot_state.as_ref(), &store_snapshot, height)?;
        {
            let mut m = metrics.lock();
            m.commits_fired = m.commits_fired.saturating_add(1);
        }
        persistence.commit_notify().notify_waiters();
        return Ok(());
    }

    // `Arc::make_mut` copies once per drive_commit; `current` is always a live
    // second reference. State and epoch come from ONE load so the swap below can
    // refuse a derivation another writer has already superseded.
    let derived_from = instance.current_snapshot();
    let current = Arc::clone(&derived_from.state);
    let entries_per_shard = u32::try_from(
        current
            .encoded_db
            .config
            .entries_per_shard()
            .min(u64::from(u32::MAX)),
    )
    .unwrap_or(u32::MAX);
    let entry_size = current.entry_size;

    ensure_encoder_matches_stored_cell(current.shard_config(), entries_per_shard, encoder)?;
    let mut new_db = Arc::clone(&current.encoded_db);
    let instance_label = instance.id.as_str().to_owned();
    for shard_id in dirty {
        let bytes = {
            let store = logical_store.lock();
            encoder.materialize_shard(shard_id, &store)
        };
        match super::inspire::re_encode_shard(
            Arc::make_mut(&mut new_db),
            params,
            shard_id,
            &bytes,
            entry_size,
        ) {
            Ok(()) => {}
            Err(AdapterError::ShardOutOfRange {
                shard_id: oor_id,
                db_shard_count,
            }) => {
                // Out-of-range shard ids are unencodable; dropping breaks the retry
                // loop. Metric carries only `instance` to bound label cardinality.
                let removed = logical_store.lock().drop_dirty_shard(oor_id);
                if removed {
                    tracing::error!(
                        instance_id = %instance_label,
                        shard_id = oor_id,
                        db_shard_count,
                        "drive_commit: dropping unsatisfiable dirty shard \
                         (id past EncodedDatabase shard count); subsequent \
                         commits will not retry this shard"
                    );
                    metrics::counter!(
                        "raven_railgun_unsatisfiable_dirty_shards_total",
                        "instance" => instance_label.clone(),
                    )
                    .increment(1);
                }
            }
            Err(e) => return Err(e),
        }
    }

    publish_recommitted_state(instance, &derived_from, &current, &new_db, height)?;

    // Derive the upper-sibling addenda from the tree this state was encoded from, recorded against
    // the encoded database just published. The consumer is the sole writer for this instance and is inside
    // this function, so no append can interleave and the pair is consistent by construction.
    {
        let snapshot = instance.current_snapshot();
        let entries_per_shard = encoder.entries_per_shard();
        let mut store = logical_store.lock();
        store.refresh_committed_addenda(&snapshot.state.encoded_db, entries_per_shard);
    }

    let snapshot_state = instance.current_state();
    // Snapshot the store under-lock so it restores atomically with the state.
    let store_snapshot = {
        let s = logical_store.lock();
        s.clone()
    };
    let _new_id = persistence.commit_v6(snapshot_state.as_ref(), &store_snapshot, height)?;

    logical_store.lock().clear_dirty_shards();
    {
        let mut m = metrics.lock();
        m.commits_fired = m.commits_fired.saturating_add(1);
    }
    persistence.commit_notify().notify_waiters();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pir_table::{PerLeafCommitmentEncoder, PirTableEncoder};
    use raven_inspire::params::{InspireParams, InspireVariant};
    use raven_railgun_core::InstanceId;

    const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-v1-test";
    /// Shared by [`test_encoder`] and [`build_toy_state`]; divergence is a
    /// cell-shape mismatch the open/commit guards refuse.
    const TOY_ENTRY_SIZE: usize = 256;
    const TOY_ENTRIES_PER_SHARD: u32 = 2048;

    fn test_encoder() -> Arc<dyn PirTableEncoder> {
        Arc::new(
            PerLeafCommitmentEncoder::new(TOY_ENTRY_SIZE, TOY_ENTRIES_PER_SHARD, 0)
                .expect("test encoder"),
        )
    }

    #[test]
    fn quiet_chain_holds_lag_at_zero_while_event_distance_grows() {
        let mut m = ConsumerMetrics::default();
        m.record_applied_block(1_000);
        m.last_applied_leaf_block = 1_000;

        for head in [1_001u64, 1_500, 20_000, 9_000_000] {
            m.last_known_chain_head = head;
            m.last_scanned_block = head;
            assert_eq!(
                m.indexer_lag_blocks(),
                0,
                "scanner at tip must report zero lag at head {head}"
            );
            assert_eq!(m.blocks_since_last_applied_event(), head - 1_000);
        }

        assert_eq!(m.last_applied_block, 1_000);
        assert_eq!(
            m.last_applied_leaf_block, 1_000,
            "resume floor must be untouched by scan progress"
        );
    }

    #[test]
    fn backfill_reports_real_lag() {
        let m = ConsumerMetrics {
            last_applied_block: 500,
            last_scanned_block: 600,
            last_known_chain_head: 10_600,
            ..ConsumerMetrics::default()
        };
        assert_eq!(m.indexer_lag_blocks(), 10_000);
    }

    #[test]
    fn record_applied_block_leaves_resume_floor_alone() {
        let mut m = ConsumerMetrics {
            last_applied_leaf_block: 42,
            ..ConsumerMetrics::default()
        };
        m.record_applied_block(777);
        assert_eq!(m.last_applied_block, 777);
        assert_eq!(m.last_scanned_block, 777);
        assert_eq!(m.last_applied_leaf_block, 42);
    }

    // The two recorders differ in exactly one observable, and `/health/ready` gates on it.
    // Held over arbitrary error runs and heights: the defect guarded here is a non-tree
    // event ending an error run that leaf application is still stuck in, so the stall reads
    // as resolved while every later leaf fails the contiguity guard.
    proptest::proptest! {
        #[test]
        fn a_non_tree_event_advances_height_without_clearing_the_error_run(
            errors in 1u64..64,
            start_height in 0u64..30_000_000,
            step in 1u64..1_000_000,
        ) {
            let height = start_height.saturating_add(step);
            let base = ConsumerMetrics {
                last_applied_leaf_block: start_height,
                consecutive_event_errors: errors,
                ..ConsumerMetrics::default()
            };

            let mut non_tree = base;
            non_tree.record_applied_non_tree_event(height);
            proptest::prop_assert_eq!(
                non_tree.last_applied_block, height,
                "a non-tree event still advances the chain cursor"
            );
            proptest::prop_assert_eq!(
                non_tree.events_processed, base.events_processed + 1,
                "and is still counted as an applied event"
            );
            proptest::prop_assert_eq!(
                non_tree.last_applied_leaf_block, start_height,
                "but it must NOT advance the resume floor: no leaves were applied"
            );
            proptest::prop_assert_eq!(
                non_tree.consecutive_event_errors, errors,
                "and it must NOT clear the error run /health/ready gates on"
            );

            // A tree mutation does clear it.
            let mut tree = base;
            tree.record_applied_event(height);
            proptest::prop_assert_eq!(
                tree.consecutive_event_errors, 0,
                "a real tree mutation ends the error run"
            );
            proptest::prop_assert_eq!(
                tree.last_applied_block, height,
                "and advances the chain cursor too"
            );
        }
    }

    /// The routing, not the recorders: which arm calls which.
    ///
    /// The property test above proves the two recorders differ, and it passes even if the
    /// `Nullified` arm is rewired to the wrong one - reverting `:1210` leaves all 318
    /// engine tests green. That is a proxy assertion: it checks the correlate instead of
    /// the observable. This drives a real `Nullified` through `run_consumer_task` and
    /// asserts the error run the health gate reads actually survives it.
    #[tokio::test]
    async fn a_nullified_event_does_not_clear_a_leaf_stall_through_the_consumer() {
        const STALLED_RUN: u64 = 3;
        const NULLIFIED_HEIGHT: u64 = 2_000;

        let dir = tempfile::tempdir().expect("tempdir");
        let state = build_toy_state().expect("toy state");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("nullified-routing"),
            SnapshotPolicy::default(),
            test_encoder(),
        )
        .expect("open");
        let persistence = Arc::new(opened.persistence);

        let instance = Arc::new(PirInstance::<RavenInspireScheme>::new(
            InstanceId::new("nullified-routing"),
            crate::InstanceRole::Live,
            state,
        ));
        let logical_store = Arc::new(parking_lot::Mutex::new(
            super::super::inspire::LogicalLeafStore::new(),
        ));

        // A leaf application is already wedged: the health gate is latched open.
        let metrics = Arc::new(parking_lot::Mutex::new(ConsumerMetrics {
            consecutive_event_errors: STALLED_RUN,
            last_applied_leaf_block: 1_000,
            ..ConsumerMetrics::default()
        }));

        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let task = tokio::spawn(run_consumer_task(
            Arc::clone(&instance),
            Arc::clone(&persistence),
            Arc::clone(&logical_store),
            Arc::clone(&metrics),
            InspireParams::secure_128_d2048(),
            test_encoder(),
            rx,
            None,
        ));

        tx.send(ConsumerEvent::Chain(
            raven_railgun_core::RailgunEvent::Nullified {
                block_number: NULLIFIED_HEIGHT,
                tx_hash: [7u8; 32],
                tree_number: 0,
                nullifiers: vec![[9u8; 32]],
            },
            NULLIFIED_HEIGHT,
        ))
        .await
        .expect("send nullified");
        tx.send(ConsumerEvent::Shutdown)
            .await
            .expect("send shutdown");
        drop(tx);
        task.await.expect("join").expect("consumer task");

        let m = metrics.lock();
        assert_eq!(
            m.last_applied_block, NULLIFIED_HEIGHT,
            "the nullifier still advances the chain cursor"
        );
        assert_eq!(
            m.last_applied_leaf_block, 1_000,
            "but it applied no leaves, so the resume floor must not move"
        );
        assert_eq!(
            m.consecutive_event_errors, STALLED_RUN,
            "and it must NOT clear the stall /health/ready gates on: leaf application is \
             still wedged, and a nullifier says nothing about that"
        );
    }

    /// A committed toy instance and its consumer, stopped with `before_stop` run first.
    async fn stop_committed_consumer(
        label: &str,
        before_stop: impl FnOnce(&InspirePersistence),
    ) -> (Result<()>, SnapshotId, SnapshotId) {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = build_toy_state().expect("toy state");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new(label),
            SnapshotPolicy::default(),
            test_encoder(),
        )
        .expect("open");
        let persistence = Arc::new(opened.persistence);
        let store = super::super::inspire::LogicalLeafStore::new();
        persistence
            .commit_v6(&state, &store, 0)
            .expect("initial commit");
        let committed = persistence.current_snapshot_id();
        let instance = Arc::new(PirInstance::<RavenInspireScheme>::new(
            InstanceId::new(label),
            crate::InstanceRole::Live,
            state,
        ));
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let task = tokio::spawn(run_consumer_task(
            instance,
            Arc::clone(&persistence),
            Arc::new(parking_lot::Mutex::new(store)),
            Arc::new(parking_lot::Mutex::new(ConsumerMetrics::default())),
            InspireParams::secure_128_d2048(),
            test_encoder(),
            rx,
            None,
        ));
        before_stop(&persistence);
        tx.send(ConsumerEvent::Shutdown)
            .await
            .expect("send shutdown");
        let outcome = task.await.expect("join");
        (outcome, committed, persistence.current_snapshot_id())
    }

    /// Nothing was applied since the last commit, so the stop has nothing to publish: a
    /// snapshot here rewrites the whole encoded database, per instance, inside the stop budget.
    #[tokio::test]
    async fn an_idle_stop_writes_no_commit() {
        let (outcome, committed, after) = stop_committed_consumer("idle-stop", |_| {}).await;
        outcome.expect("an idle stop succeeds");
        assert_eq!(after, committed, "an idle stop published a snapshot");
    }

    #[tokio::test]
    async fn a_stop_after_a_wal_append_still_commits() {
        let (outcome, committed, after) = stop_committed_consumer("appended-stop", |persistence| {
            persistence.signal_reorg(0).expect("append a WAL entry");
        })
        .await;
        outcome.expect("the final commit succeeds");
        assert_eq!(
            after,
            committed.next(),
            "the appended entry was not committed"
        );
    }

    /// A final commit that fails is the consumer's error, so the stop can report it rather
    /// than exit as if the state were published.
    #[tokio::test]
    async fn a_failed_final_commit_is_the_consumers_error() {
        let (outcome, committed, after) = stop_committed_consumer("failed-stop", |persistence| {
            persistence.signal_reorg(0).expect("append a WAL entry");
            // A published store longer than the one held: the commit guard refuses it.
            persistence
                .committed_leaf_count
                .store(1, std::sync::atomic::Ordering::Release);
        })
        .await;
        let error = outcome.expect_err("the refused final commit must surface");
        assert!(error.to_string().contains("commit refused"), "{error}");
        assert_eq!(after, committed);
    }

    /// Harness for the routing tests: a live consumer over a toy instance, seeded with a
    /// wedged leaf application so the health signal is observable.
    async fn drive_consumer(
        events: Vec<ConsumerEvent>,
        stalled_run: u64,
        floor: u64,
        label: &str,
    ) -> ConsumerMetrics {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = build_toy_state().expect("toy state");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new(label),
            SnapshotPolicy::default(),
            test_encoder(),
        )
        .expect("open");
        let persistence = Arc::new(opened.persistence);
        let instance = Arc::new(PirInstance::<RavenInspireScheme>::new(
            InstanceId::new(label),
            crate::InstanceRole::Live,
            state,
        ));
        let logical_store = Arc::new(parking_lot::Mutex::new(
            super::super::inspire::LogicalLeafStore::new(),
        ));
        let metrics = Arc::new(parking_lot::Mutex::new(ConsumerMetrics {
            consecutive_event_errors: stalled_run,
            last_applied_leaf_block: floor,
            ..ConsumerMetrics::default()
        }));

        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let task = tokio::spawn(run_consumer_task(
            Arc::clone(&instance),
            Arc::clone(&persistence),
            Arc::clone(&logical_store),
            Arc::clone(&metrics),
            InspireParams::secure_128_d2048(),
            test_encoder(),
            rx,
            None,
        ));
        for e in events {
            tx.send(e).await.expect("send");
        }
        tx.send(ConsumerEvent::Shutdown).await.expect("shutdown");
        drop(tx);
        task.await.expect("join").expect("consumer task");
        let m = *metrics.lock();
        m
    }

    /// `Unshield` moves no leaves, so it must not clear the stall the health gate reads.
    /// Companion to the `Nullified` routing test: the recorder property test passes even when
    /// an arm is rewired, so each arm needs its own route asserted.
    #[tokio::test]
    async fn an_unshield_event_does_not_clear_a_leaf_stall_through_the_consumer() {
        const STALL: u64 = 5;
        const HEIGHT: u64 = 3_000;
        let m = drive_consumer(
            vec![ConsumerEvent::Chain(
                raven_railgun_core::RailgunEvent::Unshield {
                    block_number: HEIGHT,
                    tx_hash: [3u8; 32],
                    to: [4u8; 20],
                    token: [5u8; 32],
                    amount: 1,
                    fee: 0,
                },
                HEIGHT,
            )],
            STALL,
            1_000,
            "unshield-routing",
        )
        .await;

        assert_eq!(
            m.last_applied_block, HEIGHT,
            "the chain cursor still advances"
        );
        assert_eq!(
            m.last_applied_leaf_block, 1_000,
            "an unshield applies no leaves, so the resume floor must not move"
        );
        assert_eq!(
            m.consecutive_event_errors, STALL,
            "and it must NOT clear the stall: leaf application is still wedged"
        );
    }

    /// The opposite direction, and it is what makes the pair meaningful. A PPOI list leaf DOES
    /// grow an IMT, so it MUST clear the error run - a PPOI-only instance, which is the live
    /// deployment shape, has no other route out of 503.
    #[tokio::test]
    async fn a_ppoi_list_leaf_clears_the_error_run_because_it_grows_a_tree() {
        const STALL: u64 = 4;
        const HEIGHT: u64 = 4_000;
        let m = drive_consumer(
            vec![ConsumerEvent::Ppoi(
                raven_railgun_persistence::WalEntryPayload::PpoiListLeafAdded {
                    list_key: [1u8; 32],
                    list_index: 0,
                    blinded_commitment: [2u8; 32],
                    event_type: raven_railgun_persistence::PpoiEventType::Shield,
                    validated_merkleroot: [0; 32],
                },
                HEIGHT,
            )],
            STALL,
            1_000,
            "ppoi-leaf-routing",
        )
        .await;

        assert_eq!(
            m.consecutive_event_errors, 0,
            "a PPOI list leaf grows the PPOI IMT, so it is a tree mutation and must clear the run"
        );
    }

    /// The partition must not drift from the one `validate_apply` screens: every variant that
    /// reaches `checked_imt_append` is exactly a variant that may clear the error run.
    #[test]
    fn the_tree_append_partition_matches_the_screened_variants() {
        use raven_railgun_persistence::WalEntryPayload as P;
        let appends = [
            P::AppendLeaf {
                tree_number: 0,
                leaf_index: 0,
                commitment: [1u8; 32],
            },
            P::PpoiListLeafAdded {
                list_key: [1u8; 32],
                list_index: 0,
                blinded_commitment: [2u8; 32],
                event_type: raven_railgun_persistence::PpoiEventType::Shield,
                validated_merkleroot: [0; 32],
            },
        ];
        let inert = [
            P::Reorg { height: 1 },
            P::Heartbeat {
                wallclock_unix_ms: 0,
            },
        ];
        assert_eq!(
            appends.len() + inert.len(),
            4,
            "every payload variant must be classified; a new one defaults to nothing"
        );
        for p in &appends {
            assert!(
                super::super::inspire::appends_to_a_tree(p),
                "{p:?} reaches checked_imt_append and must be allowed to clear the run"
            );
        }
        for p in &inert {
            assert!(
                !super::super::inspire::appends_to_a_tree(p),
                "{p:?} appends to no tree and must not clear the run"
            );
        }
    }

    fn leaf_at(leaf_index: u32, commitment: u8) -> raven_railgun_core::CommitmentLeaf {
        raven_railgun_core::CommitmentLeaf {
            tree_number: 0,
            leaf_index,
            commitment_hash: [commitment; 32],
            ciphertext: Vec::new(),
        }
    }

    fn shield_at(height: u64, leaves: Vec<raven_railgun_core::CommitmentLeaf>) -> ConsumerEvent {
        let start_position = leaves.first().map_or(0, |l| l.leaf_index);
        ConsumerEvent::Chain(
            raven_railgun_core::RailgunEvent::Shield {
                block_number: height,
                tx_hash: [7u8; 32],
                tree_number: 0,
                start_position,
                leaves,
            },
            height,
        )
    }

    const BREAK_AT: u64 = 5_000;

    /// The apply-stage producer. A gapped leaf fails the contiguity screen inside
    /// `apply_one_leaf`, and the break must record BOTH the abandoned tail and the block it
    /// lives in - the count alone cannot tell a later rewind whether it reaches the gap.
    #[tokio::test]
    async fn a_gapped_leaf_records_the_abandoned_tail_and_the_block_it_broke_on() {
        let m = drive_consumer(
            vec![shield_at(
                BREAK_AT,
                vec![leaf_at(3, 0x11), leaf_at(4, 0x12)],
            )],
            0,
            1_000,
            "abandon-records-block",
        )
        .await;

        assert_eq!(
            m.unapplied_leaves, 2,
            "the failing leaf and every one after it are unapplied"
        );
        assert_eq!(
            m.first_abandoned_block,
            Some(BREAK_AT),
            "the block must survive to the clear site, which is the only thing that can \
             judge whether a rewind reaches the gap"
        );
    }

    /// The replay-screen producer, which is a different break in the same loop: a redelivered
    /// leaf carrying a divergent commitment. Asserted separately so removing either producer
    /// alone reddens something.
    #[tokio::test]
    async fn a_divergent_redelivery_records_the_abandoned_tail_and_its_block() {
        let m = drive_consumer(
            vec![
                shield_at(BREAK_AT - 100, vec![leaf_at(0, 0x21)]),
                shield_at(BREAK_AT, vec![leaf_at(0, 0x22), leaf_at(1, 0x23)]),
            ],
            0,
            1_000,
            "abandon-records-block-replay",
        )
        .await;

        assert_eq!(
            m.unapplied_leaves, 2,
            "a divergent redelivery abandons the whole tail, not just the divergent leaf"
        );
        assert_eq!(m.first_abandoned_block, Some(BREAK_AT));
    }

    /// The fail-open this closes. The indexer rescans from `rewind_height + 1`, so a rewind AT
    /// the abandoned block redelivers nothing that is missing. Clearing on it is irreversible:
    /// a zeroed gap can never be re-derived, and `/health/ready` then returns 200 over a tree
    /// that fails the contiguity screen for every later leaf.
    #[tokio::test]
    async fn a_rewind_at_the_abandoned_block_must_not_clear_the_gap() {
        let m = drive_consumer(
            vec![
                shield_at(BREAK_AT, vec![leaf_at(3, 0x31), leaf_at(4, 0x32)]),
                ConsumerEvent::Reorg(BREAK_AT),
            ],
            0,
            1_000,
            "rewind-at-gap",
        )
        .await;

        assert_eq!(
            m.unapplied_leaves, 2,
            "a rewind that does not reach below the gap must leave the signal standing"
        );
        assert_eq!(m.first_abandoned_block, Some(BREAK_AT));
    }

    /// A rewind ABOVE it is the same case and is the likelier one in production: a tip reorg
    /// lands far above a gap opened earlier.
    #[tokio::test]
    async fn a_rewind_above_the_abandoned_block_must_not_clear_the_gap() {
        let m = drive_consumer(
            vec![
                shield_at(BREAK_AT, vec![leaf_at(3, 0x41), leaf_at(4, 0x42)]),
                ConsumerEvent::Reorg(BREAK_AT + 250),
            ],
            0,
            1_000,
            "rewind-above-gap",
        )
        .await;

        assert_eq!(
            m.unapplied_leaves, 2,
            "a tip reorg above the gap redelivers none of it"
        );
        assert_eq!(m.first_abandoned_block, Some(BREAK_AT));
    }

    /// The inverse, so the guard cannot be a permanent wedge dressed up as a fix: a rewind
    /// BELOW the abandoned block does redeliver those leaves, and must clear.
    ///
    /// A second break AFTER the rewind is what makes this discriminating. Asserting only
    /// `0`/`None` cannot tell "cleared" from "never recorded", so it passes vacuously when a
    /// producer is deleted; the follow-on break gives a value only a recorded-then-cleared
    /// history can produce - 2 leaves at the LATER block, never 4 at the earlier one.
    #[tokio::test]
    async fn a_rewind_below_the_abandoned_block_clears_the_gap() {
        const LATER_BREAK: u64 = BREAK_AT + 500;
        let m = drive_consumer(
            vec![
                shield_at(BREAK_AT, vec![leaf_at(3, 0x51), leaf_at(4, 0x52)]),
                ConsumerEvent::Reorg(BREAK_AT - 1),
                shield_at(LATER_BREAK, vec![leaf_at(6, 0x53), leaf_at(7, 0x54)]),
            ],
            0,
            1_000,
            "rewind-below-gap",
        )
        .await;

        assert_eq!(
            m.unapplied_leaves, 2,
            "the rewind redelivers the first gap, so only the SECOND break is outstanding; \
             4 here means the clear never fired"
        );
        assert_eq!(
            m.first_abandoned_block,
            Some(LATER_BREAK),
            "the cleared block must not survive as the minimum"
        );
    }

    #[test]
    fn ppoi_height_zero_cannot_regress_the_applied_pointer() {
        let mut m = ConsumerMetrics {
            last_applied_leaf_block: 22_950_000,
            ..ConsumerMetrics::default()
        };
        m.record_applied_block(23_000_000);
        m.last_known_chain_head = 23_000_005;

        for _ in 0..4 {
            m.record_applied_block(0);
        }

        assert_eq!(
            m.last_applied_block, 23_000_000,
            "a PPOI row at height 0 sharing the chain bridge's metrics must not \
             reset the applied pointer"
        );
        assert_eq!(m.last_scanned_block, 23_000_000);
        assert_eq!(
            m.blocks_since_last_applied_event(),
            5,
            "the derived gauge must stay bounded, not read the whole chain height"
        );
        assert_eq!(
            m.last_applied_leaf_block, 22_950_000,
            "resume floor is written only by the leaf paths"
        );
    }

    #[test]
    fn record_consumer_error_bumps_metric_under_each_op_label() {
        let metrics = std::sync::Arc::new(parking_lot::Mutex::new(ConsumerMetrics::default()));

        let cases = [
            ("AppendLeaf apply", 100u64),
            ("Reorg apply", 99u64),
            ("Ppoi apply", 200u64),
        ];

        let err = AdapterError::Internal("synthetic apply_event failure".to_owned());
        let mut expected = 0u64;
        for (op, height) in cases {
            record_consumer_error(&metrics, &err, op, height);
            expected += 1;
            let snap = *metrics.lock();
            assert_eq!(
                snap.consumer_errors, expected,
                "consumer_errors after op={op} should be {expected}"
            );
        }
    }

    #[test]
    fn record_consumer_error_saturates_at_u64_max() {
        let metrics = std::sync::Arc::new(parking_lot::Mutex::new(ConsumerMetrics {
            consumer_errors: u64::MAX,
            ..ConsumerMetrics::default()
        }));
        let err = AdapterError::Internal("post-saturation".to_owned());
        record_consumer_error(&metrics, &err, "test", 0);
        let snap = *metrics.lock();
        assert_eq!(
            snap.consumer_errors,
            u64::MAX,
            "saturating_add must not wrap"
        );
    }

    /// Same shape, distinguishable session store, carrying the donor's database by Arc -
    /// exactly what `heartbeat_session_eviction` publishes.
    fn evicted_from(donor: &InspireServerState) -> InspireServerState {
        InspireServerState {
            crs: Arc::clone(&donor.crs),
            encoded_db: Arc::clone(&donor.encoded_db),
            cache: Arc::clone(&donor.cache),
            session_store: Arc::new(crate::session_pool::BoundedSessionStore::new()),
            variant: donor.variant,
            entry_size: donor.entry_size,
        }
    }

    /// A commit that loses the swap to a session eviction must republish, not fail.
    ///
    /// The re-encode spans the whole per-shard loop while the eviction ticker derives in
    /// nanoseconds, so the eviction essentially always wins. Surfacing that as an error
    /// abandons the block's remaining leaves and the contiguity guard then refuses every
    /// later leaf permanently.
    #[test]
    fn a_commit_that_loses_the_swap_to_a_session_eviction_republishes() {
        let state = build_toy_state().expect("toy state");
        let inst = Arc::new(PirInstance::<RavenInspireScheme>::new(
            InstanceId::new("swap-retry"),
            crate::InstanceRole::Live,
            state,
        ));

        // The commit captures its derivation.
        let derived_from = inst.current_snapshot();
        let current = Arc::clone(&derived_from.state);
        let new_db = Arc::clone(&current.encoded_db);

        // The eviction ticker wins the race while the re-encode is still running.
        inst.swap_state(evicted_from(&current), derived_from.epoch.next())
            .expect("the eviction publishes first");
        let after_eviction = inst.current_epoch();

        publish_recommitted_state(&inst, &derived_from, &current, &new_db, 4_242)
            .expect("a commit that lost only to a session swap must republish");

        assert!(
            inst.current_epoch() > after_eviction,
            "the republished commit must advance past the eviction that beat it"
        );
    }

    /// But it must NOT republish over another COMMIT. Those rows were re-encoded from a
    /// database that is no longer published, so republishing them drops that update.
    #[test]
    fn a_commit_that_loses_to_another_commit_is_refused_without_retrying() {
        let state = build_toy_state().expect("toy state");
        let inst = Arc::new(PirInstance::<RavenInspireScheme>::new(
            InstanceId::new("swap-refuse"),
            crate::InstanceRole::Live,
            state,
        ));

        let derived_from = inst.current_snapshot();
        let current = Arc::clone(&derived_from.state);
        let new_db = Arc::clone(&current.encoded_db);

        // A second commit publishes a DIFFERENT database, not just a new session store.
        let rival_db = Arc::new((*current.encoded_db).clone());
        let rival = InspireServerState {
            crs: Arc::clone(&current.crs),
            encoded_db: rival_db,
            cache: Arc::clone(&current.cache),
            session_store: Arc::clone(&current.session_store),
            variant: current.variant,
            entry_size: current.entry_size,
        };
        inst.swap_state(rival, derived_from.epoch.next())
            .expect("the rival commit publishes first");

        let err = publish_recommitted_state(&inst, &derived_from, &current, &new_db, 4_243)
            .expect_err("republishing over another commit would drop its update");
        assert!(
            format!("{err}").contains("stale state swap"),
            "the refusal must be the staleness one, not the retry-exhausted one; got: {err}"
        );
    }

    /// A geometry refusal must reach the operator as itself.
    ///
    /// `swap_state` refuses a shape mismatch BEFORE its compare-and-swap, so nothing
    /// swapped and `encoded_db` stays pointer-equal. Classifying by pointer identity
    /// therefore read a geometry refusal as contention, retried it four times, and told
    /// the operator to raise `session_eviction_interval_secs` - a ticker that was never
    /// involved. The safety gate fired correctly and was announced as its opposite.
    #[test]
    fn a_shape_mismatch_surfaces_as_itself_and_never_as_internal() {
        let state = build_toy_state().expect("toy state");
        let inst = Arc::new(PirInstance::<RavenInspireScheme>::new(
            InstanceId::new("swap-shape"),
            crate::InstanceRole::Live,
            state,
        ));

        let derived_from = inst.current_snapshot();
        let current = Arc::clone(&derived_from.state);

        // A database encoded at a different record width: legal bytes, illegal geometry
        // to publish under live clients whose queries decompose against the old one.
        let other_width = build_toy_state_with_entry_size(TOY_ENTRY_SIZE / 2)
            .expect("second toy state at half the record width");
        let new_db = Arc::clone(&other_width.encoded_db);
        assert_ne!(
            new_db.config.entry_size_bytes, current.encoded_db.config.entry_size_bytes,
            "the fixture must actually differ in shape, or this test proves nothing"
        );

        let err = publish_recommitted_state(&inst, &derived_from, &current, &new_db, 4_244)
            .expect_err("publishing a different geometry must be refused");

        assert!(
            matches!(err, AdapterError::StateShapeMismatch { .. }),
            "a geometry refusal must keep its type; got: {err:?}"
        );
        let text = format!("{err}");
        assert!(
            text.contains("state shape mismatch"),
            "the operator must be told the geometry moved; got: {text}"
        );
        assert!(
            !text.contains("session_eviction_interval_secs"),
            "and must NOT be sent to tune a ticker that was never involved; got: {text}"
        );
    }

    // These cannot call `raven_railgun_testkit::try_toy_state`, though the integration tests in
    // engine/tests/ can. The testkit dev-dependency links its OWN build of this crate, so its
    // `InspireServerState` is a distinct type from the one these unit tests compile against:
    // `expected inspire::InspireServerState, found InspireServerState`. Promoting the testkit to a
    // normal dependency would fix the types and put fixture code in the shipped binary, which is
    // the worse trade. The DB formula is shared - that is the part that was actually duplicated -
    // and the four-line wrapper stays local.
    fn build_toy_state_with_entry_size(entry_size: usize) -> Result<InspireServerState> {
        let params = InspireParams::secure_128_d2048();
        let db = raven_railgun_testkit::toy_db(raven_railgun_testkit::TOY_ENTRIES, entry_size);
        let (state, _sk) = super::super::inspire::setup_state(
            &params,
            &db,
            entry_size,
            InspireVariant::TwoPacking,
        )?;
        Ok(state)
    }

    fn build_toy_state() -> Result<InspireServerState> {
        build_toy_state_with_entry_size(TOY_ENTRY_SIZE)
    }

    fn small_params() -> InspireParams {
        InspireParams {
            ring_dim: 256,
            q: 1_152_921_504_606_830_593,
            crt_moduli: vec![1_152_921_504_606_830_593],
            p: 65_537,
            sigma: 6.4,
            gadget_base: 1 << 20,
            query_gadget_len: 3,
            packing_gadget_len: 3,
            security_level: raven_inspire::params::SecurityLevel::Bits128,
        }
    }

    fn build_small_cache_state_with_key(
    ) -> Result<(InspireServerState, raven_inspire::rlwe::RlweSecretKey)> {
        let params = small_params();
        let db = raven_railgun_testkit::toy_db(256, 32);
        super::super::inspire::setup_state(&params, &db, 32, InspireVariant::TwoPacking)
    }

    fn build_small_cache_state() -> Result<InspireServerState> {
        build_small_cache_state_with_key().map(|(state, _)| state)
    }

    fn small_cache_encoder() -> Arc<dyn PirTableEncoder> {
        Arc::new(PerLeafCommitmentEncoder::new(32, 256, 0).expect("small encoder"))
    }

    #[test]
    fn fresh_open_returns_no_recovered_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("toy"),
            SnapshotPolicy::default(),
            test_encoder(),
        )
        .expect("open");
        assert!(opened.recovered_state.is_none());
        assert_eq!(opened.persistence.wal_next_seq(), 0);
        assert_eq!(opened.persistence.current_snapshot_id(), SnapshotId(0));
    }

    #[test]
    fn commit_then_reopen_recovers_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = build_toy_state().expect("state");

        {
            let layout = StoreLayout::open(dir.path()).expect("layout");
            let opened = InspirePersistence::open(
                layout,
                SCHEME_TAG,
                InstanceId::new("toy"),
                SnapshotPolicy::default(),
                test_encoder(),
            )
            .expect("open");
            assert!(opened.recovered_state.is_none());
            opened.persistence.commit(&state, 100).expect("commit");
            assert_eq!(opened.persistence.current_snapshot_id(), SnapshotId(1));
        }

        let layout2 = StoreLayout::open(dir.path()).expect("layout 2");
        let opened2 = InspirePersistence::open(
            layout2,
            SCHEME_TAG,
            InstanceId::new("toy"),
            SnapshotPolicy::default(),
            test_encoder(),
        )
        .expect("open 2");
        let recovered = opened2.recovered_state.expect("recovered some");
        assert_eq!(recovered.entry_size, state.entry_size);
        assert_eq!(recovered.variant, state.variant);
    }

    #[test]
    fn unchanged_commit_skips_cache_rewrite_and_recovery_repairs_corruption() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = build_small_cache_state().expect("state");
        let encoded_before = bincode::serialize(&*state.encoded_db).expect("encoded db");
        let cache_path = dir
            .path()
            .join(crate::offline_packing_keys_cache::CACHE_RELATIVE_PATH);

        {
            let opened = InspirePersistence::open(
                StoreLayout::open(dir.path()).expect("layout"),
                SCHEME_TAG,
                InstanceId::new("cache-skip"),
                SnapshotPolicy::default(),
                small_cache_encoder(),
            )
            .expect("open");
            opened
                .persistence
                .commit(&state, 100)
                .expect("first commit");
            let mut corrupted = std::fs::read(&cache_path).expect("cache bytes");
            *corrupted.last_mut().expect("nonempty cache") ^= 1;
            std::fs::write(&cache_path, &corrupted).expect("corrupt cache body");

            opened
                .persistence
                .commit(&state, 101)
                .expect("second commit");
            assert!(
                std::fs::read(&cache_path).expect("cache after second commit") == corrupted,
                "same-identity commit rewrote the cache"
            );
        }

        let reopened = InspirePersistence::open(
            StoreLayout::open(dir.path()).expect("reopen layout"),
            SCHEME_TAG,
            InstanceId::new("cache-skip"),
            SnapshotPolicy::default(),
            small_cache_encoder(),
        )
        .expect("reopen");
        assert!(!reopened.recovered_cache_hit);
        let recovered = reopened.recovered_state.expect("recovered state");
        assert_eq!(
            bincode::serialize(&*recovered.encoded_db).expect("recovered encoded db"),
            encoded_before
        );
        let columns = recovered
            .encoded_db
            .shards
            .first()
            .expect("recovered shard")
            .polynomials
            .len();
        let identity = crate::offline_packing_keys_cache::CellShape::for_inspiring(
            &recovered.crs.params,
            columns,
            recovered.crs.inspiring_w_seed,
        );
        assert!(matches!(
            crate::offline_packing_keys_cache::OfflinePackingKeysCache::new(dir.path())
                .load(&identity),
            crate::offline_packing_keys_cache::CacheLoad::Hit(_)
        ));
        let mut corrupted_again = std::fs::read(&cache_path).expect("repaired cache bytes");
        *corrupted_again.last_mut().expect("nonempty repaired cache") ^= 1;
        std::fs::write(&cache_path, &corrupted_again).expect("corrupt repaired cache");
        reopened
            .persistence
            .commit(&recovered, 102)
            .expect("post-recovery commit");
        assert!(
            std::fs::read(&cache_path).expect("cache after post-recovery commit")
                == corrupted_again,
            "first post-recovery commit rewrote a successfully repaired cache"
        );
    }

    #[test]
    fn failed_cache_store_is_retried_by_the_next_commit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = build_small_cache_state().expect("state");
        let cache_dir = dir.path().join("cache");
        std::fs::write(&cache_dir, b"blocks directory creation").expect("cache blocker");
        let opened = InspirePersistence::open(
            StoreLayout::open(dir.path()).expect("layout"),
            SCHEME_TAG,
            InstanceId::new("cache-retry"),
            SnapshotPolicy::default(),
            small_cache_encoder(),
        )
        .expect("open");

        opened
            .persistence
            .commit(&state, 100)
            .expect("first commit");
        std::fs::remove_file(&cache_dir).expect("remove cache blocker");
        opened
            .persistence
            .commit(&state, 101)
            .expect("retry commit");

        let columns = state
            .encoded_db
            .shards
            .first()
            .expect("setup shard")
            .polynomials
            .len();
        let identity = crate::offline_packing_keys_cache::CellShape::for_inspiring(
            &state.crs.params,
            columns,
            state.crs.inspiring_w_seed,
        );
        assert!(matches!(
            crate::offline_packing_keys_cache::OfflinePackingKeysCache::new(dir.path())
                .load(&identity),
            crate::offline_packing_keys_cache::CacheLoad::Hit(_)
        ));
    }

    /// Fresh-bootstrap replay must include seq 0 inclusive.
    #[test]
    fn fresh_bootstrap_seq0_event_survives_drop_and_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");

        {
            let layout = StoreLayout::open(dir.path()).expect("layout 1");
            let opened = InspirePersistence::open(
                layout,
                SCHEME_TAG,
                InstanceId::new("h1-regression"),
                SnapshotPolicy::default(),
                test_encoder(),
            )
            .expect("open 1");
            // Commitment must be a valid BN254 Fr element.
            let commitment = {
                let mut b = [0u8; 32];
                b[31] = 0x07;
                b
            };
            let payload = WalEntryPayload::AppendLeaf {
                tree_number: 0,
                leaf_index: 0,
                commitment,
            };
            let (seq, _trig) = opened
                .persistence
                .apply_event(&payload, 100)
                .expect("apply");
            assert_eq!(seq, 0, "first event must be at WAL seq 0");
        }

        let layout2 = StoreLayout::open(dir.path()).expect("layout 2");
        let opened2 = InspirePersistence::open(
            layout2,
            SCHEME_TAG,
            InstanceId::new("h1-regression"),
            SnapshotPolicy::default(),
            test_encoder(),
        )
        .expect("open 2");
        let recovered_leaf = opened2.recovered_logical_store.leaf(0, 0).copied();
        let expected = {
            let mut b = [0u8; 32];
            b[31] = 0x07;
            b
        };
        assert_eq!(
            recovered_leaf,
            Some(expected),
            "WAL replay floor V2: fresh-bootstrap seq 0 event must survive drop+reopen \
             (pre-fix V1 silently dropped it)"
        );
    }

    /// Invalid WAL entries soft-skip on replay; valid ones land.
    #[test]
    fn poisoned_wal_is_tolerantly_replayed_with_soft_skip() {
        let dir = tempfile::tempdir().expect("tempdir");

        let valid_b07 = {
            let mut b = [0u8; 32];
            b[31] = 0x07;
            b
        };
        let valid_b09 = {
            let mut b = [0u8; 32];
            b[31] = 0x09;
            b
        };
        let valid_b0b = {
            let mut b = [0u8; 32];
            b[31] = 0x0b;
            b
        };
        {
            let layout = StoreLayout::open(dir.path()).expect("layout 1");
            let opened = InspirePersistence::open(
                layout,
                SCHEME_TAG,
                InstanceId::new("tolerant-replay-test"),
                SnapshotPolicy::default(),
                test_encoder(),
            )
            .expect("open 1");

            opened
                .persistence
                .apply_event(
                    &WalEntryPayload::AppendLeaf {
                        tree_number: 0,
                        leaf_index: 0,
                        commitment: valid_b07,
                    },
                    100,
                )
                .expect("apply seq 0");
            opened
                .persistence
                .apply_event(
                    &WalEntryPayload::AppendLeaf {
                        tree_number: 0,
                        leaf_index: 5, // SPARSE - replay will reject this
                        commitment: valid_b09,
                    },
                    101,
                )
                .expect("apply seq 1 (poisoned)");
            opened
                .persistence
                .apply_event(
                    &WalEntryPayload::AppendLeaf {
                        tree_number: 0,
                        leaf_index: 1,
                        commitment: valid_b0b,
                    },
                    102,
                )
                .expect("apply seq 2");
        }

        let layout2 = StoreLayout::open(dir.path()).expect("layout 2");
        let opened2 = InspirePersistence::open(
            layout2,
            SCHEME_TAG,
            InstanceId::new("tolerant-replay-test"),
            SnapshotPolicy::default(),
            test_encoder(),
        )
        .expect("open 2 must succeed despite invalid entry");

        assert_eq!(
            opened2.recovered_logical_store.leaf_count(),
            2,
            "tolerant-replay must drop 1 invalid entry; 2 valid entries land"
        );
        assert_eq!(
            opened2.recovered_logical_store.leaf(0, 0).copied(),
            Some(valid_b07),
            "leaf 0 (seq 0 valid) must replay"
        );
        assert_eq!(
            opened2.recovered_logical_store.leaf(0, 1).copied(),
            Some(valid_b0b),
            "leaf 1 (seq 2, post-skip) must replay"
        );
        assert!(
            opened2.recovered_logical_store.leaf(0, 5).is_none(),
            "the rejected sparse leaf must NOT survive replay"
        );
    }

    fn shared_prometheus_handle() -> &'static metrics_exporter_prometheus::PrometheusHandle {
        use std::sync::OnceLock;
        static HANDLE: OnceLock<metrics_exporter_prometheus::PrometheusHandle> = OnceLock::new();
        HANDLE.get_or_init(|| {
            let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
            builder
                .install_recorder()
                .expect("first-time PrometheusBuilder install in this test must succeed")
        })
    }

    #[test]
    fn fresh_open_describes_wal_replay_skipped_at_module_init() {
        let handle = shared_prometheus_handle();
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let _opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("describe-init-test"),
            SnapshotPolicy::default(),
            test_encoder(),
        )
        .expect("fresh open");
        let rendered = handle.render();
        assert!(
            rendered.contains("# HELP raven_railgun_wal_replay_skipped_total"),
            "fresh open() must register HELP metadata at module init; got render:\n{rendered}"
        );
        assert!(
            rendered.contains("# TYPE raven_railgun_wal_replay_skipped_total counter"),
            "fresh open() must register TYPE metadata at module init; got render:\n{rendered}"
        );
    }
    // The counter-increment assertion lives in its own test binary: the Prometheus
    // recorder installs once per process and cross-test rendering races otherwise.

    #[test]
    fn apply_event_increments_seq_and_triggers_when_cap_reached() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let policy = SnapshotPolicy {
            max_appends_per_snapshot: 3,
            max_seconds_between_snapshots: u64::MAX,
            retention: RetentionPolicy {
                archived_wals_retain: 4,
                snapshots_retain: 4,
            },
        };
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("toy"),
            policy,
            test_encoder(),
        )
        .expect("open");
        let payload = WalEntryPayload::AppendLeaf {
            tree_number: 0,
            leaf_index: 0,
            commitment: [0u8; 32],
        };

        let (seq0, trig0) = opened.persistence.apply_event(&payload, 100).expect("a0");
        assert_eq!(seq0, 0);
        assert!(!trig0);
        let (seq1, trig1) = opened.persistence.apply_event(&payload, 101).expect("a1");
        assert_eq!(seq1, 1);
        assert!(!trig1);
        let (seq2, trig2) = opened.persistence.apply_event(&payload, 102).expect("a2");
        assert_eq!(seq2, 2);
        assert!(trig2);
    }

    #[test]
    fn end_to_end_kill_restart_recovers_byte_identical() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = build_toy_state().expect("state");

        {
            let layout = StoreLayout::open(dir.path()).expect("layout");
            let opened = InspirePersistence::open(
                layout,
                SCHEME_TAG,
                InstanceId::new("e2e"),
                SnapshotPolicy::default(),
                test_encoder(),
            )
            .expect("open 1");
            opened.persistence.commit(&state, 100).expect("commit 1");
            // Big-endian u32 zero-padded to 32 bytes, so below the BN254 Fr prime.
            for i in 0..1000u32 {
                let mut commitment = [0u8; 32];
                if let Some(dst) = commitment.get_mut(28..) {
                    dst.copy_from_slice(&i.to_be_bytes());
                }
                let p = WalEntryPayload::AppendLeaf {
                    tree_number: 3,
                    leaf_index: i,
                    commitment,
                };
                opened
                    .persistence
                    .apply_event(&p, 100 + u64::from(i))
                    .expect("apply");
            }
        }

        let layout2 = StoreLayout::open(dir.path()).expect("layout 2");
        let opened2 = InspirePersistence::open(
            layout2,
            SCHEME_TAG,
            InstanceId::new("e2e"),
            SnapshotPolicy::default(),
            test_encoder(),
        )
        .expect("open 2");
        let recovered = opened2.recovered_state.expect("recovered");
        assert_eq!(recovered.entry_size, state.entry_size);
        assert_eq!(recovered.variant, state.variant);
        assert_eq!(opened2.persistence.wal_next_seq(), 1000);
    }

    #[test]
    fn archive_cleanup_retains_only_recent_n() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = build_toy_state().expect("state");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let policy = SnapshotPolicy {
            max_appends_per_snapshot: usize::MAX,
            max_seconds_between_snapshots: u64::MAX,
            retention: RetentionPolicy {
                archived_wals_retain: 2,
                snapshots_retain: usize::MAX,
            },
        };
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("retain"),
            policy,
            test_encoder(),
        )
        .expect("open");
        for h in 0..5u64 {
            opened.persistence.commit(&state, 100 + h).expect("commit");
        }
        let archive_dir = opened
            .persistence
            .layout()
            .root()
            .join("wal")
            .join("archived");
        let count = std::fs::read_dir(&archive_dir).expect("read").count();
        assert!(count <= 2, "archive_dir count {count} > retention 2");
    }

    #[test]
    fn snapshot_cleanup_retains_only_recent_n() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = build_toy_state().expect("state");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let policy = SnapshotPolicy {
            max_appends_per_snapshot: usize::MAX,
            max_seconds_between_snapshots: u64::MAX,
            retention: RetentionPolicy {
                archived_wals_retain: usize::MAX,
                snapshots_retain: 2,
            },
        };
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("snap-retain"),
            policy,
            test_encoder(),
        )
        .expect("open");
        for h in 0..5u64 {
            opened.persistence.commit(&state, 100 + h).expect("commit");
        }
        let snap_dir = opened.persistence.layout().root().join("snapshots");
        let mut surviving: Vec<u64> = std::fs::read_dir(&snap_dir)
            .expect("read")
            .filter_map(std::result::Result::ok)
            .filter_map(|de| {
                de.file_name()
                    .to_string_lossy()
                    .strip_prefix("snap-")
                    .and_then(|s| s.parse::<u64>().ok())
            })
            .collect();
        surviving.sort_unstable();
        assert!(
            surviving.len() <= 2,
            "surviving snap count {} > retention 2 ({surviving:?})",
            surviving.len()
        );
        let live_id = opened.persistence.current_snapshot_id().0;
        assert!(
            surviving.contains(&live_id),
            "live snapshot id {live_id} missing from survivors {surviving:?}"
        );
    }

    #[test]
    fn retention_failure_after_publish_does_not_report_commit_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = build_toy_state().expect("state");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let policy = SnapshotPolicy {
            max_appends_per_snapshot: usize::MAX,
            max_seconds_between_snapshots: u64::MAX,
            retention: RetentionPolicy {
                archived_wals_retain: usize::MAX,
                snapshots_retain: 0,
            },
        };
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("retention-failure-after-publish"),
            policy,
            test_encoder(),
        )
        .expect("open");
        let wrong_type = opened
            .persistence
            .layout()
            .root()
            .join("snapshots")
            .join("snap-999999");
        std::fs::write(&wrong_type, b"not a snapshot directory").expect("plant wrong type");

        let id = opened
            .persistence
            .commit_v6(&state, &crate::inspire::LogicalLeafStore::new(), 100)
            .expect("retention housekeeping must not turn a durable commit into failure");
        assert_eq!(opened.persistence.current_snapshot_id(), id);
        assert!(
            opened
                .persistence
                .layout()
                .root()
                .join("snapshots")
                .join(format!("snap-{:06}", id.0))
                .is_dir(),
            "published snapshot must remain durable after retention refusal"
        );
        assert!(
            wrong_type.is_file(),
            "failed retention must leave the obstacle intact"
        );
        assert_eq!(
            super::retention_failures().get("retention-failure-after-publish"),
            Some(&1),
            "a failed retention pass must be counted where readiness can report it"
        );
        drop(opened);

        let reopened = InspirePersistence::open(
            StoreLayout::open(dir.path()).expect("reopen layout"),
            SCHEME_TAG,
            InstanceId::new("retention-failure-after-publish"),
            policy,
            test_encoder(),
        )
        .expect("reopen committed snapshot");
        assert_eq!(reopened.persistence.current_snapshot_id(), id);
        assert!(reopened.recovered_state.is_some());
    }

    #[test]
    fn snapshot_cleanup_skipped_in_forensic_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = build_toy_state().expect("state");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let policy = SnapshotPolicy {
            max_appends_per_snapshot: usize::MAX,
            max_seconds_between_snapshots: u64::MAX,
            retention: RetentionPolicy {
                archived_wals_retain: usize::MAX,
                snapshots_retain: usize::MAX,
            },
        };
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("forensic"),
            policy,
            test_encoder(),
        )
        .expect("open");
        for h in 0..5u64 {
            opened.persistence.commit(&state, 100 + h).expect("commit");
        }
        let snap_dir = opened.persistence.layout().root().join("snapshots");
        let count = std::fs::read_dir(&snap_dir).expect("read").count();
        assert_eq!(count, 5, "forensic mode should retain all snapshots");
    }

    #[test]
    fn snapshot_cleanup_never_deletes_live_snapshot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = build_toy_state().expect("state");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let policy = SnapshotPolicy {
            max_appends_per_snapshot: usize::MAX,
            max_seconds_between_snapshots: u64::MAX,
            retention: RetentionPolicy {
                archived_wals_retain: usize::MAX,
                snapshots_retain: 1,
            },
        };
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("live"),
            policy,
            test_encoder(),
        )
        .expect("open");
        for h in 0..3u64 {
            opened.persistence.commit(&state, 100 + h).expect("commit");
            let live_id = opened.persistence.current_snapshot_id();
            let live_dir = opened
                .persistence
                .layout()
                .root()
                .join("snapshots")
                .join(format!("snap-{:06}", live_id.0));
            assert!(
                live_dir.is_dir(),
                "live snapshot dir {} missing after commit {h}",
                live_dir.display()
            );
        }
    }

    #[test]
    fn signal_reorg_appends_marker() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("reorg"),
            SnapshotPolicy::default(),
            test_encoder(),
        )
        .expect("open");
        let seq = opened.persistence.signal_reorg(24_978_034).expect("reorg");
        assert_eq!(seq, 0);
        assert_eq!(opened.persistence.wal_next_seq(), 1);
    }

    /// Non-empty WAL with no manifest must be refused.
    #[test]
    fn fresh_bootstrap_refuses_wal_ghost() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("wal").join("archived")).expect("mkdir");
        std::fs::create_dir_all(dir.path().join("snapshots")).expect("mkdir");
        std::fs::write(
            dir.path().join("wal").join("current.log"),
            b"\xde\xad\xbe\xef\xde\xad\xbe\xef",
        )
        .expect("plant ghost wal");

        let layout = StoreLayout::open(dir.path()).expect("layout");
        let err = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("ghost"),
            SnapshotPolicy::default(),
            test_encoder(),
        )
        .expect_err("ghost WAL must refuse");
        assert!(matches!(err, AdapterError::Internal(_)));
        let msg = format!("{err}");
        assert!(
            msg.contains("fresh-bootstrap refused"),
            "error message must surface the ghost-WAL refusal: {msg}"
        );
    }

    #[test]
    fn fresh_bootstrap_accepts_empty_wal() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("wal").join("archived")).expect("mkdir");
        std::fs::create_dir_all(dir.path().join("snapshots")).expect("mkdir");
        std::fs::write(dir.path().join("wal").join("current.log"), b"").expect("plant empty wal");

        let layout = StoreLayout::open(dir.path()).expect("layout");
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("clean"),
            SnapshotPolicy::default(),
            test_encoder(),
        )
        .expect("empty WAL + no manifest must succeed");
        assert!(opened.recovered_state.is_none());
    }

    #[test]
    fn scheme_tag_mismatch_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = build_toy_state().expect("state");
        {
            let layout = StoreLayout::open(dir.path()).expect("layout");
            let opened = InspirePersistence::open(
                layout,
                "scheme-A",
                InstanceId::new("toy"),
                SnapshotPolicy::default(),
                test_encoder(),
            )
            .expect("open");
            opened.persistence.commit(&state, 0).expect("commit");
        }
        let layout2 = StoreLayout::open(dir.path()).expect("layout 2");
        let err = InspirePersistence::open(
            layout2,
            "scheme-B",
            InstanceId::new("toy"),
            SnapshotPolicy::default(),
            test_encoder(),
        )
        .expect_err("mismatch should reject");
        assert!(matches!(err, AdapterError::Internal(_)));
        let message = err.to_string();
        for needle in [
            "\"scheme-A\"",
            "\"scheme-B\"",
            &dir.path().display().to_string(),
            "set this instance's scheme_tag to \"scheme-A\"",
            "start on an empty one",
        ] {
            assert!(message.contains(needle), "{needle}: {message}");
        }
    }

    /// The tag outlives every data_dir written under it, so it names the scheme and a layout
    /// version, and nothing about how the work was organised.
    #[test]
    fn the_persisted_scheme_tag_names_the_scheme_and_a_version() {
        let tag = super::SCHEME_TAG;
        let (scheme, version) = tag.rsplit_once("-v").expect("a -v<N> suffix");
        assert!(
            !version.is_empty() && version.bytes().all(|b| b.is_ascii_digit()),
            "{tag}"
        );
        assert_eq!(scheme, "raven-inspire-twopacking-inspiring", "{tag}");
    }

    #[test]
    fn instance_id_mismatch_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = build_toy_state().expect("state");
        {
            let layout = StoreLayout::open(dir.path()).expect("layout");
            let opened = InspirePersistence::open(
                layout,
                SCHEME_TAG,
                InstanceId::new("toy-a"),
                SnapshotPolicy::default(),
                test_encoder(),
            )
            .expect("open");
            opened.persistence.commit(&state, 0).expect("commit");
        }
        let layout = StoreLayout::open(dir.path()).expect("layout 2");
        let err = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("toy-b"),
            SnapshotPolicy::default(),
            test_encoder(),
        )
        .expect_err("mismatch should reject");
        let message = err.to_string();
        assert!(matches!(err, AdapterError::Internal(_)));
        assert!(message.contains("instance_id mismatch"), "{message}");
    }

    type UnsatShardFixtures = (
        Arc<crate::PirInstance<crate::inspire::RavenInspireScheme>>,
        Arc<InspirePersistence>,
        Arc<parking_lot::Mutex<crate::inspire::LogicalLeafStore>>,
        raven_inspire::params::InspireParams,
        Arc<dyn PirTableEncoder>,
        Arc<parking_lot::Mutex<ConsumerMetrics>>,
        tempfile::TempDir,
    );

    fn build_unsat_shard_fixtures() -> UnsatShardFixtures {
        use crate::inspire::LogicalLeafStore;
        use crate::{InstanceRole, PirInstance};
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let state = build_toy_state().expect("state");
        let params = InspireParams::secure_128_d2048();
        let encoder = test_encoder();
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("unsat-shard-fixtures"),
            SnapshotPolicy::default(),
            Arc::clone(&encoder),
        )
        .expect("open");
        let persistence = Arc::new(opened.persistence);
        let empty_store = LogicalLeafStore::default();
        persistence
            .commit_v6(&state, &empty_store, 0)
            .expect("initial commit");
        let instance: Arc<PirInstance<RavenInspireScheme>> = Arc::new(PirInstance::new(
            InstanceId::new("unsat-shard-fixtures"),
            InstanceRole::Live,
            state,
        ));
        let logical_store = Arc::new(parking_lot::Mutex::new(LogicalLeafStore::new()));
        let metrics = Arc::new(parking_lot::Mutex::new(ConsumerMetrics::default()));
        (
            instance,
            persistence,
            logical_store,
            params,
            encoder,
            metrics,
            dir,
        )
    }

    /// The resume floor names the last FULLY applied block. A leaf that fails partway
    /// through an event must not leave the floor on that block: the marker is written
    /// from it (`commit_v6` -> `current_marker`) and the indexer resumes above it, so
    /// the event's remaining leaves would never be re-delivered.
    #[test]
    fn a_failed_leaf_does_not_leave_the_resume_floor_on_a_partially_applied_block() {
        const PRIOR: u64 = 100;
        const EVENT: u64 = 200;
        let (instance, persistence, logical_store, params, encoder, metrics, _dir) =
            build_unsat_shard_fixtures();
        metrics.lock().last_applied_leaf_block = PRIOR;

        let leaf = |idx: u32, seed: u8| {
            let mut c = [0u8; 32];
            c[31] = seed;
            WalEntryPayload::AppendLeaf {
                tree_number: 0,
                leaf_index: idx,
                commitment: c,
            }
        };

        super::apply_one_leaf(
            &leaf(0, 1),
            EVENT,
            &instance,
            &persistence,
            &logical_store,
            &params,
            encoder.as_ref(),
            &metrics,
        )
        .expect("first leaf of the event applies");

        // Non-contiguous: leaf 5 with only leaf 0 present. Aborts the event mid-way.
        super::apply_one_leaf(
            &leaf(5, 2),
            EVENT,
            &instance,
            &persistence,
            &logical_store,
            &params,
            encoder.as_ref(),
            &metrics,
        )
        .expect_err("a non-contiguous leaf must be refused");

        assert_eq!(
            metrics.lock().last_applied_leaf_block,
            PRIOR,
            "block {EVENT} is only partially applied, so the floor must still name {PRIOR}; \
             advancing it writes a manifest marker the indexer resumes above, and the \
             event's remaining leaves are never re-read"
        );
    }

    #[test]
    fn drive_commit_removes_unsatisfiable_shard_id_from_dirty_set() {
        let (instance, persistence, logical_store, params, encoder, metrics, _dir) =
            build_unsat_shard_fixtures();
        let db_shard_count = instance.current_state().encoded_db.shards.len();
        let unsat_id = u32::try_from(db_shard_count).expect("u32 shard id");
        logical_store
            .lock()
            .dirty_shards_mut_for_test()
            .insert(unsat_id);
        assert!(logical_store.lock().dirty_shards().contains(&unsat_id));

        super::drive_commit(
            &instance,
            &persistence,
            &logical_store,
            &params,
            encoder.as_ref(),
            10,
            &metrics,
        )
        .expect("drive_commit must succeed despite the unsatisfiable shard");

        assert!(
            !logical_store.lock().dirty_shards().contains(&unsat_id),
            "unsatisfiable shard {unsat_id} must be dropped from dirty_shards \
             so subsequent commits do not retry it"
        );
    }

    #[test]
    fn drive_commit_carries_sessions_and_copies_the_database_once() {
        use crate::{InstanceRole, PirInstance};

        let dir = tempfile::tempdir().expect("tempdir");
        let (state, secret_key) = build_small_cache_state_with_key().expect("state");
        let params = small_params();
        let encoder = small_cache_encoder();
        let opened = InspirePersistence::open(
            StoreLayout::open(dir.path()).expect("layout"),
            SCHEME_TAG,
            InstanceId::new("drive-commit-contract"),
            SnapshotPolicy::default(),
            Arc::clone(&encoder),
        )
        .expect("open");
        let persistence = Arc::new(opened.persistence);
        let logical_store = Arc::new(parking_lot::Mutex::new(
            super::super::inspire::LogicalLeafStore::new(),
        ));
        persistence
            .commit_v6(&state, &logical_store.lock(), 0)
            .expect("initial commit");
        let instance: Arc<PirInstance<RavenInspireScheme>> = Arc::new(PirInstance::new(
            InstanceId::new("drive-commit-contract"),
            InstanceRole::Live,
            state,
        ));
        let registered_state = instance.current_state();
        let mut client = super::super::inspire::build_client_session(
            (*registered_state.crs).clone(),
            secret_key,
            &params,
        )
        .expect("client");
        super::super::inspire::register_client_session(&mut client, registered_state.as_ref())
            .expect("register session");

        let donor = instance.current_snapshot();
        let donor_db_bytes = bincode::serialize(&*donor.state.encoded_db).expect("donor db");
        let donor_session_store = Arc::clone(&donor.state.session_store);
        logical_store
            .lock()
            .apply(
                &WalEntryPayload::AppendLeaf {
                    tree_number: 0,
                    leaf_index: 0,
                    commitment: [7; 32],
                },
                1,
                encoder.as_ref(),
            )
            .expect("apply leaf");
        assert_eq!(logical_store.lock().dirty_shards().len(), 1);
        assert!(logical_store.lock().dirty_shards().contains(&0));
        let metrics = Arc::new(parking_lot::Mutex::new(ConsumerMetrics::default()));

        super::drive_commit(
            &instance,
            &persistence,
            &logical_store,
            &params,
            encoder.as_ref(),
            1,
            &metrics,
        )
        .expect("drive commit");

        let published = instance.current_snapshot();
        assert!(published.epoch > donor.epoch);
        assert!(logical_store.lock().dirty_shards().is_empty());
        assert!(!Arc::ptr_eq(
            &published.state.encoded_db,
            &donor.state.encoded_db
        ));
        assert_ne!(
            bincode::serialize(&*published.state.encoded_db).expect("published db"),
            donor_db_bytes
        );
        assert_eq!(
            bincode::serialize(&*donor.state.encoded_db).expect("held donor db"),
            donor_db_bytes
        );
        assert!(Arc::ptr_eq(
            &published.state.session_store,
            &donor_session_store
        ));
        assert_eq!(published.state.session_store.len(), 1);
    }

    /// The empty-dirty branch commits the store verbatim and archives the WAL
    /// that held the leaves, so a store shorter than the committed one converts a
    /// bad start state into permanent loss.
    #[test]
    fn drive_commit_refuses_a_store_shorter_than_the_committed_snapshot() {
        use crate::inspire::LogicalLeafStore;
        let (instance, persistence, logical_store, params, encoder, metrics, _dir) =
            build_unsat_shard_fixtures();

        for leaf_index in 0..3u32 {
            let mut commitment = [0u8; 32];
            commitment[31] = u8::try_from(leaf_index).expect("< 3") | 0x20;
            let payload = WalEntryPayload::AppendLeaf {
                tree_number: 0,
                leaf_index,
                commitment,
            };
            logical_store
                .lock()
                .apply(&payload, 100 + u64::from(leaf_index), encoder.as_ref())
                .expect("seed leaf applies");
        }
        super::drive_commit(
            &instance,
            &persistence,
            &logical_store,
            &params,
            encoder.as_ref(),
            102,
            &metrics,
        )
        .expect("the seeded leaves must commit");
        assert_eq!(persistence.committed_leaf_count(), 3);

        let published = persistence.current_snapshot_id();
        let fresh_store = Arc::new(parking_lot::Mutex::new(LogicalLeafStore::new()));
        let err = super::drive_commit(
            &instance,
            &persistence,
            &fresh_store,
            &params,
            encoder.as_ref(),
            103,
            &metrics,
        )
        .expect_err("a store shorter than the committed snapshot must refuse");
        let msg = format!("{err}");
        assert!(
            msg.contains('0') && msg.contains('3'),
            "the refusal must name both leaf counts, got: {msg}"
        );
        assert_eq!(
            persistence.current_snapshot_id(),
            published,
            "the refusal must not advance the manifest; advancing archives the WAL \
             that still holds the leaves"
        );
    }

    #[test]
    fn unsatisfiable_shard_metric_increments_per_drop_with_bounded_cardinality() {
        // Thread-local recorder avoids racing the process-global Prometheus handle.
        // The metric MUST carry only `instance`; `shard_id` would leak a series per id.
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        metrics::with_local_recorder(&recorder, || {
            let (instance, persistence, logical_store, params, encoder, metrics, _dir) =
                build_unsat_shard_fixtures();
            let db_shard_count = instance.current_state().encoded_db.shards.len();
            let unsat_id = u32::try_from(db_shard_count).expect("u32 shard id");
            logical_store
                .lock()
                .dirty_shards_mut_for_test()
                .insert(unsat_id);
            super::drive_commit(
                &instance,
                &persistence,
                &logical_store,
                &params,
                encoder.as_ref(),
                42,
                &metrics,
            )
            .expect("drive_commit must drop the unsatisfiable shard");
        });

        let snap = snapshotter.snapshot().into_vec();
        let mut found_value: Option<u64> = None;
        for (ck, _unit, _desc, value) in snap {
            if ck.key().name() != "raven_railgun_unsatisfiable_dirty_shards_total" {
                continue;
            }
            let labels: Vec<(&str, &str)> =
                ck.key().labels().map(|l| (l.key(), l.value())).collect();
            let has_shard_id = labels.iter().any(|(k, _)| *k == "shard_id");
            assert!(
                !has_shard_id,
                "raven_railgun_unsatisfiable_dirty_shards_total MUST NOT carry a \
                 `shard_id` label (cardinality leak); got {labels:?}"
            );
            let has_instance = labels.iter().any(|(k, _)| *k == "instance");
            if has_instance {
                if let DebugValue::Counter(v) = value {
                    found_value = Some(v);
                    break;
                }
            }
        }
        let v = found_value.unwrap_or_else(|| {
            panic!(
                "no counter slot for raven_railgun_unsatisfiable_dirty_shards_total{{instance=...}} \
                 in DebuggingRecorder snapshot"
            )
        });
        assert_eq!(
            v, 1,
            "counter must increment exactly once per drop; got {v}"
        );
    }

    #[test]
    fn unsatisfiable_shard_metric_cardinality_bounded_across_distinct_shard_ids() {
        // 32 dropped shard ids must yield exactly one series keyed on `(instance,)`.
        use metrics_util::debugging::DebuggingRecorder;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        metrics::with_local_recorder(&recorder, || {
            let (instance, persistence, logical_store, params, encoder, metrics, _dir) =
                build_unsat_shard_fixtures();
            let db_shard_count = instance.current_state().encoded_db.shards.len();
            let base = u32::try_from(db_shard_count).expect("u32 base shard id");
            for k in 0u32..32u32 {
                let unsat_id = base + k;
                logical_store
                    .lock()
                    .dirty_shards_mut_for_test()
                    .insert(unsat_id);
                super::drive_commit(
                    &instance,
                    &persistence,
                    &logical_store,
                    &params,
                    encoder.as_ref(),
                    u64::from(k),
                    &metrics,
                )
                .expect("drive_commit must drop each unsatisfiable shard");
            }
        });

        let snap = snapshotter.snapshot().into_vec();
        let mut series_count: usize = 0;
        let mut has_shard_id_label = false;
        let mut has_instance_label = false;
        for (ck, _unit, _desc, _value) in snap {
            if ck.key().name() != "raven_railgun_unsatisfiable_dirty_shards_total" {
                continue;
            }
            series_count += 1;
            for label in ck.key().labels() {
                if label.key() == "shard_id" {
                    has_shard_id_label = true;
                }
                if label.key() == "instance" {
                    has_instance_label = true;
                }
            }
        }
        assert_eq!(
            series_count, 1,
            "metric must have exactly one (instance,) tuple regardless of how \
             many distinct shard_ids were dropped; got {series_count} series \
             (a regression that re-introduced a `shard_id` label would surface \
             here as `series_count == 32`)"
        );
        assert!(
            has_instance_label,
            "the single slot must carry the `instance` label"
        );
        assert!(
            !has_shard_id_label,
            "metric MUST NOT carry a `shard_id` label (cardinality leak)"
        );
    }

    #[test]
    fn drive_commit_consumer_errors_bounded_after_unsatisfiable_shard() {
        let (instance, persistence, logical_store, params, encoder, metrics, _dir) =
            build_unsat_shard_fixtures();
        let db_shard_count = instance.current_state().encoded_db.shards.len();
        let unsat_id = u32::try_from(db_shard_count).expect("u32 shard id");
        logical_store
            .lock()
            .dirty_shards_mut_for_test()
            .insert(unsat_id);

        // After the first commit the dirty set is empty, so no further errors.
        for height in 0..100u64 {
            super::drive_commit(
                &instance,
                &persistence,
                &logical_store,
                &params,
                encoder.as_ref(),
                height,
                &metrics,
            )
            .expect("drive_commit must remain Ok across the loop");
        }

        let m = metrics.lock();
        assert_eq!(
            m.consumer_errors, 0,
            "100 commits with a once-unsatisfiable shard must not accumulate \
             consumer_errors (drive_commit returns Ok after dropping the shard)"
        );
        assert_eq!(
            m.commits_fired, 100,
            "every drive_commit must still bump commits_fired"
        );
    }

    /// Pinned against literals: the static policy keeps no append or timer trigger, and the
    /// consumer's bound is what still publishes the rows such an instance applies.
    #[test]
    fn every_policy_publishes_within_a_bounded_nonzero_time() {
        assert_eq!(
            SnapshotPolicy::static_default().publish_bound(),
            Duration::from_secs(300)
        );
        assert_eq!(
            SnapshotPolicy::default().publish_bound(),
            Duration::from_secs(300)
        );
        let with_timer = |secs| SnapshotPolicy {
            max_seconds_between_snapshots: secs,
            ..SnapshotPolicy::static_default()
        };
        assert_eq!(with_timer(2).publish_bound(), Duration::from_secs(2));
        assert_eq!(
            with_timer(0).publish_bound(),
            Duration::from_secs(1),
            "a zero bound would retry a failing publish in a tight loop"
        );
    }

    /// The append that fills a tree publishes at once under the static policy, and the one
    /// before it does not. The fixture's table is one shard, so the filled leaf's shard is out of
    /// range and dropped; the commit is what is counted.
    #[test]
    fn the_append_that_fills_a_tree_publishes_under_the_static_policy() {
        use crate::imt::TREE_MAX_ITEMS;
        let (instance, persistence, logical_store, params, encoder, metrics, _dir) =
            build_unsat_shard_fixtures();
        persistence.set_snapshot_policy(SnapshotPolicy::static_default());
        let leaf = |index: usize| {
            let mut commitment = [0u8; 32];
            commitment[28..].copy_from_slice(&u32::try_from(index).expect("u32").to_be_bytes());
            WalEntryPayload::AppendLeaf {
                tree_number: 0,
                leaf_index: u32::try_from(index).expect("u32"),
                commitment,
            }
        };
        {
            let prefill: Vec<_> = (0..TREE_MAX_ITEMS - 2).map(|i| (leaf(i), 1)).collect();
            let mut store = logical_store.lock();
            store
                .seed_leaf_run(&prefill, encoder.as_ref())
                .expect("prefill");
            store.clear_dirty_shards();
        }
        let append = |index: usize| {
            super::apply_one_leaf(
                &leaf(index),
                1,
                &instance,
                &persistence,
                &logical_store,
                &params,
                encoder.as_ref(),
                &metrics,
            )
            .expect("append");
            metrics.lock().commits_fired
        };
        assert_eq!(append(TREE_MAX_ITEMS - 2), 0, "a tree with room left waits");
        assert_eq!(
            append(TREE_MAX_ITEMS - 1),
            1,
            "the filling append publishes"
        );
        assert!(logical_store.lock().dirty_shards().is_empty());
    }

    /// The mirror path's twin of the chain fill test: the row that fills a list block's tree
    /// publishes at once under the static policy. The fixture's encoder maps no list row to a
    /// shard, so the commit is what is counted.
    #[test]
    fn the_ppoi_row_that_fills_a_list_tree_publishes_under_the_static_policy() {
        use crate::imt::TREE_MAX_ITEMS;
        let (instance, persistence, logical_store, params, encoder, metrics, _dir) =
            build_unsat_shard_fixtures();
        persistence.set_snapshot_policy(SnapshotPolicy::static_default());
        let row = |index: usize| {
            let list_index = u32::try_from(index).expect("u32");
            let mut blinded_commitment = [0u8; 32];
            blinded_commitment[28..].copy_from_slice(&list_index.to_be_bytes());
            WalEntryPayload::PpoiListLeafAdded {
                list_key: [0x5c; 32],
                list_index,
                blinded_commitment,
                event_type: raven_railgun_persistence::PpoiEventType::Shield,
                validated_merkleroot: [0; 32],
            }
        };
        {
            let prefill: Vec<_> = (0..TREE_MAX_ITEMS - 2).map(|i| (row(i), 0)).collect();
            let mut store = logical_store.lock();
            store
                .seed_leaf_run(&prefill, encoder.as_ref())
                .expect("prefill");
            store.clear_dirty_shards();
        }
        // Mirror rows carry height 0, as in production.
        let append = |index: usize| {
            super::apply_list_rows(
                &[(row(index), 0)],
                &instance,
                &persistence,
                &logical_store,
                &params,
                encoder.as_ref(),
                &metrics,
            );
            assert_eq!(metrics.lock().consumer_errors, 0, "row {index} was refused");
            metrics.lock().commits_fired
        };
        assert_eq!(
            append(TREE_MAX_ITEMS - 2),
            0,
            "a list tree with room left waits"
        );
        assert_eq!(append(TREE_MAX_ITEMS - 1), 1, "the filling row publishes");
        assert!(logical_store.lock().dirty_shards().is_empty());
    }

    /// The timed publish writes the resume floor, so it must name the last fully applied block:
    /// never the chain head a heartbeat reports, never a block whose event broke partway.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_deferred_publish_commits_the_last_fully_applied_block_as_the_floor() {
        const APPLIED: u64 = 1_000;
        const BROKEN: u64 = 2_000;
        const HEAD: u64 = 50_000;
        let (instance, persistence, logical_store, params, encoder, metrics, _dir) =
            build_unsat_shard_fixtures();
        persistence.set_snapshot_policy(SnapshotPolicy {
            max_seconds_between_snapshots: 2,
            ..SnapshotPolicy::static_default()
        });
        // The same timer also trips on an append, and a mid-event commit keeps the previous
        // floor by design. Parking the append-side clock in the future keeps a slow box from
        // taking that path, so every commit here is the timed publish.
        let park_append_timer = || {
            persistence.counters.lock().last_snapshot_at =
                Instant::now() + Duration::from_secs(3_600);
        };
        park_append_timer();
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let task = tokio::spawn(run_consumer_task(
            Arc::clone(&instance),
            Arc::clone(&persistence),
            Arc::clone(&logical_store),
            Arc::clone(&metrics),
            params,
            encoder,
            rx,
            None,
        ));
        let heartbeat = || ConsumerEvent::Heartbeat {
            chain_head: HEAD,
            scanned_through: HEAD,
        };
        let published = |commits: u64| {
            let metrics = Arc::clone(&metrics);
            async move {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
                while metrics.lock().commits_fired < commits {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "no timed publish within 45 s at a 2 s bound"
                    );
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        };

        tx.send(shield_at(APPLIED, vec![leaf_at(0, 1)]))
            .await
            .expect("send");
        tx.send(heartbeat()).await.expect("send");
        published(1).await;
        assert_eq!(
            persistence.manifest_block_height(),
            APPLIED,
            "the floor is the applied block, not the chain head"
        );

        park_append_timer();
        // Leaf 1 applies, then a divergent redelivery of leaf 0 breaks the event.
        tx.send(shield_at(BROKEN, vec![leaf_at(1, 2), leaf_at(0, 9)]))
            .await
            .expect("send");
        tx.send(heartbeat()).await.expect("send");
        published(2).await;
        assert_eq!(
            persistence.manifest_block_height(),
            APPLIED,
            "block {BROKEN} broke partway, so the floor must stay on {APPLIED}"
        );
        assert!(logical_store.lock().dirty_shards().is_empty());
        assert_eq!(
            metrics.lock().commits_fired,
            2,
            "one publish per applied event"
        );

        drop(tx);
        task.await.expect("join").expect("consumer task");
    }

    /// A failing publish is retried once per bound, never in a loop, and holds the error run
    /// only until a publish lands: a complete tree applies no event that would clear it. The
    /// failure is a file squatting on the next snapshot's staging path, removed mid-test.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_deferred_publish_is_retried_per_bound_and_clears_once_one_lands() {
        let (instance, persistence, logical_store, params, encoder, metrics, _dir) =
            build_unsat_shard_fixtures();
        persistence.set_snapshot_policy(SnapshotPolicy {
            max_seconds_between_snapshots: 1,
            ..SnapshotPolicy::static_default()
        });
        let leaf = WalEntryPayload::AppendLeaf {
            tree_number: 0,
            leaf_index: 0,
            commitment: [7; 32],
        };
        crate::inspire::apply_wal_entry(&mut logical_store.lock(), &leaf, 1, encoder.as_ref())
            .expect("apply");
        let next = SnapshotId(persistence.current_snapshot_id().0 + 1);
        let blocker = persistence
            .layout()
            .snapshot_dir(next)
            .with_extension("tmp");
        std::fs::write(&blocker, b"").expect("blocker");

        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let task = tokio::spawn(run_consumer_task(
            Arc::clone(&instance),
            Arc::clone(&persistence),
            Arc::clone(&logical_store),
            Arc::clone(&metrics),
            params,
            encoder,
            rx,
            None,
        ));
        tokio::time::sleep(Duration::from_millis(3_500)).await;
        let failed = *metrics.lock();
        assert!(
            (1..=4).contains(&failed.consumer_errors),
            "{} failed publishes in 3.5 s at a 1 s bound",
            failed.consumer_errors
        );
        assert_eq!(
            failed.consecutive_event_errors, failed.consumer_errors,
            "readiness must see a publish that is failing"
        );
        assert_eq!(failed.commits_fired, 0);
        assert_eq!(logical_store.lock().dirty_shards().len(), 1, "still owed");

        std::fs::remove_file(&blocker).expect("unblock");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while metrics.lock().commits_fired == 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        tx.send(ConsumerEvent::Shutdown)
            .await
            .expect("send shutdown");
        task.await.expect("join").expect("consumer task");

        let landed = *metrics.lock();
        assert!(landed.commits_fired >= 1, "the retry published");
        assert_eq!(
            landed.consecutive_event_errors, 0,
            "a landed publish must reopen readiness with no event to help"
        );
        assert_eq!(landed.consumer_errors, failed.consumer_errors);
        assert!(logical_store.lock().dirty_shards().is_empty());
    }

    const LIST: [u8; 32] = [0x5c; 32];

    fn list_bc(index: u32) -> [u8; 32] {
        let mut bc = [0u8; 32];
        bc[0] = 0x0b;
        bc[1..5].copy_from_slice(&index.to_be_bytes());
        bc[31] = 0x01;
        bc
    }

    /// Rows `0..count` of [`LIST`], each carrying the root upstream publishes with it.
    fn list_rows(count: u32) -> Vec<(WalEntryPayload, u64)> {
        let mut tree = crate::imt::Imt::new().expect("imt");
        (0..count)
            .map(|index| {
                tree.insert_leaves(index as usize, &[list_bc(index)])
                    .expect("append");
                let row = WalEntryPayload::PpoiListLeafAdded {
                    list_key: LIST,
                    list_index: index,
                    blinded_commitment: list_bc(index),
                    event_type: raven_railgun_persistence::PpoiEventType::Shield,
                    validated_merkleroot: tree.root(),
                };
                (row, 0)
            })
            .collect()
    }

    fn rows_held(store: &parking_lot::Mutex<crate::inspire::LogicalLeafStore>) -> usize {
        store
            .lock()
            .ppoi_imt(&LIST)
            .map_or(0, crate::imt::Imt::leaf_count)
    }

    /// A kill between a page's apply and its sync: nothing derived from the page may show
    /// (store rows the shim and the feed read, the ack, a publish, a snapshot or manifest), and
    /// after the power loss that drops its unsynced frames, recovery stands on the last synced
    /// page and the page applies again when the feed asks for it again.
    #[allow(clippy::indexing_slicing, clippy::too_many_lines)]
    #[test]
    fn a_crash_between_apply_and_sync_shows_nothing_of_the_page_and_recovers_to_the_last_synced_one(
    ) {
        let (instance, persistence, logical_store, params, encoder, metrics, dir) =
            build_unsat_shard_fixtures();
        // Due by the append count once the second page lands, so a publish of it would show.
        persistence.set_snapshot_policy(SnapshotPolicy {
            max_appends_per_snapshot: 6,
            max_seconds_between_snapshots: 3_600,
            ..SnapshotPolicy::default()
        });
        let rows = list_rows(9);
        let apply = |persistence: &Arc<InspirePersistence>,
                     logical_store: &Arc<parking_lot::Mutex<crate::inspire::LogicalLeafStore>>,
                     metrics: &Arc<parking_lot::Mutex<ConsumerMetrics>>,
                     page: std::ops::Range<usize>| {
            apply_list_rows(
                &rows[page],
                &instance,
                persistence,
                logical_store,
                &params,
                encoder.as_ref(),
                metrics,
            );
        };

        apply(&persistence, &logical_store, &metrics, 0..5);
        assert_eq!(rows_held(&logical_store), 5);
        let durable = persistence.wal.synced_len();
        let acked = *metrics.lock();
        let snapshot = persistence.current_snapshot_id();
        let epoch = instance.current_snapshot().epoch;

        persistence
            .fail_next_sync
            .store(true, std::sync::atomic::Ordering::SeqCst);
        apply(&persistence, &logical_store, &metrics, 5..9);
        let after = *metrics.lock();
        assert_eq!(
            rows_held(&logical_store),
            5,
            "the store shows the unsynced page"
        );
        assert_eq!(
            after.events_processed, acked.events_processed,
            "acked unsynced rows"
        );
        assert_eq!(
            after.commits_fired, acked.commits_fired,
            "committed unsynced rows"
        );
        assert_eq!(
            persistence.current_snapshot_id(),
            snapshot,
            "snapshot or manifest moved"
        );
        assert_eq!(
            instance.current_snapshot().epoch,
            epoch,
            "published unsynced rows"
        );
        assert_eq!(
            persistence.list_row_refused(),
            Some(5),
            "the feed must ask for row 5 again"
        );
        assert!(
            after.consecutive_event_errors > 0,
            "readiness must see the failure"
        );
        assert_eq!(persistence.wal.synced_len(), durable);

        let wal = persistence.layout().wal_current_path();
        drop(persistence);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&wal)
            .expect("wal")
            .set_len(durable)
            .expect("drop the unsynced suffix");
        let reopened = InspirePersistence::open(
            StoreLayout::open(dir.path()).expect("layout"),
            SCHEME_TAG,
            InstanceId::new("unsat-shard-fixtures"),
            SnapshotPolicy::default(),
            Arc::clone(&encoder),
        )
        .expect("reopen");
        let logical_store = Arc::new(parking_lot::Mutex::new(reopened.recovered_logical_store));
        assert_eq!(
            rows_held(&logical_store),
            5,
            "recovery stands on the synced page"
        );

        let persistence = Arc::new(reopened.persistence);
        let metrics = Arc::new(parking_lot::Mutex::new(ConsumerMetrics::default()));
        apply(&persistence, &logical_store, &metrics, 5..9);
        assert_eq!(rows_held(&logical_store), 9);
        let WalEntryPayload::PpoiListLeafAdded {
            validated_merkleroot,
            ..
        } = rows[8].0
        else {
            panic!("a list row");
        };
        assert_eq!(
            logical_store.lock().ppoi_imt_root(&LIST),
            Some(validated_merkleroot)
        );
        assert_eq!(metrics.lock().consumer_errors, 0);
    }

    /// A row sent again is skipped: no error, no ack, no WAL entry, nothing for readiness or
    /// the root screen to count. Only a different row at a held index is refused.
    #[allow(clippy::indexing_slicing)]
    #[test]
    fn a_row_sent_again_is_skipped_and_counts_nothing() {
        let (instance, persistence, logical_store, params, encoder, metrics, _dir) =
            build_unsat_shard_fixtures();
        let rows = list_rows(6);
        let apply = |batch: &[(WalEntryPayload, u64)]| {
            apply_list_rows(
                batch,
                &instance,
                &persistence,
                &logical_store,
                &params,
                encoder.as_ref(),
                &metrics,
            );
        };
        apply(&rows[..4]);
        let applied = *metrics.lock();
        let seq = persistence.wal_next_seq();

        apply(&rows[1..4]);
        let mut in_one_batch = rows[4..6].to_vec();
        in_one_batch.extend_from_slice(&rows[4..6]);
        apply(&in_one_batch);
        let after = *metrics.lock();
        assert_eq!(rows_held(&logical_store), 6);
        assert_eq!(after.consumer_errors, 0);
        assert_eq!(after.consecutive_event_errors, 0);
        assert_eq!(persistence.list_row_refused(), None);
        assert_eq!(after.events_processed, applied.events_processed + 2);
        assert_eq!(
            persistence.wal_next_seq(),
            seq + 2,
            "a skipped row reached the WAL"
        );

        let WalEntryPayload::PpoiListLeafAdded {
            list_index,
            event_type,
            validated_merkleroot,
            ..
        } = rows[2].0
        else {
            panic!("a list row");
        };
        apply(&[(
            WalEntryPayload::PpoiListLeafAdded {
                list_key: LIST,
                list_index,
                blinded_commitment: list_bc(99),
                event_type,
                validated_merkleroot,
            },
            0,
        )]);
        let refused = *metrics.lock();
        assert_eq!(
            refused.consumer_errors, 1,
            "a different row at a held index"
        );
        assert_eq!(
            persistence.list_row_refused(),
            None,
            "it leaves no row lacking"
        );
    }

    /// A refused row names the row the instance lacks, and so do the rows past it that arrive
    /// before it is sent again; applying it clears the name.
    #[allow(clippy::indexing_slicing)]
    #[test]
    fn a_refused_row_names_the_row_the_instance_lacks_until_it_applies() {
        let (instance, persistence, logical_store, params, encoder, metrics, _dir) =
            build_unsat_shard_fixtures();
        let rows = list_rows(6);
        let apply = |batch: &[(WalEntryPayload, u64)]| {
            apply_list_rows(
                batch,
                &instance,
                &persistence,
                &logical_store,
                &params,
                encoder.as_ref(),
                &metrics,
            );
        };
        let mut diverged = rows[3].clone();
        if let WalEntryPayload::PpoiListLeafAdded {
            validated_merkleroot,
            ..
        } = &mut diverged.0
        {
            validated_merkleroot[31] ^= 1;
        }
        let mut batch = rows[..3].to_vec();
        batch.push(diverged);
        batch.extend_from_slice(&rows[4..]);
        apply(&batch);
        assert_eq!(rows_held(&logical_store), 3);
        assert_eq!(persistence.list_row_refused(), Some(3));
        assert_eq!(metrics.lock().consumer_errors, 3);

        apply(&rows[3..]);
        assert_eq!(rows_held(&logical_store), 6);
        assert_eq!(persistence.list_row_refused(), None);
        assert_eq!(metrics.lock().consecutive_event_errors, 0);
    }

    /// A list block on the per-list path10 encoder, two shards wide, so list rows dirty shards.
    fn list_block_fixture(policy: SnapshotPolicy) -> UnsatShardFixtures {
        use crate::pir_table::list::PATH10_RECORD_BYTES;
        let dir = tempfile::tempdir().expect("tempdir");
        let params = InspireParams::secure_128_d2048();
        let encoder = crate::pir_table::EncoderKind::PerListPath10 { list_key: LIST }
            .build(PATH10_RECORD_BYTES, 2048)
            .expect("encoder");
        let seed = vec![0u8; 2 * 2048 * PATH10_RECORD_BYTES];
        let (state, _) = super::super::inspire::setup_state(
            &params,
            &seed,
            PATH10_RECORD_BYTES,
            InspireVariant::TwoPacking,
        )
        .expect("state");
        let opened = InspirePersistence::open(
            StoreLayout::open(dir.path()).expect("layout"),
            SCHEME_TAG,
            InstanceId::new("list-block"),
            policy,
            Arc::clone(&encoder),
        )
        .expect("open");
        let persistence = Arc::new(opened.persistence);
        persistence
            .commit_v6(&state, &crate::inspire::LogicalLeafStore::default(), 0)
            .expect("initial commit");
        let instance = Arc::new(PirInstance::<RavenInspireScheme>::new(
            InstanceId::new("list-block"),
            crate::InstanceRole::Live,
            state,
        ));
        (
            instance,
            persistence,
            Arc::new(parking_lot::Mutex::new(
                crate::inspire::LogicalLeafStore::new(),
            )),
            params,
            encoder,
            Arc::new(parking_lot::Mutex::new(ConsumerMetrics::default())),
            dir,
        )
    }

    /// Waits until `done` holds, failing only when `progress` stops moving for 60 s.
    async fn until<P: PartialEq + std::fmt::Debug>(
        what: &str,
        progress: impl Fn() -> P,
        done: impl Fn() -> bool,
    ) {
        let mut last = progress();
        let mut since = tokio::time::Instant::now();
        while !done() {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let now = progress();
            if now == last {
                assert!(
                    since.elapsed() < Duration::from_secs(60),
                    "{what}: stuck at {now:?}"
                );
            } else {
                (last, since) = (now, tokio::time::Instant::now());
            }
        }
    }

    /// While a feed catches up, the append count re-encodes nothing; catching up publishes once,
    /// and from then on the policy counts appends again.
    #[allow(clippy::indexing_slicing)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_backfilling_block_commits_on_catching_up_and_on_its_policy_after() {
        let (instance, persistence, logical_store, params, encoder, metrics, _dir) =
            list_block_fixture(SnapshotPolicy {
                max_appends_per_snapshot: 4,
                max_seconds_between_snapshots: 3_600,
                ..SnapshotPolicy::default()
            });
        persistence.set_backfilling(true);
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let task = tokio::spawn(run_consumer_task(
            Arc::clone(&instance),
            Arc::clone(&persistence),
            Arc::clone(&logical_store),
            Arc::clone(&metrics),
            params,
            encoder,
            rx,
            None,
        ));
        let rows = list_rows(16);
        for (row, height) in &rows[..12] {
            tx.send(ConsumerEvent::Ppoi(row.clone(), *height))
                .await
                .expect("send");
        }
        // Behind the rows in the queue, so once it lands every commit they drove has run.
        tx.send(ConsumerEvent::Heartbeat {
            chain_head: 7,
            scanned_through: 7,
        })
        .await
        .expect("send");
        until(
            "12 rows applied",
            || {
                (
                    rows_held(&logical_store),
                    metrics.lock().last_known_chain_head,
                )
            },
            || metrics.lock().last_known_chain_head == 7,
        )
        .await;
        assert_eq!(rows_held(&logical_store), 12);
        assert_eq!(
            metrics.lock().commits_fired,
            0,
            "12 rows at a 4-append policy re-encoded the block while backfilling"
        );
        assert!(!logical_store.lock().dirty_shards().is_empty());

        persistence.set_backfilling(false);
        until(
            "the catch-up publish",
            || metrics.lock().commits_fired,
            || metrics.lock().commits_fired == 1,
        )
        .await;
        assert!(logical_store.lock().dirty_shards().is_empty());

        for (row, height) in &rows[12..] {
            tx.send(ConsumerEvent::Ppoi(row.clone(), *height))
                .await
                .expect("send");
        }
        until(
            "a commit on the policy",
            || (rows_held(&logical_store), metrics.lock().commits_fired),
            || metrics.lock().commits_fired == 2,
        )
        .await;
        tx.send(ConsumerEvent::Shutdown).await.expect("shutdown");
        task.await.expect("join").expect("consumer task");
    }

    /// The append count a backfill built up is left to the publish that ends the backfill, which
    /// the consumer makes once its queue is empty, so rows still queued do not re-encode the
    /// block once more on the way.
    #[test]
    fn ending_a_backfill_leaves_the_append_count_to_the_catch_up_publish() {
        let (_instance, persistence, _store, _params, _encoder, _metrics, _dir) =
            build_unsat_shard_fixtures();
        persistence.set_snapshot_policy(SnapshotPolicy {
            max_appends_per_snapshot: 4,
            max_seconds_between_snapshots: 3_600,
            ..SnapshotPolicy::default()
        });
        persistence.set_backfilling(true);
        for _ in 0..6 {
            persistence.count_append();
        }
        assert!(!persistence.snapshot_due(), "due while backfilling");
        persistence.set_backfilling(false);
        assert!(
            !persistence.snapshot_due(),
            "due again ahead of the catch-up publish"
        );
        persistence
            .publish_requested
            .store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(
            persistence.snapshot_due(),
            "once the consumer takes the request, the policy counts appends again"
        );
    }
}
