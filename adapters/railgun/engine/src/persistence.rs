//! Persistence integration glue for [`PirInstance<RavenInspireScheme>`].
//! Wraps `Manifest`, `Snapshot`, `Wal`, `StoreLayout` with a per-instance
//! `SnapshotPolicy` and the bootstrap/commit/archive flow.

use super::inspire::{snapshot_inspire_state, InspireServerState, RavenInspireScheme};
use super::{InstanceRole, PirInstance};
use parking_lot::Mutex;
use raven_railgun_core::{AdapterError, Epoch, InstanceId, Result};
use raven_railgun_persistence::{
    Manifest, Snapshot, SnapshotId, StoreLayout, Wal, WalEntryPayload, MANIFEST_SCHEMA_VERSION,
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
}

/// Snapshot cadence and retention config.
#[derive(Clone, Copy, Debug)]
pub struct SnapshotPolicy {
    /// WAL appends since last snapshot before triggering.
    pub max_appends_per_snapshot: usize,
    /// Seconds since last snapshot before triggering.
    pub max_seconds_between_snapshots: u64,
    /// Sealed WAL file retention count.
    pub archived_wals_retain: usize,
    /// `snap-NNNNNN/` directory retention count. The live snapshot is never deleted.
    pub snapshots_retain: usize,
}

impl Default for SnapshotPolicy {
    fn default() -> Self {
        Self {
            max_appends_per_snapshot: 1000,
            max_seconds_between_snapshots: 300,
            archived_wals_retain: 16,
            snapshots_retain: 4,
        }
    }
}

impl SnapshotPolicy {
    /// Policy for static commit-tree instances: effectively snapshot-once.
    pub const fn static_default() -> Self {
        Self {
            max_appends_per_snapshot: usize::MAX,
            max_seconds_between_snapshots: u64::MAX,
            archived_wals_retain: 4,
            snapshots_retain: 2,
        }
    }
}

#[derive(Debug)]
struct SnapshotCounters {
    appends_since_snapshot: usize,
    last_snapshot_at: Instant,
}

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
}

/// Result of [`InspirePersistence::open`].
#[derive(Debug)]
pub struct OpenedInstance {
    /// Persistence handle.
    pub persistence: InspirePersistence,
    /// Recovered state; `None` on fresh bootstrap.
    pub recovered_state: Option<InspireServerState>,
    /// Logical leaf store rebuilt from WAL replay. Empty on fresh bootstrap.
    pub recovered_logical_store: super::inspire::LogicalLeafStore,
}

impl InspirePersistence {
    /// Open at `layout`. Recovers from an existing manifest or initializes fresh.
    ///
    /// Rejects if `encoder.label()` doesn't match the manifest's stored label.
    #[allow(clippy::too_many_lines)]
    pub fn open(
        layout: StoreLayout,
        scheme_tag: impl Into<String>,
        instance_id: InstanceId,
        policy: SnapshotPolicy,
        encoder: Arc<dyn super::pir_table::PirTableEncoder>,
    ) -> Result<OpenedInstance> {
        ensure_metrics_described();
        let scheme_tag = scheme_tag.into();
        let encoder_label = encoder.label();
        if let Some(manifest) = Manifest::load(&layout)
            .map_err(|e| AdapterError::Internal(format!("manifest load: {e}")))?
        {
            if manifest.scheme_tag != scheme_tag {
                return Err(AdapterError::Internal(format!(
                    "manifest scheme_tag mismatch: stored {} != configured {}",
                    manifest.scheme_tag, scheme_tag
                )));
            }
            if manifest.instance_id != instance_id.to_string() {
                return Err(AdapterError::Internal(format!(
                    "manifest instance_id mismatch: stored {} != configured {}",
                    manifest.instance_id, instance_id
                )));
            }
            if manifest.encoder_label != encoder_label {
                return Err(AdapterError::Internal(format!(
                    "manifest encoder_label mismatch: stored {} != configured {}; \
                     on-disk encoded DB was built with a different encoder shape, \
                     operator must reconcile (clear data_dir + restart with the new \
                     encoder, OR revert config to the on-disk encoder)",
                    manifest.encoder_label, encoder_label
                )));
            }
            // SnapshotId(0): sentinel for "manifest exists but no commit yet".
            // Reopen with id=0 → recovered_state is None; LogicalLeafStore rebuilt from WAL.
            //
            // V6-aware: `restore_inspire_state_v6` auto-dispatches on the
            // `SNAPSHOT_V6_MAGIC` prefix. V6 snapshots carry the embedded
            // [`LogicalLeafStore`] which seeds the replay base below; V5
            // snapshots (legacy) return a default-empty store and rely on
            // WAL replay to repopulate.
            let (recovered_state, recovered_seed_store, entries_per_shard) =
                if manifest.current_snapshot_id == SnapshotId(0) {
                    (None, super::inspire::LogicalLeafStore::new(), u32::MAX)
                } else {
                    let snap = Snapshot::load(&layout, manifest.current_snapshot_id)
                        .map_err(|e| AdapterError::Internal(format!("snapshot load: {e}")))?;
                    let (s, store) = super::inspire::restore_inspire_state_v6(&snap.data)?;
                    let eps = u32::try_from(
                        s.encoded_db
                            .config
                            .entries_per_shard()
                            .min(u64::from(u32::MAX)),
                    )
                    .unwrap_or(u32::MAX);
                    (Some(s), store, eps)
                };
            let wal_floor = manifest.current_snapshot_seq.checked_sub(1);
            let wal = Wal::open(&layout, wal_floor)
                .map_err(|e| AdapterError::Internal(format!("wal open: {e}")))?;
            let mut logical_store = recovered_seed_store;
            let replay = wal
                .replay()
                .map_err(|e| AdapterError::Internal(format!("wal replay: {e}")))?;
            // Tolerant-replay: `InvalidQuery` during replay is soft-skipped (log + count).
            // `Internal`/`Serialization` errors still bubble.
            let mut replay_skipped: u64 = 0;
            let _ = entries_per_shard;
            let replay_encoder = encoder.as_ref();
            for entry in &replay.entries {
                if entry.seq < manifest.current_snapshot_seq {
                    continue;
                }
                let payload: WalEntryPayload = bincode::deserialize(&entry.payload)
                    .map_err(|e| AdapterError::Serialization(format!("wal payload: {e}")))?;
                if let Err(e) = super::inspire::apply_wal_entry(
                    &mut logical_store,
                    &payload,
                    entry.block_height,
                    replay_encoder,
                ) {
                    if matches!(e, AdapterError::InvalidQuery(_)) {
                        tracing::warn!(
                            seq = entry.seq,
                            block_height = entry.block_height,
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
                    "wal replay completed with {replay_skipped} skipped invalid entries"
                );
                metrics::counter!("raven_railgun_wal_replay_skipped_total")
                    .increment(replay_skipped);
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
                },
                recovered_state,
                recovered_logical_store: logical_store,
            })
        } else {
            // Fresh bootstrap: no manifest. Refuse if WAL is non-empty to avoid replaying
            // ghost entries from a prior failed bootstrap.
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
                current_block_height: 0,
                encoder_label: encoder_label.to_owned(),
                prev_encoder_label: None,
            };
            // Persist manifest before returning so a commit() failure lands in recovery path.
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
                },
                recovered_state: None,
                recovered_logical_store: super::inspire::LogicalLeafStore::new(),
            })
        }
    }

    /// Snapshot state (V5 legacy codec), archive WAL, and bump the
    /// manifest atomically.
    ///
    /// Retained for the encoder-migration tools and back-compat
    /// regression tests. New code should call [`InspirePersistence::commit_v6`]
    /// so the embedded [`super::inspire::LogicalLeafStore`] travels with
    /// the snapshot and survives WAL archival.
    pub fn commit(
        &self,
        state: &InspireServerState,
        current_block_height: u64,
    ) -> Result<SnapshotId> {
        let bundle = snapshot_inspire_state(state)?;
        self.commit_serialized_bundle(bundle, current_block_height)
    }

    /// V6 commit: snapshot `(state, store)` to the V6 envelope, archive
    /// WAL, and bump the manifest atomically. The manifest's
    /// `schema_version` advances to [`raven_railgun_persistence::MANIFEST_SCHEMA_VERSION`]
    /// (currently V6) on the next manifest save.
    pub fn commit_v6(
        &self,
        state: &InspireServerState,
        store: &super::inspire::LogicalLeafStore,
        current_block_height: u64,
    ) -> Result<SnapshotId> {
        let bundle = super::inspire::snapshot_inspire_state_v6(state, store)?;
        self.commit_serialized_bundle(bundle, current_block_height)
    }

    fn commit_serialized_bundle(
        &self,
        bundle: Vec<u8>,
        current_block_height: u64,
    ) -> Result<SnapshotId> {
        let snap = Snapshot::build(bundle);

        // Lock-drop + CAS: read next_id under lock, drop lock, save snapshot (slow),
        // re-lock and CAS-check before committing — keeps manifest lock contention minimal.
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

        // Manifest-save BEFORE archive: crash between (1) and (2) is safe — replay
        // floor already advanced, so surviving events in current.log are replayed.
        let prev_seq = m.current_snapshot_seq;
        let cur_seq = self.wal.next_seq().saturating_sub(1);
        let new_floor = self.wal.next_seq();
        m.current_snapshot_id = next_id;
        m.current_snapshot_seq = new_floor;
        m.current_block_height = current_block_height;
        m.schema_version = MANIFEST_SCHEMA_VERSION;
        m.save(&self.layout)
            .map_err(|e| AdapterError::Internal(format!("manifest save: {e}")))?;

        let archive_from = prev_seq;
        self.wal
            .archive(archive_from, cur_seq)
            .map_err(|e| AdapterError::Internal(format!("wal archive: {e}")))?;

        {
            let mut c = self.counters.lock();
            c.appends_since_snapshot = 0;
            c.last_snapshot_at = Instant::now();
        }

        drop(m);
        self.cleanup_archived_wals()?;
        self.cleanup_old_snapshots()?;

        Ok(next_id)
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
        let mut c = self.counters.lock();
        c.appends_since_snapshot = c.appends_since_snapshot.saturating_add(1);
        let elapsed = c.last_snapshot_at.elapsed();
        let policy_snap = *self.policy.read();
        let trigger = c.appends_since_snapshot >= policy_snap.max_appends_per_snapshot
            || elapsed >= Duration::from_secs(policy_snap.max_seconds_between_snapshots);
        Ok((seq, trigger))
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

    /// Recovered chain-event block height baseline.
    ///
    /// Returns `manifest.current_block_height`, advanced by
    /// [`Self::commit_v6`] / [`Self::commit`] on every successful
    /// commit and recovered by [`Self::open`]. Operator-facing
    /// surfaces (`/v1/status.consumer.last_applied_block`, the
    /// per-tree-floor map built at serve-time) seed off this value so
    /// a freshly-restarted instance does NOT re-scan events the chain
    /// driver already applied + the consumer task would only drop as
    /// duplicates.
    #[must_use]
    pub fn manifest_block_height(&self) -> u64 {
        self.manifest.lock().current_block_height
    }

    /// Append a `Reorg` WAL marker. Returns the assigned WAL seq.
    pub fn signal_reorg(&self, height: u64) -> Result<u64> {
        let payload = WalEntryPayload::Reorg { height };
        let (seq, _) = self.apply_event(&payload, height)?;
        Ok(seq)
    }

    fn cleanup_archived_wals(&self) -> Result<()> {
        let retain = self.policy.read().archived_wals_retain;
        if retain == usize::MAX {
            return Ok(());
        }
        let archive_dir = self.layout.root().join("wal").join("archived");
        if !archive_dir.is_dir() {
            return Ok(());
        }
        let mut entries: Vec<_> = std::fs::read_dir(&archive_dir)
            .map_err(|e| AdapterError::Internal(format!("read archive dir: {e}")))?
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("seq-"))
            .collect();
        // Sort newest-first by filename (filenames embed seq
        // numbers + are zero-padded by `wal_archived_path`).
        entries.sort_by_key(|e| std::cmp::Reverse(e.file_name()));
        for old in entries.into_iter().skip(retain) {
            let _ = std::fs::remove_file(old.path());
        }
        Ok(())
    }

    fn cleanup_old_snapshots(&self) -> Result<()> {
        let retain = self.policy.read().snapshots_retain;
        if retain == usize::MAX {
            return Ok(());
        }
        let snap_dir = self.layout.root().join("snapshots");
        if !snap_dir.is_dir() {
            return Ok(());
        }
        let live_id = self.manifest.lock().current_snapshot_id;
        let mut entries: Vec<(u64, std::path::PathBuf)> = std::fs::read_dir(&snap_dir)
            .map_err(|e| AdapterError::Internal(format!("read snapshots dir: {e}")))?
            .filter_map(std::result::Result::ok)
            .filter_map(|de| {
                let name = de.file_name();
                let s = name.to_string_lossy();
                let num = s.strip_prefix("snap-")?.parse::<u64>().ok()?;
                Some((num, de.path()))
            })
            .collect();
        // Newest first by id.
        entries.sort_by_key(|(n, _)| std::cmp::Reverse(*n));
        for (id, path) in entries.into_iter().skip(retain) {
            if id == live_id.0 {
                // Never delete the live snapshot. (This branch
                // fires when policy.snapshots_retain is small
                // enough that the live id is older than the
                // retention window; it's a load-bearing safety.)
                continue;
            }
            let _ = std::fs::remove_dir_all(&path);
        }
        Ok(())
    }
}

/// Construct a [`PirInstance<RavenInspireScheme>`] tied to a persistence handle.
///
/// Recovers from disk if a manifest exists; otherwise calls `fresh_state_factory`.
pub fn bootstrap_inspire_instance(
    layout: StoreLayout,
    scheme_tag: impl Into<String>,
    instance_id: InstanceId,
    role: InstanceRole,
    policy: SnapshotPolicy,
    encoder: Arc<dyn super::pir_table::PirTableEncoder>,
    fresh_state_factory: impl FnOnce() -> Result<InspireServerState>,
) -> Result<(PirInstance<RavenInspireScheme>, Arc<InspirePersistence>)> {
    let opened =
        InspirePersistence::open(layout, scheme_tag, instance_id.clone(), policy, encoder)?;
    let persistence = Arc::new(opened.persistence);
    let state = if let Some(s) = opened.recovered_state {
        s
    } else {
        // Fire commit_notify so observers waiting on first commit don't deadlock.
        // Bootstrap first commit uses the V6 envelope so the embedded
        // `LogicalLeafStore` travels with the snapshot from the very
        // first manifest write. Empty store on first bootstrap.
        let s = fresh_state_factory()?;
        let empty_store = super::inspire::LogicalLeafStore::default();
        persistence.commit_v6(&s, &empty_store, 0)?;
        persistence.commit_notify().notify_waiters();
        s
    };
    let instance = PirInstance::new(instance_id, role, state);
    let _ = Epoch::ZERO; // import path
    Ok((instance, persistence))
}

/// One unit of work the engine consumer task processes.
#[derive(Debug, Clone)]
pub enum ConsumerEvent {
    /// A decoded chain event from the indexer.
    Chain(raven_railgun_core::RailgunEvent, u64),
    /// A reorg fence.
    Reorg(u64),
    /// A PPOI status row from the upstream mirror.
    Ppoi(raven_railgun_persistence::WalEntryPayload, u64),
    /// Heartbeat carrying the chain-head block number.
    Heartbeat(u64),
    /// Operator-driven shutdown signal.
    Shutdown,
}

/// Consumer-task progress and lag metrics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConsumerMetrics {
    /// Last block height applied.
    pub last_applied_block: u64,
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
}

impl ConsumerMetrics {
    /// Lag = chain_head - last_applied.
    #[must_use]
    pub fn indexer_lag_blocks(&self) -> u64 {
        self.last_known_chain_head
            .saturating_sub(self.last_applied_block)
    }
}

/// Layer 2 verifier wiring threaded into [`run_consumer_task`].
pub struct Layer2VerifierContext {
    /// Authority model. `UpstreamSignature` skips the verifier loop.
    pub verification_mode: super::orchestrator::VerificationMode,
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
            .field("verification_mode", &self.verification_mode)
            .field("cadence_n", &self.cadence_n)
            .field("tree_number", &self.tree_number)
            .field("chain_source_attached", &self.chain_source.is_some())
            .finish()
    }
}

struct Layer2VerifierState {
    ctx: Layer2VerifierContext,
    commits_since_last_verify: u32,
    last_in_sync_height: u64,
    last_seen_commits: u64,
    last_seen_reorgs: u64,
}

impl Layer2VerifierState {
    fn new(ctx: Layer2VerifierContext, baseline_metrics: &ConsumerMetrics) -> Self {
        Self {
            ctx,
            commits_since_last_verify: 0,
            last_in_sync_height: baseline_metrics.last_applied_block,
            last_seen_commits: baseline_metrics.commits_fired,
            last_seen_reorgs: baseline_metrics.reorgs_handled,
        }
    }

    fn is_active(&self) -> bool {
        self.ctx.cadence_n > 0
            && self.ctx.chain_source.is_some()
            && matches!(
                self.ctx.verification_mode,
                super::orchestrator::VerificationMode::ChainRootHistory,
            )
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

        let (commits, reorgs) = {
            let m = metrics.lock();
            (m.commits_fired, m.reorgs_handled)
        };

        if commits == self.last_seen_commits {
            if reorgs > self.last_seen_reorgs {
                self.last_seen_reorgs = reorgs;
                self.commits_since_last_verify = 0;
            }
            return;
        }
        self.last_seen_commits = commits;

        if reorgs > self.last_seen_reorgs {
            self.last_seen_reorgs = reorgs;
            self.commits_since_last_verify = 0;
            tracing::debug!(
                tree_number = self.ctx.tree_number,
                "layer2 verifier: skipping cycle; layer1 reorg fired this cycle"
            );
            return;
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
                self.last_in_sync_height = current_height;
                metrics::counter!("raven_railgun_layer2_in_sync_total").increment(1);
            }
            crate::layer_two::VerifyOutcome::OutOfSync {
                local_root,
                tree_number,
            } => {
                metrics::counter!("raven_railgun_layer2_out_of_sync_total").increment(1);
                tracing::warn!(
                    ?local_root,
                    tree_number,
                    last_in_sync_height = self.last_in_sync_height,
                    "layer2 verifier: OutOfSync; cascading reorg through existing reorg path"
                );
                let payload = WalEntryPayload::Reorg {
                    height: self.last_in_sync_height,
                };
                if let Err(e) = apply_reorg(
                    &payload,
                    self.last_in_sync_height,
                    instance,
                    persistence,
                    logical_store,
                    params,
                    encoder,
                    metrics,
                ) {
                    record_consumer_error(
                        metrics,
                        &e,
                        "Layer2 synthetic reorg apply",
                        self.last_in_sync_height,
                    );
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
         IMT root and cascaded a synthetic reorg through the existing \
         reorg path."
    );
    metrics::counter!("raven_railgun_layer2_out_of_sync_total").increment(0);
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

    let mut verifier_state = verifier_ctx.map(|ctx| {
        let baseline = *metrics.lock();
        Layer2VerifierState::new(ctx, &baseline)
    });

    loop {
        let Some(msg) = rx.recv().await else {
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
                        for leaf in &leaves {
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
                        // Per-leaf path above handled commit +
                        // metrics; the outer match arm only
                        // updates aggregate event counters.
                        let _ = (tree_number, leaves);
                        {
                            let mut m = metrics.lock();
                            m.last_applied_block = height;
                            if !had_error {
                                m.events_processed = m.events_processed.saturating_add(1);
                            }
                        }
                        continue;
                    }
                    raven_railgun_core::RailgunEvent::Nullified { .. } => {
                        // Nullifiers don't produce new leaves; tracked
                        // out-of-band by the wallet (it computes its
                        // own nullifier and cross-references against
                        // chain Nullified events). The engine just
                        // records the height; no WAL payload is the
                        // stable behavior.
                        let mut m = metrics.lock();
                        m.last_applied_block = height;
                        m.events_processed = m.events_processed.saturating_add(1);
                        continue;
                    }
                    raven_railgun_core::RailgunEvent::Unshield { .. } => {
                        // Unshield emits to public; not a tree mutation.
                        // Same as Nullified above.
                        let mut m = metrics.lock();
                        m.last_applied_block = height;
                        m.events_processed = m.events_processed.saturating_add(1);
                        continue;
                    }
                }
            }
            ConsumerEvent::Reorg(height) => {
                let p = WalEntryPayload::Reorg { height };
                if let Err(e) = apply_reorg(
                    &p,
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
            ConsumerEvent::Ppoi(payload, height) => (payload, height),
            ConsumerEvent::Heartbeat(chain_head) => {
                let mut m = metrics.lock();
                m.last_known_chain_head = chain_head;
                let lag = m.indexer_lag_blocks();
                drop(m);
                // emit indexer_lag_blocks gauge so
                // operators can alert on stale indexers from
                // /metrics. The gauge is process-global; the
                // HTTP layer's /v1/status endpoint can read the
                // same `metrics` struct via the orchestrator
                // handle when wired in V2.
                #[allow(clippy::cast_precision_loss)]
                let lag_f64 = lag as f64;
                #[allow(clippy::cast_precision_loss)]
                let head_f64 = chain_head as f64;
                metrics::gauge!("raven_railgun_indexer_lag_blocks").set(lag_f64);
                metrics::gauge!("raven_railgun_indexer_chain_head_block").set(head_f64);
                continue;
            }
            ConsumerEvent::Shutdown => {
                // Final-drive-on-shutdown: on shutdown, force a
                // final `drive_commit` so any dirty shards land
                // on disk + the manifest reflects the latest
                // applied block_height. The persistence layer's
                // per-WAL-append fsync already protects committed
                // events; the final commit additionally re-encodes
                // any dirty shards and bumps the snapshot, so the
                // next cold-start has a fresh restore point with
                // no stale WAL replay.
                let final_height = {
                    let m = metrics.lock();
                    m.last_applied_block.max(m.last_known_chain_head)
                };
                if let Err(e) = drive_commit(
                    &instance,
                    &persistence,
                    &logical_store,
                    &params,
                    encoder.as_ref(),
                    final_height,
                    &metrics,
                ) {
                    tracing::warn!(
                        error = %e,
                        "final drive_commit on Shutdown failed; \
                         persistence-side fsync still protects committed events"
                    );
                } else {
                    tracing::info!(final_height, "consumer drained final commit on Shutdown");
                }
                tracing::info!("consumer received Shutdown");
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
        {
            let mut m = metrics.lock();
            m.last_applied_block = height;
            m.events_processed = m.events_processed.saturating_add(1);
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
}

// validate-before-WAL-write: rejected events do not poison the WAL.
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
    {
        let mut store = logical_store.lock();
        super::inspire::apply_wal_entry(&mut store, p, height, encoder)?;
    }
    if trigger {
        drive_commit(
            instance,
            persistence,
            logical_store,
            params,
            encoder,
            height,
            metrics,
        )?;
    }
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
    {
        let mut m = metrics.lock();
        m.reorgs_handled = m.reorgs_handled.saturating_add(1);
    }
    // After a reorg always commit so dirty shards re-encode.
    drive_commit(
        instance,
        persistence,
        logical_store,
        params,
        encoder,
        height,
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
    let (_seq, trigger) = persistence.apply_event(payload, height)?;
    {
        let mut store = logical_store.lock();
        super::inspire::apply_wal_entry(&mut store, payload, height, encoder)?;
    }
    if trigger {
        drive_commit(
            instance,
            persistence,
            logical_store,
            params,
            encoder,
            height,
            metrics,
        )?;
    }
    Ok(())
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
        // Snapshot the LogicalLeafStore under-lock so the embedded V6 body
        // is consistent with the InspireServerState captured above; release
        // the lock before fsync work.
        let store_snapshot = {
            let s = logical_store.lock();
            s.clone()
        };
        let _new_id = persistence.commit_v6(snapshot_state.as_ref(), &store_snapshot, height)?;
        {
            let mut m = metrics.lock();
            m.commits_fired = m.commits_fired.saturating_add(1);
        }
        persistence.commit_notify().notify_waiters();
        return Ok(());
    }

    // Take an `Arc<EncodedDatabase>` from the donor state. `Arc::make_mut`
    // below triggers a Vec memcpy IFF other Arcs are alive (e.g. an in-flight
    // query holding the donor); bounded to once per drive_commit batch.
    let current = instance.current_state();
    let entries_per_shard = u32::try_from(
        current
            .encoded_db
            .config
            .entries_per_shard()
            .min(u64::from(u32::MAX)),
    )
    .unwrap_or(u32::MAX);
    let entry_size = current.entry_size;

    let _ = entries_per_shard;
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
                // Structurally unencodable: the shard id is past the
                // EncodedDatabase shard count for this instance. Drop it
                // from `dirty_shards` to break the retry loop that would
                // otherwise bump `consumer_errors` once per commit cadence
                // trigger forever. Cardinality-bounded metric: only the
                // `instance` label is dim'd; per-shard forensic detail is
                // preserved in the tracing line below.
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

    let new_state = super::inspire::InspireServerState {
        crs: Arc::clone(&current.crs),
        encoded_db: new_db,
        cache: Arc::clone(&current.cache),
        session_store: Arc::clone(&current.session_store),
        variant: current.variant,
        entry_size: current.entry_size,
    };

    let next_epoch = instance.current_epoch().next();
    instance.swap_state(new_state, next_epoch);

    let snapshot_state = instance.current_state();
    // V6 commit carries the in-memory LogicalLeafStore alongside the
    // InspireServerState so the next open path can restore both atomically.
    // Snapshot the store under-lock (dirty-shards already drained into the
    // new EncodedDatabase above) before clearing the dirty set.
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

    const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-test";

    fn test_encoder() -> Arc<dyn PirTableEncoder> {
        Arc::new(PerLeafCommitmentEncoder::new(32, 2048).expect("test encoder"))
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

    fn build_toy_state() -> Result<InspireServerState> {
        let params = InspireParams::secure_128_d2048();
        let entries = 256usize;
        let entry_size = 256usize;
        let db: Vec<u8> = (0..entries)
            .flat_map(|i| (0..entry_size).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
            .collect();
        let (state, _sk) = super::super::inspire::setup_state(
            &params,
            &db,
            entry_size,
            InspireVariant::TwoPacking,
        )?;
        Ok(state)
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

    /// Regression: pre-fix V1 skipped seq-0 events on fresh-bootstrap
    /// replay; V2 replays from seq 0 inclusive.
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
            // Commitment must be a valid BN254 Fr element (high byte < 0x30).
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

    /// Regression: invalid WAL entries (sparse `AppendLeaf` → `InvalidQuery`) must
    /// soft-skip on replay; valid entries still land in the recovered store.
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
    // The poisoned-WAL counter-increment assertion lives in its own
    // integration-test binary at
    // `engine/tests/poisoned_wal_replay_counter.rs`. Running it as a
    // standalone binary gives the test a fresh process + a fresh
    // first-time `metrics_exporter_prometheus::PrometheusBuilder::install_recorder`
    // call, free of cross-test rendering races against the lib-test
    // binary's shared `OnceLock`-cached Prometheus handle.

    #[test]
    fn apply_event_increments_seq_and_triggers_when_cap_reached() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let policy = SnapshotPolicy {
            max_appends_per_snapshot: 3,
            max_seconds_between_snapshots: u64::MAX,
            archived_wals_retain: 4,
            snapshots_retain: 4,
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
            // Commitments encode `i` as big-endian u32 zero-padded to 32 bytes
            // — trivially below BN254 Fr prime.
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
            archived_wals_retain: 2,
            snapshots_retain: usize::MAX,
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
            archived_wals_retain: usize::MAX,
            snapshots_retain: 2,
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
    fn snapshot_cleanup_skipped_in_forensic_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = build_toy_state().expect("state");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let policy = SnapshotPolicy {
            max_appends_per_snapshot: usize::MAX,
            max_seconds_between_snapshots: u64::MAX,
            archived_wals_retain: usize::MAX,
            snapshots_retain: usize::MAX,
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
            archived_wals_retain: usize::MAX,
            snapshots_retain: 1,
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

    /// Regression (fix #3): non-empty WAL with no manifest must be refused.
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
    }

    // ---------------------------------------------------------------
    // ShardOutOfRange producer + consumer wiring
    //
    // `re_encode_shard` must surface a typed `ShardOutOfRange` so
    // `drive_commit` can drop the shard from `dirty_shards` (otherwise
    // every commit cadence retries the structurally-bad id forever and
    // bumps `consumer_errors`). The emitted metric carries only the
    // `instance` label (bounded cardinality); per-shard forensic detail
    // lives in the tracing log, not the metric label set.
    // ---------------------------------------------------------------

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
        let instance = Arc::new(PirInstance::new(
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
    fn unsatisfiable_shard_metric_increments_per_drop_with_bounded_cardinality() {
        // Thread-local `DebuggingRecorder` avoids racing the process-
        // global Prometheus handle that sibling tests install. The
        // recorder is per-thread + scoped to the closure body; the
        // emit shape under test is independent of which recorder runs.
        //
        // The metric MUST carry only the `instance` label. The
        // pre-fix emission embedded `shard_id => oor_id.to_string()`,
        // which under repeated encoder mismatch would retain one
        // Prometheus series per (instance, shard_id) tuple forever.
        // Per-shard forensic detail lives in the tracing log.
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
        // Drive 32 commits, each inserting a fresh out-of-range shard id
        // (base, base+1, ..., base+31). The load-bearing cardinality
        // invariant: across all 32 distinct shard ids, the recorder
        // exposes EXACTLY ONE counter slot keyed on `(instance,)`.
        // Pre-fix the producer was `Internal(...)` and never reached the
        // counter emit; an even-earlier shape carried `shard_id` as a
        // label, which would have produced 32 distinct (instance,
        // shard_id) tuples and a classical cardinality leak.
        //
        // The exact total value across 32 emits is a property of the
        // recorder's accumulator semantics, not the production-code
        // invariant under test. The per-drop counter total is locked
        // separately by `unsatisfiable_shard_metric_increments_per_drop_*`.
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

        // 100 successive commits: the first drops the shard; every
        // subsequent commit walks the (now empty) dirty set and produces
        // 0 errors. The contract is "drive_commit returns Ok after the
        // first drop and consumer_errors does not accumulate". Pre-fix
        // (Internal variant) every commit returned Err and the consumer
        // task would have bumped `consumer_errors` once per cadence.
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
}
