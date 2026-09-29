//! Turns `tree_observed` broadcast signals into live PIR instances.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{setup_state, LogicalLeafStore, RavenInspireScheme};
use raven_railgun_engine::orchestrator::{ChainTreeRoutes, DataSourceFilter, PerInstanceHandles};
use raven_railgun_engine::persistence::{
    bootstrap_inspire_instance_with_session_limits, run_consumer_task, ConsumerEvent,
    ConsumerMetrics, InspirePersistence, Layer2VerifierContext, SnapshotPolicy,
};
use raven_railgun_engine::pir_table::{
    validate_cell_width, validate_rows_per_shard, validate_total_entries, EncoderKind,
    PirTableEncoder,
};
use raven_railgun_engine::session_pool::SessionStoreLimits;
use raven_railgun_engine::tree_fill_watcher::TreeFillWatcher;
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
use raven_railgun_persistence::StoreLayout;

use crate::auto_spawn::{
    append_spawn_record, data_dir_for_tree, instance_id_for_tree, load_spawn_log, SpawnRecord,
};

#[derive(Debug, Clone)]
enum PolicyRefusal {
    MaxInstanceCount {
        current: usize,
        cap: u32,
    },
    Cooldown {
        elapsed: std::time::Duration,
        cooldown: std::time::Duration,
    },
}

impl std::fmt::Display for PolicyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MaxInstanceCount { current, cap } => write!(
                f,
                "smart-policy max_instance_count={cap} reached \
                 ({current} chain-tree instances live); spawn refused"
            ),
            Self::Cooldown { elapsed, cooldown } => write!(
                f,
                "smart-policy cooldown not elapsed ({elapsed:?} < {cooldown:?}); spawn refused"
            ),
        }
    }
}

/// Engine-facing view of the `[auto_spawn]` TOML section.
#[derive(Debug, Clone)]
pub struct AutoSpawnRuntime {
    /// Must contain `{tree_number}`.
    pub data_dir_template: String,
    /// Only chain-tree encoders (per-leaf-bc, per-leaf-path, per-node) are valid.
    pub encoder: String,
    pub scheme_tag: String,
    pub entries: usize,
    pub entry_bytes: usize,
    pub channel_capacity: usize,
    pub verification_cadence_n: u32,
    /// When `Some(n)`: refuse spawns once the registry holds n chain-tree instances.
    pub max_instance_count: Option<u32>,
    /// When `Some(d)`: refuse spawns within `d` of the previous successful spawn.
    pub cooldown: Option<std::time::Duration>,
    /// Bounds of each spawned instance's packing-key store.
    pub session_limits: SessionStoreLimits,
}

impl AutoSpawnRuntime {
    pub fn resolve_encoder(&self, t: u32) -> anyhow::Result<EncoderKind> {
        match self.encoder.as_str() {
            "per-leaf-bc" => Ok(EncoderKind::PerLeafBc { tree_number: t }),
            "per-leaf-path" => Ok(EncoderKind::PerLeafPath { tree_number: t }),
            "per-node" => Ok(EncoderKind::PerNode { tree_number: t }),
            other => anyhow::bail!(
                "auto_spawn.encoder = {other:?} is not a chain-tree encoder \
                 (allowed: per-leaf-bc, per-leaf-path, per-node)"
            ),
        }
    }
}

/// Rows per shard: `setup` sizes every shard at `ring_dim * entry_size` bytes, so a
/// shard is `ring_dim` rows wide regardless of total cell rows.
fn rows_per_shard(params: &InspireParams) -> u32 {
    u32::try_from(params.ring_dim).unwrap_or(u32::MAX)
}

struct SpawnInputs<'a> {
    runtime: &'a AutoSpawnRuntime,
    params: &'a InspireParams,
    engine: &'a Arc<Engine<RavenInspireScheme>>,
    chain_tree_routes: &'a ChainTreeRoutes,
    registry: &'a SpawnRegistry,
    spawn_log_dir: PathBuf,
    /// `None` skips L2 verifier wiring (synthetic chain-source tests, ppoi-only deployments).
    chain_source: Option<Arc<dyn raven_railgun_indexer::ChainSource>>,
}

/// Chain-tree instances the driver knows about.
pub struct SpawnRegistry {
    inner: parking_lot::Mutex<RegistryInner>,
}

impl std::fmt::Debug for SpawnRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let g = self.inner.lock();
        f.debug_struct("SpawnRegistry")
            .field(
                "known_trees",
                &g.by_tree.keys().copied().collect::<Vec<u32>>(),
            )
            .field("auto_spawned_count", &g.auto_spawned.len())
            .finish()
    }
}

struct RegistryInner {
    by_tree: std::collections::BTreeMap<u32, RegistryEntry>,
    /// Auto-spawned only; bootstrap-seeded entries shut down via `MultiOrchestratorHandle`.
    auto_spawned: Vec<AutoSpawnedHandle>,
    last_spawn_at: Option<std::time::Instant>,
    refused_spawns: u64,
}

#[derive(Clone)]
struct RegistryEntry {
    instance: Arc<PirInstance<RavenInspireScheme>>,
    persistence: Arc<InspirePersistence>,
}

pub struct AutoSpawnedHandle {
    pub instance_id: InstanceId,
    pub consumer_sender: tokio::sync::mpsc::Sender<ConsumerEvent>,
    /// The consumer's result; an `Err` after `Shutdown` is a final commit that did not land.
    pub consumer_join: tokio::task::JoinHandle<raven_railgun_core::Result<()>>,
}

impl std::fmt::Debug for AutoSpawnedHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutoSpawnedHandle")
            .field("instance_id", &self.instance_id)
            .finish_non_exhaustive()
    }
}

impl SpawnRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: parking_lot::Mutex::new(RegistryInner {
                by_tree: std::collections::BTreeMap::new(),
                auto_spawned: Vec::new(),
                last_spawn_at: None,
                refused_spawns: 0,
            }),
        }
    }

    pub fn seed_from_bootstrap(&self, handles: &[PerInstanceHandles]) {
        let mut g = self.inner.lock();
        for h in handles {
            if let DataSourceFilter::ChainTreeNumber(t) = h.config.data_source {
                g.by_tree.insert(
                    t,
                    RegistryEntry {
                        instance: Arc::clone(&h.instance),
                        persistence: Arc::clone(&h.persistence),
                    },
                );
            }
        }
    }

    #[must_use]
    pub fn known(&self) -> Vec<u32> {
        self.inner.lock().by_tree.keys().copied().collect()
    }

    #[must_use]
    pub fn auto_spawned_len(&self) -> usize {
        self.inner.lock().auto_spawned.len()
    }

    #[must_use]
    pub fn refused_spawns(&self) -> u64 {
        self.inner.lock().refused_spawns
    }

    #[must_use]
    pub fn chain_tree_count(&self) -> usize {
        self.inner.lock().by_tree.len()
    }

    fn check_policy(
        &self,
        runtime: &AutoSpawnRuntime,
        now: std::time::Instant,
    ) -> Result<(), PolicyRefusal> {
        let mut g = self.inner.lock();
        if let Some(cap) = runtime.max_instance_count {
            let cap_usize = usize::try_from(cap).unwrap_or(usize::MAX);
            if g.by_tree.len() >= cap_usize {
                g.refused_spawns += 1;
                return Err(PolicyRefusal::MaxInstanceCount {
                    current: g.by_tree.len(),
                    cap,
                });
            }
        }
        if let Some(cooldown) = runtime.cooldown {
            if let Some(prev) = g.last_spawn_at {
                let elapsed = now.saturating_duration_since(prev);
                if elapsed < cooldown {
                    g.refused_spawns += 1;
                    return Err(PolicyRefusal::Cooldown { elapsed, cooldown });
                }
            }
        }
        Ok(())
    }

    fn stamp_spawned_at(&self, now: std::time::Instant) {
        self.inner.lock().last_spawn_at = Some(now);
    }

    pub fn drain_auto_spawned(&self) -> Vec<AutoSpawnedHandle> {
        let mut g = self.inner.lock();
        std::mem::take(&mut g.auto_spawned)
    }

    fn record_spawn(
        &self,
        tree: u32,
        instance: Arc<PirInstance<RavenInspireScheme>>,
        persistence: Arc<InspirePersistence>,
    ) {
        let mut g = self.inner.lock();
        g.by_tree.insert(
            tree,
            RegistryEntry {
                instance,
                persistence,
            },
        );
    }

    fn record_auto_spawned(&self, handle: AutoSpawnedHandle) {
        let mut g = self.inner.lock();
        g.auto_spawned.push(handle);
    }

    fn flip_predecessor_to_static(&self, new_tree: u32) {
        let g = self.inner.lock();
        if let Some(entry) = new_tree
            .checked_sub(1)
            .and_then(|prev| g.by_tree.get(&prev))
        {
            entry.instance.set_role(InstanceRole::Static);
            entry
                .persistence
                .set_snapshot_policy(SnapshotPolicy::static_default());
            // Atomic with the route append so /v1/status and routing observe it together.
            let prev_state = entry.instance.drain_state();
            if matches!(
                prev_state,
                raven_railgun_engine::DrainState::Draining
                    | raven_railgun_engine::DrainState::Drained
            ) {
                entry
                    .instance
                    .set_drain_state(raven_railgun_engine::DrainState::Drained);
                tracing::info!(
                    prev_tree = new_tree - 1,
                    drain_from = prev_state.label(),
                    "auto_spawn: predecessor was admin-drained; promoted to Drained \
                     atomically with successor route install"
                );
            }
            tracing::info!(
                prev_tree = new_tree - 1,
                "auto_spawn: flipped predecessor tree to Static"
            );
        }
    }
}

impl Default for SpawnRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Re-bootstrap every record in `spawn_log.jsonl`; only directory-level I/O errors return.
#[allow(clippy::too_many_arguments)]
pub fn replay_spawn_log(
    runtime: &AutoSpawnRuntime,
    params: &InspireParams,
    engine: &Arc<Engine<RavenInspireScheme>>,
    chain_tree_routes: &ChainTreeRoutes,
    registry: &SpawnRegistry,
    spawn_log_dir: PathBuf,
    chain_source: Option<Arc<dyn raven_railgun_indexer::ChainSource>>,
) -> anyhow::Result<Vec<u32>> {
    let records = load_spawn_log(&spawn_log_dir)
        .with_context(|| format!("read spawn log at {}", spawn_log_dir.display()))?;
    let mut restored = Vec::new();
    for record in records {
        if !record.data_dir.exists() {
            tracing::error!(
                tree_number = record.tree_number,
                data_dir = %record.data_dir.display(),
                "spawn_log replay: data_dir missing; skipping (operator must reconcile)"
            );
            continue;
        }
        let inputs = SpawnInputs {
            runtime,
            params,
            engine,
            chain_tree_routes,
            registry,
            spawn_log_dir: spawn_log_dir.clone(),
            chain_source: chain_source.clone(),
        };
        match spawn_one(&inputs, record.tree_number, /*append_log=*/ false) {
            Ok(()) => {
                restored.push(record.tree_number);
            }
            Err(e) => {
                tracing::error!(
                    tree_number = record.tree_number,
                    error = %e,
                    "spawn_log replay: bootstrap failed; skipping (operator must reconcile)"
                );
            }
        }
    }
    Ok(restored)
}

#[allow(clippy::too_many_arguments)]
pub async fn run_driver(
    runtime: AutoSpawnRuntime,
    params: InspireParams,
    engine: Arc<Engine<RavenInspireScheme>>,
    chain_tree_routes: ChainTreeRoutes,
    registry: Arc<SpawnRegistry>,
    spawn_log_dir: PathBuf,
    chain_source: Option<Arc<dyn raven_railgun_indexer::ChainSource>>,
    tree_observed: tokio::sync::broadcast::Receiver<u32>,
) {
    let live = Arc::new(arc_swap::ArcSwap::from_pointee(runtime));
    run_driver_dynamic(
        live,
        params,
        engine,
        chain_tree_routes,
        registry,
        spawn_log_dir,
        chain_source,
        tree_observed,
    )
    .await;
}

/// [`run_driver`] re-reading `live_runtime` per spawn so SIGHUP can swap templates.
#[allow(clippy::too_many_arguments)]
pub async fn run_driver_dynamic(
    live_runtime: Arc<arc_swap::ArcSwap<AutoSpawnRuntime>>,
    params: InspireParams,
    engine: Arc<Engine<RavenInspireScheme>>,
    chain_tree_routes: ChainTreeRoutes,
    registry: Arc<SpawnRegistry>,
    spawn_log_dir: PathBuf,
    chain_source: Option<Arc<dyn raven_railgun_indexer::ChainSource>>,
    mut tree_observed: tokio::sync::broadcast::Receiver<u32>,
) {
    let initial_known = registry.known();
    let highest_known = initial_known.iter().copied().max().unwrap_or(0);
    let mut watcher = TreeFillWatcher::new(highest_known);
    tracing::info!(
        highest_known,
        "auto_spawn driver started; awaiting tree boundary"
    );
    loop {
        match tree_observed.recv().await {
            Ok(t) => {
                let Some(new_tree) = watcher.observe_tree_number(t) else {
                    continue;
                };
                let runtime_snapshot = live_runtime.load_full();
                let inputs = SpawnInputs {
                    runtime: runtime_snapshot.as_ref(),
                    params: &params,
                    engine: &engine,
                    chain_tree_routes: &chain_tree_routes,
                    registry: &registry,
                    spawn_log_dir: spawn_log_dir.clone(),
                    chain_source: chain_source.clone(),
                };
                if let Err(e) = spawn_one(&inputs, new_tree, /*append_log=*/ true) {
                    tracing::error!(
                        tree_number = new_tree,
                        error = %e,
                        "auto_spawn: failed to bootstrap successor; will retry on next tree event"
                    );
                    // Roll back, else the watcher skips the retry event for this tree.
                    watcher = TreeFillWatcher::new(new_tree.saturating_sub(1));
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                tracing::warn!(
                    skipped,
                    "auto_spawn driver lagged; will re-sync on next event"
                );
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                tracing::info!("auto_spawn driver: broadcast closed; exiting");
                return;
            }
        }
    }
}

/// Pre-spawn a successor once leaf-fill crosses the threshold; `Ok(false)` when
/// `tree` is already registered.
#[allow(clippy::too_many_arguments)]
pub fn pre_spawn_for_tree(
    runtime: &AutoSpawnRuntime,
    params: &InspireParams,
    engine: &Arc<Engine<RavenInspireScheme>>,
    chain_tree_routes: &ChainTreeRoutes,
    registry: &Arc<SpawnRegistry>,
    spawn_log_dir: PathBuf,
    chain_source: Option<Arc<dyn raven_railgun_indexer::ChainSource>>,
    tree: u32,
) -> anyhow::Result<bool> {
    if registry.known().contains(&tree) {
        return Ok(false);
    }
    let inputs = SpawnInputs {
        runtime,
        params,
        engine,
        chain_tree_routes,
        registry,
        spawn_log_dir,
        chain_source,
    };
    spawn_one(&inputs, tree, /*append_log=*/ true)?;
    // spawn_one returns Ok(()) on policy refusal, so the registry is the discriminator.
    Ok(registry.known().contains(&tree))
}

/// Bootstrap a successor, wire it into engine + routes + registry, append the
/// [`SpawnRecord`], then flip the predecessor to Static. That order is crash-safe:
/// no log entry can point at a half-built layout, and a crash after the append is
/// recovered by the next successful spawn.
#[allow(clippy::too_many_lines)]
fn spawn_one(inputs: &SpawnInputs<'_>, tree: u32, append_log: bool) -> anyhow::Result<()> {
    let runtime = inputs.runtime;
    // Replay must reconstruct every pre-crash record, so it bypasses the policy gate.
    if append_log {
        let now = std::time::Instant::now();
        if let Err(refusal) = inputs.registry.check_policy(runtime, now) {
            tracing::error!(
                tree_number = tree,
                reason = %refusal,
                "auto_spawn: smart-policy refused spawn"
            );
            return Ok(());
        }
    }
    let data_dir = data_dir_for_tree(&runtime.data_dir_template, tree);
    let instance_id = InstanceId::new(instance_id_for_tree(tree));
    let encoder_kind = runtime.resolve_encoder(tree)?;
    let requested_entry_size = runtime.entry_bytes.max(32);
    let entries = runtime.entries.max(1);
    let entries_per_shard_u32 = rows_per_shard(inputs.params);

    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("create auto_spawn data_dir {}", data_dir.display()))?;
    let layout = StoreLayout::open(&data_dir)
        .with_context(|| format!("open StoreLayout at {}", data_dir.display()))?;
    let entry_size = encoder_kind.effective_record_size(requested_entry_size);
    crate::serve_production_multi::warn_on_record_size_override(
        encoder_kind,
        requested_entry_size,
        entry_size,
    );
    validate_cell_width(entry_size, inputs.params.ring_dim)
        .map_err(|e| anyhow::anyhow!("encoder cell shape rejected: {e}"))?;
    validate_rows_per_shard(entries_per_shard_u32, inputs.params.ring_dim)
        .map_err(|e| anyhow::anyhow!("auto_spawn rows per shard rejected: {e}"))?;
    // An undersized cell dirties shards past the allocated database and drive_commit
    // drops them silently, so the instance would serve factory bytes forever.
    validate_total_entries(&encoder_kind, entries)
        .map_err(|e| anyhow::anyhow!("auto_spawn total entries rejected: {e}"))?;
    let encoder: Arc<dyn PirTableEncoder> = encoder_kind
        .build(entry_size, entries_per_shard_u32)
        .map_err(|e| anyhow::anyhow!("build encoder: {e}"))?;

    let policy = SnapshotPolicy::default();
    let params = inputs.params.clone();
    let factory_entries = entries;
    let factory_entry_size = entry_size;
    let fresh_state_factory = move || {
        let initial_db: Vec<u8> = (0..factory_entries)
            .flat_map(|i| {
                (0..factory_entry_size).map(move |j| u8::try_from((i + j) % 251).unwrap_or(0))
            })
            .collect();
        let (state, _sk) = setup_state(
            &params,
            &initial_db,
            factory_entry_size,
            InspireVariant::TwoPacking,
        )
        .map_err(|e| raven_railgun_core::AdapterError::Internal(format!("setup_state: {e}")))?;
        Ok(state)
    };

    let (instance, persistence, recovered_store) = bootstrap_inspire_instance_with_session_limits(
        layout,
        runtime.scheme_tag.clone(),
        instance_id.clone(),
        InstanceRole::Live,
        policy,
        Arc::clone(&encoder),
        runtime.session_limits,
        fresh_state_factory,
    )
    .map_err(|e| anyhow::anyhow!("bootstrap_inspire_instance: {e}"))?;

    let instance_arc: Arc<PirInstance<RavenInspireScheme>> = Arc::new(instance);
    let cap = runtime.channel_capacity.max(1);
    let (sender, receiver) = tokio::sync::mpsc::channel::<ConsumerEvent>(cap);

    inputs
        .engine
        .add_live(Arc::clone(&instance_arc))
        .map_err(|e| anyhow::anyhow!("engine.add_live: {e}"))?;

    inputs.chain_tree_routes.rcu(|cur| {
        let mut next: Vec<(u32, tokio::sync::mpsc::Sender<ConsumerEvent>)> = (**cur).clone();
        next.push((tree, sender.clone()));
        next
    });

    let metrics = Arc::new(parking_lot::Mutex::new(ConsumerMetrics::default()));
    let logical_store = Arc::new(parking_lot::Mutex::new(recovered_store));
    let verifier_ctx = inputs
        .chain_source
        .as_ref()
        .map(|cs| Layer2VerifierContext {
            cadence_n: runtime.verification_cadence_n,
            tree_number: tree,
            chain_source: Some(Arc::clone(cs)),
        });

    let consumer_inputs = ConsumerSpawnInputs {
        instance: Arc::clone(&instance_arc),
        persistence: Arc::clone(&persistence),
        store: Arc::clone(&logical_store),
        metrics: Arc::clone(&metrics),
        params: inputs.params.clone(),
        encoder,
        receiver,
        verifier_ctx,
    };
    let consumer_join = spawn_consumer_task(consumer_inputs);

    // Before the role flip, else flip_predecessor_to_static races a `registry.known()` reader.
    inputs
        .registry
        .record_spawn(tree, Arc::clone(&instance_arc), Arc::clone(&persistence));
    inputs.registry.record_auto_spawned(AutoSpawnedHandle {
        instance_id: instance_id.clone(),
        consumer_sender: sender,
        consumer_join,
    });

    if append_log {
        let record = SpawnRecord {
            tree_number: tree,
            instance_id: instance_id.to_string(),
            data_dir: data_dir.clone(),
            spawned_at_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        };
        append_spawn_record(&inputs.spawn_log_dir, &record)
            .with_context(|| "append spawn record")?;
    }
    inputs.registry.flip_predecessor_to_static(tree);
    if append_log {
        // After every side effect: the cooldown measures successful-spawn intervals.
        inputs.registry.stamp_spawned_at(std::time::Instant::now());
    }
    tracing::info!(
        tree,
        instance_id = %instance_id,
        data_dir = %data_dir.display(),
        "auto_spawn: successor instance live"
    );
    Ok(())
}

struct ConsumerSpawnInputs {
    instance: Arc<PirInstance<RavenInspireScheme>>,
    persistence: Arc<InspirePersistence>,
    store: Arc<parking_lot::Mutex<LogicalLeafStore>>,
    metrics: Arc<parking_lot::Mutex<ConsumerMetrics>>,
    params: InspireParams,
    encoder: Arc<dyn PirTableEncoder>,
    receiver: tokio::sync::mpsc::Receiver<ConsumerEvent>,
    verifier_ctx: Option<Layer2VerifierContext>,
}

fn spawn_consumer_task(
    inputs: ConsumerSpawnInputs,
) -> tokio::task::JoinHandle<raven_railgun_core::Result<()>> {
    tokio::spawn(async move {
        let outcome = run_consumer_task(
            inputs.instance,
            inputs.persistence,
            inputs.store,
            inputs.metrics,
            inputs.params,
            inputs.encoder,
            inputs.receiver,
            inputs.verifier_ctx,
        )
        .await;
        if let Err(e) = &outcome {
            tracing::error!(error = %e, "auto_spawn consumer task exiting");
        }
        outcome
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn resolve_encoder_per_node_carries_tree_number() {
        let r = AutoSpawnRuntime {
            data_dir_template: String::new(),
            encoder: "per-node".to_owned(),
            scheme_tag: String::new(),
            entries: 1,
            entry_bytes: 32,
            channel_capacity: 1,
            verification_cadence_n: 0,
            max_instance_count: None,
            cooldown: None,
            session_limits: SessionStoreLimits::default(),
        };
        match r.resolve_encoder(7).unwrap() {
            EncoderKind::PerNode { tree_number } => assert_eq!(tree_number, 7),
            other => panic!("expected PerNode, got {other:?}"),
        }
    }

    #[test]
    fn rows_per_shard_equals_the_shard_config_setup_builds() {
        let params = InspireParams::secure_128_d2048();
        let entry_size = 32usize;
        let db: Vec<u8> = (0..4096usize)
            .flat_map(|i| (0..entry_size).map(move |j| u8::try_from((i + j) % 251).unwrap_or(0)))
            .collect();
        let (state, _sk) =
            setup_state(&params, &db, entry_size, InspireVariant::TwoPacking).expect("setup_state");
        assert!(
            state.encoded_db.shards.len() > 1,
            "a multi-shard cell is what makes this assertion discriminating"
        );
        assert_eq!(
            u64::from(rows_per_shard(&params)),
            state.encoded_db.config.entries_per_shard(),
            "the encoder must be told a shard's row count, not the cell's total"
        );
    }

    #[test]
    fn resolve_encoder_rejects_ppoi_label() {
        let r = AutoSpawnRuntime {
            data_dir_template: String::new(),
            encoder: "per-list-path10".to_owned(),
            scheme_tag: String::new(),
            entries: 1,
            entry_bytes: 32,
            channel_capacity: 1,
            verification_cadence_n: 0,
            max_instance_count: None,
            cooldown: None,
            session_limits: SessionStoreLimits::default(),
        };
        let err = r.resolve_encoder(0).expect_err("must reject");
        let msg = format!("{err:#}");
        assert!(msg.contains("not a chain-tree encoder"), "got: {msg}");
    }

    #[tokio::test]
    async fn registry_seed_then_flip_marks_predecessor_static() {
        use raven_inspire::params::InspireVariant;
        use raven_railgun_engine::orchestrator::InstanceConfig;
        let params = InspireParams::secure_128_d2048();
        let entry_size = 32usize;
        let db: Vec<u8> = (0..256usize)
            .flat_map(|i| (0..entry_size).map(move |j| u8::try_from((i + j) % 251).unwrap_or(0)))
            .collect();
        let (state0, _sk0) =
            setup_state(&params, &db, entry_size, InspireVariant::TwoPacking).expect("s0");
        let (state1, _sk1) =
            setup_state(&params, &db, entry_size, InspireVariant::TwoPacking).expect("s1");

        let inst0 = Arc::new(PirInstance::<RavenInspireScheme>::new(
            InstanceId::new("commit-tree-0"),
            InstanceRole::Live,
            state0,
        ));
        let inst1 = Arc::new(PirInstance::<RavenInspireScheme>::new(
            InstanceId::new("commit-tree-1"),
            InstanceRole::Live,
            state1,
        ));

        let tmp = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(tmp.path()).expect("layout");
        let encoder: Arc<dyn PirTableEncoder> = EncoderKind::PerLeafBc { tree_number: 0 }
            .build(entry_size, 2048)
            .expect("encoder");
        let opened = InspirePersistence::open(
            layout,
            "raven-inspire-twopacking-inspiring-v1",
            InstanceId::new("commit-tree-0"),
            SnapshotPolicy::default(),
            encoder,
        )
        .expect("open");
        let pers = Arc::new(opened.persistence);

        let cfg0 = InstanceConfig::commit_tree(
            "commit-tree-0",
            tmp.path().to_path_buf(),
            0,
            InstanceRole::Live,
        );
        let cfg1 = InstanceConfig::commit_tree(
            "commit-tree-1",
            tmp.path().to_path_buf(),
            1,
            InstanceRole::Live,
        );
        let (tx0, _rx0) = tokio::sync::mpsc::channel::<ConsumerEvent>(1);
        let (tx1, _rx1) = tokio::sync::mpsc::channel::<ConsumerEvent>(1);
        let h0 = PerInstanceHandles {
            config: cfg0,
            instance: Arc::clone(&inst0),
            persistence: Arc::clone(&pers),
            consumer: tokio::spawn(async { Ok(()) }),
            sender: tx0,
            metrics: Arc::new(parking_lot::Mutex::new(ConsumerMetrics::default())),
            logical_store: Arc::new(parking_lot::Mutex::new(LogicalLeafStore::new())),
        };
        let h1 = PerInstanceHandles {
            config: cfg1,
            instance: Arc::clone(&inst1),
            persistence: Arc::clone(&pers),
            consumer: tokio::spawn(async { Ok(()) }),
            sender: tx1,
            metrics: Arc::new(parking_lot::Mutex::new(ConsumerMetrics::default())),
            logical_store: Arc::new(parking_lot::Mutex::new(LogicalLeafStore::new())),
        };

        let registry = SpawnRegistry::new();
        registry.seed_from_bootstrap(&[h0, h1]);
        assert_eq!(registry.known(), vec![0, 1]);
        registry.flip_predecessor_to_static(1);
        assert_eq!(inst0.role(), InstanceRole::Static);
        assert_eq!(inst1.role(), InstanceRole::Live);
    }
}
