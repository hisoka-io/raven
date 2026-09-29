//! Single- and multi-instance bootstrap: wires indexer and mirror workers into
//! a consumer-task graph.

use crate::inspire::{InspireServerState, LogicalLeafStore, RavenInspireScheme};
use crate::persistence::{
    bootstrap_inspire_instance_with_session_limits, run_consumer_task, ConsumerEvent,
    ConsumerMetrics, InspirePersistence, Layer2VerifierContext, SnapshotPolicy,
};
use crate::session_pool::SessionStoreLimits;
use crate::{Engine, InstanceRole, PirInstance};
use raven_railgun_core::{AdapterError, InstanceId, Result};
use raven_railgun_indexer::{ChainSource, IndexerMessage};
use raven_railgun_persistence::{StoreLayout, WalEntryPayload};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Drains [`IndexerMessage`] and forwards translated [`ConsumerEvent`]s to the consumer task.
pub async fn indexer_to_consumer_bridge(
    mut rx: mpsc::Receiver<IndexerMessage>,
    tx: mpsc::Sender<ConsumerEvent>,
    chain_tree: Option<u32>,
) {
    while let Some(msg) = rx.recv().await {
        let translated = match msg {
            IndexerMessage::Event {
                event,
                block_height,
            } => {
                // The single-instance path has no route table, so the ingest tree filter
                // lives here: it keeps foreign-tree events out of the store, WAL and snapshots.
                // Row correctness does not rest on it: each chain-tree encoder also ignores
                // trees outside its pin. `None` is a per-list encoder: nothing is dropped,
                // and the store still applies every chain leaf it is sent.
                if let (Some(scope), Some(event_tree)) = (chain_tree, event.tree_number()) {
                    if event_tree != scope {
                        tracing::trace!(
                            scope,
                            event_tree,
                            "indexer_to_consumer_bridge: dropping an event for another tree"
                        );
                        continue;
                    }
                }
                ConsumerEvent::Chain(event, block_height)
            }
            IndexerMessage::Reorg { height } => ConsumerEvent::Reorg(height),
            IndexerMessage::ReorgBarrier {
                height,
                completion,
                timeout_secs: _,
            } => ConsumerEvent::ReorgBarrier { height, completion },
            IndexerMessage::Heartbeat {
                chain_head_block,
                scanned_through_block,
                ..
            } => ConsumerEvent::Heartbeat {
                chain_head: chain_head_block,
                scanned_through: scanned_through_block,
            },
        };
        if tx.send(translated).await.is_err() {
            tracing::info!("indexer_to_consumer_bridge: consumer channel closed; exiting");
            return;
        }
    }
    tracing::info!("indexer_to_consumer_bridge: indexer channel closed; exiting");
}

/// Drains PPOI-mirror payloads and forwards as [`ConsumerEvent::Ppoi`].
pub async fn mirror_to_consumer_bridge(
    mut rx: mpsc::Receiver<(WalEntryPayload, u64)>,
    tx: mpsc::Sender<ConsumerEvent>,
) {
    while let Some((payload, height)) = rx.recv().await {
        let event = ConsumerEvent::Ppoi(payload, height);
        if tx.send(event).await.is_err() {
            tracing::info!("mirror_to_consumer_bridge: consumer channel closed; exiting");
            return;
        }
    }
    tracing::info!("mirror_to_consumer_bridge: mirror channel closed; exiting");
}

/// Channel senders for the indexer and mirror bridge tasks.
#[derive(Debug, Clone)]
pub struct OrchestratorChannels {
    /// Indexer inbound sender.
    pub indexer_tx: mpsc::Sender<IndexerMessage>,
    /// Mirror inbound sender.
    pub mirror_tx: mpsc::Sender<(WalEntryPayload, u64)>,
}

/// Operator-facing handle returned by [`bootstrap_railgun_engine`].
pub struct OrchestratorHandle {
    /// PIR engine registry.
    pub engine: Arc<Engine<RavenInspireScheme>>,
    /// Live PirInstance shared by consumer task and HTTP layer.
    pub instance: Arc<PirInstance<RavenInspireScheme>>,
    /// Persistence handle.
    pub persistence: Arc<InspirePersistence>,
    /// Consumer task join handle.
    pub consumer: tokio::task::JoinHandle<Result<()>>,
    /// MPSC sender for chain events + PPOI rows + shutdown.
    pub sender: tokio::sync::mpsc::Sender<ConsumerEvent>,
    /// Live consumer metrics.
    pub metrics: Arc<parking_lot::Mutex<ConsumerMetrics>>,
    /// Shared logical leaf store.
    pub logical_store: Arc<parking_lot::Mutex<LogicalLeafStore>>,
    /// Bridge channel senders for indexer and mirror workers.
    pub channels: OrchestratorChannels,
    /// Indexer->consumer bridge task.
    pub indexer_bridge: tokio::task::JoinHandle<()>,
    /// Mirror->consumer bridge task.
    pub mirror_bridge: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for OrchestratorHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrchestratorHandle")
            .field("instances", &self.engine.instances().len())
            .field("metrics", &*self.metrics.lock())
            .finish_non_exhaustive()
    }
}

/// Configuration for [`bootstrap_railgun_engine`].
#[derive(Clone)]
pub struct OrchestratorConfig {
    /// Persistence layout root.
    pub data_dir: std::path::PathBuf,
    /// Acquire an advisory flock on `data_dir/.lock`. Recommended for production.
    pub use_flock: bool,
    /// Snapshot policy.
    pub snapshot_policy: SnapshotPolicy,
    /// Scheme tag stored in the manifest.
    pub scheme_tag: String,
    /// Operator-defined instance id.
    pub instance_id: InstanceId,
    /// Instance role.
    pub role: InstanceRole,
    /// MPSC capacity for indexer -> consumer messaging.
    pub channel_capacity: usize,
    /// Encoder kind.
    pub encoder: super::pir_table::EncoderKind,
    /// Bytes per row, matching `fresh_state_factory`'s `entry_size`.
    pub record_size: usize,
    /// Rows per shard, matching `shard_config().entries_per_shard()`.
    pub entries_per_shard: u32,
    /// Max concurrent in-flight respond ops. `None` resolves via [`default_k_for`].
    pub max_concurrent_queries: Option<usize>,
    /// Run the Layer 2 verifier every Nth commit. `0` disables. Only a chain-tree encoder is
    /// verified.
    pub verification_cadence_n: u32,
    /// Tree number whose IMT the verifier cross-checks against rootHistory.
    pub verification_tree_number: u32,
    /// Chain source for the Layer 2 verifier. `None` disables the verifier.
    pub chain_source: Option<Arc<dyn ChainSource>>,
    /// Bounds of the instance's packing-key store.
    pub session_limits: SessionStoreLimits,
}

impl OrchestratorConfig {
    /// Default config for the demo binary.
    #[must_use]
    pub fn demo(data_dir: std::path::PathBuf, instance_id: impl Into<String>) -> Self {
        Self {
            data_dir,
            use_flock: true,
            snapshot_policy: SnapshotPolicy::default(),
            scheme_tag: "raven-inspire-twopacking-inspiring-wp3-cache-session".to_owned(),
            instance_id: InstanceId::new(instance_id),
            role: InstanceRole::Live,
            channel_capacity: 1024,
            encoder: super::pir_table::EncoderKind::default(),
            record_size: 512,
            entries_per_shard: 2048,
            max_concurrent_queries: None,
            verification_cadence_n: 10,
            verification_tree_number: 0,
            chain_source: None,
            session_limits: SessionStoreLimits::default(),
        }
    }

    /// Resolve concurrency cap: explicit override or per-encoder default, minimum 1.
    #[must_use]
    pub fn resolved_max_concurrent_queries(&self) -> usize {
        self.max_concurrent_queries
            .unwrap_or_else(|| default_k_for(self.encoder))
            .max(1)
    }
}

impl std::fmt::Debug for OrchestratorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrchestratorConfig")
            .field("data_dir", &self.data_dir)
            .field("use_flock", &self.use_flock)
            .field("snapshot_policy", &self.snapshot_policy)
            .field("scheme_tag", &self.scheme_tag)
            .field("instance_id", &self.instance_id)
            .field("role", &self.role)
            .field("channel_capacity", &self.channel_capacity)
            .field("encoder", &self.encoder)
            .field("record_size", &self.record_size)
            .field("entries_per_shard", &self.entries_per_shard)
            .field("max_concurrent_queries", &self.max_concurrent_queries)
            .field("verification_cadence_n", &self.verification_cadence_n)
            .field("verification_tree_number", &self.verification_tree_number)
            .field("chain_source_attached", &self.chain_source.is_some())
            .field("session_limits", &self.session_limits)
            .finish()
    }
}

/// Per-encoder default concurrency cap (`max_concurrent_queries`).
#[must_use]
pub const fn default_k_for(encoder: super::pir_table::EncoderKind) -> usize {
    encoder.default_concurrency()
}

/// Bootstrap persistence plus the consumer task. `fresh_state_factory` runs
/// only when no manifest exists.
pub fn bootstrap_railgun_engine(
    config: OrchestratorConfig,
    params: raven_inspire::params::InspireParams,
    fresh_state_factory: impl FnOnce() -> Result<InspireServerState>,
) -> Result<OrchestratorHandle> {
    let layout = if config.use_flock {
        let (l, lock) = StoreLayout::open_with_lock(&config.data_dir)
            .map_err(|e| AdapterError::Internal(format!("StoreLayout::open_with_lock: {e}")))?;
        // deliberate: the flock must outlive this scope or the data_dir unlocks
        let _ = Box::leak(Box::new(lock));
        l
    } else {
        StoreLayout::open(&config.data_dir)
            .map_err(|e| AdapterError::Internal(format!("StoreLayout::open: {e}")))?
    };

    let encoder: Arc<dyn super::pir_table::PirTableEncoder> = config
        .encoder
        .build(config.record_size, config.entries_per_shard)?;

    let (instance, persistence, recovered_store) = bootstrap_inspire_instance_with_session_limits(
        layout,
        config.scheme_tag.clone(),
        config.instance_id.clone(),
        config.role,
        config.snapshot_policy,
        Arc::clone(&encoder),
        config.session_limits,
        fresh_state_factory,
    )?;

    let instance_arc: Arc<PirInstance<RavenInspireScheme>> = Arc::new(instance);
    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    engine.register_instance(Arc::clone(&instance_arc))?;
    let engine = Arc::new(engine);

    let cap = config.channel_capacity.max(1);
    let (sender, receiver) = mpsc::channel::<ConsumerEvent>(cap);
    let (indexer_tx, indexer_rx) = mpsc::channel::<IndexerMessage>(cap);
    let (mirror_tx, mirror_rx) = mpsc::channel::<(WalEntryPayload, u64)>(cap);

    let metrics = Arc::new(parking_lot::Mutex::new(ConsumerMetrics::default()));
    let logical_store = Arc::new(parking_lot::Mutex::new(recovered_store));

    // A list's root is published by its provider, not the chain, so no rootHistory can check it.
    let verifier_ctx = config
        .chain_source
        .as_ref()
        .filter(|_| config.encoder.chain_tree_number().is_some())
        .map(|cs| Layer2VerifierContext {
            cadence_n: config.verification_cadence_n,
            tree_number: config.verification_tree_number,
            chain_source: Some(Arc::clone(cs)),
        });

    let consumer = {
        let instance_for_task = Arc::clone(&instance_arc);
        let persistence_for_task = Arc::clone(&persistence);
        let store_for_task = Arc::clone(&logical_store);
        let metrics_for_task = Arc::clone(&metrics);
        let encoder = Arc::clone(&encoder);
        tokio::spawn(async move {
            run_consumer_task(
                instance_for_task,
                persistence_for_task,
                store_for_task,
                metrics_for_task,
                params,
                encoder,
                receiver,
                verifier_ctx,
            )
            .await
        })
    };

    let indexer_bridge = {
        let cons_tx = sender.clone();
        tokio::spawn(indexer_to_consumer_bridge(
            indexer_rx,
            cons_tx,
            config.encoder.chain_tree_number(),
        ))
    };
    let mirror_bridge = {
        let cons_tx = sender.clone();
        tokio::spawn(mirror_to_consumer_bridge(mirror_rx, cons_tx))
    };

    Ok(OrchestratorHandle {
        engine,
        instance: instance_arc,
        persistence,
        consumer,
        sender,
        metrics,
        logical_store,
        channels: OrchestratorChannels {
            indexer_tx,
            mirror_tx,
        },
        indexer_bridge,
        mirror_bridge,
    })
}

/// Routing filter: maps chain/mirror events to a specific instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DataSourceFilter {
    /// Consume chain `AppendLeaf` events for this tree number.
    ChainTreeNumber(u32),
    /// Consume one 65,536-row block of a PPOI list using local row indices.
    PpoiListBlock {
        /// 32-byte list key.
        list_key: [u8; 32],
        /// Zero-based block number.
        block: u32,
    },
}

/// Per-instance configuration for [`bootstrap_railgun_engine_multi`].
#[derive(Clone)]
pub struct InstanceConfig {
    /// Operator-assigned stable identifier.
    pub instance_id: InstanceId,
    /// Instance role.
    pub role: InstanceRole,
    /// Per-instance persistence root.
    pub data_dir: std::path::PathBuf,
    /// Encoder kind.
    pub encoder: super::pir_table::EncoderKind,
    /// Bytes per row, matching `fresh_state_factory`'s `entry_size`.
    pub record_size: usize,
    /// Rows per shard, matching `shard_config().entries_per_shard()`.
    pub entries_per_shard: u32,
    /// Routing filter for chain/mirror events. Only a chain tree is verified against the chain.
    pub data_source: DataSourceFilter,
    /// Acquire an advisory flock on `data_dir/.lock`.
    pub use_flock: bool,
    /// Snapshot policy.
    pub snapshot_policy: SnapshotPolicy,
    /// Scheme tag stored in the manifest.
    pub scheme_tag: String,
    /// MPSC capacity for indexer/mirror -> consumer messaging.
    pub channel_capacity: usize,
    /// Max concurrent in-flight respond ops. `None` resolves via [`default_k_for`].
    pub max_concurrent_queries: Option<usize>,
    /// Run the Layer 2 verifier every Nth commit. `0` disables.
    pub verification_cadence_n: u32,
    /// Chain source for the Layer 2 verifier. `None` disables the verifier.
    pub chain_source: Option<Arc<dyn ChainSource>>,
}

impl std::fmt::Debug for InstanceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstanceConfig")
            .field("instance_id", &self.instance_id)
            .field("role", &self.role)
            .field("data_dir", &self.data_dir)
            .field("encoder", &self.encoder)
            .field("record_size", &self.record_size)
            .field("entries_per_shard", &self.entries_per_shard)
            .field("data_source", &self.data_source)
            .field("use_flock", &self.use_flock)
            .field("snapshot_policy", &self.snapshot_policy)
            .field("scheme_tag", &self.scheme_tag)
            .field("channel_capacity", &self.channel_capacity)
            .field("max_concurrent_queries", &self.max_concurrent_queries)
            .field("verification_cadence_n", &self.verification_cadence_n)
            .field("chain_source_attached", &self.chain_source.is_some())
            .finish()
    }
}

impl InstanceConfig {
    /// Resolve concurrency cap: explicit override or per-encoder default, minimum 1.
    #[must_use]
    pub fn resolved_max_concurrent_queries(&self) -> usize {
        self.max_concurrent_queries
            .unwrap_or_else(|| default_k_for(self.encoder))
            .max(1)
    }

    /// Default config for a commit-tree instance.
    #[must_use]
    pub fn commit_tree(
        instance_id: impl Into<String>,
        data_dir: std::path::PathBuf,
        tree_number: u32,
        role: InstanceRole,
    ) -> Self {
        Self {
            instance_id: InstanceId::new(instance_id),
            role,
            data_dir,
            encoder: super::pir_table::EncoderKind::PerLeafPath { tree_number },
            record_size: 16 * 32,
            entries_per_shard: 2048,
            data_source: DataSourceFilter::ChainTreeNumber(tree_number),
            use_flock: true,
            snapshot_policy: match role {
                InstanceRole::Static => SnapshotPolicy::static_default(),
                _ => SnapshotPolicy::default(),
            },
            scheme_tag: "raven-inspire-twopacking-inspiring-wp3-cache-session".to_owned(),
            channel_capacity: 1024,
            max_concurrent_queries: None,
            verification_cadence_n: 10,
            chain_source: None,
        }
    }
}

/// Per-instance handles produced by [`bootstrap_railgun_engine_multi`].
pub struct PerInstanceHandles {
    /// Config that produced these handles.
    pub config: InstanceConfig,
    /// Live PIR instance.
    pub instance: Arc<PirInstance<RavenInspireScheme>>,
    /// Persistence handle.
    pub persistence: Arc<InspirePersistence>,
    /// Consumer task join handle.
    pub consumer: tokio::task::JoinHandle<Result<()>>,
    /// MPSC sender into this instance's consumer task.
    pub sender: tokio::sync::mpsc::Sender<ConsumerEvent>,
    /// Live consumer metrics.
    pub metrics: Arc<parking_lot::Mutex<ConsumerMetrics>>,
    /// Logical leaf store.
    pub logical_store: Arc<parking_lot::Mutex<LogicalLeafStore>>,
}

impl std::fmt::Debug for PerInstanceHandles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerInstanceHandles")
            .field("instance_id", &self.config.instance_id)
            .field("role", &self.config.role)
            .field("data_source", &self.config.data_source)
            .field("encoder_label", &self.config.encoder.label())
            .finish_non_exhaustive()
    }
}

/// Chain-tree routing table, swapped via `ArcSwap::rcu` so the router picks up
/// new routes lock-free.
pub type ChainTreeRoutes = Arc<arc_swap::ArcSwap<Vec<(u32, mpsc::Sender<ConsumerEvent>)>>>;

/// Per-block PPOI routing table, fixed at boot: a block is declared in config and served
/// after a restart.
pub type PpoiListRoutes = Arc<[(DataSourceFilter, mpsc::Sender<ConsumerEvent>)]>;

/// Operator-facing handle returned by [`bootstrap_railgun_engine_multi`].
pub struct MultiOrchestratorHandle {
    /// One handle per running instance.
    pub instances: Vec<PerInstanceHandles>,
    /// Inbound channels for indexer/mirror workers.
    pub channels: OrchestratorChannels,
    /// Router task: fans events by `data_source` to per-instance consumers.
    pub router: tokio::task::JoinHandle<()>,
    /// Live chain-tree routing table.
    pub chain_tree_routes: ChainTreeRoutes,
    /// PPOI routing table.
    pub ppoi_list_routes: PpoiListRoutes,
    /// Lossy broadcast of every chain `tree_number` seen by the router.
    pub tree_observed: tokio::sync::broadcast::Sender<u32>,
}

impl std::fmt::Debug for MultiOrchestratorHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiOrchestratorHandle")
            .field("instance_count", &self.instances.len())
            .finish_non_exhaustive()
    }
}

/// Bootstrap several instances behind one shared router, each with default session limits.
///
/// # Errors
///
/// [`AdapterError::InvalidQuery`] if `configs` is empty or two share a
/// `data_source`.
pub fn bootstrap_railgun_engine_multi<F>(
    configs: Vec<InstanceConfig>,
    params: raven_inspire::params::InspireParams,
    mut fresh_state_factory: F,
) -> Result<MultiOrchestratorHandle>
where
    F: FnMut(&InstanceConfig) -> Result<InspireServerState>,
{
    bootstrap_railgun_engine_multi_with_session_limits(
        configs,
        params,
        SessionStoreLimits::default(),
        |cfg, _crs| fresh_state_factory(cfg),
    )
}

/// An instance whose data dir is open and whose state is recovered or still to be built.
struct OpenedSlot {
    cfg: InstanceConfig,
    encoder: Arc<dyn super::pir_table::PirTableEncoder>,
    session_store: Arc<crate::session_pool::BoundedSessionStore>,
    persistence: Arc<InspirePersistence>,
    state: Option<InspireServerState>,
    store: LogicalLeafStore,
}

/// The CRS each list is served under. Packing keys are a function of the CRS's `w_seed` and the
/// cell's packing width, and a client derives one context per list and width, so a block served
/// under another seed returns bytes unrelated to its rows at HTTP 200.
#[derive(Default)]
struct ServedCrs {
    by_list: Vec<ListCrs>,
    any: Vec<Arc<raven_inspire::ServerCrs>>,
}

struct ListCrs {
    list_key: [u8; 32],
    crs: Arc<raven_inspire::ServerCrs>,
}

/// One list and width's recovered blocks, grouped by the seed each was built under.
struct RecoveredList {
    list_key: [u8; 32],
    columns: usize,
    seeds: Vec<(Arc<raven_inspire::ServerCrs>, Vec<InstanceId>)>,
}

impl ServedCrs {
    fn list_of(source: DataSourceFilter) -> Option<[u8; 32]> {
        match source {
            DataSourceFilter::PpoiListBlock { list_key, .. } => Some(list_key),
            DataSourceFilter::ChainTreeNumber(_) => None,
        }
    }

    fn list_crs(&self, list_key: [u8; 32], columns: usize) -> Option<&ListCrs> {
        self.by_list
            .iter()
            .find(|list| list.list_key == list_key && list.crs.inspiring_num_columns == columns)
    }

    /// Every block of a list and width recovered under one seed, or a refusal naming, per list,
    /// the blocks outside the seed most of its blocks hold: those are the ones to rebuild.
    fn from_recovered(slots: &[OpenedSlot]) -> Result<Self> {
        let mut served = Self::default();
        let mut lists: Vec<RecoveredList> = Vec::new();
        for slot in slots {
            let Some(state) = slot.state.as_ref() else {
                continue;
            };
            served.remember(&state.crs);
            let Some(list_key) = Self::list_of(slot.cfg.data_source) else {
                continue;
            };
            let columns = state.crs.inspiring_num_columns;
            let at = lists
                .iter()
                .position(|list| list.list_key == list_key && list.columns == columns)
                .unwrap_or_else(|| {
                    lists.push(RecoveredList {
                        list_key,
                        columns,
                        seeds: Vec::new(),
                    });
                    lists.len() - 1
                });
            let Some(list) = lists.get_mut(at) else {
                continue;
            };
            let block = slot.cfg.instance_id.clone();
            match list
                .seeds
                .iter_mut()
                .find(|(crs, _)| crs.inspiring_w_seed == state.crs.inspiring_w_seed)
            {
                Some((_, blocks)) => blocks.push(block),
                None => list.seeds.push((Arc::clone(&state.crs), vec![block])),
            }
        }
        let mut refusals: Vec<String> = Vec::new();
        for list in lists {
            // Ties go to the seed seen first, so the choice follows config order.
            let kept = list
                .seeds
                .iter()
                .enumerate()
                .max_by_key(|(at, (_, blocks))| (blocks.len(), std::cmp::Reverse(*at)))
                .map(|(at, _)| at);
            let Some((crs, _)) = kept.and_then(|at| list.seeds.get(at)) else {
                continue;
            };
            if list.seeds.len() > 1 {
                let groups: Vec<String> = list
                    .seeds
                    .iter()
                    .map(|(other, blocks)| {
                        let names: Vec<&str> = blocks.iter().map(InstanceId::as_str).collect();
                        format!(
                            "w_seed {} held by {}{}",
                            seed_prefix(&other.inspiring_w_seed),
                            names.join(", "),
                            if Arc::ptr_eq(other, crs) {
                                " (kept)"
                            } else {
                                ""
                            }
                        )
                    })
                    .collect();
                refusals.push(format!(
                    "list {}: {}",
                    hex_lower_32(&list.list_key),
                    groups.join("; ")
                ));
            }
            served.by_list.push(ListCrs {
                list_key: list.list_key,
                crs: Arc::clone(crs),
            });
        }
        if refusals.is_empty() {
            return Ok(served);
        }
        Err(AdapterError::Internal(format!(
            "recovered blocks of one list are served under different CRS packing seeds ({}). A \
             client derives one context per list, so a block under another seed returns \
             unrelated bytes. Operator: stop, delete the data_dir of each block not marked \
             kept, and restart; those blocks rebuild under the kept seed and re-sync from \
             upstream.",
            refusals.join(" | "),
        )))
    }

    /// The CRS a fresh instance of `cfg` at `columns` packing columns is served under, and
    /// whether its list set it: its list's, else any this boot holds at that width.
    fn for_fresh(
        &self,
        cfg: &InstanceConfig,
        columns: usize,
    ) -> Option<(Arc<raven_inspire::ServerCrs>, bool)> {
        let list = Self::list_of(cfg.data_source)
            .and_then(|key| self.list_crs(key, columns))
            .map(|list| (Arc::clone(&list.crs), true));
        list.or_else(|| {
            self.any
                .iter()
                .find(|crs| crs.inspiring_num_columns == columns)
                .map(|crs| (Arc::clone(crs), false))
        })
    }

    fn record(&mut self, cfg: &InstanceConfig, crs: &Arc<raven_inspire::ServerCrs>) {
        if let Some(list_key) = Self::list_of(cfg.data_source) {
            if self.list_crs(list_key, crs.inspiring_num_columns).is_none() {
                self.by_list.push(ListCrs {
                    list_key,
                    crs: Arc::clone(crs),
                });
            }
        }
        self.remember(crs);
    }

    fn remember(&mut self, crs: &Arc<raven_inspire::ServerCrs>) {
        if !self
            .any
            .iter()
            .any(|held| held.inspiring_num_columns == crs.inspiring_num_columns)
        {
            self.any.push(Arc::clone(crs));
        }
    }
}

fn seed_prefix(seed: &[u8; 32]) -> String {
    hex_lower_32(seed).chars().take(16).collect()
}

/// A recovered data dir is booted only by the binary and the list it was built for.
fn require_recovered_cell_matches(
    cfg: &InstanceConfig,
    state: &InspireServerState,
    store: &LogicalLeafStore,
    params: &raven_inspire::params::InspireParams,
) -> Result<()> {
    if state.crs.params != *params {
        return Err(AdapterError::Internal(format!(
            "instance {id} at {dir} was built under InsPIRe parameters {stored:?}, but this \
             binary serves {params:?}. Its encoded rows and every client context derived from \
             its CRS belong to the other parameters, so it is refused rather than served. \
             Operator: boot it with the binary that built it, or delete the data_dir and \
             re-sync.",
            id = cfg.instance_id,
            dir = cfg.data_dir.display(),
            stored = state.crs.params,
        )));
    }
    if let DataSourceFilter::PpoiListBlock { list_key, .. } = cfg.data_source {
        let configured_held = usize::from(store.ppoi_imt(&list_key).is_some());
        if store.ppoi_list_count() > configured_held {
            return Err(AdapterError::Internal(format!(
                "instance {id} at {dir} holds rows of a list other than the configured list \
                 {list}. Serving it would publish the other list's rows as this one's. \
                 Operator: point the instance at the list its data_dir was built for, or delete \
                 the data_dir and re-sync.",
                id = cfg.instance_id,
                dir = cfg.data_dir.display(),
                list = hex_lower_32(&list_key),
            )));
        }
    }
    Ok(())
}

/// Data dirs opened at once. Each open holds its snapshot's decompressed body beside the state it
/// decodes, so this bounds the transient memory a boot adds to the served states.
const PARALLEL_DATA_DIR_OPENS: usize = 4;

/// Open every data dir, recovering what a snapshot holds, several at a time. Results keep the
/// order of `configs`, and the first failure in that order is the one returned.
fn open_every_data_dir(
    configs: Vec<InstanceConfig>,
    params: &raven_inspire::params::InspireParams,
    session_limits: SessionStoreLimits,
) -> Result<Vec<OpenedSlot>> {
    let pending: Vec<parking_lot::Mutex<Option<InstanceConfig>>> = configs
        .into_iter()
        .map(|cfg| parking_lot::Mutex::new(Some(cfg)))
        .collect();
    let opened: Vec<parking_lot::Mutex<Option<Result<OpenedSlot>>>> = pending
        .iter()
        .map(|_| parking_lot::Mutex::new(None))
        .collect();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let workers = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(PARALLEL_DATA_DIR_OPENS)
        .min(pending.len())
        .max(1);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let at = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let (Some(slot), Some(out)) = (pending.get(at), opened.get(at)) else {
                    break;
                };
                if let Some(cfg) = slot.lock().take() {
                    *out.lock() = Some(open_data_dir(cfg, params, session_limits));
                }
            });
        }
    });
    opened
        .into_iter()
        .map(|out| {
            out.into_inner().unwrap_or_else(|| {
                Err(AdapterError::Internal(
                    "a data dir open ended without a result".to_owned(),
                ))
            })
        })
        .collect()
}

fn open_data_dir(
    cfg: InstanceConfig,
    params: &raven_inspire::params::InspireParams,
    session_limits: SessionStoreLimits,
) -> Result<OpenedSlot> {
    let layout = if cfg.use_flock {
        let (l, lock) = StoreLayout::open_with_lock(&cfg.data_dir)
            .map_err(|e| AdapterError::Internal(format!("StoreLayout::open_with_lock: {e}")))?;
        let _ = Box::leak(Box::new(lock));
        l
    } else {
        StoreLayout::open(&cfg.data_dir)
            .map_err(|e| AdapterError::Internal(format!("StoreLayout::open: {e}")))?
    };

    let encoder: Arc<dyn super::pir_table::PirTableEncoder> =
        cfg.encoder.build(cfg.record_size, cfg.entries_per_shard)?;

    let session_store = Arc::new(crate::session_pool::BoundedSessionStore::open_with_limits(
        layout.root(),
        session_limits,
    )?);
    let opened = InspirePersistence::open(
        layout,
        cfg.scheme_tag.clone(),
        cfg.instance_id.clone(),
        cfg.snapshot_policy,
        Arc::clone(&encoder),
    )?;
    if let Some(state) = opened.recovered_state.as_ref() {
        require_recovered_cell_matches(&cfg, state, &opened.recovered_logical_store, params)?;
    }
    Ok(OpenedSlot {
        cfg,
        encoder,
        session_store,
        persistence: Arc::new(opened.persistence),
        state: opened.recovered_state,
        store: opened.recovered_logical_store,
    })
}

/// Build and commit a state for every instance no snapshot recovered, each under the CRS its
/// list is served under.
fn build_fresh_states<F>(slots: &mut [OpenedSlot], fresh_state_factory: &mut F) -> Result<()>
where
    F: FnMut(&InstanceConfig, Option<&Arc<raven_inspire::ServerCrs>>) -> Result<InspireServerState>,
{
    let mut served = ServedCrs::from_recovered(slots)?;
    for slot in slots.iter_mut().filter(|slot| slot.state.is_none()) {
        let columns = super::pir_table::pir_cell_columns(slot.encoder.record_size());
        let donor = served.for_fresh(&slot.cfg, columns);
        let built = fresh_state_factory(&slot.cfg, donor.as_ref().map(|(crs, _)| crs))?;
        let state = match donor {
            Some((crs, _))
                if crs.params == built.crs.params
                    && crs.inspiring_num_columns == built.crs.inspiring_num_columns =>
            {
                crate::inspire::serve_under_crs(built, &crs)?
            }
            Some((crs, true)) => {
                return Err(AdapterError::Internal(format!(
                    "fresh instance {id} was built for a cell of {built_columns} packing columns \
                     under {built_params:?}, but its list is served at {columns} columns under \
                     {params:?}; one client context cannot decode both",
                    id = slot.cfg.instance_id,
                    built_columns = built.crs.inspiring_num_columns,
                    built_params = built.crs.params,
                    columns = crs.inspiring_num_columns,
                    params = crs.params,
                )));
            }
            _ => built,
        };
        served.record(&slot.cfg, &state.crs);
        // V6 so the store travels with the snapshot from the first manifest write.
        slot.persistence
            .commit_v6(&state, &LogicalLeafStore::default(), 0)?;
        slot.persistence.commit_notify().notify_waiters();
        slot.state = Some(state);
    }
    Ok(())
}

/// Serve an opened instance and spawn its consumer.
fn start_instance(
    slot: OpenedSlot,
    params: &raven_inspire::params::InspireParams,
) -> Result<PerInstanceHandles> {
    let OpenedSlot {
        cfg,
        encoder,
        session_store,
        persistence,
        state,
        store: recovered_store,
    } = slot;
    let mut state = state.ok_or_else(|| {
        AdapterError::Internal(format!(
            "instance {} has neither a recovered nor a fresh state",
            cfg.instance_id
        ))
    })?;
    state.session_store = session_store;
    let instance = PirInstance::new(cfg.instance_id.clone(), cfg.role, state);
    let instance_arc: Arc<PirInstance<RavenInspireScheme>> = Arc::new(instance);

    let cap = cfg.channel_capacity.max(1);
    let (sender, receiver) = mpsc::channel::<ConsumerEvent>(cap);
    let metrics = Arc::new(parking_lot::Mutex::new(ConsumerMetrics::default()));
    let logical_store = Arc::new(parking_lot::Mutex::new(recovered_store));
    let verifier_ctx = match (&cfg.chain_source, cfg.data_source) {
        (Some(cs), DataSourceFilter::ChainTreeNumber(tn)) => Some(Layer2VerifierContext {
            cadence_n: cfg.verification_cadence_n,
            tree_number: tn,
            chain_source: Some(Arc::clone(cs)),
        }),
        _ => None,
    };
    let consumer = {
        let instance_for_task = Arc::clone(&instance_arc);
        let persistence_for_task = Arc::clone(&persistence);
        let store_for_task = Arc::clone(&logical_store);
        let metrics_for_task = Arc::clone(&metrics);
        let params = params.clone();
        tokio::spawn(async move {
            run_consumer_task(
                instance_for_task,
                persistence_for_task,
                store_for_task,
                metrics_for_task,
                params,
                encoder,
                receiver,
                verifier_ctx,
            )
            .await
        })
    };

    Ok(PerInstanceHandles {
        config: cfg,
        instance: instance_arc,
        persistence,
        consumer,
        sender,
        metrics,
        logical_store,
    })
}

/// [`bootstrap_railgun_engine_multi`] with every instance's packing-key store opened at
/// `session_limits`.
///
/// Every data dir is opened before any fresh state is built, so a fresh instance is built only
/// when no snapshot recovers it, and under the CRS its list's recovered blocks are served under
/// (else under the first CRS the boot holds). `fresh_state_factory` receives that CRS; a state
/// built under another is moved onto it.
///
/// # Errors
///
/// As [`bootstrap_railgun_engine_multi`], plus [`AdapterError::Internal`] when
/// `session_limits` admits no session, when a recovered data dir was built under other
/// parameters or for another list, or when the recovered blocks of one list disagree on their
/// CRS packing seed.
pub fn bootstrap_railgun_engine_multi_with_session_limits<F>(
    configs: Vec<InstanceConfig>,
    params: raven_inspire::params::InspireParams,
    session_limits: SessionStoreLimits,
    mut fresh_state_factory: F,
) -> Result<MultiOrchestratorHandle>
where
    F: FnMut(&InstanceConfig, Option<&Arc<raven_inspire::ServerCrs>>) -> Result<InspireServerState>,
{
    if configs.is_empty() {
        return Err(AdapterError::InvalidQuery(
            "bootstrap_railgun_engine_multi requires at least one InstanceConfig".to_owned(),
        ));
    }
    let mut seen: std::collections::HashSet<(DataSourceFilter, &'static str)> =
        std::collections::HashSet::with_capacity(configs.len());
    for cfg in &configs {
        if !seen.insert((cfg.data_source, cfg.encoder.label())) {
            return Err(AdapterError::InvalidQuery(format!(
                "duplicate (data_source, encoder) across InstanceConfigs: data_source={:?} encoder={}",
                cfg.data_source,
                cfg.encoder.label()
            )));
        }
    }

    let router_capacity = configs
        .iter()
        .map(|c| c.channel_capacity.max(1))
        .max()
        .unwrap_or(1024);

    let mut slots = open_every_data_dir(configs, &params, session_limits)?;
    build_fresh_states(&mut slots, &mut fresh_state_factory)?;
    let per_instance = slots
        .into_iter()
        .map(|slot| start_instance(slot, &params))
        .collect::<Result<Vec<PerInstanceHandles>>>()?;

    let (indexer_tx, indexer_rx) = mpsc::channel::<IndexerMessage>(router_capacity);
    let (mirror_tx, mirror_rx) = mpsc::channel::<(WalEntryPayload, u64)>(router_capacity);

    let routes: Vec<(DataSourceFilter, mpsc::Sender<ConsumerEvent>)> = per_instance
        .iter()
        .map(|p| (p.config.data_source, p.sender.clone()))
        .collect();
    let initial_chain_tree_routes: Vec<(u32, mpsc::Sender<ConsumerEvent>)> = routes
        .iter()
        .filter_map(|(ds, tx)| match ds {
            DataSourceFilter::ChainTreeNumber(t) => Some((*t, tx.clone())),
            DataSourceFilter::PpoiListBlock { .. } => None,
        })
        .collect();
    let ppoi_routes: Vec<(DataSourceFilter, mpsc::Sender<ConsumerEvent>)> = routes
        .iter()
        .filter_map(|(ds, tx)| match ds {
            DataSourceFilter::PpoiListBlock { .. } => Some((*ds, tx.clone())),
            DataSourceFilter::ChainTreeNumber(_) => None,
        })
        .collect();

    let chain_tree_routes = Arc::new(arc_swap::ArcSwap::from_pointee(initial_chain_tree_routes));
    let ppoi_list_routes: PpoiListRoutes = ppoi_routes.into();
    // Lagged receivers re-sync on the next event, so a small capacity suffices.
    let (tree_observed_tx, _) = tokio::sync::broadcast::channel::<u32>(64);

    let router = tokio::spawn(multi_instance_router(
        indexer_rx,
        mirror_rx,
        Arc::clone(&chain_tree_routes),
        Arc::clone(&ppoi_list_routes),
        tree_observed_tx.clone(),
    ));

    Ok(MultiOrchestratorHandle {
        instances: per_instance,
        channels: OrchestratorChannels {
            indexer_tx,
            mirror_tx,
        },
        router,
        chain_tree_routes,
        ppoi_list_routes,
        tree_observed: tree_observed_tx,
    })
}

pub(crate) fn hex_lower_32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn count_router_drop(reason: &'static str) {
    metrics::counter!(ROUTER_DROPPED, "reason" => reason).increment(1);
}

/// Leaves per PPOI block, the width `DataSourceFilter::PpoiListBlock` partitions on.
/// One block's leaf span. **The routing boundary and the readiness-target name must both be
/// this symbol.** They were not: the name used the const while `payload_for_ppoi_route` carried
/// bare `65_536` literals, so respelling the const moved which target an operator alert matches
/// without moving which block a leaf routes to — two copies of one decision, the same shape as
/// the separator drift below it.
pub const LEAVES_PER_PPOI_BLOCK: u32 = 65_536;

// A block must fit in ONE IMT. `checked_imt_append` refuses at `TREE_MAX_ITEMS`, so a wider
// block would route leaves that the per-list tree then rejects one at a time -- a block that
// can never complete, discovered leaf by leaf in production rather than here. Nothing asserted
// this; the two constants live in different files and agreed by coincidence.
const _: () = assert!(
    LEAVES_PER_PPOI_BLOCK as usize <= crate::imt::TREE_MAX_ITEMS,
    "LEAVES_PER_PPOI_BLOCK exceeds the per-list IMT capacity"
);

/// Split a list-wide PPOI event index into `(block, index within that block)`.
///
/// A PPOI list is a forest of depth-16 trees, not one tree: upstream derives the tree from
/// `floor(eventIndex / 65_536)` and publishes, per event, the root of the tree that event
/// landed in. Anything rebuilding a list from global indices has to make the same split or it
/// runs a single tree into the capacity wall at 65,536, so the split lives here once rather
/// than as a second copy of `/` and `%` beside every caller.
///
/// ```
/// # use raven_railgun_engine::orchestrator::{split_ppoi_index, LEAVES_PER_PPOI_BLOCK};
/// assert_eq!(split_ppoi_index(LEAVES_PER_PPOI_BLOCK - 1), (0, LEAVES_PER_PPOI_BLOCK - 1));
/// assert_eq!(split_ppoi_index(LEAVES_PER_PPOI_BLOCK), (1, 0));
/// ```
#[must_use]
pub const fn split_ppoi_index(list_index: u32) -> (u32, u32) {
    (
        list_index / LEAVES_PER_PPOI_BLOCK,
        list_index % LEAVES_PER_PPOI_BLOCK,
    )
}

/// The list-wide index of `local` inside `block`, the inverse of [`split_ppoi_index`].
///
/// `None` past `u32::MAX`, which a depth-16 forest reaches at block 65,536.
///
/// ```
/// # use raven_railgun_engine::orchestrator::{global_ppoi_index, LEAVES_PER_PPOI_BLOCK};
/// assert_eq!(global_ppoi_index(1, 0), Some(LEAVES_PER_PPOI_BLOCK));
/// assert_eq!(global_ppoi_index(u32::MAX, 0), None);
/// ```
#[must_use]
pub const fn global_ppoi_index(block: u32, local: u32) -> Option<u32> {
    match block.checked_mul(LEAVES_PER_PPOI_BLOCK) {
        Some(base) => base.checked_add(local),
        None => None,
    }
}

/// Routing targets that are **currently** not receiving events.
///
/// Self-healing: a delivery clears the target, a miss or a dead consumer marks it. That
/// is the same two-way choice `ConsumerMetrics` documents for `consecutive_event_errors`
/// ("any applied event clears it") as against `unapplied_leaves` ("a contiguity gap
/// outlives unrelated successes"). This registry is the first kind, because chain-tree
/// routes are installed at runtime: an event of a new tree can arrive before the
/// auto-spawned instance for it exists and miss, and the first delivery after the spawn
/// clears the mark. PPOI routes are fixed at boot, so a PPOI mark stays until a restart with a
/// config that serves the target.
///
/// **Deliberately not disk-backed, unlike `LAYER2_DIVERGENT`.** The mark asserts a live
/// property — "no route accepts this target right now" — which the next event for that
/// target re-establishes or clears on its own. A restart therefore does not need to carry
/// it. Note what this does NOT claim: events already dropped stay dropped, because the
/// mirror cursor advanced past them. Durable accounting for that loss is a different
/// problem and this registry is not it.
static ROUTER_UNROUTED_TARGETS: parking_lot::Mutex<std::collections::BTreeSet<String>> =
    parking_lot::Mutex::new(std::collections::BTreeSet::new());

/// Routing targets not currently receiving events, sorted. Readiness probes MUST fail
/// closed while this is non-empty: every entry means some instance is missing events it
/// should be getting, right now.
///
/// Granularity is the point. `list:<hex>:block:<n>` is one unprovisioned block of a list
/// that is otherwise served; `list:<hex>` is a list no route mentions at all, which is
/// the shape of the tree-4 outage. An operator alert can tell them apart.
///
/// ```
/// # use raven_railgun_engine::orchestrator::router_unrouted_targets;
/// assert!(
///     router_unrouted_targets().is_empty(),
///     "no routing has run in this process, so nothing can be unrouted"
/// );
/// ```
#[must_use]
pub fn router_unrouted_targets() -> Vec<String> {
    ROUTER_UNROUTED_TARGETS.lock().iter().cloned().collect()
}

/// Mark a target as not currently receiving events.
pub fn mark_router_unrouted_target(target: &str) {
    ROUTER_UNROUTED_TARGETS.lock().insert(target.to_owned());
}

/// Clear a target: an event reached every route bound to it.
pub fn clear_router_unrouted_target(target: &str) {
    ROUTER_UNROUTED_TARGETS.lock().remove(target);
}

/// A route miss: count it and mark the target unrouted.
fn record_no_route(target: String) {
    count_router_drop("no_route");
    ROUTER_UNROUTED_TARGETS.lock().insert(target);
}

/// A consumer whose channel is gone. The route exists, so this is not `no_route` — but
/// the target is not receiving either, which is the half the counter description calls
/// out and nothing surfaced.
fn record_consumer_closed(target: String) {
    count_router_drop("consumer_channel_closed");
    ROUTER_UNROUTED_TARGETS.lock().insert(target);
}

/// The list key a routing filter is bound to, if any.
fn filter_list_key(filter: &DataSourceFilter) -> Option<[u8; 32]> {
    match filter {
        DataSourceFilter::PpoiListBlock { list_key, .. } => Some(*list_key),
        DataSourceFilter::ChainTreeNumber(_) => None,
    }
}

/// Name the target a mirror payload belongs to, at the granularity that distinguishes an
/// unprovisioned block from a wholly unserved list.
fn ppoi_target_name(
    payload: &WalEntryPayload,
    lk: &[u8; 32],
    routes: &[(DataSourceFilter, mpsc::Sender<ConsumerEvent>)],
) -> String {
    let hex = hex_lower_32(lk);
    let list_is_routed = routes
        .iter()
        .any(|(filter, _)| filter_list_key(filter).is_some_and(|k| k == *lk));
    match payload {
        WalEntryPayload::PpoiListLeafAdded { list_index, .. } if list_is_routed => {
            format!("list:{hex}:block:{}", split_ppoi_index(*list_index).0)
        }
        _ => format!("list:{hex}"),
    }
}

/// Router drops are silent by construction: an event for a tree no instance routes,
/// or a consumer whose channel has closed, leaves no trace a test or an operator can
/// see. That is the shape of the tree-4 outage. Counted here so it is assertable.
const ROUTER_DROPPED: &str = "raven_railgun_router_dropped_events_total";

fn ensure_router_metrics_described() {
    metrics::describe_counter!(
        ROUTER_DROPPED,
        metrics::Unit::Count,
        "Count of indexer/mirror events the multi-instance router discarded. \
         `reason=no_route`: no instance is bound to the event's tree number or \
         list key, so the event is lost and that tree falls behind the chain. \
         `reason=consumer_channel_closed`: the bound consumer task is gone. \
         Both must stay at 0 in a healthy deployment; non-zero means events \
         are being dropped on the floor."
    );
    metrics::counter!(ROUTER_DROPPED, "reason" => "no_route").increment(0);
    metrics::counter!(ROUTER_DROPPED, "reason" => "consumer_channel_closed").increment(0);
}

/// Fan indexer and mirror events to per-instance consumers by `data_source`.
/// Returns once both inbound channels close.
async fn multi_instance_router(
    mut indexer_rx: mpsc::Receiver<IndexerMessage>,
    mut mirror_rx: mpsc::Receiver<(WalEntryPayload, u64)>,
    chain_tree_routes: ChainTreeRoutes,
    ppoi_list_routes: PpoiListRoutes,
    tree_observed: tokio::sync::broadcast::Sender<u32>,
) {
    ensure_router_metrics_described();
    let mut indexer_open = true;
    let mut mirror_open = true;
    loop {
        tokio::select! {
            msg = indexer_rx.recv(), if indexer_open => {
                if let Some(m) = msg {
                    forward_indexer_message(m, &chain_tree_routes, &tree_observed).await;
                } else {
                    indexer_open = false;
                    tracing::info!("multi_instance_router: indexer channel closed");
                }
            }
            msg = mirror_rx.recv(), if mirror_open => {
                if let Some((payload, height)) = msg {
                    forward_mirror_payload(payload, height, &ppoi_list_routes).await;
                } else {
                    mirror_open = false;
                    tracing::info!("multi_instance_router: mirror channel closed");
                }
            }
            else => {
                tracing::info!("multi_instance_router: both channels closed; exiting");
                return;
            }
        }
    }
}

async fn forward_indexer_message(
    msg: IndexerMessage,
    chain_tree_routes: &arc_swap::ArcSwap<Vec<(u32, mpsc::Sender<ConsumerEvent>)>>,
    tree_observed: &tokio::sync::broadcast::Sender<u32>,
) {
    match msg {
        IndexerMessage::Event {
            event,
            block_height,
        } => {
            let target_tree = match &event {
                raven_railgun_core::RailgunEvent::Shield { tree_number, .. }
                | raven_railgun_core::RailgunEvent::Transact { tree_number, .. }
                | raven_railgun_core::RailgunEvent::Nullified { tree_number, .. } => {
                    Some(*tree_number)
                }
                raven_railgun_core::RailgunEvent::Unshield { .. } => None,
            };
            if let Some(t) = target_tree {
                let _ = tree_observed.send(t);
                let routes = chain_tree_routes.load();
                // Fan out to every sender bound to `t`: encoders can share a tree
                // number, so `.find()` would drop events past the first match.
                let matched: Vec<mpsc::Sender<ConsumerEvent>> = routes
                    .iter()
                    .filter(|(tn, _)| *tn == t)
                    .map(|(_, s)| s.clone())
                    .collect();
                // Last recipient takes ownership, so the common single-route case never clones.
                let target = format!("tree:{t}");
                if let Some((last, rest)) = matched.split_last() {
                    let mut delivered_to_all = true;
                    for tx in rest {
                        if tx
                            .send(ConsumerEvent::Chain(event.clone(), block_height))
                            .await
                            .is_err()
                        {
                            record_consumer_closed(target.clone());
                            delivered_to_all = false;
                            tracing::warn!(
                                tree_number = t,
                                block_height,
                                "consumer channel closed; chain event dropped"
                            );
                        }
                    }
                    if last
                        .send(ConsumerEvent::Chain(event, block_height))
                        .await
                        .is_err()
                    {
                        record_consumer_closed(target.clone());
                        delivered_to_all = false;
                        tracing::warn!(
                            tree_number = t,
                            block_height,
                            "consumer channel closed; chain event dropped"
                        );
                    }
                    // Self-healing: reaching every bound route is what clears the mark.
                    if delivered_to_all {
                        clear_router_unrouted_target(&target);
                    }
                } else {
                    record_no_route(target);
                    tracing::warn!(
                        tree_number = t,
                        block_height,
                        "no instance routes tree; event dropped and that tree now \
                         trails the chain"
                    );
                }
            }
        }
        IndexerMessage::Reorg { height } => {
            let routes = chain_tree_routes.load();
            for (_, tx) in routes.iter() {
                let _ = tx.send(ConsumerEvent::Reorg(height)).await;
            }
        }
        IndexerMessage::ReorgBarrier {
            height,
            completion,
            timeout_secs,
        } => {
            forward_reorg_barrier(height, completion, timeout_secs, chain_tree_routes).await;
        }
        IndexerMessage::Heartbeat {
            chain_head_block,
            scanned_through_block,
            ..
        } => {
            let routes = chain_tree_routes.load();
            for (_, tx) in routes.iter() {
                let _ = tx
                    .send(ConsumerEvent::Heartbeat {
                        chain_head: chain_head_block,
                        scanned_through: scanned_through_block,
                    })
                    .await;
            }
        }
    }
}

async fn forward_reorg_barrier(
    height: u64,
    completion: mpsc::Sender<std::result::Result<(), String>>,
    timeout_secs: u64,
    chain_tree_routes: &arc_swap::ArcSwap<Vec<(u32, mpsc::Sender<ConsumerEvent>)>>,
) {
    let consumers: Vec<mpsc::Sender<ConsumerEvent>> = chain_tree_routes
        .load()
        .iter()
        .map(|(_, sender)| sender.clone())
        .collect();
    if consumers.is_empty() {
        let _ = completion.send(Ok(())).await;
        return;
    }
    let (consumer_completion, mut completed) = mpsc::channel(consumers.len().max(1));
    let mut failures = Vec::new();
    let mut expected = 0usize;
    for sender in consumers {
        if sender
            .send(ConsumerEvent::ReorgBarrier {
                height,
                completion: consumer_completion.clone(),
            })
            .await
            .is_err()
        {
            failures.push("consumer channel closed".to_owned());
        } else {
            expected = expected.saturating_add(1);
        }
    }
    drop(consumer_completion);
    let mut received = 0usize;
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs.max(1));
    while received < expected {
        match tokio::time::timeout_at(deadline, completed.recv()).await {
            Ok(Some(outcome)) => {
                received = received.saturating_add(1);
                if let Err(reason) = outcome {
                    failures.push(reason);
                }
            }
            Ok(None) => break,
            Err(_) => {
                failures.push(format!(
                    "durable acknowledgement timed out after {}s",
                    timeout_secs.max(1)
                ));
                break;
            }
        }
    }
    if received != expected {
        failures.push(format!(
            "received {received} durable acknowledgement(s), expected {expected}"
        ));
    }
    let aggregate = if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} chain consumer(s) failed: {}",
            failures.len(),
            failures.join("; ")
        ))
    };
    let _ = completion.send(aggregate).await;
}

async fn forward_mirror_payload(
    payload: WalEntryPayload,
    height: u64,
    ppoi_list_routes: &[(DataSourceFilter, mpsc::Sender<ConsumerEvent>)],
) {
    let list_key: Option<[u8; 32]> = match &payload {
        WalEntryPayload::PpoiListLeafAdded { list_key, .. } => Some(*list_key),
        WalEntryPayload::AppendLeaf { .. }
        | WalEntryPayload::Reorg { .. }
        | WalEntryPayload::Heartbeat { .. } => None,
    };
    let Some(lk) = list_key else {
        tracing::trace!("mirror payload without list_key; dropping");
        return;
    };
    let mut matched = Vec::new();
    for (filter, sender) in ppoi_list_routes {
        let routed = payload_for_ppoi_route(*filter, &payload, lk);
        if let Some(routed) = routed {
            matched.push((sender.clone(), routed));
        }
    }
    let target = ppoi_target_name(&payload, &lk, ppoi_list_routes);
    let Some((last, rest)) = matched.split_last() else {
        record_no_route(target);
        tracing::warn!(
            height,
            "no instance routes this payload; mirror payload dropped and that target now \
             trails the mirror"
        );
        return;
    };
    let mut delivered_to_all = true;
    for (tx, routed) in rest {
        if tx
            .send(ConsumerEvent::Ppoi(routed.clone(), height))
            .await
            .is_err()
        {
            record_consumer_closed(target.clone());
            delivered_to_all = false;
            tracing::warn!(height, "consumer channel closed; mirror payload dropped");
        }
    }
    if last
        .0
        .send(ConsumerEvent::Ppoi(last.1.clone(), height))
        .await
        .is_err()
    {
        record_consumer_closed(target.clone());
        delivered_to_all = false;
        tracing::warn!(height, "consumer channel closed; mirror payload dropped");
    }
    // Self-healing: reaching every bound route is what clears the mark.
    if delivered_to_all {
        clear_router_unrouted_target(&target);
    }
}

fn payload_for_ppoi_route(
    filter: DataSourceFilter,
    payload: &WalEntryPayload,
    list_key: [u8; 32],
) -> Option<WalEntryPayload> {
    match (filter, payload) {
        (
            DataSourceFilter::PpoiListBlock {
                list_key: route_key,
                block,
            },
            WalEntryPayload::PpoiListLeafAdded {
                list_index,
                blinded_commitment,
                event_type,
                validated_merkleroot,
                ..
            },
        ) if route_key == list_key && split_ppoi_index(*list_index).0 == block => {
            Some(WalEntryPayload::PpoiListLeafAdded {
                list_key: route_key,
                list_index: split_ppoi_index(*list_index).1,
                blinded_commitment: *blinded_commitment,
                event_type: *event_type,
                validated_merkleroot: *validated_merkleroot,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod forest_routing_tests {
    use super::*;

    fn leaf(index: u32) -> WalEntryPayload {
        WalEntryPayload::PpoiListLeafAdded {
            list_key: [7; 32],
            list_index: index,
            blinded_commitment: [8; 32],
            event_type: raven_railgun_persistence::PpoiEventType::Shield,
            validated_merkleroot: [10; 32],
        }
    }

    #[test]
    fn six_block_routes_localize_every_global_boundary_and_refuse_the_seventh() {
        for block in 0..6u32 {
            for local in [0u32, LEAVES_PER_PPOI_BLOCK - 1] {
                let global = block * LEAVES_PER_PPOI_BLOCK + local;
                let routed = payload_for_ppoi_route(
                    DataSourceFilter::PpoiListBlock {
                        list_key: [7; 32],
                        block,
                    },
                    &leaf(global),
                    [7; 32],
                )
                .expect("configured block routes");
                assert!(matches!(
                    routed,
                    WalEntryPayload::PpoiListLeafAdded { list_index, .. } if list_index == local
                ));
            }
        }
        let seventh = leaf(6 * LEAVES_PER_PPOI_BLOCK);
        assert!((0..6u32).all(|block| payload_for_ppoi_route(
            DataSourceFilter::PpoiListBlock {
                list_key: [7; 32],
                block,
            },
            &seventh,
            [7; 32],
        )
        .is_none()));
    }

    #[test]
    fn the_split_and_its_inverse_agree_across_the_first_block_boundary() {
        for global in [
            0,
            LEAVES_PER_PPOI_BLOCK - 1,
            LEAVES_PER_PPOI_BLOCK,
            LEAVES_PER_PPOI_BLOCK + 1,
        ] {
            let (block, local) = split_ppoi_index(global);
            assert!(
                local < LEAVES_PER_PPOI_BLOCK,
                "{global} localized to {local}"
            );
            assert_eq!(global_ppoi_index(block, local), Some(global));
        }
        assert_eq!(split_ppoi_index(LEAVES_PER_PPOI_BLOCK - 1), (0, 65_535));
        assert_eq!(split_ppoi_index(LEAVES_PER_PPOI_BLOCK), (1, 0));
        assert_eq!(split_ppoi_index(LEAVES_PER_PPOI_BLOCK + 1), (1, 1));
    }

    // Routes are fixed at boot, so a list is routed for the whole process or never. A routed list
    // names its targets by block, so readiness can tell an undeclared block from an unserved list.
    #[test]
    fn a_routed_list_names_its_targets_by_block_and_an_unrouted_one_by_list() {
        let (tx, _rx) = mpsc::channel(1);
        let routes = [(
            DataSourceFilter::PpoiListBlock {
                list_key: [7; 32],
                block: 3,
            },
            tx,
        )];
        let hex = hex_lower_32(&[7; 32]);
        let named = |index: u32, routes: &[(DataSourceFilter, mpsc::Sender<ConsumerEvent>)]| {
            ppoi_target_name(&leaf(index), &[7; 32], routes)
        };
        assert_eq!(
            named(3 * LEAVES_PER_PPOI_BLOCK + 7, &routes),
            format!("list:{hex}:block:3")
        );
        assert_eq!(
            named(5 * LEAVES_PER_PPOI_BLOCK, &routes),
            format!("list:{hex}:block:5")
        );
        assert_eq!(named(0, &[]), format!("list:{hex}"));
    }
}

#[cfg(test)]
mod session_limit_tests {
    use super::*;
    use raven_inspire::inspiring::ClientPackingKeys;
    use raven_inspire::math::GaussianSampler;
    use raven_inspire::params::{InspireParams, InspireVariant};
    use std::time::Duration;

    const ENTRY_SIZE: usize = 256;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_store_a_multi_bootstrap_opens_carries_the_requested_limits() {
        let root = tempfile::tempdir().expect("tempdir");
        let params = InspireParams::secure_128_d2048();
        let (donor, secret_key) = crate::inspire::setup_state(
            &params,
            &raven_railgun_testkit::toy_db(raven_railgun_testkit::TOY_ENTRIES, ENTRY_SIZE),
            ENTRY_SIZE,
            InspireVariant::TwoPacking,
        )
        .expect("toy state");
        let configs: Vec<InstanceConfig> = (0..2u32)
            .map(|tree| {
                let mut cfg = InstanceConfig::commit_tree(
                    format!("tree-{tree}"),
                    root.path().join(format!("tree-{tree}")),
                    tree,
                    InstanceRole::Live,
                );
                cfg.encoder = crate::pir_table::EncoderKind::PerLeafBc { tree_number: tree };
                cfg.record_size = ENTRY_SIZE;
                cfg.use_flock = false;
                cfg
            })
            .collect();
        let limits = SessionStoreLimits {
            max_sessions: 2,
            ttl: Duration::from_secs(600),
        };

        let handle =
            bootstrap_railgun_engine_multi_with_session_limits(configs, params, limits, |_, _| {
                Ok(InspireServerState {
                    crs: Arc::clone(&donor.crs),
                    encoded_db: Arc::clone(&donor.encoded_db),
                    cache: Arc::clone(&donor.cache),
                    session_store: Arc::new(crate::session_pool::BoundedSessionStore::new()),
                    variant: donor.variant,
                    entry_size: donor.entry_size,
                })
            })
            .expect("bootstrap");

        let mut sampler = GaussianSampler::with_seed(donor.crs.params.sigma, 3);
        let keys = ClientPackingKeys::generate(
            &secret_key,
            donor.cache.pack_params(),
            donor.crs.inspiring_w_seed,
            &mut sampler,
        );
        let context = donor.crs.params.ntt_context();
        assert_eq!(handle.instances.len(), 2);
        for per in &handle.instances {
            let state = per.instance.current_state();
            assert_eq!(
                state.session_store.limits(),
                limits,
                "{}",
                per.config.instance_id
            );
            for seat in 0..limits.max_sessions {
                state
                    .session_store
                    .register_server_side(keys.clone(), state.cache.pack_params(), &context)
                    .unwrap_or_else(|error| panic!("seat {seat}: {error}"));
            }
            let refusal = state
                .session_store
                .register_server_side(keys.clone(), state.cache.pack_params(), &context)
                .expect_err("the requested ceiling, not the default, refuses");
            assert!(
                refusal.to_string().contains("2 live sessions"),
                "{}: {refusal}",
                per.config.instance_id
            );
        }

        handle.router.abort();
        drop(handle.channels);
        for per in handle.instances {
            let _ = per.sender.send(ConsumerEvent::Shutdown).await;
            let _ = tokio::time::timeout(Duration::from_secs(5), per.consumer).await;
        }
    }
}
