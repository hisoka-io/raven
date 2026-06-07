//! Single- and multi-instance bootstrap: wires indexer + PPOI mirror
//! into an orchestrated consumer-task graph.

use crate::inspire::{InspireServerState, LogicalLeafStore, RavenInspireScheme};
use crate::persistence::{
    bootstrap_inspire_instance, run_consumer_task, ConsumerEvent, ConsumerMetrics,
    InspirePersistence, Layer2VerifierContext, SnapshotPolicy,
};
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
) {
    while let Some(msg) = rx.recv().await {
        let translated = match msg {
            IndexerMessage::Event {
                event,
                block_height,
            } => ConsumerEvent::Chain(event, block_height),
            IndexerMessage::Reorg { height } => ConsumerEvent::Reorg(height),
            IndexerMessage::Heartbeat {
                chain_head_block, ..
            } => ConsumerEvent::Heartbeat(chain_head_block),
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
    /// Indexer→consumer bridge task.
    pub indexer_bridge: tokio::task::JoinHandle<()>,
    /// Mirror→consumer bridge task.
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
    /// MPSC capacity for indexer → consumer messaging.
    pub channel_capacity: usize,
    /// Encoder kind.
    pub encoder: super::pir_table::EncoderKind,
    /// Bytes per row, matching `fresh_state_factory`'s `entry_size`.
    pub record_size: usize,
    /// Rows per shard, matching `shard_config().entries_per_shard()`.
    pub entries_per_shard: u32,
    /// Max concurrent in-flight respond ops. `None` resolves via [`default_k_for`].
    pub max_concurrent_queries: Option<usize>,
    /// On-disk-state authority: chain rootHistory or upstream signature.
    pub verification_mode: VerificationMode,
    /// Run the Layer 2 verifier every Nth commit. `0` disables.
    pub verification_cadence_n: u32,
    /// Tree number whose IMT the verifier cross-checks against rootHistory.
    pub verification_tree_number: u32,
    /// Chain source for the Layer 2 verifier. `None` disables the verifier.
    pub chain_source: Option<Arc<dyn ChainSource>>,
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
            verification_mode: VerificationMode::ChainRootHistory,
            verification_cadence_n: 10,
            verification_tree_number: 0,
            chain_source: None,
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
            .field("verification_mode", &self.verification_mode)
            .field("verification_cadence_n", &self.verification_cadence_n)
            .field("verification_tree_number", &self.verification_tree_number)
            .field("chain_source_attached", &self.chain_source.is_some())
            .finish()
    }
}

/// Per-encoder default concurrency cap (`max_concurrent_queries`).
#[must_use]
pub const fn default_k_for(encoder: super::pir_table::EncoderKind) -> usize {
    match encoder {
        super::pir_table::EncoderKind::PerNode { .. }
        | super::pir_table::EncoderKind::PerListPath { .. }
        | super::pir_table::EncoderKind::PerListNode { .. } => 16,
        super::pir_table::EncoderKind::PerLeafPath { .. } => 8,
        super::pir_table::EncoderKind::PerLeafBc
        | super::pir_table::EncoderKind::PerListStatus { .. } => 4,
    }
}

/// Bootstrap the Railgun engine (persistence + consumer task).
///
/// `fresh_state_factory` is called only on first bootstrap (no manifest).
pub fn bootstrap_railgun_engine(
    config: OrchestratorConfig,
    params: raven_inspire::params::InspireParams,
    fresh_state_factory: impl FnOnce() -> Result<InspireServerState>,
) -> Result<OrchestratorHandle> {
    let layout = if config.use_flock {
        let (l, lock) = StoreLayout::open_with_lock(&config.data_dir)
            .map_err(|e| AdapterError::Internal(format!("StoreLayout::open_with_lock: {e}")))?;
        // Hold the flock for the process lifetime.
        let _ = Box::leak(Box::new(lock));
        l
    } else {
        StoreLayout::open(&config.data_dir)
            .map_err(|e| AdapterError::Internal(format!("StoreLayout::open: {e}")))?
    };

    let encoder: Arc<dyn super::pir_table::PirTableEncoder> = config
        .encoder
        .build(config.record_size, config.entries_per_shard)?;

    let (instance, persistence) = bootstrap_inspire_instance(
        layout,
        config.scheme_tag.clone(),
        config.instance_id.clone(),
        config.role,
        config.snapshot_policy,
        Arc::clone(&encoder),
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
    let logical_store = Arc::new(parking_lot::Mutex::new(LogicalLeafStore::new()));

    let verifier_ctx = config
        .chain_source
        .as_ref()
        .map(|cs| Layer2VerifierContext {
            verification_mode: config.verification_mode,
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
        tokio::spawn(indexer_to_consumer_bridge(indexer_rx, cons_tx))
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

/// On-disk-state authority for a deployment instance.
///
/// PPOI instances must use `UpstreamSignature`; PPOI list roots are not chain-anchored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationMode {
    /// Cross-check IMT root against `RailgunSmartWallet.rootHistory`.
    ChainRootHistory,
    /// Trust the upstream `signedPOIEvent` signature.
    UpstreamSignature,
}

/// Routing filter: maps chain/mirror events to a specific instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DataSourceFilter {
    /// Consume chain `AppendLeaf` events for this tree number.
    ChainTreeNumber(u32),
    /// Consume mirror `PpoiStatus`/`PpoiListLeafAdded` events for this list key.
    PpoiList([u8; 32]),
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
    /// On-disk-state authority.
    pub verification_mode: VerificationMode,
    /// Routing filter for chain/mirror events.
    pub data_source: DataSourceFilter,
    /// Acquire an advisory flock on `data_dir/.lock`.
    pub use_flock: bool,
    /// Snapshot policy.
    pub snapshot_policy: SnapshotPolicy,
    /// Scheme tag stored in the manifest.
    pub scheme_tag: String,
    /// MPSC capacity for indexer/mirror → consumer messaging.
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
            .field("verification_mode", &self.verification_mode)
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
            verification_mode: VerificationMode::ChainRootHistory,
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

    /// Default config for a PPOI list instance.
    #[must_use]
    pub fn ppoi_list(
        instance_id: impl Into<String>,
        data_dir: std::path::PathBuf,
        list_key: [u8; 32],
    ) -> Self {
        Self {
            instance_id: InstanceId::new(instance_id),
            role: InstanceRole::Live,
            data_dir,
            encoder: super::pir_table::EncoderKind::PerListPath { list_key },
            record_size: 16 * 32,
            entries_per_shard: 2048,
            verification_mode: VerificationMode::UpstreamSignature,
            data_source: DataSourceFilter::PpoiList(list_key),
            use_flock: true,
            snapshot_policy: SnapshotPolicy::default(),
            scheme_tag: "raven-inspire-twopacking-inspiring-wp3-cache-session".to_owned(),
            channel_capacity: 1024,
            max_concurrent_queries: None,
            verification_cadence_n: 0,
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
            .field("verification_mode", &self.config.verification_mode)
            .field("encoder_label", &self.config.encoder.label())
            .finish_non_exhaustive()
    }
}

/// Live-mutable chain-tree routing table (`tree_number` → consumer sender).
///
/// Updated via `ArcSwap::rcu` by the auto-spawn driver; router picks up new routes
/// lock-free.
pub type ChainTreeRoutes = Arc<arc_swap::ArcSwap<Vec<(u32, mpsc::Sender<ConsumerEvent>)>>>;

/// Live-mutable PPOI-list routing table (`list_key` → consumer sender).
///
/// Updated via `ArcSwap::rcu` by the auto-spawn driver on `list_observed`.
pub type PpoiListRoutes = Arc<arc_swap::ArcSwap<Vec<([u8; 32], mpsc::Sender<ConsumerEvent>)>>>;

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
    /// Live PPOI-list routing table.
    pub ppoi_list_routes: PpoiListRoutes,
    /// Lossy broadcast of every chain `tree_number` seen by the router.
    pub tree_observed: tokio::sync::broadcast::Sender<u32>,
    /// Lossy broadcast of every PPOI `list_key` seen by the router.
    pub list_observed: tokio::sync::broadcast::Sender<[u8; 32]>,
}

impl std::fmt::Debug for MultiOrchestratorHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiOrchestratorHandle")
            .field("instance_count", &self.instances.len())
            .finish_non_exhaustive()
    }
}

/// Bootstrap a multi-instance Railgun engine with a single shared router.
///
/// # Errors
///
/// Returns [`AdapterError::InvalidQuery`] if `configs` is empty or two configs share
/// the same `data_source`.
#[allow(clippy::too_many_lines)]
pub fn bootstrap_railgun_engine_multi<F>(
    configs: Vec<InstanceConfig>,
    params: raven_inspire::params::InspireParams,
    mut fresh_state_factory: F,
) -> Result<MultiOrchestratorHandle>
where
    F: FnMut(&InstanceConfig) -> Result<InspireServerState>,
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

    let mut per_instance: Vec<PerInstanceHandles> = Vec::with_capacity(configs.len());
    for cfg in configs {
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

        let opened = InspirePersistence::open(
            layout,
            cfg.scheme_tag.clone(),
            cfg.instance_id.clone(),
            cfg.snapshot_policy,
            Arc::clone(&encoder),
        )?;
        let persistence = Arc::new(opened.persistence);
        let recovered_store = opened.recovered_logical_store;
        let state = if let Some(s) = opened.recovered_state {
            s
        } else {
            let s = fresh_state_factory(&cfg)?;
            // V6 envelope so the embedded store travels with the snapshot from
            // the first manifest write; empty on first bootstrap.
            let empty_store = LogicalLeafStore::default();
            persistence.commit_v6(&s, &empty_store, 0)?;
            persistence.commit_notify().notify_waiters();
            s
        };
        let instance = PirInstance::new(cfg.instance_id.clone(), cfg.role, state);
        let instance_arc: Arc<PirInstance<RavenInspireScheme>> = Arc::new(instance);

        let cap = cfg.channel_capacity.max(1);
        let (sender, receiver) = mpsc::channel::<ConsumerEvent>(cap);
        let metrics = Arc::new(parking_lot::Mutex::new(ConsumerMetrics::default()));
        let logical_store = Arc::new(parking_lot::Mutex::new(recovered_store));
        let verifier_ctx = match (&cfg.chain_source, cfg.data_source) {
            (Some(cs), DataSourceFilter::ChainTreeNumber(tn)) => Some(Layer2VerifierContext {
                verification_mode: cfg.verification_mode,
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
            let encoder = Arc::clone(&encoder);
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

        per_instance.push(PerInstanceHandles {
            config: cfg,
            instance: instance_arc,
            persistence,
            consumer,
            sender,
            metrics,
            logical_store,
        });
    }

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
            DataSourceFilter::PpoiList(_) => None,
        })
        .collect();
    let ppoi_routes: Vec<([u8; 32], mpsc::Sender<ConsumerEvent>)> = routes
        .iter()
        .filter_map(|(ds, tx)| match ds {
            DataSourceFilter::PpoiList(k) => Some((*k, tx.clone())),
            DataSourceFilter::ChainTreeNumber(_) => None,
        })
        .collect();

    let chain_tree_routes = Arc::new(arc_swap::ArcSwap::from_pointee(initial_chain_tree_routes));
    let ppoi_list_routes: PpoiListRoutes = Arc::new(arc_swap::ArcSwap::from_pointee(ppoi_routes));
    // Lagged receivers re-sync on the next event — capacity 64 is sufficient.
    let (tree_observed_tx, _) = tokio::sync::broadcast::channel::<u32>(64);
    let (list_observed_tx, _) = tokio::sync::broadcast::channel::<[u8; 32]>(64);

    let router = tokio::spawn(multi_instance_router(
        indexer_rx,
        mirror_rx,
        Arc::clone(&chain_tree_routes),
        Arc::clone(&ppoi_list_routes),
        tree_observed_tx.clone(),
        list_observed_tx.clone(),
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
        list_observed: list_observed_tx,
    })
}

/// Fans indexer and mirror events to per-instance consumers by `data_source`.
/// Returns when both inbound channels are closed.
async fn multi_instance_router(
    mut indexer_rx: mpsc::Receiver<IndexerMessage>,
    mut mirror_rx: mpsc::Receiver<(WalEntryPayload, u64)>,
    chain_tree_routes: ChainTreeRoutes,
    ppoi_list_routes: PpoiListRoutes,
    tree_observed: tokio::sync::broadcast::Sender<u32>,
    list_observed: tokio::sync::broadcast::Sender<[u8; 32]>,
) {
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
                    forward_mirror_payload(
                        payload,
                        height,
                        &ppoi_list_routes,
                        &list_observed,
                    )
                    .await;
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
                if let Some(tx) = routes
                    .iter()
                    .find(|(tn, _)| *tn == t)
                    .map(|(_, s)| s.clone())
                {
                    let _ = tx.send(ConsumerEvent::Chain(event, block_height)).await;
                } else {
                    tracing::trace!(tree_number = t, "no instance routes tree; dropping event");
                }
            }
        }
        IndexerMessage::Reorg { height } => {
            let routes = chain_tree_routes.load();
            for (_, tx) in routes.iter() {
                let _ = tx.send(ConsumerEvent::Reorg(height)).await;
            }
        }
        IndexerMessage::Heartbeat {
            chain_head_block, ..
        } => {
            let routes = chain_tree_routes.load();
            for (_, tx) in routes.iter() {
                let _ = tx.send(ConsumerEvent::Heartbeat(chain_head_block)).await;
            }
        }
    }
}

async fn forward_mirror_payload(
    payload: WalEntryPayload,
    height: u64,
    ppoi_list_routes: &arc_swap::ArcSwap<Vec<([u8; 32], mpsc::Sender<ConsumerEvent>)>>,
    list_observed: &tokio::sync::broadcast::Sender<[u8; 32]>,
) {
    let list_key: Option<[u8; 32]> = match &payload {
        WalEntryPayload::PpoiStatus { list_key, .. }
        | WalEntryPayload::PpoiListLeafAdded { list_key, .. } => Some(*list_key),
        WalEntryPayload::AppendLeaf { .. }
        | WalEntryPayload::Reorg { .. }
        | WalEntryPayload::Heartbeat { .. } => None,
    };
    let Some(lk) = list_key else {
        tracing::trace!("mirror payload without list_key; dropping");
        return;
    };
    // Fired before routing so a fresh list_key surfaces before any instance route exists.
    let _ = list_observed.send(lk);
    let routes = ppoi_list_routes.load();
    // Fan out to ALL senders bound to `lk`: distinct encoders can share one
    // list_key, so `.find()` would drop events past the first match.
    let matched: Vec<mpsc::Sender<ConsumerEvent>> = routes
        .iter()
        .filter(|(k, _)| *k == lk)
        .map(|(_, s)| s.clone())
        .collect();
    if matched.is_empty() {
        tracing::trace!("no instance routes list_key; dropping mirror payload");
        return;
    }
    for tx in matched {
        let _ = tx.send(ConsumerEvent::Ppoi(payload.clone(), height)).await;
    }
}
