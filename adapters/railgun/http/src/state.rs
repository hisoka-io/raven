//! Application state shared across handlers.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Instant;

use raven_railgun_core::InstanceId;
use raven_railgun_engine::persistence::ConsumerMetrics;
use raven_railgun_engine::{Engine, PirScheme};
use tokio::sync::Semaphore;

use crate::auth::SessionMap;
use crate::config::HttpConfig;
use crate::global_prometheus_handle;

// Re-export the client-id header name so external consumers can import
// it from the crate root alongside [`AppState`]. The canonical
// definition lives in [`crate::auth`].
pub use crate::auth::X_RAVEN_CLIENT_ID;

/// Application state shared across handlers. Cheap to clone (Arc inside).
/// Manual `Clone` impl avoids the derive's incorrect `S: Clone` bound.
pub struct AppState<S: PirScheme> {
    /// Engine registry of PIR instances.
    pub engine: Arc<Engine<S>>,
    /// Layer config (auth, rate limit, session, concurrency).
    pub config: Arc<HttpConfig>,
    /// Bearer token for read scope, in an RwLock for hot rotation without restart.
    pub read_token: Arc<parking_lot::RwLock<String>>,
    /// Bearer token for admin scope (optional).
    pub admin_token: Arc<Option<String>>,
    /// Identifier surfaced in `X-Raven-Scheme`.
    pub scheme_name: Arc<String>,
    /// Orchestrator metrics for `/v1/status` lag fields. `None` omits the fields.
    pub(crate) consumer_metrics:
        Arc<Option<Arc<parking_lot::Mutex<raven_railgun_engine::persistence::ConsumerMetrics>>>>,
    /// Shared logical leaf store for the PPOI shim routes. `None` returns 503.
    pub(crate) logical_store:
        Arc<Option<Arc<parking_lot::Mutex<raven_railgun_engine::inspire::LogicalLeafStore>>>>,
    /// Per-instance concurrency caps for `/v1/status`. Falls back to `max_concurrent_queries`.
    pub(crate) instance_concurrency: Arc<HashMap<InstanceId, u32>>,
    /// Indexer chain-source mode flag for `/v1/health/ready`.
    pub(crate) chain_source_mode: Arc<Option<Arc<raven_railgun_indexer::ModeFlag>>>,
    /// Multi-endpoint RPC pool for `/v1/health/ready`. `None` for single-endpoint.
    pub(crate) rpc_pool: Arc<Option<Arc<raven_railgun_indexer::rpc_pool::RpcEndpointPool>>>,
    pub(crate) sessions: Arc<SessionMap>,
    pub(crate) semaphore: Arc<Semaphore>,
    pub(crate) metrics_handle: Arc<metrics_exporter_prometheus::PrometheusHandle>,
    /// Per-instance [`ConsumerMetrics`] map. Populated via
    /// [`AppState::with_instance_metrics`] in multi-instance deployments
    /// so the `/metrics` handler can emit per-instance Prometheus labels
    /// (`raven_railgun_consumer_*{instance="..."}`,
    /// `raven_railgun_indexer_lag_blocks{instance="..."}`, etc.). Empty
    /// for tests + single-instance deployments that wire only the legacy
    /// single-cell [`AppState::with_consumer_metrics`]; the metrics
    /// handler falls back to that cell when this map is empty.
    ///
    /// Consumed by `refresh_dynamic_metrics` in the `metrics_handler` to
    /// emit per-instance `consumer_*` gauges alongside the engine-side
    /// `drain_state` / `in_flight` / `epoch` / `role` gauges from the
    /// `engine.instances()` walk.
    pub(crate) instance_metrics: Arc<HashMap<InstanceId, Arc<parking_lot::Mutex<ConsumerMetrics>>>>,
    /// Process start instant. Used to render `raven_railgun_uptime_seconds`
    /// on every scrape. Resets on process restart per Prometheus
    /// counter convention.
    pub(crate) process_started_at: Instant,
    /// Per-AppState ETag cache for `GET /v1/instance/:id/params`.
    /// Keyed by `InstanceId` with `(epoch, sha256)` payload so an epoch
    /// bump invalidates the cached hash for a given instance without
    /// growing the map across the lifetime of the process.
    pub(crate) params_etag_cache: Arc<ParamsEtagCache>,
}

/// Per-AppState ETag cache type for `/v1/instance/:id/params`.
///
/// Map shape: `InstanceId -> (Epoch, sha256)`. One entry per instance;
/// an epoch bump overwrites the prior payload. The map never grows
/// beyond `O(instance count)`.
pub(crate) type ParamsEtagCache =
    parking_lot::RwLock<HashMap<InstanceId, (raven_railgun_core::Epoch, [u8; 32])>>;

impl<S: PirScheme> Clone for AppState<S> {
    fn clone(&self) -> Self {
        Self {
            engine: Arc::clone(&self.engine),
            config: Arc::clone(&self.config),
            read_token: Arc::clone(&self.read_token),
            admin_token: Arc::clone(&self.admin_token),
            scheme_name: Arc::clone(&self.scheme_name),
            consumer_metrics: Arc::clone(&self.consumer_metrics),
            logical_store: Arc::clone(&self.logical_store),
            instance_concurrency: Arc::clone(&self.instance_concurrency),
            chain_source_mode: Arc::clone(&self.chain_source_mode),
            rpc_pool: Arc::clone(&self.rpc_pool),
            sessions: Arc::clone(&self.sessions),
            semaphore: Arc::clone(&self.semaphore),
            metrics_handle: Arc::clone(&self.metrics_handle),
            instance_metrics: Arc::clone(&self.instance_metrics),
            process_started_at: self.process_started_at,
            params_etag_cache: Arc::clone(&self.params_etag_cache),
        }
    }
}

impl<S: PirScheme> std::fmt::Debug for AppState<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("scheme_name", &self.scheme_name)
            .field(
                "max_concurrent_queries",
                &self.config.max_concurrent_queries,
            )
            .field("session_count", &self.sessions.len())
            .finish_non_exhaustive()
    }
}

impl<S: PirScheme> AppState<S> {
    /// Build an [`AppState`]. Installs the global Prometheus recorder (idempotent).
    ///
    /// # Errors
    /// Returns `Err` if config validation fails or the Prometheus recorder install fails.
    pub fn new(engine: Engine<S>, config: HttpConfig) -> Result<Self, String> {
        config.validate()?;
        let read_token = Arc::new(parking_lot::RwLock::new(config.read_token.clone()));
        let admin_token = Arc::new(config.admin_token.clone());
        let scheme_name = Arc::new(config.scheme_name.clone());
        let max_concurrent = config.max_concurrent_queries.max(1);
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let sessions = Arc::new(SessionMap::new());

        let metrics_handle = global_prometheus_handle()?;
        describe_prometheus_metrics();

        Ok(Self {
            engine: Arc::new(engine),
            config: Arc::new(config),
            read_token,
            admin_token,
            scheme_name,
            consumer_metrics: Arc::new(None),
            logical_store: Arc::new(None),
            instance_concurrency: Arc::new(HashMap::new()),
            chain_source_mode: Arc::new(None),
            rpc_pool: Arc::new(None),
            sessions,
            semaphore,
            metrics_handle,
            instance_metrics: Arc::new(HashMap::new()),
            process_started_at: Instant::now(),
            params_etag_cache: Arc::new(parking_lot::RwLock::new(HashMap::new())),
        })
    }

    /// Attach the chain-source mode flag; surfaced in `/v1/health/ready`.
    #[must_use]
    pub fn with_chain_source_mode(mut self, mode: Arc<raven_railgun_indexer::ModeFlag>) -> Self {
        self.chain_source_mode = Arc::new(Some(mode));
        self
    }

    /// Attach the RPC pool; surfaced under `rpc_pool.endpoints` in `/v1/health/ready`.
    #[must_use]
    pub fn with_rpc_pool(
        mut self,
        pool: Arc<raven_railgun_indexer::rpc_pool::RpcEndpointPool>,
    ) -> Self {
        self.rpc_pool = Arc::new(Some(pool));
        self
    }

    /// Register per-instance concurrency caps for `active_k_concurrency` in `/v1/status`.
    #[must_use]
    pub fn with_instance_concurrency(mut self, per_instance: HashMap<InstanceId, u32>) -> Self {
        self.instance_concurrency = Arc::new(per_instance);
        self
    }

    /// Attach consumer metrics; surfaced as indexer lag in `/v1/status`.
    #[must_use]
    pub fn with_consumer_metrics(
        mut self,
        metrics: Arc<parking_lot::Mutex<raven_railgun_engine::persistence::ConsumerMetrics>>,
    ) -> Self {
        self.consumer_metrics = Arc::new(Some(metrics));
        self
    }

    /// Register a per-instance map of [`ConsumerMetrics`] handles so the
    /// `/metrics` handler can emit per-instance-labeled gauges + counters
    /// (one row per instance, instead of the single-cell fallback that
    /// only surfaces the first instance's progress).
    ///
    /// Multi-instance deployments call this builder once with the
    /// resolved metrics handle from every per-instance bootstrap so
    /// every instance's `events_processed`, `commits_fired`,
    /// `consumer_errors`, `last_applied_block`, `last_known_chain_head`,
    /// and `indexer_lag_blocks` flow into Prometheus under
    /// `instance="<id>"`. When this map is empty (single-instance
    /// deployments + tests) the `/metrics` handler falls back to
    /// surfacing only the legacy single-cell `consumer_metrics` (if
    /// wired).
    #[must_use]
    pub fn with_instance_metrics(
        mut self,
        per_instance: HashMap<InstanceId, Arc<parking_lot::Mutex<ConsumerMetrics>>>,
    ) -> Self {
        self.instance_metrics = Arc::new(per_instance);
        self
    }

    /// Attach the logical leaf store for the PPOI shim routes. Without this, shim routes 503.
    #[must_use]
    pub fn with_logical_store(
        mut self,
        store: Arc<parking_lot::Mutex<raven_railgun_engine::inspire::LogicalLeafStore>>,
    ) -> Self {
        self.logical_store = Arc::new(Some(store));
        self
    }

    /// Hot-rotate the read bearer token in-process without dropping in-flight queries.
    /// In-flight requests that already cleared auth continue on their prior snapshot.
    pub fn set_read_token(&self, new_token: &str) {
        let mut guard = self.read_token.write();
        new_token.clone_into(&mut guard);
    }

    /// Spawn a periodic sweeper that drops session entries past TTL.
    ///
    /// Without the sweeper, expired entries are only purged lazily on `get`
    /// against the same key, so a token that churns once and never repeats
    /// stays resident until process restart. The sweeper bounds the resident
    /// session set so bearer rotation under sustained churn does not bloat
    /// memory. Each removed entry bumps
    /// `raven_railgun_session_evictions_total{reason="ttl"}`.
    ///
    /// `interval` is the tick cadence; pick relative to `session_ttl_secs`
    /// (default 60 s sweep against 1 h TTL keeps the map within one minute
    /// of the configured window). `0` or sub-second values are clamped to
    /// 1 s so the sweeper never spins.
    #[must_use]
    pub fn start_session_sweeper(
        &self,
        interval: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        let sessions = Arc::clone(&self.sessions);
        let interval = interval.max(std::time::Duration::from_secs(1));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let now = std::time::Instant::now();
                let removed = sessions.sweep_expired(now);
                if removed > 0 {
                    #[allow(clippy::cast_possible_truncation)]
                    let removed_u64 = removed as u64;
                    metrics::counter!("raven_railgun_session_evictions_total", "reason" => "ttl")
                        .increment(removed_u64);
                }
            }
        })
    }
}

/// Register HELP + TYPE descriptions for every Prometheus metric the
/// HTTP layer emits. Called from [`AppState::new`] so the descriptions
/// land before the first scrape regardless of which counter happens
/// to fire first; idempotent (the metrics crate dedupes on the metric
/// name, and a [`OnceLock`] guards the body for cheap repeat calls).
///
/// Per-instance gauges (`raven_railgun_drain_state`,
/// `raven_railgun_in_flight`, `raven_railgun_epoch`,
/// `raven_railgun_consumer_*`, `raven_railgun_indexer_*_per_instance`,
/// `raven_railgun_snapshots`, `raven_railgun_reorgs_handled`) are
/// described here so dashboards see the HELP line at boot; the
/// per-scrape *values* + `instance=".."` labels are produced by the
/// orchestrator-side `refresh_dynamic_metrics` / `emit_instance_metrics`
/// pass that the `metrics_handler` invokes before render.
#[allow(clippy::too_many_lines)]
pub(crate) fn describe_prometheus_metrics() {
    static DESCRIBED: OnceLock<()> = OnceLock::new();
    if DESCRIBED.get().is_some() {
        return;
    }
    metrics::describe_counter!(
        "raven_railgun_queries_total",
        "Total PIR queries served, labelled by instance + kind (single|batch)"
    );
    metrics::describe_counter!(
        "raven_railgun_auth_ok_total",
        "Total authenticated requests, labelled by scope"
    );
    metrics::describe_histogram!(
        "raven_railgun_respond_seconds",
        "PIR respond latency in seconds, labelled by instance + kind"
    );
    metrics::describe_histogram!(
        "raven_railgun_batch_size",
        "PIR batch size (queries per batch), labelled by instance"
    );
    metrics::describe_gauge!(
        "raven_railgun_uptime_seconds",
        "Seconds since the process started; resets on restart"
    );
    metrics::describe_gauge!(
        "raven_railgun_sessions_active",
        "Live sticky-session count across all instances"
    );
    metrics::describe_gauge!(
        "raven_railgun_sessions_occupancy",
        "Live sticky-session count per instance"
    );
    metrics::describe_gauge!(
        "raven_railgun_semaphore_permits_available",
        "Permits free in the global respond concurrency semaphore"
    );
    metrics::describe_gauge!(
        "raven_railgun_drain_state",
        "1 when instance is route-eligible (Active), 0 otherwise"
    );
    metrics::describe_gauge!(
        "raven_railgun_in_flight",
        "Per-instance in-flight respond count"
    );
    metrics::describe_gauge!(
        "raven_railgun_epoch",
        "Per-instance epoch (incremented on each swap_state)"
    );
    metrics::describe_gauge!(
        "raven_railgun_role",
        "Always 1.0; carries the operator-visible role label as a separate dim"
    );
    metrics::describe_gauge!(
        "raven_railgun_consumer_last_applied_block",
        "Per-instance last-applied chain block height"
    );
    metrics::describe_gauge!(
        "raven_railgun_consumer_last_known_chain_head",
        "Per-instance last-known chain head"
    );
    metrics::describe_gauge!(
        "raven_railgun_consumer_indexer_lag_blocks",
        "Per-instance indexer lag (chain_head - last_applied)"
    );
    metrics::describe_gauge!(
        "raven_railgun_consumer_events_processed",
        "Per-instance count of consumer events successfully applied"
    );
    metrics::describe_gauge!(
        "raven_railgun_consumer_errors",
        "Per-instance count of consumer per-event errors logged-and-continued"
    );
    metrics::describe_gauge!(
        "raven_railgun_consumer_commits_fired",
        "Per-instance count of commits / snapshots fired"
    );
    metrics::describe_gauge!(
        "raven_railgun_consumer_reorgs_handled",
        "Per-instance count of reorgs handled by the consumer"
    );
    metrics::describe_counter!(
        "raven_railgun_sessions_established_total",
        "Lifetime count of sticky-session establishment events, labelled by instance"
    );
    metrics::describe_counter!(
        "raven_railgun_session_evictions_total",
        "Lifetime count of sticky-session entries evicted, labelled by `reason` \
         (ttl = swept past expires_at, lru = displaced on cap-pressure upsert)"
    );
    metrics::describe_counter!(
        "raven_railgun_session_eviction_pressure_total",
        "Lifetime count of LRU-pressure session evictions per instance"
    );
    metrics::describe_counter!(
        "raven_railgun_session_eviction_swaps_total",
        "Lifetime count of heartbeat swap_state evictions per instance"
    );
    metrics::describe_counter!(
        "raven_railgun_indexer_dropped_logs_total",
        "Lifetime count of indexer logs dropped due to missing fields, labelled by reason"
    );
    metrics::describe_counter!(
        "raven_railgun_indexer_reorg_window_persist_failed_total",
        "Lifetime count of reorg-window persistence failures"
    );

    // Force the eviction counter into the registry at boot so a
    // Prometheus scrape against an empty-map deployment still finds
    // the series (zero-valued). Without this, the counter line is
    // absent until the first eviction fires; dashboards that pin
    // alerts on `rate(raven_railgun_session_evictions_total[5m])`
    // see "no data" instead of zero.
    metrics::counter!(
        "raven_railgun_session_evictions_total",
        "reason" => "ttl",
    )
    .increment(0);
    metrics::counter!("raven_railgun_indexer_reorg_window_persist_failed_total").increment(0);

    let _ = DESCRIBED.set(());
}
