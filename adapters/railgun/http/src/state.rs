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

pub use crate::auth::X_RAVEN_CLIENT_ID;

/// Handler-shared state; cheap to clone. The manual `Clone` avoids the derive's
/// spurious `S: Clone` bound.
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
    /// Instance-labelled `/metrics` gauges; empty falls back to `consumer_metrics`.
    pub(crate) instance_metrics: Arc<HashMap<InstanceId, Arc<parking_lot::Mutex<ConsumerMetrics>>>>,
    /// Process start instant, for `raven_railgun_uptime_seconds`.
    pub(crate) process_started_at: Instant,
    /// ETag cache keyed so an epoch bump invalidates without growing the map.
    pub(crate) params_etag_cache: Arc<ParamsEtagCache>,
}

/// `InstanceId -> (Epoch, sha256)` for `/v1/instance/:id/params`.
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
    /// Build an [`AppState`], installing the global Prometheus recorder (idempotent).
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

    /// `/metrics` emits `instance="<id>"` gauges; empty falls back to the single cell.
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

    /// Hot-rotate the read bearer token; requests that already cleared auth continue
    /// on their prior snapshot.
    pub fn set_read_token(&self, new_token: &str) {
        let mut guard = self.read_token.write();
        new_token.clone_into(&mut guard);
    }

    /// Sweep past-TTL session entries, which otherwise purge only lazily on `get`
    /// and leak a once-churned token until restart. `interval` has a 1 s floor.
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

impl AppState<raven_railgun_engine::inspire::RavenInspireScheme> {
    /// Sweep past-TTL packing-key registrations from every instance's
    /// [`BoundedSessionStore`](raven_railgun_engine::session_pool::BoundedSessionStore).
    /// `resolve` already refuses expired handles; this only keeps gauges honest.
    #[must_use]
    pub fn start_packing_key_sweeper(
        &self,
        interval: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        let engine = Arc::clone(&self.engine);
        let interval = interval.max(std::time::Duration::from_secs(1));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let now = Instant::now();
                for instance in engine.instances() {
                    instance.current_state().session_store.sweep_expired(now);
                }
            }
        })
    }
}

/// Register HELP + TYPE before the first scrape. [`OnceLock`]-guarded.
pub(crate) fn describe_prometheus_metrics() {
    static DESCRIBED: OnceLock<()> = OnceLock::new();
    if DESCRIBED.get().is_some() {
        return;
    }
    register_prometheus_descriptions();
    let _ = DESCRIBED.set(());
}

/// Unguarded body of [`describe_prometheus_metrics`], so a recorder can be
/// driven through it more than once per process.
#[allow(clippy::too_many_lines)]
fn register_prometheus_descriptions() {
    metrics::describe_counter!(
        "raven_railgun_queries_total",
        "Total PIR queries served, labelled by instance + kind (single|batch|fanout)"
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
    metrics::describe_histogram!(
        "raven_railgun_fanout_shards",
        "Fan-out width (shards served per uploaded query), labelled by instance"
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
        "raven_railgun_consumer_last_scanned_block",
        "Per-instance highest scanned chain block height"
    );
    metrics::describe_gauge!(
        "raven_railgun_consumer_last_known_chain_head",
        "Per-instance last-known chain head"
    );
    metrics::describe_gauge!(
        "raven_railgun_consumer_indexer_lag_blocks",
        "Per-instance indexer lag (chain_head - last_scanned)"
    );
    metrics::describe_gauge!(
        "raven_railgun_consumer_blocks_since_last_applied_event",
        "Per-instance chain_head - last_applied; grows on a quiet chain by design"
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
    metrics::describe_gauge!(
        "raven_railgun_consumer_last_applied_leaf_block",
        "Per-instance height of the last block whose LEAVES were applied. Unlike          last_applied_block this is not advanced by an event that leaves the tree untouched"
    );
    metrics::describe_gauge!(
        "raven_railgun_consumer_consecutive_event_errors",
        "Per-instance length of the current consumer error run; the value /health/ready gates on"
    );
    metrics::describe_counter!(
        "raven_railgun_sessions_established_total",
        "Lifetime count of sticky-session establishment events, labelled by instance"
    );
    metrics::describe_counter!(
        "raven_railgun_session_evictions_total",
        "Lifetime count of session entries evicted, labelled by `reason` \
         (ttl = sticky entry swept past expires_at, lru = displaced on cap-pressure \
         upsert, expired = packing keys past TTL, removed = explicit removal, \
         flushed = dropped by the packing-key occupancy backstop)"
    );
    metrics::describe_counter!(
        "raven_railgun_batch_off_ladder_total",
        "Lifetime count of batches refused for an off-ladder length, labelled by instance"
    );
    metrics::describe_counter!(
        "raven_railgun_session_store_flushes_total",
        "Lifetime count of packing-key store flushes triggered by the occupancy cap"
    );
    metrics::describe_gauge!(
        "raven_railgun_session_store_occupancy",
        "Packing-key sets resident in the engine session store; the memory-occupancy figure"
    );
    metrics::describe_gauge!(
        "raven_railgun_session_store_serviceable",
        "Session handles the engine store will still resolve"
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
    metrics::describe_counter!(
        "raven_railgun_indexer_reorg_window_tip_hash_failed_total",
        "Lifetime count of scan ticks held because the chunk's tip block hash \
         could not be fetched, leaving the reorg window unable to span it"
    );

    // An unfired series must scrape as zero, not "no data"; dashboards alert on rate.
    metrics::counter!(
        "raven_railgun_session_evictions_total",
        "reason" => "ttl",
    )
    .increment(0);
    metrics::counter!("raven_railgun_indexer_reorg_window_persist_failed_total").increment(0);
    metrics::counter!("raven_railgun_indexer_reorg_window_tip_hash_failed_total").increment(0);
}

#[cfg(test)]
mod tests {
    use super::register_prometheus_descriptions;

    const TIP_HASH_FAILED: &str = "raven_railgun_indexer_reorg_window_tip_hash_failed_total";

    /// A described-but-unfired counter renders nothing, so the operator sees
    /// "no data" where a rate alert needs a zero series.
    #[test]
    fn indexer_tip_hash_failed_counter_scrapes_zero_before_it_fires() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, register_prometheus_descriptions);
        let rendered = handle.render();

        assert!(
            rendered.contains(&format!("# HELP {TIP_HASH_FAILED}")),
            "counter must register HELP text; rendered:\n{rendered}"
        );
        assert!(
            rendered.contains(&format!("{TIP_HASH_FAILED} 0")),
            "counter must scrape as zero before it fires; rendered:\n{rendered}"
        );
    }
}
