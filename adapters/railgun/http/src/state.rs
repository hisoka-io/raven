//! Application state shared across handlers.

use std::collections::HashMap;
use std::sync::Arc;

use raven_railgun_core::InstanceId;
use raven_railgun_engine::{Engine, PirScheme};
use tokio::sync::Semaphore;

use crate::auth::SessionMap;
use crate::config::HttpConfig;
use crate::global_prometheus_handle;

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
}

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
}
