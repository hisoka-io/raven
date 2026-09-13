//! Round-robin RPC endpoint pool with per-endpoint rate limiting and circuit-breaker cooldowns.
//!
//! [`PinnedSession`] scopes to a SINGLE call, so its retries cannot straddle two nodes; what
//! makes a verification round's reads comparable is the shared `block_id`, not endpoint pinning.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use parking_lot::Mutex;

use crate::{ChainSource, IndexerError, Result, RpcChainSource};
use raven_railgun_core::RailgunEvent;

/// Default consecutive-failures threshold before the circuit breaker trips an endpoint.
pub const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;

/// Default cooldown TTL when an endpoint is errored or breaker-tripped.
pub const DEFAULT_COOLDOWN_SECS: u64 = 30;

/// At most one attempt per endpoint per call before returning [`PoolError::Exhausted`].
const MAX_RETRY_FACTOR: usize = 1;

/// Pool-selection strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolStrategy {
    RoundRobin,
    PrimaryWithFailover,
}

/// Per-endpoint health state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointHealth {
    Healthy,
    /// Errors observed but below the circuit-breaker threshold.
    Degraded,
    /// In cooldown; cleared when `Instant::now()` passes `until`.
    CoolingDown {
        until: Instant,
    },
}

/// Coarse classification of the RPC error for [`RpcEndpointPool::mark_endpoint_error`].
#[derive(Debug, Clone, Copy)]
pub enum ErrorKind {
    RateLimited,
    ServerError,
    Network,
    Other,
}

/// Error surface for [`RpcEndpointPool::select_for_request`] and pool-driven retries.
#[derive(thiserror::Error, Debug)]
pub enum PoolError {
    #[error("rpc endpoint pool exhausted: no healthy endpoint available")]
    Exhausted,
    #[error("rpc endpoint pool requires at least one endpoint")]
    Empty,
    #[error("rpc endpoint config: {url} has invalid rps={rps} burst={burst}; both must be >= 1")]
    InvalidEndpointConfig { url: String, rps: u32, burst: u32 },
    #[error(
        "rpc endpoint pool entries {first_index} and {duplicate_index} resolve to the same endpoint \
         {url_redacted}; remove the duplicate so failover uses independent providers"
    )]
    DuplicateEndpoint {
        first_index: usize,
        duplicate_index: usize,
        url_redacted: String,
    },
}

impl EndpointConfig {
    /// Returns [`PoolError::InvalidEndpointConfig`] if `rps`/`burst` are 0 or `url` is unparseable.
    pub fn validate(&self) -> std::result::Result<(), PoolError> {
        if self.rps == 0 || self.burst == 0 {
            return Err(PoolError::InvalidEndpointConfig {
                url: self.url.clone(),
                rps: self.rps,
                burst: self.burst,
            });
        }
        self.canonical_url()?;
        Ok(())
    }

    fn canonical_url(&self) -> std::result::Result<reqwest::Url, PoolError> {
        let mut url =
            self.url
                .parse::<reqwest::Url>()
                .map_err(|error| PoolError::InvalidEndpointConfig {
                    url: format!("{} (parse error: {error})", self.url),
                    rps: self.rps,
                    burst: self.burst,
                })?;
        url.set_fragment(None);
        Ok(url)
    }
}

impl From<PoolError> for IndexerError {
    fn from(e: PoolError) -> Self {
        IndexerError::Pool(e)
    }
}

/// Per-endpoint configuration consumed by [`RpcEndpointPool::new`].
#[derive(Debug, Clone)]
pub struct EndpointConfig {
    pub url: String,
    pub rps: u32,
    pub burst: u32,
}

/// Pool-wide configuration.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub strategy: PoolStrategy,
    pub cooldown_secs_on_error: u64,
    pub circuit_breaker_threshold: u32,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            strategy: PoolStrategy::RoundRobin,
            cooldown_secs_on_error: DEFAULT_COOLDOWN_SECS,
            circuit_breaker_threshold: CIRCUIT_BREAKER_THRESHOLD,
        }
    }
}

/// Mutable per-endpoint state kept under [`Mutex`].
#[derive(Debug)]
struct EndpointState {
    health: EndpointHealth,
    consecutive_errors: u32,
    in_flight: u32,
}

impl Default for EndpointState {
    fn default() -> Self {
        Self {
            health: EndpointHealth::Healthy,
            consecutive_errors: 0,
            in_flight: 0,
        }
    }
}

type EndpointLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// One RPC endpoint inside the pool.
pub struct RpcEndpoint {
    url: String,
    rps: u32,
    burst: u32,
    state: Mutex<EndpointState>,
    limiter: EndpointLimiter,
    /// Populated only after `eth_chainId` matched, so holding a provider IS the proof of
    /// verification. A separate flag beside this cell cannot hold that invariant: an
    /// unverified initialiser fills the cell and every later verified read then finds it
    /// populated and skips the probe.
    provider: tokio::sync::OnceCell<(u64, Arc<dyn alloy::providers::Provider + Send + Sync>)>,
}

impl std::fmt::Debug for RpcEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcEndpoint")
            .field("url_redacted", &redact_url(&self.url))
            .field("rps", &self.rps)
            .field("burst", &self.burst)
            .field("state", &*self.state.lock())
            .finish_non_exhaustive()
    }
}

impl RpcEndpoint {
    pub fn new(cfg: EndpointConfig) -> std::result::Result<Self, PoolError> {
        cfg.validate()?;
        let rps_nz = NonZeroU32::new(cfg.rps).ok_or_else(|| PoolError::InvalidEndpointConfig {
            url: cfg.url.clone(),
            rps: cfg.rps,
            burst: cfg.burst,
        })?;
        let burst_nz =
            NonZeroU32::new(cfg.burst).ok_or_else(|| PoolError::InvalidEndpointConfig {
                url: cfg.url.clone(),
                rps: cfg.rps,
                burst: cfg.burst,
            })?;
        let quota = Quota::per_second(rps_nz).allow_burst(burst_nz);
        Ok(Self {
            url: cfg.url,
            rps: cfg.rps,
            burst: cfg.burst,
            state: Mutex::new(EndpointState::default()),
            limiter: RateLimiter::direct(quota),
            provider: tokio::sync::OnceCell::new(),
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn url_redacted(&self) -> String {
        redact_url(&self.url)
    }

    /// The verified route to this endpoint's provider.
    ///
    /// Dials on first use and refuses to hand back a handle until `eth_chainId` answers
    /// `expected_chain_id`. Verification lives in the connection constructor rather than in
    /// selection, so it binds to the handle a request will actually run on and cannot be
    /// bypassed by reaching the endpoint some other way. `select_for_request` knows nothing
    /// about chain ids and must not: it serves consumers that have no chain source at all.
    ///
    /// The cell stores only on success, so a failed dial or a failed probe is retried on the
    /// next call rather than latched.
    ///
    /// # Errors
    /// [`IndexerError::ChainIdMismatch`] when the endpoint answers with a different chain,
    /// and the transport error otherwise.
    pub async fn verified_provider(
        &self,
        expected_chain_id: u64,
    ) -> Result<&(dyn alloy::providers::Provider + Send + Sync)> {
        let (verified_chain_id, provider) = self
            .provider
            .get_or_try_init(|| async {
                let url = self
                    .url
                    .parse::<reqwest::Url>()
                    .map_err(|e| IndexerError::InvalidRpcUrl(e.to_string()))?;
                let provider: Arc<dyn alloy::providers::Provider + Send + Sync> =
                    Arc::new(alloy::providers::ProviderBuilder::new().connect_http(url));
                // Bounded here, and labelled, because the typed timeout class drives
                // immediate endpoint cooldown and the hang tests assert the refusal.
                let actual = crate::with_rpc_timeout("eth_chainId probe", async {
                    alloy::providers::Provider::get_chain_id(provider.as_ref())
                        .await
                        .map_err(|e| IndexerError::provider("eth_chainId", e))
                })
                .await?;
                if actual != expected_chain_id {
                    return Err(IndexerError::ChainIdMismatch {
                        expected: expected_chain_id,
                        actual,
                    });
                }
                Ok::<_, IndexerError>((actual, provider))
            })
            .await?;
        // The cell caches the handle AND the identity it was verified against. Caching the
        // handle alone would hand a chain-1 provider to a caller asking for chain 137,
        // because `get_or_try_init` does not re-run its closure once populated.
        if *verified_chain_id != expected_chain_id {
            return Err(IndexerError::ChainIdMismatch {
                expected: expected_chain_id,
                actual: *verified_chain_id,
            });
        }
        Ok(provider.as_ref())
    }

    pub fn health(&self) -> EndpointHealth {
        self.state.lock().health
    }

    pub fn rps(&self) -> u32 {
        self.rps
    }

    pub fn burst(&self) -> u32 {
        self.burst
    }
}

pub struct RpcEndpointPool {
    endpoints: Vec<Arc<RpcEndpoint>>,
    next_idx: AtomicUsize,
    config: PoolConfig,
    sticky_sessions_opened: AtomicU64,
}

impl std::fmt::Debug for RpcEndpointPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcEndpointPool")
            .field("endpoints", &self.endpoints.len())
            .field("strategy", &self.config.strategy)
            .field(
                "cooldown_secs_on_error",
                &self.config.cooldown_secs_on_error,
            )
            .field(
                "sticky_sessions_opened",
                &self.sticky_sessions_opened.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

/// One entry in [`RpcEndpointPool::health_snapshot`].
#[derive(Debug, Clone)]
pub struct EndpointHealthSnapshot {
    pub url_redacted: String,
    pub health: EndpointHealth,
    pub in_flight: u32,
    pub rps: u32,
    pub burst: u32,
}

impl RpcEndpointPool {
    pub fn new(
        endpoint_configs: Vec<EndpointConfig>,
        config: PoolConfig,
    ) -> std::result::Result<Self, PoolError> {
        if endpoint_configs.is_empty() {
            return Err(PoolError::Empty);
        }
        let mut canonical_urls = Vec::with_capacity(endpoint_configs.len());
        for (duplicate_index, endpoint_config) in endpoint_configs.iter().enumerate() {
            endpoint_config.validate()?;
            let canonical_url = endpoint_config.canonical_url()?;
            if let Some(first_index) = canonical_urls
                .iter()
                .position(|seen: &reqwest::Url| seen == &canonical_url)
            {
                return Err(PoolError::DuplicateEndpoint {
                    first_index,
                    duplicate_index,
                    url_redacted: redact_url(canonical_url.as_str()),
                });
            }
            canonical_urls.push(canonical_url);
        }
        let endpoints: std::result::Result<Vec<_>, PoolError> = endpoint_configs
            .into_iter()
            .map(|c| RpcEndpoint::new(c).map(Arc::new))
            .collect();
        Ok(Self {
            endpoints: endpoints?,
            next_idx: AtomicUsize::new(0),
            config,
            sticky_sessions_opened: AtomicU64::new(0),
        })
    }

    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    pub fn endpoints(&self) -> &[Arc<RpcEndpoint>] {
        &self.endpoints
    }

    /// Select an endpoint, skipping those in cooldown or with an exhausted token bucket.
    pub fn select_for_request(&self) -> std::result::Result<Arc<RpcEndpoint>, PoolError> {
        self.select_for_request_excluding(&[])
    }

    fn select_for_request_excluding(
        &self,
        attempted: &[Arc<RpcEndpoint>],
    ) -> std::result::Result<Arc<RpcEndpoint>, PoolError> {
        let n = self.endpoints.len();
        let now = Instant::now();
        match self.config.strategy {
            PoolStrategy::RoundRobin => {
                for _ in 0..n {
                    let idx = self.next_idx.fetch_add(1, Ordering::Relaxed) % n;
                    let endpoint = match self.endpoints.get(idx) {
                        Some(e) => Arc::clone(e),
                        None => continue,
                    };
                    if Self::was_attempted(&endpoint, attempted) {
                        continue;
                    }
                    if Self::try_acquire(&endpoint, now) {
                        return Ok(endpoint);
                    }
                }
                Err(PoolError::Exhausted)
            }
            PoolStrategy::PrimaryWithFailover => {
                for idx in 0..n {
                    let endpoint = match self.endpoints.get(idx) {
                        Some(e) => Arc::clone(e),
                        None => continue,
                    };
                    if Self::was_attempted(&endpoint, attempted) {
                        continue;
                    }
                    if Self::try_acquire(&endpoint, now) {
                        return Ok(endpoint);
                    }
                }
                Err(PoolError::Exhausted)
            }
        }
    }

    fn was_attempted(endpoint: &Arc<RpcEndpoint>, attempted: &[Arc<RpcEndpoint>]) -> bool {
        attempted
            .iter()
            .any(|previous| Arc::ptr_eq(previous, endpoint))
    }

    fn try_acquire(endpoint: &Arc<RpcEndpoint>, now: Instant) -> bool {
        {
            let mut state = endpoint.state.lock();
            if let EndpointHealth::CoolingDown { until } = state.health {
                if now < until {
                    return false;
                }
                state.health = EndpointHealth::Degraded;
            }
        }
        if endpoint.limiter.check().is_err() {
            return false;
        }
        let mut state = endpoint.state.lock();
        state.in_flight = state.in_flight.saturating_add(1);
        true
    }

    /// Release the in-flight counter after a request completes. Must be called after every
    /// successful [`Self::select_for_request`].
    pub fn release_in_flight(&self, endpoint: &Arc<RpcEndpoint>) {
        let mut state = endpoint.state.lock();
        state.in_flight = state.in_flight.saturating_sub(1);
    }

    /// Mark an error. `RateLimited`/`ServerError`/`Network` force immediate cooldown;
    /// `Other` increments the breaker counter and trips at the threshold.
    pub fn mark_endpoint_error(&self, endpoint: &Arc<RpcEndpoint>, kind: ErrorKind) {
        let until = Instant::now() + Duration::from_secs(self.config.cooldown_secs_on_error.max(1));
        let mut state = endpoint.state.lock();
        state.consecutive_errors = state.consecutive_errors.saturating_add(1);
        let trip = match kind {
            ErrorKind::RateLimited | ErrorKind::ServerError | ErrorKind::Network => true,
            ErrorKind::Other => state.consecutive_errors >= self.config.circuit_breaker_threshold,
        };
        if trip {
            state.health = EndpointHealth::CoolingDown { until };
        } else {
            state.health = EndpointHealth::Degraded;
        }
    }

    pub fn mark_endpoint_success(&self, endpoint: &Arc<RpcEndpoint>) {
        let now = Instant::now();
        let mut state = endpoint.state.lock();
        state.consecutive_errors = 0;
        if let EndpointHealth::CoolingDown { until } = state.health {
            if now >= until {
                state.health = EndpointHealth::Healthy;
            }
        } else {
            state.health = EndpointHealth::Healthy;
        }
    }

    /// Per-endpoint health snapshot; URLs are redacted to host only.
    pub fn health_snapshot(&self) -> Vec<EndpointHealthSnapshot> {
        self.endpoints
            .iter()
            .map(|e| {
                let st = e.state.lock();
                EndpointHealthSnapshot {
                    url_redacted: e.url_redacted(),
                    health: st.health,
                    in_flight: st.in_flight,
                    rps: e.rps,
                    burst: e.burst,
                }
            })
            .collect()
    }

    /// Open a sticky session; the returned [`PinnedSession`] pins all calls to one endpoint.
    pub fn pinned_session(&self) -> std::result::Result<PinnedSession, PoolError> {
        let endpoint = self.select_for_request()?;
        self.sticky_sessions_opened.fetch_add(1, Ordering::Relaxed);
        Ok(PinnedSession { endpoint })
    }
}

/// Sticky-session handle; drops the in-flight counter on drop.
pub struct PinnedSession {
    endpoint: Arc<RpcEndpoint>,
}

impl std::fmt::Debug for PinnedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedSession")
            .field("endpoint_url_redacted", &self.endpoint.url_redacted())
            .finish_non_exhaustive()
    }
}

impl PinnedSession {
    pub fn endpoint(&self) -> &Arc<RpcEndpoint> {
        &self.endpoint
    }
}

impl Drop for PinnedSession {
    fn drop(&mut self) {
        let mut state = self.endpoint.state.lock();
        state.in_flight = state.in_flight.saturating_sub(1);
    }
}

/// A [`ChainSource`] backed by an [`RpcEndpointPool`].
pub struct PooledRpcChainSource {
    pool: Arc<RpcEndpointPool>,
    railgun_proxy: alloy::primitives::Address,
    chain_id: u64,
}

impl std::fmt::Debug for PooledRpcChainSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledRpcChainSource")
            .field("pool", &self.pool)
            .field("railgun_proxy", &self.railgun_proxy)
            .field("chain_id", &self.chain_id)
            .finish_non_exhaustive()
    }
}

impl PooledRpcChainSource {
    pub fn new(
        pool: Arc<RpcEndpointPool>,
        railgun_proxy: alloy::primitives::Address,
        chain_id: u64,
    ) -> Self {
        Self {
            pool,
            railgun_proxy,
            chain_id,
        }
    }

    pub fn pool(&self) -> &Arc<RpcEndpointPool> {
        &self.pool
    }

    pub fn railgun_proxy(&self) -> &alloy::primitives::Address {
        &self.railgun_proxy
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn pinned_at(&self) -> Result<PinnedSession> {
        self.pool.pinned_session().map_err(IndexerError::from)
    }

    /// Verify every endpoint's chain id before it may serve a request.
    ///
    /// Probing whichever endpoint `select_for_request` happened to return left the
    /// other n-1 unchecked while `run_with_pool` round-robins across all of them, so a
    /// foreign endpoint answered its share of `events_in_range` with `Ok(vec![])` and
    /// the worker advanced its cursor over the skipped range.
    ///
    /// A transport failure is NOT a verification failure. Propagating it aborted the whole
    /// loop, so one unreachable endpoint took the indexer down and bypassed the pool's own
    /// failover. Such an endpoint is marked errored and re-probed here on a later call.
    /// Selection knows nothing about chain ids and may still hand it out; the attempt then
    /// fails closed, because [`RpcEndpoint::verified_provider`] is the only route to a
    /// provider and it refuses until `eth_chainId` matches. Only a real chain-id mismatch,
    /// or having nothing left to use, is fatal.
    ///
    /// This eager sweep is what makes a foreign endpoint ANYWHERE in the pool fatal at the
    /// first call rather than whenever round-robin happens to reach it.
    async fn verify_chain_id_once(&self) -> Result<()> {
        let mut verified = 0usize;
        let mut unreachable: Vec<String> = Vec::new();
        let mut cooling = 0usize;
        for endpoint in self.pool.endpoints() {
            // A cooling-down endpoint cannot be SELECTED, so probing it buys nothing and costs a
            // full `RPC_TIMEOUT_SECS` per pooled call when it is black-holed rather than merely
            // erroring. Skipping is safe because verification is enforced AT USE:
            // `verified_provider` runs the probe inside the cell and compares the id the cell was
            // verified against, so an endpoint that becomes selectable is still refused there if
            // it answers for another chain. This sweep is early detection, not the admission gate.
            if matches!(endpoint.health(), EndpointHealth::CoolingDown { .. }) {
                cooling += 1;
                continue;
            }
            match endpoint.verified_provider(self.chain_id).await {
                // Deliberately does NOT mark success. Once the provider cell is populated
                // this returns from cache without touching the network, so treating it as
                // evidence of health would reset `consecutive_errors` on every request and
                // flip a Degraded endpoint back to Healthy with nothing behind it - which
                // both makes the Other-kind circuit breaker unreachable (`MAX_RETRY_FACTOR`
                // caps errors at one per call) and lets `/status` report a failing endpoint
                // as healthy. Health is attributed by the paths that make real calls,
                // `run_with_pool` and `run_pinned`, which mark both outcomes.
                Ok(_) => {
                    verified += 1;
                }
                Err(e @ IndexerError::ChainIdMismatch { .. }) => {
                    self.pool.mark_endpoint_error(endpoint, ErrorKind::Other);
                    return Err(e);
                }
                Err(e) => {
                    self.pool.mark_endpoint_error(endpoint, ErrorKind::Network);
                    unreachable.push(format!("{}: {e}", redact_url(endpoint.url())));
                }
            }
        }
        if verified == 0 {
            return Err(IndexerError::Unavailable {
                operation: format!(
                    "no RPC endpoint could be verified against chain {}; {cooling} skipped as \
                     cooling down, and every endpoint probed failed its eth_chainId check: [{}]. \
                     Add or restore an endpoint that answers with the configured chain id",
                    self.chain_id,
                    unreachable.join("; ")
                ),
            });
        }
        Ok(())
    }
}

pub(crate) fn classify_indexer_error(err: &IndexerError) -> ErrorKind {
    match err.failure_class() {
        crate::IndexerFailureClass::RateLimited => ErrorKind::RateLimited,
        crate::IndexerFailureClass::RemoteTransient
        | crate::IndexerFailureClass::RemoteServer
        | crate::IndexerFailureClass::RemoteMalformedResponse
        | crate::IndexerFailureClass::Unavailable => ErrorKind::ServerError,
        crate::IndexerFailureClass::Transport => ErrorKind::Network,
        crate::IndexerFailureClass::UnsupportedCapability
        | crate::IndexerFailureClass::InvalidRequest
        | crate::IndexerFailureClass::ProtocolDecode
        | crate::IndexerFailureClass::LocalConfiguration
        | crate::IndexerFailureClass::LocalContract
        | crate::IndexerFailureClass::ChainMismatch
        | crate::IndexerFailureClass::Integrity
        | crate::IndexerFailureClass::Closed
        | crate::IndexerFailureClass::RemoteOther
        | crate::IndexerFailureClass::LegacyOpaque => ErrorKind::Other,
    }
}

fn can_failover_to_distinct_endpoint(err: &IndexerError) -> bool {
    match err.failure_class() {
        crate::IndexerFailureClass::InvalidRequest
        | crate::IndexerFailureClass::LocalConfiguration
        | crate::IndexerFailureClass::LocalContract
        | crate::IndexerFailureClass::ChainMismatch
        | crate::IndexerFailureClass::Integrity
        | crate::IndexerFailureClass::Closed => false,
        crate::IndexerFailureClass::RateLimited
        | crate::IndexerFailureClass::RemoteTransient
        | crate::IndexerFailureClass::RemoteServer
        | crate::IndexerFailureClass::Transport
        | crate::IndexerFailureClass::UnsupportedCapability
        | crate::IndexerFailureClass::ProtocolDecode
        | crate::IndexerFailureClass::RemoteMalformedResponse
        | crate::IndexerFailureClass::Unavailable
        | crate::IndexerFailureClass::RemoteOther
        | crate::IndexerFailureClass::LegacyOpaque => true,
    }
}

async fn run_with_pool<F, Fut, T>(pool: &Arc<RpcEndpointPool>, mut op: F) -> Result<T>
where
    F: FnMut(Arc<RpcEndpoint>) -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let attempts = pool.len() * MAX_RETRY_FACTOR;
    let mut last_err: Option<IndexerError> = None;
    let mut attempted = Vec::with_capacity(attempts);
    for _ in 0..attempts {
        let endpoint = match pool.select_for_request_excluding(&attempted) {
            Ok(e) => e,
            Err(e) => {
                if last_err.is_none() {
                    last_err = Some(IndexerError::from(e));
                }
                break;
            }
        };
        let endpoint_for_release = Arc::clone(&endpoint);
        // Every pooled ChainSource method funnels through here, so the timeout lives at
        // the chokepoint: a new method cannot be added that forgets it.
        let result = crate::with_rpc_timeout("pooled rpc attempt", op(endpoint)).await;
        pool.release_in_flight(&endpoint_for_release);
        match result {
            Ok(v) => {
                pool.mark_endpoint_success(&endpoint_for_release);
                return Ok(v);
            }
            Err(e) => {
                let kind = classify_indexer_error(&e);
                pool.mark_endpoint_error(&endpoint_for_release, kind);
                attempted.push(endpoint_for_release);
                if !can_failover_to_distinct_endpoint(&e) {
                    return Err(e);
                }
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or(IndexerError::Unavailable {
        operation: "RPC endpoint pool retry chain".into(),
    }))
}

async fn run_pinned<F, Fut, T>(
    pool: &Arc<RpcEndpointPool>,
    endpoint: Arc<RpcEndpoint>,
    op: F,
) -> Result<T>
where
    F: FnOnce(Arc<RpcEndpoint>) -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let endpoint_for_marking = Arc::clone(&endpoint);
    // Same chokepoint reasoning as `run_with_pool`: a pinned attempt gets the same bound.
    let result = crate::with_rpc_timeout("pinned rpc attempt", op(endpoint)).await;
    match result {
        Ok(v) => {
            pool.mark_endpoint_success(&endpoint_for_marking);
            Ok(v)
        }
        Err(e) => {
            let kind = classify_indexer_error(&e);
            pool.mark_endpoint_error(&endpoint_for_marking, kind);
            Err(e)
        }
    }
}

#[async_trait]
impl ChainSource for PooledRpcChainSource {
    async fn latest_block(&self) -> Result<u64> {
        self.verify_chain_id_once().await?;
        let chain_id = self.chain_id;
        run_with_pool(&self.pool, |endpoint: Arc<RpcEndpoint>| async move {
            let provider = endpoint.verified_provider(chain_id).await?;
            let block = provider
                .get_block_by_number(alloy::eips::BlockNumberOrTag::Finalized)
                .await
                .map_err(|e| IndexerError::provider("get_block_by_number(finalized)", e))?;
            let block = block.ok_or(IndexerError::Unavailable {
                operation: "get_block_by_number(finalized): chain may be too young".into(),
            })?;
            Ok(block.header.number)
        })
        .await
    }

    async fn events_in_range(&self, from_block: u64, to_block: u64) -> Result<Vec<RailgunEvent>> {
        let proxy = self.railgun_proxy;
        if to_block < from_block {
            return Ok(Vec::new());
        }
        let filter = crate::event_filter(proxy, from_block, to_block)?;
        self.verify_chain_id_once().await?;
        let chain_id = self.chain_id;
        run_with_pool(&self.pool, move |endpoint: Arc<RpcEndpoint>| {
            let filter = filter.clone();
            async move {
                let provider = endpoint.verified_provider(chain_id).await?;
                let logs = provider
                    .get_logs(&filter)
                    .await
                    .map_err(|error| IndexerError::provider("get_logs", error))?;
                crate::decode_logs(logs)
            }
        })
        .await
    }

    async fn root_history(
        &self,
        tree_number: u32,
        merkle_root: [u8; 32],
        at: Option<alloy::eips::BlockId>,
    ) -> Result<bool> {
        self.verify_chain_id_once().await?;
        let chain_id = self.chain_id;
        let proxy = self.railgun_proxy;
        let body = move |endpoint: Arc<RpcEndpoint>| async move {
            let provider = endpoint.verified_provider(chain_id).await?;
            use alloy::sol_types::SolCall;
            let call = crate::abi::rootHistoryCall {
                tree: alloy::primitives::U256::from(tree_number),
                root: alloy::primitives::FixedBytes::<32>::from(merkle_root),
            };
            let calldata: alloy::primitives::Bytes = call.abi_encode().into();
            let tx = alloy::rpc::types::eth::TransactionRequest {
                to: Some(alloy::primitives::TxKind::Call(proxy)),
                input: alloy::rpc::types::eth::TransactionInput::new(calldata),
                ..Default::default()
            };
            let mut call_builder = provider.call(tx);
            if let Some(b) = at {
                call_builder = call_builder.block(b);
            }
            let result_bytes: alloy::primitives::Bytes = call_builder
                .await
                .map_err(|e| IndexerError::provider("eth_call rootHistory", e))?;
            let decoded = crate::abi::rootHistoryCall::abi_decode_returns(&result_bytes)
                .map_err(|e| IndexerError::Decode(format!("rootHistory decode: {e}")))?;
            Ok(decoded)
        };
        match at {
            Some(_) => {
                let session = self.pinned_at()?;
                let endpoint = Arc::clone(session.endpoint());
                let res = run_pinned(&self.pool, endpoint, body).await;
                drop(session);
                res
            }
            None => run_with_pool(&self.pool, body).await,
        }
    }

    async fn block_hash(&self, block_number: u64) -> Result<[u8; 32]> {
        self.verify_chain_id_once().await?;
        let chain_id = self.chain_id;
        run_with_pool(&self.pool, move |endpoint: Arc<RpcEndpoint>| async move {
            let provider = endpoint.verified_provider(chain_id).await?;
            let block = provider
                .get_block_by_number(alloy::eips::BlockNumberOrTag::Number(block_number))
                .await
                .map_err(|e| IndexerError::provider("get_block_by_number(number)", e))?;
            let block = block.ok_or(IndexerError::Unavailable {
                operation: format!("get_block_by_number({block_number})"),
            })?;
            Ok(block.header.hash.0)
        })
        .await
    }

    async fn merkle_root(&self, at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        self.verify_chain_id_once().await?;
        let chain_id = self.chain_id;
        let proxy = self.railgun_proxy;
        let body = move |endpoint: Arc<RpcEndpoint>| async move {
            let provider = endpoint.verified_provider(chain_id).await?;
            use alloy::sol_types::SolCall;
            let call = crate::abi::merkleRootCall {};
            let calldata: alloy::primitives::Bytes = call.abi_encode().into();
            let tx = alloy::rpc::types::eth::TransactionRequest {
                to: Some(alloy::primitives::TxKind::Call(proxy)),
                input: alloy::rpc::types::eth::TransactionInput::new(calldata),
                ..Default::default()
            };
            let mut call_builder = provider.call(tx);
            if let Some(b) = at {
                call_builder = call_builder.block(b);
            }
            let result_bytes: alloy::primitives::Bytes = call_builder
                .await
                .map_err(|e| IndexerError::provider("eth_call merkleRoot", e))?;
            let decoded = crate::abi::merkleRootCall::abi_decode_returns(&result_bytes)
                .map_err(|e| IndexerError::Decode(format!("merkleRoot decode: {e}")))?;
            Ok(decoded.0)
        };
        match at {
            Some(_) => {
                let session = self.pinned_at()?;
                let endpoint = Arc::clone(session.endpoint());
                let res = run_pinned(&self.pool, endpoint, body).await;
                drop(session);
                res
            }
            None => run_with_pool(&self.pool, body).await,
        }
    }

    async fn active_tree_number(&self, at: Option<alloy::eips::BlockId>) -> Result<u32> {
        self.verify_chain_id_once().await?;
        let chain_id = self.chain_id;
        let proxy = self.railgun_proxy;
        let body = move |endpoint: Arc<RpcEndpoint>| async move {
            let provider = endpoint.verified_provider(chain_id).await?;
            use alloy::sol_types::SolCall;
            let call = crate::abi::treeNumberCall {};
            let calldata: alloy::primitives::Bytes = call.abi_encode().into();
            let tx = alloy::rpc::types::eth::TransactionRequest {
                to: Some(alloy::primitives::TxKind::Call(proxy)),
                input: alloy::rpc::types::eth::TransactionInput::new(calldata),
                ..Default::default()
            };
            let mut call_builder = provider.call(tx);
            if let Some(b) = at {
                call_builder = call_builder.block(b);
            }
            let result_bytes: alloy::primitives::Bytes = call_builder
                .await
                .map_err(|e| IndexerError::provider("eth_call treeNumber", e))?;
            let decoded = crate::abi::treeNumberCall::abi_decode_returns(&result_bytes)
                .map_err(|e| IndexerError::Decode(format!("treeNumber decode: {e}")))?;
            Ok(u32::try_from(decoded).unwrap_or(u32::MAX))
        };
        match at {
            Some(_) => {
                let session = self.pinned_at()?;
                let endpoint = Arc::clone(session.endpoint());
                let res = run_pinned(&self.pool, endpoint, body).await;
                drop(session);
                res
            }
            None => run_with_pool(&self.pool, body).await,
        }
    }
}

/// Erases the single-vs-pooled-vs-WS-auto-fallback choice from the indexer
/// worker type signature. The two `AutoFallback*` variants concretize
/// [`crate::AutoFallbackChainSource`]'s fallback type parameter
/// (single-RPC vs pooled), since the generic doesn't erase to a single trait
/// object without a `Box<dyn ChainSource>` indirection that defeats per-method
/// static dispatch.
#[derive(Clone)]
pub enum DynChainSource {
    /// Single-endpoint legacy source.
    Single(Arc<RpcChainSource>),
    /// Multi-endpoint pooled source.
    Pooled(Arc<PooledRpcChainSource>),
    /// WS auto-fallback wrapping a single-RPC fallback.
    AutoFallbackSingle(Arc<crate::AutoFallbackChainSource<crate::WsChainSource, RpcChainSource>>),
    /// WS auto-fallback wrapping a pooled-RPC fallback.
    AutoFallbackPooled(
        Arc<crate::AutoFallbackChainSource<crate::WsChainSource, PooledRpcChainSource>>,
    ),
}

impl std::fmt::Debug for DynChainSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Single(_) => f.debug_tuple("DynChainSource::Single").finish(),
            Self::Pooled(_) => f.debug_tuple("DynChainSource::Pooled").finish(),
            Self::AutoFallbackSingle(_) => {
                f.debug_tuple("DynChainSource::AutoFallbackSingle").finish()
            }
            Self::AutoFallbackPooled(_) => {
                f.debug_tuple("DynChainSource::AutoFallbackPooled").finish()
            }
        }
    }
}

#[async_trait]
impl ChainSource for DynChainSource {
    async fn latest_block(&self) -> Result<u64> {
        match self {
            Self::Single(s) => s.latest_block().await,
            Self::Pooled(s) => s.latest_block().await,
            Self::AutoFallbackSingle(s) => s.latest_block().await,
            Self::AutoFallbackPooled(s) => s.latest_block().await,
        }
    }
    async fn events_in_range(&self, from: u64, to: u64) -> Result<Vec<RailgunEvent>> {
        match self {
            Self::Single(s) => s.events_in_range(from, to).await,
            Self::Pooled(s) => s.events_in_range(from, to).await,
            Self::AutoFallbackSingle(s) => s.events_in_range(from, to).await,
            Self::AutoFallbackPooled(s) => s.events_in_range(from, to).await,
        }
    }
    async fn root_history(
        &self,
        tree_number: u32,
        merkle_root: [u8; 32],
        at: Option<alloy::eips::BlockId>,
    ) -> Result<bool> {
        match self {
            Self::Single(s) => s.root_history(tree_number, merkle_root, at).await,
            Self::Pooled(s) => s.root_history(tree_number, merkle_root, at).await,
            Self::AutoFallbackSingle(s) => s.root_history(tree_number, merkle_root, at).await,
            Self::AutoFallbackPooled(s) => s.root_history(tree_number, merkle_root, at).await,
        }
    }
    async fn block_hash(&self, block_number: u64) -> Result<[u8; 32]> {
        match self {
            Self::Single(s) => s.block_hash(block_number).await,
            Self::Pooled(s) => s.block_hash(block_number).await,
            Self::AutoFallbackSingle(s) => s.block_hash(block_number).await,
            Self::AutoFallbackPooled(s) => s.block_hash(block_number).await,
        }
    }
    async fn merkle_root(&self, at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        match self {
            Self::Single(s) => s.merkle_root(at).await,
            Self::Pooled(s) => s.merkle_root(at).await,
            Self::AutoFallbackSingle(s) => s.merkle_root(at).await,
            Self::AutoFallbackPooled(s) => s.merkle_root(at).await,
        }
    }
    async fn active_tree_number(&self, at: Option<alloy::eips::BlockId>) -> Result<u32> {
        match self {
            Self::Single(s) => s.active_tree_number(at).await,
            Self::Pooled(s) => s.active_tree_number(at).await,
            Self::AutoFallbackSingle(s) => s.active_tree_number(at).await,
            Self::AutoFallbackPooled(s) => s.active_tree_number(at).await,
        }
    }
}

/// Strip path, query, and userinfo from a URL, leaving `scheme://host[:port]`.
fn redact_url(s: &str) -> String {
    match s.parse::<reqwest::Url>() {
        Ok(u) => match (u.scheme(), u.host_str(), u.port()) {
            (scheme, Some(host), Some(port)) => format!("{scheme}://{host}:{port}"),
            (scheme, Some(host), None) => format!("{scheme}://{host}"),
            _ => "<unparseable>".to_owned(),
        },
        Err(_) => "<unparseable>".to_owned(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn make_pool(n: usize, strategy: PoolStrategy) -> Arc<RpcEndpointPool> {
        let cfgs = (0..n)
            .map(|i| EndpointConfig {
                url: format!("http://endpoint-{i}.example/"),
                rps: 100,
                burst: 100,
            })
            .collect();
        Arc::new(
            RpcEndpointPool::new(
                cfgs,
                PoolConfig {
                    strategy,
                    ..PoolConfig::default()
                },
            )
            .expect("pool"),
        )
    }

    #[test]
    fn empty_pool_rejected() {
        let err = RpcEndpointPool::new(Vec::new(), PoolConfig::default()).expect_err("must fail");
        assert!(matches!(err, PoolError::Empty));
    }

    #[test]
    fn validate_rejects_unparseable_url() {
        let cfg = EndpointConfig {
            url: "not a url at all".to_owned(),
            rps: 10,
            burst: 10,
        };
        let err = cfg.validate().expect_err("malformed url must error");
        match err {
            PoolError::InvalidEndpointConfig { url, rps, burst } => {
                assert!(
                    url.contains("parse error"),
                    "must surface parse failure; got {url}"
                );
                assert_eq!(rps, 10);
                assert_eq!(burst, 10);
            }
            other => panic!("expected InvalidEndpointConfig, got {other:?}"),
        }
    }

    #[test]
    fn pool_rejects_an_exact_duplicate_endpoint() {
        let url = "https://rpc.example/v1".to_owned();
        let error = RpcEndpointPool::new(
            vec![
                EndpointConfig {
                    url: url.clone(),
                    rps: 10,
                    burst: 10,
                },
                EndpointConfig {
                    url,
                    rps: 20,
                    burst: 20,
                },
            ],
            PoolConfig::default(),
        )
        .expect_err("one physical provider must not occupy two retry slots");
        assert!(
            error.to_string().contains("remove the duplicate"),
            "duplicate error must name the operator action: {error}"
        );

        match error {
            PoolError::DuplicateEndpoint {
                first_index,
                duplicate_index,
                url_redacted,
            } => {
                assert_eq!((first_index, duplicate_index), (0, 1));
                assert_eq!(url_redacted, "https://rpc.example");
            }
            other => panic!("expected DuplicateEndpoint, got {other:?}"),
        }
    }

    #[test]
    fn pool_rejects_urls_the_parser_normalizes_to_one_endpoint() {
        let first = "HTTP://RPC.EXAMPLE:80/a/../v1";
        let second = "http://rpc.example/v1";
        assert_eq!(
            first.parse::<reqwest::Url>().expect("first URL"),
            second.parse::<reqwest::Url>().expect("second URL"),
            "fixture must be equivalent under the production URL parser"
        );

        let error = RpcEndpointPool::new(
            [first, second]
                .map(|url| EndpointConfig {
                    url: url.to_owned(),
                    rps: 10,
                    burst: 10,
                })
                .to_vec(),
            PoolConfig::default(),
        )
        .expect_err("parser-equivalent URLs must not create distinct retry slots");

        assert!(matches!(
            error,
            PoolError::DuplicateEndpoint {
                first_index: 0,
                duplicate_index: 1,
                ..
            }
        ));
    }

    #[test]
    fn round_robin_distributes_evenly() {
        let pool = make_pool(3, PoolStrategy::RoundRobin);
        let mut counts = [0u32; 3];
        for _ in 0..9 {
            let endpoint = pool.select_for_request().expect("select");
            for (i, e) in pool.endpoints().iter().enumerate() {
                if Arc::ptr_eq(e, &endpoint) {
                    if let Some(slot) = counts.get_mut(i) {
                        *slot += 1;
                    }
                }
            }
            pool.release_in_flight(&endpoint);
        }
        assert_eq!(counts, [3, 3, 3]);
    }

    #[test]
    fn primary_with_failover_prefers_index_zero() {
        let pool = make_pool(3, PoolStrategy::PrimaryWithFailover);
        for _ in 0..9 {
            let endpoint = pool.select_for_request().expect("select");
            assert!(Arc::ptr_eq(
                &endpoint,
                pool.endpoints().first().expect("zero")
            ));
            pool.release_in_flight(&endpoint);
        }
    }

    #[test]
    fn both_strategies_exclude_an_endpoint_already_tried_by_the_operation() {
        for strategy in [PoolStrategy::RoundRobin, PoolStrategy::PrimaryWithFailover] {
            let pool = make_pool(3, strategy);
            let first = pool.select_for_request().expect("first endpoint");
            pool.release_in_flight(&first);
            pool.next_idx.store(0, Ordering::Relaxed);

            let alternate = pool
                .select_for_request_excluding(&[Arc::clone(&first)])
                .expect("distinct alternate");
            assert!(!Arc::ptr_eq(&first, &alternate), "strategy={strategy:?}");
            pool.release_in_flight(&alternate);
        }
    }

    #[test]
    fn classification_picks_rate_limited_for_429() {
        let err = IndexerError::provider(
            "test",
            alloy::transports::TransportErrorKind::http_error(429, String::new()),
        );
        assert!(matches!(
            classify_indexer_error(&err),
            ErrorKind::RateLimited
        ));
    }

    #[test]
    fn classification_picks_server_error_for_5xx() {
        let err = IndexerError::provider(
            "test",
            alloy::transports::TransportErrorKind::http_error(503, String::new()),
        );
        assert!(matches!(
            classify_indexer_error(&err),
            ErrorKind::ServerError
        ));
    }

    #[test]
    fn classification_picks_network_for_timeout() {
        let err = IndexerError::Timeout { operation: "test" };
        assert!(matches!(classify_indexer_error(&err), ErrorKind::Network));
    }

    #[test]
    fn redact_url_strips_path_and_query() {
        let s = "https://eth.example.com/v2/SOME-API-KEY?token=abc";
        assert_eq!(redact_url(s), "https://eth.example.com");
    }

    #[test]
    fn redact_url_keeps_port() {
        let s = "http://eth.example.com:8545/v2/key";
        assert_eq!(redact_url(s), "http://eth.example.com:8545");
    }
}
