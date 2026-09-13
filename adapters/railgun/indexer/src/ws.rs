//! WebSocket-backed [`ChainSource`] with automatic fallback to the polling [`crate::RpcChainSource`].
//!
//! [`AutoFallbackChainSource`] falls back on transport errors and re-probes WS after
//! a floor of [`MIN_POLLING_DURATION`] to prevent mode oscillation.
//!
//! Wired in `serve-production` via `--ws-endpoint <URL>`; the constructed
//! [`AutoFallbackChainSource`] wraps a [`WsChainSource`] over the configured
//! fallback (single-RPC or `RpcEndpointPool`). The current transport mode is
//! mirrored to `/v1/health/ready` as `chain_source_mode`. Without
//! `--ws-endpoint`, the binary constructs a plain [`RpcChainSource`]
//! (polling-only).

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use raven_railgun_core::RailgunEvent;
use tokio::sync::RwLock;

use crate::{ChainSource, IndexerError, Result, RpcChainSource};

/// Per-attempt WS reconnect backoff cap.
pub const WS_RECONNECT_CAP_SECS: u64 = 30;

/// Minimum dwell time in `Polling` mode before re-attempting WS.
pub const MIN_POLLING_DURATION: Duration = Duration::from_secs(60);

/// Operator-readable mode of the [`AutoFallbackChainSource`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSourceMode {
    Subscribe,
    Polling,
}

/// A `WsConnect` that counts dials.
///
/// alloy re-dials underneath a live provider handle (`alloy-pubsub` `service.rs:61` calls
/// `try_reconnect`), and the consumer sees neither an error nor a stream close. A chain-id
/// check performed once at construction therefore describes the FIRST socket only, and a URL
/// repointed onto another chain is served unverified from then on. The counter turns that
/// invisible event into an observable one.
///
/// Only `connect` is overridden: `PubSubConnect::try_reconnect` defaults to `self.connect()`,
/// so the reconnect path runs through this same increment.
#[derive(Clone, Debug)]
struct CountedWsConnect {
    inner: alloy::providers::WsConnect,
    dials: Arc<std::sync::atomic::AtomicU64>,
}

impl alloy::pubsub::PubSubConnect for CountedWsConnect {
    fn is_local(&self) -> bool {
        self.inner.is_local()
    }

    async fn connect(&self) -> alloy::transports::TransportResult<alloy::pubsub::ConnectionHandle> {
        // Bumped BEFORE the dial so a failed re-dial still invalidates: a handle whose
        // socket died is not evidence about the chain behind the URL either.
        self.dials.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.inner.connect().await
    }
}

/// WS-backed chain source wrapping an alloy `connect_ws` provider.
///
/// Currently invokes methods one-shot over WS transport; long-lived subscriptions are handled
/// by [`crate::subscribe::SubscribeWorker`].
pub struct WsChainSource {
    rpc_url: String,
    railgun_proxy: alloy::primitives::Address,
    chain_id: u64,
    /// Dial counter shared with the connector, so a re-dial is visible here.
    dials: Arc<std::sync::atomic::AtomicU64>,
    /// The handle and the dial count it was verified at. A `OnceCell` cannot express this:
    /// it has no way to invalidate, so the verification would outlive its connection.
    provider: RwLock<Option<(u64, Arc<dyn alloy::providers::Provider + Send + Sync>)>>,
}

impl std::fmt::Debug for WsChainSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsChainSource")
            .field("rpc_url", &self.rpc_url)
            .field("railgun_proxy", &self.railgun_proxy)
            .field("chain_id", &self.chain_id)
            .field(
                "dials",
                &self.dials.load(std::sync::atomic::Ordering::Acquire),
            )
            .finish_non_exhaustive()
    }
}

impl WsChainSource {
    #[must_use]
    pub fn new(
        rpc_url: impl Into<String>,
        railgun_proxy: alloy::primitives::Address,
        chain_id: u64,
    ) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            railgun_proxy,
            chain_id,
            dials: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            provider: RwLock::new(None),
        }
    }

    #[must_use]
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    #[must_use]
    pub fn railgun_proxy(&self) -> &alloy::primitives::Address {
        &self.railgun_proxy
    }

    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// A provider whose chain id was verified for the connection it is currently on.
    ///
    /// Re-verifies whenever the dial counter has moved since the handle was checked, which
    /// is what makes this survive alloy's silent re-dial. The probe runs on the EXISTING
    /// handle rather than dropping it: alloy has already reconnected and re-subscribed, and
    /// dropping would kill live subscriptions to prove something a query can prove.
    async fn verified_provider(&self) -> Result<Arc<dyn alloy::providers::Provider + Send + Sync>> {
        use std::sync::atomic::Ordering;

        if let Some((seen_at, provider)) = self.provider.read().await.as_ref() {
            if *seen_at == self.dials.load(Ordering::Acquire) {
                return Ok(Arc::clone(provider));
            }
        }

        let mut slot = self.provider.write().await;
        // Another task may have refreshed while this one waited for the write lock.
        if let Some((seen_at, provider)) = slot.as_ref() {
            if *seen_at == self.dials.load(Ordering::Acquire) {
                return Ok(Arc::clone(provider));
            }
        }

        // A handle already in `slot` means the socket was replaced underneath it, so the
        // chain behind the URL is re-checked on the handle alloy has already reconnected.
        let provider: Arc<dyn alloy::providers::Provider + Send + Sync> =
            if let Some((_, existing)) = slot.take() {
                existing
            } else {
                let connect = CountedWsConnect {
                    inner: alloy::providers::WsConnect::new(self.rpc_url.clone()),
                    dials: Arc::clone(&self.dials),
                };
                Arc::new(
                    alloy::providers::ProviderBuilder::new()
                        .connect_pubsub_with(connect)
                        .await
                        .map_err(|e| IndexerError::provider("WS connect", e))?,
                )
            };

        let dialled_at = self.dials.load(Ordering::Acquire);
        let actual = alloy::providers::Provider::get_chain_id(provider.as_ref())
            .await
            .map_err(|e| IndexerError::provider("eth_chainId", e))?;
        if actual != self.chain_id {
            return Err(IndexerError::ChainIdMismatch {
                expected: self.chain_id,
                actual,
            });
        }
        // An answer that crossed a re-dial says nothing about the socket now in use, so it
        // is not stored; the next call re-verifies. `slot` stays None on every failure
        // path, which is what preserves retry-on-failure against a dead URL.
        if dialled_at == self.dials.load(Ordering::Acquire) {
            *slot = Some((dialled_at, Arc::clone(&provider)));
        }
        Ok(provider)
    }
}

#[async_trait]
impl ChainSource for WsChainSource {
    async fn latest_block(&self) -> Result<u64> {
        crate::with_rpc_timeout(
            "ws latest_block",
            Box::pin(async {
                let p = self.verified_provider().await?;
                let block = p
                    .get_block_by_number(alloy::eips::BlockNumberOrTag::Finalized)
                    .await
                    .map_err(|e| IndexerError::provider("get_block_by_number(finalized)", e))?;
                let block = block.ok_or(IndexerError::Unavailable {
                    operation: "get_block_by_number(finalized): chain may be too young".into(),
                })?;
                Ok(block.header.number)
            }),
        )
        .await
    }

    async fn events_in_range(&self, from_block: u64, to_block: u64) -> Result<Vec<RailgunEvent>> {
        crate::with_rpc_timeout(
            "ws events_in_range",
            Box::pin(async {
                crate::fetch_events_in_range(
                    self.railgun_proxy,
                    from_block,
                    to_block,
                    |filter| async move {
                        let provider = self.verified_provider().await?;
                        provider
                            .get_logs(&filter)
                            .await
                            .map_err(|error| IndexerError::provider("get_logs", error))
                    },
                )
                .await
            }),
        )
        .await
    }

    async fn root_history(
        &self,
        tree_number: u32,
        merkle_root: [u8; 32],
        at: Option<alloy::eips::BlockId>,
    ) -> Result<bool> {
        crate::with_rpc_timeout(
            "ws root_history",
            Box::pin(async {
                use alloy::sol_types::SolCall;
                let p = self.verified_provider().await?;
                let call = crate::abi::rootHistoryCall {
                    tree: alloy::primitives::U256::from(tree_number),
                    root: alloy::primitives::FixedBytes::<32>::from(merkle_root),
                };
                let calldata: alloy::primitives::Bytes = call.abi_encode().into();
                let tx = alloy::rpc::types::eth::TransactionRequest {
                    to: Some(alloy::primitives::TxKind::Call(self.railgun_proxy)),
                    input: alloy::rpc::types::eth::TransactionInput::new(calldata),
                    ..Default::default()
                };
                let mut call_builder = p.call(tx);
                if let Some(b) = at {
                    call_builder = call_builder.block(b);
                }
                let result_bytes: alloy::primitives::Bytes = call_builder
                    .await
                    .map_err(|e| IndexerError::provider("eth_call rootHistory", e))?;
                let decoded = crate::abi::rootHistoryCall::abi_decode_returns(&result_bytes)
                    .map_err(|e| IndexerError::Decode(format!("rootHistory decode: {e}")))?;
                Ok(decoded)
            }),
        )
        .await
    }

    async fn block_hash(&self, block_number: u64) -> Result<[u8; 32]> {
        crate::with_rpc_timeout(
            "ws block_hash",
            Box::pin(async {
                let p = self.verified_provider().await?;
                let block = p
                    .get_block_by_number(alloy::eips::BlockNumberOrTag::Number(block_number))
                    .await
                    .map_err(|e| IndexerError::provider("get_block_by_number(number)", e))?;
                let block = block.ok_or(IndexerError::Unavailable {
                    operation: format!("get_block_by_number({block_number})"),
                })?;
                Ok(block.header.hash.0)
            }),
        )
        .await
    }

    async fn merkle_root(&self, at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        crate::with_rpc_timeout(
            "ws merkle_root",
            Box::pin(async {
                use alloy::sol_types::SolCall;
                let p = self.verified_provider().await?;
                let call = crate::abi::merkleRootCall {};
                let calldata: alloy::primitives::Bytes = call.abi_encode().into();
                let tx = alloy::rpc::types::eth::TransactionRequest {
                    to: Some(alloy::primitives::TxKind::Call(self.railgun_proxy)),
                    input: alloy::rpc::types::eth::TransactionInput::new(calldata),
                    ..Default::default()
                };
                let mut call_builder = p.call(tx);
                if let Some(b) = at {
                    call_builder = call_builder.block(b);
                }
                let result_bytes: alloy::primitives::Bytes = call_builder
                    .await
                    .map_err(|e| IndexerError::provider("eth_call merkleRoot", e))?;
                let decoded = crate::abi::merkleRootCall::abi_decode_returns(&result_bytes)
                    .map_err(|e| IndexerError::Decode(format!("merkleRoot decode: {e}")))?;
                Ok(decoded.0)
            }),
        )
        .await
    }

    async fn active_tree_number(&self, at: Option<alloy::eips::BlockId>) -> Result<u32> {
        crate::with_rpc_timeout(
            "ws active_tree_number",
            Box::pin(async {
                use alloy::sol_types::SolCall;
                let p = self.verified_provider().await?;
                let call = crate::abi::treeNumberCall {};
                let calldata: alloy::primitives::Bytes = call.abi_encode().into();
                let tx = alloy::rpc::types::eth::TransactionRequest {
                    to: Some(alloy::primitives::TxKind::Call(self.railgun_proxy)),
                    input: alloy::rpc::types::eth::TransactionInput::new(calldata),
                    ..Default::default()
                };
                let mut call_builder = p.call(tx);
                if let Some(b) = at {
                    call_builder = call_builder.block(b);
                }
                let result_bytes: alloy::primitives::Bytes = call_builder
                    .await
                    .map_err(|e| IndexerError::provider("eth_call treeNumber", e))?;
                let decoded = crate::abi::treeNumberCall::abi_decode_returns(&result_bytes)
                    .map_err(|e| IndexerError::Decode(format!("treeNumber decode: {e}")))?;
                let tree_u32 = u32::try_from(decoded).unwrap_or(u32::MAX);
                Ok(tree_u32)
            }),
        )
        .await
    }
}

/// Mutable mode + reconnect-budget state shared across calls.
#[derive(Debug)]
struct AutoFallbackState {
    mode: ChainSourceMode,
    polling_since: Option<std::time::Instant>,
    reconnect_attempt: u32,
}

/// Wrapper that prefers a `WsChainSource` and falls back to polling on transport errors.
pub struct AutoFallbackChainSource<P, F>
where
    P: ChainSource,
    F: ChainSource,
{
    primary: Arc<P>,
    fallback: Arc<F>,
    state: RwLock<AutoFallbackState>,
}

impl<P, F> std::fmt::Debug for AutoFallbackChainSource<P, F>
where
    P: ChainSource + std::fmt::Debug,
    F: ChainSource + std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutoFallbackChainSource")
            .field("primary", &self.primary)
            .field("fallback", &self.fallback)
            .finish_non_exhaustive()
    }
}

impl<P, F> AutoFallbackChainSource<P, F>
where
    P: ChainSource,
    F: ChainSource,
{
    pub fn new(primary: Arc<P>, fallback: Arc<F>) -> Self {
        Self {
            primary,
            fallback,
            state: RwLock::new(AutoFallbackState {
                mode: ChainSourceMode::Subscribe,
                polling_since: None,
                reconnect_attempt: 0,
            }),
        }
    }

    pub async fn mode(&self) -> ChainSourceMode {
        self.state.read().await.mode
    }

    pub fn primary(&self) -> &Arc<P> {
        &self.primary
    }

    pub fn fallback(&self) -> &Arc<F> {
        &self.fallback
    }

    async fn should_attempt_ws(&self) -> bool {
        let s = self.state.read().await;
        match s.mode {
            ChainSourceMode::Subscribe => true,
            ChainSourceMode::Polling => s
                .polling_since
                .is_some_and(|since| since.elapsed() >= MIN_POLLING_DURATION),
        }
    }

    async fn record_ws_success(&self) {
        let mut s = self.state.write().await;
        s.mode = ChainSourceMode::Subscribe;
        s.polling_since = None;
        s.reconnect_attempt = 0;
    }

    async fn record_ws_failure(&self) {
        let mut s = self.state.write().await;
        s.mode = ChainSourceMode::Polling;
        if s.polling_since.is_none() {
            s.polling_since = Some(std::time::Instant::now());
        }
        s.reconnect_attempt = s.reconnect_attempt.saturating_add(1);
    }

    pub async fn next_reconnect_backoff(&self) -> Duration {
        let s = self.state.read().await;
        let attempt = s.reconnect_attempt.min(31);
        let secs = 1u64.saturating_mul(1u64 << attempt);
        Duration::from_secs(secs.min(WS_RECONNECT_CAP_SECS))
    }
}

pub(crate) fn is_ws_fallback_error(err: &IndexerError) -> bool {
    matches!(
        err.failure_class(),
        crate::IndexerFailureClass::Transport
            | crate::IndexerFailureClass::UnsupportedCapability
            | crate::IndexerFailureClass::ProtocolDecode
            | crate::IndexerFailureClass::RemoteMalformedResponse
    )
}

#[async_trait]
impl<P, F> ChainSource for AutoFallbackChainSource<P, F>
where
    P: ChainSource,
    F: ChainSource,
{
    async fn latest_block(&self) -> Result<u64> {
        if self.should_attempt_ws().await {
            match self.primary.latest_block().await {
                Ok(v) => {
                    self.record_ws_success().await;
                    return Ok(v);
                }
                Err(e) if is_ws_fallback_error(&e) => {
                    tracing::warn!(error = %e, "WS latest_block failed; falling back");
                    self.record_ws_failure().await;
                }
                Err(e) => return Err(e),
            }
        }
        self.fallback.latest_block().await
    }

    async fn events_in_range(&self, from_block: u64, to_block: u64) -> Result<Vec<RailgunEvent>> {
        if self.should_attempt_ws().await {
            match self.primary.events_in_range(from_block, to_block).await {
                Ok(v) => {
                    self.record_ws_success().await;
                    return Ok(v);
                }
                Err(e) if is_ws_fallback_error(&e) => {
                    tracing::warn!(error = %e, "WS events_in_range failed; falling back");
                    self.record_ws_failure().await;
                }
                Err(e) => return Err(e),
            }
        }
        self.fallback.events_in_range(from_block, to_block).await
    }

    async fn root_history(
        &self,
        tree_number: u32,
        merkle_root: [u8; 32],
        at: Option<alloy::eips::BlockId>,
    ) -> Result<bool> {
        if self.should_attempt_ws().await {
            match self
                .primary
                .root_history(tree_number, merkle_root, at)
                .await
            {
                Ok(v) => {
                    self.record_ws_success().await;
                    return Ok(v);
                }
                Err(e) if is_ws_fallback_error(&e) => {
                    tracing::warn!(error = %e, "WS root_history failed; falling back");
                    self.record_ws_failure().await;
                }
                Err(e) => return Err(e),
            }
        }
        self.fallback
            .root_history(tree_number, merkle_root, at)
            .await
    }

    async fn block_hash(&self, block_number: u64) -> Result<[u8; 32]> {
        if self.should_attempt_ws().await {
            match self.primary.block_hash(block_number).await {
                Ok(v) => {
                    self.record_ws_success().await;
                    return Ok(v);
                }
                Err(e) if is_ws_fallback_error(&e) => {
                    tracing::warn!(error = %e, "WS block_hash failed; falling back");
                    self.record_ws_failure().await;
                }
                Err(e) => return Err(e),
            }
        }
        self.fallback.block_hash(block_number).await
    }

    async fn merkle_root(&self, at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        if self.should_attempt_ws().await {
            match self.primary.merkle_root(at).await {
                Ok(v) => {
                    self.record_ws_success().await;
                    return Ok(v);
                }
                Err(e) if is_ws_fallback_error(&e) => {
                    tracing::warn!(error = %e, "WS merkle_root failed; falling back");
                    self.record_ws_failure().await;
                }
                Err(e) => return Err(e),
            }
        }
        self.fallback.merkle_root(at).await
    }

    async fn active_tree_number(&self, at: Option<alloy::eips::BlockId>) -> Result<u32> {
        if self.should_attempt_ws().await {
            match self.primary.active_tree_number(at).await {
                Ok(v) => {
                    self.record_ws_success().await;
                    return Ok(v);
                }
                Err(e) if is_ws_fallback_error(&e) => {
                    tracing::warn!(
                        error = %e,
                        "WS active_tree_number failed; falling back"
                    );
                    self.record_ws_failure().await;
                }
                Err(e) => return Err(e),
            }
        }
        self.fallback.active_tree_number(at).await
    }
}

#[must_use]
pub fn ws_with_rpc_fallback(
    ws_url: impl Into<String>,
    rpc_url: impl Into<String>,
    railgun_proxy: alloy::primitives::Address,
    start_block: u64,
    chain_id: u64,
) -> AutoFallbackChainSource<WsChainSource, RpcChainSource> {
    let ws = Arc::new(WsChainSource::new(ws_url, railgun_proxy, chain_id));
    let rpc = Arc::new(RpcChainSource::new(
        rpc_url,
        railgun_proxy,
        start_block,
        chain_id,
    ));
    AutoFallbackChainSource::new(ws, rpc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider_error(source: alloy::transports::TransportError) -> IndexerError {
        IndexerError::Provider {
            operation: "policy table",
            source,
        }
    }

    fn error_response(code: i64, message: &'static str) -> alloy::transports::TransportError {
        let parse_error = serde_json::from_str::<serde_json::Value>("{")
            .expect_err("the malformed control must fail JSON decoding");
        alloy::transports::TransportError::deser_err(
            parse_error,
            format!(r#"{{"code":{code},"message":"{message}"}}"#),
        )
    }

    fn assert_policy(
        label: &str,
        error: IndexerError,
        class: crate::IndexerFailureClass,
        non_retryable: bool,
        pool_kind: crate::rpc_pool::ErrorKind,
        ws_fallback: bool,
    ) {
        assert_eq!(error.failure_class(), class, "{label}: factual class");
        assert_eq!(
            crate::is_non_retryable(&error),
            non_retryable,
            "{label}: single-endpoint retry policy"
        );
        assert_eq!(
            std::mem::discriminant(&crate::rpc_pool::classify_indexer_error(&error)),
            std::mem::discriminant(&pool_kind),
            "{label}: pool health policy"
        );
        assert_eq!(
            is_ws_fallback_error(&error),
            ws_fallback,
            "{label}: WS fallback policy"
        );
    }

    #[test]
    fn every_indexer_and_alloy_error_variant_has_an_explicit_layer_policy() {
        use crate::rpc_pool::{ErrorKind, PoolError};
        use crate::{IndexerFailureClass as C, SubscriptionStream};
        use alloy::transports::{RpcError, TransportErrorKind};

        let cases = [
            (
                "legacy rpc",
                IndexerError::Rpc("opaque".into()),
                C::LegacyOpaque,
                false,
                ErrorKind::Other,
                false,
            ),
            (
                "legacy alloy",
                IndexerError::Alloy("opaque".into()),
                C::LegacyOpaque,
                false,
                ErrorKind::Other,
                false,
            ),
            (
                "application decode",
                IndexerError::Decode("malformed event".into()),
                C::ProtocolDecode,
                true,
                ErrorKind::Other,
                true,
            ),
            (
                "timeout",
                IndexerError::Timeout {
                    operation: "eth_getLogs",
                },
                C::Transport,
                false,
                ErrorKind::Network,
                true,
            ),
            (
                "subscription closed",
                IndexerError::SubscriptionClosed {
                    stream: SubscriptionStream::Logs,
                },
                C::Transport,
                false,
                ErrorKind::Network,
                true,
            ),
            (
                "subscription lagged",
                IndexerError::SubscriptionLagged {
                    stream: SubscriptionStream::Heads,
                    skipped: 3,
                },
                C::Transport,
                false,
                ErrorKind::Network,
                true,
            ),
            (
                "unavailable",
                IndexerError::Unavailable {
                    operation: "finalized block".into(),
                },
                C::Unavailable,
                false,
                ErrorKind::ServerError,
                false,
            ),
            (
                "contract violation",
                IndexerError::ContractViolation {
                    operation: "events_in_range",
                    reason: "range too wide".into(),
                },
                C::LocalContract,
                true,
                ErrorKind::Other,
                false,
            ),
            (
                "invalid url",
                IndexerError::InvalidRpcUrl("relative URL without a base".into()),
                C::LocalConfiguration,
                true,
                ErrorKind::Other,
                false,
            ),
            (
                "pool exhausted",
                IndexerError::Pool(PoolError::Exhausted),
                C::Unavailable,
                false,
                ErrorKind::ServerError,
                false,
            ),
            (
                "pool empty",
                IndexerError::Pool(PoolError::Empty),
                C::LocalConfiguration,
                true,
                ErrorKind::Other,
                false,
            ),
            (
                "pool config invalid",
                IndexerError::Pool(PoolError::InvalidEndpointConfig {
                    url: "invalid".into(),
                    rps: 0,
                    burst: 0,
                }),
                C::LocalConfiguration,
                true,
                ErrorKind::Other,
                false,
            ),
            (
                "pool endpoint duplicate",
                IndexerError::Pool(PoolError::DuplicateEndpoint {
                    first_index: 0,
                    duplicate_index: 1,
                    url_redacted: "https://rpc.example".into(),
                }),
                C::LocalConfiguration,
                true,
                ErrorKind::Other,
                false,
            ),
            (
                "chain mismatch",
                IndexerError::ChainIdMismatch {
                    expected: 1,
                    actual: 2,
                },
                C::ChainMismatch,
                true,
                ErrorKind::Other,
                false,
            ),
            (
                "reorg too deep",
                IndexerError::ReorgTooDeep(7),
                C::Integrity,
                true,
                ErrorKind::Other,
                false,
            ),
            (
                "reorg fence",
                IndexerError::ReorgFence {
                    height: 7,
                    reason: "consumer closed".into(),
                },
                C::Integrity,
                true,
                ErrorKind::Other,
                false,
            ),
            (
                "reorg window miss",
                IndexerError::ReorgWindowMiss {
                    cursor: 7,
                    window_len: 0,
                    window_oldest: None,
                    window_newest: None,
                },
                C::Integrity,
                true,
                ErrorKind::Other,
                false,
            ),
            (
                "startup",
                IndexerError::Startup("window corrupt".into()),
                C::Integrity,
                true,
                ErrorKind::Other,
                false,
            ),
            (
                "closed",
                IndexerError::Closed,
                C::Closed,
                true,
                ErrorKind::Other,
                false,
            ),
            (
                "JSON-RPC method not found",
                provider_error(error_response(-32601, "Method not found")),
                C::UnsupportedCapability,
                true,
                ErrorKind::Other,
                true,
            ),
            (
                "JSON-RPC rate limited",
                provider_error(error_response(429, "Too Many Requests")),
                C::RateLimited,
                false,
                ErrorKind::RateLimited,
                false,
            ),
            (
                "JSON-RPC internal",
                provider_error(error_response(-32603, "Internal error")),
                C::RemoteServer,
                false,
                ErrorKind::ServerError,
                false,
            ),
            (
                "JSON-RPC parse error",
                provider_error(error_response(-32700, "Parse error")),
                C::InvalidRequest,
                true,
                ErrorKind::Other,
                false,
            ),
            (
                "JSON-RPC invalid request",
                provider_error(error_response(-32600, "Invalid request")),
                C::InvalidRequest,
                true,
                ErrorKind::Other,
                false,
            ),
            (
                "null response",
                provider_error(RpcError::NullResp),
                C::Unavailable,
                false,
                ErrorKind::ServerError,
                false,
            ),
            (
                "unsupported feature",
                provider_error(RpcError::UnsupportedFeature("batching")),
                C::UnsupportedCapability,
                true,
                ErrorKind::Other,
                true,
            ),
            (
                "local usage",
                provider_error(RpcError::local_usage(std::io::Error::other("bad request"))),
                C::LocalContract,
                true,
                ErrorKind::Other,
                false,
            ),
            (
                "serialization",
                provider_error(RpcError::ser_err(
                    serde_json::from_str::<serde_json::Value>("{").expect_err("invalid JSON"),
                )),
                C::LocalContract,
                true,
                ErrorKind::Other,
                false,
            ),
            (
                "deserialization",
                provider_error(RpcError::DeserError {
                    err: serde_json::from_str::<serde_json::Value>("{").expect_err("invalid JSON"),
                    text: "{".into(),
                }),
                C::RemoteMalformedResponse,
                false,
                ErrorKind::ServerError,
                true,
            ),
            (
                "missing batch response",
                provider_error(TransportErrorKind::missing_batch_response(1u64.into())),
                C::Unavailable,
                false,
                ErrorKind::ServerError,
                false,
            ),
            (
                "backend gone",
                provider_error(TransportErrorKind::backend_gone()),
                C::Transport,
                false,
                ErrorKind::Network,
                true,
            ),
            (
                "pubsub unavailable",
                provider_error(TransportErrorKind::pubsub_unavailable()),
                C::UnsupportedCapability,
                true,
                ErrorKind::Other,
                true,
            ),
            (
                "HTTP rate limited",
                provider_error(TransportErrorKind::http_error(429, String::new())),
                C::RateLimited,
                false,
                ErrorKind::RateLimited,
                false,
            ),
            (
                "HTTP transient",
                provider_error(TransportErrorKind::http_error(408, String::new())),
                C::RemoteTransient,
                false,
                ErrorKind::ServerError,
                false,
            ),
            (
                "HTTP server",
                provider_error(TransportErrorKind::http_error(503, String::new())),
                C::RemoteServer,
                false,
                ErrorKind::ServerError,
                false,
            ),
            (
                "HTTP client",
                provider_error(TransportErrorKind::http_error(401, String::new())),
                C::InvalidRequest,
                true,
                ErrorKind::Other,
                false,
            ),
            (
                "custom transport",
                provider_error(TransportErrorKind::custom_str("socket unavailable")),
                C::Transport,
                false,
                ErrorKind::Network,
                true,
            ),
            (
                "context preserves class",
                IndexerError::Context {
                    operation: "initial scan watermark",
                    source: Box::new(provider_error(error_response(-32601, "Method not found"))),
                },
                C::UnsupportedCapability,
                true,
                ErrorKind::Other,
                true,
            ),
        ];

        for (label, error, class, non_retryable, pool_kind, ws_fallback) in cases {
            assert_policy(label, error, class, non_retryable, pool_kind, ws_fallback);
        }
    }

    #[test]
    fn ws_chain_source_constructor_round_trips() {
        let proxy = alloy::primitives::address!("fa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9");
        let src = WsChainSource::new("wss://eth.example/v1", proxy, 1);
        assert_eq!(src.rpc_url(), "wss://eth.example/v1");
        assert_eq!(src.railgun_proxy(), &proxy);
        assert_eq!(src.chain_id(), 1);
    }

    #[tokio::test]
    async fn ws_source_uses_the_shared_actionable_range_contract() {
        let proxy = alloy::primitives::address!("fa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9");
        let source = WsChainSource::new("not a URL", proxy, 1);
        let to_block = crate::SCAN_CHUNK_BLOCKS;
        let error = source
            .events_in_range(0, to_block)
            .await
            .expect_err("oversized range must fail before dialing");
        assert_eq!(
            error.to_string(),
            format!(
                "contract violation during events_in_range: span={} blocks; caller must chunk to \
                 <= SCAN_CHUNK_BLOCKS={} per the trait contract",
                to_block + 1,
                crate::SCAN_CHUNK_BLOCKS
            )
        );
    }

    #[test]
    fn opaque_error_text_never_steers_ws_fallback() {
        for s in [
            "ws connect: handshake failed",
            "websocket dropped",
            "connection closed by peer",
            "connection refused",
            "operation timed out",
            "method not supported by node",
        ] {
            let e = IndexerError::Rpc(s.into());
            assert!(!is_ws_fallback_error(&e), "opaque text steered policy: {s}");
        }
        let proto = IndexerError::Decode("malformed bytes32".into());
        assert!(is_ws_fallback_error(&proto));
    }
}
