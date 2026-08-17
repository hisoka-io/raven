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
                        .map_err(|e| IndexerError::Alloy(format!("ws connect: {e}")))?,
                )
            };

        let dialled_at = self.dials.load(Ordering::Acquire);
        let actual = alloy::providers::Provider::get_chain_id(provider.as_ref())
            .await
            .map_err(|e| IndexerError::Rpc(format!("eth_chainId: {e}")))?;
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
                    .map_err(|e| {
                        IndexerError::Rpc(format!("get_block_by_number(finalized): {e}"))
                    })?;
                let block = block.ok_or_else(|| {
                    IndexerError::Rpc("finalized block not yet available; chain too young".into())
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
                if to_block < from_block {
                    return Ok(Vec::new());
                }
                let span = to_block.saturating_sub(from_block).saturating_add(1);
                if span > crate::SCAN_CHUNK_BLOCKS {
                    return Err(IndexerError::Rpc(format!(
                        "events_in_range called with span={span} blocks; caller must chunk \
                     to <= SCAN_CHUNK_BLOCKS={} per the trait contract",
                        crate::SCAN_CHUNK_BLOCKS
                    )));
                }
                let p = self.verified_provider().await?;

                use alloy::sol_types::SolEvent;
                let topic0 = [
                    crate::abi::Shield::SIGNATURE_HASH,
                    crate::abi::Transact::SIGNATURE_HASH,
                    crate::abi::Unshield::SIGNATURE_HASH,
                    crate::abi::Nullified::SIGNATURE_HASH,
                ];
                let filter = alloy::rpc::types::eth::Filter::new()
                    .address(self.railgun_proxy)
                    .from_block(from_block)
                    .to_block(to_block)
                    .event_signature(topic0.to_vec());

                let logs = p
                    .get_logs(&filter)
                    .await
                    .map_err(|e| IndexerError::Rpc(format!("get_logs: {e}")))?;

                let mut events = Vec::with_capacity(logs.len());
                for log in logs {
                    let Some(block_number) = crate::block_number_or_drop(&log) else {
                        continue;
                    };
                    let tx_hash = log.transaction_hash.map_or([0u8; 32], |h| h.0);
                    let primary_topic = log.topic0().copied().unwrap_or_default();
                    if let Some(e) = crate::decode_log_to_railgun_event(
                        primary_topic,
                        &log,
                        block_number,
                        tx_hash,
                    )? {
                        events.push(e);
                    }
                }
                Ok(events)
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
                    .map_err(|e| IndexerError::Rpc(format!("eth_call rootHistory: {e}")))?;
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
                    .map_err(|e| {
                        IndexerError::Rpc(format!("get_block_by_number({block_number}): {e}"))
                    })?;
                let block = block.ok_or_else(|| {
                    IndexerError::Rpc(format!("block {block_number} not yet available"))
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
                    .map_err(|e| IndexerError::Rpc(format!("eth_call merkleRoot: {e}")))?;
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
                    .map_err(|e| IndexerError::Rpc(format!("eth_call treeNumber: {e}")))?;
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

fn is_ws_transport_error(err: &IndexerError) -> bool {
    let msg = format!("{err}").to_lowercase();
    msg.contains("ws connect:")
        || msg.contains("websocket")
        || msg.contains("connection closed")
        || msg.contains("connection refused")
        || msg.contains("connection reset")
        || msg.contains("connection aborted")
        || msg.contains("broken pipe")
        || msg.contains("eof")
        || msg.contains("timed out")
        || msg.contains("timeout")
        || msg.contains("method not supported")
        || msg.contains("method not found")
        || msg.contains("unsupported method")
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
                Err(e) if is_ws_transport_error(&e) => {
                    tracing::warn!(error = %e, "WS latest_block transport error; falling back");
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
                Err(e) if is_ws_transport_error(&e) => {
                    tracing::warn!(error = %e, "WS events_in_range transport error; falling back");
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
                Err(e) if is_ws_transport_error(&e) => {
                    tracing::warn!(error = %e, "WS root_history transport error; falling back");
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
                Err(e) if is_ws_transport_error(&e) => {
                    tracing::warn!(error = %e, "WS block_hash transport error; falling back");
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
                Err(e) if is_ws_transport_error(&e) => {
                    tracing::warn!(error = %e, "WS merkle_root transport error; falling back");
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
                Err(e) if is_ws_transport_error(&e) => {
                    tracing::warn!(
                        error = %e,
                        "WS active_tree_number transport error; falling back"
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

    #[test]
    fn ws_chain_source_constructor_round_trips() {
        let proxy = alloy::primitives::address!("fa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9");
        let src = WsChainSource::new("wss://eth.example/v1", proxy, 1);
        assert_eq!(src.rpc_url(), "wss://eth.example/v1");
        assert_eq!(src.railgun_proxy(), &proxy);
        assert_eq!(src.chain_id(), 1);
    }

    #[test]
    fn ws_transport_error_classifier_matches_expected_substrings() {
        for s in [
            "ws connect: handshake failed",
            "websocket dropped",
            "connection closed by peer",
            "connection refused",
            "operation timed out",
            "method not supported by node",
        ] {
            let e = IndexerError::Rpc(s.into());
            assert!(is_ws_transport_error(&e), "should match: {s}");
        }
        let proto = IndexerError::Decode("malformed bytes32".into());
        assert!(!is_ws_transport_error(&proto));
    }
}
