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

/// WS-backed chain source wrapping an alloy `connect_ws` provider.
///
/// Currently invokes methods one-shot over WS transport; long-lived subscriptions are handled
/// by [`crate::subscribe::SubscribeWorker`].
pub struct WsChainSource {
    rpc_url: String,
    railgun_proxy: alloy::primitives::Address,
    chain_id: u64,
    provider: tokio::sync::OnceCell<Arc<dyn alloy::providers::Provider + Send + Sync>>,
}

impl std::fmt::Debug for WsChainSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsChainSource")
            .field("rpc_url", &self.rpc_url)
            .field("railgun_proxy", &self.railgun_proxy)
            .field("chain_id", &self.chain_id)
            .field("provider_initialized", &self.provider.initialized())
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
            provider: tokio::sync::OnceCell::new(),
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

    async fn provider(&self) -> Result<&(dyn alloy::providers::Provider + Send + Sync)> {
        let p = self
            .provider
            .get_or_try_init(|| async {
                let connect = alloy::providers::WsConnect::new(self.rpc_url.clone());
                let provider = alloy::providers::ProviderBuilder::new()
                    .connect_ws(connect)
                    .await
                    .map_err(|e| IndexerError::Alloy(format!("ws connect: {e}")))?;
                let actual = alloy::providers::Provider::get_chain_id(&provider)
                    .await
                    .map_err(|e| IndexerError::Rpc(format!("eth_chainId: {e}")))?;
                if actual != self.chain_id {
                    return Err(IndexerError::ChainIdMismatch {
                        expected: self.chain_id,
                        actual,
                    });
                }
                Ok::<_, IndexerError>(
                    Arc::new(provider) as Arc<dyn alloy::providers::Provider + Send + Sync>
                )
            })
            .await?;
        Ok(p.as_ref())
    }
}

#[async_trait]
impl ChainSource for WsChainSource {
    async fn latest_block(&self) -> Result<u64> {
        let p = self.provider().await?;
        let block = p
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Finalized)
            .await
            .map_err(|e| IndexerError::Rpc(format!("get_block_by_number(finalized): {e}")))?;
        let block = block.ok_or_else(|| {
            IndexerError::Rpc("finalized block not yet available; chain too young".into())
        })?;
        Ok(block.header.number)
    }

    async fn events_in_range(&self, from_block: u64, to_block: u64) -> Result<Vec<RailgunEvent>> {
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
        let p = self.provider().await?;

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
            let block_number = log.block_number.unwrap_or(0);
            let tx_hash = log.transaction_hash.map_or([0u8; 32], |h| h.0);
            let primary_topic = log.topic0().copied().unwrap_or_default();
            if let Some(e) =
                crate::decode_log_to_railgun_event(primary_topic, &log, block_number, tx_hash)?
            {
                events.push(e);
            }
        }
        Ok(events)
    }

    async fn root_history(
        &self,
        tree_number: u32,
        merkle_root: [u8; 32],
        at: Option<alloy::eips::BlockId>,
    ) -> Result<bool> {
        use alloy::sol_types::SolCall;
        let p = self.provider().await?;
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
    }

    async fn block_hash(&self, block_number: u64) -> Result<[u8; 32]> {
        let p = self.provider().await?;
        let block = p
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Number(block_number))
            .await
            .map_err(|e| IndexerError::Rpc(format!("get_block_by_number({block_number}): {e}")))?;
        let block = block
            .ok_or_else(|| IndexerError::Rpc(format!("block {block_number} not yet available")))?;
        Ok(block.header.hash.0)
    }

    async fn merkle_root(&self, at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        use alloy::sol_types::SolCall;
        let p = self.provider().await?;
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
    }

    async fn active_tree_number(&self, at: Option<alloy::eips::BlockId>) -> Result<u32> {
        use alloy::sol_types::SolCall;
        let p = self.provider().await?;
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
