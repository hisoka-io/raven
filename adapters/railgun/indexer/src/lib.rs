//! Chain-event indexer for the Raven Railgun PIR adapter.
//!
//! `ChainSource` trait + `RpcChainSource` HTTP/WS implementations +
//! `IndexerWorker` polling loop with Layer 1 reorg detection.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::doc_lazy_continuation,
    clippy::print_stderr,
    clippy::items_after_statements,
    clippy::too_many_lines
)]

use async_trait::async_trait;
use raven_railgun_core::RailgunEvent;

pub mod rpc_pool;
pub mod subscribe;
pub mod subsquid;
pub mod ws;
pub use subscribe::{
    AlloyWsLogStreamer, LogStreamer, ModeFlag, SubscribeStreams, SubscribeWorker,
    SubscribeWorkerConfig, SUBSCRIBE_CHANNEL_CAPACITY, SUBSCRIBE_HEARTBEAT_SECS,
};
pub use ws::{
    ws_with_rpc_fallback, AutoFallbackChainSource, ChainSourceMode, WsChainSource,
    MIN_POLLING_DURATION, WS_RECONNECT_CAP_SECS,
};

pub use alloy::eips::BlockId;
pub use alloy::eips::BlockNumberOrTag;

#[derive(thiserror::Error, Debug)]
pub enum IndexerError {
    #[error("rpc error: {0}")]
    Rpc(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("reorg detected at depth {0}")]
    ReorgTooDeep(u64),
    #[error("source closed")]
    Closed,
    #[error("alloy error: {0}")]
    Alloy(String),
    #[error(
        "chain id mismatch: configured {expected}, RPC reports {actual}; \
         operator pointed adapter at the wrong network"
    )]
    ChainIdMismatch {
        /// Operator-configured chain id (`new(... , chain_id, ...)`).
        expected: u64,
        /// Chain id reported by the RPC's `eth_chainId` response.
        actual: u64,
    },
}

pub type Result<T, E = IndexerError> = core::result::Result<T, E>;

/// Maximum blocks per `eth_getLogs` chunk. Mirrors Railgun TS engine's `SCAN_CHUNKS = 499`.
pub const SCAN_CHUNK_BLOCKS: u64 = 499;

/// Maximum retries per chunk. Reduced from 30 to bound the total retry budget;
/// the original 17-min worst case stalled the engine consumer and froze the lag gauge.
pub const MAX_RPC_RETRIES: u32 = 6;

/// Per-chunk timeout (seconds).
pub const RPC_TIMEOUT_SECS: u64 = 5;

/// Maximum cumulative retry elapsed time (seconds) before surfacing the last error.
pub const MAX_RPC_TOTAL_ELAPSED_SECS: u64 = 90;

/// Default polling cadence (seconds).
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 10;

/// Maximum scanned-back blocks during reorg recovery before bailing.
pub const MAX_REORG_BLOCKS: u64 = 256;

/// A source of decoded Railgun chain events, ordered by block.
///
/// `events_in_range` returns events ordered by `block_number` then log index.
/// `latest_block` returns a finalized block (not a reorg-vulnerable tip).
#[async_trait]
pub trait ChainSource: Send + Sync + 'static {
    /// Latest finalized block the source has processed.
    async fn latest_block(&self) -> Result<u64>;

    /// Pull events in the inclusive range `[from_block, to_block]`.
    /// Caller must chunk to at most [`SCAN_CHUNK_BLOCKS`].
    async fn events_in_range(&self, from_block: u64, to_block: u64) -> Result<Vec<RailgunEvent>>;

    /// Verify a `(tree_number, merkle_root)` pair against the contract's `rootHistory` mapping.
    ///
    /// `at` pins all reads in a Layer 2 verification round to the same block height to avoid
    /// false InSync/OutOfSync from chain advancement between calls. `None` reads at chain head.
    async fn root_history(
        &self,
        tree_number: u32,
        merkle_root: [u8; 32],
        at: Option<alloy::eips::BlockId>,
    ) -> Result<bool>;

    /// Fetch the canonical block hash for Layer 1 reorg detection.
    async fn block_hash(&self, block_number: u64) -> Result<[u8; 32]>;

    /// Read the contract's current global `merkleRoot` (active tree only; `Commitments.sol:39`).
    ///
    /// `at` pins the read; pass `Some(block_id)` in a Layer 2 verification round.
    async fn merkle_root(&self, at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]>;

    /// Read the contract's current `treeNumber` (`Commitments.sol:45`).
    ///
    /// Trees with `tree_number < active_tree_number()` are frozen. `at` pins the read.
    async fn active_tree_number(&self, at: Option<alloy::eips::BlockId>) -> Result<u32>;
}

/// HTTP-backed chain source using alloy's `eth_getLogs` polling.
pub struct RpcChainSource {
    rpc_url: String,
    railgun_proxy: alloy::primitives::Address,
    _start_block: u64,
    chain_id: u64,
    provider: tokio::sync::OnceCell<std::sync::Arc<dyn alloy::providers::Provider + Send + Sync>>,
}

impl std::fmt::Debug for RpcChainSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcChainSource")
            .field("rpc_url", &self.rpc_url)
            .field("railgun_proxy", &self.railgun_proxy)
            .field("chain_id", &self.chain_id)
            .field("provider_initialized", &self.provider.initialized())
            .finish_non_exhaustive()
    }
}

impl RpcChainSource {
    /// Construct a new HTTP-backed chain source.
    #[must_use]
    pub fn new(
        rpc_url: impl Into<String>,
        railgun_proxy: alloy::primitives::Address,
        start_block: u64,
        chain_id: u64,
    ) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            railgun_proxy,
            _start_block: start_block,
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

    /// Build the alloy provider on first use and verify `eth_chainId` matches the configured
    /// value. A mismatch surfaces as [`IndexerError::ChainIdMismatch`] to prevent silently
    /// indexing foreign-chain commitments. Runs exactly once per process via the `OnceCell`.
    async fn provider(&self) -> Result<&(dyn alloy::providers::Provider + Send + Sync)> {
        let p = self
            .provider
            .get_or_try_init(|| async {
                let url = self
                    .rpc_url
                    .parse::<reqwest::Url>()
                    .map_err(|e| IndexerError::Alloy(format!("invalid rpc_url: {e}")))?;
                let provider = alloy::providers::ProviderBuilder::new().connect_http(url);
                let actual = alloy::providers::Provider::get_chain_id(&provider)
                    .await
                    .map_err(|e| IndexerError::Rpc(format!("eth_chainId: {e}")))?;
                if actual != self.chain_id {
                    return Err(IndexerError::ChainIdMismatch {
                        expected: self.chain_id,
                        actual,
                    });
                }
                Ok::<_, IndexerError>(std::sync::Arc::new(provider)
                    as std::sync::Arc<dyn alloy::providers::Provider + Send + Sync>)
            })
            .await?;
        Ok(p.as_ref())
    }
}

#[async_trait]
impl ChainSource for RpcChainSource {
    async fn latest_block(&self) -> Result<u64> {
        let p = self.provider().await?;
        let block = retry_rpc(|| async {
            p.get_block_by_number(alloy::eips::BlockNumberOrTag::Finalized)
                .await
                .map_err(|e| IndexerError::Rpc(format!("get_block_by_number(finalized): {e}")))
        })
        .await?;
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
        if span > SCAN_CHUNK_BLOCKS {
            return Err(IndexerError::Rpc(format!(
                "events_in_range called with span={span} blocks; caller must chunk \
                 to <= SCAN_CHUNK_BLOCKS={SCAN_CHUNK_BLOCKS} per the trait contract"
            )));
        }
        let p = self.provider().await?;

        use alloy::sol_types::SolEvent;
        let topic0 = [
            abi::Shield::SIGNATURE_HASH,
            abi::Transact::SIGNATURE_HASH,
            abi::Unshield::SIGNATURE_HASH,
            abi::Nullified::SIGNATURE_HASH,
        ];
        let filter = alloy::rpc::types::eth::Filter::new()
            .address(self.railgun_proxy)
            .from_block(from_block)
            .to_block(to_block)
            .event_signature(topic0.to_vec());

        let logs = retry_rpc(|| async {
            p.get_logs(&filter)
                .await
                .map_err(|e| IndexerError::Rpc(format!("get_logs: {e}")))
        })
        .await?;

        let mut events = Vec::with_capacity(logs.len());
        for log in logs {
            let block_number = log.block_number.unwrap_or(0);
            let tx_hash = log.transaction_hash.map_or([0u8; 32], |h| h.0);
            let primary_topic = log.topic0().copied().unwrap_or_default();
            let event = decode_log_to_railgun_event(primary_topic, &log, block_number, tx_hash)?;
            if let Some(e) = event {
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
        let call = abi::rootHistoryCall {
            tree: alloy::primitives::U256::from(tree_number),
            root: alloy::primitives::FixedBytes::<32>::from(merkle_root),
        };
        let calldata: alloy::primitives::Bytes = call.abi_encode().into();
        let tx = alloy::rpc::types::eth::TransactionRequest {
            to: Some(alloy::primitives::TxKind::Call(self.railgun_proxy)),
            input: alloy::rpc::types::eth::TransactionInput::new(calldata),
            ..Default::default()
        };
        let result_bytes: alloy::primitives::Bytes = retry_rpc(|| async {
            let mut call_builder = p.call(tx.clone());
            if let Some(b) = at {
                call_builder = call_builder.block(b);
            }
            call_builder
                .await
                .map_err(|e| IndexerError::Rpc(format!("eth_call rootHistory: {e}")))
        })
        .await?;
        let decoded = abi::rootHistoryCall::abi_decode_returns(&result_bytes)
            .map_err(|e| IndexerError::Decode(format!("rootHistory decode: {e}")))?;
        Ok(decoded)
    }

    async fn block_hash(&self, block_number: u64) -> Result<[u8; 32]> {
        let p = self.provider().await?;
        let block = retry_rpc(|| async {
            p.get_block_by_number(alloy::eips::BlockNumberOrTag::Number(block_number))
                .await
                .map_err(|e| IndexerError::Rpc(format!("get_block_by_number({block_number}): {e}")))
        })
        .await?;
        let block = block
            .ok_or_else(|| IndexerError::Rpc(format!("block {block_number} not yet available")))?;
        Ok(block.header.hash.0)
    }

    async fn merkle_root(&self, at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        use alloy::sol_types::SolCall;
        let p = self.provider().await?;
        let call = abi::merkleRootCall {};
        let calldata: alloy::primitives::Bytes = call.abi_encode().into();
        let tx = alloy::rpc::types::eth::TransactionRequest {
            to: Some(alloy::primitives::TxKind::Call(self.railgun_proxy)),
            input: alloy::rpc::types::eth::TransactionInput::new(calldata),
            ..Default::default()
        };
        let result_bytes: alloy::primitives::Bytes = retry_rpc(|| async {
            let mut call_builder = p.call(tx.clone());
            if let Some(b) = at {
                call_builder = call_builder.block(b);
            }
            call_builder
                .await
                .map_err(|e| IndexerError::Rpc(format!("eth_call merkleRoot: {e}")))
        })
        .await?;
        let decoded = abi::merkleRootCall::abi_decode_returns(&result_bytes)
            .map_err(|e| IndexerError::Decode(format!("merkleRoot decode: {e}")))?;
        Ok(decoded.0)
    }

    async fn active_tree_number(&self, at: Option<alloy::eips::BlockId>) -> Result<u32> {
        use alloy::sol_types::SolCall;
        let p = self.provider().await?;
        let call = abi::treeNumberCall {};
        let calldata: alloy::primitives::Bytes = call.abi_encode().into();
        let tx = alloy::rpc::types::eth::TransactionRequest {
            to: Some(alloy::primitives::TxKind::Call(self.railgun_proxy)),
            input: alloy::rpc::types::eth::TransactionInput::new(calldata),
            ..Default::default()
        };
        let result_bytes: alloy::primitives::Bytes = retry_rpc(|| async {
            let mut call_builder = p.call(tx.clone());
            if let Some(b) = at {
                call_builder = call_builder.block(b);
            }
            call_builder
                .await
                .map_err(|e| IndexerError::Rpc(format!("eth_call treeNumber: {e}")))
        })
        .await?;
        let decoded = abi::treeNumberCall::abi_decode_returns(&result_bytes)
            .map_err(|e| IndexerError::Decode(format!("treeNumber decode: {e}")))?;
        // Contract treeNumber is uint256 on-chain but operationally fits u32.
        // Saturate to u32::MAX so a future overflow produces consistent OutOfSync rather than panic.
        let tree_u32 = u32::try_from(decoded).unwrap_or(u32::MAX);
        Ok(tree_u32)
    }
}

/// Compute Railgun's canonical `tokenHash` from a decoded `TokenData` log struct.
/// Dispatches on `tokenType` per `engine/src/note/note-util.ts:191-200`.
fn compute_token_data_hash(token: &abi::TokenData) -> Result<[u8; 32]> {
    use raven_railgun_poseidon::{token_data_hash, TokenType};

    let token_type = TokenType::from_u8(token.tokenType).ok_or_else(|| {
        IndexerError::Decode(format!(
            "invalid tokenType {}; expected 0/1/2",
            token.tokenType
        ))
    })?;
    let token_address: [u8; 20] = token.tokenAddress.0 .0;
    let token_sub_id = token.tokenSubID.to_be_bytes::<32>();
    Ok(token_data_hash(token_type, token_address, token_sub_id))
}

/// Compute the Railgun-canonical Shield `commitment_hash` from a decoded `CommitmentPreimage`.
///
/// `commitment_hash = Poseidon(npk, tokenHash, valueAfterFee)` per `shield-note.ts:49-54`.
fn compute_shield_commitment_hash(preimage: &abi::CommitmentPreimage) -> Result<[u8; 32]> {
    use raven_railgun_poseidon::shield_commitment_hash;

    let npk = preimage.npk.0;
    let token_hash = compute_token_data_hash(&preimage.token)?;
    let value_u256 = alloy::primitives::U256::from(preimage.value);
    let value_be = value_u256.to_be_bytes::<32>();
    shield_commitment_hash(npk, token_hash, value_be)
        .map_err(|e| IndexerError::Decode(format!("shield commitment Poseidon: {e}")))
}

/// Decode a single `eth_getLogs` entry into a typed `RailgunEvent`.
///
/// Returns `Ok(None)` for a recognized topic[0] that maps to a legacy/out-of-scope event.
pub(crate) fn decode_log_to_railgun_event(
    topic0: alloy::primitives::B256,
    log: &alloy::rpc::types::eth::Log,
    block_number: u64,
    tx_hash: [u8; 32],
) -> Result<Option<RailgunEvent>> {
    use alloy::sol_types::SolEvent;
    use raven_railgun_core::CommitmentLeaf;

    let log_data = log.data();

    if topic0 == abi::Shield::SIGNATURE_HASH {
        let decoded: abi::Shield = abi::Shield::decode_log_data(log_data)
            .map_err(|e| IndexerError::Decode(format!("Shield decode: {e}")))?;
        let tree_number: u32 = decoded.treeNumber.try_into().map_err(|_| {
            IndexerError::Decode(format!(
                "Shield treeNumber out of u32 range: {}",
                decoded.treeNumber
            ))
        })?;
        let start_position: u32 = decoded.startPosition.try_into().map_err(|_| {
            IndexerError::Decode(format!(
                "Shield startPosition out of u32 range: {}",
                decoded.startPosition
            ))
        })?;
        let mut leaves = Vec::with_capacity(decoded.commitments.len());
        for (i, preimage) in decoded.commitments.iter().enumerate() {
            let ciphertext = decoded
                .shieldCiphertext
                .get(i)
                .map(|c| {
                    let mut out = Vec::with_capacity(32 * 4);
                    for b in &c.encryptedBundle {
                        out.extend_from_slice(b.as_slice());
                    }
                    out.extend_from_slice(c.shieldKey.as_slice());
                    out
                })
                .unwrap_or_default();

            let commitment_hash = compute_shield_commitment_hash(preimage)?;
            #[allow(clippy::cast_possible_truncation)]
            let leaf_index = start_position.saturating_add(i as u32);
            leaves.push(CommitmentLeaf {
                tree_number,
                leaf_index,
                commitment_hash,
                ciphertext,
            });
        }
        Ok(Some(RailgunEvent::Shield {
            block_number,
            tx_hash,
            tree_number,
            start_position,
            leaves,
        }))
    } else if topic0 == abi::Transact::SIGNATURE_HASH {
        let decoded: abi::Transact = abi::Transact::decode_log_data(log_data)
            .map_err(|e| IndexerError::Decode(format!("Transact decode: {e}")))?;
        let tree_number: u32 = decoded.treeNumber.try_into().map_err(|_| {
            IndexerError::Decode(format!(
                "Transact treeNumber out of u32 range: {}",
                decoded.treeNumber
            ))
        })?;
        let start_position: u32 = decoded.startPosition.try_into().map_err(|_| {
            IndexerError::Decode(format!(
                "Transact startPosition out of u32 range: {}",
                decoded.startPosition
            ))
        })?;
        let mut leaves = Vec::with_capacity(decoded.hash.len());
        for (i, h) in decoded.hash.iter().enumerate() {
            let ciphertext = decoded
                .ciphertext
                .get(i)
                .map(|c| {
                    let mut out = Vec::with_capacity(32 * 4 + 64 + 32 + 32);
                    for b in &c.ciphertext {
                        out.extend_from_slice(b.as_slice());
                    }
                    out.extend_from_slice(c.blindedSenderViewingKey.as_slice());
                    out.extend_from_slice(c.blindedReceiverViewingKey.as_slice());
                    out.extend_from_slice(&c.annotationData);
                    out.extend_from_slice(&c.memo);
                    out
                })
                .unwrap_or_default();
            #[allow(clippy::cast_possible_truncation)]
            let leaf_index = start_position.saturating_add(i as u32);
            leaves.push(CommitmentLeaf {
                tree_number,
                leaf_index,
                commitment_hash: h.0,
                ciphertext,
            });
        }
        Ok(Some(RailgunEvent::Transact {
            block_number,
            tx_hash,
            tree_number,
            start_position,
            leaves,
        }))
    } else if topic0 == abi::Unshield::SIGNATURE_HASH {
        let decoded: abi::Unshield = abi::Unshield::decode_log_data(log_data)
            .map_err(|e| IndexerError::Decode(format!("Unshield decode: {e}")))?;
        let token_hash = compute_token_data_hash(&decoded.token)?;
        // uint120 on-chain but alloy decodes to U256; fail-fast rather than saturating to u128::MAX.
        let amount: u128 = decoded.amount.try_into().map_err(|_| {
            IndexerError::Decode(format!(
                "Unshield amount out of u128 range: {}",
                decoded.amount
            ))
        })?;
        let fee: u128 = decoded.fee.try_into().map_err(|_| {
            IndexerError::Decode(format!("Unshield fee out of u128 range: {}", decoded.fee))
        })?;
        Ok(Some(RailgunEvent::Unshield {
            block_number,
            tx_hash,
            to: decoded.to.0.into(),
            token: token_hash,
            amount,
            fee,
        }))
    } else if topic0 == abi::Nullified::SIGNATURE_HASH {
        let decoded: abi::Nullified = abi::Nullified::decode_log_data(log_data)
            .map_err(|e| IndexerError::Decode(format!("Nullified decode: {e}")))?;
        let nullifiers: Vec<[u8; 32]> = decoded.nullifier.iter().map(|n| n.0).collect();
        Ok(Some(RailgunEvent::Nullified {
            block_number,
            tx_hash,
            tree_number: u32::from(decoded.treeNumber),
            nullifiers,
        }))
    } else {
        tracing::warn!(
            ?topic0,
            "indexer received log with unrecognized topic[0]; skipping (legacy or out-of-V1-scope)"
        );
        Ok(None)
    }
}

/// Outbound message from indexer worker to engine consumer task.
#[derive(Debug, Clone)]
pub enum IndexerMessage {
    /// A decoded chain event.
    Event {
        event: RailgunEvent,
        block_height: u64,
    },
    /// Reorg fence: surviving entries have `block_height <= height`.
    Reorg { height: u64 },
    /// Heartbeat for liveness and lag-tracking.
    Heartbeat {
        wallclock_unix_ms: u64,
        chain_head_block: u64,
    },
}

/// Configuration for [`IndexerWorker::run`].
#[derive(Clone, Debug)]
pub struct IndexerWorkerConfig {
    pub start_block: u64,
    pub poll_interval_secs: u64,
    pub chunk_blocks: u64,
}

impl Default for IndexerWorkerConfig {
    fn default() -> Self {
        Self {
            start_block: 0,
            poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
            chunk_blocks: SCAN_CHUNK_BLOCKS,
        }
    }
}

/// Polling worker that drives a [`ChainSource`] and emits [`IndexerMessage`]s.
///
/// Maintains a sliding block-hash cache for Layer 1 reorg detection. Layer 2
/// reorg detection (rootHistory) is handled by the engine consumer.
#[derive(Debug)]
pub struct IndexerWorker<S: ChainSource + std::fmt::Debug> {
    source: std::sync::Arc<S>,
    sender: tokio::sync::mpsc::Sender<IndexerMessage>,
}

/// Maximum cached `(block_number, block_hash)` pairs for Layer 1 reorg detection.
#[allow(clippy::cast_possible_truncation)]
pub const REORG_CACHE_DEPTH: usize = MAX_REORG_BLOCKS as usize;

impl<S: ChainSource + std::fmt::Debug> IndexerWorker<S> {
    pub fn new(
        source: std::sync::Arc<S>,
        sender: tokio::sync::mpsc::Sender<IndexerMessage>,
    ) -> Self {
        Self { source, sender }
    }

    /// Run the worker loop until the channel closes or an unrecoverable RPC error fires.
    pub async fn run(&self, config: IndexerWorkerConfig) -> Result<u64> {
        use tokio::time::{interval, Duration, MissedTickBehavior};
        let mut tick = interval(Duration::from_secs(config.poll_interval_secs.max(1)));
        // `Delay` prevents burst catch-up ticks after a stalled scan from hammering the RPC.
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut cursor = config.start_block;
        let mut hash_cache: std::collections::BTreeMap<u64, [u8; 32]> =
            std::collections::BTreeMap::new();
        loop {
            tick.tick().await;
            if self.sender.is_closed() {
                tracing::info!(cursor, "indexer worker exiting; channel closed");
                return Ok(cursor);
            }
            let latest = match self.source.latest_block().await {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(error = %e, "indexer latest_block failed; will retry");
                    continue;
                }
            };

            if cursor > 0 && hash_cache.contains_key(&cursor) {
                match detect_reorg_layer1(&*self.source, &hash_cache, cursor).await {
                    Ok(None) => { /* canonical; continue */ }
                    Ok(Some(reorg_height)) => {
                        let msg = IndexerMessage::Reorg {
                            height: reorg_height,
                        };
                        if self.sender.send(msg).await.is_err() {
                            return Ok(cursor);
                        }
                        hash_cache.retain(|&n, _| n <= reorg_height);
                        cursor = reorg_height;
                        let _ = self.send_heartbeat(latest);
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Layer 1 reorg check failed; will retry");
                        continue;
                    }
                }
            }

            if latest <= cursor {
                let _ = self.send_heartbeat(latest);
                continue;
            }
            let to = (cursor.saturating_add(config.chunk_blocks)).min(latest);
            let events = match self
                .source
                .events_in_range(cursor.saturating_add(1), to)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, from = cursor + 1, to, "events_in_range failed");
                    continue;
                }
            };
            for event in events {
                let block_height = match &event {
                    RailgunEvent::Shield { block_number, .. }
                    | RailgunEvent::Transact { block_number, .. }
                    | RailgunEvent::Nullified { block_number, .. }
                    | RailgunEvent::Unshield { block_number, .. } => *block_number,
                };
                let msg = IndexerMessage::Event {
                    event,
                    block_height,
                };
                if let Err(e) = self.sender.send(msg).await {
                    tracing::info!(error = %e, "engine consumer dropped channel; exiting");
                    return Ok(cursor);
                }
            }

            if let Ok(tip_hash) = self.source.block_hash(to).await {
                hash_cache.insert(to, tip_hash);
                if hash_cache.len() > REORG_CACHE_DEPTH {
                    let to_keep = to.saturating_sub(MAX_REORG_BLOCKS);
                    hash_cache.retain(|&n, _| n >= to_keep);
                }
            }

            cursor = to;
            let _ = self.send_heartbeat(latest);
        }
    }

    fn send_heartbeat(&self, chain_head_block: u64) -> std::result::Result<(), ()> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let msg = IndexerMessage::Heartbeat {
            wallclock_unix_ms: now_ms,
            chain_head_block,
        };
        match self.sender.try_send(msg) {
            Ok(()) => Ok(()),
            Err(_) => Err(()),
        }
    }
}

/// Build the bounded MPSC for indexer-to-engine messaging (capacity 1024).
#[must_use]
pub fn build_indexer_channel() -> (
    tokio::sync::mpsc::Sender<IndexerMessage>,
    tokio::sync::mpsc::Receiver<IndexerMessage>,
) {
    tokio::sync::mpsc::channel(1024)
}

/// Layer 1 reorg detection.
///
/// Re-fetches the cursor's block hash and walks the cache backward to find the surviving tip.
/// Returns `Ok(None)` if canonical, `Ok(Some(h))` with the surviving height, or
/// `Err(ReorgTooDeep)` if no cached entry survives (operator intervention required).
pub async fn detect_reorg_layer1<S: ChainSource + ?Sized>(
    source: &S,
    cache: &std::collections::BTreeMap<u64, [u8; 32]>,
    cursor: u64,
) -> Result<Option<u64>> {
    let observed = source.block_hash(cursor).await?;
    let cached = cache.get(&cursor).copied().unwrap_or([0u8; 32]);
    if observed == cached {
        return Ok(None);
    }
    let candidates: Vec<(u64, [u8; 32])> =
        cache.range(..cursor).rev().map(|(&k, &v)| (k, v)).collect();
    for (height, cached_hash) in candidates {
        let observed_at = match source.block_hash(height).await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(error = %e, height, "block_hash failed during reorg walk-back");
                continue;
            }
        };
        if observed_at == cached_hash {
            return Ok(Some(height));
        }
    }
    Err(IndexerError::ReorgTooDeep(cursor))
}

/// Returns true if an `IndexerError` should NOT be retried.
///
/// HTTP 4xx (non-transient), "method not found", and JSON decode errors are
/// operator-visible misconfigurations that retrying only delays surfacing.
fn is_non_retryable(err: &IndexerError) -> bool {
    let s = format!("{err}");
    let lower = s.to_lowercase();
    let four_xx_transient = ["408", "425", "429"];
    let is_4xx = (400..500).any(|code| {
        lower.contains(&format!(" {code}"))
            || lower.contains(&format!("status {code}"))
            || lower.contains(&format!("status: {code}"))
    });
    let is_transient_4xx = four_xx_transient.iter().any(|c| lower.contains(c));
    if is_4xx && !is_transient_4xx {
        return true;
    }
    if lower.contains("method not supported")
        || lower.contains("method not found")
        || lower.contains("unsupported method")
    {
        return true;
    }
    if lower.contains("decode") && lower.contains("json") {
        return true;
    }
    false
}

/// Exponential-backoff retry helper for RPC calls.
///
/// Bounded by [`MAX_RPC_RETRIES`] and [`MAX_RPC_TOTAL_ELAPSED_SECS`]. Per-attempt timeout
/// is [`RPC_TIMEOUT_SECS`]. Non-retryable errors (HTTP 4xx, JSON decode, "method not found")
/// fail-fast without consuming the retry budget.
async fn retry_rpc<F, Fut, T>(mut op: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    use tokio::time::{sleep, timeout, Duration};
    let started = std::time::Instant::now();
    let total_cap = Duration::from_secs(MAX_RPC_TOTAL_ELAPSED_SECS);
    let mut last_err: Option<IndexerError> = None;
    for attempt in 0..MAX_RPC_RETRIES {
        match timeout(Duration::from_secs(RPC_TIMEOUT_SECS), op()).await {
            Ok(Ok(v)) => return Ok(v),
            Ok(Err(e)) => {
                tracing::warn!(attempt, error = %e, "RPC attempt failed");
                if is_non_retryable(&e) {
                    tracing::warn!(error = %e, "RPC error is non-retryable; fail-fast");
                    return Err(e);
                }
                last_err = Some(e);
            }
            Err(_) => {
                tracing::warn!(attempt, "RPC attempt timed out");
                last_err = Some(IndexerError::Rpc(format!(
                    "timeout after {RPC_TIMEOUT_SECS}s on attempt {attempt}"
                )));
            }
        }
        if started.elapsed() >= total_cap {
            tracing::warn!(
                elapsed_secs = started.elapsed().as_secs(),
                "RPC total retry budget exhausted; giving up"
            );
            break;
        }
        let backoff_ms = 100u64.saturating_mul(1u64 << attempt.min(8));
        let backoff = Duration::from_millis(backoff_ms.min(30_000));
        let remaining = total_cap.saturating_sub(started.elapsed());
        sleep(backoff.min(remaining)).await;
    }
    Err(last_err.unwrap_or_else(|| IndexerError::Rpc("retry exhausted".into())))
}

/// Alloy `sol!`-generated types for Railgun's V2 contract events and supporting structs.
///
/// V2 only; legacy pre-PPOI-launch events are out of scope.
pub mod abi {
    alloy::sol! {
        #[derive(Debug)]
        struct TokenData {
            uint8 tokenType;
            address tokenAddress;
            uint256 tokenSubID;
        }

        /// `npk` is `bytes32` (not `uint256`): the two have the same encoding but different
        /// keccak256 typestrings, so the wrong type produces a mismatched topic-0 hash.
        #[derive(Debug)]
        struct CommitmentPreimage {
            bytes32 npk;
            TokenData token;
            uint120 value;
        }

        #[derive(Debug)]
        struct ShieldCiphertext {
            bytes32[3] encryptedBundle;
            bytes32 shieldKey;
        }

        #[derive(Debug)]
        struct CommitmentCiphertext {
            bytes32[4] ciphertext;
            bytes32 blindedSenderViewingKey;
            bytes32 blindedReceiverViewingKey;
            bytes annotationData;
            bytes memo;
        }

        #[derive(Debug)]
        event Shield(
            uint256 treeNumber,
            uint256 startPosition,
            CommitmentPreimage[] commitments,
            ShieldCiphertext[] shieldCiphertext,
            uint256[] fees
        );

        #[derive(Debug)]
        event Transact(
            uint256 treeNumber,
            uint256 startPosition,
            bytes32[] hash,
            CommitmentCiphertext[] ciphertext
        );

        #[derive(Debug)]
        event Unshield(address to, TokenData token, uint256 amount, uint256 fee);

        #[derive(Debug)]
        event Nullified(uint16 treeNumber, bytes32[] nullifier);

        function rootHistory(uint256 tree, bytes32 root) external view returns (bool);
        function merkleRoot() external view returns (bytes32);
        function treeNumber() external view returns (uint256);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn rpc_chain_source_constructor_round_trips() {
        let proxy = address!("fa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9");
        let src = RpcChainSource::new("https://eth.example/v1", proxy, 18_514_200, 1);
        assert_eq!(src.rpc_url(), "https://eth.example/v1");
        assert_eq!(src.railgun_proxy(), &proxy);
        assert_eq!(src.chain_id(), 1);
    }

    #[test]
    fn chain_id_mismatch_error_displays_actionable_message() {
        let err = IndexerError::ChainIdMismatch {
            expected: 1,
            actual: 11_155_111,
        };
        let msg = format!("{err}");
        assert!(msg.contains("chain id mismatch"), "missing label in: {msg}");
        assert!(msg.contains("configured 1"), "missing expected: {msg}");
        assert!(msg.contains("11155111"), "missing actual: {msg}");
        assert!(msg.contains("wrong network"), "missing remediation: {msg}");
    }

    #[test]
    fn abi_topic0_hashes_are_stable() {
        use alloy::sol_types::SolEvent;
        let shield = format!("{:?}", abi::Shield::SIGNATURE_HASH);
        let transact = format!("{:?}", abi::Transact::SIGNATURE_HASH);
        let unshield = format!("{:?}", abi::Unshield::SIGNATURE_HASH);
        let nullified = format!("{:?}", abi::Nullified::SIGNATURE_HASH);
        for (name, h) in [
            ("Shield", &shield),
            ("Transact", &transact),
            ("Unshield", &unshield),
            ("Nullified", &nullified),
        ] {
            assert!(
                h.starts_with("0x") && h.len() == 66,
                "{name} hash malformed: {h}"
            );
        }
        // Locked alloy-computed Shield topic-0. Verified with:
        //   cast keccak 'Shield(uint256,uint256,(bytes32,(uint8,address,uint256),uint120)[],(bytes32[3],bytes32)[],uint256[])'
        assert_eq!(
            shield,
            "0x3a5b9dc26075a3801a6ddccf95fec485bb7500a91b44cec1add984c21ee6db3b"
        );
        eprintln!("ABI topic-0 hashes (alloy-computed):");
        eprintln!("  Shield:    {shield}");
        eprintln!("  Transact:  {transact}");
        eprintln!("  Unshield:  {unshield}");
        eprintln!("  Nullified: {nullified}");
    }

    #[test]
    fn compute_token_data_hash_erc20_matches_poseidon_helper() {
        let addr = [0x42u8; 20];
        let token = abi::TokenData {
            tokenType: 0,
            tokenAddress: alloy::primitives::Address::from(addr),
            tokenSubID: alloy::primitives::U256::ZERO,
        };
        let got = compute_token_data_hash(&token).expect("erc20 ok");
        let expected = raven_railgun_poseidon::token_data_hash_erc20(addr);
        assert_eq!(got, expected);
    }

    #[test]
    fn compute_token_data_hash_nft_matches_poseidon_helper() {
        let addr = [0x42u8; 20];
        let sub_id = [0xabu8; 32];
        let token = abi::TokenData {
            tokenType: 1,
            tokenAddress: alloy::primitives::Address::from(addr),
            tokenSubID: alloy::primitives::U256::from_be_bytes(sub_id),
        };
        let got = compute_token_data_hash(&token).expect("nft ok");
        let expected = raven_railgun_poseidon::token_data_hash_nft(1, addr, sub_id);
        assert_eq!(got, expected);
    }

    #[test]
    fn compute_token_data_hash_rejects_invalid_token_type() {
        let token = abi::TokenData {
            tokenType: 42,
            tokenAddress: alloy::primitives::Address::ZERO,
            tokenSubID: alloy::primitives::U256::ZERO,
        };
        let result = compute_token_data_hash(&token);
        assert!(
            matches!(&result, Err(IndexerError::Decode(msg)) if msg.contains("tokenType")),
            "expected Decode err mentioning 'tokenType' for tokenType=42, got {result:?}"
        );
    }

    #[test]
    fn shield_and_unshield_arms_produce_same_token_hash_for_same_token_data() {
        // ERC-20 case
        let erc20 = abi::TokenData {
            tokenType: 0,
            tokenAddress: alloy::primitives::Address::from([0x55u8; 20]),
            tokenSubID: alloy::primitives::U256::ZERO,
        };
        let h_erc20 = compute_token_data_hash(&erc20).expect("erc20");
        let again_erc20 = compute_token_data_hash(&erc20).expect("erc20 again");
        assert_eq!(h_erc20, again_erc20);

        // NFT case
        let nft = abi::TokenData {
            tokenType: 2,
            tokenAddress: alloy::primitives::Address::from([0x77u8; 20]),
            tokenSubID: alloy::primitives::U256::from(0x1234_u64),
        };
        let h_nft = compute_token_data_hash(&nft).expect("nft");
        let again_nft = compute_token_data_hash(&nft).expect("nft again");
        assert_eq!(h_nft, again_nft);

        let same_addr_erc20 = abi::TokenData {
            tokenType: 0,
            tokenAddress: alloy::primitives::Address::from([0x77u8; 20]),
            tokenSubID: alloy::primitives::U256::ZERO,
        };
        let h_same_addr = compute_token_data_hash(&same_addr_erc20).expect("erc20 same addr");
        assert_ne!(
            h_nft, h_same_addr,
            "ERC-20 padded-address path must differ from NFT keccak path"
        );
    }
}
