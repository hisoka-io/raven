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
#[non_exhaustive]
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
    #[error(
        "reorg window holds no hash for cursor {cursor}: {window_len} entries, \
         oldest={window_oldest:?} newest={window_newest:?}; a window gap is \
         indistinguishable from a divergence, so no reorg height can be derived"
    )]
    ReorgWindowMiss {
        /// Height whose cached hash was required.
        cursor: u64,
        /// Entries present in the window.
        window_len: usize,
        /// Lowest cached height, `None` when the window is empty.
        window_oldest: Option<u64>,
        /// Highest cached height, `None` when the window is empty.
        window_newest: Option<u64>,
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

/// Maximum BLOCK DISTANCE a Layer 1 walk-back may travel below the cursor
/// before bailing. Not an entry count: see [`REORG_WINDOW_ENTRIES`].
pub const MAX_REORG_BLOCKS: u64 = 256;

/// Maximum cached `(block_number, block_hash)` ENTRIES retained for Layer 1
/// reorg detection. Not a block distance: one entry per tick covers a whole
/// [`SCAN_CHUNK_BLOCKS`] chunk, so N entries span up to N chunks of blocks.
pub const REORG_WINDOW_ENTRIES: usize = 256;

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
            let Some(block_number) = block_number_or_drop(&log) else {
                continue;
            };
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
        // on-chain uint256; saturate so overflow yields OutOfSync, not panic.
        let tree_u32 = u32::try_from(decoded).unwrap_or(u32::MAX);
        Ok(tree_u32)
    }
}

/// Compute Railgun's canonical `tokenHash` from a decoded `TokenData` log struct.
/// Dispatches on `tokenType` per the Railgun engine's `src/note/note-util.ts`.
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
/// `commitment_hash = Poseidon(npk, tokenHash, valueAfterFee)` per `shield-note.ts`.
fn compute_shield_commitment_hash(preimage: &abi::CommitmentPreimage) -> Result<[u8; 32]> {
    use raven_railgun_poseidon::shield_commitment_hash;

    let npk = preimage.npk.0;
    let token_hash = compute_token_data_hash(&preimage.token)?;
    let value_u256 = alloy::primitives::U256::from(preimage.value);
    let value_be = value_u256.to_be_bytes::<32>();
    shield_commitment_hash(npk, token_hash, value_be)
        .map_err(|e| IndexerError::Decode(format!("shield commitment Poseidon: {e}")))
}

/// Height of a log, or `None` after counting it on
/// `raven_railgun_indexer_dropped_logs_total`.
///
/// A pending log carries no height. Fabricating one lands the event at height
/// 0, which no later `Reorg(h)` can undo: truncation drops only leaves above `h`.
#[must_use]
pub(crate) fn block_number_or_drop(log: &alloy::rpc::types::eth::Log) -> Option<u64> {
    if log.block_number.is_none() {
        metrics::counter!(
            "raven_railgun_indexer_dropped_logs_total",
            "reason" => "missing_block_number"
        )
        .increment(1);
        tracing::warn!(
            tx_hash = ?log.transaction_hash,
            topic0 = ?log.topic0(),
            "dropping log with missing block_number"
        );
    }
    log.block_number
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
    ///
    /// `scanned_through_block` is the worker's scan watermark, NOT the chain
    /// tip: every block up to it has been fetched and its events dispatched.
    /// Lag is measured against it because an applied-event height stalls on a
    /// quiet chain even when the scanner is fully caught up.
    Heartbeat {
        wallclock_unix_ms: u64,
        chain_head_block: u64,
        scanned_through_block: u64,
    },
}

/// Configuration for [`IndexerWorker::run`].
#[derive(Clone, Debug)]
pub struct IndexerWorkerConfig {
    /// Block to start scanning from (resume point).
    pub start_block: u64,
    /// Polling cadence between calls to `latest_block`.
    pub poll_interval_secs: u64,
    /// Maximum span to fetch per `events_in_range` call.
    /// Defaults to [`SCAN_CHUNK_BLOCKS`].
    pub chunk_blocks: u64,
    /// Per-tree floor: events for a tree in this map below its floor are dropped. Empty = no filter.
    pub per_tree_start_blocks: std::collections::BTreeMap<u32, u64>,
    /// Sidecar path for the Layer 1 reorg-window cache, persisting it across restarts. `None` = ephemeral.
    pub reorg_window_path: Option<std::path::PathBuf>,
    /// Cached `(height, hash)` entries retained. Defaults to [`REORG_WINDOW_ENTRIES`].
    pub reorg_window_entries: usize,
    /// Block distance a walk-back may travel below the cursor. Defaults to [`MAX_REORG_BLOCKS`].
    pub reorg_max_depth_blocks: u64,
}

impl Default for IndexerWorkerConfig {
    fn default() -> Self {
        Self {
            start_block: 0,
            poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
            chunk_blocks: SCAN_CHUNK_BLOCKS,
            per_tree_start_blocks: std::collections::BTreeMap::new(),
            reorg_window_path: None,
            reorg_window_entries: REORG_WINDOW_ENTRIES,
            reorg_max_depth_blocks: MAX_REORG_BLOCKS,
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
        let entry_cap = config.reorg_window_entries.max(1);
        let max_depth_blocks = config.reorg_max_depth_blocks.max(1);
        // bootstrap from sidecar so a reorg-while-down is detectable on resume.
        let mut hash_cache: std::collections::BTreeMap<u64, [u8; 32]> =
            match config.reorg_window_path.as_ref() {
                Some(path) => match load_reorg_window(path) {
                    Ok(map) => map,
                    Err(e) => {
                        tracing::warn!(
                            path = %path.display(),
                            error = %e,
                            "indexer reorg-window sidecar load failed; starting empty"
                        );
                        std::collections::BTreeMap::new()
                    }
                },
                None => std::collections::BTreeMap::new(),
            };
        // stale top hash means reorg-while-down: rebuild so the next-tick walk-back fires.
        if let Some(path) = config.reorg_window_path.as_ref() {
            if let Some((&top_height, &top_hash)) = hash_cache.iter().next_back() {
                match self.source.block_hash(top_height).await {
                    Ok(observed) if observed != top_hash => {
                        tracing::warn!(
                            top_height,
                            "indexer reorg-window stale at restart; rebuilding from RPC"
                        );
                        hash_cache = self
                            .rebuild_reorg_window(top_height, max_depth_blocks, entry_cap)
                            .await;
                        persist_reorg_window_best_effort(path, &hash_cache);
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(
                            top_height,
                            error = %e,
                            "indexer reorg-window stale-check RPC failed; \
                             keeping in-memory cache"
                        );
                    }
                }
            }
        }
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

            // Gating this on `contains_key(cursor)` would skip the check exactly
            // when the window cannot vouch for the cursor. An empty window is a
            // cold start with no baseline to check against.
            if cursor > 0 && !hash_cache.is_empty() {
                let rewind_to = match detect_reorg_layer1(
                    &*self.source,
                    &hash_cache,
                    cursor,
                    max_depth_blocks,
                )
                .await
                {
                    Ok(None) => None,
                    Ok(Some(reorg_height)) => Some(reorg_height),
                    // A gap and a divergence are the same observation, so no
                    // reorg height can be derived across it: fall back to the
                    // newest height the window can still vouch for.
                    Err(miss @ IndexerError::ReorgWindowMiss { .. }) => {
                        tracing::warn!(error = %miss, "rewinding to the newest verifiable height");
                        let verifiable = hash_cache.range(..cursor).next_back().map(|(&h, _)| h);
                        if verifiable.is_none() {
                            hash_cache.clear();
                            if let Some(path) = config.reorg_window_path.as_ref() {
                                persist_reorg_window_best_effort(path, &hash_cache);
                            }
                        }
                        verifiable
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Layer 1 reorg check failed; will retry");
                        continue;
                    }
                };
                if let Some(height) = rewind_to {
                    if self
                        .sender
                        .send(IndexerMessage::Reorg { height })
                        .await
                        .is_err()
                    {
                        return Ok(cursor);
                    }
                    hash_cache.retain(|&n, _| n <= height);
                    cursor = height;
                    if let Some(path) = config.reorg_window_path.as_ref() {
                        persist_reorg_window_best_effort(path, &hash_cache);
                    }
                    let _ = self.send_heartbeat(latest, cursor);
                    continue;
                }
            }

            if latest <= cursor {
                let _ = self.send_heartbeat(latest, cursor);
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
            // An uncached tip is a hole the walk-back cannot cross, so hold the
            // cursor rather than scan past it. Held before delivery: a hold after
            // delivery replays the whole chunk on every subsequent tick, and a
            // crash between the two would leave the window short of the events
            // the consumer already applied.
            let tip_hash = match self.source.block_hash(to).await {
                Ok(h) => h,
                Err(e) => {
                    metrics::counter!("raven_railgun_indexer_reorg_window_tip_hash_failed_total")
                        .increment(1);
                    tracing::warn!(
                        error = %e,
                        to,
                        cursor,
                        "reorg-window tip hash unavailable; holding cursor"
                    );
                    let _ = self.send_heartbeat(latest, cursor);
                    continue;
                }
            };
            hash_cache.insert(to, tip_hash);
            // Bound by entry count: a tick spans a whole chunk, so a
            // block-distance bound would evict every prior boundary.
            while hash_cache.len() > entry_cap {
                hash_cache.pop_first();
            }
            if let Some(path) = config.reorg_window_path.as_ref() {
                persist_reorg_window_best_effort(path, &hash_cache);
            }

            for event in events {
                let block_height = match &event {
                    RailgunEvent::Shield { block_number, .. }
                    | RailgunEvent::Transact { block_number, .. }
                    | RailgunEvent::Nullified { block_number, .. }
                    | RailgunEvent::Unshield { block_number, .. } => *block_number,
                };
                let event_tree = match &event {
                    RailgunEvent::Shield { tree_number, .. }
                    | RailgunEvent::Transact { tree_number, .. }
                    | RailgunEvent::Nullified { tree_number, .. } => Some(*tree_number),
                    RailgunEvent::Unshield { .. } => None,
                };
                if let Some(tree) = event_tree {
                    if let Some(&floor) = config.per_tree_start_blocks.get(&tree) {
                        if block_height < floor {
                            tracing::trace!(
                                tree_number = tree,
                                block_height,
                                floor,
                                "indexer dropping event below per-tree floor"
                            );
                            continue;
                        }
                    }
                }
                let msg = IndexerMessage::Event {
                    event,
                    block_height,
                };
                if let Err(e) = self.sender.send(msg).await {
                    tracing::info!(error = %e, "engine consumer dropped channel; exiting");
                    return Ok(cursor);
                }
            }

            cursor = to;
            let _ = self.send_heartbeat(latest, cursor);
        }
    }

    /// Rebuild the reorg-window cache from RPC below `top_height`. Used when a
    /// sidecar load detects a chain reorg deeper than the persisted window
    /// (e.g. reorged-while-down).
    ///
    /// Bounded by both inputs, which are different units: walking deeper than
    /// `depth_blocks` outruns what the walk-back can use, and walking further
    /// back than `entry_cap` buys hashes the cap immediately evicts.
    async fn rebuild_reorg_window(
        &self,
        top_height: u64,
        depth_blocks: u64,
        entry_cap: usize,
    ) -> std::collections::BTreeMap<u64, [u8; 32]> {
        let span = depth_blocks.min(u64::try_from(entry_cap).unwrap_or(u64::MAX));
        let from = top_height.saturating_sub(span);
        let mut rebuilt = std::collections::BTreeMap::new();
        for n in from..=top_height {
            match self.source.block_hash(n).await {
                Ok(h) => {
                    rebuilt.insert(n, h);
                }
                Err(e) => {
                    tracing::warn!(
                        block_number = n,
                        error = %e,
                        "indexer reorg-window rebuild block_hash failed; skipping"
                    );
                }
            }
        }
        while rebuilt.len() > entry_cap.max(1) {
            rebuilt.pop_first();
        }
        rebuilt
    }

    fn send_heartbeat(
        &self,
        chain_head_block: u64,
        scanned_through_block: u64,
    ) -> std::result::Result<(), ()> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let msg = IndexerMessage::Heartbeat {
            wallclock_unix_ms: now_ms,
            chain_head_block,
            scanned_through_block,
        };
        match self.sender.try_send(msg) {
            Ok(()) => Ok(()),
            Err(_) => Err(()),
        }
    }
}

/// Magic bytes identifying the on-disk reorg-window sidecar format.
pub const REORG_WINDOW_MAGIC: [u8; 8] = *b"RVNRGIDX";
/// Reorg-window sidecar schema version. Bump on layout changes.
pub const REORG_WINDOW_VERSION: u16 = 1;

/// Typed error for reorg-window sidecar codec failures.
///
/// Wire format for the reorg-window sidecar:
/// `magic(8) || version(u16 LE) || count(u32 LE) || count x (block(u64 LE) || hash(32))`
/// followed by a trailing CRC32 (u32 LE) over everything before it.
///
/// Atomic-renamed at write time so a torn write yields the previous
/// good copy on the next load.
#[derive(Debug)]
pub struct ReorgWindowError(String);

impl std::fmt::Display for ReorgWindowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ReorgWindowError {}

/// Serialise the reorg-window cache to the on-disk byte format.
#[must_use]
pub fn encode_reorg_window(cache: &std::collections::BTreeMap<u64, [u8; 32]>) -> Vec<u8> {
    let count: u32 = u32::try_from(cache.len()).unwrap_or(u32::MAX);
    let body_len = REORG_WINDOW_MAGIC.len() + 2 + 4 + cache.len() * (8 + 32) + 4;
    let mut buf = Vec::with_capacity(body_len);
    buf.extend_from_slice(&REORG_WINDOW_MAGIC);
    buf.extend_from_slice(&REORG_WINDOW_VERSION.to_le_bytes());
    buf.extend_from_slice(&count.to_le_bytes());
    for (height, hash) in cache {
        buf.extend_from_slice(&height.to_le_bytes());
        buf.extend_from_slice(hash);
    }
    let crc = crc32(&buf);
    buf.extend_from_slice(&crc.to_le_bytes());
    buf
}

/// Deserialise the reorg-window cache. Returns an empty map if the
/// file is missing; returns an error if the magic / version / CRC
/// checks fail.
pub fn load_reorg_window(
    path: &std::path::Path,
) -> std::result::Result<std::collections::BTreeMap<u64, [u8; 32]>, ReorgWindowError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(std::collections::BTreeMap::new());
        }
        Err(e) => return Err(ReorgWindowError(format!("read {}: {e}", path.display()))),
    };
    decode_reorg_window(&bytes)
}

/// Decode the reorg-window sidecar from a byte slice. Validates the
/// trailing CRC32, magic, and version fields before yielding the map.
pub fn decode_reorg_window(
    bytes: &[u8],
) -> std::result::Result<std::collections::BTreeMap<u64, [u8; 32]>, ReorgWindowError> {
    let header_len = REORG_WINDOW_MAGIC.len() + 2 + 4;
    if bytes.len() < header_len + 4 {
        return Err(ReorgWindowError(format!(
            "reorg-window sidecar too small: {} bytes",
            bytes.len()
        )));
    }
    let body_end = bytes.len() - 4;
    let body = bytes
        .get(..body_end)
        .ok_or_else(|| ReorgWindowError("reorg-window body slice oob".to_owned()))?;
    let crc_observed = crc32(body);
    let crc_tail = bytes
        .get(body_end..)
        .ok_or_else(|| ReorgWindowError("reorg-window crc tail oob".to_owned()))?;
    let crc_stored_arr: [u8; 4] = crc_tail
        .try_into()
        .map_err(|_| ReorgWindowError("CRC slice length mismatch".to_owned()))?;
    let crc_stored = u32::from_le_bytes(crc_stored_arr);
    if crc_observed != crc_stored {
        return Err(ReorgWindowError(format!(
            "reorg-window CRC mismatch: observed {crc_observed:08x}, stored {crc_stored:08x}"
        )));
    }
    let magic_slice = body
        .get(..REORG_WINDOW_MAGIC.len())
        .ok_or_else(|| ReorgWindowError("reorg-window magic slice oob".to_owned()))?;
    if magic_slice != REORG_WINDOW_MAGIC {
        return Err(ReorgWindowError("reorg-window magic mismatch".to_owned()));
    }
    let mut cur = REORG_WINDOW_MAGIC.len();
    let version_slice = body
        .get(cur..cur + 2)
        .ok_or_else(|| ReorgWindowError("reorg-window version slice oob".to_owned()))?;
    let version_arr: [u8; 2] = version_slice
        .try_into()
        .map_err(|_| ReorgWindowError("version slice length mismatch".to_owned()))?;
    cur += 2;
    let version = u16::from_le_bytes(version_arr);
    if version != REORG_WINDOW_VERSION {
        return Err(ReorgWindowError(format!(
            "reorg-window version mismatch: file v{version}, code v{REORG_WINDOW_VERSION}"
        )));
    }
    let count_slice = body
        .get(cur..cur + 4)
        .ok_or_else(|| ReorgWindowError("reorg-window count slice oob".to_owned()))?;
    let count_arr: [u8; 4] = count_slice
        .try_into()
        .map_err(|_| ReorgWindowError("count slice length mismatch".to_owned()))?;
    cur += 4;
    let count = u32::from_le_bytes(count_arr) as usize;
    let entry_size = 8 + 32;
    let expected = cur + count * entry_size + 4;
    if expected != bytes.len() {
        return Err(ReorgWindowError(format!(
            "reorg-window length mismatch: header says {count} entries, file is {} bytes",
            bytes.len()
        )));
    }
    let mut out = std::collections::BTreeMap::new();
    for _ in 0..count {
        let height_slice = body
            .get(cur..cur + 8)
            .ok_or_else(|| ReorgWindowError("reorg-window height slice oob".to_owned()))?;
        let height_arr: [u8; 8] = height_slice
            .try_into()
            .map_err(|_| ReorgWindowError("height slice length mismatch".to_owned()))?;
        cur += 8;
        let height = u64::from_le_bytes(height_arr);
        let hash_slice = body
            .get(cur..cur + 32)
            .ok_or_else(|| ReorgWindowError("reorg-window hash slice oob".to_owned()))?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(hash_slice);
        cur += 32;
        out.insert(height, hash);
    }
    Ok(out)
}

/// Persist the reorg window; errors are dropped (recoverable next tick) and counted on
/// `raven_railgun_indexer_reorg_window_persist_failed_total`.
pub fn persist_reorg_window_best_effort(
    path: &std::path::Path,
    cache: &std::collections::BTreeMap<u64, [u8; 32]>,
) {
    if let Err(e) = persist_reorg_window(path, cache) {
        metrics::counter!("raven_railgun_indexer_reorg_window_persist_failed_total").increment(1);
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "indexer reorg-window persist failed; will retry next tick"
        );
    }
}

/// Atomic-rename writer: write tmp, fsync, rename, then best-effort fsync the parent dir.
pub fn persist_reorg_window(
    path: &std::path::Path,
    cache: &std::collections::BTreeMap<u64, [u8; 32]>,
) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let bytes = encode_reorg_window(cache);
    let tmp = match path.file_name() {
        Some(name) => {
            let mut tmp_name = std::ffi::OsString::from(name);
            tmp_name.push(".tmp");
            path.with_file_name(tmp_name)
        }
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "reorg-window path has no file name",
            ))
        }
    };
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    // best-effort: an unsynced rename is still recoverable next tick, so never propagate.
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// CRC-32 (IEEE polynomial), vendored to avoid a CRC dep; window is a few KB so speed is moot.
fn crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut c = u32::try_from(i).unwrap_or(0);
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xedb8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *slot = c;
        }
        t
    });
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        let idx = ((crc ^ u32::from(b)) & 0xff) as usize;
        let slot = table.get(idx).copied().unwrap_or(0);
        crc = slot ^ (crc >> 8);
    }
    crc ^ 0xffff_ffff
}

/// Build the bounded MPSC for indexer-to-engine messaging (capacity 1024).
#[must_use]
pub fn build_indexer_channel() -> (
    tokio::sync::mpsc::Sender<IndexerMessage>,
    tokio::sync::mpsc::Receiver<IndexerMessage>,
) {
    tokio::sync::mpsc::channel(1024)
}

/// Layer 1 reorg detection, bounded to `max_depth_blocks` below `cursor`.
///
/// Re-fetches the cursor's block hash and walks the cache backward to find the surviving tip.
/// Returns `Ok(None)` if canonical, `Ok(Some(h))` with the surviving height,
/// `Err(ReorgWindowMiss)` if the cursor is not in the window, or
/// `Err(ReorgTooDeep)` if no cached entry within the bound survives (operator
/// intervention required).
///
/// `max_depth_blocks` is a BLOCK DISTANCE. The window is capped by entry count,
/// and a tick caches one entry per whole chunk, so an unbounded walk-back would
/// truncate thousands of blocks below the cursor.
pub async fn detect_reorg_layer1<S: ChainSource + ?Sized>(
    source: &S,
    cache: &std::collections::BTreeMap<u64, [u8; 32]>,
    cursor: u64,
    max_depth_blocks: u64,
) -> Result<Option<u64>> {
    // Checked before any RPC: a miss is knowable from the window alone, and
    // surfacing it as an Rpc error would hide the gap behind a retry.
    let Some(cached) = cache.get(&cursor).copied() else {
        return Err(IndexerError::ReorgWindowMiss {
            cursor,
            window_len: cache.len(),
            window_oldest: cache.keys().next().copied(),
            window_newest: cache.keys().next_back().copied(),
        });
    };
    let observed = source.block_hash(cursor).await?;
    if observed == cached {
        return Ok(None);
    }
    let floor = cursor.saturating_sub(max_depth_blocks);
    let candidates: Vec<(u64, [u8; 32])> = cache
        .range(floor..cursor)
        .rev()
        .map(|(&k, &v)| (k, v))
        .collect();
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

    /// Covers the routing decision over both height classes, not the
    /// `raven_railgun_indexer_dropped_logs_total` increment: the counter is
    /// asserted over the public ingest paths in `tests/subscribe_block_number_drop.rs`.
    #[test]
    fn block_number_or_drop_passes_heights_through_and_drops_pending() {
        let at_height = alloy::rpc::types::eth::Log {
            block_number: Some(77),
            ..Default::default()
        };
        assert_eq!(block_number_or_drop(&at_height), Some(77));

        let pending = alloy::rpc::types::eth::Log {
            block_number: None,
            ..Default::default()
        };
        assert_eq!(
            block_number_or_drop(&pending),
            None,
            "a pending log must drop, not land at a fabricated height"
        );
    }

    /// Spelling gate, NOT a proof that downstream matches need a wildcard: an
    /// exhaustive match inside the defining crate compiles either way, so only
    /// a compile-fail harness could observe the semantic effect.
    #[test]
    fn indexer_error_declares_non_exhaustive() {
        let src = include_str!("lib.rs");
        let decl = src
            .find("pub enum IndexerError {")
            .expect("`pub enum IndexerError {` must be present in src/lib.rs");
        let attrs: Vec<&str> = src[..decl]
            .lines()
            .rev()
            .take_while(|l| {
                let t = l.trim_start();
                t.is_empty() || t.starts_with('#') || t.starts_with("///")
            })
            .collect();
        assert!(
            attrs.iter().any(|l| l.trim() == "#[non_exhaustive]"),
            "IndexerError must carry #[non_exhaustive]; without it every added \
             variant is a breaking change for downstream matches. attrs found: {attrs:?}"
        );
    }
}
