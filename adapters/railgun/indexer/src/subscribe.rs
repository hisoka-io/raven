//! Long-lived `eth_subscribe`-backed listener with polling fallback.
//!
//! Generic over [`LogStreamer`] so tests can drive the worker with a synthetic stream
//! producer without a real WebSocket handshake.

use std::{
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::{
    decode_log_to_railgun_event, ChainSource, ChainSourceMode, IndexerError, IndexerMessage,
    Result, MAX_RPC_TOTAL_ELAPSED_SECS, MIN_POLLING_DURATION,
};

/// Heartbeat window; if no frame crosses the listener within this interval, fall back to polling.
pub const SUBSCRIBE_HEARTBEAT_SECS: u64 = 30;

/// Channel capacity for forwarded `newHeads`/`logs` frames. Bounded to prevent unbounded
/// memory growth if the downstream consumer stalls; back-pressure triggers polling fallback.
pub const SUBSCRIBE_CHANNEL_CAPACITY: usize = 256;

/// Long-lived stream producer for a Railgun chain WS subscription.
#[async_trait]
pub trait LogStreamer: Send + Sync + 'static {
    /// Open both subscriptions and return the two receiver halves.
    async fn open(&self) -> Result<SubscribeStreams>;
}

/// Pair of bounded channels handed back by a [`LogStreamer`].
#[derive(Debug)]
pub struct SubscribeStreams {
    pub heads: mpsc::Receiver<Result<u64>>,
    pub logs: mpsc::Receiver<Result<alloy::rpc::types::eth::Log>>,
}

/// Production [`LogStreamer`] that opens `eth_subscribe(newHeads)` and `eth_subscribe(logs, ...)`
/// and pumps items into bounded channels. Each `open()` establishes a fresh WS handshake.
#[derive(Debug)]
pub struct AlloyWsLogStreamer {
    rpc_url: String,
    railgun_proxy: alloy::primitives::Address,
    chain_id: u64,
    channel_capacity: usize,
}

impl AlloyWsLogStreamer {
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
            channel_capacity: SUBSCRIBE_CHANNEL_CAPACITY,
        }
    }

    #[must_use]
    pub fn with_channel_capacity(mut self, cap: usize) -> Self {
        self.channel_capacity = cap.max(1);
        self
    }
}

#[async_trait]
impl LogStreamer for AlloyWsLogStreamer {
    async fn open(&self) -> Result<SubscribeStreams> {
        use alloy::sol_types::SolEvent;

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

        let topic0 = [
            crate::abi::Shield::SIGNATURE_HASH,
            crate::abi::Transact::SIGNATURE_HASH,
            crate::abi::Unshield::SIGNATURE_HASH,
            crate::abi::Nullified::SIGNATURE_HASH,
        ];
        let filter = alloy::rpc::types::eth::Filter::new()
            .address(self.railgun_proxy)
            .event_signature(topic0.to_vec());

        let head_sub = alloy::providers::Provider::subscribe_blocks(&provider)
            .await
            .map_err(|e| IndexerError::Rpc(format!("eth_subscribe newHeads: {e}")))?;
        let log_sub = alloy::providers::Provider::subscribe_logs(&provider, &filter)
            .await
            .map_err(|e| IndexerError::Rpc(format!("eth_subscribe logs: {e}")))?;

        let (heads_tx, heads_rx) = mpsc::channel(self.channel_capacity);
        let (logs_tx, logs_rx) = mpsc::channel(self.channel_capacity);

        let mut heads = head_sub;
        let _provider = provider;
        tokio::spawn(async move {
            loop {
                match heads.recv().await {
                    Ok(header) => {
                        let n = header.inner.number;
                        if heads_tx.send(Ok(n)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = heads_tx
                            .send(Err(IndexerError::Rpc(format!("newHeads stream: {e}"))))
                            .await;
                        break;
                    }
                }
            }
        });

        let mut logs = log_sub;
        tokio::spawn(async move {
            loop {
                match logs.recv().await {
                    Ok(log) => {
                        if logs_tx.send(Ok(log)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = logs_tx
                            .send(Err(IndexerError::Rpc(format!("logs stream: {e}"))))
                            .await;
                        break;
                    }
                }
            }
        });

        Ok(SubscribeStreams {
            heads: heads_rx,
            logs: logs_rx,
        })
    }
}

/// Atomic mode flag shared between the worker loop and external observers (e.g. health handlers).
#[derive(Debug)]
pub struct ModeFlag {
    inner: AtomicU8,
}

impl Default for ModeFlag {
    fn default() -> Self {
        Self::new(ChainSourceMode::Subscribe)
    }
}

impl ModeFlag {
    #[must_use]
    pub fn new(initial: ChainSourceMode) -> Self {
        Self {
            inner: AtomicU8::new(mode_to_u8(initial)),
        }
    }

    pub fn get(&self) -> ChainSourceMode {
        u8_to_mode(self.inner.load(Ordering::Acquire))
    }

    pub fn set(&self, mode: ChainSourceMode) {
        self.inner.store(mode_to_u8(mode), Ordering::Release);
    }
}

const MODE_SUBSCRIBE: u8 = 0;
const MODE_POLLING: u8 = 1;

fn mode_to_u8(m: ChainSourceMode) -> u8 {
    match m {
        ChainSourceMode::Subscribe => MODE_SUBSCRIBE,
        ChainSourceMode::Polling => MODE_POLLING,
    }
}

fn u8_to_mode(v: u8) -> ChainSourceMode {
    if v == MODE_POLLING {
        ChainSourceMode::Polling
    } else {
        ChainSourceMode::Subscribe
    }
}

/// Configuration for [`SubscribeWorker::run`].
#[derive(Clone, Debug)]
pub struct SubscribeWorkerConfig {
    pub heartbeat_secs: u64,
    pub reconnect_total_secs: u64,
    pub polling_dwell: Duration,
}

impl Default for SubscribeWorkerConfig {
    fn default() -> Self {
        Self {
            heartbeat_secs: SUBSCRIBE_HEARTBEAT_SECS,
            reconnect_total_secs: MAX_RPC_TOTAL_ELAPSED_SECS,
            polling_dwell: MIN_POLLING_DURATION,
        }
    }
}

/// Worker driving a [`LogStreamer`] with a polling [`ChainSource`] fallback.
///
/// Falls back to polling on stream error/close/heartbeat miss; stays in polling once the
/// cumulative reconnect budget (`reconnect_total_secs`) is exhausted.
pub struct SubscribeWorker<Stream, Fallback>
where
    Stream: LogStreamer,
    Fallback: ChainSource,
{
    streamer: Arc<Stream>,
    fallback: Arc<Fallback>,
    sender: mpsc::Sender<IndexerMessage>,
    mode: Arc<ModeFlag>,
}

impl<Stream, Fallback> std::fmt::Debug for SubscribeWorker<Stream, Fallback>
where
    Stream: LogStreamer + std::fmt::Debug,
    Fallback: ChainSource + std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubscribeWorker")
            .field("streamer", &self.streamer)
            .field("fallback", &self.fallback)
            .field("mode", &self.mode.get())
            .finish_non_exhaustive()
    }
}

impl<Stream, Fallback> SubscribeWorker<Stream, Fallback>
where
    Stream: LogStreamer,
    Fallback: ChainSource,
{
    pub fn new(
        streamer: Arc<Stream>,
        fallback: Arc<Fallback>,
        sender: mpsc::Sender<IndexerMessage>,
    ) -> Self {
        Self {
            streamer,
            fallback,
            sender,
            mode: Arc::new(ModeFlag::default()),
        }
    }

    pub fn with_mode_flag(
        streamer: Arc<Stream>,
        fallback: Arc<Fallback>,
        sender: mpsc::Sender<IndexerMessage>,
        mode: Arc<ModeFlag>,
    ) -> Self {
        Self {
            streamer,
            fallback,
            sender,
            mode,
        }
    }

    pub fn mode_flag(&self) -> Arc<ModeFlag> {
        Arc::clone(&self.mode)
    }

    pub fn current_mode(&self) -> ChainSourceMode {
        self.mode.get()
    }

    /// Drive the worker until the outbound channel closes.
    ///
    /// The reconnect budget (`reconnect_total_secs`) is anchored at the first loop entry so
    /// a flapping endpoint cannot reset it on every successful open.
    pub async fn run(&self, config: SubscribeWorkerConfig) -> Result<()> {
        let total_budget = Duration::from_secs(config.reconnect_total_secs);
        let outer_started = Instant::now();
        loop {
            if self.sender.is_closed() {
                tracing::info!("subscribe worker exiting; outbound channel closed");
                return Ok(());
            }

            let connect_started = Instant::now();
            self.mode.set(ChainSourceMode::Subscribe);

            match self.streamer.open().await {
                Ok(streams) => {
                    tracing::info!("WS subscription opened");
                    self.drain_streams(streams, &config).await?;
                    tracing::warn!("WS subscription closed; entering polling dwell");
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        elapsed_secs = connect_started.elapsed().as_secs(),
                        "WS subscription open failed; entering polling dwell"
                    );
                }
            }

            if self.sender.is_closed() {
                return Ok(());
            }

            self.mode.set(ChainSourceMode::Polling);
            let polling_started = Instant::now();
            let dwell = config.polling_dwell;
            self.run_polling(polling_started, dwell).await?;

            if self.sender.is_closed() {
                return Ok(());
            }

            if outer_started.elapsed() >= total_budget {
                tracing::warn!(
                    cumulative_elapsed_secs = outer_started.elapsed().as_secs(),
                    budget_secs = total_budget.as_secs(),
                    "subscribe reconnect budget exhausted; staying in polling mode"
                );
                self.run_polling_indefinitely().await?;
                return Ok(());
            }
        }
    }

    async fn drain_streams(
        &self,
        streams: SubscribeStreams,
        config: &SubscribeWorkerConfig,
    ) -> Result<()> {
        let SubscribeStreams {
            mut heads,
            mut logs,
        } = streams;
        let heartbeat = Duration::from_secs(config.heartbeat_secs.max(1));
        let mut last_chain_head: u64 = 0;
        let mut last_frame_at = Instant::now();
        let mut heads_open = true;
        let mut logs_open = true;

        while heads_open || logs_open {
            let since_last = last_frame_at.elapsed();
            let remaining = heartbeat.saturating_sub(since_last);
            if remaining.is_zero() {
                tracing::warn!(
                    window_secs = heartbeat.as_secs(),
                    "WS heartbeat window expired without frames"
                );
                return Ok(());
            }

            tokio::select! {
                biased;

                () = self.sender.closed() => {
                    return Ok(());
                }

                head_frame = async { heads.recv().await }, if heads_open => {
                    match head_frame {
                        Some(Ok(n)) => {
                            last_chain_head = n;
                            last_frame_at = Instant::now();
                            self.send_heartbeat(n);
                        }
                        Some(Err(e)) => {
                            tracing::warn!(error = %e, "WS newHeads error frame");
                            return Ok(());
                        }
                        None => {
                            tracing::debug!("WS newHeads stream closed; logs stream may continue");
                            heads_open = false;
                        }
                    }
                }

                log_frame = async { logs.recv().await }, if logs_open => {
                    match log_frame {
                        Some(Ok(log)) => {
                            last_frame_at = Instant::now();
                            self.handle_log_frame(log, last_chain_head).await?;
                        }
                        Some(Err(e)) => {
                            tracing::warn!(error = %e, "WS logs error frame");
                            return Ok(());
                        }
                        None => {
                            tracing::debug!("WS logs stream closed; heads stream may continue");
                            logs_open = false;
                        }
                    }
                }

                () = tokio::time::sleep(remaining) => {
                    tracing::warn!(
                        window_secs = heartbeat.as_secs(),
                        "WS heartbeat missed; treating as transport break"
                    );
                    return Ok(());
                }
            }
        }
        tracing::debug!("both WS streams closed cleanly; returning to reconnect loop");
        Ok(())
    }

    async fn handle_log_frame(
        &self,
        log: alloy::rpc::types::eth::Log,
        observed_head: u64,
    ) -> Result<()> {
        let block_number = log.block_number.unwrap_or(observed_head);
        let tx_hash = log.transaction_hash.map_or([0u8; 32], |h| h.0);
        let topic0 = log.topic0().copied().unwrap_or_default();
        let event = decode_log_to_railgun_event(topic0, &log, block_number, tx_hash)?;
        if let Some(e) = event {
            let msg = IndexerMessage::Event {
                event: e,
                block_height: block_number,
            };
            if self.sender.send(msg).await.is_err() {
                tracing::info!("downstream consumer dropped channel; exiting");
            }
        }
        Ok(())
    }

    fn send_heartbeat(&self, chain_head_block: u64) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let msg = IndexerMessage::Heartbeat {
            wallclock_unix_ms: now_ms,
            chain_head_block,
        };
        let _ = self.sender.try_send(msg);
    }

    async fn run_polling(&self, started: Instant, dwell: Duration) -> Result<()> {
        let base_tick = Duration::from_secs(crate::DEFAULT_POLL_INTERVAL_SECS.max(1));
        let tick = base_tick.min(dwell.max(Duration::from_millis(1)));
        loop {
            if self.sender.is_closed() {
                return Ok(());
            }
            if started.elapsed() >= dwell {
                return Ok(());
            }
            match self.fallback.latest_block().await {
                Ok(n) => {
                    self.send_heartbeat(n);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "polling fallback latest_block failed");
                }
            }
            tokio::time::sleep(tick).await;
        }
    }

    async fn run_polling_indefinitely(&self) -> Result<()> {
        let tick = Duration::from_secs(crate::DEFAULT_POLL_INTERVAL_SECS.max(1));
        while !self.sender.is_closed() {
            match self.fallback.latest_block().await {
                Ok(n) => {
                    self.send_heartbeat(n);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "polling fallback latest_block failed");
                }
            }
            tokio::time::sleep(tick).await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_flag_round_trips() {
        let flag = ModeFlag::default();
        assert_eq!(flag.get(), ChainSourceMode::Subscribe);
        flag.set(ChainSourceMode::Polling);
        assert_eq!(flag.get(), ChainSourceMode::Polling);
        flag.set(ChainSourceMode::Subscribe);
        assert_eq!(flag.get(), ChainSourceMode::Subscribe);
    }

    #[test]
    fn subscribe_worker_config_defaults_match_constants() {
        let cfg = SubscribeWorkerConfig::default();
        assert_eq!(cfg.heartbeat_secs, SUBSCRIBE_HEARTBEAT_SECS);
        assert_eq!(cfg.reconnect_total_secs, MAX_RPC_TOTAL_ELAPSED_SECS);
        assert_eq!(cfg.polling_dwell, MIN_POLLING_DURATION);
    }

    #[test]
    fn alloy_streamer_constructor_round_trips() {
        let proxy = alloy::primitives::address!("fa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9");
        let s = AlloyWsLogStreamer::new("wss://eth.example/v1", proxy, 1).with_channel_capacity(8);
        assert_eq!(s.rpc_url, "wss://eth.example/v1");
        assert_eq!(s.railgun_proxy, proxy);
        assert_eq!(s.chain_id, 1);
        assert_eq!(s.channel_capacity, 8);
    }
}
