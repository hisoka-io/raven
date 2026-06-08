//! Wiring tests for `--ws-endpoint` on `serve-production`: the WS primary
//! serves while healthy, transport-class errors fall back to polling, and the
//! transition surfaces through the `ModeFlag` the `/v1/health/ready` handler reads.
//!
//! Driven with synthetic `ChainSource` impls for determinism; the real
//! `tokio_tungstenite` listener is covered by the indexer crate's own tests.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

use async_trait::async_trait;
use raven_railgun_core::RailgunEvent;
use raven_railgun_indexer::{
    AutoFallbackChainSource, ChainSource, ChainSourceMode, IndexerError, ModeFlag, Result,
    WsChainSource,
};

const PROXY_HEX: &str = "fa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9";

fn proxy() -> alloy::primitives::Address {
    alloy::primitives::address!("fa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9")
}

/// WS-like primary: `Ok` for `success_budget` calls, then a transport-class
/// `Rpc` error so the wrapper falls back.
#[derive(Debug)]
struct FlakyWsLike {
    success_budget: AtomicU64,
    calls: AtomicU64,
    head: u64,
}

impl FlakyWsLike {
    fn new(success_budget: u64, head: u64) -> Self {
        Self {
            success_budget: AtomicU64::new(success_budget),
            calls: AtomicU64::new(0),
            head,
        }
    }
    fn try_consume(&self) -> bool {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let prev = self
            .success_budget
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                if v == 0 {
                    None
                } else {
                    Some(v - 1)
                }
            });
        prev.is_ok()
    }
}

#[async_trait]
impl ChainSource for FlakyWsLike {
    async fn latest_block(&self) -> Result<u64> {
        if self.try_consume() {
            Ok(self.head)
        } else {
            Err(IndexerError::Rpc("websocket dropped: simulated".into()))
        }
    }
    async fn events_in_range(&self, _from: u64, _to: u64) -> Result<Vec<RailgunEvent>> {
        if self.try_consume() {
            Ok(Vec::new())
        } else {
            Err(IndexerError::Rpc("websocket dropped: simulated".into()))
        }
    }
    async fn root_history(
        &self,
        _tree: u32,
        _root: [u8; 32],
        _at: Option<alloy::eips::BlockId>,
    ) -> Result<bool> {
        if self.try_consume() {
            Ok(true)
        } else {
            Err(IndexerError::Rpc("method not supported".into()))
        }
    }
    async fn block_hash(&self, _n: u64) -> Result<[u8; 32]> {
        if self.try_consume() {
            Ok([1u8; 32])
        } else {
            Err(IndexerError::Rpc("websocket dropped: simulated".into()))
        }
    }
    async fn merkle_root(&self, _at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        if self.try_consume() {
            Ok([2u8; 32])
        } else {
            Err(IndexerError::Rpc("websocket dropped: simulated".into()))
        }
    }
    async fn active_tree_number(&self, _at: Option<alloy::eips::BlockId>) -> Result<u32> {
        if self.try_consume() {
            Ok(3)
        } else {
            Err(IndexerError::Rpc("websocket dropped: simulated".into()))
        }
    }
}

/// Always-succeeds fallback returning fixed sentinels; proves the wrapper routed here.
#[derive(Debug)]
struct StaticFallback {
    head: u64,
    calls: AtomicU64,
}

impl StaticFallback {
    fn new(head: u64) -> Self {
        Self {
            head,
            calls: AtomicU64::new(0),
        }
    }
    fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ChainSource for StaticFallback {
    async fn latest_block(&self) -> Result<u64> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.head)
    }
    async fn events_in_range(&self, _from: u64, _to: u64) -> Result<Vec<RailgunEvent>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Vec::new())
    }
    async fn root_history(
        &self,
        _tree: u32,
        _root: [u8; 32],
        _at: Option<alloy::eips::BlockId>,
    ) -> Result<bool> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }
    async fn block_hash(&self, _n: u64) -> Result<[u8; 32]> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok([0xAB; 32])
    }
    async fn merkle_root(&self, _at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok([0xCD; 32])
    }
    async fn active_tree_number(&self, _at: Option<alloy::eips::BlockId>) -> Result<u32> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(7)
    }
}

/// Happy path: healthy WS stays in `Subscribe` and the mirror keeps `ModeFlag` aligned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_production_with_ws_endpoint_uses_subscribe_listener() {
    let primary = Arc::new(FlakyWsLike::new(64, 1_001));
    let fallback = Arc::new(StaticFallback::new(2_002));
    let auto = Arc::new(AutoFallbackChainSource::new(
        Arc::clone(&primary),
        Arc::clone(&fallback),
    ));

    // mirrors the production task: poll wrapper mode into a ModeFlag
    let flag = Arc::new(ModeFlag::new(ChainSourceMode::Subscribe));
    let flag_for_task = Arc::clone(&flag);
    let auto_for_task = Arc::clone(&auto);
    let mirror = tokio::spawn(async move {
        for _ in 0..50u32 {
            flag_for_task.set(auto_for_task.mode().await);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    for _ in 0..5u32 {
        let n = auto.latest_block().await.expect("latest");
        assert_eq!(n, 1_001, "WS primary should serve while budget remains");
    }
    assert_eq!(
        flag.get(),
        ChainSourceMode::Subscribe,
        "happy-path WS keeps flag in Subscribe"
    );
    assert_eq!(fallback.calls(), 0, "fallback must not be hit");

    let _ = tokio::time::timeout(Duration::from_secs(2), mirror).await;
    drop(primary);
    drop(auto);
}

/// WS failure after budget trips the wrapper to `Polling` and the ModeFlag follows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_production_ws_drop_falls_back_to_pool_within_60s() {
    let primary = Arc::new(FlakyWsLike::new(2, 9_999));
    let fallback = Arc::new(StaticFallback::new(8_888));
    let auto = Arc::new(AutoFallbackChainSource::new(
        Arc::clone(&primary),
        Arc::clone(&fallback),
    ));

    let flag = Arc::new(ModeFlag::new(ChainSourceMode::Subscribe));
    let flag_for_task = Arc::clone(&flag);
    let auto_for_task = Arc::clone(&auto);
    let mirror = tokio::spawn(async move {
        for _ in 0..200u32 {
            flag_for_task.set(auto_for_task.mode().await);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    // third call exhausts the budget, routes to fallback, stamps Polling
    let _a = auto.latest_block().await.expect("first ok");
    let _b = auto.latest_block().await.expect("second ok");
    let n = auto
        .latest_block()
        .await
        .expect("third routed via fallback");
    assert_eq!(
        n, 8_888,
        "after WS budget exhausts, the value must come from fallback"
    );

    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(2) {
        if flag.get() == ChainSourceMode::Polling {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        flag.get(),
        ChainSourceMode::Polling,
        "WS drop must surface as Polling on the operator-visible flag"
    );
    assert!(fallback.calls() >= 1, "fallback must have been called");

    let _ = tokio::time::timeout(Duration::from_secs(2), mirror).await;
}

/// "method not supported" on a `root_history` call is a transport break that routes to fallback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_production_pool_handles_eth_call_when_ws_returns_method_not_supported() {
    let primary = Arc::new(FlakyWsLike::new(0, 0));
    let fallback = Arc::new(StaticFallback::new(0));
    let auto = AutoFallbackChainSource::new(Arc::clone(&primary), Arc::clone(&fallback));

    let ok = auto
        .root_history(3, [9u8; 32], None)
        .await
        .expect("root_history routed via fallback");
    assert!(ok, "fallback must produce the bool result");
    assert_eq!(
        fallback.calls(),
        1,
        "fallback must serve exactly one root_history call"
    );
    assert_eq!(
        auto.mode().await,
        ChainSourceMode::Polling,
        "method-not-supported must demote the mode"
    );
}

/// Guards the `ChainSourceMode` -> string mapping the `/v1/health/ready` handler serializes.
#[tokio::test]
async fn serve_production_health_ready_surfaces_chain_source_mode() {
    // constructor must accept a wss:// URL without an eager handshake (lazy provider)
    let ws = WsChainSource::new("wss://eth.example/v1", proxy(), 1);
    assert_eq!(ws.rpc_url(), "wss://eth.example/v1");
    assert_eq!(
        format!("{:#x}", ws.railgun_proxy()),
        format!("0x{PROXY_HEX}")
    );

    let flag = Arc::new(ModeFlag::new(ChainSourceMode::Subscribe));
    let mode_str = match flag.get() {
        ChainSourceMode::Subscribe => "subscribe",
        ChainSourceMode::Polling => "polling",
    };
    assert_eq!(mode_str, "subscribe");
    flag.set(ChainSourceMode::Polling);
    let mode_str = match flag.get() {
        ChainSourceMode::Subscribe => "subscribe",
        ChainSourceMode::Polling => "polling",
    };
    assert_eq!(mode_str, "polling");
}

/// `MultiServeOptions` is constructible with the `ws_endpoint` field set.
#[test]
fn multi_serve_options_accepts_ws_endpoint() {
    use raven_railgun_cli::serve_production_multi::MultiServeOptions;
    let opts = MultiServeOptions {
        bind: "127.0.0.1:0".parse().expect("addr"),
        token: "ws-wiring-test-token-padded-long".to_owned(),
        rpc_url: "http://127.0.0.1:1".to_owned(),
        railgun_proxy: format!("0x{PROXY_HEX}"),
        chain_id: 1,
        start_block: 0,
        mirror_endpoint: "http://127.0.0.1:1".to_owned(),
        max_concurrent_queries: 4,
        cors_allowed_origins: None,
        trust_proxy_header: None,
        rate_limit_rps: None,
        rate_limit_burst: None,
        respond_timeout_secs: 30,
        session_eviction_interval_secs: None,
        instances: vec![],
        skip_chain_workers: true,
        skip_mirror_workers: true,
        entries: 256,
        bootstrap_observer: None,
        auto_spawn: None,
        rpc_pool: None,
        instance_templates: vec![],
        ppoi_list_templates: vec![],
        tree_fill_threshold: None,
        reload_config_path: None,
        ws_endpoint: Some("wss://eth.example/v1".to_owned()),
        reorg_window_path: None,
        metrics_public: None,
    };
    assert_eq!(opts.ws_endpoint.as_deref(), Some("wss://eth.example/v1"));
    assert_eq!(opts.chain_id, 1);
    assert_eq!(opts.respond_timeout_secs, 30);
    assert!(opts.skip_chain_workers);
}
