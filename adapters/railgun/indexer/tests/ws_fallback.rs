//! WS-backed `ChainSource` + `AutoFallbackChainSource` wrapper tests.
//!
//! Bad-URL error propagation + fallback latch behavior under transport errors.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::needless_continue
)]

use async_trait::async_trait;
use raven_railgun_core::RailgunEvent;
use raven_railgun_indexer::{
    AutoFallbackChainSource, ChainSource, ChainSourceMode, IndexerError, Result, WsChainSource,
};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

#[derive(Debug)]
struct FailingPrimary {
    calls: AtomicU64,
    fail_for: u64,
}

impl FailingPrimary {
    fn new(fail_for: u64) -> Self {
        Self {
            calls: AtomicU64::new(0),
            fail_for,
        }
    }
    fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
    fn maybe_fail(&self) -> Result<()> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n < self.fail_for {
            Err(IndexerError::Rpc(
                "ws connect: connection refused by peer".into(),
            ))
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl ChainSource for FailingPrimary {
    async fn latest_block(&self) -> Result<u64> {
        self.maybe_fail()?;
        Ok(2_000)
    }
    async fn events_in_range(&self, _from: u64, _to: u64) -> Result<Vec<RailgunEvent>> {
        self.maybe_fail()?;
        Ok(Vec::new())
    }
    async fn root_history(
        &self,
        _tree: u32,
        _root: [u8; 32],
        _at: Option<alloy::eips::BlockId>,
    ) -> Result<bool> {
        self.maybe_fail()?;
        Ok(true)
    }
    async fn block_hash(&self, _n: u64) -> Result<[u8; 32]> {
        self.maybe_fail()?;
        Ok([0xaa; 32])
    }
    async fn merkle_root(&self, _at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        self.maybe_fail()?;
        Ok([0xbb; 32])
    }
    async fn active_tree_number(&self, _at: Option<alloy::eips::BlockId>) -> Result<u32> {
        self.maybe_fail()?;
        Ok(7)
    }
}

#[derive(Debug)]
struct AlwaysOkFallback {
    calls: AtomicU64,
    latest: u64,
}

impl AlwaysOkFallback {
    fn new(latest: u64) -> Self {
        Self {
            calls: AtomicU64::new(0),
            latest,
        }
    }
    fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ChainSource for AlwaysOkFallback {
    async fn latest_block(&self) -> Result<u64> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.latest)
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
        Ok([0x77; 32])
    }
    async fn merkle_root(&self, _at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok([0x88; 32])
    }
    async fn active_tree_number(&self, _at: Option<alloy::eips::BlockId>) -> Result<u32> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(42)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_chain_source_bad_url_returns_error_no_panic() {
    let proxy = alloy::primitives::address!("fa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9");
    let src = WsChainSource::new("ws://127.0.0.1:1/never-listens", proxy, 1);

    let r1 = src.latest_block().await;
    assert!(r1.is_err(), "expected error from bad WS URL, got: {r1:?}");

    let r2 = src.block_hash(0).await;
    assert!(r2.is_err());

    let r3 = src.merkle_root(None).await;
    assert!(r3.is_err());

    let r4 = src.active_tree_number(None).await;
    assert!(r4.is_err());

    let r5 = src.root_history(0, [0u8; 32], None).await;
    assert!(r5.is_err());

    let r6 = src.events_in_range(0, 10).await;
    assert!(r6.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn autofallback_transitions_to_polling_on_ws_error_and_serves_from_fallback() {
    let primary = Arc::new(FailingPrimary::new(1));
    let fallback = Arc::new(AlwaysOkFallback::new(1_500));

    let wrapper = AutoFallbackChainSource::new(primary.clone(), fallback.clone());

    assert_eq!(wrapper.mode().await, ChainSourceMode::Subscribe);

    let v1 = wrapper.latest_block().await.expect("first call");
    assert_eq!(v1, 1_500, "fallback value expected, primary still failing");
    assert_eq!(wrapper.mode().await, ChainSourceMode::Polling);

    let primary_calls_after_first = primary.calls();
    let v2 = wrapper.latest_block().await.expect("second call");
    assert_eq!(v2, 1_500);
    assert_eq!(
        primary.calls(),
        primary_calls_after_first,
        "primary must not be called while inside MIN_POLLING_DURATION dwell"
    );
    assert_eq!(wrapper.mode().await, ChainSourceMode::Polling);

    assert!(
        fallback.calls() >= 2,
        "fallback should have served both calls, got {}",
        fallback.calls()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn autofallback_stays_in_subscribe_on_primary_success() {
    let primary = Arc::new(FailingPrimary::new(0));
    let fallback = Arc::new(AlwaysOkFallback::new(1_500));

    let wrapper = AutoFallbackChainSource::new(primary.clone(), fallback.clone());

    let v = wrapper.latest_block().await.expect("primary ok");
    assert_eq!(v, 2_000, "primary value expected");
    assert_eq!(wrapper.mode().await, ChainSourceMode::Subscribe);
    assert_eq!(fallback.calls(), 0, "fallback should never be touched");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn autofallback_reconnect_backoff_under_cap() {
    let primary = Arc::new(FailingPrimary::new(u64::MAX));
    let fallback = Arc::new(AlwaysOkFallback::new(1));
    let wrapper = AutoFallbackChainSource::new(primary, fallback);

    let initial = wrapper.next_reconnect_backoff().await;
    assert_eq!(
        initial.as_secs(),
        1,
        "before any failure, backoff should be 2^0 = 1s"
    );

    let _ = wrapper.latest_block().await;
    let after_one = wrapper.next_reconnect_backoff().await;
    let cap = raven_railgun_indexer::WS_RECONNECT_CAP_SECS;
    assert!(
        after_one.as_secs() <= cap,
        "backoff must be <= cap={cap}, got {after_one:?}"
    );
    assert!(
        after_one >= initial,
        "backoff must not decrease after a failure; initial={initial:?}, after={after_one:?}"
    );
}
