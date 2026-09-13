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
            transport_err()
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

/// Fails only after every participant is parked inside the call, which means
/// every participant has already passed the Subscribe-mode gate: all `n` calls
/// record a failure instead of the 2nd..nth being swallowed by the polling
/// dwell. That makes `reconnect_attempt = n` reachable in-process.
#[derive(Debug)]
struct BarrierPrimary {
    barrier: tokio::sync::Barrier,
}

impl BarrierPrimary {
    fn new(parties: usize) -> Self {
        Self {
            barrier: tokio::sync::Barrier::new(parties.max(1)),
        }
    }
}

fn transport_err<T>() -> Result<T> {
    Err(IndexerError::Provider {
        operation: "test WS transport",
        source: alloy::transports::TransportErrorKind::custom_str("connection refused by peer"),
    })
}

fn method_missing<T>() -> Result<T> {
    let source = alloy::transports::TransportError::deser_err(
        serde_json::from_str::<serde_json::Value>("{")
            .expect_err("the malformed control must fail JSON decoding"),
        r#"{"code":-32601,"message":"Method not found"}"#,
    );
    Err(IndexerError::Provider {
        operation: "test WS method",
        source,
    })
}

fn parse_error<T>() -> Result<T> {
    let source = alloy::transports::TransportError::deser_err(
        serde_json::from_str::<serde_json::Value>("{")
            .expect_err("the malformed control must fail JSON decoding"),
        r#"{"code":-32700,"message":"Parse error"}"#,
    );
    Err(IndexerError::Provider {
        operation: "test invalid request",
        source,
    })
}

#[derive(Debug, Clone, Copy)]
enum DecodeFailure {
    Application,
    RemoteResponse,
}

#[derive(Debug)]
struct DecodeFailingPrimary(DecodeFailure);

impl DecodeFailingPrimary {
    fn fail<T>(&self) -> Result<T> {
        match self.0 {
            DecodeFailure::Application => Err(IndexerError::Decode("malformed event".into())),
            DecodeFailure::RemoteResponse => {
                let parse_error = serde_json::from_str::<serde_json::Value>("{")
                    .expect_err("the malformed control must fail JSON decoding");
                Err(IndexerError::Provider {
                    operation: "test WS response",
                    source: alloy::transports::TransportError::deser_err(parse_error, "{"),
                })
            }
        }
    }
}

#[async_trait]
impl ChainSource for DecodeFailingPrimary {
    async fn latest_block(&self) -> Result<u64> {
        self.fail()
    }

    async fn events_in_range(&self, _from: u64, _to: u64) -> Result<Vec<RailgunEvent>> {
        self.fail()
    }

    async fn root_history(
        &self,
        _tree: u32,
        _root: [u8; 32],
        _at: Option<alloy::eips::BlockId>,
    ) -> Result<bool> {
        self.fail()
    }

    async fn block_hash(&self, _n: u64) -> Result<[u8; 32]> {
        self.fail()
    }

    async fn merkle_root(&self, _at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        self.fail()
    }

    async fn active_tree_number(&self, _at: Option<alloy::eips::BlockId>) -> Result<u32> {
        self.fail()
    }
}

async fn assert_decode_uses_http_fallback(failure: DecodeFailure) {
    let primary = Arc::new(DecodeFailingPrimary(failure));
    let fallback = Arc::new(AlwaysOkFallback::new(1_337));
    let wrapper = AutoFallbackChainSource::new(primary, Arc::clone(&fallback));

    assert_eq!(wrapper.latest_block().await.expect("HTTP fallback"), 1_337);
    assert_eq!(wrapper.mode().await, ChainSourceMode::Polling);
    assert_eq!(fallback.calls(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn application_decode_uses_an_independent_http_fallback() {
    assert_decode_uses_http_fallback(DecodeFailure::Application).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_response_decode_uses_http_fallback() {
    assert_decode_uses_http_fallback(DecodeFailure::RemoteResponse).await;
}

#[derive(Debug)]
struct MethodMissingPrimary;

#[async_trait]
impl ChainSource for MethodMissingPrimary {
    async fn latest_block(&self) -> Result<u64> {
        method_missing()
    }

    async fn events_in_range(&self, _from: u64, _to: u64) -> Result<Vec<RailgunEvent>> {
        method_missing()
    }

    async fn root_history(
        &self,
        _tree: u32,
        _root: [u8; 32],
        _at: Option<alloy::eips::BlockId>,
    ) -> Result<bool> {
        method_missing()
    }

    async fn block_hash(&self, _n: u64) -> Result<[u8; 32]> {
        method_missing()
    }

    async fn merkle_root(&self, _at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        method_missing()
    }

    async fn active_tree_number(&self, _at: Option<alloy::eips::BlockId>) -> Result<u32> {
        method_missing()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_method_not_found_fails_fast_but_ws_falls_back_to_polling() {
    let primary = Arc::new(MethodMissingPrimary);
    let fallback = Arc::new(AlwaysOkFallback::new(1_337));
    let wrapper = AutoFallbackChainSource::new(primary, Arc::clone(&fallback));

    assert_eq!(wrapper.latest_block().await.expect("HTTP fallback"), 1_337);
    assert_eq!(wrapper.mode().await, ChainSourceMode::Polling);
    assert_eq!(fallback.calls(), 1);
}

#[derive(Debug)]
struct ParseErrorPrimary;

#[async_trait]
impl ChainSource for ParseErrorPrimary {
    async fn latest_block(&self) -> Result<u64> {
        parse_error()
    }

    async fn events_in_range(&self, _from: u64, _to: u64) -> Result<Vec<RailgunEvent>> {
        parse_error()
    }

    async fn root_history(
        &self,
        _tree: u32,
        _root: [u8; 32],
        _at: Option<alloy::eips::BlockId>,
    ) -> Result<bool> {
        parse_error()
    }

    async fn block_hash(&self, _n: u64) -> Result<[u8; 32]> {
        parse_error()
    }

    async fn merkle_root(&self, _at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        parse_error()
    }

    async fn active_tree_number(&self, _at: Option<alloy::eips::BlockId>) -> Result<u32> {
        parse_error()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn json_rpc_parse_error_never_uses_http_fallback() {
    let primary = Arc::new(ParseErrorPrimary);
    let fallback = Arc::new(AlwaysOkFallback::new(1_337));
    let wrapper = AutoFallbackChainSource::new(primary, Arc::clone(&fallback));

    let error = wrapper
        .latest_block()
        .await
        .expect_err("JSON-RPC parse error must fail fast");
    assert!(matches!(
        error,
        IndexerError::Provider {
            source: alloy::transports::RpcError::ErrorResp(payload),
            ..
        } if payload.code == -32700
    ));
    assert_eq!(wrapper.mode().await, ChainSourceMode::Subscribe);
    assert_eq!(fallback.calls(), 0);
}

#[async_trait]
impl ChainSource for BarrierPrimary {
    async fn latest_block(&self) -> Result<u64> {
        self.barrier.wait().await;
        transport_err()
    }
    async fn events_in_range(&self, _from: u64, _to: u64) -> Result<Vec<RailgunEvent>> {
        transport_err()
    }
    async fn root_history(
        &self,
        _tree: u32,
        _root: [u8; 32],
        _at: Option<alloy::eips::BlockId>,
    ) -> Result<bool> {
        transport_err()
    }
    async fn block_hash(&self, _n: u64) -> Result<[u8; 32]> {
        transport_err()
    }
    async fn merkle_root(&self, _at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        transport_err()
    }
    async fn active_tree_number(&self, _at: Option<alloy::eips::BlockId>) -> Result<u32> {
        transport_err()
    }
}

/// Backoff after exactly `failures` recorded WS transport failures.
async fn backoff_after_failures(failures: u32) -> std::time::Duration {
    let primary = Arc::new(BarrierPrimary::new(failures as usize));
    let fallback = Arc::new(AlwaysOkFallback::new(1));
    let wrapper = Arc::new(AutoFallbackChainSource::new(primary, fallback));

    let mut handles = Vec::with_capacity(failures as usize);
    for _ in 0..failures {
        let w = Arc::clone(&wrapper);
        handles.push(tokio::spawn(async move {
            let _ = w.latest_block().await;
        }));
    }
    for h in handles {
        h.await.expect("failure task joined");
    }
    wrapper.next_reconnect_backoff().await
}

/// Locks the whole curve `min(2^attempt, cap)`, not just its first point: a
/// removed cap and a frozen (non-doubling) backoff each passed the previous
/// version of this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn autofallback_reconnect_backoff_doubles_then_caps() {
    let cap = raven_railgun_indexer::WS_RECONNECT_CAP_SECS;
    let mut prev = 0u64;
    for failures in [0u32, 1, 2, 3, 4, 5, 6, 40] {
        let expected = (1u64 << failures.min(31)).min(cap);
        let got = backoff_after_failures(failures).await;
        assert_eq!(
            got.as_secs(),
            expected,
            "after {failures} failures the backoff must be min(2^{failures}, {cap})s"
        );
        assert!(
            got.as_secs() >= prev,
            "backoff must never decrease as failures accumulate; \
             {prev}s -> {got:?} at {failures} failures"
        );
        prev = got.as_secs();
    }
    assert_eq!(
        backoff_after_failures(5).await.as_secs(),
        cap,
        "2^5 = 32 > {cap}: the cap must clamp from the 5th failure on"
    );
}
