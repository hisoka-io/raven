//! RED pins for two KNOWN `subscribe.rs` defects, kept `#[ignore]`d so CI
//! stays green until the fixes land. Run with `--run-ignored` to see them red.
//!
//! 1. `handle_log_frame` never reads `log.removed`: a reorged-out log
//!    (`removed: true`) is forwarded as a fresh `Event`, re-applying a leaf
//!    the chain has withdrawn. Trigger: any WS `logs` subscription frame with
//!    `removed: true` (Geth/Erigon emit these on reorg).
//! 2. `SubscribeWorker::run` has no gap backfill: events landing between a
//!    stream close and the next successful open are never delivered. The
//!    fallback `ChainSource` can serve them via `events_in_range`, but the
//!    worker never asks. Trigger: any WS reconnect while the chain advances.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::needless_continue,
    clippy::match_same_arms
)]

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use alloy::primitives::{Address as AlloyAddress, B256, U256};
use alloy::sol_types::{SolEvent, SolValue};
use async_trait::async_trait;
use raven_railgun_core::RailgunEvent;
use raven_railgun_indexer::{
    abi, ChainSource, IndexerMessage, LogStreamer, Result, SubscribeStreams, SubscribeWorker,
    SubscribeWorkerConfig,
};
use tokio::sync::mpsc;

fn shield_log(block_number: u64, removed: bool) -> alloy::rpc::types::eth::Log {
    let commitments = vec![abi::CommitmentPreimage {
        npk: B256::from([0x07_u8; 32]),
        token: abi::TokenData {
            tokenType: 0,
            tokenAddress: AlloyAddress::from([0x42; 20]),
            tokenSubID: U256::from(0u64),
        },
        value: alloy::primitives::Uint::<120, 2>::from(1_000u64),
    }];
    let shield_ct = vec![abi::ShieldCiphertext {
        encryptedBundle: [B256::ZERO, B256::ZERO, B256::ZERO],
        shieldKey: B256::ZERO,
    }];
    let fees: Vec<U256> = vec![U256::from(0u64)];
    let data = (
        U256::from(0u64),
        U256::from(0u64),
        commitments,
        shield_ct,
        fees,
    )
        .abi_encode_params();
    alloy::rpc::types::eth::Log {
        inner: alloy::primitives::Log {
            address: AlloyAddress::ZERO,
            data: alloy::primitives::LogData::new_unchecked(
                vec![abi::Shield::SIGNATURE_HASH],
                data.into(),
            ),
        },
        block_number: Some(block_number),
        transaction_hash: Some(B256::ZERO),
        removed,
        ..Default::default()
    }
}

/// Serves a per-open script of (heads, logs); each open consumes one script
/// entry, then the streams close so the worker cycles into its next open.
#[derive(Debug)]
struct ScriptedOpens {
    scripts: Mutex<Vec<(Vec<u64>, Vec<alloy::rpc::types::eth::Log>)>>,
    opens: AtomicU64,
}

#[async_trait]
impl LogStreamer for ScriptedOpens {
    async fn open(&self) -> Result<SubscribeStreams> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        let (heads, logs) = {
            let mut g = self.scripts.lock().expect("poison");
            if g.is_empty() {
                (Vec::new(), Vec::new())
            } else {
                g.remove(0)
            }
        };
        let (heads_tx, heads_rx) = mpsc::channel(heads.len() + 1);
        let (logs_tx, logs_rx) = mpsc::channel(logs.len() + 1);
        for n in heads {
            heads_tx.try_send(Ok(n)).expect("heads script fits");
        }
        for log in logs {
            logs_tx.try_send(Ok(log)).expect("logs script fits");
        }
        // Both senders drop here: the streams close once drained, forcing the
        // reconnect path under test.
        Ok(SubscribeStreams {
            heads: heads_rx,
            logs: logs_rx,
        })
    }
}

/// Fallback that can serve real events for the gap the stream missed.
#[derive(Debug)]
struct BackfillFallback {
    tip: u64,
    events: Vec<RailgunEvent>,
    range_calls: AtomicU64,
}

#[async_trait]
impl ChainSource for BackfillFallback {
    async fn latest_block(&self) -> Result<u64> {
        Ok(self.tip)
    }
    async fn events_in_range(&self, from: u64, to: u64) -> Result<Vec<RailgunEvent>> {
        self.range_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .events
            .iter()
            .filter(|e| {
                let h = match e {
                    RailgunEvent::Shield { block_number, .. }
                    | RailgunEvent::Transact { block_number, .. }
                    | RailgunEvent::Nullified { block_number, .. }
                    | RailgunEvent::Unshield { block_number, .. } => *block_number,
                };
                (from..=to).contains(&h)
            })
            .cloned()
            .collect())
    }
    async fn root_history(
        &self,
        _tree: u32,
        _root: [u8; 32],
        _at: Option<alloy::eips::BlockId>,
    ) -> Result<bool> {
        Ok(true)
    }
    async fn block_hash(&self, _n: u64) -> Result<[u8; 32]> {
        Ok([0u8; 32])
    }
    async fn merkle_root(&self, _at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        Ok([0u8; 32])
    }
    async fn active_tree_number(&self, _at: Option<alloy::eips::BlockId>) -> Result<u32> {
        Ok(0)
    }
}

async fn collect_event_heights(rx: &mut mpsc::Receiver<IndexerMessage>, for_secs: u64) -> Vec<u64> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(for_secs);
    let mut heights = Vec::new();
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(300), rx.recv()).await {
            Ok(Some(IndexerMessage::Event { block_height, .. })) => heights.push(block_height),
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    heights
}

/// DEFECT PIN (red today): a `removed: true` log frame must NOT be forwarded
/// as a fresh event. `handle_log_frame` ignores the flag, so the withdrawn
/// leaf is re-applied downstream with no `Reorg` fence.
#[ignore = "pins subscribe.rs defect: log.removed is ignored and replayed as an insert"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removed_log_frame_is_not_forwarded_as_an_event() {
    let streamer = Arc::new(ScriptedOpens {
        scripts: Mutex::new(vec![(vec![100], vec![shield_log(100, true)])]),
        opens: AtomicU64::new(0),
    });
    let fallback = Arc::new(BackfillFallback {
        tip: 100,
        events: Vec::new(),
        range_calls: AtomicU64::new(0),
    });
    let (tx, mut rx) = mpsc::channel(16);
    let worker = SubscribeWorker::new(streamer, fallback, tx);
    let cfg = SubscribeWorkerConfig {
        heartbeat_secs: 1,
        reconnect_total_secs: 1,
        polling_dwell: Duration::from_millis(100),
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let heights = collect_event_heights(&mut rx, 4).await;
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;

    assert!(
        heights.is_empty(),
        "a removed (reorged-out) log must not surface as an Event; got heights {heights:?}"
    );
}

/// DEFECT PIN (red today): events landing while the stream was down must be
/// backfilled on reconnect. The worker inherits only a watermark across the
/// dwell and never asks the fallback for the missed range, so block 101's
/// Shield leaf is silently lost.
#[ignore = "pins subscribe.rs defect: no gap backfill across reconnect"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_missed_between_stream_close_and_reopen_are_backfilled() {
    // Open 1 sees block 100; the gap event lands at 101 while the stream is
    // down; open 2 resumes at 102 without replaying 101.
    let streamer = Arc::new(ScriptedOpens {
        scripts: Mutex::new(vec![
            (vec![100], vec![shield_log(100, false)]),
            (vec![102], vec![shield_log(102, false)]),
        ]),
        opens: AtomicU64::new(0),
    });
    let missed = RailgunEvent::Unshield {
        block_number: 101,
        tx_hash: [0xab; 32],
        to: [0x11; 20],
        token: [0x22; 32],
        amount: 1,
        fee: 0,
    };
    let fallback = Arc::new(BackfillFallback {
        tip: 102,
        events: vec![missed],
        range_calls: AtomicU64::new(0),
    });
    let (tx, mut rx) = mpsc::channel(64);
    let worker = SubscribeWorker::new(streamer, fallback, tx);
    let cfg = SubscribeWorkerConfig {
        heartbeat_secs: 1,
        reconnect_total_secs: 20,
        polling_dwell: Duration::from_millis(100),
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let heights = collect_event_heights(&mut rx, 8).await;
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;

    assert!(
        heights.contains(&101),
        "the event that landed during the reconnect gap must be delivered \
         (backfilled from the fallback); got heights {heights:?}"
    );
}
