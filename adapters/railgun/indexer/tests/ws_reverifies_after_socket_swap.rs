//! A WS chain id verified once describes the first socket, not the current one.
//!
//! alloy re-dials underneath a live provider handle (`alloy-pubsub` `service.rs:61` calls
//! `try_reconnect`) and the consumer sees neither an error nor a stream close. So a check
//! performed inside a `OnceCell` initialiser is evidence about a connection that may no
//! longer exist, and a URL repointed onto another chain is served unverified from then on.
//!
//! This drives the real thing: a WS server that answers one chain, drops the socket, then
//! answers a different chain on the next accept. Without the dial counter the second answer
//! is never checked and the source keeps serving.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use raven_railgun_indexer::{ws::WsChainSource, ChainSource, IndexerError};
use serde_json::{json, Value};

const HONEST_CHAIN: u64 = 1;
const FOREIGN_CHAIN: u64 = 137;

const ZERO32: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

/// A minimally-complete block. The test asserts on `number`; every other field exists only
/// so the response deserializes.
fn block_at(number: u64) -> Value {
    json!({
        "hash": ZERO32,
        "parentHash": ZERO32,
        "sha3Uncles": ZERO32,
        "miner": "0x0000000000000000000000000000000000000000",
        "stateRoot": ZERO32,
        "transactionsRoot": ZERO32,
        "receiptsRoot": ZERO32,
        "logsBloom": format!("0x{}", "0".repeat(512)),
        "difficulty": "0x0",
        "number": format!("0x{number:x}"),
        "gasLimit": "0x1c9c380",
        "gasUsed": "0x0",
        "timestamp": "0x65000000",
        "extraData": "0x",
        "mixHash": ZERO32,
        "nonce": "0x0000000000000000",
        "baseFeePerGas": "0x7",
        "size": "0x220",
        "transactions": [],
        "uncles": []
    })
}

/// Serves JSON-RPC over WS. The Nth accepted connection reports `chains[N-1]`, and any
/// connection past the first entry stays open; the first one closes after `close_after`
/// requests so alloy is forced to re-dial.
async fn spawn_ws(chains: Vec<u64>, close_after: usize) -> (String, Arc<AtomicU64>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let accepts = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&accepts);

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let n = usize::try_from(counter.fetch_add(1, Ordering::SeqCst)).unwrap_or(usize::MAX);
            let reported = *chains.get(n).unwrap_or(chains.last().expect("non-empty"));
            let is_first = n == 0;
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let mut served = 0usize;
                while let Some(Ok(msg)) = ws.next().await {
                    let tokio_tungstenite::tungstenite::Message::Text(text) = msg else {
                        continue;
                    };
                    let Ok(req) = serde_json::from_str::<Value>(&text) else {
                        continue;
                    };
                    let id = req.get("id").cloned().unwrap_or(Value::Null);
                    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
                    let result = match method {
                        "eth_chainId" => json!(format!("0x{reported:x}")),
                        // `latest_block` deserializes a full Block, so a scalar will not do.
                        "eth_getBlockByNumber" => block_at(0x2710),
                        _ => json!("0x2710"),
                    };
                    let body = json!({ "jsonrpc": "2.0", "id": id, "result": result });
                    if ws
                        .send(tokio_tungstenite::tungstenite::Message::Text(
                            body.to_string().into(),
                        ))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    served += 1;
                    if is_first && served >= close_after {
                        // Drop the socket under the live handle. alloy reconnects silently.
                        let _ = ws.close(None).await;
                        return;
                    }
                }
            });
        }
    });

    (format!("ws://{addr}"), accepts)
}

/// The property: after the transport is replaced, the next call must be verified against
/// the NEW socket. It answers a different chain, so it must be refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_socket_swapped_onto_another_chain_is_refused_on_the_next_call() {
    // First connection honest, every later one foreign.
    let (url, accepts) = spawn_ws(vec![HONEST_CHAIN, FOREIGN_CHAIN], 2).await;
    let src = WsChainSource::new(
        url,
        alloy::primitives::address!("fa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"),
        HONEST_CHAIN,
    );

    // Verified against the honest first socket.
    src.latest_block()
        .await
        .expect("the honest first connection must serve");

    // The server dropped that socket. Poll until the transport has actually been replaced
    // and the source refuses, rather than assuming a fixed reconnect delay.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut last: Option<IndexerError> = None;
    while std::time::Instant::now() < deadline {
        match src.latest_block().await {
            Err(IndexerError::ChainIdMismatch { .. }) => {
                assert!(
                    accepts.load(Ordering::SeqCst) >= 2,
                    "the refusal must follow an actual re-dial, not precede one"
                );
                return;
            }
            Err(e) => last = Some(e),
            Ok(_) => last = None,
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!(
        "a socket swapped onto chain {FOREIGN_CHAIN} was never refused; \
         accepts={}, last error={last:?}",
        accepts.load(Ordering::SeqCst)
    );
}

/// The inverse, so the refusal is not blanket: a reconnect onto the SAME chain keeps
/// serving. Without this, returning `ChainIdMismatch` unconditionally would pass the test
/// above while breaking every real reconnect.
#[tokio::test(flavor = "multi_thread")]
async fn a_reconnect_onto_the_same_chain_keeps_serving() {
    let (url, accepts) = spawn_ws(vec![HONEST_CHAIN, HONEST_CHAIN, HONEST_CHAIN], 2).await;
    let src = WsChainSource::new(
        url,
        alloy::primitives::address!("fa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"),
        HONEST_CHAIN,
    );

    src.latest_block().await.expect("first connection serves");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        if accepts.load(Ordering::SeqCst) >= 2 {
            let block = src
                .latest_block()
                .await
                .expect("a reconnect onto the same chain must keep serving");
            assert_eq!(block, 0x2710);
            return;
        }
        let _ = src.latest_block().await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!(
        "the transport never reconnected; accepts={}",
        accepts.load(Ordering::SeqCst)
    );
}
