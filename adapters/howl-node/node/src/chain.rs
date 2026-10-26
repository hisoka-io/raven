//! What the node reads from the chain, and a JSON-RPC source for it.

use std::fmt::Write as _;
use std::future::Future;

use howl_indexer::{
    RawLog, TOPIC_GENESIS_SEEDED, TOPIC_LEAF_INSERTED, TOPIC_NEW_NOTE, TOPIC_NEW_PRIVATE_MEMO,
};
use serde_json::{json, Value};

/// Why a chain read failed. Never carries the endpoint, which may hold a credential.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// The request did not complete.
    #[error("chain request failed: {0}")]
    Transport(String),
    /// The endpoint answered with an error.
    #[error("chain endpoint refused {method}: {message}")]
    Rpc {
        /// Method called.
        method: &'static str,
        /// The endpoint's message.
        message: String,
    },
    /// The endpoint answered with something this build cannot read.
    #[error("chain endpoint answered {method} with an unreadable result: {what}")]
    Malformed {
        /// Method called.
        method: &'static str,
        /// What was wrong.
        what: &'static str,
    },
    /// The answer outgrew what one read may hold; a smaller range may fit.
    #[error("chain endpoint answered {method} with more than {limit} bytes")]
    TooLarge {
        /// Method called.
        method: &'static str,
        /// The byte limit.
        limit: usize,
    },
    /// The pool had no code at the block read: it was not deployed yet, or the address is
    /// not a pool.
    #[error("the pool address has no code at the block read")]
    NoCode,
}

/// A block's hash and its parent's: a run of headers that link proves one chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The block's hash.
    pub hash: [u8; 32],
    /// Its parent's hash.
    pub parent: [u8; 32],
}

/// A pool log with the hash of the block the endpoint read it from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockLog {
    /// The log.
    pub log: RawLog,
    /// Hash of its block.
    pub block_hash: [u8; 32],
}

/// The four reads that keep the node on the chain.
pub trait Chain: Send + Sync {
    /// Number of the newest block.
    fn head(&self) -> impl Future<Output = Result<u64, ChainError>> + Send;

    /// Header of block `number` on the chain as it is now; `None` when there is no such block.
    fn header(
        &self,
        number: u64,
    ) -> impl Future<Output = Result<Option<Header>, ChainError>> + Send;

    /// Hash of block `number` on the chain as it is now; `None` when there is no such block.
    fn block_hash(
        &self,
        number: u64,
    ) -> impl Future<Output = Result<Option<[u8; 32]>, ChainError>> + Send {
        async move { Ok(self.header(number).await?.map(|header| header.hash)) }
    }

    /// Every pool log of the four tree events in blocks `from..=to`.
    fn logs(
        &self,
        from: u64,
        to: u64,
    ) -> impl Future<Output = Result<Vec<BlockLog>, ChainError>> + Send;

    /// The pool's leaf count after the block whose hash is `block`, when the source can read
    /// it. Read by hash, it belongs to that block whatever the chain did since. A batch that
    /// ends on another count is refused, which catches a log source that dropped logs and an
    /// absence of logs read from another fork. [`ChainError::NoCode`] when the pool had no
    /// code at that block.
    fn leaf_count(
        &self,
        block: [u8; 32],
    ) -> impl Future<Output = Result<Option<u64>, ChainError>> + Send;
}

/// Bytes one `eth_getLogs` answer may hold before the read is dropped and its range halved:
/// 3 KiB for each leaf of one batch, more than an insert's logs take, so a range the table
/// takes in one batch always fits, and a denser one costs no more than this to refuse.
pub const LOG_BYTES_LIMIT: usize = 3 * 1024 * howl_store::MAX_BATCH_ROWS;

/// `bytes4(keccak256("getNextLeafIndex()"))`.
pub const SELECTOR_NEXT_LEAF_INDEX: [u8; 4] = [0x50, 0xe9, 0xb9, 0x25];

/// A chain read over Ethereum JSON-RPC.
#[derive(Clone)]
pub struct RpcChain {
    client: reqwest::Client,
    // May carry a credential: never formatted.
    url: String,
    pool: [u8; 20],
    log_bytes_limit: usize,
}

impl std::fmt::Debug for RpcChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcChain")
            .field("pool", &hex(&self.pool))
            .finish_non_exhaustive()
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn quantity(n: u64) -> String {
    format!("0x{n:x}")
}

/// Bytes of a `0x` hex string.
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    let digits = text.strip_prefix("0x")?;
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    let digit = |c: u8| (c as char).to_digit(16).and_then(|d| u8::try_from(d).ok());
    digits
        .as_bytes()
        .chunks(2)
        .map(|pair| match pair {
            [high, low] => Some(digit(*high)? << 4 | digit(*low)?),
            _ => None,
        })
        .collect()
}

fn parse_quantity(value: &Value) -> Option<u64> {
    u64::from_str_radix(value.as_str()?.strip_prefix("0x")?, 16).ok()
}

fn fixed<const N: usize>(value: &Value) -> Option<[u8; N]> {
    unhex(value.as_str()?)?.try_into().ok()
}

/// One log of an `eth_getLogs` answer; `Ok(None)` for a log the endpoint marks removed.
fn parse_log(log: &Value) -> Result<Option<BlockLog>, ChainError> {
    let bad = |what| ChainError::Malformed {
        method: "eth_getLogs",
        what,
    };
    if log.get("removed").and_then(Value::as_bool) == Some(true) {
        return Ok(None);
    }
    let topics = log
        .get("topics")
        .and_then(Value::as_array)
        .ok_or_else(|| bad("topics"))?
        .iter()
        .map(|topic| fixed::<32>(topic).ok_or_else(|| bad("topic")))
        .collect::<Result<Vec<_>, _>>()?;
    let block_hash = log
        .get("blockHash")
        .and_then(fixed::<32>)
        .ok_or_else(|| bad("blockHash"))?;
    let log = RawLog {
        block_number: log
            .get("blockNumber")
            .and_then(parse_quantity)
            .ok_or_else(|| bad("blockNumber"))?,
        log_index: log
            .get("logIndex")
            .and_then(parse_quantity)
            .ok_or_else(|| bad("logIndex"))?,
        address: log
            .get("address")
            .and_then(fixed::<20>)
            .ok_or_else(|| bad("address"))?,
        topics,
        data: log
            .get("data")
            .and_then(Value::as_str)
            .and_then(unhex)
            .ok_or_else(|| bad("data"))?,
    };
    Ok(Some(BlockLog { log, block_hash }))
}

impl RpcChain {
    /// A source reading `pool` through the endpoint at `url`.
    ///
    /// # Errors
    /// [`ChainError::Transport`] when the HTTP client cannot be built.
    pub fn new(url: String, pool: [u8; 20]) -> Result<Self, ChainError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|_| ChainError::Transport("could not build the HTTP client".to_owned()))?;
        Ok(Self {
            client,
            url,
            pool,
            log_bytes_limit: LOG_BYTES_LIMIT,
        })
    }

    /// The same source with `limit` bytes per logs answer instead of [`LOG_BYTES_LIMIT`].
    #[must_use]
    pub const fn with_log_bytes_limit(mut self, limit: usize) -> Self {
        self.log_bytes_limit = limit;
        self
    }

    async fn call(&self, method: &'static str, params: Value) -> Result<Value, ChainError> {
        self.call_limited(method, params, usize::MAX).await
    }

    /// [`Self::call`], dropping an answer longer than `limit` bytes as it arrives.
    async fn call_limited(
        &self,
        method: &'static str,
        params: Value,
        limit: usize,
    ) -> Result<Value, ChainError> {
        let request = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let mut response = self
            .client
            .post(&self.url)
            .json(&request)
            .send()
            .await
            // The error's text names the URL; only its kind leaves this function.
            .map_err(|e| ChainError::Transport(transport_kind(&e).to_owned()))?;
        let status = response.status();
        let too_large = ChainError::TooLarge { method, limit };
        if response
            .content_length()
            .is_some_and(|length| length > u64::try_from(limit).unwrap_or(u64::MAX))
        {
            return Err(too_large);
        }
        let mut raw = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| ChainError::Transport(transport_kind(&e).to_owned()))?
        {
            if raw.len() + chunk.len() > limit {
                return Err(too_large);
            }
            raw.extend_from_slice(&chunk);
        }
        let mut body: Value = serde_json::from_slice(&raw).map_err(|_| {
            ChainError::Transport(format!("{method}: status {status}, body unreadable"))
        })?;
        drop(raw);
        if let Some(error) = body.get("error") {
            return Err(ChainError::Rpc {
                method,
                message: error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("no message")
                    .chars()
                    .take(200)
                    .collect(),
            });
        }
        body.get_mut("result")
            .map(Value::take)
            .ok_or(ChainError::Malformed {
                method,
                what: "no result",
            })
    }
}

fn transport_kind(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timed out"
    } else if error.is_connect() {
        "could not connect"
    } else if error.is_body() || error.is_decode() {
        "body unreadable"
    } else {
        "request failed"
    }
}

impl Chain for RpcChain {
    async fn head(&self) -> Result<u64, ChainError> {
        let result = self.call("eth_blockNumber", json!([])).await?;
        parse_quantity(&result).ok_or(ChainError::Malformed {
            method: "eth_blockNumber",
            what: "not a quantity",
        })
    }

    async fn header(&self, number: u64) -> Result<Option<Header>, ChainError> {
        let result = self
            .call("eth_getBlockByNumber", json!([quantity(number), false]))
            .await?;
        if result.is_null() {
            return Ok(None);
        }
        let field = |name, what| {
            result
                .get(name)
                .and_then(fixed::<32>)
                .ok_or(ChainError::Malformed {
                    method: "eth_getBlockByNumber",
                    what,
                })
        };
        Ok(Some(Header {
            hash: field("hash", "hash")?,
            parent: field("parentHash", "parentHash")?,
        }))
    }

    async fn logs(&self, from: u64, to: u64) -> Result<Vec<BlockLog>, ChainError> {
        let topics = [
            TOPIC_LEAF_INSERTED,
            TOPIC_GENESIS_SEEDED,
            TOPIC_NEW_NOTE,
            TOPIC_NEW_PRIVATE_MEMO,
        ]
        .map(|topic| hex(&topic));
        let filter = json!([{
            "address": hex(&self.pool),
            "fromBlock": quantity(from),
            "toBlock": quantity(to),
            "topics": [topics],
        }]);
        let result = self
            .call_limited("eth_getLogs", filter, self.log_bytes_limit)
            .await?;
        let mut logs = Vec::new();
        for log in result.as_array().ok_or(ChainError::Malformed {
            method: "eth_getLogs",
            what: "not a list",
        })? {
            logs.extend(parse_log(log)?);
        }
        Ok(logs)
    }

    async fn leaf_count(&self, block: [u8; 32]) -> Result<Option<u64>, ChainError> {
        // EIP-1898: the state of exactly that block.
        let call = json!([
            { "to": hex(&self.pool), "data": hex(&SELECTOR_NEXT_LEAF_INDEX) },
            { "blockHash": hex(&block) },
        ]);
        let result = self.call("eth_call", call).await?;
        // A call to an address without code succeeds with no bytes.
        if result.as_str() == Some("0x") {
            return Err(ChainError::NoCode);
        }
        let bytes = result
            .as_str()
            .and_then(unhex)
            .filter(|bytes| bytes.len() == 32)
            .ok_or(ChainError::Malformed {
                method: "eth_call",
                what: "not one word",
            })?;
        let (high, low) = bytes.split_at(24);
        if high.iter().any(|byte| *byte != 0) {
            return Err(ChainError::Malformed {
                method: "eth_call",
                what: "leaf count beyond 64 bits",
            });
        }
        let mut word = [0u8; 8];
        word.copy_from_slice(low);
        Ok(Some(u64::from_be_bytes(word)))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::{hex, parse_log, unhex, SELECTOR_NEXT_LEAF_INDEX};
    use serde_json::json;

    #[test]
    fn the_leaf_count_selector_is_the_keccak_of_its_signature() {
        use sha3::{Digest, Keccak256};
        let hash = Keccak256::digest(b"getNextLeafIndex()");
        assert_eq!(hash[..4], SELECTOR_NEXT_LEAF_INDEX);
    }

    #[test]
    fn hex_round_trips_and_refuses_odd_or_bare_digits() {
        assert_eq!(hex(&[0x00, 0xab, 0x10]), "0x00ab10");
        assert_eq!(unhex("0x00ab10"), Some(vec![0x00, 0xab, 0x10]));
        assert_eq!(unhex("0xabc"), None);
        assert_eq!(unhex("abcd"), None);
        assert_eq!(unhex("0xzz"), None);
    }

    #[test]
    fn a_log_parses_and_a_removed_log_is_dropped() {
        let log = json!({
            "blockNumber": "0x1a",
            "blockHash": format!("0x{}", "33".repeat(32)),
            "logIndex": "0x3",
            "address": format!("0x{}", "11".repeat(20)),
            "topics": [format!("0x{}", "22".repeat(32))],
            "data": "0x0102",
            "removed": false,
        });
        let parsed = parse_log(&log).expect("parses").expect("kept");
        assert_eq!(parsed.block_hash, [0x33; 32]);
        let parsed = parsed.log;
        assert_eq!((parsed.block_number, parsed.log_index), (26, 3));
        assert_eq!(parsed.address, [0x11; 20]);
        assert_eq!(parsed.topics, vec![[0x22; 32]]);
        assert_eq!(parsed.data, vec![1, 2]);
        let mut removed = log.clone();
        removed["removed"] = json!(true);
        assert!(parse_log(&removed).expect("parses").is_none());
        // A log that cannot be placed on a block is refused, not applied.
        let mut unplaced = log;
        unplaced["blockHash"] = json!(null);
        assert!(parse_log(&unplaced).is_err());
    }
}
