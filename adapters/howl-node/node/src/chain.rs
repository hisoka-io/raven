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
}

/// The four reads that keep the node on the chain.
pub trait Chain: Send + Sync {
    /// Number of the newest block.
    fn head(&self) -> impl Future<Output = Result<u64, ChainError>> + Send;

    /// Hash of block `number` on the chain as it is now; `None` when there is no such block.
    fn block_hash(
        &self,
        number: u64,
    ) -> impl Future<Output = Result<Option<[u8; 32]>, ChainError>> + Send;

    /// Every pool log of the four tree events in blocks `from..=to`.
    fn logs(
        &self,
        from: u64,
        to: u64,
    ) -> impl Future<Output = Result<Vec<RawLog>, ChainError>> + Send;

    /// The pool's leaf count after block `number`, when the source can read it. A batch that
    /// ends on another count is refused, which catches a log source that dropped logs.
    fn leaf_count(
        &self,
        number: u64,
    ) -> impl Future<Output = Result<Option<u64>, ChainError>> + Send;
}

/// `bytes4(keccak256("getNextLeafIndex()"))`.
pub const SELECTOR_NEXT_LEAF_INDEX: [u8; 4] = [0x50, 0xe9, 0xb9, 0x25];

/// A chain read over Ethereum JSON-RPC.
#[derive(Clone)]
pub struct RpcChain {
    client: reqwest::Client,
    // May carry a credential: never formatted.
    url: String,
    pool: [u8; 20],
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
fn parse_log(log: &Value) -> Result<Option<RawLog>, ChainError> {
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
    Ok(Some(RawLog {
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
    }))
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
        Ok(Self { client, url, pool })
    }

    async fn call(&self, method: &'static str, params: Value) -> Result<Value, ChainError> {
        let request = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let response = self
            .client
            .post(&self.url)
            .json(&request)
            .send()
            .await
            // The error's text names the URL; only its kind leaves this function.
            .map_err(|e| ChainError::Transport(transport_kind(&e).to_owned()))?;
        let status = response.status();
        let mut body: Value = response.json().await.map_err(|_| {
            ChainError::Transport(format!("{method}: status {status}, body unreadable"))
        })?;
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

    async fn block_hash(&self, number: u64) -> Result<Option<[u8; 32]>, ChainError> {
        let result = self
            .call("eth_getBlockByNumber", json!([quantity(number), false]))
            .await?;
        if result.is_null() {
            return Ok(None);
        }
        result
            .get("hash")
            .and_then(fixed::<32>)
            .map(Some)
            .ok_or(ChainError::Malformed {
                method: "eth_getBlockByNumber",
                what: "hash",
            })
    }

    async fn logs(&self, from: u64, to: u64) -> Result<Vec<RawLog>, ChainError> {
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
        let result = self.call("eth_getLogs", filter).await?;
        let mut logs = Vec::new();
        for log in result.as_array().ok_or(ChainError::Malformed {
            method: "eth_getLogs",
            what: "not a list",
        })? {
            logs.extend(parse_log(log)?);
        }
        Ok(logs)
    }

    async fn leaf_count(&self, number: u64) -> Result<Option<u64>, ChainError> {
        let call = json!([
            { "to": hex(&self.pool), "data": hex(&SELECTOR_NEXT_LEAF_INDEX) },
            quantity(number),
        ]);
        let result = self.call("eth_call", call).await?;
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
            "logIndex": "0x3",
            "address": format!("0x{}", "11".repeat(20)),
            "topics": [format!("0x{}", "22".repeat(32))],
            "data": "0x0102",
            "removed": false,
        });
        let parsed = parse_log(&log).expect("parses").expect("kept");
        assert_eq!((parsed.block_number, parsed.log_index), (26, 3));
        assert_eq!(parsed.address, [0x11; 20]);
        assert_eq!(parsed.topics, vec![[0x22; 32]]);
        assert_eq!(parsed.data, vec![1, 2]);
        let mut removed = log;
        removed["removed"] = json!(true);
        assert!(parse_log(&removed).expect("parses").is_none());
    }
}
