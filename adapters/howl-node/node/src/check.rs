//! Whether an endpoint can serve a node: the reads the follower makes, made once, read only.
//!
//! The follower needs the chain id it was given, a pool count read by block hash (EIP-1898) at
//! the head and at the walk depth below it, and the pool's logs from the deployment block under
//! the four-topic filter. An endpoint that fails any of these fails the follower's steps later,
//! so the check names which one before a node is started on it.

use howl_indexer::{
    TOPIC_GENESIS_SEEDED, TOPIC_LEAF_INSERTED, TOPIC_NEW_NOTE, TOPIC_NEW_PRIVATE_MEMO,
};

use crate::chain::{Chain, ChainError, RpcChain};

/// Blocks from the deployment block the logs read asks for at most; halved while refused.
pub const LOGS_WINDOW: u64 = 10_000;

const TOPICS: [([u8; 32], &str); 4] = [
    (TOPIC_LEAF_INSERTED, "LeafInserted"),
    (TOPIC_GENESIS_SEEDED, "GenesisSeeded"),
    (TOPIC_NEW_NOTE, "NewNote"),
    (TOPIC_NEW_PRIVATE_MEMO, "NewPrivateMemo"),
];

/// What the node would be started with.
#[derive(Debug, Clone, Copy)]
pub struct Expect {
    /// The chain id the node is given.
    pub chain_id: u64,
    /// The pool's address.
    pub pool: [u8; 20],
    /// The block the pool was deployed in.
    pub deployment_block: u64,
    /// The walk depth the node runs with.
    pub walk_blocks: u64,
}

/// One check's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The check.
    pub name: &'static str,
    /// Whether the endpoint passed it.
    pub ok: bool,
    /// What was read, or why it failed.
    pub detail: String,
}

fn finding(name: &'static str, ok: bool, detail: impl Into<String>) -> Finding {
    Finding {
        name,
        ok,
        detail: detail.into(),
    }
}

/// The pool's count at block `number`, read by that block's hash.
async fn count_by_hash(chain: &RpcChain, number: u64) -> Result<u64, String> {
    let header = chain
        .header(number)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("block {number} unknown to the endpoint"))?;
    match chain.leaf_count(header.hash).await {
        Ok(Some(count)) => Ok(count),
        Ok(None) => Err("no count answered".to_owned()),
        Err(ChainError::NoCode) => Err(format!("the pool has no code at block {number}")),
        Err(e) => Err(e.to_string()),
    }
}

/// Every check, in order; the endpoint is usable when each one is ok.
pub async fn check(chain: &RpcChain, expect: &Expect) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.push(match chain.chain_id().await {
        Ok(id) if id == expect.chain_id => finding("chain_id", true, id.to_string()),
        Ok(id) => finding(
            "chain_id",
            false,
            format!("{id}, the node is given {}", expect.chain_id),
        ),
        Err(e) => finding("chain_id", false, e.to_string()),
    });
    let head = match chain.head().await {
        Ok(head) => head,
        Err(e) => {
            findings.push(finding("head", false, e.to_string()));
            return findings;
        }
    };
    findings.push(finding("head", true, head.to_string()));
    findings.push(match count_by_hash(chain, head).await {
        Ok(count) => finding("call_by_hash", true, format!("leaves={count} at {head}")),
        Err(e) => finding("call_by_hash", false, e),
    });
    let deep = head.saturating_sub(expect.walk_blocks);
    findings.push(match count_by_hash(chain, deep).await {
        Ok(count) => finding(
            "state_at_walk_depth",
            true,
            format!("leaves={count} at {deep}, {} below the head", head - deep),
        ),
        Err(e) => finding("state_at_walk_depth", false, e),
    });
    findings.extend(logs_from_deployment(chain, expect, head).await);
    findings
}

/// The logs read at the deployment block, and whether the answer kept to the filter.
async fn logs_from_deployment(chain: &RpcChain, expect: &Expect, head: u64) -> Vec<Finding> {
    let from = expect.deployment_block;
    if from > head {
        return vec![finding(
            "logs_from_deployment",
            false,
            format!("the deployment block {from} is past the head {head}"),
        )];
    }
    let mut to = head.min(from.saturating_add(LOGS_WINDOW - 1));
    let logs = loop {
        match chain.logs(from, to).await {
            Ok(logs) => break logs,
            Err(e) if to == from => {
                return vec![finding("logs_from_deployment", false, e.to_string())]
            }
            Err(_) => to = from + (to - from) / 2,
        }
    };
    let foreign = logs.iter().any(|logged| {
        logged.log.address != expect.pool
            || !logged
                .log
                .topics
                .first()
                .is_some_and(|topic| TOPICS.iter().any(|(known, _)| known == topic))
    });
    let present: Vec<&str> = TOPICS
        .iter()
        .filter(|(topic, _)| {
            logs.iter()
                .any(|logged| logged.log.topics.first() == Some(topic))
        })
        .map(|(_, name)| *name)
        .collect();
    vec![
        finding(
            "logs_from_deployment",
            true,
            format!("blocks {from}..={to}: {} logs", logs.len()),
        ),
        if foreign {
            finding(
                "event_filter",
                false,
                "the answer holds logs of another address or topic",
            )
        } else {
            finding(
                "event_filter",
                true,
                if present.is_empty() {
                    "no pool event in the window".to_owned()
                } else {
                    format!("present: {}", present.join(", "))
                },
            )
        },
    ]
}
