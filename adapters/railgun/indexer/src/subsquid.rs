//! Subsquid oracle client + fixture for G5'.D root byte-identity tests.

use async_trait::async_trait;
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum SubsquidError {
    // Per-list PPOI IMT roots are not in the subsquid schema; upstream's
    // `CommitmentBatchEventNew` exposes only `{id, treeNumber, batchStartTreePosition}`.
    // Those roots live in the Railway PPOI aggregator, not subsquid.
    #[error("not indexed: {0}")]
    NotIndexed(String),
    #[error("http error: {0}")]
    Http(String),
    #[error("decode error: {0}")]
    Decode(String),
}

pub type Result<T, E = SubsquidError> = core::result::Result<T, E>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubsquidCommitmentRoot {
    pub tree_number: u32,
    pub leaf_count: u64,
    pub root: [u8; 32],
}

#[async_trait]
pub trait SubsquidRootSource: Send + Sync {
    async fn commitment_root_at_height(
        &self,
        tree_number: u32,
        block_height: u64,
    ) -> Result<SubsquidCommitmentRoot>;

    async fn ppoi_list_root_at_height(
        &self,
        list_key: [u8; 32],
        block_height: u64,
    ) -> Result<[u8; 32]>;
}

#[derive(Debug, Default)]
pub struct FixtureSubsquidSource {
    tree_roots: HashMap<(u32, u64), SubsquidCommitmentRoot>,
    list_roots: HashMap<([u8; 32], u64), [u8; 32]>,
}

impl FixtureSubsquidSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_tree_root(
        &mut self,
        tree_number: u32,
        block_height: u64,
        leaf_count: u64,
        root: [u8; 32],
    ) {
        self.tree_roots.insert(
            (tree_number, block_height),
            SubsquidCommitmentRoot {
                tree_number,
                leaf_count,
                root,
            },
        );
    }

    pub fn insert_list_root(&mut self, list_key: [u8; 32], block_height: u64, root: [u8; 32]) {
        self.list_roots.insert((list_key, block_height), root);
    }

    pub fn corrupt_tree_root(
        &mut self,
        tree_number: u32,
        block_height: u64,
        corrupted: [u8; 32],
    ) -> bool {
        if let Some(entry) = self.tree_roots.get_mut(&(tree_number, block_height)) {
            entry.root = corrupted;
            true
        } else {
            false
        }
    }
}

#[async_trait]
impl SubsquidRootSource for FixtureSubsquidSource {
    async fn commitment_root_at_height(
        &self,
        tree_number: u32,
        block_height: u64,
    ) -> Result<SubsquidCommitmentRoot> {
        self.tree_roots
            .get(&(tree_number, block_height))
            .cloned()
            .ok_or_else(|| {
                SubsquidError::NotIndexed(format!(
                    "no fixture entry for tree={tree_number} block={block_height}"
                ))
            })
    }

    async fn ppoi_list_root_at_height(
        &self,
        list_key: [u8; 32],
        block_height: u64,
    ) -> Result<[u8; 32]> {
        self.list_roots
            .get(&(list_key, block_height))
            .copied()
            .ok_or_else(|| {
                SubsquidError::NotIndexed(format!(
                    "no fixture entry for list_key at block={block_height}"
                ))
            })
    }
}

/// Queries `Transaction.merkleRoot` for the latest tx with `utxoTreeOut == tree` at or before `block`.
pub(crate) const SUBSQUID_TX_ROOT_QUERY: &str =
    "query TxMerkleRoot($tree: BigInt!, $block: BigInt!) { \
    transactions(\
        where: { utxoTreeOut_eq: $tree, blockNumber_lte: $block }, \
        orderBy: blockNumber_DESC, \
        limit: 1\
    ) { merkleRoot blockNumber utxoTreeOut utxoBatchStartPositionOut commitments } \
}";

/// `leaf_count` is reconstructed as `utxoBatchStartPositionOut + commitments.len()`; subsquid
/// has no `leafCount` scalar.
pub(crate) fn decode_subsquid_tx_root(
    body: &serde_json::Value,
    tree_number: u32,
    block_height: u64,
) -> Result<SubsquidCommitmentRoot> {
    if let Some(errors) = body.get("errors").and_then(serde_json::Value::as_array) {
        if !errors.is_empty() {
            return Err(SubsquidError::Decode(format!(
                "graphql errors: {}",
                serde_json::Value::Array(errors.clone())
            )));
        }
    }
    let tx = body.pointer("/data/transactions/0").ok_or_else(|| {
        SubsquidError::NotIndexed(format!("tree={tree_number} block={block_height}"))
    })?;
    let root_hex = tx
        .get("merkleRoot")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| SubsquidError::Decode("merkleRoot missing on transaction".into()))?;
    let root = decode_bytes32_hex(root_hex)?;
    let start_pos: u64 = tx
        .get("utxoBatchStartPositionOut")
        .and_then(parse_subsquid_bignum)
        .ok_or_else(|| SubsquidError::Decode("utxoBatchStartPositionOut missing".into()))?;
    let commitments_len: u64 = tx
        .get("commitments")
        .and_then(serde_json::Value::as_array)
        .map(|a| a.len() as u64)
        .ok_or_else(|| SubsquidError::Decode("commitments[] missing on transaction".into()))?;
    let leaf_count = start_pos.saturating_add(commitments_len);
    Ok(SubsquidCommitmentRoot {
        tree_number,
        leaf_count,
        root,
    })
}

// Subsquid encodes BigInt as JSON strings; some gateways relay them as numbers.
fn parse_subsquid_bignum(v: &serde_json::Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    v.as_str().and_then(|s| s.parse::<u64>().ok())
}

/// HTTP client against a real subsquid GraphQL endpoint.
pub struct SubsquidClient {
    endpoint: String,
    http: reqwest::Client,
}

impl std::fmt::Debug for SubsquidClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubsquidClient")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl SubsquidClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl SubsquidRootSource for SubsquidClient {
    async fn commitment_root_at_height(
        &self,
        tree_number: u32,
        block_height: u64,
    ) -> Result<SubsquidCommitmentRoot> {
        let body = serde_json::json!({
            "query": SUBSQUID_TX_ROOT_QUERY,
            "variables": {
                "tree": tree_number,
                "block": block_height,
            },
        });
        let resp = self
            .http
            .post(&self.endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|e| SubsquidError::Http(e.to_string()))?;
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SubsquidError::Decode(e.to_string()))?;
        decode_subsquid_tx_root(&body, tree_number, block_height)
    }

    async fn ppoi_list_root_at_height(
        &self,
        _list_key: [u8; 32],
        _block_height: u64,
    ) -> Result<[u8; 32]> {
        Err(SubsquidError::NotIndexed(
            "per-list PPOI roots are not indexed in the subsquid schema".into(),
        ))
    }
}

/// Decode a `0x`-prefixed or bare 64-character hex string into 32 bytes.
pub fn decode_bytes32_hex(s: &str) -> Result<[u8; 32]> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    if trimmed.len() != 64 {
        return Err(SubsquidError::Decode(format!(
            "expected 64 hex chars, got {}",
            trimmed.len()
        )));
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let pair = trimmed
            .get(i * 2..i * 2 + 2)
            .ok_or_else(|| SubsquidError::Decode(format!("hex parse out of range at byte {i}")))?;
        *slot = u8::from_str_radix(pair, 16)
            .map_err(|e| SubsquidError::Decode(format!("hex parse byte {i}: {e}")))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_bytes32_hex_round_trips_with_0x_prefix() {
        let hex = "0xefc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";
        let bytes = decode_bytes32_hex(hex).expect("valid hex");
        assert_eq!(bytes[0], 0xef);
        assert_eq!(bytes[31], 0x88);
    }

    #[test]
    fn decode_bytes32_hex_rejects_wrong_length() {
        assert!(decode_bytes32_hex("0xdeadbeef").is_err());
    }

    #[test]
    fn fixture_source_returns_not_indexed_for_missing_entry() {
        let fixture = FixtureSubsquidSource::new();
        let rt = tokio::runtime::Runtime::new().expect("rt");
        let err = rt
            .block_on(fixture.commitment_root_at_height(0, 100))
            .expect_err("missing entry");
        assert!(matches!(err, SubsquidError::NotIndexed(_)));
    }

    #[test]
    fn fixture_corrupt_tree_root_mutates_in_place() {
        let mut fixture = FixtureSubsquidSource::new();
        fixture.insert_tree_root(0, 100, 32, [1u8; 32]);
        let did_corrupt = fixture.corrupt_tree_root(0, 100, [2u8; 32]);
        assert!(did_corrupt);
        let rt = tokio::runtime::Runtime::new().expect("rt");
        let resp = rt
            .block_on(fixture.commitment_root_at_height(0, 100))
            .expect("present");
        assert_eq!(resp.root, [2u8; 32]);
    }

    #[test]
    fn subsquid_client_ppoi_list_root_returns_not_indexed() {
        let client = SubsquidClient::new("https://squid.example.io/graphql");
        let rt = tokio::runtime::Runtime::new().expect("rt");
        let err = rt
            .block_on(client.ppoi_list_root_at_height([0u8; 32], 200))
            .expect_err("NotIndexed");
        assert!(matches!(err, SubsquidError::NotIndexed(_)));
    }

    #[test]
    fn subsquid_query_targets_transaction_entity() {
        let q = SUBSQUID_TX_ROOT_QUERY;
        assert!(
            q.contains("transactions("),
            "query must select `transactions(...)`: {q}"
        );
        assert!(
            q.contains("merkleRoot"),
            "query must request merkleRoot: {q}"
        );
        assert!(
            q.contains("utxoTreeOut_eq: $tree"),
            "query must filter by utxoTreeOut_eq variable: {q}"
        );
        assert!(
            q.contains("blockNumber_lte: $block"),
            "query must filter by blockNumber_lte variable: {q}"
        );
        assert!(
            !q.contains("commitmentBatches"),
            "query must NOT target the non-existent commitmentBatches field: {q}"
        );
        assert!(
            !q.contains("leafCount"),
            "schema has no leafCount scalar; must not request it: {q}"
        );
    }

    #[test]
    fn decode_subsquid_tx_root_extracts_root_and_reconstructs_leaf_count() {
        let body = serde_json::json!({
            "data": {
                "transactions": [
                    {
                        "merkleRoot": "0xefc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88",
                        "blockNumber": "5944900",
                        "utxoTreeOut": "0",
                        "utxoBatchStartPositionOut": "30",
                        "commitments": [
                            "0xaa",
                            "0xbb",
                        ],
                    }
                ]
            }
        });
        let r = decode_subsquid_tx_root(&body, 0, 5_944_900).expect("decode ok");
        assert_eq!(r.tree_number, 0);
        assert_eq!(r.leaf_count, 32);
        assert_eq!(r.root[0], 0xef);
        assert_eq!(r.root[31], 0x88);
    }

    #[test]
    fn decode_subsquid_tx_root_accepts_numeric_bignum() {
        let body = serde_json::json!({
            "data": {
                "transactions": [
                    {
                        "merkleRoot": "0xefc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88",
                        "blockNumber": 5_944_900_u64,
                        "utxoTreeOut": 0_u64,
                        "utxoBatchStartPositionOut": 30_u64,
                        "commitments": ["0xaa", "0xbb"],
                    }
                ]
            }
        });
        let r = decode_subsquid_tx_root(&body, 0, 5_944_900).expect("decode ok");
        assert_eq!(r.leaf_count, 32);
    }

    #[test]
    fn decode_subsquid_tx_root_returns_not_indexed_for_empty_array() {
        let body = serde_json::json!({ "data": { "transactions": [] } });
        let err = decode_subsquid_tx_root(&body, 0, 100).expect_err("empty");
        assert!(matches!(err, SubsquidError::NotIndexed(_)));
    }

    #[test]
    fn decode_subsquid_tx_root_surfaces_graphql_errors_as_decode() {
        let body = serde_json::json!({
            "errors": [{"message": "Cannot query field \"transactions\""}]
        });
        let err = decode_subsquid_tx_root(&body, 0, 100).expect_err("graphql err");
        assert!(matches!(&err, SubsquidError::Decode(msg) if msg.contains("graphql errors")));
    }

    #[test]
    fn decode_subsquid_tx_root_rejects_missing_merkle_root() {
        let body = serde_json::json!({
            "data": {
                "transactions": [
                    {
                        "blockNumber": "1",
                        "utxoTreeOut": "0",
                        "utxoBatchStartPositionOut": "0",
                        "commitments": [],
                    }
                ]
            }
        });
        let err = decode_subsquid_tx_root(&body, 0, 1).expect_err("missing root");
        assert!(matches!(&err, SubsquidError::Decode(msg) if msg.contains("merkleRoot")));
    }

    #[test]
    fn decode_subsquid_tx_root_rejects_legacy_commitment_batches_shape() {
        let body = serde_json::json!({
            "data": {
                "commitmentBatches": [
                    { "treeNumber": 0, "leafCount": 32, "merkleRoot": "0xab" }
                ]
            }
        });
        let err = decode_subsquid_tx_root(&body, 0, 100).expect_err("legacy shape");
        assert!(matches!(err, SubsquidError::NotIndexed(_)));
    }
}
