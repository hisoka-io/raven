use async_trait::async_trait;
use reqwest::Client;
use url::Url;

use crate::subgraph::{
    self, CommitmentRow, GraphRequest, GraphResponse, LatestCommitmentResponse, LatestVars,
    TreeLeavesResponse, TreeLeavesVars,
};
use crate::types::{CommitmentKind, CommitmentRecord, ScanCursor, TreeStatus};

#[derive(Debug, thiserror::Error)]
pub(crate) enum SourceError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("graphql error(s): {0}")]
    Graph(String),
    #[error("graphql response missing data field")]
    MissingData,
    #[error("subgraph returned no commitments — tree is empty")]
    EmptyTree,
    #[error("invalid {field} from subgraph: {value}")]
    InvalidField { field: &'static str, value: String },
    #[error("unknown commitmentType from subgraph: {0}")]
    UnknownKind(String),
    #[error("active tree filled; restart to pick up the next")]
    TreeFilled,
}

#[async_trait]
pub(crate) trait CommitmentSource: Send + Sync {
    /// Pull every commitment with `leaf_index >= cursor.next_leaf()` from the
    /// active tree and return the records in order along with the new cursor.
    /// Internally paginates so the caller gets one consolidated batch.
    async fn poll_once(
        &self,
        cursor: ScanCursor,
    ) -> Result<(ScanCursor, Vec<CommitmentRecord>), SourceError>;

    fn active_tree(&self) -> u32;
}

pub(crate) struct SubgraphSource {
    http: Client,
    endpoint: Url,
    active_tree: u32,
}

impl SubgraphSource {
    pub(crate) async fn new(endpoint: Url, http: Client) -> Result<(Self, TreeStatus), SourceError> {
        let status = Self::fetch_tree_status(&http, &endpoint).await?;
        let source = Self { http, endpoint, active_tree: status.tree_number };
        Ok((source, status))
    }

    pub(crate) async fn fetch_tree_status(
        http: &Client,
        endpoint: &Url,
    ) -> Result<TreeStatus, SourceError> {
        let resp = post::<_, LatestCommitmentResponse>(
            http,
            endpoint,
            subgraph::LATEST_COMMITMENT_QUERY,
            LatestVars {},
        )
        .await?;

        let row = resp.commitments.into_iter().next().ok_or(SourceError::EmptyTree)?;

        let tree_number = u32::try_from(row.tree_number).map_err(|_| SourceError::InvalidField {
            field: "treeNumber",
            value: row.tree_number.to_string(),
        })?;
        let last_leaf = u32::try_from(row.tree_position).map_err(|_| SourceError::InvalidField {
            field: "treePosition",
            value: row.tree_position.to_string(),
        })?;
        let last_block = row.block_number.parse::<u64>().map_err(|_| SourceError::InvalidField {
            field: "blockNumber",
            value: row.block_number,
        })?;

        Ok(TreeStatus { tree_number, size: last_leaf.saturating_add(1), last_block })
    }
}

#[async_trait]
impl CommitmentSource for SubgraphSource {
    fn active_tree(&self) -> u32 {
        self.active_tree
    }

    async fn poll_once(
        &self,
        cursor: ScanCursor,
    ) -> Result<(ScanCursor, Vec<CommitmentRecord>), SourceError> {
        let mut all = Vec::new();
        let mut from_leaf = cursor.next_leaf();
        let mut latest_processed = cursor.last_processed_leaf;

        loop {
            let resp = post::<_, TreeLeavesResponse>(
                &self.http,
                &self.endpoint,
                subgraph::TREE_LEAVES_QUERY,
                TreeLeavesVars { tree: self.active_tree, from_leaf },
            )
            .await?;

            let page_len = resp.commitments.len();
            if page_len == 0 {
                break;
            }

            for row in resp.commitments {
                let record = parse_row(row)?;
                latest_processed = Some(record.leaf_index);
                all.push(record);
            }

            if let Some(last) = latest_processed {
                from_leaf = last.saturating_add(1);
                if u64::from(last) + 1 >= u64::from(TreeStatus::TREE_CAPACITY) {
                    return Err(SourceError::TreeFilled);
                }
            }

            if u32::try_from(page_len).unwrap_or(u32::MAX) < subgraph::PAGE_LIMIT {
                break;
            }
        }

        Ok((ScanCursor { last_processed_leaf: latest_processed }, all))
    }
}

fn parse_row(row: CommitmentRow) -> Result<CommitmentRecord, SourceError> {
    let leaf_index = u32::try_from(row.tree_position).map_err(|_| SourceError::InvalidField {
        field: "treePosition",
        value: row.tree_position.to_string(),
    })?;
    let block_number = row.block_number.parse::<u64>().map_err(|_| SourceError::InvalidField {
        field: "blockNumber",
        value: row.block_number,
    })?;
    let kind = CommitmentKind::from_subgraph_str(&row.commitment_type)
        .ok_or_else(|| SourceError::UnknownKind(row.commitment_type.clone()))?;
    // Subgraph returns hashes as decimal BigInt strings (Poseidon field
    // elements), and transactionHash as 0x-prefixed hex.
    let hash = decimal_to_bytes32(&row.hash, "hash")?;
    let tx_hash = parse_hex_bytes32(&row.transaction_hash, "transactionHash")?;
    Ok(CommitmentRecord { leaf_index, kind, hash, block_number, tx_hash })
}

fn parse_hex_bytes32(s: &str, field: &'static str) -> Result<[u8; 32], SourceError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    if stripped.len() != 64 {
        return Err(SourceError::InvalidField { field, value: s.to_owned() });
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(stripped.as_bytes()[i * 2])
            .ok_or_else(|| SourceError::InvalidField { field, value: s.to_owned() })?;
        let lo = hex_nibble(stripped.as_bytes()[i * 2 + 1])
            .ok_or_else(|| SourceError::InvalidField { field, value: s.to_owned() })?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

/// Convert a decimal string (up to 256 bits) into 32 big-endian bytes.
/// Errors if any non-digit appears or if the value exceeds 2^256 - 1.
fn decimal_to_bytes32(s: &str, field: &'static str) -> Result<[u8; 32], SourceError> {
    if s.is_empty() {
        return Err(SourceError::InvalidField { field, value: s.to_owned() });
    }
    let mut out = [0u8; 32];
    for ch in s.bytes() {
        if !ch.is_ascii_digit() {
            return Err(SourceError::InvalidField { field, value: s.to_owned() });
        }
        let digit = u16::from(ch - b'0');
        // out = out * 10 + digit, big-endian, propagating carries from LSB.
        let mut carry: u16 = digit;
        for byte in out.iter_mut().rev() {
            let v = u16::from(*byte) * 10 + carry;
            *byte = (v & 0xff) as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            return Err(SourceError::InvalidField { field, value: s.to_owned() });
        }
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

async fn post<V: serde::Serialize, R: for<'de> serde::Deserialize<'de>>(
    http: &Client,
    endpoint: &Url,
    query: &'static str,
    variables: V,
) -> Result<R, SourceError> {
    let body = GraphRequest { query, variables };
    let resp: GraphResponse<R> = http.post(endpoint.clone()).json(&body).send().await?.json().await?;

    if !resp.errors.is_empty() {
        let joined = resp.errors.into_iter().map(|e| e.message).collect::<Vec<_>>().join("; ");
        return Err(SourceError::Graph(joined));
    }
    resp.data.ok_or(SourceError::MissingData)
}
