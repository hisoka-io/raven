use async_trait::async_trait;
use reqwest::Client;
use url::Url;

use crate::subgraph::{
    self, CommitmentRow, GraphRequest, GraphResponse, LatestCommitmentResponse, LatestVars,
    TreeLeavesResponse, TreeLeavesVars,
};
use crate::types::{CommitmentRecord, ScanCursor, TreeStatus};

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

        Ok(TreeStatus { tree_number, size: last_leaf.saturating_add(1) })
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
    // Subgraph returns `hash` as a decimal BigInt string (Poseidon field element).
    let hash = decimal_to_bytes32(&row.hash, "hash")?;
    Ok(CommitmentRecord { leaf_index, hash })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use raven_core::{MemoryStore, StorageBackend};
    use raven_indexer::Indexer;

    /// Stub source that returns one canned batch per `poll_once`, then empty.
    struct StubSource {
        active_tree: u32,
        batches: Mutex<std::vec::IntoIter<Vec<CommitmentRecord>>>,
    }

    impl StubSource {
        fn new(active_tree: u32, batches: Vec<Vec<CommitmentRecord>>) -> Self {
            Self {
                active_tree,
                batches: Mutex::new(batches.into_iter()),
            }
        }
    }

    #[async_trait]
    impl CommitmentSource for StubSource {
        fn active_tree(&self) -> u32 {
            self.active_tree
        }

        async fn poll_once(
            &self,
            cursor: ScanCursor,
        ) -> Result<(ScanCursor, Vec<CommitmentRecord>), SourceError> {
            let next_batch = {
                let mut iter = self.batches.lock().expect("stub batches lock");
                iter.next().unwrap_or_default()
            };

            let last = next_batch.last().map(|r| r.leaf_index).or(cursor.last_processed_leaf);
            Ok((ScanCursor { last_processed_leaf: last }, next_batch))
        }
    }

    fn rec(leaf: u32, byte: u8) -> CommitmentRecord {
        CommitmentRecord { leaf_index: leaf, hash: [byte; 32] }
    }

    #[tokio::test]
    async fn poller_writes_into_indexer_and_snapshot_reflects_all_leaves() {
        let batch_a = vec![rec(0, 0xAA), rec(1, 0xBB), rec(2, 0xCC)];
        let batch_b = vec![rec(3, 0xDD), rec(4, 0xEE)];
        let total = batch_a.len() + batch_b.len();

        let source = StubSource::new(0, vec![batch_a.clone(), batch_b.clone()]);
        let indexer: Indexer<MemoryStore> = Indexer::new(MemoryStore::new());

        let mut cursor = ScanCursor::empty();
        for _ in 0..2 {
            let (next, batch) = source.poll_once(cursor).await.expect("poll_once");
            indexer
                .put_many(batch.iter().map(|r| (r.key(), r.to_bytes())))
                .expect("put_many");
            cursor = next;
        }

        assert_eq!(indexer.len().expect("len"), total as u64);
        assert_eq!(cursor.last_processed_leaf, Some(4));

        for rec in batch_a.iter().chain(batch_b.iter()) {
            let stored = indexer.get(rec.key()).expect("get").expect("present");
            assert_eq!(&stored[..], &rec.hash[..]);
        }

        // Snapshot read confirms point-in-time view at the latest generation.
        let snap = indexer.backend().snapshot().expect("snapshot");
        assert_eq!(snap.len(), total as u64);
    }
}
