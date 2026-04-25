use serde::{Deserialize, Serialize};

pub(crate) const PAGE_LIMIT: u32 = 10_000;

pub(crate) const LATEST_COMMITMENT_QUERY: &str = r"
query LatestCommitment {
  commitments(orderBy: [blockNumber_DESC, treePosition_DESC], limit: 1) {
    treeNumber
    treePosition
    blockNumber
  }
}
";

pub(crate) const TREE_LEAVES_QUERY: &str = r"
query TreeLeaves($tree: Int!, $fromLeaf: Int!) {
  commitments(
    orderBy: [treePosition_ASC]
    where: { treeNumber_eq: $tree, treePosition_gte: $fromLeaf }
    limit: 10000
  ) {
    treePosition
    blockNumber
    transactionHash
    commitmentType
    hash
  }
}
";

#[derive(Debug, Serialize)]
pub(crate) struct GraphRequest<'a, V: Serialize> {
    pub query: &'a str,
    pub variables: V,
}

#[derive(Debug, Serialize)]
pub(crate) struct LatestVars {}

#[derive(Debug, Serialize)]
pub(crate) struct TreeLeavesVars {
    pub tree: u32,
    #[serde(rename = "fromLeaf")]
    pub from_leaf: u32,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GraphResponse<T> {
    pub data: Option<T>,
    #[serde(default)]
    pub errors: Vec<GraphError>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GraphError {
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LatestCommitmentResponse {
    pub commitments: Vec<LatestCommitmentRow>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LatestCommitmentRow {
    #[serde(rename = "treeNumber")]
    pub tree_number: i64,
    #[serde(rename = "treePosition")]
    pub tree_position: i64,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TreeLeavesResponse {
    pub commitments: Vec<CommitmentRow>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CommitmentRow {
    #[serde(rename = "treePosition")]
    pub tree_position: i64,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "commitmentType")]
    pub commitment_type: String,
    pub hash: String,
}
