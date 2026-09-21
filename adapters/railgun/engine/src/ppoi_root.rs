//! Holding a mirrored PPOI list row to the root the upstream node published with it.
//!
//! Upstream publishes, per event, the root of the one depth-16 tree the event landed in, read
//! after that event's own insert, and refuses a synced event whose root its own insert does not
//! reproduce. A row is therefore consistent iff appending its leaf here gives the same root.

use crate::orchestrator::hex_lower_32;
use raven_railgun_core::AdapterError;

pub(crate) const PPOI_ROOT_DIVERGENCE_TOTAL: &str = "raven_railgun_ppoi_root_divergence_total";
pub(crate) const PPOI_ROOT_UNASSERTED_TOTAL: &str = "raven_railgun_ppoi_root_unasserted_total";

/// What a producer with no upstream root writes; the WAL row has no `Option`. The upstream
/// feed cannot serve it: a row leaves that node with a stored tree root or not at all.
pub(crate) const NO_UPSTREAM_ROOT: [u8; 32] = [0; 32];

/// A `PpoiListLeafAdded` whose upstream root is not the root its own append produces.
///
/// ```
/// # use raven_railgun_engine::ppoi_root::PpoiRootDivergence;
/// let divergence = PpoiRootDivergence {
///     list_key: [0xef; 32],
///     list_index: 7,
///     local_root: [0x11; 32],
///     upstream_root: [0x22; 32],
/// };
/// let message = divergence.to_string();
/// assert!(message.contains("list_index 7"));
/// assert!(message.contains(&"11".repeat(32)) && message.contains(&"22".repeat(32)));
/// ```
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "PPOI root divergence on list {} at list_index {list_index}: appending the leaf gives \
     root {}, upstream validatedMerkleroot is {}; the row is refused and this list stays at \
     {list_index} leaves until that index arrives with a root this tree reproduces",
    hex_lower_32(.list_key),
    hex_lower_32(.local_root),
    hex_lower_32(.upstream_root)
)]
pub struct PpoiRootDivergence {
    /// List the row belongs to.
    pub list_key: [u8; 32],
    /// Index the row appends at, local to the tree that holds it.
    pub list_index: u32,
    /// Root this tree has once the row's leaf is appended.
    pub local_root: [u8; 32],
    /// Root the row carried.
    pub upstream_root: [u8; 32],
}

impl From<PpoiRootDivergence> for AdapterError {
    // `InvalidQuery` is what every other pre-WAL refusal of a row is.
    fn from(divergence: PpoiRootDivergence) -> Self {
        Self::InvalidQuery(divergence.to_string())
    }
}

pub(crate) fn ensure_metrics_described() {
    metrics::describe_counter!(
        PPOI_ROOT_DIVERGENCE_TOTAL,
        metrics::Unit::Count,
        "Count of PPOI list rows refused before the WAL write because appending the row's \
         leaf does not give the upstream validatedMerkleroot the row carries. Must stay at 0. \
         Non-zero means the served tree and the upstream list disagree at the logged \
         list_index: that list stops ingesting there, and resumes only when that index is \
         delivered again with a root this tree reproduces."
    );
    metrics::counter!(PPOI_ROOT_DIVERGENCE_TOTAL).increment(0);
    metrics::describe_counter!(
        PPOI_ROOT_UNASSERTED_TOTAL,
        metrics::Unit::Count,
        "Count of PPOI list rows applied with no root comparison because they carry the \
         all-zero root. The upstream feed never serves one, so this must stay at 0 in \
         production; non-zero means a producer is writing rows nothing verifies."
    );
    metrics::counter!(PPOI_ROOT_UNASSERTED_TOTAL).increment(0);
}
