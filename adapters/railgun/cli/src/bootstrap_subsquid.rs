//! Bootstrap an instance's on-disk state from a Subsquid checkpoint.
//!
//! Per-tree algorithm:
//!
//! 1. Load the per-endpoint heterogeneous rpc-pool config.
//! 2. Pin a `checkpoint_block = chain_head - checkpoint_depth` from
//!    the live RPC.
//! 3. Probe at least one pooled RPC endpoint for archival state at
//!    `checkpoint_block`: a dry `eth_call merkleRoot()` MUST succeed
//!    on at least one endpoint, otherwise bail with
//!    [`BootstrapError::NoArchivalRpc`] before any per-tree work.
//!    Subsquid does not expose a per-tree post-state anchor, so the
//!    chain ABI is the canonical verifier and archival state is
//!    mandatory.
//! 4. Page through Subsquid's `commitments(orderBy: treePosition_ASC,
//!    treePosition_gt: $cursor, first: 1000)` until empty (single-key
//!    cursor on `treePosition`). Decode each `Commitment.hash` decimal-
//!    string `BigInt` into a 32-byte big-endian field element via the
//!    `bigint_to_fr_bytes` decoder (validated `< BN254_FR_MODULUS`).
//! 5. Replay leaves into a local `raven_railgun_engine::imt::Imt` to
//!    produce `local_root`.
//! 6. Branch on `chain.active_tree_number_at(checkpoint_block) ==
//!    tree`:
//!    - Live tree: fetch `chain.merkle_root_at(checkpoint_block)`
//!      and assert byte-identity vs `local_root` (oracle kind
//!      [`OracleKind::ChainLiveTree`]).
//!    - Static tree: call `chain.root_history_at(tree, local_root,
//!      checkpoint_block)` and assert it returns `true` (oracle kind
//!      [`OracleKind::ChainStaticTree`], membership semantics: "this
//!      root was recorded by the chain for this tree at this block").
//!
//!    The chain oracle is mandatory in V1; there is no graceful
//!    degrade path. Subsquid is leaves-only.
//! 7. Drop the initial snapshot via `bootstrap_inspire_instance` with
//!    a deterministic placeholder DB matching the production cell
//!    shape; the real per-leaf encoding lands once the consumer task
//!    starts streaming chain events from `start_block = checkpoint`.
//! 8. PPOI list bootstrap pulls upstream `/poi-events/{ct}/{cid}` from
//!    Railway and asserts each `validatedMerkleroot` byte-equals our
//!    locally-computed per-list IMT root (upstream-aggregator oracle).
//!
//! The module surfaces `BootstrapError` + a `bootstrap_one_tree`
//! coroutine that the CLI subcommand orchestrates per tree number.
//! Test doubles (`SubsquidLeavesSource` + `ChainOracle`) keep the
//! algorithm exercise-able without live network I/O.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::Deserialize;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::{InstanceId, RailgunEvent};
use raven_railgun_engine::imt::{Imt, TREE_MAX_ITEMS};
use raven_railgun_engine::inspire::{setup_state, LogicalLeafStore};
use raven_railgun_engine::persistence::{bootstrap_inspire_instance, SnapshotPolicy};
use raven_railgun_engine::pir_table::{
    EncoderKind, PirTableEncoder, LEAVES_PER_TREE, NODE_HASH_BYTES, PATH_RECORD_BYTES,
    PER_NODE_TOTAL_NODES,
};
use raven_railgun_engine::InstanceRole;
use raven_railgun_persistence::{StoreLayout, WalEntryPayload};

/// BN254 Fr modulus as 32 big-endian bytes:
/// `21888242871839275222246405745257275088548364400416034343698204186575808495617`.
/// Locked literal taken from `raven-railgun-poseidon`'s upstream
/// reference (BN254 SNARK_PRIME).
const BN254_FR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Maximum leaves per Subsquid commitments page.
const SUBSQUID_PAGE: usize = 1000;

/// Hard cap on the bootstrap loop wall-clock.
const DEFAULT_MAX_BOOTSTRAP_WALL_MINS: u64 = 30;

/// Source identifier for an oracle byte-identity disagreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OracleKind {
    /// Live-tree path: `chain.merkle_root_at()` disagreed with the
    /// locally rebuilt IMT root (byte-identity oracle).
    ChainLiveTree,
    /// Static-tree path: `chain.root_history_at(tree, local_root)`
    /// returned `false` (membership oracle: the chain has not
    /// recorded this root for this tree).
    ChainStaticTree,
    /// PPOI: Railway `validatedMerkleroot` disagreed with our local
    /// per-list IMT root.
    PpoiUpstreamList,
}

/// Bootstrap-time errors. All variants are actionable: each carries
/// the operator-facing context needed to decide whether to retry,
/// re-pin the checkpoint, or escalate.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("invalid pool config: {0}")]
    PoolConfig(String),
    #[error("Subsquid endpoint unreachable: {0}")]
    SubsquidUnreachable(String),
    #[error("Subsquid response decode: {0}")]
    SubsquidDecode(String),
    #[error("Subsquid Commitment.hash bigint decode at index {index}: {reason}")]
    BigintDecode { index: usize, reason: String },
    #[error("Subsquid pagination produced {observed} leaves; expected {expected}")]
    PartialLeafCount { observed: usize, expected: usize },
    #[error("RPC unreachable: {0}")]
    RpcUnreachable(String),
    #[error(
        "no archival RPC available for verification at checkpoint block {checkpoint_block}: {actionable}"
    )]
    NoArchivalRpc {
        checkpoint_block: u64,
        actionable: String,
    },
    #[error(
        "oracle byte-identity mismatch ({kind:?}) at tree={tree_number}: expected {expected_hex} observed {observed_hex} (first match at leaf index {first_match_index})"
    )]
    OracleByteIdentityMismatch {
        kind: OracleKind,
        tree_number: u32,
        expected_hex: String,
        observed_hex: String,
        /// Index in the leaf sequence at which the rebuilt IMT first
        /// matched the target root (or `leaves.len()` if no match).
        /// Renamed from `divergence_leaf_index` to reflect the
        /// post-insert search semantics.
        first_match_index: usize,
    },
    #[error("data_dir lock held: {path}")]
    LockHeld { path: String },
    #[error("data_dir IO {path}: {error}")]
    DataDirIo { path: String, error: String },
    #[error("engine bootstrap: {0}")]
    Engine(String),
    #[error("snapshot commit: {0}")]
    Snapshot(String),
    #[error("bootstrap exceeded {limit_mins} minute wall-clock budget")]
    BudgetExhausted { limit_mins: u64 },
    #[error("PPOI Railway endpoint unreachable: {0}")]
    PpoiUnreachable(String),
    #[error("PPOI response decode: {0}")]
    PpoiDecode(String),
    #[error("PPOI list_key {list_hex} bootstrap: {reason}")]
    PpoiList { list_hex: String, reason: String },
    /// Boundary repair could not recover a missing leaf from the chain.
    /// Surfaces the residual gap so the operator can decide whether
    /// the divergence is an upstream Subsquid bug, a deeper local
    /// bug, or a chain RPC pruning the boundary range.
    #[error(
        "boundary repair failed at tree={tree_number} missing_index={missing_index}: {reason}"
    )]
    BoundaryRepairFailed {
        tree_number: u32,
        missing_index: u32,
        reason: String,
    },
}

/// Decode a Subsquid `BigInt` decimal-string (`Commitment.hash`) into
/// a 32-byte big-endian buffer. Rejects values `>= BN254_FR_MODULUS`
/// (off-curve leaves) and any non-decimal characters. Strips a single
/// `0x`-prefix only when present and the rest is hex (safety net for
/// gateways that relay BigInt as hex; documented as a non-canonical
/// shape upstream).
pub fn decode_bigint_to_be_bytes32(s: &str) -> Result<[u8; 32], String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("empty bigint".to_owned());
    }
    let big = if let Some(hex) = trimmed.strip_prefix("0x") {
        if hex.len() > 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("hex shape rejected: {trimmed}"));
        }
        let padded = format!("{hex:0>64}");
        let mut out = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            let pair = padded
                .get(i * 2..i * 2 + 2)
                .ok_or_else(|| format!("hex range: {trimmed}"))?;
            *slot = u8::from_str_radix(pair, 16).map_err(|e| format!("hex parse: {e}"))?;
        }
        out
    } else {
        if !trimmed.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("non-decimal: {trimmed}"));
        }
        decimal_string_to_be_bytes32(trimmed)?
    };
    if !is_below_modulus(&big, &BN254_FR_MODULUS_BE) {
        return Err(format!(">= BN254_FR_MODULUS: 0x{}", to_hex(&big)));
    }
    Ok(big)
}

/// Long-form decimal -> 32-byte BE conversion. Walks the digit string
/// via a base-10 multiply-add over a 32-byte big-endian accumulator;
/// returns an error if the result would exceed 32 bytes.
fn decimal_string_to_be_bytes32(digits: &str) -> Result<[u8; 32], String> {
    let mut acc = [0u8; 32];
    for ch in digits.chars() {
        let d = ch.to_digit(10).ok_or_else(|| format!("digit: {ch}"))?;
        let mut carry: u32 = d;
        for byte in acc.iter_mut().rev() {
            let v = u32::from(*byte) * 10 + carry;
            *byte = (v & 0xff) as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            return Err("decimal overflows 32 bytes".to_owned());
        }
    }
    Ok(acc)
}

fn is_below_modulus(value: &[u8; 32], modulus: &[u8; 32]) -> bool {
    for (v, m) in value.iter().zip(modulus.iter()) {
        match v.cmp(m) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    false
}

fn to_hex(b: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for x in b {
        let _ = write!(out, "{x:02x}");
    }
    out
}

/// One Subsquid commitment row (subset relevant to bootstrap).
#[derive(Debug, Clone)]
pub struct CommitmentRow {
    pub tree_position: u64,
    pub leaf: [u8; 32],
    /// Block number the upstream indexer recorded for this leaf.
    /// Used by boundary-repair to seed chain `eth_getLogs` ranges
    /// without an out-of-band hint.
    pub block_number: u64,
}

/// Trait abstracting the paginated commitments source so tests can
/// swap in a deterministic stub. Subsquid is leaves-only; per-tree
/// post-state anchors are fetched from the chain ABI, not Subsquid.
#[async_trait]
pub trait SubsquidLeavesSource: Send + Sync {
    /// Fetch up to [`SUBSQUID_PAGE`] commitments for `tree_number` at
    /// `block_height_lte = checkpoint_block`, ordered ascending by
    /// `treePosition`, with `treePosition_gt = cursor`. An empty page
    /// signals end-of-stream.
    async fn fetch_commitments_page(
        &self,
        tree_number: u32,
        checkpoint_block: u64,
        cursor: Option<u64>,
        page_size: usize,
    ) -> Result<Vec<CommitmentRow>, BootstrapError>;
}

/// Chain-side oracle surface. Surfaces the three pinned reads the
/// bootstrap needs:
///
/// - `chain_head()` to pin a `checkpoint_block = head - depth`.
/// - `active_tree_number_at(block)` to branch live vs static.
/// - `merkle_root_at(block)` for the live-tree byte-identity oracle.
/// - `root_history_at(tree, root, block)` for the static-tree
///   membership oracle.
/// - `archival_probe(block)` to fail-fast if the operator's RPC pool
///   has no archival endpoint covering the checkpoint.
#[async_trait]
pub trait ChainOracle: Send + Sync {
    async fn chain_head(&self) -> Result<u64, BootstrapError>;
    async fn active_tree_number_at(&self, block: u64) -> Result<u32, BootstrapError>;
    async fn merkle_root_at(&self, block: u64) -> Result<[u8; 32], BootstrapError>;
    async fn root_history_at(
        &self,
        tree_number: u32,
        merkle_root: [u8; 32],
        block: u64,
    ) -> Result<bool, BootstrapError>;
    /// Fetch decoded Shield/Transact commitment events for the inclusive
    /// block range `[from_block, to_block]` and project them down to
    /// `(tree_number, leaf_index, commitment_hash)` triples. Used by the
    /// Subsquid boundary-repair path to chain-backfill leaves that the
    /// upstream indexer dropped or duplicated at a tree-rollover block.
    /// The caller is expected to pass a small range (the repair path
    /// uses ~21 blocks) so this stays within typical RPC `eth_getLogs`
    /// span limits.
    async fn commitment_events_in_range(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<(u32, u32, [u8; 32])>, BootstrapError>;
    /// Best-effort dry probe: succeed iff at least one endpoint in the
    /// underlying pool can serve historical state at `block`. The
    /// default implementation issues `merkle_root_at(block)` and maps
    /// any error to a typed `NoArchivalRpc`. Implementations may
    /// override to walk the pool explicitly.
    async fn archival_probe(&self, block: u64) -> Result<(), BootstrapError> {
        match self.merkle_root_at(block).await {
            Ok(_) => Ok(()),
            Err(BootstrapError::RpcUnreachable(msg)) if looks_like_pruning_error(&msg) => {
                Err(BootstrapError::NoArchivalRpc {
                    checkpoint_block: block,
                    actionable: format!(
                        "every RPC endpoint in the pool refused historical state at \
                         block {block} (likely public/pruning nodes); add an \
                         Alchemy/Infura/Quicknode archival endpoint to your \
                         rpc-pool.toml and rerun. underlying: {msg}"
                    ),
                })
            }
            Err(other) => Err(other),
        }
    }
}

/// Heuristic: classify an RPC error string as the upstream
/// "historical state not available" / "pruning" family. Mainnet RPCs
/// surface this as JSON-RPC code -32000 with various message strings;
/// matching on substrings is the operator-friendly compromise versus
/// parsing the raw JSON-RPC error body.
fn looks_like_pruning_error(msg: &str) -> bool {
    let lc = msg.to_lowercase();
    lc.contains("-32000")
        || lc.contains("historical state")
        || lc.contains("pruning")
        || lc.contains("not available")
        || lc.contains("missing trie node")
        || lc.contains("only the most recent")
        || lc.contains("archive node")
}

/// One bootstrap-tree invocation summary surfaced for benching.
#[derive(Debug, Clone)]
pub struct BootstrapTreeReport {
    pub tree_number: u32,
    pub checkpoint_block: u64,
    pub leaves: usize,
    pub local_root: [u8; 32],
    /// `Some(root)` when the live-tree byte-identity oracle was used
    /// (i.e. `chain.active_tree_number_at(checkpoint) == tree`). For
    /// static trees this is `None` and verification used the
    /// membership oracle instead.
    pub chain_live_root: Option<[u8; 32]>,
    /// `true` iff the static-tree membership oracle returned `true`
    /// (i.e. the chain's `rootHistory(tree, local_root)` recorded
    /// this root). `None` for live trees.
    pub chain_static_membership: Option<bool>,
    pub wall_clock_secs: f64,
    pub subsquid_pages: u32,
    pub data_dir: PathBuf,
}

/// Configuration consumed by `bootstrap_one_tree`.
#[derive(Debug, Clone)]
pub struct BootstrapTreeConfig {
    pub tree_number: u32,
    pub checkpoint_depth: u64,
    pub data_dir: PathBuf,
    pub instance_id: String,
    pub scheme_tag: String,
    pub entries: usize,
    pub entry_bytes: usize,
    pub max_wall_mins: u64,
    /// Filled-tree row-count threshold above which the boundary
    /// repair path will gap-walk + chain-backfill missing leaves.
    /// Production defaults to `TREE_MAX_ITEMS - 16` (i.e. only act
    /// on trees that are essentially full); tests lower this so
    /// the repair path stays exercise-able with synthetic 4/8/N-leaf
    /// fixtures instead of forcing every test to allocate 65,536
    /// rows + 65,536 IMT inserts.
    pub repair_trigger_threshold: usize,
    /// Expected post-repair count of leaves for a filled tree. The
    /// gap-walk visits `0..expected_filled_count`; production locks
    /// this at `TREE_MAX_ITEMS = 65,536` per Railgun's
    /// `Commitments.sol::TREE_DEPTH = 16`. Tests scale this down so
    /// the synthetic fixtures stay small.
    pub expected_filled_count: usize,
    /// Encoder kind to stamp into the manifest for this tree. Defaults
    /// to [`EncoderKind::PerLeafBc`] for backward compatibility; the
    /// CLI orchestrator overrides this to match the production lock
    /// (per-tree `EncoderKind::PerNode { tree_number }`).
    pub encoder_kind: EncoderKind,
}

impl Default for BootstrapTreeConfig {
    fn default() -> Self {
        Self {
            tree_number: 0,
            checkpoint_depth: 64,
            data_dir: PathBuf::new(),
            instance_id: "commit-tree-bootstrap".to_owned(),
            scheme_tag: "raven-inspire-twopacking-inspiring-wp3-cache-session".to_owned(),
            entries: 65_536,
            entry_bytes: 512,
            max_wall_mins: DEFAULT_MAX_BOOTSTRAP_WALL_MINS,
            repair_trigger_threshold: BOUNDARY_REPAIR_TRIGGER_THRESHOLD,
            expected_filled_count: TREE_MAX_ITEMS,
            encoder_kind: EncoderKind::PerLeafBc,
        }
    }
}

/// Cross-tree carry for Subsquid stowaway rows whose `treePosition`
/// landed `>= TREE_MAX_ITEMS` for the tree that was being bootstrapped.
/// Per `Commitments.sol` no batch spans tree boundaries, so an
/// impossible-position row is the SAME physical commitment that the
/// chain emitted at `treeNumber = N+1, startPosition = 0`. Boundary
/// repair re-tags `tree_position -= TREE_MAX_ITEMS` and stows it under
/// the target tree number; the next tree's bootstrap drains the carry
/// before chain-backfill so the leaf data is preserved end-to-end.
pub type StowawayCarry = HashMap<u32, Vec<CommitmentRow>>;

/// Sliding window (in blocks) for chain-backfill `eth_getLogs` queries
/// when boundary repair has to recover a missing leaf. Selected to be
/// large enough to cover the rollover transaction and any neighbouring
/// commitment events but small enough to stay within typical RPC
/// `eth_getLogs` span caps.
const BOUNDARY_REPAIR_WINDOW_BLOCKS: u64 = 10;

/// Below this filled-tree row count (post position-filter) we skip the
/// chain gap-walk: a tree this far from `TREE_MAX_ITEMS` is either an
/// artificial test fixture or a degenerate Subsquid response, and the
/// existing static-membership oracle is the right place to hard-stop.
/// At or above this threshold the tree is clearly "almost full" and we
/// chain-backfill the residual gap.
const BOUNDARY_REPAIR_TRIGGER_THRESHOLD: usize = TREE_MAX_ITEMS - 16;

/// Extract every row in `rows` whose `tree_position >= TREE_MAX_ITEMS`
/// and re-tag it as the same physical commitment in tree
/// `tree_number + 1` at `tree_position - TREE_MAX_ITEMS`. Returns the
/// count of rows moved into the carry. Per `Commitments.sol` no batch
/// spans tree boundaries, so an impossible-position row in tree `N`
/// from Subsquid's perspective is the chain's `treeNumber = N + 1,
/// startPosition = 0` log carried under the wrong key.
fn extract_cross_tree_stowaways(
    rows: &mut Vec<CommitmentRow>,
    tree_number: u32,
    carry: &mut StowawayCarry,
) -> u32 {
    let mut stowaways: Vec<CommitmentRow> = Vec::new();
    rows.retain(|r| {
        if r.tree_position >= TREE_MAX_ITEMS as u64 {
            tracing::warn!(
                tree_number,
                tree_position = r.tree_position,
                block_number = r.block_number,
                "boundary_repair: re-tagging row with impossible treePosition (>= TREE_MAX_ITEMS) as next tree's stowaway"
            );
            stowaways.push(r.clone());
            false
        } else {
            true
        }
    });
    let count = u32::try_from(stowaways.len()).unwrap_or(u32::MAX);
    if !stowaways.is_empty() {
        let target_tree = tree_number.saturating_add(1);
        let bucket = carry.entry(target_tree).or_default();
        for row in stowaways {
            let new_position = row.tree_position.saturating_sub(TREE_MAX_ITEMS as u64);
            bucket.push(CommitmentRow {
                tree_position: new_position,
                leaf: row.leaf,
                block_number: row.block_number,
            });
        }
    }
    count
}

/// Filter impossible `treePosition >= TREE_MAX_ITEMS` rows by
/// re-tagging them as the next tree's leaf-zero stowaway, then chain-
/// backfill any remaining gaps for a filled tree. Mutates `rows` in
/// place; returns the number of leaves repaired (`re-tags + backfills`).
///
/// Algorithm:
///
/// 1. For any row with `tree_position >= TREE_MAX_ITEMS` (e.g. the
///    Subsquid stowaway at position 65,536 in mainnet tree 0): drop
///    it from the current tree AND push a re-tagged copy
///    (`tree_position -= TREE_MAX_ITEMS`) into
///    `carry[tree_number + 1]` so the next per-tree call can drain it
///    before its own gap-walk. Per `Commitments.sol` no batch spans
///    tree boundaries; the chain log was emitted at
///    `treeNumber = N + 1, startPosition = 0` and Subsquid mis-tagged
///    it as `treeNumber = N, startPosition = TREE_MAX_ITEMS`. Each
///    re-tag emits a `tracing::warn!` carrying the row's
///    `block_number` so an operator can correlate.
/// 2. If the tree is filled (`active_tree_number > tree_number`) and
///    the row count is short of `TREE_MAX_ITEMS`, gap-walk the
///    sorted positions and chain-backfill each missing position via
///    [`ChainOracle::commitment_events_in_range`]. The query window
///    is `[anchor - BOUNDARY_REPAIR_WINDOW_BLOCKS,
///    anchor + BOUNDARY_REPAIR_WINDOW_BLOCKS]` where `anchor` is
///    derived from neighbouring rows' `block_number`s (boundary
///    rollovers happen at the smallest / largest blockNumbers; this
///    is monotone with `treePosition` per the Railgun proxy's append
///    semantics).
/// 3. If a position cannot be recovered, surfaces
///    [`BootstrapError::BoundaryRepairFailed`] with the residual
///    diagnostic. Live-tree rows are NOT gap-walked: a partial live
///    tree is operationally normal.
async fn repair_boundary_if_needed(
    rows: &mut Vec<CommitmentRow>,
    tree_number: u32,
    is_filled_tree: bool,
    chain: &dyn ChainOracle,
    repair_trigger_threshold: usize,
    expected_filled_count: usize,
    carry: &mut StowawayCarry,
) -> Result<u32, BootstrapError> {
    let mut repaired = extract_cross_tree_stowaways(rows, tree_number, carry);

    if !is_filled_tree {
        return Ok(repaired);
    }
    if rows.len() == expected_filled_count {
        return Ok(repaired);
    }
    if rows.len() < repair_trigger_threshold {
        return Ok(repaired);
    }

    rows.sort_by_key(|r| r.tree_position);

    let mut have: Vec<bool> = vec![false; expected_filled_count];
    for r in rows.iter() {
        let idx = usize::try_from(r.tree_position).unwrap_or(usize::MAX);
        if let Some(slot) = have.get_mut(idx) {
            *slot = true;
        }
    }

    let max_observed_position = rows.iter().map(|r| r.tree_position).max().unwrap_or(0);
    let max_observed_idx = usize::try_from(max_observed_position).unwrap_or(usize::MAX);

    let min_known_block = rows.iter().map(|r| r.block_number).min();
    let max_known_block = rows.iter().map(|r| r.block_number).max();

    let mut chain_cache: Vec<(u32, u32, [u8; 32])> = Vec::new();
    let mut scanned_ranges: Vec<(u64, u64)> = Vec::new();

    let half = expected_filled_count / 2;
    for (missing_index, slot) in have.iter_mut().enumerate() {
        if *slot {
            continue;
        }
        if missing_index > max_observed_idx {
            tracing::info!(
                tree_number,
                missing_index,
                max_observed_position,
                "boundary_repair: skipping tail-gap (tree closed before reaching this position; \
                 chain rolled over to next tree per Commitments.sol no-batch-spans-trees)"
            );
            continue;
        }
        let missing_u32 = u32::try_from(missing_index).unwrap_or(u32::MAX);
        let anchor = if missing_index == 0 || missing_index < half {
            min_known_block
        } else {
            max_known_block
        };
        let anchor = anchor.ok_or_else(|| BootstrapError::BoundaryRepairFailed {
            tree_number,
            missing_index: missing_u32,
            reason: "no anchor block available; subsquid returned zero rows for this tree".into(),
        })?;
        let from_block = anchor.saturating_sub(BOUNDARY_REPAIR_WINDOW_BLOCKS);
        let to_block = anchor.saturating_add(BOUNDARY_REPAIR_WINDOW_BLOCKS);
        if !scanned_ranges
            .iter()
            .any(|(f, t)| *f == from_block && *t == to_block)
        {
            let events = chain
                .commitment_events_in_range(from_block, to_block)
                .await?;
            chain_cache.extend(events);
            scanned_ranges.push((from_block, to_block));
        }

        let found = chain_cache
            .iter()
            .find(|(t, idx, _)| *t == tree_number && *idx == missing_u32);
        match found {
            Some((_, _, hash)) => {
                rows.push(CommitmentRow {
                    tree_position: missing_index as u64,
                    leaf: *hash,
                    block_number: anchor,
                });
                *slot = true;
                repaired = repaired.saturating_add(1);
            }
            None => {
                return Err(BootstrapError::BoundaryRepairFailed {
                    tree_number,
                    missing_index: missing_u32,
                    reason: format!(
                        "chain.commitment_events_in_range({from_block}, {to_block}) returned no \
                         Shield/Transact log carrying tree={tree_number} leaf_index={missing_u32}; \
                         widen the search window or surface as a deeper Subsquid divergence"
                    ),
                });
            }
        }
    }

    rows.sort_by_key(|r| r.tree_position);
    Ok(repaired)
}

/// Page through the Subsquid commitments feed for one tree, returning
/// the accumulated `(rows, page_count)` tuple. Extracted from
/// [`bootstrap_one_tree`] for clippy::too_many_lines hygiene + so the
/// boundary-repair flow can be unit-tested without the surrounding
/// chain-oracle dance.
async fn page_subsquid_leaves(
    cfg: &BootstrapTreeConfig,
    leaves_src: &dyn SubsquidLeavesSource,
    checkpoint_block: u64,
    started: Instant,
    budget: Duration,
) -> Result<(Vec<CommitmentRow>, u32), BootstrapError> {
    let mut rows: Vec<CommitmentRow> = Vec::new();
    let mut cursor: Option<u64> = None;
    let mut pages: u32 = 0;
    loop {
        if started.elapsed() > budget {
            return Err(BootstrapError::BudgetExhausted {
                limit_mins: cfg.max_wall_mins,
            });
        }
        let page = leaves_src
            .fetch_commitments_page(cfg.tree_number, checkpoint_block, cursor, SUBSQUID_PAGE)
            .await?;
        if page.is_empty() {
            break;
        }
        pages = pages.saturating_add(1);
        let mut last_pos: Option<u64> = cursor;
        for row in &page {
            if let Some(prev) = last_pos {
                if row.tree_position <= prev {
                    return Err(BootstrapError::SubsquidDecode(format!(
                        "tree_position not strictly ascending: {} <= {}",
                        row.tree_position, prev
                    )));
                }
            }
            last_pos = Some(row.tree_position);
            rows.push(row.clone());
        }
        cursor = last_pos;
        if page.len() < SUBSQUID_PAGE {
            break;
        }
    }
    Ok((rows, pages))
}

/// Run the bootstrap algorithm against a single tree.
///
/// Algorithm: page leaves from Subsquid, replay locally into an IMT,
/// then verify the rebuilt root with the chain ABI:
///
/// - LIVE tree (`active_tree_number_at(checkpoint) == tree`): assert
///   byte-identity vs `merkle_root_at(checkpoint)`.
/// - STATIC tree: assert membership via
///   `root_history_at(tree, local_root, checkpoint) == true`.
///
/// Caller is expected to have run [`ChainOracle::archival_probe`]
/// before invoking this. Mismatches surface as
/// [`BootstrapError::OracleByteIdentityMismatch`].
///
/// Convenience wrapper over [`bootstrap_one_tree_with_carry`] for
/// callers that bootstrap a single tree without a cross-tree stowaway
/// re-tag (e.g. the live tree on its own). Production orchestrators
/// MUST use [`bootstrap_one_tree_with_carry`] and thread the same
/// [`StowawayCarry`] across the per-tree loop so any
/// `tree_position >= TREE_MAX_ITEMS` row in tree `N` lands as the
/// `position 0` leaf in tree `N+1`.
pub async fn bootstrap_one_tree(
    cfg: &BootstrapTreeConfig,
    leaves_src: &dyn SubsquidLeavesSource,
    chain: &dyn ChainOracle,
) -> Result<BootstrapTreeReport, BootstrapError> {
    let mut carry = StowawayCarry::new();
    bootstrap_one_tree_with_carry(cfg, leaves_src, chain, &mut carry).await
}

/// Variant of [`bootstrap_one_tree`] that accepts a shared
/// [`StowawayCarry`] across per-tree calls so any Subsquid stowaway at
/// `treePosition >= TREE_MAX_ITEMS` in tree `N` is preserved as the
/// `position 0` leaf of tree `N + 1`. The orchestrator MUST invoke
/// trees in ascending order so a stowaway is in the carry before the
/// downstream tree's pagination resolves.
pub async fn bootstrap_one_tree_with_carry(
    cfg: &BootstrapTreeConfig,
    leaves_src: &dyn SubsquidLeavesSource,
    chain: &dyn ChainOracle,
    carry: &mut StowawayCarry,
) -> Result<BootstrapTreeReport, BootstrapError> {
    let started = Instant::now();
    let budget = Duration::from_secs(cfg.max_wall_mins.saturating_mul(60).max(1));
    let head = chain.chain_head().await?;
    let checkpoint_block = head.saturating_sub(cfg.checkpoint_depth);

    let (mut rows, pages) =
        page_subsquid_leaves(cfg, leaves_src, checkpoint_block, started, budget).await?;

    if let Some(carried) = carry.remove(&cfg.tree_number) {
        for row in carried {
            let exists = rows.iter().any(|r| r.tree_position == row.tree_position);
            if exists {
                tracing::warn!(
                    tree_number = cfg.tree_number,
                    tree_position = row.tree_position,
                    block_number = row.block_number,
                    "boundary_repair: cross-tree carry collides with paged Subsquid row; keeping paged row"
                );
                continue;
            }
            rows.push(row);
        }
        rows.sort_by_key(|r| r.tree_position);
    }

    let active_for_repair = chain
        .active_tree_number_at(checkpoint_block)
        .await
        .map_err(|e| classify_archival_error(e, checkpoint_block))?;
    let is_filled_tree = active_for_repair > cfg.tree_number;
    repair_boundary_if_needed(
        &mut rows,
        cfg.tree_number,
        is_filled_tree,
        chain,
        cfg.repair_trigger_threshold,
        cfg.expected_filled_count,
        carry,
    )
    .await?;

    let leaves: Vec<[u8; 32]> = rows.iter().map(|r| r.leaf).collect();
    let mut imt = Imt::new().map_err(|e| BootstrapError::Engine(format!("imt new: {e}")))?;
    for (i, leaf) in leaves.iter().enumerate() {
        imt.insert_leaves(i, std::slice::from_ref(leaf))
            .map_err(|e| BootstrapError::Engine(format!("imt insert {i}: {e}")))?;
    }
    let local_root = imt.root();

    // Chain branch: live vs static. Both reads are pinned to the
    // checkpoint block; archival state is mandatory and the caller
    // is expected to have probed for it before getting here.
    // `active_for_repair` was already fetched above to drive the
    // boundary-repair "is this tree filled" decision; reuse it.
    let is_live = active_for_repair == cfg.tree_number;

    let mut chain_live_root: Option<[u8; 32]> = None;
    let mut chain_static_membership: Option<bool> = None;
    if is_live {
        let chain_root = chain
            .merkle_root_at(checkpoint_block)
            .await
            .map_err(|e| classify_archival_error(e, checkpoint_block))?;
        chain_live_root = Some(chain_root);
        if local_root != chain_root {
            let mi = first_match_index(&leaves, &chain_root)?;
            return Err(BootstrapError::OracleByteIdentityMismatch {
                kind: OracleKind::ChainLiveTree,
                tree_number: cfg.tree_number,
                expected_hex: to_hex(&local_root),
                observed_hex: to_hex(&chain_root),
                first_match_index: mi,
            });
        }
    } else {
        let recorded = chain
            .root_history_at(cfg.tree_number, local_root, checkpoint_block)
            .await
            .map_err(|e| classify_archival_error(e, checkpoint_block))?;
        chain_static_membership = Some(recorded);
        if !recorded {
            return Err(BootstrapError::OracleByteIdentityMismatch {
                kind: OracleKind::ChainStaticTree,
                tree_number: cfg.tree_number,
                expected_hex: to_hex(&local_root),
                observed_hex: "rootHistory(tree, local_root) == false".to_owned(),
                first_match_index: leaves.len(),
            });
        }
    }

    persist_initial_snapshot(cfg, &leaves, checkpoint_block)?;

    Ok(BootstrapTreeReport {
        tree_number: cfg.tree_number,
        checkpoint_block,
        leaves: leaves.len(),
        local_root,
        chain_live_root,
        chain_static_membership,
        wall_clock_secs: started.elapsed().as_secs_f64(),
        subsquid_pages: pages,
        data_dir: cfg.data_dir.clone(),
    })
}

/// Map a transient `RpcUnreachable` whose message screams "no archival
/// state" into the typed [`BootstrapError::NoArchivalRpc`] variant so
/// the operator gets an actionable message instead of a generic RPC
/// error. Pass-through for every other error.
fn classify_archival_error(e: BootstrapError, checkpoint_block: u64) -> BootstrapError {
    match e {
        BootstrapError::RpcUnreachable(msg) if looks_like_pruning_error(&msg) => {
            BootstrapError::NoArchivalRpc {
                checkpoint_block,
                actionable: format!(
                    "the RPC endpoint that served this call returned a \
                     pruning/historical-state error: {msg}. Add an \
                     Alchemy/Infura/Quicknode archival endpoint to your \
                     rpc-pool.toml so the pool can serve eth_call at \
                     block {checkpoint_block}."
                ),
            }
        }
        other => other,
    }
}

/// Walk the leaf sequence and return the first index `i` such that the
/// IMT after `i+1` inserts equals `target_root`, or `leaves.len()` if
/// no prefix matches. Used to give the operator a precise "the last
/// good leaf was N" hint when the byte-identity oracle disagrees with
/// our locally rebuilt root.
fn first_match_index(leaves: &[[u8; 32]], target_root: &[u8; 32]) -> Result<usize, BootstrapError> {
    let mut imt =
        Imt::new().map_err(|e| BootstrapError::Engine(format!("imt new (match-search): {e}")))?;
    for (i, leaf) in leaves.iter().enumerate() {
        imt.insert_leaves(i, std::slice::from_ref(leaf))
            .map_err(|e| BootstrapError::Engine(format!("imt insert (match-search) {i}: {e}")))?;
        if imt.root() == *target_root {
            return Ok(i);
        }
    }
    Ok(leaves.len())
}

/// Cell shape (total rows × record-size in bytes) the PIR table for a
/// given encoder kind expects. Single source of truth for all bootstrap
/// encoded_db sizing.
fn cell_shape_for_encoder(kind: EncoderKind) -> (u32, usize) {
    match kind {
        EncoderKind::PerLeafBc | EncoderKind::PerListStatus { .. } => {
            (LEAVES_PER_TREE, NODE_HASH_BYTES)
        }
        EncoderKind::PerLeafPath { .. } | EncoderKind::PerListPath { .. } => {
            (LEAVES_PER_TREE, PATH_RECORD_BYTES)
        }
        EncoderKind::PerNode { .. } | EncoderKind::PerListNode { .. } => {
            (PER_NODE_TOTAL_NODES, NODE_HASH_BYTES)
        }
    }
}

fn persist_initial_snapshot(
    cfg: &BootstrapTreeConfig,
    leaves: &[[u8; 32]],
    checkpoint_block: u64,
) -> Result<(), BootstrapError> {
    std::fs::create_dir_all(&cfg.data_dir).map_err(|e| BootstrapError::DataDirIo {
        path: cfg.data_dir.display().to_string(),
        error: e.to_string(),
    })?;
    let (layout, _lock) = StoreLayout::open_with_lock(&cfg.data_dir).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("locked") || msg.contains("LockHeld") || msg.contains("WouldBlock") {
            BootstrapError::LockHeld {
                path: cfg.data_dir.display().to_string(),
            }
        } else {
            BootstrapError::DataDirIo {
                path: cfg.data_dir.display().to_string(),
                error: msg,
            }
        }
    })?;

    let encoder_kind = cfg.encoder_kind;
    let (total_rows, record_size) = cell_shape_for_encoder(encoder_kind);
    let entries_per_shard: u32 = 2048;
    let num_shards = total_rows.div_ceil(entries_per_shard);

    let encoder: Arc<dyn PirTableEncoder> = encoder_kind
        .build(record_size, entries_per_shard)
        .map_err(|e| BootstrapError::Engine(format!("encoder build: {e}")))?;

    let mut store = LogicalLeafStore::default();
    for (idx, leaf) in leaves.iter().enumerate() {
        let leaf_index = u32::try_from(idx)
            .map_err(|_| BootstrapError::Engine(format!("leaf_index {idx} overflows u32")))?;
        let payload = WalEntryPayload::AppendLeaf {
            tree_number: cfg.tree_number,
            leaf_index,
            commitment: *leaf,
        };
        store
            .apply(&payload, checkpoint_block, encoder.as_ref())
            .map_err(|e| BootstrapError::Engine(format!("apply leaf {idx}: {e}")))?;
    }

    let total_db_rows = (num_shards as usize) * (entries_per_shard as usize);
    let mut encoded_db: Vec<u8> = Vec::with_capacity(total_db_rows.saturating_mul(record_size));
    for shard_id in 0..num_shards {
        let shard_bytes = encoder.materialize_shard(shard_id, &store);
        encoded_db.extend_from_slice(&shard_bytes);
    }

    let params = InspireParams::secure_128_d2048();
    let mut state_holder = Some({
        let (state, _sk) = setup_state(
            &params,
            &encoded_db,
            record_size,
            InspireVariant::TwoPacking,
        )
        .map_err(|e| BootstrapError::Engine(format!("setup_state: {e}")))?;
        state
    });
    let factory = move || {
        state_holder.take().ok_or_else(|| {
            raven_railgun_core::AdapterError::Internal("factory called twice".into())
        })
    };
    let instance_id = InstanceId::new(cfg.instance_id.clone());
    let layout_clone = layout.clone();
    let (_inst, persistence) = bootstrap_inspire_instance(
        layout,
        cfg.scheme_tag.clone(),
        instance_id,
        InstanceRole::Live,
        SnapshotPolicy::default(),
        encoder,
        factory,
    )
    .map_err(|e| BootstrapError::Engine(format!("bootstrap_inspire_instance: {e}")))?;

    for (idx, leaf) in leaves.iter().enumerate() {
        let leaf_index = u32::try_from(idx)
            .map_err(|_| BootstrapError::Engine(format!("leaf_index {idx} overflows u32")))?;
        let payload = WalEntryPayload::AppendLeaf {
            tree_number: cfg.tree_number,
            leaf_index,
            commitment: *leaf,
        };
        persistence
            .apply_event(&payload, checkpoint_block)
            .map_err(|e| BootstrapError::Engine(format!("apply_event leaf {idx}: {e}")))?;
    }

    let mut manifest = raven_railgun_persistence::Manifest::load(&layout_clone)
        .map_err(|e| BootstrapError::Snapshot(format!("manifest load: {e}")))?
        .ok_or_else(|| {
            BootstrapError::Snapshot("manifest absent after bootstrap_inspire_instance".into())
        })?;
    manifest.current_block_height = checkpoint_block;
    manifest
        .save(&layout_clone)
        .map_err(|e| BootstrapError::Snapshot(format!("manifest save: {e}")))?;
    Ok(())
}

/// PPOI list bootstrap (Railway upstream is the only path; Subsquid
/// schema does not expose per-list IMT roots).
#[async_trait]
pub trait PpoiEventsSource: Send + Sync {
    /// Fetch every event for `list_key`. Each row carries the
    /// upstream-published `validatedMerkleroot` that the sequence is
    /// asserted against.
    async fn fetch_all_events(
        &self,
        list_key: [u8; 32],
    ) -> Result<Vec<PpoiEventRow>, BootstrapError>;
}

#[derive(Debug, Clone)]
pub struct PpoiEventRow {
    pub index: u64,
    pub leaf: [u8; 32],
    pub validated_merkleroot: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct PpoiListReport {
    pub list_key: [u8; 32],
    pub events: usize,
    pub local_root: [u8; 32],
}

/// Operator-side resilience policy for the PPOI bootstrap step.
///
/// `Strict` preserves the original V1 behaviour: any upstream
/// unreachability hard-stops the bootstrap. `SkipOnUnreachable` is the
/// always-works baseline: when every upstream source fails with a
/// transport-level error, the per-list IMT is seeded EMPTY and a loud
/// warn-level log is emitted to surface the upstream-signature gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PpoiBootstrapMode {
    /// Hard-stop on any upstream unreachability. Default for V1
    /// backward compatibility.
    #[default]
    Strict,
    /// Loudly warn and seed an EMPTY per-list IMT when every upstream
    /// source returns a `PpoiUnreachable` (or `PpoiDecode`) error. Any
    /// non-transport error (e.g. byte-identity mismatch) still
    /// hard-stops to preserve oracle integrity.
    SkipOnUnreachable,
}

impl PpoiBootstrapMode {
    /// Parse the CLI string into a mode value.
    pub fn parse_cli(s: &str) -> Result<Self, String> {
        match s {
            "strict" => Ok(Self::Strict),
            "skip-on-unreachable" => Ok(Self::SkipOnUnreachable),
            other => Err(format!(
                "unknown ppoi-bootstrap-mode {other}; expected one of strict | skip-on-unreachable"
            )),
        }
    }
}

/// Bootstrap one PPOI list — assert each upstream
/// `validatedMerkleroot` matches our locally rebuilt per-list IMT root
/// after each successive insert.
///
/// Convenience wrapper for the strict-mode default. Tests and the CLI
/// MUST call [`bootstrap_one_list_with_mode`] when they need to expose
/// the operator-side resilience policy.
pub async fn bootstrap_one_list(
    list_key: [u8; 32],
    src: &dyn PpoiEventsSource,
    data_dir_template: &str,
) -> Result<PpoiListReport, BootstrapError> {
    bootstrap_one_list_with_mode(
        list_key,
        src,
        data_dir_template,
        PpoiBootstrapMode::Strict,
        &[],
    )
    .await
}

/// Bootstrap one PPOI list with explicit operator-side resilience
/// policy. `tried_sources_for_log` is informational only; it ends up
/// in the WARN message emitted in [`PpoiBootstrapMode::SkipOnUnreachable`]
/// mode so operators can see exactly which URLs were tried.
pub async fn bootstrap_one_list_with_mode(
    list_key: [u8; 32],
    src: &dyn PpoiEventsSource,
    _data_dir_template: &str,
    mode: PpoiBootstrapMode,
    tried_sources_for_log: &[String],
) -> Result<PpoiListReport, BootstrapError> {
    let events = match src.fetch_all_events(list_key).await {
        Ok(v) => v,
        Err(e) => {
            if matches!(
                e,
                BootstrapError::PpoiUnreachable(_) | BootstrapError::PpoiDecode(_)
            ) && mode == PpoiBootstrapMode::SkipOnUnreachable
            {
                let imt = Imt::new()
                    .map_err(|err| BootstrapError::Engine(format!("ppoi imt new: {err}")))?;
                let key_hex = to_hex(&list_key);
                let sources_csv = if tried_sources_for_log.is_empty() {
                    String::from("(none)")
                } else {
                    tried_sources_for_log.join(", ")
                };
                tracing::warn!(
                    list_key = %key_hex,
                    tried_sources = %sources_csv,
                    cause = %e,
                    "PPOI bootstrap skipped: list_key={key_hex}; sources tried: {sources_csv}; per-list IMT seeded EMPTY; runtime mirror will populate when upstream becomes reachable. UPSTREAM SIGNATURE VERIFY GAP: validatedMerkleroot byte-identity oracle and ed25519 signed-event verification both deferred."
                );
                return Ok(PpoiListReport {
                    list_key,
                    events: 0,
                    local_root: imt.root(),
                });
            }
            return Err(e);
        }
    };
    let mut imt = Imt::new().map_err(|e| BootstrapError::Engine(format!("ppoi imt new: {e}")))?;
    for (i, ev) in events.iter().enumerate() {
        imt.insert_leaves(i, std::slice::from_ref(&ev.leaf))
            .map_err(|e| BootstrapError::Engine(format!("ppoi imt insert {i}: {e}")))?;
        let local = imt.root();
        if local != ev.validated_merkleroot {
            return Err(BootstrapError::OracleByteIdentityMismatch {
                kind: OracleKind::PpoiUpstreamList,
                tree_number: u32::MAX,
                expected_hex: to_hex(&local),
                observed_hex: to_hex(&ev.validated_merkleroot),
                first_match_index: i,
            });
        }
    }
    Ok(PpoiListReport {
        list_key,
        events: events.len(),
        local_root: imt.root(),
    })
}

/// Per-URL HTTP timeout when probing a Railway PPOI base. Operators
/// run with multiple bases in priority order; on transport failure or
/// non-2xx response we walk to the next base. Mirrors the upstream
/// wallet behaviour at `repo-cache/wallet/src/services/poi/poi-node-request.ts`.
const RAILWAY_PER_URL_TIMEOUT: Duration = Duration::from_secs(8);

/// The default Railway base list that every operator gets unless they
/// override `--ppoi-endpoint`. Order is priority-significant: the first
/// reachable base wins.
pub const DEFAULT_RAILWAY_BASES: &[&str] = &[
    "https://poi.us.proxy.railwayapi.xyz",
    "https://poi-lb.us.proxy.railwayapi.xyz",
    "https://ppoi-agg.horsewithsixlegs.xyz",
];

/// Live HTTP client wrapping the upstream Railway PPOI events feed.
/// Only consumed by the CLI binary; tests use an in-process axum stub
/// implementing [`PpoiEventsSource`] directly.
///
/// Operators supply an ordered list of base URLs; the client walks
/// them sequentially with a per-URL `RAILWAY_PER_URL_TIMEOUT`. On
/// connect-error / TCP-timeout / non-2xx response, the next base is
/// tried. `BootstrapError::PpoiUnreachable` only fires after every
/// base fails.
pub struct RailwayPpoiClient {
    bases: Vec<String>,
    chain_type: u32,
    chain_id: u64,
    http: reqwest::Client,
}

impl std::fmt::Debug for RailwayPpoiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RailwayPpoiClient")
            .field("bases", &self.bases)
            .field("chain_type", &self.chain_type)
            .field("chain_id", &self.chain_id)
            .finish_non_exhaustive()
    }
}

impl RailwayPpoiClient {
    /// Single-base constructor preserved for existing call sites; the
    /// multi-base variant is what the CLI threads through.
    /// Returns an error if `base` is empty after trimming.
    pub fn new(base: impl Into<String>, chain_type: u32, chain_id: u64) -> Self {
        let s: String = base.into();
        if let Ok(c) = Self::new_multi(vec![s.clone()], chain_type, chain_id) {
            return c;
        }
        let http = reqwest::Client::builder()
            .timeout(RAILWAY_PER_URL_TIMEOUT)
            .connect_timeout(RAILWAY_PER_URL_TIMEOUT)
            .build()
            .unwrap_or_else(|e| {
                tracing::warn!(
                    error = %e,
                    "reqwest builder failed for RailwayPpoiClient; falling back to Client::new() (no timeout)"
                );
                reqwest::Client::new()
            });
        Self {
            bases: vec![s],
            chain_type,
            chain_id,
            http,
        }
    }

    /// Multi-base constructor. Returns an error when the base list is
    /// empty (operator-input validation: the CLI converts this into a
    /// clean `clap` error).
    pub fn new_multi(bases: Vec<String>, chain_type: u32, chain_id: u64) -> Result<Self, String> {
        if bases.is_empty() {
            return Err("RailwayPpoiClient: at least one base URL is required".to_owned());
        }
        let cleaned: Vec<String> = bases
            .into_iter()
            .map(|s| s.trim().trim_end_matches('/').to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        if cleaned.is_empty() {
            return Err("RailwayPpoiClient: every supplied base URL was empty".to_owned());
        }
        let http = reqwest::Client::builder()
            .timeout(RAILWAY_PER_URL_TIMEOUT)
            .connect_timeout(RAILWAY_PER_URL_TIMEOUT)
            .build()
            .map_err(|e| format!("reqwest builder: {e}"))?;
        Ok(Self {
            bases: cleaned,
            chain_type,
            chain_id,
            http,
        })
    }

    /// Read-only accessor for the bases list (used by the CLI to
    /// thread the same set into `bootstrap_one_list_with_mode`'s
    /// operator-facing log).
    pub fn bases(&self) -> &[String] {
        &self.bases
    }
}

#[derive(Debug, Deserialize)]
struct WireSignedPoiEvent {
    index: u64,
    #[serde(rename = "blindedCommitment")]
    blinded_commitment: String,
}

#[derive(Debug, Deserialize)]
struct WirePoiEventEntry {
    #[serde(rename = "signedPOIEvent")]
    signed_event: WireSignedPoiEvent,
    #[serde(rename = "validatedMerkleroot")]
    validated_merkleroot: String,
}

#[async_trait]
impl PpoiEventsSource for RailwayPpoiClient {
    async fn fetch_all_events(
        &self,
        list_key: [u8; 32],
    ) -> Result<Vec<PpoiEventRow>, BootstrapError> {
        let body = serde_json::json!({
            "txidVersion": "V2_PoseidonMerkle",
            "listKey": to_hex(&list_key),
            "startIndex": 0u64,
            "endIndex": u64::from(u32::MAX),
        });
        let mut last_err = String::from("(no bases attempted)");
        for base in &self.bases {
            let url = format!("{}/poi-events/{}/{}", base, self.chain_type, self.chain_id);
            let resp = match self.http.post(&url).json(&body).send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{base}: {e}");
                    tracing::warn!(base = %base, error = %e, "Railway PPOI base unreachable; trying next");
                    last_err = msg;
                    continue;
                }
            };
            if !resp.status().is_success() {
                let status = resp.status();
                let msg = format!("{base}: HTTP {status}");
                tracing::warn!(base = %base, status = %status, "Railway PPOI base non-2xx; trying next");
                last_err = msg;
                continue;
            }
            let parsed: Vec<WirePoiEventEntry> = match resp.json().await {
                Ok(v) => v,
                Err(e) => {
                    let msg = format!("{base}: decode {e}");
                    tracing::warn!(base = %base, error = %e, "Railway PPOI base body decode failed; trying next");
                    last_err = msg;
                    continue;
                }
            };
            let mut out = Vec::with_capacity(parsed.len());
            for entry in parsed {
                let leaf = parse_hex32(&entry.signed_event.blinded_commitment)
                    .map_err(|e| BootstrapError::PpoiDecode(format!("blindedCommitment: {e}")))?;
                let root = parse_hex32(&entry.validated_merkleroot)
                    .map_err(|e| BootstrapError::PpoiDecode(format!("validatedMerkleroot: {e}")))?;
                out.push(PpoiEventRow {
                    index: entry.signed_event.index,
                    leaf,
                    validated_merkleroot: root,
                });
            }
            return Ok(out);
        }
        Err(BootstrapError::PpoiUnreachable(format!(
            "all {} Railway base(s) failed; last error: {last_err}",
            self.bases.len()
        )))
    }
}

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    if trimmed.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", trimmed.len()));
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let pair = trimmed
            .get(i * 2..i * 2 + 2)
            .ok_or_else(|| format!("range at {i}"))?;
        *slot = u8::from_str_radix(pair, 16).map_err(|e| format!("byte {i}: {e}"))?;
    }
    Ok(out)
}

/// Live Subsquid client implementing [`SubsquidLeavesSource`] against
/// a real GraphQL endpoint. Tests use an in-process stub.
pub struct SubsquidLeavesClient {
    endpoint: String,
    http: reqwest::Client,
}

impl std::fmt::Debug for SubsquidLeavesClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubsquidLeavesClient")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

/// Per-request timeout for Subsquid GraphQL pages. Operator's gateway
/// is intermittently slow (502s + outright stalls observed on mainnet);
/// without a timeout, `reqwest::Client::new()` waits indefinitely on a
/// hung connection and the per-tree wall budget never fires because it
/// is checked between pages, not during a stalled request.
const SUBSQUID_PER_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum retry attempts on transient Subsquid failures (5xx, decode
/// errors, network timeouts). Backoff is exponential: 2s, 4s, 8s.
const SUBSQUID_MAX_RETRIES: u32 = 3;

impl SubsquidLeavesClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(SUBSQUID_PER_REQUEST_TIMEOUT)
            .connect_timeout(SUBSQUID_PER_REQUEST_TIMEOUT)
            .build()
            .unwrap_or_else(|e| {
                tracing::warn!(
                    error = %e,
                    "reqwest builder failed for SubsquidLeavesClient; falling back to Client::new() (no timeout)"
                );
                reqwest::Client::new()
            });
        Self {
            endpoint: endpoint.into(),
            http,
        }
    }
}

const SUBSQUID_COMMITMENTS_QUERY: &str =
    "query Commits($tree: Int!, $block: BigInt!, $cursor: Int!, $limit: Int!) { \
    commitments( \
        where: { treeNumber_eq: $tree, blockNumber_lte: $block, treePosition_gt: $cursor }, \
        orderBy: treePosition_ASC, \
        limit: $limit \
    ) { treePosition hash blockNumber } \
}";

// Subsquid is leaves-only. The chain ABI (`merkleRoot()` /
// `rootHistory(tree, root)`) is the canonical post-state oracle.

#[async_trait]
impl SubsquidLeavesSource for SubsquidLeavesClient {
    #[allow(clippy::too_many_lines)]
    async fn fetch_commitments_page(
        &self,
        tree_number: u32,
        checkpoint_block: u64,
        cursor: Option<u64>,
        page_size: usize,
    ) -> Result<Vec<CommitmentRow>, BootstrapError> {
        // First-page cursor sentinel `-1` so the `treePosition_gt`
        // filter includes leaf 0. Subsequent pages use the last
        // `treePosition` from the previous page. `treePosition` is
        // `Int!` upstream so we send it as a JSON integer.
        let cursor_value: i64 = match cursor {
            Some(c) => i64::try_from(c).unwrap_or(i64::MAX),
            None => -1,
        };
        let body = serde_json::json!({
            "query": SUBSQUID_COMMITMENTS_QUERY,
            "variables": {
                "tree": tree_number,
                "block": checkpoint_block.to_string(),
                "cursor": cursor_value,
                "limit": u64::try_from(page_size).unwrap_or(u64::MAX),
            },
        });
        let mut last_err: Option<BootstrapError> = None;
        let mut response_body: Option<serde_json::Value> = None;
        for attempt in 0..=SUBSQUID_MAX_RETRIES {
            if attempt > 0 {
                let backoff_secs = 2u64.saturating_pow(attempt);
                tracing::warn!(
                    attempt,
                    backoff_secs,
                    last_err = ?last_err,
                    "subsquid page request failed; retrying with backoff"
                );
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
            }
            let send_result = self.http.post(&self.endpoint).json(&body).send().await;
            let resp = match send_result {
                Ok(r) => r,
                Err(e) => {
                    last_err = Some(BootstrapError::SubsquidUnreachable(e.to_string()));
                    continue;
                }
            };
            if !resp.status().is_success() {
                last_err = Some(BootstrapError::SubsquidUnreachable(format!(
                    "{}",
                    resp.status()
                )));
                continue;
            }
            match resp.json::<serde_json::Value>().await {
                Ok(b) => {
                    response_body = Some(b);
                    break;
                }
                Err(e) => {
                    last_err = Some(BootstrapError::SubsquidDecode(e.to_string()));
                }
            }
        }
        let Some(body) = response_body else {
            return Err(last_err.unwrap_or_else(|| {
                BootstrapError::SubsquidUnreachable("retry budget exhausted".to_owned())
            }));
        };
        if let Some(errors) = body.get("errors").and_then(|v| v.as_array()) {
            if !errors.is_empty() {
                return Err(BootstrapError::SubsquidDecode(format!(
                    "graphql errors: {errors:?}"
                )));
            }
        }
        let arr = body
            .pointer("/data/commitments")
            .and_then(|v| v.as_array())
            .ok_or_else(|| BootstrapError::SubsquidDecode("missing /data/commitments".into()))?;
        let mut out = Vec::with_capacity(arr.len());
        for (i, row) in arr.iter().enumerate() {
            let pos = row
                .get("treePosition")
                .and_then(|v| {
                    v.as_str()
                        .and_then(|s| s.parse::<u64>().ok())
                        .or_else(|| v.as_u64())
                })
                .ok_or_else(|| BootstrapError::SubsquidDecode(format!("treePosition[{i}]")))?;
            let hash = row
                .get("hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| BootstrapError::SubsquidDecode(format!("hash[{i}]")))?;
            let leaf = decode_bigint_to_be_bytes32(hash)
                .map_err(|reason| BootstrapError::BigintDecode { index: i, reason })?;
            let block_number = row
                .get("blockNumber")
                .and_then(|v| {
                    v.as_str()
                        .and_then(|s| s.parse::<u64>().ok())
                        .or_else(|| v.as_u64())
                })
                .unwrap_or(0);
            out.push(CommitmentRow {
                tree_position: pos,
                leaf,
                block_number,
            });
        }
        Ok(out)
    }
}

/// Adapter wrapping a [`raven_railgun_indexer::ChainSource`] into the
/// bootstrap [`ChainOracle`] surface so the live CLI can drive the
/// 3-oracle path against a real RPC pool.
pub struct ChainSourceOracle {
    inner: Arc<dyn raven_railgun_indexer::ChainSource>,
}

impl std::fmt::Debug for ChainSourceOracle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainSourceOracle").finish_non_exhaustive()
    }
}

impl ChainSourceOracle {
    pub fn new(inner: Arc<dyn raven_railgun_indexer::ChainSource>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl ChainOracle for ChainSourceOracle {
    async fn chain_head(&self) -> Result<u64, BootstrapError> {
        self.inner
            .latest_block()
            .await
            .map_err(|e| BootstrapError::RpcUnreachable(e.to_string()))
    }
    async fn active_tree_number_at(&self, block: u64) -> Result<u32, BootstrapError> {
        let at = Some(alloy::eips::BlockId::Number(
            alloy::eips::BlockNumberOrTag::Number(block),
        ));
        self.inner
            .active_tree_number(at)
            .await
            .map_err(|e| BootstrapError::RpcUnreachable(e.to_string()))
    }
    async fn merkle_root_at(&self, block: u64) -> Result<[u8; 32], BootstrapError> {
        let at = Some(alloy::eips::BlockId::Number(
            alloy::eips::BlockNumberOrTag::Number(block),
        ));
        self.inner
            .merkle_root(at)
            .await
            .map_err(|e| BootstrapError::RpcUnreachable(e.to_string()))
    }
    async fn root_history_at(
        &self,
        tree_number: u32,
        merkle_root: [u8; 32],
        block: u64,
    ) -> Result<bool, BootstrapError> {
        let at = Some(alloy::eips::BlockId::Number(
            alloy::eips::BlockNumberOrTag::Number(block),
        ));
        self.inner
            .root_history(tree_number, merkle_root, at)
            .await
            .map_err(|e| BootstrapError::RpcUnreachable(e.to_string()))
    }
    async fn commitment_events_in_range(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<(u32, u32, [u8; 32])>, BootstrapError> {
        let events = self
            .inner
            .events_in_range(from_block, to_block)
            .await
            .map_err(|e| BootstrapError::RpcUnreachable(e.to_string()))?;
        let mut out = Vec::new();
        for ev in events {
            match ev {
                RailgunEvent::Shield { leaves, .. } | RailgunEvent::Transact { leaves, .. } => {
                    for leaf in leaves {
                        out.push((leaf.tree_number, leaf.leaf_index, leaf.commitment_hash));
                    }
                }
                RailgunEvent::Nullified { .. } | RailgunEvent::Unshield { .. } => {}
            }
        }
        Ok(out)
    }
}

/// Resolve the data_dir for a tree number from a template containing
/// the literal `{N}` substring. Errors if the substring is absent.
pub fn resolve_data_dir_template(template: &str, tree_number: u32) -> Result<PathBuf, String> {
    if !template.contains("{N}") {
        return Err(format!("template must contain {{N}}: {template}"));
    }
    Ok(PathBuf::from(
        template.replace("{N}", &tree_number.to_string()),
    ))
}

/// Resolve the PPOI data_dir from a template containing `{LIST_KEY}`.
pub fn resolve_ppoi_data_dir(template: &str, list_key: [u8; 32]) -> Result<PathBuf, String> {
    if !template.contains("{LIST_KEY}") {
        return Err(format!("template must contain {{LIST_KEY}}: {template}"));
    }
    Ok(PathBuf::from(
        template.replace("{LIST_KEY}", &to_hex(&list_key)),
    ))
}

/// Convenience accessor used by tests that need to round-trip the
/// modulus literal.
#[doc(hidden)]
pub fn modulus_be() -> [u8; 32] {
    BN254_FR_MODULUS_BE
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn decimal_zero_decodes_to_zero_bytes() {
        let out = decode_bigint_to_be_bytes32("0").expect("zero");
        assert_eq!(out, [0u8; 32]);
    }

    #[test]
    fn decimal_small_value_round_trips() {
        let out = decode_bigint_to_be_bytes32("256").expect("256");
        let mut want = [0u8; 32];
        want[30] = 0x01;
        want[31] = 0x00;
        assert_eq!(out, want);
    }

    #[test]
    fn decimal_modulus_minus_one_accepted() {
        // BN254 modulus minus 1: still canonical.
        let m1 = "21888242871839275222246405745257275088548364400416034343698204186575808495616";
        decode_bigint_to_be_bytes32(m1).expect("modulus-1 canonical");
    }

    #[test]
    fn decimal_at_modulus_rejected() {
        let m = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
        let err = decode_bigint_to_be_bytes32(m).expect_err("modulus rejected");
        assert!(err.contains("BN254"));
    }

    #[test]
    fn decimal_with_letters_rejected() {
        assert!(decode_bigint_to_be_bytes32("12abc").is_err());
    }

    #[test]
    fn template_resolution_replaces_placeholder() {
        let p = resolve_data_dir_template("/tmp/raven/commit-tree-{N}", 3).expect("ok");
        assert_eq!(p.to_string_lossy(), "/tmp/raven/commit-tree-3");
    }

    #[test]
    fn template_resolution_rejects_missing_placeholder() {
        assert!(resolve_data_dir_template("/tmp/no-placeholder", 0).is_err());
    }

    #[test]
    fn ppoi_template_resolution_replaces_placeholder() {
        let p = resolve_ppoi_data_dir("/tmp/raven/list-{LIST_KEY}", [0xab; 32]).expect("ok");
        assert!(p.to_string_lossy().ends_with(&"ab".repeat(32)));
    }
}
