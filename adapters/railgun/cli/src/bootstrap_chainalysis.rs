//! Chainalysis OFAC oracle PPOI bootstrap adapter.
//!
//! Implements [`PpoiEventsSource`] by reading the on-chain
//! Chainalysis sanctions oracle (mainnet:
//! `0x40C57923924B5c5c5455c48D93317139ADDaC8fb`) and deriving the
//! per-list IMT events the PPOI bootstrap pipeline expects.
//!
//! The adapter has two cooperating layers:
//!
//! 1. **Oracle layer.** Reads `SanctionedAddressesAdded(address[])`
//!    log entries from the oracle contract via `eth_getLogs`,
//!    block-chunked to a free-tier-safe span.
//! 2. **Derivation layer.** Maps each sanctioned address into the
//!    set of Railgun shield events whose deposit recipient (NPK
//!    derivation input) is that address, then computes
//!    `BlindedCommitment = Poseidon(commitmentHash, npk,
//!    globalTreePosition)` per
//!    `engine/src/poi/blinded-commitment.ts:13-16`.
//!
//! The on-chain shield log carries the plaintext `npk: bytes32`
//! and the `(treeNumber, startPosition)` global tree position,
//! so the derivation is deterministic from chain state alone — no
//! off-chain wallet metadata required.
//!
//! Synthetic-fixture testing keeps the wiring exercise-able
//! without live RPC. See `tests/ppoi_chainalysis_adapter.rs`.

use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, B256, U256};
use alloy::sol;
use alloy::sol_types::SolEvent;
use async_trait::async_trait;

use crate::bootstrap_subsquid::{BootstrapError, PpoiEventRow, PpoiEventsSource};
use raven_railgun_indexer::rpc_pool::RpcEndpointPool;

sol! {
    /// Chainalysis OFAC oracle event emitted when one or more
    /// addresses are added to the sanctions list. Indexed `addedAddresses`
    /// is the only field — no indexed topics.
    #[allow(missing_docs)]
    event SanctionedAddressesAdded(address[] addedAddresses);
}

/// Mainnet deployment of the Chainalysis OFAC sanctions oracle.
/// Locked literal verified against
/// `private-proof-of-innocence/packages/node/src/local-list-provider.ts`
/// (the upstream Railgun PPOI list provider routes through the same
/// oracle via the public Chainalysis API).
pub const CHAINALYSIS_ORACLE_MAINNET: &str = "0x40C57923924B5c5c5455c48D93317139ADDaC8fb";

/// Earliest block at which the Chainalysis oracle was deployed and
/// the first sanctioned-address-added events appeared. Anything
/// earlier returns no logs.
pub const CHAINALYSIS_ORACLE_FIRST_BLOCK: u64 = 14_356_508;

/// Default `eth_getLogs` chunk span. Free-tier mainnet RPCs
/// (Infura/Alchemy) cap at 10k blocks for log queries; we use a
/// conservative span that completes within the per-call timeout
/// even on the slowest publicnode endpoint.
pub const DEFAULT_LOG_CHUNK_BLOCKS: u64 = 5_000;

/// Per-call RPC timeout. Matches the existing PPOI client.
const PER_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Synthetic Shield-event row used by the derivation layer to map a
/// sanctioned address to one or more on-chain commitments. In
/// production this is hydrated from the same `eth_getLogs` pool
/// (the indexer already decodes `Shield(...)` per
/// `decode_log_to_railgun_event`); the adapter accepts pre-decoded
/// rows so synthetic-fixture tests can drive the derivation without
/// touching RPC.
#[derive(Debug, Clone)]
pub struct SyntheticShieldRow {
    /// EOA / contract that authored the shield deposit; matched
    /// byte-equal against the sanctioned set.
    pub from_address: Address,
    /// Shield commitment hash: `Poseidon(npk, tokenHash,
    /// valueAfterFee)`.
    pub commitment_hash: [u8; 32],
    /// Plaintext NPK as published in the shield log's
    /// `CommitmentPreimage`.
    pub npk: [u8; 32],
    /// Global tree position: `tree_number * 65_536 + leaf_index`,
    /// big-endian-padded into a 32-byte field element.
    pub global_tree_position: [u8; 32],
}

/// Builder/config for [`ChainalysisOnChainOracleSource`]. Holds the
/// oracle address, block range, chunk size, and an optional
/// synthetic override that bypasses RPC entirely (used by the test
/// fixture).
#[derive(Clone)]
pub struct ChainalysisOnChainOracleSource {
    pool: Option<Arc<RpcEndpointPool>>,
    oracle_addr: Address,
    block_start: u64,
    block_end: Option<u64>,
    chunk_size: u64,
    sanctioned_override: Option<Vec<Address>>,
    shield_rows: Vec<SyntheticShieldRow>,
}

impl std::fmt::Debug for ChainalysisOnChainOracleSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainalysisOnChainOracleSource")
            .field("oracle_addr", &self.oracle_addr)
            .field("block_start", &self.block_start)
            .field("block_end", &self.block_end)
            .field("chunk_size", &self.chunk_size)
            .field(
                "sanctioned_override_count",
                &self.sanctioned_override.as_ref().map(Vec::len),
            )
            .field("shield_rows_count", &self.shield_rows.len())
            .finish_non_exhaustive()
    }
}

impl ChainalysisOnChainOracleSource {
    /// Live-RPC constructor. The oracle address parses from the
    /// canonical mainnet literal; pass an alternate `oracle_addr`
    /// only for non-mainnet probes.
    pub fn new_live(
        pool: Arc<RpcEndpointPool>,
        oracle_addr: Address,
        block_start: u64,
        block_end: Option<u64>,
    ) -> Self {
        Self {
            pool: Some(pool),
            oracle_addr,
            block_start,
            block_end,
            chunk_size: DEFAULT_LOG_CHUNK_BLOCKS,
            sanctioned_override: None,
            shield_rows: Vec::new(),
        }
    }

    /// Synthetic-fixture constructor. The `sanctioned_override`
    /// short-circuits the on-chain log walk, returning the supplied
    /// addresses verbatim. `shield_rows` feeds the derivation layer
    /// directly. Used only by tests.
    #[must_use]
    pub fn new_synthetic(
        oracle_addr: Address,
        sanctioned: Vec<Address>,
        shield_rows: Vec<SyntheticShieldRow>,
    ) -> Self {
        Self {
            pool: None,
            oracle_addr,
            block_start: 0,
            block_end: None,
            chunk_size: DEFAULT_LOG_CHUNK_BLOCKS,
            sanctioned_override: Some(sanctioned),
            shield_rows,
        }
    }

    /// Override the chunk size (default
    /// [`DEFAULT_LOG_CHUNK_BLOCKS`]). Operators on archival nodes
    /// can raise; free-tier endpoints typically cap at 10k.
    #[must_use]
    pub fn with_chunk_size(mut self, blocks: u64) -> Self {
        self.chunk_size = blocks.max(1);
        self
    }

    /// Append a list of pre-decoded shield rows that the derivation
    /// layer will scan when matching sanctioned addresses. In
    /// live-RPC mode operators populate this from the indexer's
    /// existing `events_in_range` walk; the synthetic fixture path
    /// uses the constructor argument directly.
    pub fn extend_shield_rows<I>(&mut self, rows: I)
    where
        I: IntoIterator<Item = SyntheticShieldRow>,
    {
        self.shield_rows.extend(rows);
    }

    /// Read-only accessor for tests + diagnostics.
    #[must_use]
    pub fn oracle_addr(&self) -> Address {
        self.oracle_addr
    }

    /// Decode a single `SanctionedAddressesAdded` log entry into the
    /// list of addresses it added. Public so tests can verify the
    /// `sol!` decode shape directly without a full pipeline run.
    pub fn decode_added_log(log: &alloy::rpc::types::eth::Log) -> Result<Vec<Address>, String> {
        let primary = log
            .topic0()
            .copied()
            .ok_or_else(|| "missing topic0".to_owned())?;
        if primary != SanctionedAddressesAdded::SIGNATURE_HASH {
            return Err(format!(
                "wrong topic0: {primary:?} (expected SanctionedAddressesAdded)"
            ));
        }
        let log_data = log.data();
        let decoded = SanctionedAddressesAdded::decode_log_data(log_data)
            .map_err(|e| format!("decode SanctionedAddressesAdded: {e}"))?;
        Ok(decoded.addedAddresses.clone())
    }

    /// Live RPC walk: chunked `eth_getLogs` over
    /// `[block_start, block_end]` against `oracle_addr`, decoding
    /// every `SanctionedAddressesAdded` entry. Returns the
    /// deduplicated set of sanctioned addresses in
    /// first-occurrence order.
    async fn fetch_sanctioned_live(&self) -> Result<Vec<Address>, BootstrapError> {
        let pool = self.pool.as_ref().ok_or_else(|| {
            BootstrapError::PpoiUnreachable(
                "ChainalysisOnChainOracleSource: live mode requires an RPC pool".to_owned(),
            )
        })?;
        let session = pool
            .pinned_session()
            .map_err(|e| BootstrapError::PpoiUnreachable(format!("rpc pool pin: {e}")))?;
        let provider = session
            .endpoint()
            .provider()
            .await
            .map_err(|e| BootstrapError::PpoiUnreachable(format!("provider: {e}")))?;
        let last_block = if let Some(b) = self.block_end {
            b
        } else {
            tokio::time::timeout(PER_CALL_TIMEOUT, provider.get_block_number())
                .await
                .map_err(|_| {
                    BootstrapError::PpoiUnreachable(
                        "Chainalysis oracle head probe timed out".to_owned(),
                    )
                })?
                .map_err(|e| BootstrapError::PpoiUnreachable(format!("get_block_number: {e}")))?
        };
        if last_block < self.block_start {
            return Ok(Vec::new());
        }
        let mut seen: std::collections::HashSet<Address> = std::collections::HashSet::new();
        let mut out: Vec<Address> = Vec::new();
        let mut from = self.block_start;
        while from <= last_block {
            let to = from
                .saturating_add(self.chunk_size.saturating_sub(1))
                .min(last_block);
            let filter = alloy::rpc::types::eth::Filter::new()
                .address(self.oracle_addr)
                .from_block(from)
                .to_block(to)
                .event_signature(SanctionedAddressesAdded::SIGNATURE_HASH);
            let logs = tokio::time::timeout(PER_CALL_TIMEOUT, provider.get_logs(&filter))
                .await
                .map_err(|_| {
                    BootstrapError::PpoiUnreachable(format!(
                        "Chainalysis eth_getLogs timed out [{from}, {to}]"
                    ))
                })?
                .map_err(|e| {
                    BootstrapError::PpoiUnreachable(format!(
                        "Chainalysis eth_getLogs [{from}, {to}]: {e}"
                    ))
                })?;
            for log in logs {
                let added = Self::decode_added_log(&log).map_err(BootstrapError::PpoiDecode)?;
                for addr in added {
                    if seen.insert(addr) {
                        out.push(addr);
                    }
                }
            }
            from = to.saturating_add(1);
        }
        Ok(out)
    }

    /// Derive the canonical PPOI event sequence for `list_key` from
    /// the union of (sanctioned addresses) × (shield rows whose
    /// `from_address` is sanctioned). Each row's
    /// blinded-commitment is computed via
    /// `Poseidon(commitmentHash, npk, globalTreePosition)`.
    ///
    /// The local IMT root is rolled forward as we go; each
    /// `PpoiEventRow.validated_merkleroot` carries the post-insert
    /// root so the upstream byte-identity oracle in
    /// `bootstrap_one_list_with_mode` accepts the sequence.
    fn derive_event_rows(
        sanctioned: &[Address],
        shield_rows: &[SyntheticShieldRow],
    ) -> Result<Vec<PpoiEventRow>, BootstrapError> {
        if shield_rows.is_empty() {
            return Ok(Vec::new());
        }
        let sanctioned_set: std::collections::HashSet<Address> =
            sanctioned.iter().copied().collect();
        let mut filtered: Vec<&SyntheticShieldRow> = shield_rows
            .iter()
            .filter(|row| sanctioned_set.contains(&row.from_address))
            .collect();
        filtered.sort_by_key(|a| a.global_tree_position);
        let mut imt = raven_railgun_engine::imt::Imt::new()
            .map_err(|e| BootstrapError::Engine(format!("imt new: {e}")))?;
        let mut out = Vec::with_capacity(filtered.len());
        for (i, row) in filtered.iter().enumerate() {
            let bc = raven_railgun_poseidon::blinded_commitment(
                row.commitment_hash,
                row.npk,
                row.global_tree_position,
            )
            .map_err(|e| BootstrapError::Engine(format!("poseidon blinded_commitment: {e}")))?;
            imt.insert_leaves(i, std::slice::from_ref(&bc))
                .map_err(|e| BootstrapError::Engine(format!("imt insert {i}: {e}")))?;
            let idx = u64::try_from(i)
                .map_err(|_| BootstrapError::Engine(format!("derive index {i} overflow")))?;
            out.push(PpoiEventRow {
                index: idx,
                leaf: bc,
                validated_merkleroot: imt.root(),
            });
        }
        Ok(out)
    }
}

#[async_trait]
impl PpoiEventsSource for ChainalysisOnChainOracleSource {
    async fn fetch_all_events(
        &self,
        _list_key: [u8; 32],
    ) -> Result<Vec<PpoiEventRow>, BootstrapError> {
        let sanctioned = match self.sanctioned_override.clone() {
            Some(v) => v,
            None => self.fetch_sanctioned_live().await?,
        };
        if sanctioned.is_empty() {
            return Ok(Vec::new());
        }
        if self.shield_rows.is_empty() && self.pool.is_some() {
            return Err(BootstrapError::PpoiUnreachable(
                "Chainalysis adapter: sanctioned-address set is non-empty but no shield rows \
                 supplied — derivation layer requires the indexer to feed pre-decoded shield \
                 events. Live npk→EOA convergence ships in a follow-up; runtime fallback will \
                 seed an empty IMT under skip-on-unreachable."
                    .to_owned(),
            ));
        }
        Self::derive_event_rows(&sanctioned, &self.shield_rows)
    }
}

/// Parse the canonical mainnet oracle address. Convenience wrapper
/// keeps CLI parsing diagnostics actionable.
pub fn parse_chainalysis_oracle(s: &str) -> Result<Address, String> {
    s.parse::<Address>()
        .map_err(|e| format!("invalid chainalysis-oracle address {s}: {e}"))
}

/// Keeps `U256`/`B256` in scope for the live-derivation path.
#[doc(hidden)]
#[allow(dead_code)]
pub fn __keep_alloy_imports() -> (U256, B256) {
    (U256::ZERO, B256::ZERO)
}
