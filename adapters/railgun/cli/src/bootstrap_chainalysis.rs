//! [`PpoiEventsSource`] derived from the on-chain Chainalysis sanctions oracle.
//!
//! Sanctioned addresses come from `SanctionedAddressesAdded` logs; each matching
//! shield row becomes `BlindedCommitment = Poseidon(commitmentHash, npk,
//! globalTreePosition)` per the upstream engine's `src/poi/blinded-commitment.ts`.
//! Every input is on-chain, so the derivation needs no wallet metadata.

use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, B256, U256};
use alloy::sol;
use alloy::sol_types::SolEvent;
use async_trait::async_trait;

use crate::bootstrap_subsquid::{BootstrapError, PpoiEventRow, PpoiEventsSource};
use raven_railgun_indexer::rpc_pool::RpcEndpointPool;

sol! {
    #[allow(missing_docs)]
    event SanctionedAddressesAdded(address[] addedAddresses);
}

/// Mainnet sanctions oracle; matches upstream
/// `private-proof-of-innocence/packages/node/src/local-list-provider.ts`.
pub const CHAINALYSIS_ORACLE_MAINNET: &str = "0x40C57923924B5c5c5455c48D93317139ADDaC8fb";

/// Oracle deployment block; earlier ranges return no logs.
pub const CHAINALYSIS_ORACLE_FIRST_BLOCK: u64 = 14_356_508;

/// `eth_getLogs` chunk span, under the 10k free-tier cap and the per-call timeout.
pub const DEFAULT_LOG_CHUNK_BLOCKS: u64 = 5_000;

/// Per-call RPC timeout.
const PER_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Pre-decoded shield row consumed by the derivation layer.
#[derive(Debug, Clone)]
pub struct SyntheticShieldRow {
    /// Matched byte-equal against the sanctioned set.
    pub from_address: Address,
    /// `Poseidon(npk, tokenHash, valueAfterFee)`.
    pub commitment_hash: [u8; 32],
    pub npk: [u8; 32],
    /// `tree_number * 65_536 + leaf_index`, big-endian in a 32-byte field element.
    pub global_tree_position: [u8; 32],
}

/// Config for [`ChainalysisOnChainOracleSource`].
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
    /// Live-RPC constructor.
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

    /// Test constructor: `sanctioned_override` short-circuits the log walk.
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

    /// Override [`DEFAULT_LOG_CHUNK_BLOCKS`].
    #[must_use]
    pub fn with_chunk_size(mut self, blocks: u64) -> Self {
        self.chunk_size = blocks.max(1);
        self
    }

    /// Append shield rows for the derivation layer to scan.
    pub fn extend_shield_rows<I>(&mut self, rows: I)
    where
        I: IntoIterator<Item = SyntheticShieldRow>,
    {
        self.shield_rows.extend(rows);
    }

    #[must_use]
    pub fn oracle_addr(&self) -> Address {
        self.oracle_addr
    }

    /// Decode one `SanctionedAddressesAdded` entry into the addresses it added.
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

    /// Chunked `eth_getLogs` walk; returns sanctioned addresses deduplicated in
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

    /// PPOI event sequence for `list_key` over shield rows whose `from_address`
    /// is sanctioned. Each row's `validated_merkleroot` is the POST-insert root.
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
                 supplied. The derivation layer requires the indexer to feed pre-decoded \
                 shield events; without them, use skip-on-unreachable to seed an empty IMT."
                    .to_owned(),
            ));
        }
        Self::derive_event_rows(&sanctioned, &self.shield_rows)
    }
}

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
