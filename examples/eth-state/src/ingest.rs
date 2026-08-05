//! Flat balance ingestion: dense address -> leaf assignment, fixed-width big-endian
//! normalization, and the WAL payload.
//!
//! Balances MUST be width-normalized before they become rows. Raw variable-width reth/revm
//! Compact bytes fed to the encoder would shift every later column and corrupt the decode.

use std::collections::BTreeMap;

use crate::{EthStateError, ENTRY_SIZE};

/// A 20-byte Ethereum account address.
pub type Address = [u8; 20];

/// Dense `address -> u64` leaf assignment (the PIR row key). Indices are handed out
/// monotonically from 0 and are never reused.
#[derive(Debug, Default)]
pub struct FlatIndex {
    map: BTreeMap<Address, u64>,
    next: u64,
}

impl FlatIndex {
    /// A fresh, empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// The leaf for `addr`, assigning the next dense index on first sight.
    pub fn assign(&mut self, addr: Address) -> u64 {
        if let Some(&leaf) = self.map.get(&addr) {
            return leaf;
        }
        let leaf = self.next;
        self.map.insert(addr, leaf);
        self.next += 1;
        leaf
    }

    /// The leaf for `addr` if already assigned.
    pub fn get(&self, addr: &Address) -> Option<u64> {
        self.map.get(addr).copied()
    }

    /// Number of assigned addresses, which is also the next dense index.
    pub fn len(&self) -> u64 {
        self.next
    }

    /// Whether no address has been assigned yet.
    pub fn is_empty(&self) -> bool {
        self.next == 0
    }
}

/// Widen a leading-zero-trimmed big-endian balance into the fixed record: [`crate::PRESENT_TAG`]
/// at byte 0, the balance right-aligned after it. The tag is set even for a zero balance.
///
/// ```
/// let r = eth_state::ingest::normalize_balance_be(&[5]).expect("fits");
/// assert_eq!(r[0], eth_state::PRESENT_TAG);
/// assert_eq!(r[31], 5);
/// assert_eq!(r[1..31], [0u8; 30]);
/// ```
pub fn normalize_balance_be(be: &[u8]) -> Result<[u8; ENTRY_SIZE], EthStateError> {
    if be.len() >= ENTRY_SIZE {
        return Err(EthStateError::RecordTooLarge { got: be.len() });
    }
    let mut rec = [0u8; ENTRY_SIZE];
    rec[0] = crate::PRESENT_TAG;
    rec[ENTRY_SIZE - be.len()..].copy_from_slice(be);
    Ok(rec)
}

/// Opaque WAL payload, serialized through the generic `Wal`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BalanceWalPayload {
    /// An in-place balance update at a flat leaf index.
    BalanceUpdate {
        /// Dense flat leaf index.
        flat_index: u64,
        /// Fixed-width big-endian balance.
        balance_be: [u8; ENTRY_SIZE],
    },
}
