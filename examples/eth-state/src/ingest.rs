//! Flat balance ingestion: - dense address->leaf assignment, fixed-width
//! big-endian field normalization, and the demo-local WAL payload.
//!
//! Flat plain-state only: one account = one row = one 32-byte big-endian balance.
//! No trie, no state root, no ancestor churn, no storage-slot table. Forward-read
//! balances are normalized to fixed width before they become rows; raw variable-width
//! reth/revm Compact bytes are NEVER fed to the encoder (a trimmed value shifts every
//! later column and corrupts the decode).

use std::collections::BTreeMap;

use crate::{EthStateError, ENTRY_SIZE};

/// A 20-byte Ethereum account address.
pub type Address = [u8; 20];

/// Dense `address -> u64` leaf assignment (the PIR row key).
///
/// Each address gets a plain dense `u64` on first sight, monotonically from 0,
/// stable and never reused. `shard = flat_index / ENTRIES_PER_SHARD`. This follows
/// the flat single-keyspace SHAPE of EIP-7864 (Unified Binary Tree, draft); it does
/// NOT build a live unified binary tree and uses no per-tree key schedule.
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

    /// Number of assigned addresses (also the next dense index).
    pub fn len(&self) -> u64 {
        self.next
    }

    /// Whether no address has been assigned yet.
    pub fn is_empty(&self) -> bool {
        self.next == 0
    }
}

/// Normalize a big-endian balance (`<= ENTRY_SIZE - 1` bytes) into the fixed record: byte 0 is
/// the [`crate::PRESENT_TAG`], bytes `1..ENTRY_SIZE` the balance big-endian, right-aligned. The
/// tag is set on every record (including a zero balance), so the fan-out distinguishes a present
/// zero from an absent slot. reth/revm store balances leading-zero-trimmed, so a width-normalize
/// is required regardless; a balance wider than `ENTRY_SIZE - 1` is rejected (byte 0 is the tag).
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

/// Demo-local opaque WAL payload (serialized through the generic `Wal`). Defined here,
/// never reusing an application adapter's payload enum.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BalanceWalPayload {
    /// An in-place balance update at a flat leaf index.
    BalanceUpdate {
        /// The dense flat leaf index.
        flat_index: u64,
        /// The fixed 32-byte big-endian balance.
        balance_be: [u8; ENTRY_SIZE],
    },
}
