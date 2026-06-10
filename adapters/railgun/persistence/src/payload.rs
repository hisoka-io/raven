//! Application WAL payload variants persisted by this adapter.

use serde::{Deserialize, Serialize};

/// Application WAL payload variants for this adapter.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WalEntryPayload {
    /// Append a leaf to a Railgun commitment-tree shard.
    AppendLeaf {
        /// Tree index (`0..=tree_count-1`).
        tree_number: u32,
        /// Leaf index within the tree.
        leaf_index: u32,
        /// 32-byte Poseidon BN254 commitment hash.
        commitment: [u8; 32],
    },
    /// Add / update a PPOI status row.
    PpoiStatus {
        /// 32-byte list key.
        list_key: [u8; 32],
        /// 32-byte blinded commitment.
        blinded_commitment: [u8; 32],
        /// Status byte (`Valid` / `ShieldBlocked` / `ProofSubmitted` / `Missing`).
        status: u8,
    },
    /// New leaf appended to a per-list PPOI Merkle tree.
    /// Drives per-list IMT growth and the `(blinded_commitment -> list_index)` oracle.
    PpoiListLeafAdded {
        /// 32-byte list key.
        list_key: [u8; 32],
        /// Upstream-issued contiguous index within the list.
        list_index: u32,
        /// 32-byte blinded commitment.
        blinded_commitment: [u8; 32],
        /// Initial status byte.
        status: u8,
    },
    /// Reorg marker: the engine truncates WAL entries whose `marker` exceeds `height`.
    Reorg {
        /// Chain height at the fork point.
        height: u64,
    },
    /// Heartbeat (no-op) emitted at each snapshot to mark the WAL.
    Heartbeat {
        /// Unix milliseconds at emission.
        wallclock_unix_ms: u64,
    },
}
