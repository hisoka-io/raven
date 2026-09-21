use serde::{Deserialize, Serialize};

/// Upstream event kind retained with each PPOI list leaf.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PpoiEventType {
    /// Shield event.
    Shield,
    /// Transact event.
    Transact,
    /// Unshield event.
    Unshield,
    /// Legacy transact event.
    LegacyTransact,
}

/// Upstream metadata retained in logical snapshots for a PPOI list leaf.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PpoiEventMetadata {
    /// Upstream event kind.
    pub event_type: PpoiEventType,
    /// Upstream 64-byte ed25519 signature. Carried, never verified.
    pub signature: Vec<u8>,
    /// Upstream root after appending the leaf.
    pub validated_merkleroot: [u8; 32],
}

/// Application WAL payload variants for this adapter.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WalEntryPayload {
    /// Append a leaf to a commitment-tree shard.
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
        /// Encoded status byte.
        status: u8,
    },
    /// New per-list leaf; drives IMT growth and the
    /// `(blinded_commitment -> list_index)` oracle.
    PpoiListLeafAdded {
        /// 32-byte list key.
        list_key: [u8; 32],
        /// Upstream-issued contiguous index within the list.
        list_index: u32,
        /// 32-byte blinded commitment.
        blinded_commitment: [u8; 32],
        /// Initial status byte.
        status: u8,
        /// Upstream event kind.
        event_type: PpoiEventType,
        /// Upstream 64-byte ed25519 signature. Carried, never verified.
        signature: Vec<u8>,
        /// Upstream root after appending this leaf.
        validated_merkleroot: [u8; 32],
    },
    /// Reorg fence; entries with a `marker` above `height` are truncated.
    Reorg {
        /// Chain height at the fork point.
        height: u64,
    },
    /// No-op WAL marker emitted at each snapshot.
    Heartbeat {
        /// Unix milliseconds at emission.
        wallclock_unix_ms: u64,
    },
}
