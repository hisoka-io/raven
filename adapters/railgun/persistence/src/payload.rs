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
    /// Upstream root after appending the leaf.
    pub validated_merkleroot: [u8; 32],
}

/// Application WAL payload variants for this adapter.
///
/// Declaration order is the bincode tag. `Heartbeat` precedes `Reorg` so that a frame of the
/// previous layout, which had a status variant at tag 1, never decodes as a different entry: its
/// append and reorg keep their tags and shapes, and every other frame is refused as short, as
/// surplus or as an unknown tag.
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
    /// New per-list leaf; drives IMT growth and the
    /// `(blinded_commitment -> list_index)` oracle.
    PpoiListLeafAdded {
        /// 32-byte list key.
        list_key: [u8; 32],
        /// Upstream-issued contiguous index within the list.
        list_index: u32,
        /// 32-byte blinded commitment.
        blinded_commitment: [u8; 32],
        /// The mirror's handoff only. Not written to the WAL and read by nothing in this crate
        /// or the engine: a filled row's status is derived from the row's presence. A replayed
        /// entry carries 0.
        #[serde(skip)]
        status: u8,
        /// Upstream event kind.
        event_type: PpoiEventType,
        /// The mirror's handoff only. Not written to the WAL: storage keeps no signature. A
        /// replayed entry carries an empty vector.
        #[serde(skip)]
        signature: Vec<u8>,
        /// Upstream root after appending this leaf.
        validated_merkleroot: [u8; 32],
    },
    /// No-op WAL marker emitted at each snapshot.
    Heartbeat {
        /// Unix milliseconds at emission.
        wallclock_unix_ms: u64,
    },
    /// Reorg fence; entries with a `marker` above `height` are truncated.
    Reorg {
        /// Chain height at the fork point.
        height: u64,
    },
}
