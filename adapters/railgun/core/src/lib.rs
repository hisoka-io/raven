//! Shared adapter types. Mirror the upstream wire shapes in
//! `shared-models/src/models/` without depending on the TS package.

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};

pub mod batch_ladder;

/// Server-runtime identity and error types, re-exported from `raven-core`.
pub use raven_core::{Epoch, InstanceId, ServerError as AdapterError};

/// Blinded commitment per upstream `src/poi/blinded-commitment.ts`:
/// `Poseidon(commitmentHash, npk, globalTreePosition)` for shield/transact,
/// the txid as 32 bytes for unshield.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlindedCommitment(
    /// Raw bytes.
    pub [u8; 32],
);

impl BlindedCommitment {
    /// Construct from raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Underlying bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 32-byte list content hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ListKey(
    /// Raw bytes.
    pub [u8; 32],
);

impl ListKey {
    /// Construct from raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Underlying bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Commitment type per upstream `BlindedCommitmentType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum BlindedCommitmentType {
    /// `Shield` event commitment; `npk` is public.
    Shield,
    /// `Transact` event commitment; `npk` is encrypted, so the BC is off-chain.
    Transact,
    /// `Unshield` event; the BC is the txid as 32 bytes, unhashed.
    Unshield,
}

/// Status per upstream `POIStatus`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum POIStatus {
    /// PPOI submitted and accepted.
    Valid,
    /// Shield blocked by the list provider.
    ShieldBlocked,
    /// PPOI proof submitted but not yet validated.
    ProofSubmitted,
    /// No PPOI association recorded for this BC.
    Missing,
}

/// Merkle authentication path: 16 Poseidon BN254 siblings, their root, and the
/// leaf-position bitmap. Shared by every upstream tree shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Merkle root the path hashes up to.
    pub root: [u8; 32],
    /// `bit_i = (leaf_index >> i) & 1`; 0 puts the leaf side left, 1 right.
    /// Packed to `u16` where upstream uses a 32-byte hex string.
    pub indices: u16,
    /// 16 sibling hashes, leaf-to-root.
    pub elements: [[u8; 32]; 16],
}

/// One leaf of the on-chain commitment tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentLeaf {
    /// 0-based tree index within the commitment-tree set.
    pub tree_number: u32,
    /// Leaf index within the tree.
    pub leaf_index: u32,
    /// Poseidon-derived commitment hash (leaf value of the IMT).
    pub commitment_hash: [u8; 32],
    /// Encrypted payload; length varies by encoding version.
    pub ciphertext: Vec<u8>,
}

/// Decoded chain event, mirroring the upstream `RailgunLogic.sol` schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RailgunEvent {
    /// `Shield`: deposit, `npk` public.
    Shield {
        /// Block height.
        block_number: u64,
        /// Transaction hash.
        tx_hash: [u8; 32],
        /// Receiving tree.
        tree_number: u32,
        /// First leaf index (`leaves[k].leaf_index = start_position + k`).
        start_position: u32,
        /// New commitment leaves.
        leaves: Vec<CommitmentLeaf>,
    },
    /// `Transact`: private transfer, `npk` encrypted in `ciphertext`.
    Transact {
        /// Block height.
        block_number: u64,
        /// Transaction hash.
        tx_hash: [u8; 32],
        /// Receiving tree.
        tree_number: u32,
        /// First leaf index.
        start_position: u32,
        /// New commitment leaves.
        leaves: Vec<CommitmentLeaf>,
    },
    /// `Nullified`: a prior commitment marked spent.
    Nullified {
        /// Block height.
        block_number: u64,
        /// Transaction hash.
        tx_hash: [u8; 32],
        /// Tree whose nullifier set the entries belong to.
        tree_number: u32,
        /// Nullifier hashes.
        nullifiers: Vec<[u8; 32]>,
    },
    /// `Unshield`: withdrawal to a public address.
    Unshield {
        /// Block height.
        block_number: u64,
        /// Transaction hash.
        tx_hash: [u8; 32],
        /// Recipient address.
        to: [u8; 20],
        /// Token data hash (`Poseidon(tokenAddress, tokenSubID, tokenType)`).
        token: [u8; 32],
        /// Withdrawn amount (token-native units).
        amount: u128,
        /// Fee paid to the proxy.
        fee: u128,
    },
}

impl RailgunEvent {
    /// Commitment tree this event belongs to, or `None` for `Unshield`, which carries no
    /// tree because it removes value rather than appending a leaf.
    ///
    /// Used by the single-instance ingest bridge to scope a store to one tree. That scope
    /// is load-bearing: `per-leaf-bc` indexes rows by `leaf_index` alone, so two trees in
    /// one store would write the same row.
    #[must_use]
    pub const fn tree_number(&self) -> Option<u32> {
        match self {
            Self::Shield { tree_number, .. }
            | Self::Transact { tree_number, .. }
            | Self::Nullified { tree_number, .. } => Some(*tree_number),
            Self::Unshield { .. } => None,
        }
    }
}

/// One `(blindedCommitment, listKey)` association row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoiStatusRow {
    /// The BC keyed against the list.
    pub blinded_commitment: BlindedCommitment,
    /// Status assigned by the list provider.
    pub status: POIStatus,
}

/// Adapter-level result alias.
pub type Result<T, E = AdapterError> = core::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blinded_commitment_round_trip_serde() {
        let bc = BlindedCommitment::from_bytes([7u8; 32]);
        let bytes = bincode::serialize(&bc).expect("serialize");
        let back: BlindedCommitment = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(bc, back);
    }

    #[test]
    fn poi_status_serde_pascal_case() {
        // PascalCase matches the upstream TS enum string format.
        let s = serde_json::to_string(&POIStatus::Valid).expect("serialize");
        assert_eq!(s, "\"Valid\"");
        let s = serde_json::to_string(&POIStatus::ShieldBlocked).expect("serialize");
        assert_eq!(s, "\"ShieldBlocked\"");
    }

    #[test]
    fn merkle_proof_round_trip_serde() {
        let proof = MerkleProof {
            root: [1u8; 32],
            indices: 0b1010_1010_0101_0101,
            elements: [[2u8; 32]; 16],
        };
        let bytes = bincode::serialize(&proof).expect("serialize");
        let back: MerkleProof = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(proof, back);
    }
}
