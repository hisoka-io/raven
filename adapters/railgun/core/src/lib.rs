//! Shared types for the Raven Railgun PIR adapter.
//!
//! These types mirror Railgun's wire shapes (per `shared-models/src/models/`)
//! but are owned by Raven so we don't take a hard TS-package dependency.

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};

/// Generic server-runtime identity and error types, re-exported from `raven-core`
/// so existing `raven_railgun_core::{InstanceId, Epoch, AdapterError}` import
/// sites keep compiling. The definitions live in `raven-core`.
pub use raven_core::{Epoch, InstanceId, ServerError as AdapterError};

/// 32-byte blinded commitment as defined in `engine/src/poi/blinded-commitment.ts`.
///
/// For shield/transact: `Poseidon(commitmentHash, npk, globalTreePosition)`.
/// For unshield: `railgunTxid` formatted to 32 bytes.
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

/// PPOI list identifier (32-byte content hash).
///
/// In production the only active list is OFAC,
/// `efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88`.
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

/// Commitment type per `BlindedCommitmentType` in
/// `shared-models/src/models/proof-of-innocence.ts:104-108`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum BlindedCommitmentType {
    /// On-chain `Shield` event commitment. `npk` is public; `bc =
    /// Poseidon(commitmentHash, npk, globalTreePosition)`.
    Shield,
    /// On-chain `Transact` event commitment. `npk` is encrypted in
    /// the ciphertext; the BC is computed by Railgun off-chain.
    Transact,
    /// On-chain `Unshield` event. The BC is the `railgunTxid` formatted
    /// to 32 bytes (no Poseidon hashing).
    Unshield,
}

/// PPOI status per `POIStatus` in
/// `shared-models/src/models/proof-of-innocence.ts:138-147`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum POIStatus {
    /// PPOI submitted and accepted.
    Valid,
    /// Shield blocked by the list provider (e.g. an OFAC sanction match).
    ShieldBlocked,
    /// PPOI proof submitted but not yet validated.
    ProofSubmitted,
    /// No PPOI association recorded for this BC.
    Missing,
}

/// Merkle authentication path: 16 sibling hashes (Poseidon BN254 field elements,
/// 32 bytes each), the root they hash to, and the leaf-position bitmap.
///
/// Same shape Railgun uses (`shared-models/src/models/proof-of-innocence.ts:28-33`)
/// for both the commitment tree, the TXID tree, and per-list PPOI trees.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Merkle root the path hashes up to.
    pub root: [u8; 32],
    /// Leaf-position bitmap: `bit_i = (leaf_index >> i) & 1`. During
    /// reconstruction, `0` = leaf-side is LEFT, `1` = leaf-side is RIGHT.
    /// Packed into `u16` vs the upstream 32-byte hex string
    /// (`engine/src/merkletree/merkletree.ts:128-160`).
    pub indices: u16,
    /// 16 sibling hashes, leaf-to-root.
    pub elements: [[u8; 32]; 16],
}

/// One leaf of the on-chain commitment tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentLeaf {
    /// Tree index (0-based) within the Railgun proxy's commitment-tree set.
    pub tree_number: u32,
    /// Leaf index within the tree.
    pub leaf_index: u32,
    /// Poseidon-derived commitment hash (leaf value of the IMT).
    pub commitment_hash: [u8; 32],
    /// Encrypted note payload (variable length per V2/V3 encoding).
    pub ciphertext: Vec<u8>,
}

/// Decoded chain event the indexer emits to the engine.
///
/// Mirrors Railgun's event schema (`RailgunLogic.sol:56-77`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RailgunEvent {
    /// `Shield` event: deposits to the Railgun proxy, npk is public.
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
    /// `Transact` event: private transfer; npk is encrypted in `ciphertext`.
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
    /// `Nullified` event: previously-shielded note marked spent.
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
    /// `Unshield` event: withdrawal to a public address.
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

/// Per-`(blindedCommitment, listKey)` association (a single row of T1's table).
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
        // serde rename_all = "PascalCase" matches Railgun's TS enum string format.
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
