//! Poseidon-BN254 helpers matching the exact shapes Railgun TS engine uses.
//!
//! All inputs/outputs are 32-byte big-endian BN254 Fr field elements
//! (circomlibjs Buffer convention). See `tests/circomlibjs_parity.rs`
//! for byte-equality checks against circomlibjs reference vectors.

#![deny(missing_docs)]
#![allow(clippy::items_after_statements)]

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};

/// Errors surfaced by Poseidon helpers.
#[derive(thiserror::Error, Debug)]
pub enum PoseidonError {
    /// `light-poseidon` rejected the input arity (supported range: 1..=12).
    #[error("light-poseidon: {0}")]
    LightPoseidon(String),
    /// Input bytes are >= BN254 field modulus.
    #[error("input bytes don't decode to a valid BN254 Fr: {0}")]
    InvalidFr(String),
}

/// Result alias for this crate.
pub type Result<T, E = PoseidonError> = core::result::Result<T, E>;

/// Decode a 32-byte big-endian buffer into a BN254 Fr, rejecting non-canonical inputs (>= modulus).
fn fr_from_be_bytes(bytes: &[u8; 32]) -> Result<Fr> {
    // `from_be_bytes_mod_order` always succeeds; re-encode and compare to enforce canonical input.
    let candidate = Fr::from_be_bytes_mod_order(bytes);
    let canonical = candidate.into_bigint().to_bytes_be();
    if canonical.as_slice() != bytes.as_slice() {
        return Err(PoseidonError::InvalidFr(format!("0x{}", hex_lower(bytes))));
    }
    Ok(candidate)
}

fn fr_to_be_bytes(fr: Fr) -> [u8; 32] {
    let bytes = fr.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let copy_len = bytes.len().min(32);
    if let Some(dst) = out.get_mut(32 - copy_len..) {
        if let Some(src) = bytes.get(..copy_len) {
            dst.copy_from_slice(src);
        }
    }
    out
}

/// Circomlibjs-compatible Poseidon-BN254 over `inputs.len()` field elements (arity 1..=12).
pub fn hash_n(inputs: &[[u8; 32]]) -> Result<[u8; 32]> {
    let mut hasher = Poseidon::<Fr>::new_circom(inputs.len())
        .map_err(|e| PoseidonError::LightPoseidon(format!("new_circom: {e:?}")))?;
    let mut frs: Vec<Fr> = Vec::with_capacity(inputs.len());
    for buf in inputs {
        frs.push(fr_from_be_bytes(buf)?);
    }
    let hash = hasher
        .hash(&frs)
        .map_err(|e| PoseidonError::LightPoseidon(format!("hash: {e:?}")))?;
    Ok(fr_to_be_bytes(hash))
}

/// `Poseidon(npk, tokenHash, valueAfterFee)` per `engine/src/note/shield-note.ts:49-54`.
pub fn shield_commitment_hash(
    npk: [u8; 32],
    token_hash: [u8; 32],
    value_after_fee: [u8; 32],
) -> Result<[u8; 32]> {
    hash_n(&[npk, token_hash, value_after_fee])
}

/// `Poseidon(commitmentHash, npk, globalTreePosition)` per `engine/src/note/note-utils.ts`.
pub fn blinded_commitment(
    commitment_hash: [u8; 32],
    npk: [u8; 32],
    global_tree_position: [u8; 32],
) -> Result<[u8; 32]> {
    hash_n(&[commitment_hash, npk, global_tree_position])
}

/// `Poseidon(left, right)` for the binary IMT used in PIR path-table and reorg detection.
pub fn merkle_node(left: [u8; 32], right: [u8; 32]) -> Result<[u8; 32]> {
    hash_n(&[left, right])
}

/// `keccak256("Railgun") mod SNARK_PRIME` — leaf-level zero value of every Railgun IMT.
#[must_use]
pub fn railgun_merkle_zero_value() -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut hasher = Keccak::v256();
    hasher.update(b"Railgun");
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);

    use ark_ff::{BigInteger, PrimeField};
    let fr = Fr::from_be_bytes_mod_order(&digest);
    let bytes = fr.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let copy_len = bytes.len().min(32);
    if let Some(dst) = out.get_mut(32 - copy_len..) {
        if let Some(src) = bytes.get(..copy_len) {
            dst.copy_from_slice(src);
        }
    }
    out
}

/// ERC-20 `tokenHash`: the 20-byte address left-zero-padded to 32 bytes (no hash).
#[must_use]
pub fn token_data_hash_erc20(token_address: [u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Some(dst) = out.get_mut(12..) {
        dst.copy_from_slice(&token_address);
    }
    out
}

/// NFT `tokenHash`: `keccak256(uint256(type) || uint256(addr) || uint256(subid)) mod SNARK_PRIME`.
#[must_use]
pub fn token_data_hash_nft(
    token_type: u8,
    token_address: [u8; 20],
    token_sub_id: [u8; 32],
) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut buf = [0u8; 96];
    if let Some(byte) = buf.get_mut(31) {
        *byte = token_type;
    }
    if let Some(dst) = buf.get_mut(32 + 12..32 + 32) {
        dst.copy_from_slice(&token_address);
    }
    if let Some(dst) = buf.get_mut(64..96) {
        dst.copy_from_slice(&token_sub_id);
    }

    let mut hasher = Keccak::v256();
    hasher.update(&buf);
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);

    use ark_ff::{BigInteger, PrimeField};
    let fr = ark_bn254::Fr::from_be_bytes_mod_order(&digest);
    let bytes = fr.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let copy_len = bytes.len().min(32);
    if let Some(dst) = out.get_mut(32 - copy_len..) {
        if let Some(src) = bytes.get(..copy_len) {
            dst.copy_from_slice(src);
        }
    }
    out
}

/// Railgun `TokenType` discriminant (`engine/src/models/formatted-types.ts:43-47`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TokenType {
    /// ERC-20 fungible token.
    Erc20 = 0,
    /// ERC-721 non-fungible token.
    Erc721 = 1,
    /// ERC-1155 semi-fungible token.
    Erc1155 = 2,
}

impl TokenType {
    /// Decode a `uint8 tokenType` from the chain; out-of-range returns `None`.
    #[must_use]
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Erc20),
            1 => Some(Self::Erc721),
            2 => Some(Self::Erc1155),
            _ => None,
        }
    }
}

/// Dispatch to [`token_data_hash_erc20`] or [`token_data_hash_nft`] based on `token_type`.
#[must_use]
pub fn token_data_hash(
    token_type: TokenType,
    token_address: [u8; 20],
    token_sub_id: [u8; 32],
) -> [u8; 32] {
    match token_type {
        TokenType::Erc20 => token_data_hash_erc20(token_address),
        TokenType::Erc721 | TokenType::Erc1155 => {
            token_data_hash_nft(token_type as u8, token_address, token_sub_id)
        }
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in bytes {
        let hi = HEX.get(((b >> 4) & 0x0f) as usize).copied().unwrap_or(b'0');
        let lo = HEX.get((b & 0x0f) as usize).copied().unwrap_or(b'0');
        s.push(hi as char);
        s.push(lo as char);
    }
    s
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn fr_from_u64(n: u64) -> [u8; 32] {
        let mut buf = [0u8; 32];
        let bytes = n.to_be_bytes();
        if let Some(dst) = buf.get_mut(24..) {
            dst.copy_from_slice(&bytes);
        }
        buf
    }

    #[test]
    fn merkle_node_helper_matches_arity_2_hash_n() {
        let l = fr_from_u64(7);
        let r = fr_from_u64(11);
        let direct = hash_n(&[l, r]).expect("hash_n");
        let via = merkle_node(l, r).expect("merkle_node");
        assert_eq!(direct, via);
    }

    #[test]
    fn shield_commitment_helper_matches_arity_3_hash_n() {
        let npk = fr_from_u64(0xdead);
        let token = fr_from_u64(0xbeef);
        let value = fr_from_u64(1_000_000);
        let direct = hash_n(&[npk, token, value]).expect("hash_n");
        let via = shield_commitment_hash(npk, token, value).expect("shield");
        assert_eq!(direct, via);
    }
}
