//! Poseidon-BN254 helpers matching the upstream TS engine's shapes. Every input
//! and output is a 32-byte big-endian Fr element (circomlibjs Buffer
//! convention); `tests/circomlibjs_parity.rs` pins byte equality.

#![deny(missing_docs)]
#![allow(clippy::items_after_statements)]

use std::cell::RefCell;

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInt, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};

/// Errors surfaced by Poseidon helpers.
#[derive(thiserror::Error, Debug)]
pub enum PoseidonError {
    /// Input arity outside the supported 1..=12 range.
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
    let mut limbs = [0u64; 4];
    for (limb, word) in limbs.iter_mut().rev().zip(bytes.as_chunks::<8>().0) {
        *limb = u64::from_be_bytes(*word);
    }
    // `from_bigint` refuses anything at or above the modulus, which is the canonical check.
    Fr::from_bigint(BigInt::new(limbs))
        .ok_or_else(|| PoseidonError::InvalidFr(format!("0x{}", hex_lower(bytes))))
}

fn fr_to_be_bytes(fr: Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (word, limb) in out
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip(fr.into_bigint().0.iter().rev())
    {
        *word = limb.to_be_bytes();
    }
    out
}

/// Highest arity light-poseidon's circom parameter set covers.
const MAX_ARITY: usize = 12;

thread_local! {
    // `new_circom` rebuilds every round constant, which costs about a fifth of a 2-to-1 hash.
    // A hasher clears its sponge at the end of each `hash`, so one per arity is reusable.
    static HASHERS: RefCell<[Option<Poseidon<Fr>>; MAX_ARITY]> =
        const { RefCell::new([const { None }; MAX_ARITY]) };
}

fn new_hasher(arity: usize) -> Result<Poseidon<Fr>> {
    Poseidon::<Fr>::new_circom(arity)
        .map_err(|e| PoseidonError::LightPoseidon(format!("new_circom: {e:?}")))
}

/// Circomlibjs-compatible Poseidon-BN254 over `inputs.len()` field elements (arity 1..=12).
pub fn hash_n(inputs: &[[u8; 32]]) -> Result<[u8; 32]> {
    let arity = inputs.len();
    if arity == 0 || arity > MAX_ARITY {
        new_hasher(arity)?;
        return Err(PoseidonError::LightPoseidon(format!(
            "unsupported arity {arity}"
        )));
    }
    let mut frs = [Fr::ZERO; MAX_ARITY];
    for (slot, buf) in frs.iter_mut().zip(inputs) {
        *slot = fr_from_be_bytes(buf)?;
    }
    let frs = frs.get(..arity).unwrap_or_default();

    // Taken out of the slot for the duration of the hash: a hasher that errors or unwinds
    // mid-sponge is dropped rather than returned, so the next call rebuilds it clean.
    let cached = HASHERS
        .try_with(|cell| cell.borrow_mut().get_mut(arity - 1).and_then(Option::take))
        .ok()
        .flatten();
    let mut hasher = match cached {
        Some(hasher) => hasher,
        None => new_hasher(arity)?,
    };
    let hash = hasher
        .hash(frs)
        .map_err(|e| PoseidonError::LightPoseidon(format!("hash: {e:?}")))?;
    let _ = HASHERS.try_with(|cell| {
        if let Some(slot) = cell.borrow_mut().get_mut(arity - 1) {
            *slot = Some(hasher);
        }
    });
    Ok(fr_to_be_bytes(hash))
}

/// `Poseidon(npk, tokenHash, valueAfterFee)` per upstream `src/note/shield-note.ts`.
pub fn shield_commitment_hash(
    npk: [u8; 32],
    token_hash: [u8; 32],
    value_after_fee: [u8; 32],
) -> Result<[u8; 32]> {
    hash_n(&[npk, token_hash, value_after_fee])
}

/// `Poseidon(commitmentHash, npk, globalTreePosition)` per upstream `src/note/note-util.ts`.
pub fn blinded_commitment(
    commitment_hash: [u8; 32],
    npk: [u8; 32],
    global_tree_position: [u8; 32],
) -> Result<[u8; 32]> {
    hash_n(&[commitment_hash, npk, global_tree_position])
}

/// `Poseidon(left, right)` for the binary IMT.
pub fn merkle_node(left: [u8; 32], right: [u8; 32]) -> Result<[u8; 32]> {
    hash_n(&[left, right])
}

/// `keccak256("Railgun") mod SNARK_PRIME`: the IMT leaf-level zero value.
#[must_use]
pub fn railgun_merkle_zero_value() -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut hasher = Keccak::v256();
    hasher.update(b"Railgun");
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);

    let fr = Fr::from_be_bytes_mod_order(&digest);
    fr_to_be_bytes(fr)
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

    let fr = Fr::from_be_bytes_mod_order(&digest);
    fr_to_be_bytes(fr)
}

/// `TokenType` discriminant per upstream `src/models/formatted-types.ts`.
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
    /// Decode a `uint8 tokenType`; `None` when out of range.
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
