//! Poseidon2 over the BN254 scalar field, byte-identical to Aztec's `poseidon2Hash`.
//!
//! This is the hash Howl's discovery layer commits to. Its generator is a thin wrapper over
//! `poseidon2Hash` from `@aztec/foundation/crypto`, so the parameterisation to match is
//! Aztec's, not a Howl-local one.
//!
//! Not to be confused with `raven-railgun-poseidon`, which wraps `light-poseidon` and is
//! Poseidon-BN254: a different hash for a different protocol's parity.
//!
//! Every constant and both linear layers are transcribed from a cited implementation and
//! pinned against Barretenberg's own permutation by the vectors in `tests/`. Nothing here was
//! derived from memory, because the canonical constants live in a WASM blob and a compiler
//! intrinsic and cannot be read from source.

#![deny(missing_docs)]

mod constants;

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};

/// Width of the permutation state.
pub const STATE_WIDTH: usize = 4;

/// Sponge rate. The capacity occupies the remaining lane, index [`STATE_WIDTH`] - 1.
pub const RATE: usize = 3;

const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 56;

/// Errors surfaced when decoding field elements from bytes.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Poseidon2Error {
    /// Input was not a whole number of 32-byte big-endian field elements.
    #[error("input is {len} bytes, which is not a multiple of 32")]
    NotFieldAligned {
        /// Length that was supplied.
        len: usize,
    },
    /// A 32-byte chunk was not a canonical BN254 scalar.
    #[error("element {index} is not below the BN254 scalar modulus")]
    NotCanonical {
        /// Position of the offending element.
        index: usize,
    },
}

fn constant(hex: &str) -> Fr {
    // The table is generated, never hand-edited, and `tests/kat_parity.rs` fails if any entry
    // is wrong. A malformed entry is a build-time defect, not a runtime input.
    let trimmed = hex.strip_prefix("0x").unwrap_or(hex);
    // Right-aligned: a value written with fewer than 64 digits is still decoded at its true
    // magnitude. Reading left-aligned shifts such a constant by a nibble per missing digit and
    // the permutation stays well-formed while producing the wrong hash.
    let digits = trimmed.as_bytes();
    let mut bytes = [0u8; 32];
    for (offset, byte) in bytes.iter_mut().rev().enumerate() {
        let nibble = |back: usize| {
            digits
                .len()
                .checked_sub(back)
                .and_then(|i| digits.get(i))
                .copied()
                .unwrap_or(b'0')
        };
        *byte = (hex_val(nibble(offset * 2 + 2)) << 4) | hex_val(nibble(offset * 2 + 1));
    }
    Fr::from_be_bytes_mod_order(&bytes)
}

const fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

fn round_constants() -> Vec<Fr> {
    constants::ROUND_CONSTANTS
        .iter()
        .copied()
        .map(constant)
        .collect()
}

fn internal_diagonal() -> [Fr; STATE_WIDTH] {
    let mut out = [Fr::from(0u64); STATE_WIDTH];
    for (slot, hex) in out.iter_mut().zip(constants::INTERNAL_DIAGONAL) {
        *slot = constant(hex);
    }
    out
}

fn sbox(x: Fr) -> Fr {
    let x2 = x * x;
    x2 * x2 * x
}

/// The external MDS layer for t = 4, in the association the reference implementation uses.
fn external_layer(s: &mut [Fr; STATE_WIDTH]) {
    let t0 = s[0] + s[1];
    let t1 = s[2] + s[3];
    let t2 = s[1].double() + t1;
    let t3 = s[3].double() + t0;
    let four = Fr::from(4u64);
    let t4 = four * t1 + t3;
    let t5 = four * t0 + t2;
    *s = [t3 + t5, t5, t2 + t4, t4];
}

/// Run the Poseidon2 permutation on a full state.
///
/// # Examples
/// ```
/// use howl_poseidon2::{permutation, STATE_WIDTH};
/// use ark_bn254::Fr;
/// let out = permutation([Fr::from(0u64); STATE_WIDTH]);
/// assert_ne!(out[0], Fr::from(0u64));
/// ```
#[must_use]
pub fn permutation(state: [Fr; STATE_WIDTH]) -> [Fr; STATE_WIDTH] {
    let rc = round_constants();
    let diag = internal_diagonal();
    let mut s = state;
    external_layer(&mut s);

    let mut k = 0usize;
    for _ in 0..FULL_ROUNDS / 2 {
        full_round(&mut s, &rc, &mut k);
    }
    for _ in 0..PARTIAL_ROUNDS {
        s[0] += rc.get(k).copied().unwrap_or_else(Fr::default);
        k += 1;
        s[0] = sbox(s[0]);
        let sum: Fr = s.iter().copied().sum();
        for (lane, d) in s.iter_mut().zip(diag) {
            *lane = *lane * d + sum;
        }
    }
    for _ in 0..FULL_ROUNDS / 2 {
        full_round(&mut s, &rc, &mut k);
    }
    s
}

fn full_round(s: &mut [Fr; STATE_WIDTH], rc: &[Fr], k: &mut usize) {
    for (i, lane) in s.iter_mut().enumerate() {
        *lane += rc.get(*k + i).copied().unwrap_or_else(Fr::default);
    }
    *k += STATE_WIDTH;
    for lane in s.iter_mut() {
        *lane = sbox(*lane);
    }
    external_layer(s);
}

/// Hash a sequence of field elements.
///
/// The capacity lane is seeded with `len * 2^64`, so two inputs differing only in length
/// cannot collide. An empty input is legal and hashes the all-zero state.
///
/// # Examples
/// ```
/// use howl_poseidon2::hash;
/// use ark_bn254::Fr;
/// let digest = hash(&[Fr::from(1u64), Fr::from(2u64)]);
/// assert_ne!(digest, hash(&[Fr::from(2u64), Fr::from(1u64)]));
/// ```
#[must_use]
pub fn hash(inputs: &[Fr]) -> Fr {
    let iv = Fr::from(inputs.len() as u64) * Fr::from(1u128 << 64);
    let mut s = [Fr::from(0u64), Fr::from(0u64), Fr::from(0u64), iv];
    let mut cache: Vec<Fr> = Vec::with_capacity(RATE);
    for input in inputs {
        if cache.len() == RATE {
            duplex(&mut s, &mut cache);
        }
        cache.push(*input);
    }
    duplex(&mut s, &mut cache);
    s[0]
}

fn duplex(s: &mut [Fr; STATE_WIDTH], cache: &mut Vec<Fr>) {
    for (lane, held) in s.iter_mut().zip(cache.iter()) {
        *lane += *held;
    }
    cache.clear();
    *s = permutation(*s);
}

/// Hash 32-byte big-endian elements, the encoding the TypeScript and Solidity sides exchange.
///
/// # Errors
/// [`Poseidon2Error::NotFieldAligned`] when the length is not a multiple of 32, and
/// [`Poseidon2Error::NotCanonical`] when a chunk is at or above the scalar modulus. A
/// non-canonical element is refused rather than reduced, because silently reducing it makes
/// two distinct wire encodings hash alike.
///
/// # Examples
/// ```
/// use howl_poseidon2::hash_be_bytes;
/// let mut one = [0u8; 32];
/// one[31] = 1;
/// assert!(hash_be_bytes(&one).is_ok());
/// assert!(hash_be_bytes(&one[..31]).is_err());
/// ```
pub fn hash_be_bytes(bytes: &[u8]) -> Result<[u8; 32], Poseidon2Error> {
    if !bytes.len().is_multiple_of(32) {
        return Err(Poseidon2Error::NotFieldAligned { len: bytes.len() });
    }
    let mut elements = Vec::with_capacity(bytes.len() / 32);
    for (index, chunk) in bytes.as_chunks::<32>().0.iter().enumerate() {
        let fr = Fr::from_be_bytes_mod_order(chunk);
        if fr.into_bigint().to_bytes_be() != chunk {
            return Err(Poseidon2Error::NotCanonical { index });
        }
        elements.push(fr);
    }
    let digest = hash(&elements);
    let be = digest.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let start = out.len().saturating_sub(be.len());
    out.get_mut(start..)
        .and_then(|slot| {
            slot.copy_from_slice(be.get(..be.len())?);
            Some(())
        })
        .ok_or(Poseidon2Error::NotCanonical { index: 0 })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{constant, constants};
    use ark_bn254::Fr;
    use ark_ff::PrimeField;

    /// The generator's first pass used a formatter that drops leading zeros; 35 of these lost a
    /// digit and the decoder read them left-aligned, producing a well-formed permutation with
    /// the wrong output. The KAT caught it, but only after the fact - this pins the shape.
    #[test]
    fn every_constant_is_a_full_width_field_element() {
        for (i, hex) in constants::ROUND_CONSTANTS
            .iter()
            .chain(constants::INTERNAL_DIAGONAL.iter())
            .enumerate()
        {
            let digits = hex.strip_prefix("0x").unwrap_or(hex);
            assert_eq!(
                digits.len(),
                64,
                "constant {i} is {} digits: {hex}",
                digits.len()
            );
            assert!(
                digits.bytes().all(|b| b.is_ascii_hexdigit()),
                "constant {i} is not hex: {hex}"
            );
        }
    }

    #[test]
    fn the_schedule_is_the_t4_shape() {
        assert_eq!(
            constants::ROUND_CONSTANTS.len(),
            super::FULL_ROUNDS * super::STATE_WIDTH + super::PARTIAL_ROUNDS
        );
        assert_eq!(constants::INTERNAL_DIAGONAL.len(), super::STATE_WIDTH);
    }

    /// Right-alignment is the property that makes a short entry harmless; assert it directly
    /// rather than trusting that every entry is padded.
    #[test]
    fn the_decoder_is_right_aligned() {
        assert_eq!(constant("0x01"), Fr::from(1u64));
        assert_eq!(constant("1"), Fr::from(1u64));
        assert_eq!(
            constant("0x0000000000000000000000000000000000000000000000000000000000000001"),
            Fr::from(1u64)
        );
        assert_eq!(constant("0x100"), Fr::from(256u64));
    }

    #[test]
    fn the_modulus_is_bn254() {
        // A wrong field would still permute; this pins which one.
        assert_eq!(
            Fr::MODULUS.to_string(),
            "21888242871839275222246405745257275088548364400416034343698204186575808495617"
        );
    }
}
