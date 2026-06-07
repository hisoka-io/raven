//! Deterministic ChaCha20 RNG wrapper.
//!
//! One named type every scheme routes through for reproducible randomness.
//! Seeded from a 32-byte [`SeedBytes`]; `from_u64` exists for tests.
//! Schemes that need non-determinism use `OsRng` explicitly.

use rand_chacha::rand_core::SeedableRng;

/// 32-byte seed for the deterministic RNG.
pub type SeedBytes = [u8; 32];

/// Thin wrapper over [`rand_chacha::ChaCha20Rng`] so every scheme routes
/// through one named type and the underlying PRG can be swapped without
/// touching call sites.
#[derive(Debug, Clone)]
pub struct DeterministicRng {
    inner: rand_chacha::ChaCha20Rng,
}

impl DeterministicRng {
    /// Construct from a fully-specified 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: SeedBytes) -> Self {
        Self {
            inner: rand_chacha::ChaCha20Rng::from_seed(seed),
        }
    }

    /// Construct from a `u64`, placing its little-endian bytes in the low
    /// eight bytes of the seed and zero-padding the rest.
    ///
    /// Intended for tests and stable reproduction cases; schemes SHOULD
    /// prefer [`DeterministicRng::from_seed`] with a derived 32-byte seed so
    /// the key space is not truncated.
    #[must_use]
    pub fn from_u64(seed: u64) -> Self {
        let mut full: SeedBytes = [0u8; 32];
        full[..8].copy_from_slice(&seed.to_le_bytes());
        Self::from_seed(full)
    }

    /// Borrow the inner `ChaCha20Rng` as a [`rand_core::RngCore`] impl for
    /// passing into APIs that want `&mut R`.
    #[must_use]
    pub fn inner_mut(&mut self) -> &mut rand_chacha::ChaCha20Rng {
        &mut self.inner
    }
}

impl rand_core::RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.inner.fill_bytes(dst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::RngCore;

    #[test]
    fn same_seed_yields_identical_byte_streams() {
        let mut a = DeterministicRng::from_seed([0x42; 32]);
        let mut b = DeterministicRng::from_seed([0x42; 32]);
        let mut ba = [0u8; 64];
        let mut bb = [0u8; 64];
        a.fill_bytes(&mut ba);
        b.fill_bytes(&mut bb);
        assert_eq!(ba, bb);
    }

    #[test]
    fn different_seeds_yield_different_byte_streams() {
        let mut a = DeterministicRng::from_seed([0; 32]);
        let mut b = DeterministicRng::from_seed([1; 32]);
        let mut ba = [0u8; 64];
        let mut bb = [0u8; 64];
        a.fill_bytes(&mut ba);
        b.fill_bytes(&mut bb);
        assert_ne!(ba, bb);
    }

    /// KAT for ChaCha20 with an all-zero seed and an all-zero nonce.
    ///
    /// Reference: RFC 8439 §2.3.2 test vector for ChaCha20 block function,
    /// with key = 0x00..00 and counter/nonce = 0. `rand_chacha::ChaCha20Rng`
    /// initialises its keystream identically, so the first 64 bytes of the
    /// RNG output must match the RFC's first-block keystream bytes verbatim.
    #[test]
    fn kat_rfc8439_zero_seed_first_block() {
        let mut rng = DeterministicRng::from_seed([0u8; 32]);
        let mut got = [0u8; 64];
        rng.fill_bytes(&mut got);
        let expected_hex = concat!(
            "76b8e0ada0f13d90405d6ae55386bd28",
            "bdd219b8a08ded1aa836efcc8b770dc7",
            "da41597c5157488d7724e03fb8d84a37",
            "6a43b8f41518a11cc387b669b2ee6586",
        );
        let expected = hex::decode(expected_hex).expect("valid hex");
        assert_eq!(got.as_slice(), expected.as_slice());
    }

    /// KAT for ChaCha20 keystream under a non-all-zero key, covering a
    /// different initialisation regime than the all-zero-key vector.
    #[test]
    fn kat_rfc8439_nonzero_key_first_block() {
        let mut seed = [0u8; 32];
        seed[31] = 0x01;
        let mut rng = DeterministicRng::from_seed(seed);
        let mut got = [0u8; 64];
        rng.fill_bytes(&mut got);
        // Cross-checked against the `chacha20` crate under the same seed;
        // any divergence means a rand_chacha backend change or RFC 8439 break.
        let expected_hex = concat!(
            "4540f05a9f1fb296d7736e7b208e3c96",
            "eb4fe1834688d2604f450952ed432d41",
            "bbe2a0b6ea7566d2a5d1e7e20d42af2c",
            "53d792b1c43fea817e9ad275ae546963",
        );
        let expected = hex::decode(expected_hex).expect("valid hex");
        assert_eq!(got.as_slice(), expected.as_slice());
    }

    /// Scope marker: ChaCha20 is used as a PRG, not AEAD, so RFC 8439 §A.5
    /// and the A.1 vectors needing counter/nonce control are out of scope;
    /// `SeedableRng` does not expose those inputs.
    #[test]
    fn aead_scope_note() {}

    #[test]
    fn from_u64_is_deterministic_and_distinct_per_seed() {
        let mut a = DeterministicRng::from_u64(0);
        let mut b = DeterministicRng::from_u64(0);
        let mut c = DeterministicRng::from_u64(1);
        assert_eq!(a.next_u64(), b.next_u64());
        assert_ne!(a.next_u64(), c.next_u64());
    }
}
