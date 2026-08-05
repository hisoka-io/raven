//! HKDF-SHA256 seed derivation. `domain` is the scheme-constant salt,
//! `info` separates sub-uses within one scheme.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::rng::SeedBytes;

/// HKDF salt. Newtype so `ikm` and `domain` cannot be swapped at a call site.
#[derive(Debug, Clone, Copy)]
pub struct DomainSeparator<'a>(pub &'a [u8]);

/// Canonical salt for scheme seed derivation; sub-domains go in `info`.
pub const SCHEME_SEED_DOMAIN: DomainSeparator<'static> = DomainSeparator(b"raven/scheme/v1");

/// Derive a 32-byte seed from `ikm` + `domain` + `info`.
#[must_use]
pub fn derive_seed(ikm: &[u8], domain: DomainSeparator<'_>, info: &[u8]) -> SeedBytes {
    let hk = Hkdf::<Sha256>::new(Some(domain.0), ikm);
    let mut out = [0u8; 32];
    // HKDF-Expand fails only above 255 * 32 output bytes; 32 always fits.
    #[allow(clippy::expect_used)]
    hk.expand(info, &mut out).expect("32 bytes always fits");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_inputs_yield_same_seed() {
        let s1 = derive_seed(b"master", SCHEME_SEED_DOMAIN, b"test.info");
        let s2 = derive_seed(b"master", SCHEME_SEED_DOMAIN, b"test.info");
        assert_eq!(s1, s2);
    }

    #[test]
    fn different_info_yields_different_seeds() {
        let s1 = derive_seed(b"master", SCHEME_SEED_DOMAIN, b"info.a");
        let s2 = derive_seed(b"master", SCHEME_SEED_DOMAIN, b"info.b");
        assert_ne!(s1, s2);
    }

    #[test]
    fn different_ikm_yields_different_seeds() {
        let s1 = derive_seed(b"master1", SCHEME_SEED_DOMAIN, b"info");
        let s2 = derive_seed(b"master2", SCHEME_SEED_DOMAIN, b"info");
        assert_ne!(s1, s2);
    }

    #[test]
    fn different_domain_yields_different_seeds() {
        let s1 = derive_seed(b"master", DomainSeparator(b"domain.a"), b"info");
        let s2 = derive_seed(b"master", DomainSeparator(b"domain.b"), b"info");
        assert_ne!(s1, s2);
    }

    /// RFC 5869 A.1, truncated to the first 32 of its 42 OKM bytes.
    #[test]
    fn kat_rfc5869_basic() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").expect("hex");
        let salt = hex::decode("000102030405060708090a0b0c").expect("hex");
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").expect("hex");
        let expected =
            hex::decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
                .expect("hex");

        let got = derive_seed(&ikm, DomainSeparator(&salt), &info);
        assert_eq!(got.as_slice(), expected.as_slice());
    }
}
