//! HKDF-SHA256 seed derivation with domain separation.
//!
//! Every scheme that needs a reproducible 32-byte seed (e.g. Deterministic
//! matrix-A construction) routes through [`derive_seed`]. Inputs: caller's
//! master secret (`ikm`), a domain separator (scheme-constant salt), and an
//! `info` string that disambiguates sub-uses within a scheme (e.g.
//! `"inspire.matrix_a"` vs `"inspire.hint"`). Output is always 32 bytes.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::rng::SeedBytes;

/// Domain separator. Newtype so callers can't accidentally swap `ikm` and
/// `domain` arguments at a call site.
#[derive(Debug, Clone, Copy)]
pub struct DomainSeparator<'a>(pub &'a [u8]);

/// Canonical domain separator for Raven scheme seed derivation. Schemes that
/// want a sub-domain push it via `info` rather than changing the salt.
pub const SCHEME_SEED_DOMAIN: DomainSeparator<'static> = DomainSeparator(b"raven/scheme/v1");

/// Derive a 32-byte seed from `ikm` + `domain` + `info`.
#[must_use]
pub fn derive_seed(ikm: &[u8], domain: DomainSeparator<'_>, info: &[u8]) -> SeedBytes {
    let hk = Hkdf::<Sha256>::new(Some(domain.0), ikm);
    let mut out = [0u8; 32];
    // HKDF-Expand for SHA-256 can only fail above 255 * 32 = 8160 output bytes;
    // we request exactly 32.
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

    /// RFC 5869 §A.1 test vector for HKDF-SHA256.
    ///
    /// Inputs:
    ///   IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
    ///   salt = 0x000102030405060708090a0b0c (13 bytes)
    ///   info = 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
    ///   L    = 42 bytes
    /// Output first 32 bytes of OKM:
    ///   3cb25f25faacd57a90434f64d0362f2a
    ///   2d2d0a90cf1a5a4c5db02d56ecc4c5bf
    ///
    /// We ask for 32 bytes here, which equals those first 32 bytes of the
    /// reference 42-byte output.
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
