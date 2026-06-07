//! Cryptographic primitives shared across Raven schemes.
//!
//! - [`rng`]: deterministic ChaCha20 RNG.
//! - [`seed`]: HKDF-SHA256 seed derivation with domain separation.
//! - [`bitpack`]: variable-width packing for LWE ciphertext limbs.
//!
//! Scheme-bound math (NTT kernels, gadget matrices, scheme-specific hashing)
//! lives in the scheme crates, not here.

// Crypto paths: every intentional cast needs a local allow with a reason.
#![deny(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_lossless
)]
#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod bitpack;
pub mod rng;
pub mod seed;

pub use rng::{DeterministicRng, SeedBytes};
pub use seed::{derive_seed, DomainSeparator, SCHEME_SEED_DOMAIN};
