//! Cryptographic primitives shared across schemes. Scheme-bound math
//! (NTT kernels, gadget matrices, scheme-specific hashing) stays in the
//! scheme crates.

#![deny(missing_docs)]
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
