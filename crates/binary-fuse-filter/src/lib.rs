#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]
#![allow(missing_docs)]
//! Binary Fuse Filter (3-wise and 4-wise XOR variants). Probabilistic
//! membership in `~1.1` bits per entry above the minimum; queries
//! XOR-reduce 3 or 4 hash-derived slots.
//!
//! Pure-Rust port of the construction in
//! `chalametpir_common::binary_fuse_filter` (BSD-3-Clause). Algorithm
//! described in <https://arxiv.org/abs/2201.01174>.
//!
//! Not a cryptographic primitive: the keyed hash gives good avalanche,
//! but fingerprints are small enough to be collision-susceptible. Do
//! not use as a secret-dependent decision primitive.
//!
//! ```no_run
//! use std::collections::HashMap;
//! use raven_bff::BinaryFuseFilter;
//!
//! let mut db: HashMap<&[u8], &[u8]> = HashMap::new();
//! db.insert(b"alice" as &[u8], b"value-a" as &[u8]);
//! db.insert(b"bob" as &[u8], b"value-b" as &[u8]);
//! let (filter, _order, _hashes, _keys) =
//!     BinaryFuseFilter::construct_3_wise(&db, 8, 100).unwrap();
//! assert!(filter.bits_per_entry() > 0.0);
//! ```

pub mod branch_opt;
pub mod error;
pub mod filter;

pub use error::{BffError, Result};
pub use filter::{
    hash_batch_for_3_wise_xor_filter, hash_batch_for_4_wise_xor_filter, hash_of_key, mix256, mod3,
    mod4, murmur64, segment_length, size_factor, BinaryFuseFilter,
    BinaryFuseFilterIntermediateStageResult,
};
