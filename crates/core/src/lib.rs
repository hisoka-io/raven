//! Core types for the Raven PIR framework: the [`storage`] contract every backend
//! implements, an in-memory reference backend, and the shared error surface.
//!
//! ```
//! use raven_core::{Bytes, Error, MemoryStore, StorageBackend};
//!
//! # fn main() -> Result<(), Error> {
//! let store = MemoryStore::new();
//! let mut txn = store.begin()?;
//! // Inserted scrambled, and deliberately more than a couple of keys: with two, half of
//! // all orderings are ascending by accident, so the example would demonstrate nothing.
//! for k in [7u64, 1, 9, 3, 5, 0, 8, 2] {
//!     txn.insert(k, Bytes::from_static(b"v"))?;
//! }
//! txn.commit()?;
//!
//! let snap = store.snapshot()?;
//! let mut keys = Vec::new();
//! for row in snap.scan() {
//!     keys.push(row?.0);
//! }
//! // The contract `scan` owes every backend: each visible key once, strictly ascending,
//! // whatever order the writes arrived in.
//! assert_eq!(keys, vec![0, 1, 2, 3, 5, 7, 8, 9]);
//! # Ok(())
//! # }
//! ```

#![deny(missing_docs)]

pub mod error;
pub mod instance;
pub mod memory;
pub mod server_error;
pub mod storage;

pub use bytes::Bytes;
pub use error::Error;
pub use instance::{Epoch, InstanceId};
pub use memory::{MemorySnapshot, MemoryStore};
pub use server_error::ServerError;
pub use storage::{Row, Snapshot, StorageBackend, Transaction};

/// Result alias defaulting to the storage-layer [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;
