//! Core types for the Raven PIR framework: the [`storage`] contract every backend
//! implements, an in-memory reference backend, and the shared error surface.
//!
//! ```
//! use raven_core::{Bytes, Error, MemoryStore, StorageBackend};
//!
//! # fn main() -> Result<(), Error> {
//! let store = MemoryStore::new();
//! let mut txn = store.begin()?;
//! txn.insert(2, Bytes::from_static(b"beta"))?;
//! txn.insert(0, Bytes::from_static(b"alpha"))?;
//! txn.commit()?;
//!
//! let snap = store.snapshot()?;
//! let mut keys = Vec::new();
//! for row in snap.scan() {
//!     keys.push(row?.0);
//! }
//! assert_eq!(keys, vec![0, 2]);
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
