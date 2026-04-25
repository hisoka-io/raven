pub mod error;
pub mod memory;
pub mod storage;

pub use bytes::Bytes;
pub use error::Error;
pub use memory::{MemorySnapshot, MemoryStore};
pub use storage::{Row, Snapshot, StorageBackend, Transaction};

pub type Result<T, E = Error> = core::result::Result<T, E>;
