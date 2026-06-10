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

pub type Result<T, E = Error> = core::result::Result<T, E>;
