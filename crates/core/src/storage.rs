//! The contract every Raven storage backend implements.
//!
//! Two invariants the types cannot express:
//!
//! 1. Snapshot isolation. A [`Snapshot`] observes exactly the state committed at
//!    its [`Snapshot::generation`] and never a later commit, including one that
//!    lands while the snapshot is still being read.
//! 2. Strictly ascending scan. [`Snapshot::scan`] yields each visible key exactly
//!    once, in ascending order. Consumers slice a key window out of the stream and
//!    stop at the first key past it, so an unordered backend yields a silently
//!    truncated database rather than an error.

use bytes::Bytes;

use crate::error::Error;

/// A stored row: `u64` key paired with its opaque value.
pub type Row = (u64, Bytes);

/// Persistent `u64`-keyed store backing a PIR engine.
pub trait StorageBackend: Send + Sync + 'static {
    /// Count of committed rows.
    fn len(&self) -> Result<u64, Error>;

    /// Whether no rows are committed.
    fn is_empty(&self) -> Result<bool, Error> {
        Ok(self.len()? == 0)
    }

    /// Open a write transaction. Its writes stay invisible to snapshots until commit.
    fn begin(&self) -> Result<Box<dyn Transaction + '_>, Error>;

    /// Pin an isolated read view of the currently committed state.
    fn snapshot(&self) -> Result<Box<dyn Snapshot>, Error>;
}

/// Atomic batch of writes. Dropping it without [`Transaction::commit`] discards them.
pub trait Transaction: Send {
    /// Stage a write, replacing any value already staged or committed for `key`.
    fn insert(&mut self, key: u64, value: Bytes) -> Result<(), Error>;

    /// Stage a deletion. Removing an absent key is not an error.
    fn remove(&mut self, key: u64) -> Result<(), Error>;

    /// Apply every staged write atomically and return the resulting generation.
    /// An empty transaction commits without advancing the generation.
    fn commit(self: Box<Self>) -> Result<u64, Error>;
}

/// Read view pinned to one generation.
pub trait Snapshot: Send + Sync {
    /// Generation this view is pinned to, monotonic across commits on one backend.
    fn generation(&self) -> u64;

    /// Count of rows visible in this view.
    fn len(&self) -> u64;

    /// Whether this view holds no rows.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Value at `key`, or `None` if absent from this view.
    fn get(&self, key: u64) -> Result<Option<Bytes>, Error>;

    /// Every visible row in strictly ascending key order, per the module contract.
    fn scan<'a>(&'a self) -> Box<dyn Iterator<Item = Result<Row, Error>> + 'a>;
}
