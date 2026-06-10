//! Crash-consistent persistence for the Raven Railgun PIR engine.
//!
//! Thin app binding over the generic durability primitives in `raven-storage`:
//! re-exports [`Snapshot`] (the storage `SnapshotFile`), [`Wal`], [`Manifest`],
//! [`StoreLayout`], and the error surface, and supplies the app-specific
//! [`SNAPSHOT_MAGIC`] and [`WalEntryPayload`] this engine writes.

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]
#![deny(missing_docs)]

mod payload;

pub use payload::WalEntryPayload;

pub use raven_storage::{
    Manifest, PersistenceError, Result, SnapshotFile as Snapshot, SnapshotHeader, SnapshotId,
    StoreLayout, Wal, WalEntry, WalReplay, MANIFEST_SCHEMA_VERSION,
    MIN_READABLE_MANIFEST_SCHEMA_VERSION, WAL_MAX_PAYLOAD_BYTES,
};

#[cfg(not(target_arch = "wasm32"))]
pub use raven_storage::ExclusiveLock;

/// Format magic stamped into every snapshot header written by this engine and
/// required by [`Snapshot::load`]. Pins the adapter's on-disk snapshot version.
pub const SNAPSHOT_MAGIC: [u8; 16] = *b"RAVEN_RAILGUN_01";
