//! Crash-consistent persistence for this adapter: a thin binding over the
//! `raven-storage` durability primitives plus the app-specific
//! [`SNAPSHOT_MAGIC`] and [`WalEntryPayload`].

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]
#![deny(missing_docs)]

mod payload;

pub use payload::{PpoiEventMetadata, PpoiEventType, WalEntryPayload};

pub use raven_storage::{
    advance_manifest_and_archive, apply_retention, atomic_write, fsync_parent_dir, open_recovery,
    publish_snapshot, Manifest, ManifestShape, PersistenceError, Result, RetentionPolicy,
    RetentionReport, SnapshotFile as Snapshot, SnapshotHeader, SnapshotId, StoreLayout,
    StoreRecovery, Wal, WalEntry, WalReplay, MANIFEST_SCHEMA_VERSION,
    MIN_READABLE_MANIFEST_SCHEMA_VERSION, WAL_MAX_PAYLOAD_BYTES,
};

#[cfg(not(target_arch = "wasm32"))]
pub use raven_storage::ExclusiveLock;

/// Snapshot header magic; pins the adapter's on-disk snapshot version.
pub const SNAPSHOT_MAGIC: [u8; 16] = *b"RAVEN_RAILGUN_01";
