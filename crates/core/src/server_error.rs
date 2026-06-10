//! Typed server-runtime error surface, distinct from the storage-layer [`crate::Error`].

use crate::instance::{Epoch, InstanceId};

/// Generic server-runtime error surface shared by the server and storage crates.
#[derive(thiserror::Error, Debug)]
pub enum ServerError {
    /// Engine instance lookup failed.
    #[error("instance not found: {0}")]
    InstanceNotFound(InstanceId),

    /// Instance is draining or drained. Routing layers should return 503
    /// (transient, retry) rather than 404.
    #[error("instance draining or drained: {instance_id}")]
    NoActiveInstance {
        /// Instance whose drain state was non-Active at routing time.
        instance_id: InstanceId,
    },

    /// Client query referenced a stale snapshot epoch.
    #[error("epoch mismatch: client requires >= {client}, server is at {server}")]
    EpochMismatch {
        /// Minimum epoch the client's session was prepared against.
        client: Epoch,
        /// Current server epoch at query time.
        server: Epoch,
    },

    /// Wrapped scheme-layer error.
    #[error("scheme error: {0}")]
    Scheme(String),

    /// Wire-format decode/encode error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Query failed structural validation before scheme dispatch.
    #[error("invalid query: {0}")]
    InvalidQuery(String),

    /// Internal post-condition violation.
    #[error("internal error: {0}")]
    Internal(String),

    /// Re-encode or query targeted a `shard_id` past the shard count. Distinct
    /// from [`ServerError::Internal`] so a caller can treat a
    /// structurally-unencodable shard as terminal while retrying transient errors.
    #[error("shard out of range: shard_id {shard_id} (have {db_shard_count} shards)")]
    ShardOutOfRange {
        /// The shard id that was requested but is not present.
        shard_id: u32,
        /// Number of shards currently in the encoded database.
        db_shard_count: usize,
    },
}

/// Server-runtime result alias.
pub type Result<T, E = ServerError> = core::result::Result<T, E>;
