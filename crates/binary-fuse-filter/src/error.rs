use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BffError {
    /// `construct_*_wise` was called with an empty key-value map.
    #[error("cannot build a binary fuse filter over an empty key-value database")]
    EmptyKeyValueDatabase,

    /// Construction failed after `max_attempt_count` retries with
    /// fresh seeds. Inspect key distribution if this fires often.
    #[error("exhausted {attempts} attempts to build a {arity}-wise XOR binary fuse filter")]
    ExhaustedAllAttemptsToBuild {
        /// Arity (3 or 4).
        arity: u32,
        /// Value of `max_attempt_count` that was exhausted.
        attempts: usize,
    },

    /// `from_bytes` got a slice with the wrong length.
    #[error("failed to deserialize filter from bytes: length mismatch")]
    FailedToDeserializeFilterFromBytes,
}

pub type Result<T> = core::result::Result<T, BffError>;
