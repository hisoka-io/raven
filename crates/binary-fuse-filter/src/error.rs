use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BffError {
    #[error("cannot build a binary fuse filter over an empty key-value database")]
    EmptyKeyValueDatabase,

    /// Every reseed failed; frequent hits point at the key distribution.
    #[error("exhausted {attempts} attempts to build a {arity}-wise XOR binary fuse filter")]
    ExhaustedAllAttemptsToBuild { arity: u32, attempts: usize },

    #[error("failed to deserialize filter from bytes: length mismatch")]
    FailedToDeserializeFilterFromBytes,
}

pub type Result<T> = core::result::Result<T, BffError>;
