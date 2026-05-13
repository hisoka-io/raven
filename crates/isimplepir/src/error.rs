use thiserror::Error;

#[derive(Debug, Error)]
pub enum IsimplePirError {
    #[error("invalid parameters: {reason}")]
    InvalidParams { reason: String },

    #[error("database shape mismatch: {reason}")]
    DatabaseShape { reason: String },

    #[error("query shape mismatch: {reason}")]
    QueryShape { reason: String },

    #[error("response shape mismatch: {reason}")]
    ResponseShape { reason: String },

    /// Out-of-order or duplicate `StateUpdate`. Recovery: client
    /// re-runs `Setup` against the current server state.
    #[error("hint version mismatch: expected {expected}, got {received}")]
    VersionMismatch { expected: u64, received: u64 },

    /// `new_value >= p`; per-update invariant violated.
    #[error("plaintext out of bound: |value| = {value_abs} but must be < {half_p}")]
    PlaintextOutOfBound { value_abs: u64, half_p: u64 },

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("deserialization error: {0}")]
    Deserialization(String),

    #[error("randomness source failed: {0}")]
    Randomness(String),

    /// Caller asked for strong deletion; scheme provides only weak
    /// (paper §2.4).
    #[error("strong deletion not supported; iSimplePIR provides weak deletion only")]
    WeakDeletionOnly,
}

pub type Result<T> = core::result::Result<T, IsimplePirError>;
