//! Storage-layer error surface, distinct from the server-runtime
//! [`crate::ServerError`].

/// Errors raised by a storage backend or by scheme code operating over one.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Caller-supplied parameters failed validation.
    #[error("invalid parameters: {0}")]
    InvalidParams(String),

    /// Lookup targeted a key the store does not hold.
    #[error("key {key} not found in store")]
    KeyNotFound {
        /// The key that was requested but is absent.
        key: u64,
    },

    /// The backend itself failed: lock poisoned, I/O, or capacity.
    #[error("storage backend error: {0}")]
    Storage(String),

    /// Scheme-layer failure surfaced through a storage call.
    #[error("scheme error: {0}")]
    Scheme(String),

    /// Wrapped foreign error, preserving the source's own message.
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl Error {
    /// Wrap a foreign error as [`Error::Other`].
    pub fn other(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Other(Box::new(err))
    }

    /// Build an [`Error::InvalidParams`] from a message.
    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self::InvalidParams(msg.into())
    }

    /// Build an [`Error::Storage`] from a message.
    pub fn storage(msg: impl Into<String>) -> Self {
        Self::Storage(msg.into())
    }

    /// Build an [`Error::Scheme`] from a message.
    pub fn scheme(msg: impl Into<String>) -> Self {
        Self::Scheme(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages() {
        let err = Error::KeyNotFound { key: 42 };
        assert_eq!(err.to_string(), "key 42 not found in store");

        let err = Error::invalid_params("dim must be power of two");
        assert_eq!(
            err.to_string(),
            "invalid parameters: dim must be power of two"
        );
    }
}
