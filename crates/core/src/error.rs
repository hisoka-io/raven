#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid parameters: {0}")]
    InvalidParams(String),

    #[error("key {key} not found in store")]
    KeyNotFound { key: u64 },

    #[error("storage backend error: {0}")]
    Storage(String),

    #[error("scheme error: {0}")]
    Scheme(String),

    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl Error {
    pub fn other(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Other(Box::new(err))
    }

    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self::InvalidParams(msg.into())
    }

    pub fn storage(msg: impl Into<String>) -> Self {
        Self::Storage(msg.into())
    }

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
