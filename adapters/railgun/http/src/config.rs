//! HTTP layer configuration.

use serde::{Deserialize, Serialize};

/// Sanity ceiling for [`HttpConfig::max_body_bytes`]; rejected at validate time.
pub(crate) const HTTP_MAX_BODY_CEILING: usize = 64 * 1024 * 1024;

/// HTTP layer configuration; all knobs are tunable without recompiling.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpConfig {
    /// Bearer token granting read scope.
    pub read_token: String,
    /// Optional bearer token granting admin scope.
    pub admin_token: Option<String>,
    /// Maximum body bytes accepted by any route. Default 8 MiB.
    pub max_body_bytes: usize,
    /// Per-IP rate limit: max sustained requests per second.
    pub rate_limit_rps: u64,
    /// Per-IP rate limit: burst budget (token bucket capacity).
    pub rate_limit_burst: u32,
    /// Max concurrent in-flight respond operations. K=4 default.
    pub max_concurrent_queries: usize,
    /// Sticky-session TTL in seconds.
    pub session_ttl_secs: u64,
    /// Sticky-session LRU cap.
    pub session_lru_cap: usize,
    /// Identifier surfaced in the `X-Raven-Scheme` response header.
    pub scheme_name: String,
    /// Per-query response timeout in seconds. A timed-out worker releases
    /// its semaphore permit so subsequent queries aren't blocked indefinitely.
    pub respond_timeout_secs: u64,
    /// When `true`, uses `SmartIpKeyExtractor` (reads `X-Forwarded-For`).
    /// Only safe behind a trusted reverse proxy that strips client-supplied headers.
    pub trust_proxy_header: bool,
    /// Explicit CORS origins. Empty = no CORS layer. Never use `["*"]`
    /// on an authenticated PIR server.
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
    /// Default-deny posture for `/metrics`. When `false`, the metrics
    /// endpoint requires bearer auth; when `true`, it is unauthenticated
    /// (operator opts in via `--metrics-public`).
    #[serde(default)]
    pub metrics_public: bool,
    /// Periodic heartbeat session-eviction interval (seconds). `0` disables.
    #[serde(default = "default_session_eviction_interval_secs")]
    pub session_eviction_interval_secs: u64,
}

fn default_session_eviction_interval_secs() -> u64 {
    3600
}

impl HttpConfig {
    /// Minimum bearer-token length (16 bytes = 128 bits of token-space).
    pub const MIN_TOKEN_LEN: usize = 16;

    /// Build a config with sensible defaults.
    pub fn demo(read_token: impl Into<String>) -> Self {
        Self {
            read_token: read_token.into(),
            admin_token: None,
            max_body_bytes: 8 * 1024 * 1024,
            rate_limit_rps: 200,
            rate_limit_burst: 400,
            max_concurrent_queries: 4,
            session_ttl_secs: 60 * 60,
            session_lru_cap: 10_000,
            scheme_name: "raven-inspire".to_owned(),
            respond_timeout_secs: 30,
            trust_proxy_header: false,
            cors_allowed_origins: Vec::new(),
            metrics_public: false,
            session_eviction_interval_secs: 3600,
        }
    }

    /// Validate config; called by [`AppState::new`].
    ///
    /// # Errors
    /// Returns `Err(String)` describing the first failing invariant.
    pub fn validate(&self) -> Result<(), String> {
        if self.read_token.len() < Self::MIN_TOKEN_LEN {
            return Err(format!(
                "read_token too short: {} bytes (minimum {})",
                self.read_token.len(),
                Self::MIN_TOKEN_LEN
            ));
        }
        if let Some(admin) = self.admin_token.as_ref() {
            if admin.len() < Self::MIN_TOKEN_LEN {
                return Err(format!(
                    "admin_token too short: {} bytes (minimum {})",
                    admin.len(),
                    Self::MIN_TOKEN_LEN
                ));
            }
        }
        for origin in &self.cors_allowed_origins {
            if origin == "*" {
                return Err("cors_allowed_origins must not contain `*` for an \
                     authenticated PIR server; list explicit origins"
                    .to_owned());
            }
            if origin.is_empty() {
                return Err("cors_allowed_origins entry must not be empty".to_owned());
            }
        }
        if self.max_body_bytes == 0 {
            return Err("max_body_bytes must be > 0".to_owned());
        }
        if self.max_body_bytes > HTTP_MAX_BODY_CEILING {
            return Err(format!(
                "max_body_bytes too large: {} bytes (sanity ceiling {} bytes)",
                self.max_body_bytes, HTTP_MAX_BODY_CEILING
            ));
        }
        Ok(())
    }
}
