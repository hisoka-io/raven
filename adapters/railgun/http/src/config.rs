//! HTTP layer configuration.

use serde::{Deserialize, Serialize};

use crate::trusted_proxy::{resolve_declared_ranges, IpCidr};

/// Sanity ceiling for [`HttpConfig::max_body_bytes`]; rejected at validate time.
pub(crate) const HTTP_MAX_BODY_CEILING: usize = 64 * 1024 * 1024;

/// Sanity ceiling for [`HttpConfig::max_fanout_shards`]; rejected at validate time.
/// One request already costs k respond operations, so the cap is the only bound
/// on request amplification.
pub(crate) const HTTP_MAX_FANOUT_CEILING: usize = 128;

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
    /// Enables forwarding-header trust. Requires a non-empty
    /// [`HttpConfig::trusted_proxy_cidrs`]; the pair is validated together.
    pub trust_proxy_header: bool,
    /// Peer ranges (CIDR, e.g. `127.0.0.1/32`, `172.16.0.0/12`, `fd00::/8`) whose
    /// `X-Forwarded-For` / `cf-connecting-ip` is honoured. Every other peer keys
    /// to its own socket address.
    #[serde(default)]
    pub trusted_proxy_cidrs: Vec<String>,
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
    /// Max shard ids accepted per `POST /v1/instance/{id}/fanout` request.
    #[serde(default = "default_max_fanout_shards")]
    pub max_fanout_shards: usize,
}

fn default_session_eviction_interval_secs() -> u64 {
    3600
}

fn default_max_fanout_shards() -> usize {
    16
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
            trusted_proxy_cidrs: Vec::new(),
            cors_allowed_origins: Vec::new(),
            metrics_public: false,
            session_eviction_interval_secs: 3600,
            max_fanout_shards: default_max_fanout_shards(),
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
        if self.max_fanout_shards == 0 {
            return Err("max_fanout_shards must be > 0".to_owned());
        }
        if self.max_fanout_shards > HTTP_MAX_FANOUT_CEILING {
            return Err(format!(
                "max_fanout_shards too large: {} (sanity ceiling {})",
                self.max_fanout_shards, HTTP_MAX_FANOUT_CEILING
            ));
        }
        self.resolve_trusted_proxy_ranges()?;
        Ok(())
    }

    /// Parse the trusted-proxy ranges, enforcing agreement with `trust_proxy_header`.
    ///
    /// Returns an empty vector when proxy trust is off.
    ///
    /// # Errors
    /// `Err(String)` when the two fields disagree or an entry fails to parse.
    pub fn resolve_trusted_proxy_ranges(&self) -> Result<Vec<IpCidr>, String> {
        resolve_declared_ranges(self.trust_proxy_header, &self.trusted_proxy_cidrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> HttpConfig {
        HttpConfig::demo("read-token-padded-long-enough")
    }

    #[test]
    fn default_posture_trusts_no_proxy() {
        let cfg = config();
        assert!(!cfg.trust_proxy_header);
        assert!(cfg.trusted_proxy_cidrs.is_empty());
        assert_eq!(
            cfg.resolve_trusted_proxy_ranges()
                .expect("default is valid"),
            Vec::new()
        );
    }

    #[test]
    fn trust_without_ranges_is_rejected() {
        let mut cfg = config();
        cfg.trust_proxy_header = true;
        let err = cfg.validate().expect_err("bare boolean trust is rejected");
        assert!(err.contains("trusted_proxy_cidrs"), "{err}");
        assert!(err.contains("directly reachable"), "{err}");
    }

    #[test]
    fn ranges_without_trust_are_rejected() {
        let mut cfg = config();
        cfg.trusted_proxy_cidrs = vec!["127.0.0.1/32".to_owned()];
        let err = cfg
            .validate()
            .expect_err("ranges that cannot apply are rejected");
        assert!(err.contains("trust_proxy_header = false"), "{err}");
    }

    #[test]
    fn a_malformed_range_fails_validation_with_the_entry_named() {
        let mut cfg = config();
        cfg.trust_proxy_header = true;
        cfg.trusted_proxy_cidrs = vec!["127.0.0.1/32".to_owned(), "10.0.0.1/8".to_owned()];
        let err = cfg.validate().expect_err("host bits are rejected");
        assert!(err.contains("10.0.0.1/8"), "{err}");
    }

    #[test]
    fn a_declared_proxy_range_validates_and_resolves() {
        let mut cfg = config();
        cfg.trust_proxy_header = true;
        cfg.trusted_proxy_cidrs = vec!["127.0.0.1/32".to_owned(), "fd00::/8".to_owned()];
        cfg.validate().expect("declared ranges validate");
        assert_eq!(
            cfg.resolve_trusted_proxy_ranges().expect("resolves").len(),
            2
        );
    }
}
