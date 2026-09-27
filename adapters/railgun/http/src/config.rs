//! HTTP layer configuration.

use std::time::Duration;

use raven_railgun_engine::session_pool::{SessionStoreLimits, DEFAULT_MAX_SESSIONS};
use serde::{Deserialize, Serialize};

use crate::trusted_proxy::{resolve_declared_ranges, IpCidr};

/// Sanity ceiling for [`HttpConfig::max_body_bytes`]; rejected at validate time.
pub(crate) const HTTP_MAX_BODY_CEILING: usize = 64 * 1024 * 1024;

/// Sanity ceiling for [`HttpConfig::max_fanout_shards`]; the only bound on request
/// amplification, since one request costs k respond operations.
pub(crate) const HTTP_MAX_FANOUT_CEILING: usize = 128;

/// Default and ceiling session lifetime in seconds; also the default eviction cadence.
pub const DEFAULT_SESSION_TTL_SECS: u64 =
    raven_railgun_engine::session_pool::DEFAULT_SESSION_TTL.as_secs();

/// HTTP layer configuration; all knobs are tunable without recompiling.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpConfig {
    /// Bearer token opening `/metrics` while [`HttpConfig::metrics_public`] is false.
    /// It gates nothing else: query, batch, session, params and status answer any caller.
    pub read_token: String,
    /// Maximum body bytes accepted by any route. Default 8 MiB.
    pub max_body_bytes: usize,
    /// Per-IP rate limit: max sustained requests per second.
    pub rate_limit_rps: u64,
    /// Per-IP rate limit: burst budget (token bucket capacity).
    pub rate_limit_burst: u32,
    /// Max concurrent in-flight respond operations. K=4 default.
    pub max_concurrent_queries: usize,
    /// Max concurrent `/v1/events` SSE streams. Each one holds a task, two timers and an
    /// `AppState` clone for as long as the client stays connected, and the route carries no
    /// credential, so a rate limit on new connections does not bound what is HELD. This does.
    ///
    /// Defaulted for serde because this struct derives `Deserialize` and adding a REQUIRED
    /// field would make every previously valid serialized config fail to load -- a break that
    /// shows up at an operator's boot, not at ours.
    #[serde(default = "default_max_sse_connections")]
    pub max_sse_connections: usize,
    /// Streams one peer may hold out of [`HttpConfig::max_sse_connections`], keyed like the
    /// rate limiter. Without it one peer holds every stream and each wallet's retry loop starves.
    #[serde(default = "default_max_sse_connections_per_peer")]
    pub max_sse_connections_per_peer: usize,
    /// Session lifetime in seconds for a packing-key seat and its handle; see
    /// [`HttpConfig::session_store_limits`]. At most [`DEFAULT_SESSION_TTL_SECS`], because one
    /// handle links every query made under it.
    pub session_ttl_secs: u64,
    /// Sticky-session bindings across all instances; at least one instance's full pool.
    pub session_lru_cap: usize,
    /// Packing-key seats per instance, and so a memory bound: a seat holds the server-derived
    /// keys, about 24 MiB at a 512 B row and 1.5 MiB at a 32 B row.
    #[serde(default = "default_max_sessions_per_instance")]
    pub max_sessions_per_instance: usize,
    /// Identifier surfaced in the `X-Raven-Scheme` response header.
    pub scheme_name: String,
    /// Per-query response timeout; a timed-out worker releases its semaphore permit.
    pub respond_timeout_secs: u64,
    /// Requires a non-empty [`HttpConfig::trusted_proxy_cidrs`]; validated as a pair.
    pub trust_proxy_header: bool,
    /// Peer CIDRs whose `X-Forwarded-For` / `cf-connecting-ip` is honoured; every
    /// other peer keys to its own socket address.
    #[serde(default)]
    pub trusted_proxy_cidrs: Vec<String>,
    /// Explicit CORS origins; empty disables the layer. Never `["*"]` here.
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
    /// When `true`, `/metrics` is unauthenticated. Default-deny.
    #[serde(default)]
    pub metrics_public: bool,
    /// Periodic heartbeat session-eviction interval (seconds). `0` disables.
    #[serde(default = "default_session_eviction_interval_secs")]
    pub session_eviction_interval_secs: u64,
    /// Max shard ids accepted per `POST /v1/instance/{id}/fanout` request.
    #[serde(default = "default_max_fanout_shards")]
    pub max_fanout_shards: usize,
    /// Mount `POST /v1/instance/{id}/fanout`. Off by default: the route has no
    /// batch-size ladder, so `shard_ids.len()` travels in the clear, and it clones
    /// the query per shard, so peak memory is `k x body`. Enable only with a cover
    /// strategy that fixes the group size.
    #[serde(default)]
    pub enable_fanout: bool,
}

fn default_session_eviction_interval_secs() -> u64 {
    DEFAULT_SESSION_TTL_SECS
}

/// Default [`HttpConfig::max_sse_connections`]: generous for a status stream a handful of
/// dashboards watch, and finite, which is the point.
pub const DEFAULT_MAX_SSE_CONNECTIONS: usize = 64;

/// Default [`HttpConfig::max_sse_connections_per_peer`]: a quarter of the global default, so a
/// shared NAT keeps room and one host needs four addresses to hold every stream.
pub const DEFAULT_MAX_SSE_CONNECTIONS_PER_PEER: usize = 16;

const fn default_max_sse_connections() -> usize {
    DEFAULT_MAX_SSE_CONNECTIONS
}

const fn default_max_sse_connections_per_peer() -> usize {
    DEFAULT_MAX_SSE_CONNECTIONS_PER_PEER
}

const fn default_max_sessions_per_instance() -> usize {
    DEFAULT_MAX_SESSIONS
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
            max_body_bytes: 8 * 1024 * 1024,
            rate_limit_rps: 200,
            rate_limit_burst: 400,
            max_concurrent_queries: 4,
            max_sse_connections: default_max_sse_connections(),
            max_sse_connections_per_peer: default_max_sse_connections_per_peer(),
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
            session_lru_cap: 10_000,
            max_sessions_per_instance: default_max_sessions_per_instance(),
            scheme_name: "raven-inspire".to_owned(),
            respond_timeout_secs: 30,
            trust_proxy_header: false,
            trusted_proxy_cidrs: Vec::new(),
            cors_allowed_origins: Vec::new(),
            metrics_public: false,
            session_eviction_interval_secs: DEFAULT_SESSION_TTL_SECS,
            enable_fanout: false,
            max_fanout_shards: default_max_fanout_shards(),
        }
    }

    /// Validate config; called by [`AppState::new`]. `Err` names the first failing
    /// invariant.
    pub fn validate(&self) -> Result<(), String> {
        if self.read_token.len() < Self::MIN_TOKEN_LEN {
            return Err(format!(
                "read_token too short: {} bytes (minimum {})",
                self.read_token.len(),
                Self::MIN_TOKEN_LEN
            ));
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
        if self.max_sse_connections == 0 {
            return Err(
                "max_sse_connections must be > 0; use a firewall to close /v1/events entirely"
                    .to_owned(),
            );
        }
        if self.max_sse_connections_per_peer == 0 {
            return Err(
                "max_sse_connections_per_peer must be > 0; use a firewall to close /v1/events \
                 entirely"
                    .to_owned(),
            );
        }
        self.validate_sessions()?;
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

    /// Packing-key store bounds for one instance, as this config sizes them. A store opened any
    /// other way keeps the compiled defaults.
    #[must_use]
    pub fn session_store_limits(&self) -> SessionStoreLimits {
        SessionStoreLimits {
            max_sessions: self.max_sessions_per_instance,
            ttl: Duration::from_secs(self.session_ttl_secs),
        }
    }

    fn validate_sessions(&self) -> Result<(), String> {
        if self.session_ttl_secs == 0 {
            return Err(
                "session_ttl_secs must be > 0; a zero lifetime issues handles that never serve"
                    .to_owned(),
            );
        }
        if self.session_ttl_secs > DEFAULT_SESSION_TTL_SECS {
            return Err(format!(
                "session_ttl_secs {} exceeds the {DEFAULT_SESSION_TTL_SECS} s ceiling: one handle \
                 links every query made under it, so lengthening it is a privacy decision, not an \
                 operator setting. Shorten it to free seats sooner",
                self.session_ttl_secs
            ));
        }
        if self.max_sessions_per_instance == 0 {
            return Err(
                "max_sessions_per_instance must be > 0; every handshake would be refused"
                    .to_owned(),
            );
        }
        if self.session_lru_cap < self.max_sessions_per_instance {
            return Err(format!(
                "session_lru_cap {} is below max_sessions_per_instance {}: the binding map would \
                 refuse handshakes the pool has seats for. Raise session_lru_cap to at least the \
                 per-instance seat count times the instance count",
                self.session_lru_cap, self.max_sessions_per_instance
            ));
        }
        Ok(())
    }

    /// Parse the trusted-proxy ranges, enforcing agreement with
    /// `trust_proxy_header`; empty when proxy trust is off.
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

    /// Adding a required field to a `Deserialize` struct breaks every previously valid
    /// serialized config, and it breaks it at an operator's boot rather than at our build.
    /// This pins that the new cap is optional and lands on its documented value.
    #[test]
    fn a_config_serialized_before_the_sse_cap_existed_still_loads() {
        let mut value = serde_json::to_value(config())
            .expect("a config serializes")
            .as_object()
            .cloned()
            .expect("an object");
        assert!(
            value.remove("max_sse_connections").is_some(),
            "the field must be present before removing it proves anything"
        );
        let restored: HttpConfig = serde_json::from_value(serde_json::Value::Object(value))
            .expect("loads without the cap");
        assert_eq!(restored.max_sse_connections, default_max_sse_connections());
        restored.validate().expect("and the default validates");
    }

    #[test]
    fn a_config_serialized_before_session_sizing_and_the_peer_cap_still_loads() {
        let mut value = serde_json::to_value(config())
            .expect("a config serializes")
            .as_object()
            .cloned()
            .expect("an object");
        for field in ["max_sessions_per_instance", "max_sse_connections_per_peer"] {
            assert!(
                value.remove(field).is_some(),
                "{field} must be present first"
            );
        }
        let restored: HttpConfig = serde_json::from_value(serde_json::Value::Object(value))
            .expect("loads without either field");
        assert_eq!(restored.max_sessions_per_instance, DEFAULT_MAX_SESSIONS);
        assert_eq!(
            restored.max_sse_connections_per_peer,
            default_max_sse_connections_per_peer()
        );
        restored.validate().expect("and the defaults validate");
    }

    #[test]
    fn session_store_limits_carry_the_configured_seats_and_lifetime() {
        let mut cfg = config();
        cfg.max_sessions_per_instance = 7;
        cfg.session_ttl_secs = 600;
        cfg.validate()
            .expect("a shorter lifetime and a smaller pool validate");
        assert_eq!(
            cfg.session_store_limits(),
            SessionStoreLimits {
                max_sessions: 7,
                ttl: Duration::from_secs(600),
            }
        );
    }

    #[test]
    fn session_sizing_at_its_bounds_validates() {
        let mut cfg = config();
        cfg.session_ttl_secs = DEFAULT_SESSION_TTL_SECS;
        cfg.max_sessions_per_instance = 1;
        cfg.session_lru_cap = 1;
        cfg.max_sse_connections_per_peer = 1;
        cfg.validate()
            .expect("the ceiling itself and one seat are legal");
        cfg.session_ttl_secs = 1;
        cfg.validate().expect("so is the shortest lifetime");
    }

    #[test]
    fn session_sizing_that_cannot_serve_is_refused_by_name() {
        type Breakage = fn(&mut HttpConfig);
        let cases: [(&str, Breakage); 5] = [
            ("session_ttl_secs", |c| c.session_ttl_secs = 0),
            ("session_ttl_secs", |c| {
                c.session_ttl_secs = DEFAULT_SESSION_TTL_SECS + 1;
            }),
            ("max_sessions_per_instance", |c| {
                c.max_sessions_per_instance = 0;
            }),
            ("session_lru_cap", |c| {
                c.session_lru_cap = c.max_sessions_per_instance - 1;
            }),
            ("max_sse_connections_per_peer", |c| {
                c.max_sse_connections_per_peer = 0;
            }),
        ];
        for (field, break_config) in cases {
            let mut cfg = config();
            break_config(&mut cfg);
            let err = cfg.validate().expect_err(field);
            assert!(err.contains(field), "{field}: {err}");
        }
    }

    /// Zero is not "unlimited" here, and reading it that way is the mistake this refuses.
    #[test]
    fn a_zero_sse_cap_is_refused_rather_than_read_as_unlimited() {
        let mut cfg = config();
        cfg.max_sse_connections = 0;
        let err = cfg.validate().expect_err("zero is refused");
        assert!(err.contains("max_sse_connections"), "{err}");
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
