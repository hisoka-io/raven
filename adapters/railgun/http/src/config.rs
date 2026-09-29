//! HTTP layer configuration.

use std::time::Duration;

use raven_railgun_engine::session_pool::{SessionStoreLimits, DEFAULT_MAX_SESSIONS};
use serde::{Deserialize, Serialize};

use crate::trusted_proxy::{resolve_declared_ranges, IpCidr};

/// Sanity ceiling for [`HttpConfig::max_body_bytes`]; rejected at validate time.
pub(crate) const HTTP_MAX_BODY_CEILING: usize = 64 * 1024 * 1024;

/// Default [`HttpConfig::respond_permit_wait_ms`]: this wait plus the default 30 s respond
/// timeout stays inside a wallet's 60 s request deadline.
pub const DEFAULT_RESPOND_PERMIT_WAIT_MS: u64 = 20_000;

/// Ceiling for [`HttpConfig::respond_permit_wait_ms`]: past a wallet's 60 s request deadline a
/// queued query is answered to nobody.
pub(crate) const HTTP_MAX_RESPOND_PERMIT_WAIT_MS: u64 = 60_000;

/// Default [`HttpConfig::session_lru_cap`]: every seat of the default pool on 156 instances.
pub const DEFAULT_SESSION_LRU_CAP: usize = 10_000;

/// Default and ceiling session lifetime in seconds; also the default eviction cadence.
pub const DEFAULT_SESSION_TTL_SECS: u64 =
    raven_railgun_engine::session_pool::DEFAULT_SESSION_TTL.as_secs();

/// HTTP layer configuration; all knobs are tunable without recompiling.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpConfig {
    /// Bearer token opening `/metrics` while [`HttpConfig::metrics_public`] is false, and
    /// required to be at least [`HttpConfig::MIN_TOKEN_LEN`] bytes only then. It gates nothing
    /// else: query, batch, session, params and status answer any caller.
    pub read_token: String,
    /// Maximum body bytes accepted by any route. Default 8 MiB.
    pub max_body_bytes: usize,
    /// Per-IP rate limit: max sustained requests per second.
    pub rate_limit_rps: u64,
    /// Per-IP rate limit: burst budget (token bucket capacity).
    pub rate_limit_burst: u32,
    /// Max concurrent in-flight respond operations. K=4 default.
    pub max_concurrent_queries: usize,
    /// Longest a query waits for one of the [`HttpConfig::max_concurrent_queries`] respond
    /// permits, in milliseconds, before it is answered 503. Applies to a single query, to each
    /// `/batch` slot, and to a session handshake's wait for a derivation permit. It bounds the
    /// queue without a per-peer cap, which would lock out every client sharing one exit address.
    /// Default [`DEFAULT_RESPOND_PERMIT_WAIT_MS`].
    #[serde(default = "default_respond_permit_wait_ms")]
    pub respond_permit_wait_ms: u64,
    /// Session handshakes deriving packing keys at once, each on a blocking thread. A handshake
    /// waits at most [`HttpConfig::respond_permit_wait_ms`] for one and is then answered 503,
    /// so a flood of them queues here rather than on the threads that serve every route.
    #[serde(default = "default_max_concurrent_handshakes")]
    pub max_concurrent_handshakes: usize,
    /// Session lifetime in seconds for a packing-key seat and its handle; see
    /// [`HttpConfig::session_store_limits`]. At most [`DEFAULT_SESSION_TTL_SECS`], because one
    /// handle links every query made under it.
    pub session_ttl_secs: u64,
    /// Sticky-session bindings across all instances. [`HttpConfig::validate`] requires one
    /// instance's full pool; [`HttpConfig::validate_for_instances`] requires every instance's,
    /// and [`crate::inspire_router`] applies it to the booted instances.
    pub session_lru_cap: usize,
    /// Packing-key seats per instance, and so a memory bound: a seat holds the server-derived
    /// keys, about 24 MiB at a 512 B row and 1.5 MiB at a 32 B row.
    #[serde(default = "default_max_sessions_per_instance")]
    pub max_sessions_per_instance: usize,
    /// Identifier surfaced in the `X-Raven-Scheme` response header.
    pub scheme_name: String,
    /// Per-query response timeout, also the bound on one handshake's key derivation. A timed-out
    /// respond or derivation keeps its permit until the detached work ends, since
    /// `spawn_blocking` cannot be cancelled.
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
}

fn default_session_eviction_interval_secs() -> u64 {
    DEFAULT_SESSION_TTL_SECS
}

/// Default [`HttpConfig::max_concurrent_handshakes`]. Derivations run in parallel, outside the
/// session store's lock, so this bounds the CPU that handshakes take from queries.
pub const DEFAULT_MAX_CONCURRENT_HANDSHAKES: usize = 2;

const fn default_max_concurrent_handshakes() -> usize {
    DEFAULT_MAX_CONCURRENT_HANDSHAKES
}

const fn default_respond_permit_wait_ms() -> u64 {
    DEFAULT_RESPOND_PERMIT_WAIT_MS
}

const fn default_max_sessions_per_instance() -> usize {
    DEFAULT_MAX_SESSIONS
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
            respond_permit_wait_ms: default_respond_permit_wait_ms(),
            max_concurrent_handshakes: default_max_concurrent_handshakes(),
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
            session_lru_cap: DEFAULT_SESSION_LRU_CAP,
            max_sessions_per_instance: default_max_sessions_per_instance(),
            scheme_name: "raven-inspire".to_owned(),
            respond_timeout_secs: 30,
            trust_proxy_header: false,
            trusted_proxy_cidrs: Vec::new(),
            cors_allowed_origins: Vec::new(),
            metrics_public: false,
            session_eviction_interval_secs: DEFAULT_SESSION_TTL_SECS,
        }
    }

    /// Validate config; called by [`crate::AppState::new`]. `Err` names the first failing
    /// invariant.
    pub fn validate(&self) -> Result<(), String> {
        if !self.metrics_public && self.read_token.len() < Self::MIN_TOKEN_LEN {
            return Err(format!(
                "read_token too short: {} bytes (minimum {}); it opens /metrics while \
                 metrics_public = false",
                self.read_token.len(),
                Self::MIN_TOKEN_LEN
            ));
        }
        for origin in &self.cors_allowed_origins {
            if origin == "*" {
                return Err(
                    "cors_allowed_origins must not contain `*`; list the wallet origins explicitly"
                        .to_owned(),
                );
            }
            if origin.is_empty() {
                return Err("cors_allowed_origins entry must not be empty".to_owned());
            }
        }
        if self.max_concurrent_handshakes == 0 {
            return Err(
                "max_concurrent_handshakes must be > 0; every session handshake would be refused"
                    .to_owned(),
            );
        }
        self.validate_sessions()?;
        self.validate_respond_permit_wait()?;
        if self.max_body_bytes == 0 {
            return Err("max_body_bytes must be > 0".to_owned());
        }
        if self.max_body_bytes > HTTP_MAX_BODY_CEILING {
            return Err(format!(
                "max_body_bytes too large: {} bytes (sanity ceiling {} bytes)",
                self.max_body_bytes, HTTP_MAX_BODY_CEILING
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
        self.validate_session_lru_cap(1)
    }

    /// [`HttpConfig::validate`], plus a binding map large enough for every seat of
    /// `instance_count` instances. The map is shared across instances, so sizing it for one
    /// pool refuses handshakes the others still have seats for.
    pub fn validate_for_instances(&self, instance_count: usize) -> Result<(), String> {
        self.validate()?;
        self.validate_session_lru_cap(instance_count)
    }

    fn validate_session_lru_cap(&self, instance_count: usize) -> Result<(), String> {
        let seats = self.max_sessions_per_instance;
        let Some(needed) = seats.checked_mul(instance_count) else {
            return Err(format!(
                "max_sessions_per_instance {seats} x {instance_count} instances overflows usize"
            ));
        };
        if self.session_lru_cap < needed {
            return Err(format!(
                "session_lru_cap {} is below max_sessions_per_instance {seats} x \
                 {instance_count} instance(s) = {needed}: the binding map would refuse \
                 handshakes the pools have seats for. Raise session_lru_cap to at least {needed}",
                self.session_lru_cap
            ));
        }
        Ok(())
    }

    fn validate_respond_permit_wait(&self) -> Result<(), String> {
        if self.respond_permit_wait_ms == 0 {
            return Err(
                "respond_permit_wait_ms must be > 0: zero is not unbounded, it refuses every \
                 query that finds all respond permits busy"
                    .to_owned(),
            );
        }
        if self.respond_permit_wait_ms > HTTP_MAX_RESPOND_PERMIT_WAIT_MS {
            return Err(format!(
                "respond_permit_wait_ms {} exceeds the {HTTP_MAX_RESPOND_PERMIT_WAIT_MS} ms \
                 ceiling: a wallet's request deadline passes first, so the query is answered to \
                 nobody",
                self.respond_permit_wait_ms
            ));
        }
        Ok(())
    }

    /// The permit wait as a [`Duration`].
    #[must_use]
    pub fn respond_permit_wait(&self) -> Duration {
        Duration::from_millis(self.respond_permit_wait_ms)
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

    #[test]
    fn a_config_serialized_before_session_sizing_and_the_handshake_cap_still_loads() {
        let mut value = serde_json::to_value(config())
            .expect("a config serializes")
            .as_object()
            .cloned()
            .expect("an object");
        for field in ["max_sessions_per_instance", "max_concurrent_handshakes"] {
            assert!(
                value.remove(field).is_some(),
                "{field} must be present first"
            );
        }
        let restored: HttpConfig = serde_json::from_value(serde_json::Value::Object(value))
            .expect("loads without either field");
        assert_eq!(restored.max_sessions_per_instance, DEFAULT_MAX_SESSIONS);
        assert_eq!(
            restored.max_concurrent_handshakes,
            DEFAULT_MAX_CONCURRENT_HANDSHAKES
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
        cfg.max_concurrent_handshakes = 1;
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
            ("max_concurrent_handshakes", |c| {
                c.max_concurrent_handshakes = 0;
            }),
        ];
        for (field, break_config) in cases {
            let mut cfg = config();
            break_config(&mut cfg);
            let err = cfg.validate().expect_err(field);
            assert!(err.contains(field), "{field}: {err}");
        }
    }

    /// `read_token` opens `/metrics` and nothing else, so a public `/metrics` needs none.
    #[test]
    fn a_public_metrics_endpoint_needs_no_read_token() {
        for token in ["", "short"] {
            let mut cfg = HttpConfig::demo(token);
            cfg.metrics_public = true;
            cfg.validate()
                .unwrap_or_else(|err| panic!("token {token:?} with public /metrics: {err}"));
        }
    }

    #[test]
    fn a_gated_metrics_endpoint_needs_a_full_length_read_token() {
        let short = "x".repeat(HttpConfig::MIN_TOKEN_LEN - 1);
        let err = HttpConfig::demo(short)
            .validate()
            .expect_err("a short token cannot gate /metrics");
        assert!(err.contains("read_token"), "{err}");
        assert!(err.contains("metrics_public"), "{err}");
        HttpConfig::demo("x".repeat(HttpConfig::MIN_TOKEN_LEN))
            .validate()
            .expect("the minimum length validates");
    }

    /// Nothing but `/metrics` is authenticated, so the refusal must not say otherwise.
    #[test]
    fn the_cors_wildcard_refusal_describes_the_server_truthfully() {
        let mut cfg = config();
        cfg.cors_allowed_origins = vec!["*".to_owned()];
        let err = cfg.validate().expect_err("a wildcard origin is refused");
        assert!(err.contains("cors_allowed_origins"), "{err}");
        assert!(!err.contains("authenticated"), "{err}");
    }

    #[test]
    fn the_binding_map_must_hold_every_instance_pool() {
        let mut cfg = config();
        cfg.max_sessions_per_instance = 64;
        cfg.session_lru_cap = 64 * 7 - 1;
        cfg.validate()
            .expect("one instance's pool fits, which is all validate can know");
        let err = cfg
            .validate_for_instances(7)
            .expect_err("seven pools do not fit");
        for needle in [
            "session_lru_cap 447",
            "max_sessions_per_instance 64",
            "7 instance",
            "448",
        ] {
            assert!(err.contains(needle), "{needle}: {err}");
        }
        cfg.session_lru_cap = 64 * 7;
        cfg.validate_for_instances(7)
            .expect("a map holding every seat validates");
    }

    #[test]
    fn a_seat_count_that_overflows_is_refused() {
        let mut cfg = config();
        cfg.max_sessions_per_instance = usize::MAX / 2 + 1;
        cfg.session_lru_cap = usize::MAX;
        cfg.validate().expect("one pool fits");
        let err = cfg.validate_for_instances(2).expect_err("two overflow");
        assert!(err.contains("overflows"), "{err}");
    }

    #[test]
    fn respond_permit_wait_is_bounded_on_both_sides() {
        let mut cfg = config();
        assert_eq!(cfg.respond_permit_wait_ms, DEFAULT_RESPOND_PERMIT_WAIT_MS);
        cfg.validate().expect("the default validates");
        for ms in [1, HTTP_MAX_RESPOND_PERMIT_WAIT_MS] {
            cfg.respond_permit_wait_ms = ms;
            cfg.validate().expect("bounds are legal");
            assert_eq!(cfg.respond_permit_wait(), Duration::from_millis(ms));
        }
        for ms in [0, HTTP_MAX_RESPOND_PERMIT_WAIT_MS + 1] {
            cfg.respond_permit_wait_ms = ms;
            let err = cfg.validate().expect_err("out of bounds");
            assert!(err.contains("respond_permit_wait_ms"), "{ms}: {err}");
        }
    }

    #[test]
    fn a_config_serialized_before_the_permit_wait_existed_still_loads() {
        let mut value = serde_json::to_value(config())
            .expect("a config serializes")
            .as_object()
            .cloned()
            .expect("an object");
        assert!(value.remove("respond_permit_wait_ms").is_some());
        let restored: HttpConfig = serde_json::from_value(serde_json::Value::Object(value))
            .expect("loads without the wait");
        assert_eq!(
            restored.respond_permit_wait_ms,
            DEFAULT_RESPOND_PERMIT_WAIT_MS
        );
        restored.validate().expect("and the default validates");
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
