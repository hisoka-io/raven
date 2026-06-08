//! Per-endpoint heterogeneous TOML loader: each `[[rpc_endpoint]]` carries its
//! own rps/burst, unlike `RpcPoolConfigToml` which bakes one budget pool-wide.
//!
//! ```toml
//! [[rpc_endpoint]]
//! url   = "https://eth-mainnet.example/v1/<key>"
//! rps   = 200
//! burst = 400
//!
//! [rpc_pool]
//! strategy               = "round-robin"
//! cooldown_secs_on_error = 30
//!
//! [ws_endpoints]
//! urls = ["wss://primary-ws.example/"]
//! ```

use serde::Deserialize;
use std::path::Path;

use raven_railgun_indexer::rpc_pool::{
    EndpointConfig, PoolConfig, PoolStrategy, RpcEndpointPool, DEFAULT_COOLDOWN_SECS,
};

/// Per-endpoint heterogeneous entry.
#[derive(Debug, Clone, Deserialize)]
pub struct EndpointEntry {
    pub url: String,
    pub rps: u32,
    pub burst: u32,
}

/// Pool-wide knobs.
#[derive(Debug, Clone, Deserialize)]
pub struct PoolMeta {
    #[serde(default = "default_strategy")]
    pub strategy: String,
    #[serde(default = "default_cooldown")]
    pub cooldown_secs_on_error: u64,
}

fn default_strategy() -> String {
    "round-robin".to_owned()
}

fn default_cooldown() -> u64 {
    DEFAULT_COOLDOWN_SECS
}

/// Optional `[ws_endpoints]` block.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct WsConfig {
    #[serde(default)]
    pub urls: Vec<String>,
}

/// Top-level array-shaped pool config consumed by the bootstrap subcommand.
#[derive(Debug, Clone, Deserialize)]
pub struct RpcEndpointArrayConfig {
    pub rpc_endpoint: Vec<EndpointEntry>,
    #[serde(default = "default_pool_meta")]
    pub rpc_pool: PoolMeta,
    #[serde(default)]
    pub ws_endpoints: WsConfig,
}

fn default_pool_meta() -> PoolMeta {
    PoolMeta {
        strategy: default_strategy(),
        cooldown_secs_on_error: default_cooldown(),
    }
}

/// Errors surfaced by the loader.
#[derive(Debug, thiserror::Error)]
pub enum RpcPoolArrayError {
    #[error("read {path}: {error}")]
    Read { path: String, error: String },
    #[error("parse toml: {0}")]
    Parse(String),
    #[error("rpc_endpoint array is empty (need at least 1 entry)")]
    Empty,
    #[error("rpc_endpoint[{index}].url is empty")]
    UrlEmpty { index: usize },
    #[error("rpc_endpoint[{index}].rps must be >= 1 (got {value})")]
    RpsZero { index: usize, value: u32 },
    #[error("rpc_endpoint[{index}].burst must be >= 1 (got {value})")]
    BurstZero { index: usize, value: u32 },
    #[error("rpc_pool.strategy '{0}' is not one of: round-robin, primary-with-failover")]
    UnknownStrategy(String),
    #[error("ws_endpoints.urls[{0}] is empty")]
    WsEmpty(usize),
    #[error("build pool: {0}")]
    Pool(String),
}

impl RpcEndpointArrayConfig {
    /// Load + validate the config from disk.
    pub fn load_from_path(path: &Path) -> Result<Self, RpcPoolArrayError> {
        let raw = std::fs::read_to_string(path).map_err(|e| RpcPoolArrayError::Read {
            path: path.display().to_string(),
            error: e.to_string(),
        })?;
        Self::load_from_str(&raw)
    }

    /// Parse + validate from a TOML string.
    pub fn load_from_str(raw: &str) -> Result<Self, RpcPoolArrayError> {
        let parsed: Self =
            toml::from_str(raw).map_err(|e| RpcPoolArrayError::Parse(e.to_string()))?;
        parsed.validate()?;
        Ok(parsed)
    }

    fn validate(&self) -> Result<(), RpcPoolArrayError> {
        if self.rpc_endpoint.is_empty() {
            return Err(RpcPoolArrayError::Empty);
        }
        for (i, e) in self.rpc_endpoint.iter().enumerate() {
            if e.url.trim().is_empty() {
                return Err(RpcPoolArrayError::UrlEmpty { index: i });
            }
            if e.rps == 0 {
                return Err(RpcPoolArrayError::RpsZero {
                    index: i,
                    value: e.rps,
                });
            }
            if e.burst == 0 {
                return Err(RpcPoolArrayError::BurstZero {
                    index: i,
                    value: e.burst,
                });
            }
        }
        match self.rpc_pool.strategy.as_str() {
            "round-robin" | "primary-with-failover" => {}
            other => return Err(RpcPoolArrayError::UnknownStrategy(other.to_owned())),
        }
        for (i, u) in self.ws_endpoints.urls.iter().enumerate() {
            if u.trim().is_empty() {
                return Err(RpcPoolArrayError::WsEmpty(i));
            }
        }
        Ok(())
    }

    /// Materialise into an `RpcEndpointPool`; per-endpoint rps/burst flow
    /// through unclamped so heterogeneous budgets reach the limiter.
    pub fn build_pool(&self) -> Result<RpcEndpointPool, RpcPoolArrayError> {
        let strategy = match self.rpc_pool.strategy.as_str() {
            "round-robin" => PoolStrategy::RoundRobin,
            "primary-with-failover" => PoolStrategy::PrimaryWithFailover,
            other => return Err(RpcPoolArrayError::UnknownStrategy(other.to_owned())),
        };
        let endpoint_configs: Vec<EndpointConfig> = self
            .rpc_endpoint
            .iter()
            .map(|e| EndpointConfig {
                url: e.url.clone(),
                rps: e.rps,
                burst: e.burst,
            })
            .collect();
        let pool_config = PoolConfig {
            strategy,
            cooldown_secs_on_error: self.rpc_pool.cooldown_secs_on_error.max(1),
            ..PoolConfig::default()
        };
        RpcEndpointPool::new(endpoint_configs, pool_config)
            .map_err(|e| RpcPoolArrayError::Pool(e.to_string()))
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::expect_used)]
mod tests {
    use super::*;

    fn good_toml() -> &'static str {
        r#"
[[rpc_endpoint]]
url   = "https://primary.example"
rps   = 200
burst = 400

[[rpc_endpoint]]
url   = "https://secondary.example"
rps   = 5
burst = 10

[rpc_pool]
strategy = "round-robin"
cooldown_secs_on_error = 45

[ws_endpoints]
urls = ["wss://primary-ws.example/"]
"#
    }

    #[test]
    fn loads_and_preserves_per_endpoint_rps_burst() {
        let cfg = RpcEndpointArrayConfig::load_from_str(good_toml()).expect("loads");
        assert_eq!(cfg.rpc_endpoint.len(), 2);
        assert_eq!(cfg.rpc_endpoint[0].rps, 200);
        assert_eq!(cfg.rpc_endpoint[0].burst, 400);
        assert_eq!(cfg.rpc_endpoint[1].rps, 5);
        assert_eq!(cfg.rpc_endpoint[1].burst, 10);
        assert_eq!(cfg.rpc_pool.cooldown_secs_on_error, 45);
        assert_eq!(cfg.ws_endpoints.urls.len(), 1);
        let pool = cfg.build_pool().expect("pool");
        assert_eq!(pool.endpoints().len(), 2);
        assert_eq!(pool.endpoints()[0].rps(), 200);
        assert_eq!(pool.endpoints()[1].rps(), 5);
    }

    #[test]
    fn rejects_zero_rps() {
        let bad = r#"
[[rpc_endpoint]]
url = "https://x"
rps = 0
burst = 1
"#;
        let err = RpcEndpointArrayConfig::load_from_str(bad).expect_err("must reject");
        assert!(matches!(err, RpcPoolArrayError::RpsZero { .. }));
    }

    #[test]
    fn rejects_unknown_strategy() {
        let bad = r#"
[[rpc_endpoint]]
url = "https://x"
rps = 1
burst = 1

[rpc_pool]
strategy = "least-loaded"
"#;
        let err = RpcEndpointArrayConfig::load_from_str(bad).expect_err("must reject");
        assert!(matches!(err, RpcPoolArrayError::UnknownStrategy(_)));
    }

    #[test]
    fn rejects_empty_endpoint_array() {
        let bad = r#"
[rpc_pool]
strategy = "round-robin"
"#;
        // serde rejects the missing field, so this is `Parse`, not `Empty`.
        let err = RpcEndpointArrayConfig::load_from_str(bad).expect_err("must reject");
        assert!(matches!(err, RpcPoolArrayError::Parse(_)));
    }

    #[test]
    fn defaults_pool_meta_when_section_omitted() {
        let raw = r#"
[[rpc_endpoint]]
url   = "https://only.example"
rps   = 50
burst = 100
"#;
        let cfg = RpcEndpointArrayConfig::load_from_str(raw).expect("loads");
        assert_eq!(cfg.rpc_pool.strategy, "round-robin");
        assert_eq!(cfg.rpc_pool.cooldown_secs_on_error, DEFAULT_COOLDOWN_SECS);
    }
}
