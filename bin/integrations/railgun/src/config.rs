use std::env;
use std::time::Duration;

/// Railgun V2 commitments subgraph for Ethereum mainnet
/// (`wallet/src/services/railgun/quick-sync/V2/graphql/.graphclientrc.yaml`).
const DEFAULT_SUBGRAPH_URL: &str =
    "https://rail-squid.squids.live/squid-railgun-ethereum-v2/graphql";

const DEFAULT_POLL_INTERVAL_MS: u64 = 5_000;

#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub(crate) subgraph_url: url::Url,
    pub(crate) poll_interval: Duration,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    #[error("RAILGUN_SUBGRAPH is not a valid URL: {0}")]
    InvalidSubgraph(String),
    #[error("RAILGUN_POLL_MS is not a valid u64: {0}")]
    InvalidPollMs(String),
}

impl Config {
    pub(crate) fn from_env() -> Result<Self, ConfigError> {
        let subgraph_url = env::var("RAILGUN_SUBGRAPH")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_SUBGRAPH_URL.to_owned());
        let subgraph_url = url::Url::parse(&subgraph_url)
            .map_err(|e| ConfigError::InvalidSubgraph(e.to_string()))?;

        let poll_interval_ms = match env::var("RAILGUN_POLL_MS") {
            Ok(v) if !v.is_empty() => {
                v.parse::<u64>().map_err(|_| ConfigError::InvalidPollMs(v))?
            }
            _ => DEFAULT_POLL_INTERVAL_MS,
        };

        Ok(Self { subgraph_url, poll_interval: Duration::from_millis(poll_interval_ms) })
    }
}
