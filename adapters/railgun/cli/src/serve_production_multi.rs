//! Boots N PIR instances from one TOML config onto a single axum router.

#![allow(clippy::too_many_lines, clippy::missing_errors_doc)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::bearer_token::{resolve_bearer_token, BearerTokenError, BEARER_TOKEN_ENV};
use anyhow::Context;
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::ServerCrs;
use raven_railgun_core::{InstanceId, ListKey};
use raven_railgun_engine::inspire::{setup_unfilled_state, LogicalLeafStore, RavenInspireScheme};
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine_multi_with_session_limits, DataSourceFilter, InstanceConfig,
    MultiOrchestratorHandle, OrchestratorChannels, PerInstanceHandles, LEAVES_PER_PPOI_BLOCK,
};
use raven_railgun_engine::persistence::{ConsumerMetrics, SnapshotPolicy};
use raven_railgun_engine::pir_table::{empty_store_shard, EncoderKind};
use raven_railgun_engine::session_pool::SessionStoreLimits;
use raven_railgun_engine::{Engine, InstanceRole};
use raven_railgun_http::{
    inspire_router, trusted_proxy::resolve_declared_ranges, AppState, HttpConfig,
};
use serde::Deserialize;

/// Optional `[auto_spawn]` TOML section.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AutoSpawnConfigToml {
    #[serde(default)]
    pub enabled: bool,
    /// Must contain `{tree_number}`.
    #[serde(default)]
    pub data_dir_template: String,
    #[serde(default)]
    pub encoder: String,
    #[serde(default)]
    pub scheme_tag: String,
    #[serde(default = "default_auto_spawn_entries")]
    pub entries: usize,
    #[serde(default = "default_auto_spawn_entry_bytes")]
    pub entry_bytes: usize,
    /// Cap on live chain-tree instances; `None` = unlimited.
    #[serde(default)]
    pub max_instance_count: Option<u32>,
    /// Minimum seconds between spawns; `None` / `0` = no cooldown.
    #[serde(default)]
    pub cooldown_seconds: Option<u32>,
}

fn default_auto_spawn_entries() -> usize {
    DEFAULT_PRODUCTION_ENTRIES
}

fn default_auto_spawn_entry_bytes() -> usize {
    DEFAULT_PRODUCTION_ENTRY_BYTES
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    global: GlobalSection,
    #[serde(default)]
    instance: Vec<InstanceSection>,
    #[serde(default)]
    auto_spawn: AutoSpawnConfigToml,
    #[serde(default)]
    rpc_pool: Option<RpcPoolConfigToml>,
    #[serde(default)]
    instance_template: Vec<InstanceTemplateToml>,
}

/// One `[[instance_template]]` row.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct InstanceTemplateToml {
    pub template_id: String,
    pub encoder: String,
    #[serde(default)]
    pub scheme_tag: String,
    /// Must contain `{tree_number}`.
    pub data_dir_template: String,
    #[serde(default)]
    pub k_concurrency: u32,
    /// Cap on live instances; `None` = unlimited.
    #[serde(default)]
    pub max_instance_count: Option<u32>,
    /// Minimum seconds between spawns; `None` / `0` = no cooldown.
    #[serde(default)]
    pub cooldown_seconds: Option<u32>,
    #[serde(default)]
    pub entries: usize,
    #[serde(default)]
    pub entry_bytes: usize,
    #[serde(default = "default_snapshot_policy_label")]
    pub snapshot_policy: String,
    #[serde(default)]
    pub tree_fill_threshold: Option<f32>,
}

fn default_snapshot_policy_label() -> String {
    "live_default".to_owned()
}

/// Optional `[rpc_pool]` TOML section.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcPoolConfigToml {
    pub urls: Vec<String>,
    #[serde(default = "default_pool_strategy")]
    pub strategy: PoolStrategyString,
    #[serde(default = "default_per_endpoint_rps")]
    pub per_endpoint_rps: u32,
    #[serde(default = "default_per_endpoint_burst")]
    pub per_endpoint_burst: u32,
    #[serde(default = "default_cooldown_secs")]
    pub cooldown_secs: u32,
}

fn default_per_endpoint_rps() -> u32 {
    50
}

fn default_per_endpoint_burst() -> u32 {
    100
}

fn default_cooldown_secs() -> u32 {
    30
}

fn default_pool_strategy() -> PoolStrategyString {
    PoolStrategyString::RoundRobin
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PoolStrategyString {
    RoundRobin,
    PrimaryWithFailover,
}

impl From<PoolStrategyString> for raven_railgun_indexer::rpc_pool::PoolStrategy {
    fn from(s: PoolStrategyString) -> Self {
        match s {
            PoolStrategyString::RoundRobin => Self::RoundRobin,
            PoolStrategyString::PrimaryWithFailover => Self::PrimaryWithFailover,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GlobalSection {
    bind: SocketAddr,
    /// Mutually exclusive with `token_file` and [`BEARER_TOKEN_ENV`]; forces a
    /// 600-mode config file.
    #[serde(default)]
    token: Option<String>,
    /// 600-mode file holding the bearer token; the production path.
    #[serde(default)]
    token_file: Option<PathBuf>,
    /// Required by a config that reads the chain (a commit-tree instance, `[auto_spawn]`, or a
    /// chain-encoder `[[instance_template]]`), and refused by one that does not.
    #[serde(default)]
    rpc_url: Option<String>,
    /// Required or refused together with `rpc_url`.
    #[serde(default)]
    railgun_proxy: Option<String>,
    /// The chain the indexer reads and the one whose PPOI lists the mirror asks upstream for.
    chain_id: u64,
    /// Required or refused together with `rpc_url`.
    #[serde(default)]
    start_block: Option<u64>,
    mirror_endpoint: String,
    /// Seconds between mirror pages while upstream answers full ones: a cold sync. A short,
    /// empty or failed page waits the poll interval. Absent, a full page is followed at once.
    #[serde(default)]
    mirror_backfill_interval_secs: Option<u64>,
    #[serde(default)]
    max_concurrent_queries: Option<usize>,
    /// Longest a query, batch slot or handshake waits for a permit before a 503.
    #[serde(default)]
    respond_permit_wait_ms: Option<u64>,
    #[serde(default)]
    respond_timeout_secs: Option<u64>,
    #[serde(default)]
    record_size: Option<usize>,
    #[serde(default)]
    entries_per_shard: Option<u32>,
    #[serde(default)]
    scheme_tag: Option<String>,
    #[serde(default)]
    use_flock: Option<bool>,
    #[serde(default)]
    channel_capacity: Option<usize>,
    /// Global fallback ceiling on chain-tree instances; per-template value overrides this.
    #[serde(default)]
    max_instance_count: Option<u32>,
    #[serde(default)]
    tree_fill_threshold: Option<f32>,
    /// WS primary transport; HTTP RPC (or pool) becomes automatic fallback.
    #[serde(default)]
    ws_endpoint: Option<String>,
    /// Per-IP rate limit (requests/sec); defaults to the `HttpConfig` value.
    #[serde(default)]
    rate_limit_rps: Option<u64>,
    /// Per-IP burst budget (token-bucket capacity).
    #[serde(default)]
    rate_limit_burst: Option<u32>,
    /// CORS allow-origin list; empty leaves CORS off. `*` and empty strings are rejected.
    #[serde(default)]
    cors_allowed_origins: Option<Vec<String>>,
    /// Trust `X-Forwarded-For` / `cf-connecting-ip`; requires `trusted_proxy_cidrs`.
    #[serde(default)]
    trust_proxy_header: Option<bool>,
    /// Peer ranges (CIDR) whose forwarding headers are honoured. Every other
    /// peer keys to its own socket address.
    #[serde(default)]
    trusted_proxy_cidrs: Option<Vec<String>>,
    /// Expose `/metrics` without bearer auth (default-deny).
    #[serde(default)]
    metrics_public: Option<bool>,
    /// Heartbeat session-eviction interval (seconds); `0` disables.
    #[serde(default)]
    session_eviction_interval_secs: Option<u64>,
    /// Packing-key seats per instance, auto-spawned ones included.
    #[serde(default)]
    max_sessions_per_instance: Option<usize>,
    /// Seat and handle lifetime in seconds; may only be lowered from the default.
    #[serde(default)]
    session_ttl_secs: Option<u64>,
    /// Sticky-session bindings across all instances; must hold every instance's seats.
    #[serde(default)]
    session_lru_cap: Option<usize>,
    /// Session handshakes deriving packing keys at once.
    #[serde(default)]
    max_concurrent_handshakes: Option<usize>,
    /// Layer 1 reorg-window cache sidecar; absent = ephemeral (rebuilt from RPC).
    #[serde(default)]
    reorg_window_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstanceSection {
    id: String,
    role: RoleString,
    encoder: EncoderString,
    #[serde(default)]
    tree_number: Option<u32>,
    #[serde(default)]
    list_key: Option<String>,
    data_dir: PathBuf,
    data_source: DataSourceSection,
    #[serde(default)]
    max_concurrent_queries: Option<usize>,
    /// Cell width for this instance; overrides `[global].record_size`.
    #[serde(default)]
    record_size: Option<usize>,
    /// Cell row count for this instance; defaults to the encoder's canonical total.
    #[serde(default)]
    entries: Option<usize>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RoleString {
    Static,
    Live,
    Sidecar,
}

impl From<RoleString> for InstanceRole {
    fn from(role: RoleString) -> Self {
        match role {
            RoleString::Static => Self::Static,
            RoleString::Live => Self::Live,
            RoleString::Sidecar => Self::Sidecar,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[allow(clippy::enum_variant_names)]
enum EncoderString {
    PerLeafBc,
    PerLeafPath,
    PerNode,
    PerListPath10,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum DataSourceSection {
    Indexer {
        filter: IndexerFilterSection,
    },
    /// One 65,536-row block of a list; `block` N holds list-wide rows from N x 65,536.
    Mirror {
        list_key: String,
        block: u32,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexerFilterSection {
    tree_number: u32,
}

/// Operator-facing args for the multi-instance path.
#[derive(Debug, Clone)]
pub struct MultiServeOptions {
    pub bind: SocketAddr,
    /// Opens `/metrics`. Empty when no source was set, which boot refuses unless `/metrics` is public.
    pub token: String,
    /// Empty when the config reads nothing off the chain; no indexer dials it then.
    pub rpc_url: String,
    /// Empty when the config reads nothing off the chain.
    pub railgun_proxy: String,
    pub chain_id: u64,
    /// Zero when the config reads nothing off the chain.
    pub start_block: u64,
    pub mirror_endpoint: String,
    /// `[global].mirror_backfill_interval_secs`; `None` keeps the mirror's 1 s request spacing, 0 only for a local replay.
    pub mirror_backfill_interval_secs: Option<u64>,
    pub max_concurrent_queries: usize,
    pub respond_timeout_secs: u64,
    pub instances: Vec<InstanceConfig>,
    /// Tests set this to skip the live RPC + indexer worker. Unset, the indexer still starts
    /// only when [`chain_indexer_reason`] names a reader.
    pub skip_chain_workers: bool,
    pub skip_mirror_workers: bool,
    /// Fallback for instances absent from `instance_entries`.
    pub entries: usize,
    /// Resolved cell row count per configured instance.
    pub instance_entries: HashMap<InstanceId, usize>,
    /// Tests set this to drive synthetic events without spinning workers.
    pub bootstrap_observer: Option<BootstrapObserver>,
    pub auto_spawn: Option<AutoSpawnConfigToml>,
    pub rpc_pool: Option<RpcPoolConfigToml>,
    pub instance_templates: Vec<InstanceTemplateToml>,
    pub tree_fill_threshold: Option<f32>,
    /// When `Some` on Unix, installs a SIGHUP handler for TOML hot-reload.
    pub reload_config_path: Option<PathBuf>,
    /// Primary indexer transport; HTTP RPC is the fallback.
    pub ws_endpoint: Option<String>,
    /// `HttpConfig.rate_limit_rps` override (`None` keeps the demo default).
    pub rate_limit_rps: Option<u64>,
    /// `HttpConfig.rate_limit_burst` override (`None` keeps the demo default).
    pub rate_limit_burst: Option<u32>,
    /// `HttpConfig.cors_allowed_origins` override. Empty `Vec` is the same as `None`.
    pub cors_allowed_origins: Option<Vec<String>>,
    /// `HttpConfig.trust_proxy_header` override.
    pub trust_proxy_header: Option<bool>,
    /// `HttpConfig.trusted_proxy_cidrs` override. Empty `Vec` is the same as `None`.
    pub trusted_proxy_cidrs: Option<Vec<String>>,
    /// `HttpConfig.metrics_public` override.
    pub metrics_public: Option<bool>,
    /// `HttpConfig.session_eviction_interval_secs` override; drives the per-instance ticker.
    pub session_eviction_interval_secs: Option<u64>,
    /// `HttpConfig.respond_permit_wait_ms` override.
    pub respond_permit_wait_ms: Option<u64>,
    /// Indexer Layer 1 reorg-window cache path; absent = ephemeral.
    pub reorg_window_path: Option<PathBuf>,
    /// Session seats, lifetime, bindings and handshake concurrency; absent keys keep the defaults.
    pub session_capacity: SessionCapacity,
    /// From the stop signal to exit; [`STOP_BUDGET`] unless a test lifts it to bound its stop by
    /// progress instead.
    pub stop_budget: std::time::Duration,
}

pub type BootstrapObserver = Arc<parking_lot::Mutex<Option<BootstrapView>>>;

#[derive(Clone)]
pub struct BootstrapView {
    pub channels: OrchestratorChannels,
    pub instances: Vec<BootstrapInstanceView>,
}

#[derive(Clone)]
pub struct BootstrapInstanceView {
    pub instance_id: InstanceId,
    pub encoder_label: &'static str,
    pub data_source: DataSourceFilter,
    pub role: InstanceRole,
    pub metrics: Arc<parking_lot::Mutex<ConsumerMetrics>>,
    pub logical_store: Arc<parking_lot::Mutex<LogicalLeafStore>>,
}

impl std::fmt::Debug for BootstrapView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapView")
            .field("instance_count", &self.instances.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for BootstrapInstanceView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapInstanceView")
            .field("instance_id", &self.instance_id)
            .field("encoder_label", &self.encoder_label)
            .field("data_source", &self.data_source)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

/// Operator bounds on what anonymous callers can hold: packing-key seats per instance, how
/// long a seat lives, the bindings that name them, and handshakes deriving at once. Every store
/// the serve path opens takes its limits from [`HttpConfig::session_store_limits`] of the same
/// config, so the HTTP layer and the stores cannot disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionCapacity {
    pub max_sessions_per_instance: usize,
    /// Refused above [`raven_railgun_http::config::DEFAULT_SESSION_TTL_SECS`].
    pub session_ttl_secs: u64,
    pub session_lru_cap: usize,
    pub max_concurrent_handshakes: usize,
}

impl Default for SessionCapacity {
    fn default() -> Self {
        Self {
            max_sessions_per_instance: raven_railgun_engine::session_pool::DEFAULT_MAX_SESSIONS,
            session_ttl_secs: raven_railgun_http::config::DEFAULT_SESSION_TTL_SECS,
            session_lru_cap: raven_railgun_http::config::DEFAULT_SESSION_LRU_CAP,
            max_concurrent_handshakes:
                raven_railgun_http::config::DEFAULT_MAX_CONCURRENT_HANDSHAKES,
        }
    }
}

impl SessionCapacity {
    pub fn apply_to(&self, config: &mut HttpConfig) {
        config.max_sessions_per_instance = self.max_sessions_per_instance;
        config.session_ttl_secs = self.session_ttl_secs;
        config.session_lru_cap = self.session_lru_cap;
        config.max_concurrent_handshakes = self.max_concurrent_handshakes;
    }
}

/// Per-leaf cell: 65,536 rows x 512 B (16 siblings x 32 B). Per-node encoders
/// derive a different shape from `TREE_DEPTH`.
pub const DEFAULT_PRODUCTION_ENTRIES: usize = 65_536;
pub const DEFAULT_PRODUCTION_ENTRY_BYTES: usize = 512;

/// Bound on the one request that decides whether the configured upstream can feed the mirror.
pub const MIRROR_PREFLIGHT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Boots that went on to serve local rows past an upstream that failed its preflight.
pub const MIRROR_PREFLIGHT_FAILED_TOTAL: &str = "raven_railgun_ppoi_mirror_preflight_failed_total";

pub(crate) fn ensure_mirror_preflight_metrics_described() {
    metrics::describe_counter!(
        MIRROR_PREFLIGHT_FAILED_TOTAL,
        metrics::Unit::Count,
        "Count of PPOI lists whose upstream failed the boot preflight while this node had \
         rows to serve, so it booted and serves them with no feed. Non-zero means the list \
         stops advancing until the upstream answers; the boot log names the endpoint and the \
         failure class."
    );
    metrics::counter!(MIRROR_PREFLIGHT_FAILED_TOTAL).increment(0);
}

/// One bounded request to the configured upstream, refused only when `can_serve_without_it`
/// is false. The worker warns and retries forever, so this is the one place a node with
/// nothing to serve can be stopped from booting clean and serving nothing. A node with rows
/// keeps serving: an upstream outage must not become this node's outage.
///
/// Counts into the recorder `AppState::new` installs, so it has to run after that.
pub(crate) async fn preflight_mirror_upstream(
    mirror: &raven_railgun_ppoi_mirror::UpstreamPpoiMirror,
    list: &ListKey,
    can_serve_without_it: bool,
    endpoint_setting: &str,
) -> anyhow::Result<()> {
    let Err(refusal) = mirror.preflight(list, MIRROR_PREFLIGHT_TIMEOUT).await else {
        return Ok(());
    };
    if !can_serve_without_it {
        anyhow::bail!(
            "{refusal}; this node holds no rows for list {} and would serve nothing: fix \
             {endpoint_setting}",
            hex::encode(list.0)
        );
    }
    metrics::counter!(MIRROR_PREFLIGHT_FAILED_TOTAL).increment(1);
    tracing::error!(
        error = %refusal,
        list_key = %hex::encode(list.0),
        "ppoi upstream failed its boot preflight; serving local rows with no feed"
    );
    Ok(())
}

/// The `list_key` a per-list encoder is pinned to, `None` for the chain-tree kinds.
///
/// EXHAUSTIVE: a new variant must state whether it pins a list rather than inherit whichever
/// arm a `_` put it in.
pub(crate) fn pinned_list_key(encoder: EncoderKind) -> Option<[u8; 32]> {
    match encoder {
        EncoderKind::PerListPath10 { list_key } => Some(list_key),
        // Pinned to a tree, not a list; `enforce_encoder_matches_data_source` gates those.
        EncoderKind::PerLeafBc { .. }
        | EncoderKind::PerLeafPath { .. }
        | EncoderKind::PerNode { .. } => None,
    }
}

/// Refuse a boot whose per-list encoder pins a different list than the one routed to it.
///
/// Every per-list encoder drops `affected_shards_for_ppoi_leaf` for a foreign `list_key` and
/// materializes from `store.ppoi_imt(&self.list_key)`, so a diverged pin reads an IMT nothing
/// ever writes: the cell stays all-zero and is served at HTTP 200 forever, with no refusal and
/// no counter. Boot is the only place that is visible.
pub(crate) fn enforce_encoder_list_key(
    instance_id: &str,
    encoder: EncoderKind,
    routed: &[u8; 32],
    routed_setting: &str,
) -> anyhow::Result<()> {
    let Some(pinned) = pinned_list_key(encoder) else {
        return Ok(());
    };
    anyhow::ensure!(
        pinned == *routed,
        "instance {instance_id:?}: encoder {label} pins list_key {pinned_hex} but \
         {routed_setting} gives list_key {routed_hex}. The encoder drops every event for a \
         list other than its own, so this instance would serve an all-zero cell at HTTP 200 \
         and never advance. Operator: set the encoder's list_key and {routed_setting} to the \
         same 64-hex value.",
        label = encoder.label(),
        pinned_hex = hex::encode(pinned),
        routed_hex = hex::encode(routed),
    );
    Ok(())
}

/// Logs a configured width the encoder's row layout overrides.
pub(crate) fn warn_on_record_size_override(
    encoder: EncoderKind,
    requested: usize,
    effective: usize,
) {
    if requested == effective {
        return;
    }
    tracing::warn!(
        encoder = encoder.label(),
        requested_record_size = requested,
        effective_record_size = effective,
        "encoder layout pins the record width; the configured width is ignored"
    );
}

const SCHEME_TAG_DEFAULT: &str = raven_railgun_engine::persistence::SCHEME_TAG;

/// Without the lock a second node, or a restart racing the old process, opens the same data_dir
/// and both write it.
fn warn_writer_lock_disabled(config: &Path) {
    tracing::error!(
        config = %config.display(),
        "[global].use_flock = false: every data_dir opens without its writer lock, so nothing \
         stops a second process from writing it at the same time. Remove the key to take the lock"
    );
}

pub fn load_options_from_toml(path: &Path) -> anyhow::Result<MultiServeOptions> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read config file: {}", path.display()))?;
    let parsed: ConfigFile =
        toml::from_str(&body).with_context(|| format!("parse config file: {}", path.display()))?;

    if parsed.instance.is_empty() {
        anyhow::bail!("config file has no [[instance]] tables: {}", path.display());
    }

    let scheme_tag = parsed
        .global
        .scheme_tag
        .clone()
        .unwrap_or_else(|| SCHEME_TAG_DEFAULT.to_owned());
    let fallback_record_size = parsed.global.record_size.unwrap_or(16 * 32);
    let entries_per_shard = parsed.global.entries_per_shard.unwrap_or(2048);
    let use_flock = parsed.global.use_flock.unwrap_or(true);
    if !use_flock {
        warn_writer_lock_disabled(path);
    }
    let channel_capacity = parsed.global.channel_capacity.unwrap_or(1024);

    let mut instances: Vec<InstanceConfig> = Vec::with_capacity(parsed.instance.len());
    let mut instance_entries: HashMap<InstanceId, usize> =
        HashMap::with_capacity(parsed.instance.len());
    for raw in parsed.instance {
        let role: InstanceRole = raw.role.into();
        let encoder = build_encoder_kind(raw.encoder, raw.tree_number, raw.list_key.as_deref())?;
        let data_source = build_data_source(&raw.data_source)?;
        enforce_encoder_matches_data_source(&raw.id, encoder, &data_source)?;
        let snapshot_policy = match role {
            InstanceRole::Static => SnapshotPolicy::static_default(),
            _ => SnapshotPolicy::default(),
        };
        // Verbatim so `validate_cell_shape` rejects a conflict instead of substituting.
        let record_size = raw.record_size.unwrap_or_else(|| {
            let effective = encoder.effective_record_size(fallback_record_size);
            warn_on_record_size_override(encoder, fallback_record_size, effective);
            effective
        });
        let instance_id = InstanceId::new(raw.id);
        instance_entries.insert(
            instance_id.clone(),
            raw.entries
                .unwrap_or_else(|| encoder.default_total_entries()),
        );
        instances.push(InstanceConfig {
            instance_id,
            role,
            data_dir: raw.data_dir,
            encoder,
            record_size,
            entries_per_shard,
            data_source,
            use_flock,
            snapshot_policy,
            scheme_tag: scheme_tag.clone(),
            channel_capacity,
            max_concurrent_queries: raw.max_concurrent_queries,
            verification_cadence_n: 0,
            chain_source: None,
        });
    }

    for tpl in &parsed.instance_template {
        if tpl.template_id.trim().is_empty() {
            anyhow::bail!("[[instance_template]] requires non-empty template_id");
        }
        if tpl.encoder.trim().is_empty() {
            anyhow::bail!(
                "[[instance_template]] template_id={:?} requires non-empty encoder",
                tpl.template_id
            );
        }
        if tpl.data_dir_template.trim().is_empty() {
            anyhow::bail!(
                "[[instance_template]] template_id={:?} requires non-empty data_dir_template",
                tpl.template_id
            );
        }
        if tpl.snapshot_policy != "live_default" {
            anyhow::bail!(
                "[[instance_template]] template_id={:?} has unknown snapshot_policy={:?} \
                 (expected \"live_default\")",
                tpl.template_id,
                tpl.snapshot_policy
            );
        }
        if let Some(t) = tpl.tree_fill_threshold {
            if !(0.0..=1.0).contains(&t) {
                anyhow::bail!(
                    "[[instance_template]] template_id={:?} tree_fill_threshold={t} \
                     out of range (must be 0.0..=1.0)",
                    tpl.template_id
                );
            }
        }
        crate::auto_spawn::validate_data_dir_template(&tpl.data_dir_template)?;
    }

    let global_max_instance_count = parsed.global.max_instance_count;
    let spawning_template = if parsed.auto_spawn.enabled {
        None
    } else {
        parsed
            .instance_template
            .iter()
            .find(|t| is_chain_encoder_label(&t.encoder))
            .map(|t| t.template_id.clone())
    };
    let auto_spawn = if parsed.auto_spawn.enabled {
        let mut cfg = parsed.auto_spawn;
        crate::auto_spawn::validate_data_dir_template(&cfg.data_dir_template)?;
        if cfg.max_instance_count.is_none() {
            cfg.max_instance_count = global_max_instance_count;
        }
        Some(cfg)
    } else {
        parsed
            .instance_template
            .iter()
            .find(|t| is_chain_encoder_label(&t.encoder))
            .map(|tpl| AutoSpawnConfigToml {
                enabled: true,
                data_dir_template: tpl.data_dir_template.clone(),
                encoder: tpl.encoder.clone(),
                scheme_tag: if tpl.scheme_tag.is_empty() {
                    scheme_tag.clone()
                } else {
                    tpl.scheme_tag.clone()
                },
                entries: if tpl.entries == 0 {
                    DEFAULT_PRODUCTION_ENTRIES
                } else {
                    tpl.entries
                },
                entry_bytes: if tpl.entry_bytes == 0 {
                    16 * 32
                } else {
                    tpl.entry_bytes
                },
                max_instance_count: tpl.max_instance_count.or(global_max_instance_count),
                cooldown_seconds: tpl.cooldown_seconds,
            })
    };

    if let Some(pool) = &parsed.rpc_pool {
        if pool.urls.is_empty() {
            anyhow::bail!("[rpc_pool] requires at least one entry in `urls`");
        }
        for url in &pool.urls {
            if url.trim().is_empty() {
                anyhow::bail!("[rpc_pool] urls entries must be non-empty");
            }
        }
        if pool.per_endpoint_rps == 0 {
            anyhow::bail!("[rpc_pool] per_endpoint_rps must be >= 1");
        }
        if pool.per_endpoint_burst == 0 {
            anyhow::bail!("[rpc_pool] per_endpoint_burst must be >= 1");
        }
    }

    if let Some(threshold) = parsed.global.tree_fill_threshold {
        if !(0.0..=1.0).contains(&threshold) {
            anyhow::bail!(
                "[global].tree_fill_threshold = {threshold} out of range (must be 0.0..=1.0)"
            );
        }
    }

    // A backfill slower than the poll it replaces is a unit slip, not a choice.
    if let Some(secs) = parsed.global.mirror_backfill_interval_secs {
        let poll = raven_railgun_ppoi_mirror::DEFAULT_POLL_INTERVAL_SECS;
        if secs > poll {
            anyhow::bail!(
                "[global].mirror_backfill_interval_secs = {secs} is slower than the {poll} s \
                 mirror poll interval it shortens (must be 0..={poll})"
            );
        }
    }

    let session_capacity = {
        let defaults = SessionCapacity::default();
        let global = &parsed.global;
        SessionCapacity {
            max_sessions_per_instance: global
                .max_sessions_per_instance
                .unwrap_or(defaults.max_sessions_per_instance),
            session_ttl_secs: global.session_ttl_secs.unwrap_or(defaults.session_ttl_secs),
            session_lru_cap: global.session_lru_cap.unwrap_or(defaults.session_lru_cap),
            max_concurrent_handshakes: global
                .max_concurrent_handshakes
                .unwrap_or(defaults.max_concurrent_handshakes),
        }
    };

    // The token gates `/metrics` alone, and `--metrics-public` can open it after this load, so
    // whether no source at all is an error is decided at boot. Any source given is vetted here.
    let token = match resolve_bearer_token(
        parsed.global.token.as_deref(),
        parsed.global.token_file.as_deref(),
        std::env::var(BEARER_TOKEN_ENV).ok(),
        path,
    ) {
        Ok(bearer) => {
            tracing::info!(source = bearer.source.label(), "bearer token resolved");
            bearer.token
        }
        Err(BearerTokenError::NoSource { .. }) => String::new(),
        Err(refused) => return Err(refused.into()),
    };

    // Ahead of `HttpConfig::validate` so an exposed-origin posture is refused
    // before bootstrap does any chain work.
    resolve_declared_ranges(
        parsed.global.trust_proxy_header.unwrap_or(false),
        parsed.global.trusted_proxy_cidrs.as_deref().unwrap_or(&[]),
    )
    .map_err(|e| anyhow::anyhow!("[global] {e}"))?;

    // A template that turned auto-spawn on is named, not the `[auto_spawn]` table it stood in for.
    let chain_reason = match &spawning_template {
        Some(template_id) if !reads_commit_tree(&instances) => Some(format!(
            "[[instance_template]] template_id={template_id:?} has a chain encoder, which turns \
             on auto-spawn of commit-tree instances"
        )),
        _ => chain_indexer_reason(&instances, auto_spawn.as_ref()),
    };
    let (rpc_url, railgun_proxy, start_block) = if let Some(reason) = chain_reason {
        (
            require_chain_key(parsed.global.rpc_url, "rpc_url", &reason)?,
            require_chain_key(parsed.global.railgun_proxy, "railgun_proxy", &reason)?,
            require_chain_key(parsed.global.start_block, "start_block", &reason)?,
        )
    } else {
        refuse_unread_chain_settings(&parsed.global, parsed.rpc_pool.is_some())?;
        (String::new(), String::new(), 0)
    };

    Ok(MultiServeOptions {
        bind: parsed.global.bind,
        token,
        rpc_url,
        railgun_proxy,
        chain_id: parsed.global.chain_id,
        start_block,
        mirror_endpoint: parsed.global.mirror_endpoint,
        mirror_backfill_interval_secs: parsed.global.mirror_backfill_interval_secs,
        max_concurrent_queries: parsed.global.max_concurrent_queries.unwrap_or(4),
        respond_permit_wait_ms: parsed.global.respond_permit_wait_ms,
        respond_timeout_secs: parsed.global.respond_timeout_secs.unwrap_or(30),
        instances,
        skip_chain_workers: false,
        skip_mirror_workers: false,
        entries: DEFAULT_PRODUCTION_ENTRIES,
        instance_entries,
        bootstrap_observer: None,
        auto_spawn,
        rpc_pool: parsed.rpc_pool,
        instance_templates: parsed.instance_template,
        tree_fill_threshold: parsed.global.tree_fill_threshold,
        reload_config_path: Some(path.to_path_buf()),
        ws_endpoint: parsed.global.ws_endpoint,
        rate_limit_rps: parsed.global.rate_limit_rps,
        rate_limit_burst: parsed.global.rate_limit_burst,
        cors_allowed_origins: parsed.global.cors_allowed_origins,
        trust_proxy_header: parsed.global.trust_proxy_header,
        trusted_proxy_cidrs: parsed.global.trusted_proxy_cidrs,
        metrics_public: parsed.global.metrics_public,
        session_eviction_interval_secs: parsed.global.session_eviction_interval_secs,
        reorg_window_path: parsed.global.reorg_window_path,
        session_capacity,
        stop_budget: STOP_BUDGET,
    })
}

/// The encoders an `[[instance_template]]` spawns commit-tree instances with.
fn is_chain_encoder_label(encoder: &str) -> bool {
    matches!(encoder, "per-leaf-bc" | "per-leaf-path" | "per-node")
}

fn reads_commit_tree(instances: &[InstanceConfig]) -> bool {
    instances
        .iter()
        .any(|instance| matches!(instance.data_source, DataSourceFilter::ChainTreeNumber(_)))
}

/// Why the node needs a chain indexer, or `None` when nothing it serves is read off the chain.
/// A commit-tree instance is fed only by the indexer, and `[auto_spawn]` creates more of them.
#[must_use]
pub fn chain_indexer_reason(
    instances: &[InstanceConfig],
    auto_spawn: Option<&AutoSpawnConfigToml>,
) -> Option<String> {
    let tree_reader = instances
        .iter()
        .find_map(|instance| match instance.data_source {
            DataSourceFilter::ChainTreeNumber(tree) => Some(format!(
                "instance {} indexes commit tree {tree}",
                instance.instance_id.as_str()
            )),
            DataSourceFilter::PpoiListBlock { .. } => None,
        });
    tree_reader.or_else(|| {
        auto_spawn
            .is_some_and(|cfg| cfg.enabled)
            .then(|| "[auto_spawn] is enabled and spawns commit-tree instances".to_owned())
    })
}

fn require_chain_key<T>(value: Option<T>, key: &str, reason: &str) -> anyhow::Result<T> {
    value.ok_or_else(|| {
        anyhow::anyhow!(
            "[global].{key} is required because {reason}, and the chain indexer reads it"
        )
    })
}

/// Only the chain indexer and `[auto_spawn]` read these, so with neither they would be dropped.
fn refuse_unread_chain_settings(global: &GlobalSection, rpc_pool: bool) -> anyhow::Result<()> {
    let unread: Vec<&str> = [
        ("[global].rpc_url", global.rpc_url.is_some()),
        ("[global].railgun_proxy", global.railgun_proxy.is_some()),
        ("[global].start_block", global.start_block.is_some()),
        ("[global].ws_endpoint", global.ws_endpoint.is_some()),
        (
            "[global].reorg_window_path",
            global.reorg_window_path.is_some(),
        ),
        (
            "[global].tree_fill_threshold",
            global.tree_fill_threshold.is_some(),
        ),
        (
            "[global].max_instance_count",
            global.max_instance_count.is_some(),
        ),
        ("[rpc_pool]", rpc_pool),
    ]
    .into_iter()
    .filter_map(|(key, set)| set.then_some(key))
    .collect();
    if unread.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "chain settings `{}` are set, but no instance indexes a commit tree and [auto_spawn] is \
         off, so nothing reads them: remove them, or declare the commit-tree instance they are for",
        unread.join("`, `")
    )
}

/// Build the HTTP configuration used by the multi-instance production path.
#[must_use]
pub fn build_http_config(opts: &MultiServeOptions) -> HttpConfig {
    let mut config = HttpConfig::demo(opts.token.clone());
    config.max_concurrent_queries = opts.max_concurrent_queries.max(1);
    config.respond_timeout_secs = opts.respond_timeout_secs;
    if let Some(rps) = opts.rate_limit_rps {
        config.rate_limit_rps = rps;
    }
    if let Some(burst) = opts.rate_limit_burst {
        config.rate_limit_burst = burst;
    }
    if let Some(origins) = opts.cors_allowed_origins.clone() {
        config.cors_allowed_origins = origins;
    }
    if let Some(trust) = opts.trust_proxy_header {
        config.trust_proxy_header = trust;
    }
    if let Some(cidrs) = opts.trusted_proxy_cidrs.clone() {
        config.trusted_proxy_cidrs = cidrs;
    }
    if let Some(public) = opts.metrics_public {
        config.metrics_public = public;
    }
    if let Some(secs) = opts.session_eviction_interval_secs {
        config.session_eviction_interval_secs = secs;
    }
    if let Some(wait) = opts.respond_permit_wait_ms {
        config.respond_permit_wait_ms = wait;
    }
    opts.session_capacity.apply_to(&mut config);
    config
}

fn build_encoder_kind(
    kind: EncoderString,
    tree_number: Option<u32>,
    list_key: Option<&str>,
) -> anyhow::Result<EncoderKind> {
    match kind {
        EncoderString::PerLeafBc => {
            let t = tree_number
                .ok_or_else(|| anyhow::anyhow!("per-leaf-bc encoder requires `tree_number`"))?;
            Ok(EncoderKind::PerLeafBc { tree_number: t })
        }
        EncoderString::PerLeafPath => {
            let t = tree_number
                .ok_or_else(|| anyhow::anyhow!("per-leaf-path encoder requires `tree_number`"))?;
            Ok(EncoderKind::PerLeafPath { tree_number: t })
        }
        EncoderString::PerNode => {
            let t = tree_number
                .ok_or_else(|| anyhow::anyhow!("per-node encoder requires `tree_number`"))?;
            Ok(EncoderKind::PerNode { tree_number: t })
        }
        EncoderString::PerListPath10 => {
            let lk = list_key
                .ok_or_else(|| anyhow::anyhow!("per-list-path10 encoder requires `list_key`"))?;
            Ok(EncoderKind::PerListPath10 {
                list_key: parse_hex32(lk)?,
            })
        }
    }
}

fn build_data_source(section: &DataSourceSection) -> anyhow::Result<DataSourceFilter> {
    match section {
        DataSourceSection::Indexer { filter } => {
            Ok(DataSourceFilter::ChainTreeNumber(filter.tree_number))
        }
        DataSourceSection::Mirror { list_key, block } => Ok(DataSourceFilter::PpoiListBlock {
            list_key: parse_hex32(list_key)?,
            block: *block,
        }),
    }
}

fn enforce_encoder_matches_data_source(
    instance_id: &str,
    encoder: EncoderKind,
    data_source: &DataSourceFilter,
) -> anyhow::Result<()> {
    match (encoder, data_source) {
        (
            EncoderKind::PerLeafBc { tree_number }
            | EncoderKind::PerLeafPath { tree_number }
            | EncoderKind::PerNode { tree_number },
            DataSourceFilter::ChainTreeNumber(routed),
        ) => {
            // Matching the family alone lets a pin disagree with the routed tree. Every
            // tree encoder drops foreign-tree events, so the mismatch is silent: the
            // instance serves its own tree's rows at HTTP 200 and never updates.
            anyhow::ensure!(
                tree_number == *routed,
                "instance {instance_id:?}: encoder {} is pinned to tree {tree_number} but \
                 data_source routes tree {routed} to it. The encoder drops every event for \
                 a tree other than its own, so this instance would serve tree {tree_number}'s rows \
                 unchanged at HTTP 200 while tree {routed} advanced. Operator: set the \
                 instance's `tree_number` and its `data_source.filter.tree_number` to the \
                 same tree.",
                encoder.label()
            );
            Ok(())
        }
        (
            EncoderKind::PerListPath10 { .. },
            DataSourceFilter::PpoiListBlock {
                list_key: routed, ..
            },
        ) => enforce_encoder_list_key(instance_id, encoder, routed, "data_source.list_key"),
        _ => anyhow::bail!(
            "instance {instance_id:?}: encoder kind {} does not match data_source {:?}",
            encoder.label(),
            data_source
        ),
    }
}

fn parse_hex32(text: &str) -> anyhow::Result<[u8; 32]> {
    raven_railgun_core::hex::decode_hex(text)
        .ok_or_else(|| anyhow::anyhow!("list_key {text:?} is not 32 bytes of hex"))
}

pub async fn run(opts: MultiServeOptions) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(opts.bind)
        .await
        .with_context(|| format!("bind {}", opts.bind))?;
    run_with_listener(opts, listener, signal_shutdown()).await
}

/// Returns `true` if the cell falls into the AVX-512-IFMA52 small-cell regression band.
fn ifma52_small_cell_threshold_breached(opts: &MultiServeOptions, entries: usize) -> bool {
    let min_record_size = opts
        .instances
        .iter()
        .map(|i| i.record_size)
        .min()
        .unwrap_or(0);
    entries < (1usize << 16) || min_record_size <= 32
}

fn warn_if_ifma52_small_cell(opts: &MultiServeOptions, entries: usize) {
    #[cfg(target_arch = "x86_64")]
    let host_has_ifma52 = std::is_x86_feature_detected!("avx512ifma");
    #[cfg(not(target_arch = "x86_64"))]
    let host_has_ifma52 = false;
    if !host_has_ifma52 {
        return;
    }

    if ifma52_small_cell_threshold_breached(opts, entries) {
        let min_record_size = opts
            .instances
            .iter()
            .map(|i| i.record_size)
            .min()
            .unwrap_or(0);
        tracing::warn!(
            entries,
            min_record_size,
            "host CPU exposes AVX-512-IFMA52 (W-G IFMA52 SIMD path) AND \
             the configured cell is small (entries < 2^16 OR \
             record_size <= 32). At T1-style small cells the IFMA52 \
             path regresses by ~1.038x on Zen 5. See OPERATOR_RUNBOOK \
             section 7a for the cell applicability table. The path is \
             auto-detected; no action required if you accept the \
             measured regression."
        );
    }
}

async fn signal_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(sig) => sig,
            Err(e) => {
                tracing::warn!(error = %e, "SIGTERM handler unavailable; waiting for SIGINT only");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            res = tokio::signal::ctrl_c() => {
                if let Err(e) = res {
                    tracing::warn!(error = %e, "ctrl_c handler error; shutting down");
                }
            }
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received; shutting down");
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Final commits a stop runs at once. Each holds its serialized snapshot while it writes, so
/// this bounds the memory a stop adds.
const PARALLEL_FINAL_COMMITS: usize = 3;

/// Time from the stop signal to exit: half the deploy's 30 s stop timeout. Seven dirty production
/// cells took 4.3-5.4 s to commit on an idle 16-core host, and past 8 s on a loaded one. A final
/// commit still running when it is spent is abandoned, and the stop returns an error: that
/// instance's next boot recovers from its last snapshot and write-ahead log, as after a crash.
pub const STOP_BUDGET: std::time::Duration = std::time::Duration::from_secs(15);

/// Run `stops`, at most `parallel` at once, until `stop_by`; returns how many had not finished.
async fn run_stops_until<S>(stops: Vec<S>, parallel: usize, stop_by: tokio::time::Instant) -> usize
where
    S: std::future::Future<Output = ()> + Send + 'static,
{
    let slots = Arc::new(tokio::sync::Semaphore::new(parallel.max(1)));
    let mut running = tokio::task::JoinSet::new();
    for stop in stops {
        let slots = Arc::clone(&slots);
        running.spawn(async move {
            let _slot = slots.acquire_owned().await;
            stop.await;
        });
    }
    let _ = tokio::time::timeout_at(stop_by, async {
        while running.join_next().await.is_some() {}
    })
    .await;
    while running.try_join_next().is_some() {}
    running.len()
}

pub async fn run_with_listener<F: std::future::Future<Output = ()> + Send + 'static>(
    opts: MultiServeOptions,
    listener: tokio::net::TcpListener,
    shutdown: F,
) -> anyhow::Result<()> {
    if opts.instances.is_empty() {
        anyhow::bail!("multi-instance serve requires at least one [[instance]] config");
    }
    let reads_chain = chain_indexer_reason(&opts.instances, opts.auto_spawn.as_ref()).is_some();
    // `--ws-endpoint` is merged in after the loader refused the TOML key, so it is refused here.
    if !reads_chain && opts.ws_endpoint.is_some() {
        anyhow::bail!(
            "a WebSocket endpoint is set (`--ws-endpoint` or `[global].ws_endpoint`), but no \
             instance indexes a commit tree and [auto_spawn] is off, so nothing reads it: drop it"
        );
    }

    let params = InspireParams::secure_128_d2048();
    let fleet_default_entries = opts.entries.max(1);
    let smallest_cell_entries = opts
        .instances
        .iter()
        .map(|cfg| entries_for_instance(&opts, cfg, fleet_default_entries))
        .min()
        .unwrap_or(fleet_default_entries);

    warn_if_ifma52_small_cell(&opts, smallest_cell_entries);

    // Before any store opens: every store, auto-spawned ones included, takes its limits here.
    let http_config = build_http_config(&opts);
    if !http_config.metrics_public && http_config.read_token.is_empty() {
        anyhow::bail!(
            "no bearer token: /metrics is not public, and the token is what opens it. Set \
             exactly one of [global].token, [global].token_file or the {BEARER_TOKEN_ENV} \
             environment variable, or serve /metrics open with [global].metrics_public = true \
             or --metrics-public"
        );
    }
    http_config
        .validate()
        .map_err(|e| anyhow::anyhow!("[global] {e}"))?;
    let session_limits = http_config.session_store_limits();
    let stop_budget = opts.stop_budget;

    let bootstrap = bootstrap_instances(&opts, fleet_default_entries, &params, session_limits)?;

    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    let mut k_map: HashMap<InstanceId, u32> =
        HashMap::with_capacity(bootstrap.handles.instances.len());
    for handle in &bootstrap.handles.instances {
        engine
            .register_instance(Arc::clone(&handle.instance))
            .map_err(|e| anyhow::anyhow!("register_instance: {e}"))?;
        let resolved =
            u32::try_from(handle.config.resolved_max_concurrent_queries()).unwrap_or(u32::MAX);
        k_map.insert(handle.instance.id.clone(), resolved);
    }

    if let Some(observer) = opts.bootstrap_observer.as_ref() {
        let view = BootstrapView {
            channels: bootstrap.handles.channels.clone(),
            instances: bootstrap
                .handles
                .instances
                .iter()
                .map(|h| BootstrapInstanceView {
                    instance_id: h.instance.id.clone(),
                    encoder_label: h.config.encoder.label(),
                    data_source: h.config.data_source,
                    role: h.config.role,
                    metrics: Arc::clone(&h.metrics),
                    logical_store: Arc::clone(&h.logical_store),
                })
                .collect(),
        };
        *observer.lock() = Some(view);
    }

    let per_tree_recovered = per_tree_recovered_floors(&bootstrap.handles.instances);
    let (reorg_window_required, recovered_block_height) =
        recovered_chain_window_requirement(&bootstrap.handles.instances);
    let per_tree_start_blocks =
        compute_effective_start_block_per_tree(opts.start_block, &per_tree_recovered);
    let min_effective_start_block = per_tree_start_blocks
        .values()
        .copied()
        .min()
        .unwrap_or(opts.start_block);
    for (tree, floor) in &per_tree_start_blocks {
        if *floor > opts.start_block {
            tracing::info!(
                tree_number = *tree,
                toml_start_block = opts.start_block,
                recovered_floor = *floor,
                "indexer per-tree start_block raised to recovered manifest floor"
            );
        }
    }

    // Sidecar beside the first data_dir so restarts resume reorg state unconfigured.
    let resolved_reorg_window_path = opts.reorg_window_path.clone().or_else(|| {
        bootstrap
            .handles
            .instances
            .first()
            .and_then(|h| h.config.data_dir.parent().map(std::path::Path::to_path_buf))
            .map(|parent| parent.join("indexer_reorg_window.bin"))
    });

    if !reads_chain {
        tracing::info!("no instance reads the chain and [auto_spawn] is off; no chain indexer");
    }
    let chain_workers = if opts.skip_chain_workers || !reads_chain {
        None
    } else {
        Some(
            spawn_chain_indexer(
                &opts,
                min_effective_start_block,
                recovered_block_height,
                reorg_window_required,
                per_tree_start_blocks.clone(),
                resolved_reorg_window_path.clone(),
                bootstrap.handles.channels.indexer_tx.clone(),
            )
            .await?,
        )
    };

    let app_state = AppState::new(engine, http_config)
        .map_err(|e| anyhow::anyhow!("AppState::new: {e}"))?
        .require_consumer_metrics();

    // After `AppState::new`, so the preflight counts into the recorder it installs.
    let mirror_workers = if opts.skip_mirror_workers {
        None
    } else {
        Some(spawn_mirror_workers(&opts, &bootstrap.handles).await?)
    };

    // Retained so shutdown can drain auto-spawned consumers; else they skip the
    // final WAL flush.
    let auto_spawn_state: Option<AutoSpawnWiring> = if let Some(cfg) = opts
        .auto_spawn
        .as_ref()
        .filter(|c| c.enabled && !c.data_dir_template.is_empty())
    {
        Some(wire_auto_spawn(
            cfg,
            &params,
            Arc::clone(&app_state.engine),
            Arc::clone(&bootstrap.handles.chain_tree_routes),
            bootstrap.handles.tree_observed.clone(),
            &bootstrap.handles.instances,
            &opts,
            session_limits,
        )?)
    } else {
        None
    };

    let watcher_views: Vec<BootstrapInstanceView> = bootstrap
        .handles
        .instances
        .iter()
        .map(|h| BootstrapInstanceView {
            instance_id: h.instance.id.clone(),
            encoder_label: h.config.encoder.label(),
            data_source: h.config.data_source,
            role: h.config.role,
            metrics: Arc::clone(&h.metrics),
            logical_store: Arc::clone(&h.logical_store),
        })
        .collect();

    let mut auxiliary_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    if let Some(wiring) = auto_spawn_state.as_ref() {
        if let Some(reload_path) = opts.reload_config_path.clone() {
            #[cfg(unix)]
            {
                let live_runtime = Arc::clone(&wiring.live_runtime);
                let entries_default = opts.entries;
                let task = tokio::spawn(async move {
                    run_sighup_reload_loop(reload_path, live_runtime, entries_default, None).await;
                });
                auxiliary_tasks.push(task);
            }
            #[cfg(not(unix))]
            {
                let _ = reload_path;
            }
        }
        if let Some(threshold) = opts.tree_fill_threshold {
            let watcher_inputs = TreeFillWatcherInputs {
                threshold,
                instance_views: watcher_views.clone(),
                live_runtime: Arc::clone(&wiring.live_runtime),
                params: params.clone(),
                engine: Arc::clone(&app_state.engine),
                chain_tree_routes: Arc::clone(&bootstrap.handles.chain_tree_routes),
                registry: Arc::clone(&wiring.registry),
                spawn_log_dir: wiring.spawn_log_dir.clone(),
            };
            let task = tokio::spawn(async move {
                run_tree_fill_watcher(watcher_inputs).await;
            });
            auxiliary_tasks.push(task);
        } else {
            // A config that switches a safety mechanism off must say so at boot, at a level
            // RUST_LOG=info shows.
            tracing::warn!(
                auto_spawn_enabled = opts.auto_spawn.as_ref().is_some_and(|c| c.enabled),
                "tree_fill_threshold is unset: tree-rollover pre-spawn is DISABLED. When the live \
                 commit-tree fills, events for its successor are dropped until an instance is \
                 configured by hand. Set [global].tree_fill_threshold (0.0..=1.0) and \
                 [auto_spawn].enabled to switch it on."
            );
        }
    }
    let app_state = if let Some(metrics) = bootstrap.handles.instances.first() {
        app_state.with_consumer_metrics(Arc::clone(&metrics.metrics))
    } else {
        app_state
    };
    let app_state = app_state.with_instance_concurrency(k_map);
    let instance_logical_stores = bootstrap
        .handles
        .instances
        .iter()
        .filter_map(|handle| match handle.config.encoder {
            EncoderKind::PerListPath10 { list_key } => Some((
                handle.instance.id.clone(),
                (list_key, Arc::clone(&handle.logical_store)),
            )),
            _ => None,
        })
        .collect();
    let app_state = app_state.with_instance_logical_stores(instance_logical_stores);
    // Every instance, tagged with the filter it was configured with. The shim routes prove
    // coverage against these rather than reaching a store directly; installing the registry
    // at all is what puts the undeclared single-store path out of production's reach.
    let shim_declarations: Vec<(
        DataSourceFilter,
        Arc<parking_lot::Mutex<raven_railgun_engine::inspire::LogicalLeafStore>>,
    )> = bootstrap
        .handles
        .instances
        .iter()
        .map(|handle| (handle.config.data_source, Arc::clone(&handle.logical_store)))
        .collect();
    let app_state = app_state.with_shim_stores(shim_declarations);
    let app_state = if let Some(pool) = chain_workers
        .as_ref()
        .and_then(|w| w.rpc_pool.as_ref())
        .map(Arc::clone)
    {
        app_state.with_rpc_pool(pool)
    } else {
        app_state
    };
    let app_state = if let Some(mode) = chain_workers
        .as_ref()
        .and_then(|w| w.chain_source_mode.as_ref())
        .map(Arc::clone)
    {
        app_state.with_chain_source_mode(mode)
    } else {
        app_state
    };
    let per_instance_metrics: std::collections::HashMap<
        InstanceId,
        Arc<parking_lot::Mutex<raven_railgun_engine::persistence::ConsumerMetrics>>,
    > = bootstrap
        .handles
        .instances
        .iter()
        .map(|h| (h.config.instance_id.clone(), Arc::clone(&h.metrics)))
        .collect();
    let app_state = app_state.with_instance_metrics(per_instance_metrics);
    let app_state = match mirror_workers.as_ref() {
        Some(workers) => app_state.with_mirror_feeds(workers.readiness_probe()),
        None => app_state,
    };

    let sweeper_handle = app_state.start_session_sweeper(std::time::Duration::from_secs(60));
    auxiliary_tasks.push(sweeper_handle);
    auxiliary_tasks.push(app_state.start_packing_key_sweeper(std::time::Duration::from_secs(60)));

    // Bounds resident memory by dropping every live session per interval.
    let eviction_secs = app_state.config.session_eviction_interval_secs;
    if eviction_secs > 0 {
        for inst in &bootstrap.handles.instances {
            let instance = Arc::clone(&inst.instance);
            let instance_id = inst.config.instance_id.clone();
            let tick = std::time::Duration::from_secs(eviction_secs);
            let handle = tokio::spawn(async move {
                let mut ticker = tokio::time::interval(tick);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                ticker.tick().await; // drop the immediate t=0 tick.
                loop {
                    ticker.tick().await;
                    match raven_railgun_engine::inspire::heartbeat_session_eviction(&instance) {
                        Ok(()) => {
                            metrics::counter!(
                                "raven_railgun_session_eviction_swaps_total",
                                "instance" => instance_id.as_str().to_owned()
                            )
                            .increment(1);
                        }
                        Err(e) => {
                            tracing::warn!(
                                instance = instance_id.as_str(),
                                error = %e,
                                "heartbeat session eviction failed"
                            );
                        }
                    }
                }
            });
            auxiliary_tasks.push(handle);
        }
    }

    let router = inspire_router(app_state).map_err(|e| anyhow::anyhow!("inspire_router: {e}"))?;

    let local_addr = listener
        .local_addr()
        .with_context(|| "listener local_addr")?;
    tracing::info!(
        bind = %local_addr,
        instances = bootstrap.handles.instances.len(),
        "raven-railgun multi-instance production serve listening"
    );

    // The budget runs from the signal, so draining open requests spends it too.
    let (signalled_tx, mut signalled_rx) = tokio::sync::oneshot::channel();
    let shutdown = async move {
        shutdown.await;
        let _ = signalled_tx.send(tokio::time::Instant::now() + stop_budget);
    };
    let serving = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown);
    let serving = std::future::IntoFuture::into_future(serving);
    tokio::pin!(serving);
    let signalled = tokio::select! {
        served = &mut serving => {
            served?;
            None
        }
        stop_by = &mut signalled_rx => {
            if stop_by.is_err() {
                (&mut serving).await?;
            }
            stop_by.ok()
        }
    };
    let stop_by = match signalled {
        Some(stop_by) => {
            if let Ok(served) = tokio::time::timeout_at(stop_by, &mut serving).await {
                served?;
            } else {
                tracing::warn!("requests still open when the stop budget was spent");
            }
            stop_by
        }
        None => tokio::time::Instant::now() + stop_budget,
    };

    drop(bootstrap.handles.channels);
    let failed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let final_commits: Vec<_> = bootstrap
        .handles
        .instances
        .into_iter()
        .map(|handle| {
            let failed = Arc::clone(&failed);
            async move {
                let instance = handle.config.instance_id;
                if !final_commit_landed(handle.sender, handle.consumer, &instance).await {
                    failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        })
        .collect();
    let mut unfinished = run_stops_until(final_commits, PARALLEL_FINAL_COMMITS, stop_by).await;
    if unfinished > 0 {
        tracing::error!(
            unfinished,
            budget_secs = stop_budget.as_secs(),
            "stop budget spent before every final commit finished; each unfinished instance \
             recovers from its last snapshot and write-ahead log at the next boot"
        );
    }
    // The feeds that hold its senders drop last, so it would not exit on its own, and nothing it
    // could still forward has a consumer.
    bootstrap.handles.router.abort();

    // Before teardown so a SIGHUP can't race driver/registry shutdown.
    for t in auxiliary_tasks {
        t.abort();
    }

    // Before the driver: else registry drain races an in-flight tree-observed event.
    if let Some(wiring) = auto_spawn_state {
        let AutoSpawnWiring {
            driver,
            registry,
            live_runtime: _,
            spawn_log_dir: _,
        } = wiring;
        let auto_spawned = registry.drain_auto_spawned();
        let drained = auto_spawned.len();
        let stops: Vec<_> = auto_spawned
            .into_iter()
            .map(|handle| {
                let failed = Arc::clone(&failed);
                async move {
                    let landed = final_commit_landed(
                        handle.consumer_sender,
                        handle.consumer_join,
                        &handle.instance_id,
                    )
                    .await;
                    if !landed {
                        failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            })
            .collect();
        let spawned_unfinished = run_stops_until(stops, PARALLEL_FINAL_COMMITS, stop_by).await;
        if spawned_unfinished > 0 {
            tracing::error!(
                unfinished = spawned_unfinished,
                budget_secs = stop_budget.as_secs(),
                "auto_spawn consumers did not exit within the stop budget; each recovers from \
                 its last snapshot and write-ahead log at the next boot"
            );
        }
        unfinished = unfinished.saturating_add(spawned_unfinished);
        if drained > 0 {
            tracing::info!(drained, "auto_spawn: drained consumers on shutdown");
        }
        driver.abort();
    }

    // Cooperative so a panic surfaces as a join error rather than being aborted away.
    if let Some(mut workers) = chain_workers {
        workers
            .shutdown_mode_mirror(stop_by.saturating_duration_since(tokio::time::Instant::now()))
            .await;
        drop(workers);
    }
    drop(mirror_workers);

    stop_outcome(StopIncomplete {
        unfinished,
        failed: failed.load(std::sync::atomic::Ordering::Relaxed),
        budget: stop_budget,
    })
}

/// Send `Shutdown` and wait for the consumer's final commit; `false` when it did not land.
async fn final_commit_landed(
    sender: tokio::sync::mpsc::Sender<raven_railgun_engine::persistence::ConsumerEvent>,
    consumer: tokio::task::JoinHandle<raven_railgun_core::Result<()>>,
    instance: &raven_railgun_core::InstanceId,
) -> bool {
    let _ = sender
        .send(raven_railgun_engine::persistence::ConsumerEvent::Shutdown)
        .await;
    let error = match consumer.await {
        Ok(Ok(())) => return true,
        Ok(Err(error)) => error.to_string(),
        Err(join) => join.to_string(),
    };
    tracing::error!(instance = instance.as_str(), %error, "final commit failed");
    false
}

/// A stop that left an instance unpublished; each such instance recovers at its next boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "stop incomplete: {unfinished} final commit(s) outran the {} s stop budget and {failed} \
     failed; each such instance recovers from its last snapshot and write-ahead log at the next \
     boot",
    budget.as_secs()
)]
pub struct StopIncomplete {
    pub unfinished: usize,
    pub failed: usize,
    pub budget: std::time::Duration,
}

/// A stop that left any instance unpublished is an error, so the process exits non-zero.
fn stop_outcome(stop: StopIncomplete) -> anyhow::Result<()> {
    if stop.unfinished > 0 || stop.failed > 0 {
        return Err(stop.into());
    }
    Ok(())
}

struct AutoSpawnWiring {
    driver: tokio::task::JoinHandle<()>,
    pub(crate) registry: Arc<crate::auto_spawn_driver::SpawnRegistry>,
    pub(crate) live_runtime: Arc<arc_swap::ArcSwap<crate::auto_spawn_driver::AutoSpawnRuntime>>,
    pub(crate) spawn_log_dir: PathBuf,
}

#[cfg(unix)]
async fn run_sighup_reload_loop(
    config_path: PathBuf,
    live_runtime: Arc<arc_swap::ArcSwap<crate::auto_spawn_driver::AutoSpawnRuntime>>,
    entries_default: usize,
    applied_observer: Option<tokio::sync::mpsc::UnboundedSender<String>>,
) {
    use tokio::signal::unix::{signal, SignalKind};

    let mut hup = match signal(SignalKind::hangup()) {
        Ok(sig) => sig,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "SIGHUP handler unavailable; auto_spawn template hot-reload disabled"
            );
            return;
        }
    };

    let mut known_ids: std::collections::HashSet<String> =
        match load_options_from_toml(&config_path) {
            Ok(opts) => opts
                .instance_templates
                .iter()
                .map(|t| t.template_id.clone())
                .collect(),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    config = %config_path.display(),
                    "auto_spawn SIGHUP reload: initial template snapshot unreadable; \
                     will surface every template as 'new' on first SIGHUP"
                );
                std::collections::HashSet::new()
            }
        };

    loop {
        if hup.recv().await.is_none() {
            tracing::info!("SIGHUP handler closed; reload loop exiting");
            return;
        }
        let opts = match load_options_from_toml(&config_path) {
            Ok(o) => o,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    config = %config_path.display(),
                    "auto_spawn SIGHUP reload: re-parse failed; keeping prior runtime"
                );
                continue;
            }
        };
        let new_ids: std::collections::HashSet<String> = opts
            .instance_templates
            .iter()
            .map(|t| t.template_id.clone())
            .collect();
        for removed in known_ids.difference(&new_ids) {
            tracing::error!(
                template_id = %removed,
                "auto_spawn SIGHUP reload: template_id removed from TOML; \
                 in-process state retained (operator must drain instances manually)"
            );
        }

        // Last template wins; each is logged so extras are not silently dropped.
        let added: Vec<&InstanceTemplateToml> = opts
            .instance_templates
            .iter()
            .filter(|t| !known_ids.contains(&t.template_id))
            .collect();
        let chain_tree_added: Vec<&InstanceTemplateToml> = added
            .iter()
            .copied()
            .filter(|t| {
                matches!(
                    t.encoder.as_str(),
                    "per-leaf-bc" | "per-leaf-path" | "per-node"
                )
            })
            .collect();
        if added.is_empty() {
            tracing::info!(
                count = new_ids.len(),
                "auto_spawn SIGHUP reload: no new template_ids; no swap"
            );
        } else if chain_tree_added.is_empty() {
            tracing::info!(
                added_count = added.len(),
                "auto_spawn SIGHUP reload: new templates present but none are chain-tree; \
                 PPOI hot-reload deferred (no live multi-list discovery)"
            );
        } else {
            for tpl in &chain_tree_added {
                let synthesized = AutoSpawnConfigToml {
                    enabled: true,
                    data_dir_template: tpl.data_dir_template.clone(),
                    encoder: tpl.encoder.clone(),
                    scheme_tag: if tpl.scheme_tag.is_empty() {
                        SCHEME_TAG_DEFAULT.to_owned()
                    } else {
                        tpl.scheme_tag.clone()
                    },
                    entries: if tpl.entries == 0 {
                        DEFAULT_PRODUCTION_ENTRIES
                    } else {
                        tpl.entries
                    },
                    entry_bytes: if tpl.entry_bytes == 0 {
                        16 * 32
                    } else {
                        tpl.entry_bytes
                    },
                    max_instance_count: tpl.max_instance_count,
                    cooldown_seconds: tpl.cooldown_seconds,
                };
                // The HTTP layer is not reloaded, so neither are the seats it was sized for.
                let session_limits = live_runtime.load().session_limits;
                let runtime =
                    runtime_from_auto_spawn_section(&synthesized, entries_default, session_limits);
                live_runtime.store(Arc::new(runtime));
                if let Some(observer) = &applied_observer {
                    let _ = observer.send(tpl.template_id.clone());
                }
                tracing::debug!(
                    template_id = %tpl.template_id,
                    encoder = %tpl.encoder,
                    "auto_spawn SIGHUP reload: applied chain-tree template"
                );
            }
            tracing::info!(
                applied_count = chain_tree_added.len(),
                last_template_id = %chain_tree_added
                    .last()
                    .map_or("", |t| t.template_id.as_str()),
                "auto_spawn SIGHUP reload: hot-applied chain-tree templates (last wins)"
            );
        }
        known_ids = new_ids;
    }
}

/// `max(toml_start_block, max(recovered))`. Single-floor deployments ONLY: mixed
/// bootstrap heights MUST use [`compute_effective_start_block_per_tree`], else the
/// global max skips every event in `(min_recovered, max_recovered]`.
#[must_use]
pub fn compute_effective_start_block(
    toml_start_block: u64,
    recovered_block_heights: &[u64],
) -> u64 {
    let max_recovered = recovered_block_heights.iter().copied().max().unwrap_or(0);
    toml_start_block.max(max_recovered)
}

/// Recovered indexer floor per chain tree. A single global floor would either
/// re-scan below the recovered prefix or skip events for the lower-height trees.
/// The committed manifest marker is the only authority: it rolls back with a
/// reorg, while `LogicalLeafStore::last_block_height` is monotone.
#[must_use]
pub fn per_tree_recovered_floors(instances: &[PerInstanceHandles]) -> BTreeMap<u32, u64> {
    let mut floors: BTreeMap<u32, u64> = BTreeMap::new();
    for h in instances {
        if let DataSourceFilter::ChainTreeNumber(tree) = h.config.data_source {
            let height = h.persistence.manifest_block_height();
            floors
                .entry(tree)
                .and_modify(|v| *v = (*v).max(height))
                .or_insert(height);
        }
    }
    floors
}

fn recovered_chain_window_requirement(instances: &[PerInstanceHandles]) -> (bool, u64) {
    let mut required = false;
    let mut high_water = 0u64;
    for handle in instances {
        if !matches!(
            handle.config.data_source,
            DataSourceFilter::ChainTreeNumber(_)
        ) {
            continue;
        }
        let manifest_height = handle.persistence.manifest_block_height();
        let store = handle.logical_store.lock();
        let store_height = store.last_block_height();
        required |= manifest_height > 0 || store_height > 0 || store.leaf_count() > 0;
        high_water = high_water.max(manifest_height).max(store_height);
    }
    (required, high_water)
}

/// Per-tree `max(toml_start_block, recovered)`. The single-cursor indexer scans
/// from `min(per_tree)`; dispatch drops events below a tree's own floor.
#[must_use]
pub fn compute_effective_start_block_per_tree(
    toml_start_block: u64,
    recovered_per_tree: &BTreeMap<u32, u64>,
) -> BTreeMap<u32, u64> {
    recovered_per_tree
        .iter()
        .map(|(&tree, &recovered)| (tree, toml_start_block.max(recovered)))
        .collect()
}

#[must_use]
pub fn compute_trigger_threshold(threshold: f32, tree_max_items: u32) -> usize {
    let clamped = f64::from(threshold).clamp(0.0, 1.0);
    let scaled = clamped * f64::from(tree_max_items);
    let rounded = scaled.round();
    if !rounded.is_finite() || rounded <= 0.0 {
        return 0;
    }
    if rounded >= f64::from(tree_max_items) {
        return tree_max_items as usize;
    }
    // `as u64` sound: rounded is finite, > 0, and < tree_max_items <= u32::MAX.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let rounded_u64 = rounded as u64;
    usize::try_from(rounded_u64).unwrap_or(0)
}

/// Must mirror the engine's `TREE_MAX_ITEMS`.
const WATCHER_TREE_MAX_ITEMS: u32 = 65_536;
const WATCHER_TREE_FILL_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

pub(crate) struct TreeFillWatcherInputs {
    pub(crate) threshold: f32,
    pub(crate) instance_views: Vec<BootstrapInstanceView>,
    live_runtime: Arc<arc_swap::ArcSwap<crate::auto_spawn_driver::AutoSpawnRuntime>>,
    pub(crate) params: InspireParams,
    pub(crate) engine: Arc<Engine<RavenInspireScheme>>,
    pub(crate) chain_tree_routes: raven_railgun_engine::orchestrator::ChainTreeRoutes,
    registry: Arc<crate::auto_spawn_driver::SpawnRegistry>,
    spawn_log_dir: PathBuf,
}

/// What one watcher poll decided. One tick is callable on its own so the rollover decision is
/// testable without the watcher's loop.
#[derive(Debug, PartialEq, Eq)]
pub enum TickOutcome {
    /// The registry knows no trees yet.
    NoActiveTree,
    /// No instance view matches the active tree.
    NoView,
    /// The tree has room; `leaf_count` is below `trigger_at`.
    BelowThreshold {
        leaf_count: usize,
        trigger_at: usize,
    },
    /// The successor was pre-spawned.
    Spawned(u32),
    /// The successor already existed; the watcher is idempotent across ticks.
    AlreadyKnown(u32),
    /// The spawn was attempted and refused; the watcher retries next tick.
    SpawnFailed(String),
}

/// One poll of the tree-fill watcher. The loop below is this plus a timer.
pub(crate) fn tree_fill_watcher_tick(
    inputs: &TreeFillWatcherInputs,
    trigger_at: usize,
) -> TickOutcome {
    let known: Vec<u32> = inputs.registry.known();
    let Some(active_tree) = known.into_iter().max() else {
        return TickOutcome::NoActiveTree;
    };
    let Some(view) = inputs.instance_views.iter().find(|v| {
        v.data_source
            == raven_railgun_engine::orchestrator::DataSourceFilter::ChainTreeNumber(active_tree)
    }) else {
        return TickOutcome::NoView;
    };
    let leaf_count = view.logical_store.lock().imt_leaf_count_for(active_tree);
    if leaf_count < trigger_at {
        return TickOutcome::BelowThreshold {
            leaf_count,
            trigger_at,
        };
    }
    let next_tree = active_tree.saturating_add(1);
    let runtime_snapshot = inputs.live_runtime.load_full();
    match crate::auto_spawn_driver::pre_spawn_for_tree(
        runtime_snapshot.as_ref(),
        &inputs.params,
        &inputs.engine,
        &inputs.chain_tree_routes,
        &inputs.registry,
        inputs.spawn_log_dir.clone(),
        None,
        next_tree,
    ) {
        Ok(true) => TickOutcome::Spawned(next_tree),
        Ok(false) => TickOutcome::AlreadyKnown(next_tree),
        Err(e) => TickOutcome::SpawnFailed(e.to_string()),
    }
}

async fn run_tree_fill_watcher(inputs: TreeFillWatcherInputs) {
    let threshold = inputs.threshold;
    if !(0.0..=1.0).contains(&threshold) {
        tracing::error!(
            threshold,
            "tree_fill_threshold out of range; pre-spawn watcher disabled"
        );
        return;
    }
    let trigger_at: usize = compute_trigger_threshold(threshold, WATCHER_TREE_MAX_ITEMS);
    let mut interval = tokio::time::interval(WATCHER_TREE_FILL_POLL_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        interval.tick().await;
        match tree_fill_watcher_tick(&inputs, trigger_at) {
            TickOutcome::NoActiveTree
            | TickOutcome::NoView
            | TickOutcome::BelowThreshold { .. } => {}
            TickOutcome::Spawned(next_tree) => {
                tracing::info!(
                    next_tree,
                    trigger_at,
                    "tree_fill_threshold: pre-spawned successor BEFORE chain rollover"
                );
            }
            TickOutcome::AlreadyKnown(next_tree) => {
                tracing::trace!(
                    next_tree,
                    "tree_fill_threshold: successor already known to registry"
                );
            }
            TickOutcome::SpawnFailed(error) => {
                tracing::error!(
                    next_tree = trigger_at,
                    error,
                    "tree_fill_threshold: pre-spawn failed; will retry on next tick"
                );
            }
        }
    }
}

fn runtime_from_auto_spawn_section(
    cfg: &AutoSpawnConfigToml,
    default_entries: usize,
    session_limits: SessionStoreLimits,
) -> crate::auto_spawn_driver::AutoSpawnRuntime {
    crate::auto_spawn_driver::AutoSpawnRuntime {
        data_dir_template: cfg.data_dir_template.clone(),
        encoder: cfg.encoder.clone(),
        scheme_tag: if cfg.scheme_tag.is_empty() {
            SCHEME_TAG_DEFAULT.to_owned()
        } else {
            cfg.scheme_tag.clone()
        },
        entries: if cfg.entries == 0 {
            default_entries
        } else {
            cfg.entries
        },
        entry_bytes: if cfg.entry_bytes == 0 {
            16 * 32
        } else {
            cfg.entry_bytes
        },
        channel_capacity: 1024,
        verification_cadence_n: 0,
        max_instance_count: cfg.max_instance_count.filter(|n| *n > 0),
        cooldown: cfg
            .cooldown_seconds
            .filter(|n| *n > 0)
            .map(|n| std::time::Duration::from_secs(u64::from(n))),
        session_limits,
    }
}

#[allow(clippy::too_many_arguments)]
fn wire_auto_spawn(
    cfg: &AutoSpawnConfigToml,
    params: &InspireParams,
    engine: Arc<raven_railgun_engine::Engine<RavenInspireScheme>>,
    chain_tree_routes: raven_railgun_engine::orchestrator::ChainTreeRoutes,
    tree_observed: tokio::sync::broadcast::Sender<u32>,
    initial_handles: &[raven_railgun_engine::orchestrator::PerInstanceHandles],
    opts: &MultiServeOptions,
    session_limits: SessionStoreLimits,
) -> anyhow::Result<AutoSpawnWiring> {
    use crate::auto_spawn_driver::{replay_spawn_log, run_driver_dynamic, SpawnRegistry};

    let runtime = runtime_from_auto_spawn_section(cfg, opts.entries, session_limits);

    let spawn_log_dir = match initial_handles.first() {
        Some(h) => h
            .config
            .data_dir
            .parent()
            .map_or_else(|| h.config.data_dir.clone(), std::path::PathBuf::from),
        None => std::path::PathBuf::from("."),
    };

    let registry = Arc::new(SpawnRegistry::new());
    registry.seed_from_bootstrap(initial_handles);

    let restored = replay_spawn_log(
        &runtime,
        params,
        &engine,
        &chain_tree_routes,
        &registry,
        spawn_log_dir.clone(),
        None,
    )
    .with_context(|| "replay spawn_log on startup")?;
    if !restored.is_empty() {
        tracing::info!(
            count = restored.len(),
            trees = ?restored,
            "auto_spawn: restored instances from spawn_log"
        );
    }

    let live_runtime = Arc::new(arc_swap::ArcSwap::from_pointee(runtime));
    let receiver = tree_observed.subscribe();
    let runtime_for_task = Arc::clone(&live_runtime);
    let params_for_task = params.clone();
    let engine_for_task = engine;
    let routes_for_task = chain_tree_routes;
    let registry_for_task = Arc::clone(&registry);
    let log_dir_for_task = spawn_log_dir.clone();
    let handle = tokio::spawn(async move {
        run_driver_dynamic(
            runtime_for_task,
            params_for_task,
            engine_for_task,
            routes_for_task,
            registry_for_task,
            log_dir_for_task,
            None,
            receiver,
        )
        .await;
    });
    Ok(AutoSpawnWiring {
        driver: handle,
        registry,
        live_runtime,
        spawn_log_dir,
    })
}

struct Bootstrap {
    handles: MultiOrchestratorHandle,
}

/// Row count `cfg` boots at: the resolved per-instance value, else `fleet_default`.
fn entries_for_instance(
    opts: &MultiServeOptions,
    cfg: &InstanceConfig,
    fleet_default: usize,
) -> usize {
    opts.instance_entries
        .get(&cfg.instance_id)
        .copied()
        .unwrap_or(fleet_default)
}

fn validate_instance_cell_shape(
    cfg: &InstanceConfig,
    entries: usize,
    ring_dim: usize,
) -> anyhow::Result<()> {
    raven_railgun_engine::pir_table::validate_cell_shape(
        &cfg.encoder,
        entries,
        cfg.record_size.max(32),
        ring_dim,
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "encoder cell shape rejected for instance {id}: {e}",
            id = cfg.instance_id
        )
    })?;
    raven_railgun_engine::pir_table::validate_rows_per_shard(cfg.entries_per_shard, ring_dim)
        .map_err(|e| {
            anyhow::anyhow!(
                "[global] entries_per_shard rejected for instance {id}: {e}",
                id = cfg.instance_id
            )
        })
}

fn bootstrap_instances(
    opts: &MultiServeOptions,
    fleet_default_entries: usize,
    params: &InspireParams,
    session_limits: SessionStoreLimits,
) -> anyhow::Result<Bootstrap> {
    let mut ids: HashSet<&InstanceId> = HashSet::with_capacity(opts.instances.len());
    for cfg in &opts.instances {
        if !ids.insert(&cfg.instance_id) {
            anyhow::bail!("duplicate instance id in config: {}", cfg.instance_id);
        }
        let entries = entries_for_instance(opts, cfg, fleet_default_entries);
        validate_instance_cell_shape(cfg, entries, params.ring_dim)?;
    }

    // Runs only for an instance no snapshot recovers.
    let factory = |cfg: &InstanceConfig, crs: Option<&Arc<ServerCrs>>| {
        let entries = entries_for_instance(opts, cfg, fleet_default_entries);
        let encoder = cfg.encoder.build(cfg.record_size, cfg.entries_per_shard)?;
        let shard_count = u32::try_from(entries.div_ceil(cfg.entries_per_shard.max(1) as usize))
            .map_err(|_| {
                raven_railgun_core::AdapterError::Internal(format!(
                    "instance {} declares {entries} rows, past a u32 shard count",
                    cfg.instance_id
                ))
            })?;
        let rows = empty_store_shard(encoder.as_ref(), shard_count)?;
        setup_unfilled_state(
            params,
            &rows,
            entries as u64,
            encoder.record_size(),
            InspireVariant::TwoPacking,
            crs,
        )
    };

    let handles = bootstrap_railgun_engine_multi_with_session_limits(
        opts.instances.clone(),
        params.clone(),
        session_limits,
        factory,
    )
    .map_err(|e| anyhow::anyhow!("bootstrap_railgun_engine_multi: {e}"))?;
    Ok(Bootstrap { handles })
}

struct ChainWorkers {
    handle: tokio::task::JoinHandle<()>,
    rpc_pool: Option<Arc<raven_railgun_indexer::rpc_pool::RpcEndpointPool>>,
    /// Mode flag for `/v1/health/ready.chain_source_mode`; `Some` when WS is set.
    chain_source_mode: Option<Arc<raven_railgun_indexer::ModeFlag>>,
    /// Polls `AutoFallbackChainSource.mode()` and writes through to `chain_source_mode`.
    mode_mirror: Option<tokio::task::JoinHandle<()>>,
    /// Cooperative shutdown signal for `mode_mirror`.
    mode_mirror_shutdown_tx: tokio::sync::watch::Sender<bool>,
}

async fn spawn_chain_indexer(
    opts: &MultiServeOptions,
    min_effective_start_block: u64,
    recovered_block_height: u64,
    reorg_window_required: bool,
    per_tree_start_blocks: BTreeMap<u32, u64>,
    resolved_reorg_window_path: Option<PathBuf>,
    indexer_tx: tokio::sync::mpsc::Sender<raven_railgun_indexer::IndexerMessage>,
) -> anyhow::Result<ChainWorkers> {
    use alloy::primitives::Address;
    use raven_railgun_indexer::rpc_pool::{
        DynChainSource, EndpointConfig, PoolConfig, PooledRpcChainSource, RpcEndpointPool,
    };
    use raven_railgun_indexer::{
        AutoFallbackChainSource, ChainSource, IndexerWorker, IndexerWorkerConfig, ModeFlag,
        RpcChainSource, WsChainSource, DEFAULT_POLL_INTERVAL_SECS,
    };

    let proxy_addr: Address = opts
        .railgun_proxy
        .parse()
        .with_context(|| format!("invalid railgun_proxy: {}", opts.railgun_proxy))?;

    let build_pool = |pool_cfg: &RpcPoolConfigToml| -> anyhow::Result<Arc<RpcEndpointPool>> {
        let endpoint_configs = pool_cfg
            .urls
            .iter()
            .map(|u| EndpointConfig {
                url: u.clone(),
                rps: pool_cfg.per_endpoint_rps,
                burst: pool_cfg.per_endpoint_burst,
            })
            .collect();
        let pool_config = PoolConfig {
            strategy: pool_cfg.strategy.into(),
            cooldown_secs_on_error: u64::from(pool_cfg.cooldown_secs.max(1)),
            ..PoolConfig::default()
        };
        let pool = Arc::new(
            RpcEndpointPool::new(endpoint_configs, pool_config)
                .map_err(|e| anyhow::anyhow!("rpc_pool init: {e}"))?,
        );
        tracing::info!(
            endpoints = pool.len(),
            strategy = ?pool.config().strategy,
            per_endpoint_rps = pool_cfg.per_endpoint_rps,
            per_endpoint_burst = pool_cfg.per_endpoint_burst,
            "rpc endpoint pool wired"
        );
        Ok(pool)
    };

    let (mode_mirror_shutdown_tx, mode_mirror_shutdown_rx) = tokio::sync::watch::channel(false);

    let (chain_source, rpc_pool, chain_source_mode) =
        match (opts.ws_endpoint.as_deref(), opts.rpc_pool.as_ref()) {
            (Some(ws_url), Some(pool_cfg)) if pool_cfg.urls.len() >= 2 => {
                let pool = build_pool(pool_cfg)?;
                let pooled = Arc::new(PooledRpcChainSource::new(
                    Arc::clone(&pool),
                    proxy_addr,
                    opts.chain_id,
                ));
                let ws = Arc::new(WsChainSource::new(ws_url, proxy_addr, opts.chain_id));
                let auto = Arc::new(AutoFallbackChainSource::new(ws, pooled));
                let mode_flag = Arc::new(ModeFlag::default());
                (
                    DynChainSource::AutoFallbackPooled(auto),
                    Some(pool),
                    Some(mode_flag),
                )
            }
            (Some(ws_url), _) => {
                let single_url = opts
                    .rpc_pool
                    .as_ref()
                    .and_then(|p| p.urls.first().cloned())
                    .unwrap_or_else(|| opts.rpc_url.clone());
                let single = Arc::new(RpcChainSource::new(
                    single_url,
                    proxy_addr,
                    opts.start_block,
                    opts.chain_id,
                ));
                let ws = Arc::new(WsChainSource::new(ws_url, proxy_addr, opts.chain_id));
                let auto = Arc::new(AutoFallbackChainSource::new(ws, single));
                let mode_flag = Arc::new(ModeFlag::default());
                (
                    DynChainSource::AutoFallbackSingle(auto),
                    None,
                    Some(mode_flag),
                )
            }
            (None, Some(pool_cfg)) if pool_cfg.urls.len() >= 2 => {
                let pool = build_pool(pool_cfg)?;
                let pooled = Arc::new(PooledRpcChainSource::new(
                    Arc::clone(&pool),
                    proxy_addr,
                    opts.chain_id,
                ));
                (DynChainSource::Pooled(pooled), Some(pool), None)
            }
            _ => {
                let url = opts
                    .rpc_pool
                    .as_ref()
                    .and_then(|p| p.urls.first().cloned())
                    .unwrap_or_else(|| opts.rpc_url.clone());
                let single = Arc::new(RpcChainSource::new(
                    url,
                    proxy_addr,
                    opts.start_block,
                    opts.chain_id,
                ));
                (DynChainSource::Single(single), None, None)
            }
        };

    let chain_source = Arc::new(chain_source);
    let head = chain_source
        .latest_block()
        .await
        .map_err(|e| anyhow::anyhow!("chain RPC unreachable: {e}"))?;
    tracing::info!(
        chain_head = head,
        start_block = opts.start_block,
        ws_endpoint = opts.ws_endpoint.as_deref().unwrap_or(""),
        "chain RPC reachable"
    );
    let worker = IndexerWorker::new(Arc::clone(&chain_source), indexer_tx);
    let worker_config = IndexerWorkerConfig {
        start_block: min_effective_start_block,
        configured_start_block: opts.start_block,
        recovered_block_height,
        reorg_window_required,
        poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
        reorg_window_path: resolved_reorg_window_path,
        per_tree_start_blocks,
        ..IndexerWorkerConfig::default()
    };
    let handle = worker
        .spawn_reconciled(worker_config)
        .await
        .map_err(|error| anyhow::anyhow!("chain indexer startup reconciliation: {error}"))?;
    let mode_mirror = match (chain_source.as_ref(), chain_source_mode.as_ref()) {
        (DynChainSource::AutoFallbackSingle(source), Some(mode)) => Some(spawn_mode_mirror_single(
            Arc::clone(source),
            Arc::clone(mode),
            mode_mirror_shutdown_rx,
        )),
        (DynChainSource::AutoFallbackPooled(source), Some(mode)) => Some(spawn_mode_mirror_pooled(
            Arc::clone(source),
            Arc::clone(mode),
            mode_mirror_shutdown_rx,
        )),
        _ => None,
    };
    Ok(ChainWorkers {
        handle,
        rpc_pool,
        chain_source_mode,
        mode_mirror,
        mode_mirror_shutdown_tx,
    })
}

/// `mode_mirror` sample cadence: keeps `chain_source_mode` within one tick of the source.
const MODE_MIRROR_TICK: std::time::Duration = std::time::Duration::from_secs(1);

fn spawn_mode_mirror_single(
    source: Arc<
        raven_railgun_indexer::AutoFallbackChainSource<
            raven_railgun_indexer::WsChainSource,
            raven_railgun_indexer::RpcChainSource,
        >,
    >,
    flag: Arc<raven_railgun_indexer::ModeFlag>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(MODE_MIRROR_TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    flag.set(source.mode().await);
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }
    })
}

fn spawn_mode_mirror_pooled(
    source: Arc<
        raven_railgun_indexer::AutoFallbackChainSource<
            raven_railgun_indexer::WsChainSource,
            raven_railgun_indexer::rpc_pool::PooledRpcChainSource,
        >,
    >,
    flag: Arc<raven_railgun_indexer::ModeFlag>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(MODE_MIRROR_TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    flag.set(source.mode().await);
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }
    })
}

impl ChainWorkers {
    /// Await before dropping `Self` so a `mode_mirror` panic is observed rather
    /// than hidden by `Drop`'s `abort()`. `false` on timeout.
    async fn shutdown_mode_mirror(&mut self, timeout: std::time::Duration) -> bool {
        let Some(handle) = self.mode_mirror.take() else {
            return true;
        };
        let _ = self.mode_mirror_shutdown_tx.send(true);
        match tokio::time::timeout(timeout, handle).await {
            Ok(Ok(())) => true,
            Ok(Err(e)) if e.is_cancelled() => true,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "mode_mirror task join error");
                false
            }
            Err(_) => {
                tracing::warn!(
                    timeout_secs = timeout.as_secs(),
                    "mode_mirror task did not observe shutdown signal within timeout"
                );
                false
            }
        }
    }
}

impl Drop for ChainWorkers {
    fn drop(&mut self) {
        let _ = self.mode_mirror_shutdown_tx.send(true);
        if let Some(handle) = self.mode_mirror.take() {
            handle.abort();
        }
        self.handle.abort();
    }
}

struct MirrorWorkers {
    handles: Vec<tokio::task::JoinHandle<()>>,
    feeds: Vec<FeedReport>,
}

/// One instance a list routes to, read afresh at every page and every readiness probe.
#[derive(Clone)]
struct ListInstance {
    data_source: DataSourceFilter,
    store: Arc<parking_lot::Mutex<LogicalLeafStore>>,
    persistence: Arc<raven_railgun_engine::persistence::InspirePersistence>,
}

impl ListInstance {
    fn rows(&self, list_key: &[u8; 32]) -> usize {
        list_rows(&self.store.lock(), list_key)
    }

    /// Its reach as it stands now.
    fn holding(&self, list_key: &[u8; 32]) -> Option<Holding> {
        let rows = self.rows(list_key);
        let (key, reach) = holding(self.data_source, rows)?;
        let refused = self.persistence.list_row_refused().is_some();
        (key == *list_key).then_some(Holding { refused, ..reach })
    }
}

/// What readiness reads of one list's feed: the feed's own progress, and every instance the
/// list routes to, read at probe time.
#[derive(Clone)]
struct FeedReport {
    list_key: [u8; 32],
    status: raven_railgun_ppoi_mirror::FeedStatus,
    instances: Vec<ListInstance>,
}

impl FeedReport {
    fn view(&self) -> raven_railgun_http::status::MirrorFeedView {
        let held: Vec<(DataSourceFilter, usize)> = self
            .instances
            .iter()
            .map(|instance| (instance.data_source, instance.rows(&self.list_key)))
            .collect();
        mirror_feed_view(&self.list_key, &self.status.snapshot(), &held)
    }
}

impl MirrorWorkers {
    fn readiness_probe(&self) -> raven_railgun_http::state::MirrorFeedProbe {
        let feeds = self.feeds.clone();
        Arc::new(move || feeds.iter().map(FeedReport::view).collect::<Vec<_>>())
    }
}

pub(crate) fn list_rows(store: &LogicalLeafStore, list_key: &[u8; 32]) -> usize {
    store
        .ppoi_imt(list_key)
        .map_or(0, raven_railgun_engine::imt::Imt::leaf_count)
}

// A caught-up feed renews the count the shim anchors a frontier on once per poll. The shim's bound
// has to outlast two failed polls in a row, each running to the request timeout.
const _: () = assert!(
    raven_railgun_http::shim_store::UPSTREAM_TIP_MAX_AGE_SECS
        >= 3 * raven_railgun_ppoi_mirror::DEFAULT_POLL_INTERVAL_SECS
            + raven_railgun_ppoi_mirror::REQUEST_TIMEOUT.as_secs()
);

async fn spawn_mirror_workers(
    opts: &MultiServeOptions,
    handle: &MultiOrchestratorHandle,
) -> anyhow::Result<MirrorWorkers> {
    use raven_railgun_ppoi_mirror::{
        ppoi_network_name, FeedStatus, MirrorConfig, UpstreamPpoiMirror,
    };

    let mirror_config = MirrorConfig {
        endpoint: opts.mirror_endpoint.clone(),
        chain_id: opts.chain_id,
        ..MirrorConfig::default()
    };
    let network = ppoi_network_name(&mirror_config.chain_type, mirror_config.chain_id);
    let mut mirror = UpstreamPpoiMirror::new(mirror_config)
        .map_err(|e| anyhow::anyhow!("ppoi mirror constructor: {e}"))?;
    if let Some(secs) = opts.mirror_backfill_interval_secs {
        mirror = mirror.with_backfill_interval(std::time::Duration::from_secs(secs));
    }
    // Readiness reads upstream's count from its node status while pages leave the tip unshown.
    if let Some(network) = network {
        mirror = mirror.with_node_status(network);
    }
    let mirror = Arc::new(mirror);
    let mirror_tx = handle.channels.mirror_tx.clone();
    ensure_mirror_preflight_metrics_described();

    let held: Vec<(DataSourceFilter, usize)> = handle
        .instances
        .iter()
        .filter_map(|inst| {
            let (list_key, _) = holding(inst.config.data_source, 0)?;
            let rows = list_rows(&inst.logical_store.lock(), &list_key);
            Some((inst.config.data_source, rows))
        })
        .collect();

    let mut handles = Vec::new();
    let mut feeds = Vec::new();
    for feed in mirror_feeds(&held) {
        let list = ListKey(feed.list_key);
        preflight_mirror_upstream(&mirror, &list, feed.holds_rows, "[global].mirror_endpoint")
            .await?;
        tracing::info!(
            list_key = %hex::encode(feed.list_key),
            resume_at = feed.resume_at,
            "ppoi mirror resuming at the lowest row any instance on the list lacks"
        );
        let on_list: Vec<&PerInstanceHandles> = handle
            .instances
            .iter()
            .filter(|inst| {
                holding(inst.config.data_source, 0).is_some_and(|(key, _)| key == feed.list_key)
            })
            .collect();
        let instances: Vec<ListInstance> = on_list
            .iter()
            .map(|inst| ListInstance {
                data_source: inst.config.data_source,
                store: Arc::clone(&inst.logical_store),
                persistence: Arc::clone(&inst.persistence),
            })
            .collect();
        let status = FeedStatus::default();
        feeds.push(FeedReport {
            list_key: feed.list_key,
            status: status.clone(),
            instances: instances.clone(),
        });
        for instance in &instances {
            instance.persistence.set_backfilling(true);
        }
        handles.push(tokio::spawn(end_backfill_once_caught_up(
            status.clone(),
            feed.list_key,
            instances.clone(),
        )));
        let list_key = feed.list_key;
        let live = move || {
            instances
                .iter()
                .filter_map(|instance| instance.holding(&list_key))
                .collect()
        };
        handles.push(tokio::spawn(run_mirror_feed(
            Arc::clone(&mirror),
            feed,
            live,
            Arc::clone(&handle.ppoi_list_routes),
            mirror_tx.clone(),
            status,
        )));
    }
    Ok(MirrorWorkers { handles, feeds })
}

/// How often a backfilling list checks whether its feed has caught up.
const CAUGHT_UP_POLL: std::time::Duration = std::time::Duration::from_secs(1);

/// Holds the list's instances in backfill until each holds every row of its reach upstream has,
/// as counted by the feed's first answer short of a page (the only answer that says upstream has
/// no row past it), or until the feed stops. Each then publishes what it holds and goes back to
/// its snapshot policy for good. Rows still on their way when upstream answers short would
/// otherwise land after that publish and wait out the publish bound.
async fn end_backfill_once_caught_up(
    status: raven_railgun_ppoi_mirror::FeedStatus,
    list_key: [u8; 32],
    instances: Vec<ListInstance>,
) {
    let mut tick = tokio::time::interval(CAUGHT_UP_POLL);
    loop {
        tick.tick().await;
        let progress = status.snapshot();
        let caught_up = progress.upstream_rows.is_some_and(|tip| {
            instances
                .iter()
                .filter_map(|instance| instance.holding(&list_key))
                .all(|reach| reach.next >= tip.clamp(reach.first, reach.end))
        });
        if caught_up || progress.stopped.is_some() {
            for instance in &instances {
                instance.persistence.set_backfilling(false);
            }
            return;
        }
    }
}

/// One list's feed, stopped in front of the first row no route on the list can hold.
///
/// Past the last declared block no route holds a row, so a feed that walked on would count it
/// delivered while it is lost. Stopping there keeps the row for the block an operator declares
/// next, and naming that block's target holds readiness down until then.
///
/// `holdings` reads every instance on the list as it stands at the call.
async fn run_mirror_feed(
    mirror: Arc<raven_railgun_ppoi_mirror::UpstreamPpoiMirror>,
    feed: MirrorFeed,
    holdings: impl Fn() -> Vec<Holding> + Send + 'static,
    routes: raven_railgun_engine::orchestrator::PpoiListRoutes,
    tx: tokio::sync::mpsc::Sender<(raven_railgun_persistence::WalEntryPayload, u64)>,
    status: raven_railgun_ppoi_mirror::FeedStatus,
) {
    let list_key = feed.list_key;
    let span = move |cursor| {
        feed_span(&holdings(), cursor, |at| {
            first_unheld_index(routes.iter().map(|(filter, _)| *filter), &list_key, at)
        })
    };
    match mirror
        .run_feed(ListKey(list_key), feed.resume_at, span, status, tx)
        .await
    {
        Ok(()) => {}
        Err(raven_railgun_ppoi_mirror::MirrorError::Unheld { list_index }) => {
            let target = format!(
                "list:{}:block:{}",
                hex::encode(list_key),
                list_index / u64::from(LEAVES_PER_PPOI_BLOCK)
            );
            raven_railgun_engine::orchestrator::mark_router_unrouted_target(&target);
            tracing::error!(
                %target,
                list_index,
                "ppoi mirror stopped: no instance holds the next row; declare the block that \
                 holds it and restart"
            );
        }
        Err(e) => tracing::error!(error = %e, "ppoi mirror worker exiting"),
    }
}

/// The first list-wide index at or after `cursor` that no route on `list_key` can hold. A
/// block route holds its block.
pub(crate) fn first_unheld_index(
    filters: impl IntoIterator<Item = DataSourceFilter>,
    list_key: &[u8; 32],
    cursor: u64,
) -> u64 {
    let held: Vec<std::ops::Range<u64>> = filters
        .into_iter()
        .filter_map(|filter| match holding(filter, 0) {
            Some((key, reach)) if key == *list_key => Some(reach.first..reach.end),
            _ => None,
        })
        .collect();
    let mut at = cursor;
    while let Some(range) = held.iter().find(|range| range.contains(&at)) {
        at = range.end;
    }
    at
}

/// One instance's reach on a list: it can hold list-wide rows `first..end`, and has applied every
/// row below `next`. `refused`: it was sent row `next` or one past it and refused it, so `next`
/// is not merely still on its way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Holding {
    first: u64,
    end: u64,
    next: u64,
    refused: bool,
}

/// The list an instance holding `rows` of it is fed from, and its reach: its block, at
/// block-local indices. The boot builds no other PPOI route.
pub(crate) fn holding(source: DataSourceFilter, rows: usize) -> Option<([u8; 32], Holding)> {
    let (list_key, first, capacity) = match source {
        DataSourceFilter::PpoiListBlock { list_key, block } => (
            list_key,
            u64::from(block) * u64::from(LEAVES_PER_PPOI_BLOCK),
            u64::from(LEAVES_PER_PPOI_BLOCK),
        ),
        DataSourceFilter::ChainTreeNumber(_) => return None,
    };
    let rows = (rows as u64).min(capacity);
    Some((
        list_key,
        Holding {
            first,
            end: first + capacity,
            next: first + rows,
            refused: false,
        },
    ))
}

/// The rows a feed at `cursor` asks for next: from the lowest index some instance still has to
/// append, to the first index past that which no instance needs. Neither end passes the first
/// row, counted from the list's lowest declared one, that no route holds; an empty span there
/// stops the feed on that row.
///
/// `holdings` are read live. Each frontier is read as advanced by every row the feed delivered
/// below `cursor`, which the router gave to every instance whose reach covers it, so rows still
/// on their way to a consumer are never asked for again. The one exception is a refused row: an
/// instance that refused its next row starts the span there, below the cursor, and the feed
/// comes back for it. A row every instance that can hold it already holds is never asked for
/// again, and a duplicate that does arrive is skipped by the consumer. A row no route holds is
/// never stepped over either: a block declared past a gap would otherwise read as caught up
/// while the gap's rows went unserved.
pub(crate) fn feed_span(
    holdings: &[Holding],
    cursor: u64,
    first_unheld: impl Fn(u64) -> u64,
) -> std::ops::Range<u64> {
    let covered = first_unheld(
        holdings
            .iter()
            .map(|reach| reach.first)
            .min()
            .unwrap_or(cursor),
    );
    let lacking: Vec<std::ops::Range<u64>> = holdings
        .iter()
        .map(|reach| {
            let from = if reach.refused {
                reach.next
            } else {
                reach.next.max(cursor.min(reach.end))
            };
            from..reach.end.min(covered)
        })
        .filter(|range| !range.is_empty())
        .collect();
    let Some(start) = lacking.iter().map(|range| range.start).min() else {
        return covered..covered;
    };
    let mut end = start;
    while let Some(further) = lacking
        .iter()
        .filter(|range| range.contains(&end))
        .map(|range| range.end)
        .max()
    {
        end = further;
    }
    start..end
}

/// One upstream feed for a PPOI list.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MirrorFeed {
    pub(crate) list_key: [u8; 32],
    /// List-wide index of the first row the worker asks for.
    pub(crate) resume_at: u64,
    /// A property of the LIST, not of one instance: a list's rows sit in several blocks, and
    /// a block past the frontier reads zero.
    pub(crate) holds_rows: bool,
}

/// One feed per PPOI list, in config order, resuming at the lowest list-wide index that some
/// instance on the list can still append.
///
/// The router fans each row to every instance on the key, so one worker feeds them all; a
/// second re-delivers every row, and each copy is refused as a duplicate. A list declared only
/// in blocks gets its worker too.
///
/// Instances on one key need not agree. One restored from an older snapshot, or added later,
/// stands behind the rest, and a feed that resumes past it leaves it refusing every later row
/// as non-contiguous, for good. The store is the cursor: the start is read off every instance's
/// replayed rows, and no sidecar is consulted, so a sidecar that is missing, torn, or written
/// ahead of rows that never reached the WAL can neither skip a row nor rewind the feed. A full
/// instance appends nothing more and does not hold the feed back; once all are full the feed
/// resumes where the declared coverage ends.
pub(crate) fn mirror_feeds(held: &[(DataSourceFilter, usize)]) -> Vec<MirrorFeed> {
    let mut lists: Vec<([u8; 32], Vec<Holding>)> = Vec::new();
    for &(source, rows) in held {
        let Some((list_key, reach)) = holding(source, rows) else {
            continue;
        };
        match lists.iter_mut().find(|(key, _)| *key == list_key) {
            Some((_, holdings)) => holdings.push(reach),
            None => lists.push((list_key, vec![reach])),
        }
    }
    lists
        .into_iter()
        .map(|(list_key, holdings)| {
            let lowest_open = holdings
                .iter()
                .filter(|reach| reach.next < reach.end)
                .map(|reach| reach.next)
                .min();
            let highest_held = holdings.iter().map(|reach| reach.next).max().unwrap_or(0);
            MirrorFeed {
                list_key,
                resume_at: lowest_open.unwrap_or(highest_held),
                holds_rows: holdings.iter().any(|reach| reach.next > reach.first),
            }
        })
        .collect()
}

/// One list's feed as readiness reports it, from the feed's progress and the rows each instance
/// on the list holds now.
pub(crate) fn mirror_feed_view(
    list_key: &[u8; 32],
    progress: &raven_railgun_ppoi_mirror::FeedProgress,
    held: &[(DataSourceFilter, usize)],
) -> raven_railgun_http::status::MirrorFeedView {
    use raven_railgun_http::status::{MirrorFeedState, MirrorFeedView};
    let holdings: Vec<Holding> = held
        .iter()
        .filter_map(|&(source, rows)| holding(source, rows))
        .filter(|(key, _)| key == list_key)
        .map(|(_, reach)| reach)
        .collect();
    let rows_held = holdings
        .iter()
        .filter(|reach| reach.next > reach.first)
        .map(|reach| reach.next)
        .max()
        .unwrap_or(0);
    let caught_up = progress.upstream_rows.is_some_and(|tip| {
        holdings
            .iter()
            .all(|reach| reach.next >= tip.clamp(reach.first, reach.end))
    });
    // Named only while an instance whose reach covers it still lacks it; the feed clears its
    // own name a page later.
    let untaken = progress.untaken_row.filter(|row| {
        holdings
            .iter()
            .any(|reach| (reach.first..reach.end).contains(row) && reach.next <= *row)
    });
    let state = if progress.stopped.is_some() {
        MirrorFeedState::Stopped
    } else if rows_held == 0 {
        MirrorFeedState::NeverFed
    } else if progress.consecutive_failures > 0 {
        MirrorFeedState::UpstreamRefusing
    } else if caught_up {
        MirrorFeedState::CaughtUp
    } else {
        MirrorFeedState::Syncing
    };
    MirrorFeedView {
        list_key: hex::encode(list_key),
        state,
        rows_held,
        upstream_rows: progress.upstream_rows,
        upstream_rows_seen: progress.upstream_rows_seen,
        next_index: progress.next_index,
        consecutive_failures: progress.consecutive_failures,
        last_failure: untaken
            .map(|row| format!("no instance took row {row}; asking for it again"))
            .or_else(|| progress.last_failure.map(|class| class.to_string())),
        seconds_since_answer: progress.last_answer.map(|at| at.elapsed().as_secs()),
    }
}

impl Drop for MirrorWorkers {
    fn drop(&mut self) {
        for h in &self.handles {
            h.abort();
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {

    mod stop_budget {
        use super::super::run_stops_until;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::time::Duration;

        /// A final commit that never returns must not hold the stop past its budget, and the
        /// ones that do return must all run, however many share the slots.
        #[tokio::test]
        async fn a_stop_that_never_finishes_is_abandoned_at_the_budget() {
            let finished = Arc::new(AtomicUsize::new(0));
            let mut stops: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> =
                vec![Box::pin(std::future::pending())];
            for _ in 0..5 {
                let finished = Arc::clone(&finished);
                stops.push(Box::pin(async move {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    finished.fetch_add(1, Ordering::SeqCst);
                }));
            }
            let stop_by = tokio::time::Instant::now() + Duration::from_millis(600);
            let unfinished =
                tokio::time::timeout(Duration::from_secs(10), run_stops_until(stops, 2, stop_by))
                    .await
                    .expect("the stop outlived its budget");
            assert_eq!(unfinished, 1);
            assert_eq!(finished.load(Ordering::SeqCst), 5);
        }
    }

    /// The tree-fill watcher's decision, at the boundary that caused the tree-4 outage.
    ///
    /// `run_tree_fill_watcher` was an unbounded `loop` with no entry point, so the mechanism whose
    /// absence stranded ~1,488 leaves had zero tests. `tree_fill_watcher_tick` is that loop's body.
    ///
    /// Covered here: the paths that decide WHETHER to spawn. The `Spawned` / `AlreadyKnown` arms
    /// are not - reaching them needs a seeded `SpawnRegistry`, which needs `PerInstanceHandles`,
    /// which needs a real bootstrapped instance. That is the production-cell cost the ignored test
    /// at `smart_policy_deferred.rs` pays, and it is red for an unrelated fixture reason. Stated
    /// rather than papered over: this covers the comparison, not the spawn.
    mod tree_fill_watcher {
        use super::super::{compute_trigger_threshold, WATCHER_TREE_MAX_ITEMS};

        #[test]
        fn the_trigger_sits_below_a_full_tree_and_leaves_headroom() {
            let trigger = compute_trigger_threshold(0.95, WATCHER_TREE_MAX_ITEMS);
            assert!(
                trigger < WATCHER_TREE_MAX_ITEMS as usize,
                "a trigger at or above capacity fires only once the tree is full, which is the \
                 outage: got {trigger} against a {WATCHER_TREE_MAX_ITEMS}-leaf tree"
            );
            let headroom = WATCHER_TREE_MAX_ITEMS as usize - trigger;
            assert!(
                headroom >= 1_024,
                "only {headroom} leaves of warning; a successor instance must be bootstrapped \
                 before the tree fills"
            );
        }

        /// The trigger must land where the fraction says, and must move when the fraction moves.
        ///
        /// The first draft of this test asserted `trigger - 1 < trigger` and `!(trigger < trigger)`.
        /// Both are true for every integer, so they tested nothing - a tautology dressed as a
        /// boundary check, which clippy caught. These assertions can fail: a rounding change, an
        /// off-by-one, or a clamp applied to the wrong operand all move at least one of them.
        #[test]
        fn the_trigger_tracks_the_fraction_and_is_strictly_monotonic() {
            assert_eq!(
                compute_trigger_threshold(0.95, WATCHER_TREE_MAX_ITEMS),
                62_259,
                "0.95 of a 65,536-leaf tree"
            );
            assert_eq!(
                compute_trigger_threshold(0.5, WATCHER_TREE_MAX_ITEMS),
                32_768
            );

            let mut previous = 0usize;
            for step in 1..=19u32 {
                let fraction = f32::from(u16::try_from(step).expect("< 20")) / 20.0;
                let trigger = compute_trigger_threshold(fraction, WATCHER_TREE_MAX_ITEMS);
                assert!(
                    trigger > previous,
                    "raising the fraction to {fraction} must raise the trigger: \
                     got {trigger} after {previous}"
                );
                assert!(
                    trigger < WATCHER_TREE_MAX_ITEMS as usize,
                    "a fraction below 1.0 must leave headroom; {fraction} gave {trigger}"
                );
                previous = trigger;
            }
        }

        /// A threshold outside 0.0..=1.0 disables the watcher, and the loop returns early. The
        /// clamp must not silently turn a nonsense value into a working one.
        #[test]
        fn an_out_of_range_threshold_clamps_rather_than_wrapping() {
            assert_eq!(
                compute_trigger_threshold(2.0, WATCHER_TREE_MAX_ITEMS),
                WATCHER_TREE_MAX_ITEMS as usize
            );
            assert_eq!(compute_trigger_threshold(-1.0, WATCHER_TREE_MAX_ITEMS), 0);
            assert_eq!(
                compute_trigger_threshold(f32::NAN, WATCHER_TREE_MAX_ITEMS),
                0
            );
        }
    }

    use super::*;

    fn write_temp_toml(body: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(body.as_bytes()).expect("write");
        f
    }

    #[test]
    fn parse_chain_and_ppoi_instances_ok() {
        let body = r#"
[global]
bind = "127.0.0.1:0"
token = "test-token-padded-long-enough"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"

[[instance]]
id = "tree-0"
role = "static"
encoder = "per-leaf-path"
tree_number = 0
data_dir = "/tmp/raven-tree-0"
data_source = { kind = "indexer", filter = { tree_number = 0 } }

[[instance]]
id = "ppoi-paths-0"
role = "live"
encoder = "per-list-path10"
list_key = "0000000000000000000000000000000000000000000000000000000000000001"
data_dir = "/tmp/raven-ppoi"
data_source = { kind = "mirror", list_key = "0000000000000000000000000000000000000000000000000000000000000001", block = 0 }
"#;
        let f = write_temp_toml(body);
        let opts = load_options_from_toml(f.path()).expect("parse");
        assert_eq!(opts.instances.len(), 2);
        assert!(matches!(
            opts.instances[0].encoder,
            EncoderKind::PerLeafPath { tree_number: 0 }
        ));
        assert!(matches!(
            opts.instances[0].data_source,
            DataSourceFilter::ChainTreeNumber(0)
        ));
        assert!(matches!(
            opts.instances[1].encoder,
            EncoderKind::PerListPath10 { .. }
        ));
        assert!(matches!(
            opts.instances[1].data_source,
            DataSourceFilter::PpoiListBlock { block: 0, .. }
        ));
    }

    fn ppoi_only_config(extra_global: &str) -> String {
        let key = "0000000000000000000000000000000000000000000000000000000000000001";
        format!(
            r#"
[global]
bind = "127.0.0.1:0"
token = "test-token-padded-long-enough"
chain_id = 1
mirror_endpoint = "http://127.0.0.1:1"
{extra_global}
[[instance]]
id = "ppoi-paths-0"
role = "live"
encoder = "per-list-path10"
list_key = "{key}"
data_dir = "/nonexistent/raven-ppoi"
data_source = {{ kind = "mirror", list_key = "{key}", block = 0 }}
"#
        )
    }

    /// `HttpConfig::validate` tells an operator to raise these, so the config file must be
    /// able to.
    #[test]
    fn every_session_and_permit_knob_is_settable_from_the_config_file() {
        let f = write_temp_toml(&ppoi_only_config(
            "max_sessions_per_instance = 7\nsession_lru_cap = 777\n\
             max_concurrent_handshakes = 3\nrespond_permit_wait_ms = 1234\n",
        ));
        let config = build_http_config(&load_options_from_toml(f.path()).expect("load"));
        assert_eq!(config.max_sessions_per_instance, 7);
        assert_eq!(config.session_lru_cap, 777);
        assert_eq!(config.max_concurrent_handshakes, 3);
        assert_eq!(config.respond_permit_wait_ms, 1234);
        config.validate().expect("the configured values validate");
    }

    #[derive(Clone, Default)]
    struct CapturedLog(Arc<parking_lot::Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLog {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn errors_logged_while(load: impl FnOnce()) -> String {
        let log = CapturedLog::default();
        let writer = log.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_max_level(tracing::Level::ERROR)
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, load);
        let bytes = log.0.lock().clone();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[test]
    fn a_disabled_writer_lock_is_logged_as_an_error_at_load() {
        let off = write_temp_toml(&ppoi_only_config("use_flock = false\n"));
        let logged = errors_logged_while(|| {
            load_options_from_toml(off.path()).expect("load");
        });
        assert!(logged.contains("ERROR"), "{logged}");
        assert!(logged.contains("use_flock = false"), "{logged}");

        let on = write_temp_toml(&ppoi_only_config(""));
        let logged = errors_logged_while(|| {
            load_options_from_toml(on.path()).expect("load");
        });
        assert!(!logged.contains("use_flock"), "{logged}");
    }

    #[tokio::test]
    #[allow(clippy::panic)]
    async fn a_final_commit_that_did_not_land_is_reported() {
        let instance = raven_railgun_core::InstanceId::new("stop-report");
        let (landed, refused, panicked) = tokio::join!(
            final_commit_landed(
                tokio::sync::mpsc::channel(1).0,
                tokio::spawn(async { Ok(()) }),
                &instance,
            ),
            final_commit_landed(
                tokio::sync::mpsc::channel(1).0,
                tokio::spawn(async {
                    Err(raven_railgun_core::AdapterError::Internal(
                        "commit refused".to_owned(),
                    ))
                }),
                &instance,
            ),
            final_commit_landed(
                tokio::sync::mpsc::channel(1).0,
                tokio::spawn(async { panic!("consumer panicked") }),
                &instance,
            ),
        );
        assert_eq!((landed, refused, panicked), (true, false, false));
    }

    #[test]
    fn a_stop_that_left_an_instance_unpublished_is_an_error() {
        let stop = |unfinished, failed| StopIncomplete {
            unfinished,
            failed,
            budget: STOP_BUDGET,
        };
        stop_outcome(stop(0, 0)).expect("a complete stop");
        for (unfinished, failed) in [(1, 0), (0, 1)] {
            let error = stop_outcome(stop(unfinished, failed)).expect_err("an incomplete stop");
            assert_eq!(
                error.downcast_ref::<StopIncomplete>(),
                Some(&stop(unfinished, failed))
            );
            assert!(error.to_string().contains("stop budget"), "{error}");
        }
    }

    /// A PPOI instance holds one block of its list. Neither a whole-list instance, a status
    /// instance nor the keys that once chose between them can be configured.
    #[test]
    fn a_ppoi_instance_must_name_its_block_and_the_retired_keys_are_refused() {
        let base = list_mismatch_config("aa", "aa");
        let cases = [
            (
                "a mirror data source without a block",
                base.replace(", block = 0", ""),
                "block",
            ),
            (
                "data_source.what",
                base.replace(", block = 0", ", block = 0, what = \"path\""),
                "what",
            ),
            (
                "verification_mode",
                base.replace(
                    "data_dir = ",
                    "verification_mode = \"upstream-asserted\"\ndata_dir = ",
                ),
                "verification_mode",
            ),
            (
                "[[ppoi_list_template]]",
                format!(
                    "{base}\n[[ppoi_list_template]]\ntemplate_id = \"t\"\nlist_key = \"{}\"\n\
                     encoder = \"per-list-path10\"\ndata_dir_template = \"/tmp/{{list_key}}\"\n",
                    "aa".repeat(32)
                ),
                "ppoi_list_template",
            ),
        ];
        for (case, body, needle) in cases {
            let f = write_temp_toml(&body);
            let err = load_options_from_toml(f.path())
                .map(|_| ())
                .expect_err(case);
            let msg = format!("{err:#}");
            assert!(
                msg.contains(needle),
                "{case}: the refusal must name {needle}: {msg}"
            );
        }
    }

    /// A tree-pinned encoder whose pin disagrees with the tree routed to it must be
    /// refused at parse time. The encoder filters every foreign-tree event, so the
    /// instance would serve its own tree's rows unchanged at HTTP 200 - no error, no
    /// empty response, just a permanently stale tree wearing a healthy status.
    #[test]
    fn an_encoder_pinned_to_another_tree_than_its_data_source_is_refused() {
        let body = &tree_mismatch_config(0, 3);
        let f = write_temp_toml(body);
        let err = load_options_from_toml(f.path())
            .expect_err("a tree-0 encoder fed tree-3 events must be refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("pinned to tree 0") && msg.contains("routes tree 3"),
            "the refusal must name both trees; got: {msg}"
        );
    }

    /// The agreeing case must still parse, so the guard cannot be satisfied by
    /// refusing every tree-pinned instance.
    #[test]
    fn an_encoder_pinned_to_the_tree_it_is_routed_still_parses() {
        let body = &tree_mismatch_config(3, 3);
        let f = write_temp_toml(body);
        let opts = load_options_from_toml(f.path()).expect("matching trees must parse");
        assert!(matches!(
            opts.instances[0].encoder,
            EncoderKind::PerNode { tree_number: 3 }
        ));
    }

    /// `per-leaf-bc` indexes rows by `leaf_index` alone, so its pin is what keeps a
    /// second tree out of the store. It must be validated like every other pinned kind.
    #[test]
    fn a_per_leaf_bc_encoder_pinned_to_another_tree_is_refused() {
        let body = tree_mismatch_config(0, 3).replace("per-node", "per-leaf-bc");
        let f = write_temp_toml(&body);
        let err = load_options_from_toml(f.path())
            .expect_err("a per-leaf-bc encoder pinned to tree 0 fed tree 3 must be refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("pinned to tree 0") && msg.contains("routes tree 3"),
            "the refusal must name both trees; got: {msg}"
        );
    }

    /// The per-list twin of the tree-pin gate. A per-list encoder drops every event for a
    /// foreign `list_key` and materializes from its own list's IMT, so the instance would
    /// serve an all-zero cell at HTTP 200 forever - no error, no empty body, just zeros.
    #[test]
    fn an_encoder_pinned_to_another_list_than_its_data_source_is_refused() {
        let f = write_temp_toml(&list_mismatch_config("aa", "bb"));
        let err = load_options_from_toml(f.path())
            .expect_err("a list-aa encoder fed list-bb events must be refused");
        let msg = format!("{err:#}");
        for needle in [
            "ppoi-list-pin",
            &"aa".repeat(32),
            &"bb".repeat(32),
            "data_source.list_key",
        ] {
            assert!(
                msg.contains(needle),
                "the refusal must name {needle}; got: {msg}"
            );
        }
    }

    /// The conjunct that keeps the guard honest: refusing every per-list instance would
    /// also satisfy the two tests above.
    #[test]
    fn an_encoder_pinned_to_the_list_it_is_routed_still_parses() {
        let f = write_temp_toml(&list_mismatch_config("aa", "aa"));
        let opts = load_options_from_toml(f.path()).expect("matching list keys must parse");
        assert_eq!(pinned_list_key(opts.instances[0].encoder), Some([0xaa; 32]));
    }

    /// Operators paste keys in both spellings, so `0x` must name the same list, byte for byte.
    #[test]
    fn a_0x_prefixed_list_key_loads_to_the_same_bytes() {
        use std::fmt::Write as _;
        let key: [u8; 32] = std::array::from_fn(|at| u8::try_from(at * 7 + 1).unwrap_or(0));
        let spelled = key.iter().fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02X}");
            hex
        });
        let body =
            list_mismatch_config("aa", "aa").replace(&"aa".repeat(32), &format!("0x{spelled}"));
        let f = write_temp_toml(&body);
        let opts = load_options_from_toml(f.path()).expect("a 0x-prefixed list key must parse");
        assert_eq!(pinned_list_key(opts.instances[0].encoder), Some(key));
        assert!(matches!(
            opts.instances[0].data_source,
            DataSourceFilter::PpoiListBlock { list_key, block: 0 } if list_key == key
        ));
    }

    fn list_mismatch_config(encoder_byte: &str, routed_byte: &str) -> String {
        let encoder_key = encoder_byte.repeat(32);
        let routed_key = routed_byte.repeat(32);
        format!(
            r#"
[global]
bind = "127.0.0.1:0"
token = "test-token-padded-long-enough"
chain_id = 1
mirror_endpoint = "http://127.0.0.1:1"

[[instance]]
id = "ppoi-list-pin"
role = "live"
encoder = "per-list-path10"
list_key = "{encoder_key}"
data_dir = "/tmp/raven-ppoi-list-pin"
data_source = {{ kind = "mirror", list_key = "{routed_key}", block = 0 }}
"#
        )
    }

    fn tree_mismatch_config(encoder_tree: u32, routed_tree: u32) -> String {
        format!(
            r#"
[global]
bind = "127.0.0.1:0"
token = "test-token-padded-long-enough"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"

[[instance]]
id = "tree-pin"
role = "static"
encoder = "per-node"
tree_number = {encoder_tree}
data_dir = "/tmp/raven-tree-pin"
data_source = {{ kind = "indexer", filter = {{ tree_number = {routed_tree} }} }}
"#
        )
    }

    #[test]
    fn placeholder_bearer_token_rejected_at_parse_time() {
        let body = r#"
[global]
bind = "127.0.0.1:0"
token = "REPLACE_ME"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"

[[instance]]
id = "tree-0"
role = "static"
encoder = "per-leaf-path"
tree_number = 0
data_dir = "/tmp/raven-tree-0"
data_source = { kind = "indexer", filter = { tree_number = 0 } }
"#;
        let f = write_temp_toml(body);
        let err = load_options_from_toml(f.path())
            .expect_err("parse must reject the literal placeholder token");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("REPLACE_ME"),
            "error must mention the placeholder string for operator forensics; got: {msg}"
        );
    }

    fn config_with_global_extras(extras: &str) -> String {
        format!(
            r#"
[global]
bind = "127.0.0.1:0"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"
{extras}

[[instance]]
id = "tree-0"
role = "static"
encoder = "per-leaf-path"
tree_number = 0
data_dir = "/tmp/raven-tree-0"
data_source = {{ kind = "indexer", filter = {{ tree_number = 0 }} }}
"#
        )
    }

    #[test]
    fn token_file_sources_the_bearer_token() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let token_path = dir.path().join("bearer-token");
        std::fs::write(&token_path, "file-sourced-token-long-enough\n").expect("write token file");
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod token file");

        let body =
            config_with_global_extras(&format!("token_file = {:?}", token_path.to_string_lossy()));
        let f = write_temp_toml(&body);
        let opts = load_options_from_toml(f.path()).expect("token_file is a valid single source");
        assert_eq!(opts.token, "file-sourced-token-long-enough");
    }

    #[test]
    fn token_and_token_file_together_are_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let token_path = dir.path().join("bearer-token");
        std::fs::write(&token_path, "file-sourced-token").expect("write token file");

        let body = config_with_global_extras(&format!(
            "token = \"inline-token-long-enough\"\ntoken_file = {:?}",
            token_path.to_string_lossy()
        ));
        let f = write_temp_toml(&body);
        let err = load_options_from_toml(f.path()).expect_err("two sources must be rejected");
        let msg = format!("{err:#}");
        assert!(msg.contains("[global].token,"), "{msg}");
        assert!(msg.contains("[global].token_file"), "{msg}");
    }

    /// The token opens `/metrics` alone, and `--metrics-public` is applied after the load, so
    /// no source at all is judged at boot; `tests/metrics_token_boot_gate.rs` holds that half.
    #[test]
    fn no_token_source_at_all_loads_with_an_empty_token() {
        let body = config_with_global_extras("");
        let f = write_temp_toml(&body);
        let opts = load_options_from_toml(f.path()).expect("zero sources must load");
        assert!(opts.token.is_empty(), "no source must leave no token");
    }

    #[test]
    fn trusted_proxy_cidrs_reach_the_serve_options() {
        let body = config_with_global_extras(
            "token = \"test-token-padded-long-enough\"\n\
             trust_proxy_header = true\n\
             trusted_proxy_cidrs = [\"127.0.0.1/32\", \"fd00::/8\"]",
        );
        let f = write_temp_toml(&body);
        let opts = load_options_from_toml(f.path()).expect("parse");
        assert_eq!(opts.trust_proxy_header, Some(true));
        assert_eq!(
            opts.trusted_proxy_cidrs.as_deref(),
            Some(["127.0.0.1/32".to_owned(), "fd00::/8".to_owned()].as_slice())
        );
    }

    #[test]
    fn bare_trust_proxy_header_is_rejected_at_parse_time() {
        let body = config_with_global_extras(
            "token = \"test-token-padded-long-enough\"\ntrust_proxy_header = true",
        );
        let f = write_temp_toml(&body);
        let err =
            load_options_from_toml(f.path()).expect_err("unscoped proxy trust must not reach boot");
        let msg = format!("{err:#}");
        assert!(msg.contains("trusted_proxy_cidrs"), "{msg}");
    }

    #[test]
    fn trusted_proxy_cidrs_without_trust_are_rejected_at_parse_time() {
        let body = config_with_global_extras(
            "token = \"test-token-padded-long-enough\"\n\
             trusted_proxy_cidrs = [\"127.0.0.1/32\"]",
        );
        let f = write_temp_toml(&body);
        let err = load_options_from_toml(f.path())
            .expect_err("ranges that cannot apply must not reach boot");
        assert!(
            format!("{err:#}").contains("trust_proxy_header = false"),
            "{err:#}"
        );
    }

    #[test]
    fn a_malformed_trusted_proxy_cidr_is_rejected_at_parse_time() {
        let body = config_with_global_extras(
            "token = \"test-token-padded-long-enough\"\n\
             trust_proxy_header = true\n\
             trusted_proxy_cidrs = [\"172.16.0.1/12\"]",
        );
        let f = write_temp_toml(&body);
        let err = load_options_from_toml(f.path()).expect_err("host bits must be rejected");
        assert!(format!("{err:#}").contains("172.16.0.0/12"), "{err:#}");
    }

    #[test]
    fn ifma52_small_cell_threshold_predicate() {
        let body = r#"
[global]
bind = "127.0.0.1:0"
token = "test-token-padded-long-enough"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"
record_size = 512

[[instance]]
id = "tree-0"
role = "static"
encoder = "per-leaf-path"
tree_number = 0
data_dir = "/tmp/raven-tree-0"
data_source = { kind = "indexer", filter = { tree_number = 0 } }
"#;
        let f = write_temp_toml(body);
        let opts = load_options_from_toml(f.path()).expect("parse");

        assert!(
            !ifma52_small_cell_threshold_breached(&opts, 1usize << 16),
            "production cell (65536 x 512 B) must NOT breach the small-cell threshold"
        );

        assert!(
            ifma52_small_cell_threshold_breached(&opts, (1usize << 16) - 1),
            "entries < 2^16 must breach the small-cell threshold"
        );

        // per-leaf-bc, not a path encoder: path encoders pin PATH_RECORD_BYTES and
        // `[global].record_size = 32` would never reach the instance.
        let body_small = r#"
[global]
bind = "127.0.0.1:0"
token = "test-token-padded-long-enough"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"
record_size = 32

[[instance]]
id = "tree-0"
role = "static"
encoder = "per-leaf-bc"
tree_number = 0
data_dir = "/tmp/raven-tree-0"
data_source = { kind = "indexer", filter = { tree_number = 0 } }
"#;
        let f_small = write_temp_toml(body_small);
        let opts_small = load_options_from_toml(f_small.path()).expect("parse");
        assert!(
            ifma52_small_cell_threshold_breached(&opts_small, 1usize << 16),
            "record_size <= 32 must breach the small-cell threshold even at 2^16 entries"
        );
    }

    #[test]
    fn record_size_resolves_per_instance() {
        let body = r#"
[global]
bind = "127.0.0.1:0"
token = "test-token-padded-long-enough"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"
record_size = 512

[[instance]]
id = "commit-tree-0"
role = "live"
encoder = "per-node"
tree_number = 0
data_dir = "/tmp/raven-commit-tree-0"
data_source = { kind = "indexer", filter = { tree_number = 0 } }

[[instance]]
id = "leaf-bc"
role = "live"
encoder = "per-leaf-bc"
tree_number = 1
data_dir = "/tmp/raven-leaf-bc"
data_source = { kind = "indexer", filter = { tree_number = 1 } }

[[instance]]
id = "leaf-bc-wide"
role = "live"
encoder = "per-leaf-bc"
tree_number = 2
record_size = 128
data_dir = "/tmp/raven-leaf-bc-wide"
data_source = { kind = "indexer", filter = { tree_number = 2 } }
"#;
        let f = write_temp_toml(body);
        let opts = load_options_from_toml(f.path()).expect("parse");
        let width = |id: &str| {
            opts.instances
                .iter()
                .find(|i| i.instance_id.as_str() == id)
                .unwrap_or_else(|| panic!("instance {id} missing"))
                .record_size
        };

        let node_hash = raven_railgun_engine::pir_table::NODE_HASH_BYTES;
        assert_eq!(
            width("commit-tree-0"),
            node_hash,
            "per-node pins its canonical width over [global].record_size"
        );
        assert_eq!(
            width("leaf-bc"),
            512,
            "an encoder without a canonical width inherits [global].record_size"
        );
        assert_eq!(
            width("leaf-bc-wide"),
            128,
            "a per-instance record_size overrides [global].record_size"
        );

        let ring_dim = InspireParams::secure_128_d2048().ring_dim;
        for cfg in &opts.instances {
            let entries = entries_for_instance(&opts, cfg, DEFAULT_PRODUCTION_ENTRIES);
            validate_instance_cell_shape(cfg, entries, ring_dim)
                .unwrap_or_else(|e| panic!("instance {} rejected: {e}", cfg.instance_id));
        }
    }

    const OFAC_LIST_KEY: &str = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";

    /// Deployed topology: 3 static + 1 live commit-tree, plus two PPOI instances.
    fn live_six_instance_toml(entries_override: Option<usize>) -> String {
        use std::fmt::Write as _;
        let mut body = String::from(
            r#"
[global]
bind = "127.0.0.1:0"
token = "test-token-padded-long-enough"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 14737691
mirror_endpoint = "http://127.0.0.1:1"
record_size = 512
"#,
        );
        for tree in 0..4u32 {
            let role = if tree == 3 { "live" } else { "static" };
            let entries_line = match entries_override {
                Some(n) => format!("entries = {n}\n"),
                None => String::new(),
            };
            write!(
                body,
                r#"
[[instance]]
id = "commit-tree-{tree}"
role = "{role}"
encoder = "per-node"
tree_number = {tree}
{entries_line}data_dir = "/tmp/raven-commit-tree-{tree}"
data_source = {{ kind = "indexer", filter = {{ tree_number = {tree} }} }}
"#
            )
            .expect("String writes are infallible");
        }
        write!(
            body,
            r#"
[[instance]]
id = "ppoi-paths10-ofac"
role = "live"
encoder = "per-list-path10"
list_key = "{OFAC_LIST_KEY}"
data_dir = "/tmp/raven-ppoi-paths10-ofac"
data_source = {{ kind = "mirror", list_key = "{OFAC_LIST_KEY}", block = 0 }}

[[instance]]
id = "ppoi-paths10-ofac-1"
role = "live"
encoder = "per-list-path10"
list_key = "{OFAC_LIST_KEY}"
data_dir = "/tmp/raven-ppoi-paths10-ofac-1"
data_source = {{ kind = "mirror", list_key = "{OFAC_LIST_KEY}", block = 1 }}
"#
        )
        .expect("String writes are infallible");
        body
    }

    fn resolved_entries(opts: &MultiServeOptions, id: &str) -> usize {
        let cfg = opts
            .instances
            .iter()
            .find(|i| i.instance_id.as_str() == id)
            .unwrap_or_else(|| panic!("instance {id} missing"));
        entries_for_instance(opts, cfg, DEFAULT_PRODUCTION_ENTRIES)
    }

    #[test]
    fn every_live_instance_shape_resolves_a_bootable_cell() {
        let f = write_temp_toml(&live_six_instance_toml(None));
        let opts = load_options_from_toml(f.path()).expect("parse");
        assert_eq!(opts.instances.len(), 6);

        for tree in 0..4u32 {
            assert_eq!(
                resolved_entries(&opts, &format!("commit-tree-{tree}")),
                131_072,
                "per-node resolves its canonical total"
            );
        }
        for id in ["ppoi-paths10-ofac", "ppoi-paths10-ofac-1"] {
            assert_eq!(
                resolved_entries(&opts, id),
                DEFAULT_PRODUCTION_ENTRIES,
                "leaf-keyed encoders keep the 65,536-row cell; a fleet-wide total would double it"
            );
        }

        let ring_dim = InspireParams::secure_128_d2048().ring_dim;
        for cfg in &opts.instances {
            let entries = entries_for_instance(&opts, cfg, DEFAULT_PRODUCTION_ENTRIES);
            validate_instance_cell_shape(cfg, entries, ring_dim).unwrap_or_else(|e| {
                panic!(
                    "instance {} rejected at its resolved cell: {e}",
                    cfg.instance_id
                )
            });
        }
    }

    #[test]
    fn a_fleet_wide_default_production_entries_rejects_the_node_family() {
        let f = write_temp_toml(&live_six_instance_toml(None));
        let opts = load_options_from_toml(f.path()).expect("parse");
        let ring_dim = InspireParams::secure_128_d2048().ring_dim;

        let rejected: Vec<&str> = opts
            .instances
            .iter()
            .filter(|cfg| {
                validate_instance_cell_shape(cfg, DEFAULT_PRODUCTION_ENTRIES, ring_dim).is_err()
            })
            .map(|cfg| cfg.instance_id.as_str())
            .collect();
        assert_eq!(
            rejected,
            [
                "commit-tree-0",
                "commit-tree-1",
                "commit-tree-2",
                "commit-tree-3",
            ],
            "one global row count cannot serve both encoder families"
        );
    }

    #[test]
    fn an_undersized_per_instance_entries_is_rejected_with_an_actionable_error() {
        let f = write_temp_toml(&live_six_instance_toml(Some(DEFAULT_PRODUCTION_ENTRIES)));
        let opts = load_options_from_toml(f.path()).expect("parse");
        let ring_dim = InspireParams::secure_128_d2048().ring_dim;
        let cfg = opts
            .instances
            .iter()
            .find(|i| i.instance_id.as_str() == "commit-tree-3")
            .expect("instance present");
        assert_eq!(
            entries_for_instance(&opts, cfg, 0),
            DEFAULT_PRODUCTION_ENTRIES,
            "an explicit entries value is carried verbatim, not substituted"
        );

        let err = validate_instance_cell_shape(cfg, DEFAULT_PRODUCTION_ENTRIES, ring_dim)
            .expect_err("65,536 rows undersize the per-node flat-index layout")
            .to_string();
        for needle in ["commit-tree-3", "per-node", "65536", "131071"] {
            assert!(err.contains(needle), "error {err:?} must name {needle}");
        }
    }

    #[test]
    fn an_explicit_per_instance_entries_overrides_the_encoder_default() {
        let f = write_temp_toml(&live_six_instance_toml(Some(262_144)));
        let opts = load_options_from_toml(f.path()).expect("parse");
        assert_eq!(resolved_entries(&opts, "commit-tree-0"), 262_144);
        assert_eq!(
            resolved_entries(&opts, "ppoi-paths10-ofac"),
            DEFAULT_PRODUCTION_ENTRIES,
            "the override is per-instance, not fleet-wide"
        );

        let ring_dim = InspireParams::secure_128_d2048().ring_dim;
        for cfg in &opts.instances {
            let entries = entries_for_instance(&opts, cfg, DEFAULT_PRODUCTION_ENTRIES);
            validate_instance_cell_shape(cfg, entries, ring_dim)
                .unwrap_or_else(|e| panic!("instance {} rejected: {e}", cfg.instance_id));
        }
    }

    #[test]
    fn empty_instance_list_rejected() {
        let body = r#"
[global]
bind = "127.0.0.1:0"
token = "test-token-padded-long-enough"
chain_id = 1
mirror_endpoint = "http://127.0.0.1:1"
"#;
        let f = write_temp_toml(body);
        let err = load_options_from_toml(f.path()).expect_err("must reject");
        let msg = format!("{err:#}");
        assert!(msg.contains("no [[instance]] tables"), "got: {msg}");
    }

    #[test]
    fn rpc_pool_section_parses_with_two_urls() {
        let body = r#"
[global]
bind = "127.0.0.1:0"
token = "test-token-padded-long-enough"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"

[rpc_pool]
urls = [
  "https://eth-mainnet.alchemyapi.io/v2/key-A",
  "https://mainnet.infura.io/v3/key-B",
]
strategy = "round-robin"
per_endpoint_rps = 30
per_endpoint_burst = 60
cooldown_secs = 15

[[instance]]
id = "tree-0"
role = "static"
encoder = "per-leaf-path"
tree_number = 0
data_dir = "/tmp/raven-rpc-pool"
data_source = { kind = "indexer", filter = { tree_number = 0 } }
"#;
        let f = write_temp_toml(body);
        let opts = load_options_from_toml(f.path()).expect("parse");
        let pool = opts.rpc_pool.expect("rpc_pool present");
        assert_eq!(pool.urls.len(), 2);
        assert_eq!(pool.strategy, PoolStrategyString::RoundRobin);
        assert_eq!(pool.per_endpoint_rps, 30);
        assert_eq!(pool.per_endpoint_burst, 60);
        assert_eq!(pool.cooldown_secs, 15);
    }

    #[test]
    fn rpc_pool_empty_urls_rejected() {
        let body = r#"
[global]
bind = "127.0.0.1:0"
token = "test-token-padded-long-enough"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"

[rpc_pool]
urls = []

[[instance]]
id = "tree-0"
role = "static"
encoder = "per-leaf-path"
tree_number = 0
data_dir = "/tmp/raven-rpc-pool"
data_source = { kind = "indexer", filter = { tree_number = 0 } }
"#;
        let f = write_temp_toml(body);
        let err = load_options_from_toml(f.path()).expect_err("must reject");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("at least one entry"),
            "expected empty-urls error; got: {msg}"
        );
    }

    #[test]
    fn rpc_pool_absent_falls_back_to_legacy_rpc_url() {
        let body = r#"
[global]
bind = "127.0.0.1:0"
token = "test-token-padded-long-enough"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"

[[instance]]
id = "tree-0"
role = "static"
encoder = "per-leaf-path"
tree_number = 0
data_dir = "/tmp/raven-no-pool"
data_source = { kind = "indexer", filter = { tree_number = 0 } }
"#;
        let f = write_temp_toml(body);
        let opts = load_options_from_toml(f.path()).expect("parse");
        assert!(opts.rpc_pool.is_none(), "absent section should be None");
        assert_eq!(opts.rpc_url, "http://127.0.0.1:1");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn sighup_loop_applies_every_new_chain_template_in_order() {
        static SIGNAL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let _signal_guard = SIGNAL_LOCK.lock().await;
        let config = write_temp_toml(
            r#"
[global]
bind = "127.0.0.1:0"
token = "sighup-source-test-token-padded"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"

[[instance_template]]
template_id = "tree-template-A"
encoder = "per-leaf-bc"
data_dir_template = "/tmp/raven-sighup-a-{tree_number}"

[[instance]]
id = "commit-tree-0"
role = "static"
encoder = "per-leaf-bc"
tree_number = 0
data_dir = "/tmp/raven-sighup-tree-0"
data_source = { kind = "indexer", filter = { tree_number = 0 } }
"#,
        );
        let boot_limits = SessionStoreLimits {
            max_sessions: 3,
            ttl: std::time::Duration::from_secs(600),
        };
        let initial_runtime = crate::auto_spawn_driver::AutoSpawnRuntime {
            data_dir_template: "/tmp/raven-sighup-a-{tree_number}".to_owned(),
            encoder: "per-leaf-bc".to_owned(),
            scheme_tag: SCHEME_TAG_DEFAULT.to_owned(),
            entries: DEFAULT_PRODUCTION_ENTRIES,
            entry_bytes: 16 * 32,
            channel_capacity: 64,
            verification_cadence_n: 0,
            max_instance_count: None,
            cooldown: None,
            session_limits: boot_limits,
        };
        let runtime = Arc::new(arc_swap::ArcSwap::from_pointee(initial_runtime));
        let (applied_tx, mut applied_rx) = tokio::sync::mpsc::unbounded_channel();
        let reload = tokio::spawn(run_sighup_reload_loop(
            config.path().to_owned(),
            Arc::clone(&runtime),
            DEFAULT_PRODUCTION_ENTRIES,
            Some(applied_tx),
        ));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        std::fs::write(
            config.path(),
            r#"
[global]
bind = "127.0.0.1:0"
token = "sighup-source-test-token-padded"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"

[[instance_template]]
template_id = "tree-template-A"
encoder = "per-leaf-bc"
data_dir_template = "/tmp/raven-sighup-a-{tree_number}"

[[instance_template]]
template_id = "tree-template-B"
encoder = "per-node"
data_dir_template = "/tmp/raven-sighup-b-{tree_number}"

[[instance_template]]
template_id = "tree-template-C"
encoder = "per-leaf-path"
data_dir_template = "/tmp/raven-sighup-c-{tree_number}"

[[instance_template]]
template_id = "tree-template-D"
encoder = "per-leaf-bc"
data_dir_template = "/tmp/raven-sighup-d-{tree_number}"

[[instance]]
id = "commit-tree-0"
role = "static"
encoder = "per-leaf-bc"
tree_number = 0
data_dir = "/tmp/raven-sighup-tree-0"
data_source = { kind = "indexer", filter = { tree_number = 0 } }
"#,
        )
        .expect("rewrite config");

        let signal_status = std::process::Command::new("kill")
            .args(["-HUP", &std::process::id().to_string()])
            .status()
            .expect("run kill");
        assert!(signal_status.success());
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let current = runtime.load();
            if current.data_dir_template == "/tmp/raven-sighup-d-{tree_number}"
                && current.encoder == "per-leaf-bc"
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "last template was not applied"
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        let mut applied = Vec::new();
        while let Ok(template_id) = applied_rx.try_recv() {
            applied.push(template_id);
        }
        assert_eq!(
            applied,
            vec![
                "tree-template-B".to_owned(),
                "tree-template-C".to_owned(),
                "tree-template-D".to_owned(),
            ]
        );
        assert_eq!(
            runtime.load().session_limits,
            boot_limits,
            "a reloaded template must spawn at the seats the running HTTP layer was sized for"
        );

        reload.abort();
        let _ = reload.await;
    }

    fn resume_points(held: &[(DataSourceFilter, usize)]) -> Vec<([u8; 32], u64)> {
        mirror_feeds(held)
            .into_iter()
            .map(|feed| (feed.list_key, feed.resume_at))
            .collect()
    }

    /// Every instance on a list is fed from the lowest row one of them lacks, whichever order
    /// the config declares them in, and an instance that can append nothing more is no floor.
    #[test]
    fn a_mirror_feed_resumes_at_the_lowest_row_any_instance_on_its_list_lacks() {
        let list = [7u8; 32];
        let block = |block| DataSourceFilter::PpoiListBlock {
            list_key: list,
            block,
        };
        let full_block = LEAVES_PER_PPOI_BLOCK as usize;
        let block_start = |block: u32| u64::from(block) * u64::from(LEAVES_PER_PPOI_BLOCK);
        let cases = [
            (
                "a block behind a later one",
                vec![(block(0), 3), (block(1), 10)],
                3,
            ),
            (
                "a full block beside a part-filled one",
                vec![(block(0), full_block), (block(1), 10)],
                block_start(1) + 10,
            ),
            (
                "full blocks below the part-filled last one",
                vec![
                    (block(0), full_block),
                    (block(4), full_block),
                    (block(5), 7),
                ],
                block_start(5) + 7,
            ),
            (
                "every instance full",
                vec![(block(1), full_block), (block(2), full_block)],
                block_start(3),
            ),
        ];
        for (case, held, resume_at) in cases {
            let reversed: Vec<_> = held.iter().rev().copied().collect();
            for order in [held, reversed] {
                assert_eq!(
                    resume_points(&order),
                    vec![(list, resume_at)],
                    "{case}: {order:?}"
                );
            }
        }
    }

    #[test]
    fn each_ppoi_list_gets_one_feed_in_config_order_and_a_chain_tree_none() {
        let (first, second) = ([2u8; 32], [1u8; 32]);
        let held = [
            (DataSourceFilter::ChainTreeNumber(3), 100),
            (
                DataSourceFilter::PpoiListBlock {
                    list_key: first,
                    block: 1,
                },
                0,
            ),
            (
                DataSourceFilter::PpoiListBlock {
                    list_key: second,
                    block: 0,
                },
                4,
            ),
            (
                DataSourceFilter::PpoiListBlock {
                    list_key: first,
                    block: 0,
                },
                0,
            ),
        ];
        let feeds: Vec<([u8; 32], u64, bool)> = mirror_feeds(&held)
            .into_iter()
            .map(|feed| (feed.list_key, feed.resume_at, feed.holds_rows))
            .collect();
        assert_eq!(feeds, vec![(first, 0, false), (second, 4, true)]);
    }

    /// Every instance on `held`'s one list as `holding` reads it, none refusing.
    fn holdings_of(held: &[(DataSourceFilter, usize)]) -> Vec<Holding> {
        held.iter()
            .filter_map(|&(source, rows)| holding(source, rows))
            .map(|(_, reach)| reach)
            .collect()
    }

    /// Every list-wide index a feed asks upstream for, paging the way the worker does, until
    /// its span comes back empty; and the index it stopped in front of. Each page is applied
    /// by every instance it can extend once the next page is under way, so some are always
    /// still in flight when the span is read.
    fn walk_feed(held: &[(DataSourceFilter, usize)], page: u64) -> (Vec<u64>, u64) {
        let feed = mirror_feeds(held).pop().expect("one list");
        let filters: Vec<DataSourceFilter> = held.iter().map(|(filter, _)| *filter).collect();
        let first_unheld = |at| first_unheld_index(filters.iter().copied(), &feed.list_key, at);
        let mut holdings = holdings_of(held);
        let mut in_flight: Vec<u64> = Vec::new();
        let mut asked = Vec::new();
        let mut cursor = feed.resume_at;
        loop {
            let span = feed_span(&holdings, cursor, first_unheld);
            for row in in_flight.drain(..) {
                for reach in &mut holdings {
                    if reach.next == row && row < reach.end {
                        reach.next += 1;
                    }
                }
            }
            cursor = cursor.max(span.start);
            if span.end <= cursor {
                return (asked, cursor);
            }
            let end = (cursor + page - 1).min(span.end - 1);
            asked.extend(cursor..=end);
            in_flight.extend(cursor..=end);
            cursor = end + 1;
        }
    }

    /// Live counts lag the cursor by whatever is still queued, and only a refusal sends the span
    /// below it: to the row the refusing instance lacks, and no further.
    #[test]
    fn only_a_refused_row_starts_the_span_below_the_cursor() {
        let list = [4u8; 32];
        let block = |block| DataSourceFilter::PpoiListBlock {
            list_key: list,
            block,
        };
        let start = |block: u64| block * u64::from(LEAVES_PER_PPOI_BLOCK);
        let unheld = |at| first_unheld_index([block(0), block(1)], &list, at);
        let queued = holdings_of(&[(block(0), 1_000), (block(1), 0)]);
        assert_eq!(
            feed_span(&queued, 1_500, unheld),
            1_500..start(2),
            "rows 1,000..1,500 are on their way, not missing"
        );
        let mut refused = queued.clone();
        refused[0].refused = true;
        assert_eq!(feed_span(&refused, 1_500, unheld), 1_000..start(2));
        let mut full_refusing = holdings_of(&[(block(0), 65_536), (block(1), 20)]);
        full_refusing[1].refused = true;
        assert_eq!(
            feed_span(&full_refusing, start(1) + 900, unheld),
            start(1) + 20..start(2)
        );
    }

    /// Instances on one list that disagree: block 0 restored from an older snapshot, block 1
    /// part-way, block 2 full, block 3 empty. The feed asks for exactly the
    /// rows some instance still has to append, each once, so no full block is handed a row it
    /// can only refuse.
    #[test]
    fn a_feed_asks_once_for_each_row_some_instance_lacks_and_never_for_one_all_hold() {
        let list = [9u8; 32];
        let block = |block| DataSourceFilter::PpoiListBlock {
            list_key: list,
            block,
        };
        let full = LEAVES_PER_PPOI_BLOCK as usize;
        let start = |block: u64| block * u64::from(LEAVES_PER_PPOI_BLOCK);
        let held = [
            (block(0), 30_000),
            (block(1), 50_000),
            (block(2), full),
            (block(3), 0),
        ];
        let (asked, stopped_at) = walk_feed(&held, 501);
        let lacked: Vec<u64> = (30_000..start(1))
            .chain(start(1) + 50_000..start(2))
            .chain(start(3)..start(4))
            .collect();
        assert_eq!(asked, lacked, "asked for a row no instance lacks, or twice");
        assert_eq!(
            stopped_at,
            start(4),
            "stops where the declared coverage ends"
        );

        let (asked, _) = walk_feed(&[(block(1), full), (block(2), 7)], 501);
        assert_eq!(
            asked.first(),
            Some(&(start(2) + 7)),
            "resumes at the global frontier, not at a block-local row count"
        );
    }

    /// The shipped forest booted empty: one page per 501 rows, back to back, through every
    /// declared block, although seven instances share the list.
    #[test]
    fn a_cold_shipped_boot_asks_for_each_page_of_the_list_exactly_once() {
        let (_, routes) = shipped_ppoi_routes();
        let held: Vec<(DataSourceFilter, usize)> = routes.iter().map(|&route| (route, 0)).collect();
        let (asked, stopped_at) = walk_feed(&held, 501);
        let declared = 7 * u64::from(LEAVES_PER_PPOI_BLOCK);
        assert!(
            asked.iter().copied().eq(0..declared),
            "every row of seven blocks, once, in order"
        );
        assert_eq!(stopped_at, declared);
    }

    /// Readiness tells the three states the operator acts on apart, and only never-fed and
    /// stopped take the node out.
    #[test]
    fn the_feed_view_tells_idle_from_never_fed_from_refusing() {
        use raven_railgun_http::status::MirrorFeedState;
        use raven_railgun_ppoi_mirror::{FeedProgress, PreflightFailure};

        let list = [3u8; 32];
        let block = |block| DataSourceFilter::PpoiListBlock {
            list_key: list,
            block,
        };
        let answered = |tip| FeedProgress {
            next_index: tip,
            upstream_rows: Some(tip),
            last_answer: Some(std::time::Instant::now()),
            ..FeedProgress::default()
        };
        let refusing = FeedProgress {
            consecutive_failures: 3,
            last_failure: Some(PreflightFailure::HttpStatus(500)),
            ..answered(1_010)
        };
        let stopped = FeedProgress {
            stopped: Some("no consumer holds list index 393216".to_owned()),
            ..answered(1_010)
        };
        let full = LEAVES_PER_PPOI_BLOCK as usize;
        let shipped_at_tip: Vec<(DataSourceFilter, usize)> = (0..5)
            .map(|index| (block(index), full))
            .chain([(block(5), 30_640), (block(6), 0)])
            .collect();
        let cases = [
            (
                "no answer yet, nothing held",
                FeedProgress::default(),
                vec![(block(0), 0), (block(1), 0)],
                MirrorFeedState::NeverFed,
            ),
            (
                "upstream answers an empty list, as it does for a wrong key",
                answered(0),
                vec![(block(0), 0), (block(1), 0)],
                MirrorFeedState::NeverFed,
            ),
            (
                "at upstream's tip, every row applied",
                answered(1_010),
                vec![(block(0), 1_010), (block(1), 0)],
                MirrorFeedState::CaughtUp,
            ),
            (
                "at upstream's tip, the block holding it still applying",
                answered(1_010),
                vec![(block(0), 1_000), (block(1), 0)],
                MirrorFeedState::Syncing,
            ),
            (
                "paging full pages",
                FeedProgress {
                    upstream_rows: None,
                    ..answered(1_002)
                },
                vec![(block(0), 1_002)],
                MirrorFeedState::Syncing,
            ),
            (
                "rows held, upstream refusing",
                refusing,
                vec![(block(0), 1_010)],
                MirrorFeedState::UpstreamRefusing,
            ),
            (
                "the feed stopped",
                stopped,
                vec![(block(0), 1_010)],
                MirrorFeedState::Stopped,
            ),
            (
                "the shipped forest at the tip, the block past it empty",
                answered(358_320),
                shipped_at_tip,
                MirrorFeedState::CaughtUp,
            ),
        ];
        for (case, progress, held, expected) in cases {
            let view = mirror_feed_view(&list, &progress, &held);
            assert_eq!(view.state, expected, "{case}");
            assert_eq!(
                view.state.fails_readiness(),
                matches!(
                    expected,
                    MirrorFeedState::NeverFed | MirrorFeedState::Stopped
                ),
                "{case}"
            );
        }
        let view = mirror_feed_view(&list, &answered(358_320), &[(block(5), 30_640)]);
        assert_eq!(
            view.rows_held, 358_320,
            "the list-wide frontier, not a block count"
        );
        let view = mirror_feed_view(
            &list,
            &FeedProgress {
                consecutive_failures: 1,
                last_failure: Some(PreflightFailure::HttpStatus(500)),
                ..FeedProgress::default()
            },
            &[(block(0), 5)],
        );
        assert_eq!(view.last_failure.as_deref(), Some("answered HTTP 500"));

        let asking_again = FeedProgress {
            untaken_row: Some(600),
            ..answered(1_010)
        };
        let view = mirror_feed_view(&list, &asking_again, &[(block(0), 600)]);
        assert_eq!(
            view.last_failure.as_deref(),
            Some("no instance took row 600; asking for it again"),
            "readiness names the row a refusing instance still lacks"
        );
        let view = mirror_feed_view(&list, &asking_again, &[(block(0), 601)]);
        assert_eq!(
            view.last_failure, None,
            "a row the instance has since taken is not named"
        );
    }

    /// A node paging full pages, with upstream's node status stating 5,000 rows: readiness shows
    /// how far behind it is, and the state still rests on the page-derived count alone.
    #[test]
    fn the_feed_view_shows_how_far_upstream_is_ahead_while_syncing() {
        use raven_railgun_http::status::MirrorFeedState;
        use raven_railgun_ppoi_mirror::FeedProgress;

        let list = [3u8; 32];
        let block_0 = DataSourceFilter::PpoiListBlock {
            list_key: list,
            block: 0,
        };
        let syncing = FeedProgress {
            next_index: 1_002,
            upstream_rows_seen: Some(5_000),
            last_answer: Some(std::time::Instant::now()),
            ..FeedProgress::default()
        };
        let view = mirror_feed_view(&list, &syncing, &[(block_0, 1_002)]);
        assert_eq!(
            (
                view.state,
                view.rows_held,
                view.upstream_rows,
                view.upstream_rows_seen
            ),
            (MirrorFeedState::Syncing, 1_002, None, Some(5_000))
        );
    }

    fn global_with(line: &str) -> String {
        format!(
            r#"
[global]
bind = "127.0.0.1:0"
token = "test-token-padded-long-enough"
chain_id = 1
mirror_endpoint = "http://127.0.0.1:1"
{line}

[[instance]]
id = "ppoi-paths-0"
role = "live"
encoder = "per-list-path10"
list_key = "0000000000000000000000000000000000000000000000000000000000000001"
data_dir = "/tmp/raven-ppoi"
data_source = {{ kind = "mirror", list_key = "0000000000000000000000000000000000000000000000000000000000000001", block = 0 }}
"#
        )
    }

    /// The setting shortens the poll; one longer than the poll is a unit slip and is refused
    /// by name before any instance boots.
    #[test]
    fn the_backfill_setting_loads_and_one_slower_than_the_poll_is_refused_by_name() {
        let backfill = |line: &str| {
            let f = write_temp_toml(&global_with(line));
            load_options_from_toml(f.path()).map(|opts| opts.mirror_backfill_interval_secs)
        };
        assert_eq!(backfill("").expect("absent"), None);
        assert_eq!(
            backfill("mirror_backfill_interval_secs = 0").expect("zero"),
            Some(0)
        );
        let poll = raven_railgun_ppoi_mirror::DEFAULT_POLL_INTERVAL_SECS;
        assert_eq!(
            backfill(&format!("mirror_backfill_interval_secs = {poll}")).expect("the poll"),
            Some(poll)
        );
        let refusal = backfill(&format!("mirror_backfill_interval_secs = {}", poll + 1))
            .expect_err("slower than the poll");
        assert!(
            format!("{refusal:#}").contains("mirror_backfill_interval_secs"),
            "{refusal:#}"
        );
    }

    /// The shipped example's PPOI routes, loaded the way boot loads them.
    fn shipped_ppoi_routes() -> ([u8; 32], Vec<DataSourceFilter>) {
        let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/mainnet-ppoi.toml");
        let body = std::fs::read_to_string(example)
            .expect("read the shipped example")
            .replace("REPLACE_ME", &"a1b2c3d4".repeat(8));
        let f = write_temp_toml(&body);
        let filters: Vec<DataSourceFilter> = load_options_from_toml(f.path())
            .expect("the shipped example loads")
            .instances
            .into_iter()
            .map(|instance| instance.data_source)
            .filter(|source| !matches!(source, DataSourceFilter::ChainTreeNumber(_)))
            .collect();
        let list_key = match filters.first() {
            Some(DataSourceFilter::PpoiListBlock { list_key, .. }) => *list_key,
            other => panic!("the shipped example declares no PPOI block: {other:?}"),
        };
        (list_key, filters)
    }

    /// The shipped forest is blocks 0-6 and nothing else. Every row below the eighth block has
    /// a holder and none at or past it does, so a row at 393,216 lands in block 6.
    #[test]
    fn the_shipped_topology_holds_every_row_below_the_eighth_block_and_none_past_it() {
        let (list, routes) = shipped_ppoi_routes();
        let blocks: Vec<u32> = routes
            .iter()
            .map(|route| match route {
                DataSourceFilter::PpoiListBlock { block, .. } => *block,
                other @ DataSourceFilter::ChainTreeNumber(_) => {
                    panic!("the shipped example declares a non-block PPOI route: {other:?}")
                }
            })
            .collect();
        assert_eq!(blocks, (0..7).collect::<Vec<u32>>());
        let block = u64::from(LEAVES_PER_PPOI_BLOCK);
        let unheld = |routes: &[DataSourceFilter], cursor| {
            first_unheld_index(routes.iter().copied(), &list, cursor)
        };
        for cursor in [0, block - 1, block, 6 * block, 7 * block - 1, 7 * block] {
            assert_eq!(unheld(&routes, cursor), 7 * block, "cursor {cursor}");
        }

        let without_block_3: Vec<_> = routes
            .iter()
            .copied()
            .filter(|route| !matches!(route, DataSourceFilter::PpoiListBlock { block: 3, .. }))
            .collect();
        assert_eq!(unheld(&without_block_3, 0), 3 * block);

        let mut with_block_7 = routes.clone();
        with_block_7.push(DataSourceFilter::PpoiListBlock {
            list_key: list,
            block: 7,
        });
        assert_eq!(unheld(&with_block_7, 7 * block), 8 * block);

        assert_eq!(
            first_unheld_index(routes.iter().copied(), &[0xAB; 32], 7),
            7,
            "another list's routes hold nothing of this one"
        );
    }

    /// The provider of the list the feed tests mirror: its rows are signed, so its key stands in
    /// for the shipped list's.
    fn provider() -> raven_railgun_ppoi_mirror::test_signer::TestListSigner {
        raven_railgun_ppoi_mirror::test_signer::TestListSigner::new(0x5A)
    }

    /// Serves every index it is asked for, signed by [`provider`], and records each page's bounds.
    async fn upstream_holding_every_row() -> (String, Arc<parking_lot::Mutex<Vec<(u64, u64)>>>) {
        upstream_holding(u64::MAX).await
    }

    /// [`upstream_holding_every_row`], holding only rows `0..rows`.
    async fn upstream_holding(rows: u64) -> (String, Arc<parking_lot::Mutex<Vec<(u64, u64)>>>) {
        use axum::{routing::post, Json, Router};
        use serde_json::{json, Value};
        let asked = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let log = Arc::clone(&asked);
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| {
                let log = Arc::clone(&log);
                async move {
                    let bound = |name: &str| {
                        request
                            .pointer(&format!("/params/{name}"))
                            .and_then(Value::as_u64)
                            .expect("page bound")
                    };
                    let (start, end) = (bound("startIndex"), bound("endIndex"));
                    log.lock().push((start, end));
                    let rows: Vec<Value> = (start..=end.min(rows.saturating_sub(1)))
                        .map(|index| {
                            provider()
                                .row(
                                    index,
                                    &format!("{index:064x}"),
                                    "Shield",
                                    &format!("{:064x}", index + 1),
                                )
                                .expect("signs")
                        })
                        .collect();
                    Json(json!({ "jsonrpc": "2.0", "id": 1, "result": rows }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("local addr"));
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        (endpoint, asked)
    }

    fn leaves_sent(
        rx: &mut tokio::sync::mpsc::Receiver<(raven_railgun_persistence::WalEntryPayload, u64)>,
    ) -> Vec<u64> {
        let mut leaves = Vec::new();
        while let Ok((payload, _)) = rx.try_recv() {
            if let raven_railgun_persistence::WalEntryPayload::PpoiListLeafAdded {
                list_index,
                ..
            } = payload
            {
                leaves.push(u64::from(list_index));
            }
        }
        leaves
    }

    /// The row past the shipped topology's last block. No route holds it, so the feed must
    /// stop in front of it and name the block readiness waits on. Declaring the block then
    /// resumes the feed at that very row, which the router places at the new block's local
    /// index 0.
    #[tokio::test]
    async fn the_shipped_feed_stops_past_its_last_block_names_the_next_and_resumes_when_declared() {
        use raven_railgun_engine::orchestrator::split_ppoi_index;
        use raven_railgun_ppoi_mirror::{MirrorConfig, UpstreamPpoiMirror};

        let list_key = provider().list_key();
        let filters: Vec<DataSourceFilter> = shipped_ppoi_routes()
            .1
            .into_iter()
            .map(|route| match route {
                DataSourceFilter::PpoiListBlock { block, .. } => {
                    DataSourceFilter::PpoiListBlock { list_key, block }
                }
                other @ DataSourceFilter::ChainTreeNumber(_) => other,
            })
            .collect();
        let next_block = 7;
        let first_unheld = u64::from(next_block * LEAVES_PER_PPOI_BLOCK);
        // The feed reads only the filters; nothing is routed in this test.
        let routes_for =
            |filters: &[DataSourceFilter]| -> raven_railgun_engine::orchestrator::PpoiListRoutes {
                filters
                    .iter()
                    .map(|&filter| (filter, tokio::sync::mpsc::channel(1).0))
                    .collect()
            };
        let (endpoint, asked) = upstream_holding_every_row().await;
        let mirror = Arc::new(
            UpstreamPpoiMirror::new(MirrorConfig {
                endpoint,
                poll_interval_secs: 1,
                ..MirrorConfig::default()
            })
            .expect("mirror"),
        );
        let feed_from = |filters: &[DataSourceFilter], frontier: u64| {
            let held: Vec<(DataSourceFilter, usize)> = filters
                .iter()
                .map(|&filter| {
                    let (_, reach) = holding(filter, 0).expect("a PPOI route");
                    let rows = frontier.clamp(reach.first, reach.end) - reach.first;
                    (filter, usize::try_from(rows).expect("rows"))
                })
                .collect();
            let feed = mirror_feeds(&held).pop().expect("one list");
            assert_eq!(
                feed.resume_at, frontier,
                "fixture: the feed starts at the frontier"
            );
            let holdings = holdings_of(&held);
            (feed, move || holdings.clone())
        };

        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        tokio::time::timeout(std::time::Duration::from_secs(10), {
            let (feed, holdings) = feed_from(&filters, first_unheld - 2);
            run_mirror_feed(
                Arc::clone(&mirror),
                feed,
                holdings,
                routes_for(&filters),
                tx,
                raven_railgun_ppoi_mirror::FeedStatus::default(),
            )
        })
        .await
        .expect("the feed must stop past the last block, not wait there");
        assert_eq!(leaves_sent(&mut rx), [first_unheld - 2, first_unheld - 1]);
        assert_eq!(
            asked.lock().clone(),
            [(first_unheld - 2, first_unheld - 1)],
            "nothing past the last declared block may be asked for"
        );
        assert_eq!(
            unrouted_on(&list_key),
            [format!("list:{}:block:{next_block}", hex::encode(list_key))],
            "readiness must name the block the feed is waiting on"
        );

        let mut declared = filters.clone();
        declared.push(DataSourceFilter::PpoiListBlock {
            list_key,
            block: next_block,
        });
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let (feed, holdings) = feed_from(&declared, first_unheld);
        let resumed = tokio::spawn(run_mirror_feed(
            mirror,
            feed,
            holdings,
            routes_for(&declared),
            tx,
            raven_railgun_ppoi_mirror::FeedStatus::default(),
        ));
        let first = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
            .await
            .expect("the declared block is fed")
            .expect("the feed is running");
        resumed.abort();
        let raven_railgun_persistence::WalEntryPayload::PpoiListLeafAdded { list_index, .. } =
            first.0
        else {
            panic!("a row's leaf goes first: {first:?}");
        };
        assert_eq!(u64::from(list_index), first_unheld);
        assert_eq!(split_ppoi_index(list_index), (next_block, 0));
    }

    /// An instance slower than the poll is not refusing: rows it has not applied yet are on their
    /// way. Read through the instance as the node reads it, one that holds none of the list for
    /// four polls while the whole of it waits in its queue is asked for no page twice, and no
    /// row is named untaken.
    #[tokio::test]
    async fn an_instance_behind_the_cursor_for_polls_is_asked_for_no_page_again() {
        use raven_railgun_engine::persistence::InspirePersistence;
        use raven_railgun_engine::pir_table::list::PATH10_RECORD_BYTES;
        use raven_railgun_ppoi_mirror::{FeedStatus, MirrorConfig, UpstreamPpoiMirror};

        const ROWS: u64 = 1_010;
        let list_key = provider().list_key();
        let block_0 = DataSourceFilter::PpoiListBlock { list_key, block: 0 };
        let dir = tempfile::tempdir().expect("tempdir");
        let opened = InspirePersistence::open(
            raven_railgun_persistence::StoreLayout::open(dir.path()).expect("layout"),
            "slow-consumer",
            InstanceId::new("slow-consumer"),
            SnapshotPolicy::default(),
            EncoderKind::PerListPath10 { list_key }
                .build(PATH10_RECORD_BYTES, 2048)
                .expect("encoder"),
        )
        .expect("open");
        let instance = ListInstance {
            data_source: block_0,
            store: Arc::new(parking_lot::Mutex::new(opened.recovered_logical_store)),
            persistence: Arc::new(opened.persistence),
        };
        let (endpoint, asked) = upstream_holding(ROWS).await;
        let mirror = Arc::new(
            UpstreamPpoiMirror::new(MirrorConfig {
                endpoint,
                poll_interval_secs: 1,
                ..MirrorConfig::default()
            })
            .expect("mirror"),
        );
        let feed = mirror_feeds(&[(block_0, 0)]).pop().expect("one list");
        let routes: raven_railgun_engine::orchestrator::PpoiListRoutes =
            [(block_0, tokio::sync::mpsc::channel(1).0)]
                .into_iter()
                .collect();
        let (tx, mut rx) = tokio::sync::mpsc::channel(2_048);
        let status = FeedStatus::default();
        let worker = tokio::spawn(run_mirror_feed(
            mirror,
            feed,
            move || instance.holding(&list_key).into_iter().collect(),
            routes,
            tx,
            status.clone(),
        ));

        let until = tokio::time::Instant::now() + std::time::Duration::from_millis(4_500);
        while tokio::time::Instant::now() < until {
            assert_eq!(status.snapshot().untaken_row, None, "{:?}", asked.lock());
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        worker.abort();

        let asked = asked.lock().clone();
        let mut delivered = 0;
        for &(start, end) in &asked {
            assert!(
                start >= delivered,
                "row {start} was asked for again with {delivered} delivered: {asked:?}"
            );
            delivered = delivered.max((end + 1).min(ROWS));
        }
        assert!(
            asked.len() >= 5,
            "fixture: three pages, then a poll a second: {asked:?}"
        );
        assert_eq!(leaves_sent(&mut rx), (0..ROWS).collect::<Vec<u64>>());
    }

    /// This list's marks in the process-wide unrouted registry, which other tests also mark.
    fn unrouted_on(list_key: &[u8; 32]) -> Vec<String> {
        let prefix = format!("list:{}:", hex::encode(list_key));
        raven_railgun_engine::orchestrator::router_unrouted_targets()
            .into_iter()
            .filter(|target| target.starts_with(&prefix))
            .collect()
    }

    /// A gap in the declared blocks: `block = 7` written for the seventh block, which is block
    /// 6, or a block left out of the middle. Stepping over the gap leaves its rows unserved
    /// behind a feed that reads as caught up, so the feed stops on the gap's first row and names
    /// its block, whether it pages up to the gap or boots already past it.
    #[tokio::test]
    async fn a_gap_in_the_declared_blocks_stops_the_feed_on_its_first_row() {
        use raven_railgun_ppoi_mirror::{FeedStatus, MirrorConfig, UpstreamPpoiMirror};

        let list_key = provider().list_key();
        let block = |block| DataSourceFilter::PpoiListBlock { list_key, block };
        let start = |block: u32| u64::from(block * LEAVES_PER_PPOI_BLOCK);
        let full = LEAVES_PER_PPOI_BLOCK as usize;
        let block_7_for_the_seventh: Vec<(DataSourceFilter, usize)> = (0..5)
            .map(|index| (block(index), full))
            .chain([(block(5), full - 2), (block(7), 0)])
            .collect();
        let block_1_left_out = vec![(block(0), full), (block(2), 7)];
        let cases = [
            (
                "paged up to the gap",
                block_7_for_the_seventh,
                vec![(start(6) - 2, start(6) - 1)],
                6,
            ),
            ("booted past the gap", block_1_left_out, vec![], 1),
        ];
        for (case, held, pages, gap_block) in cases {
            let (endpoint, asked) = upstream_holding_every_row().await;
            let mirror = Arc::new(
                UpstreamPpoiMirror::new(MirrorConfig {
                    endpoint,
                    poll_interval_secs: 1,
                    ..MirrorConfig::default()
                })
                .expect("mirror"),
            );
            let routes: raven_railgun_engine::orchestrator::PpoiListRoutes = held
                .iter()
                .map(|&(filter, _)| (filter, tokio::sync::mpsc::channel(1).0))
                .collect();
            let feed = mirror_feeds(&held).pop().expect("one list");
            let holdings = holdings_of(&held);
            let (tx, mut rx) = tokio::sync::mpsc::channel(64);
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                run_mirror_feed(
                    mirror,
                    feed,
                    move || holdings.clone(),
                    routes,
                    tx,
                    FeedStatus::default(),
                ),
            )
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{case}: the feed stepped over the gap: asked {:?}",
                    asked.lock()
                )
            });
            let sent: Vec<u64> = pages
                .iter()
                .flat_map(|&(first, last)| first..=last)
                .collect();
            assert_eq!(asked.lock().clone(), pages, "{case}");
            assert_eq!(leaves_sent(&mut rx), sent, "{case}");
            let target = format!("list:{}:block:{gap_block}", hex::encode(list_key));
            assert!(
                unrouted_on(&list_key).contains(&target),
                "{case}: readiness must name {target}: {:?}",
                unrouted_on(&list_key)
            );
        }
    }

    /// The per-list encoder reads `store.ppoi_imt(&self.list_key)` and drops every event for
    /// a foreign list, so the pin has to be recoverable to be checkable at all.
    #[test]
    fn the_per_list_encoder_reports_the_list_it_is_pinned_to() {
        let list_key = [9u8; 32];
        let encoder = EncoderKind::PerListPath10 { list_key };
        assert_eq!(super::pinned_list_key(encoder), Some(list_key));
    }

    #[test]
    fn no_chain_tree_encoder_pins_a_list() {
        for encoder in [
            EncoderKind::PerLeafBc { tree_number: 0 },
            EncoderKind::PerLeafPath { tree_number: 3 },
            EncoderKind::PerNode { tree_number: 7 },
        ] {
            assert_eq!(
                super::pinned_list_key(encoder),
                None,
                "{encoder:?} is pinned to a tree, not a list"
            );
        }
    }

    #[test]
    fn a_diverged_list_pin_is_refused_and_names_both_keys() {
        let err = super::enforce_encoder_list_key(
            "ppoi-paths-0",
            EncoderKind::PerListPath10 {
                list_key: [0xaa; 32],
            },
            &[0xbb; 32],
            "data_source.list_key",
        )
        .expect_err("a per-list encoder pinned off its routed list must be refused");
        let msg = format!("{err:#}");
        for needle in [
            "ppoi-paths-0",
            "per-list-path10",
            &"aa".repeat(32),
            &"bb".repeat(32),
            "data_source.list_key",
        ] {
            assert!(msg.contains(needle), "refusal must name {needle}: {msg}");
        }
    }

    /// Without this the guard could be satisfied by refusing every per-list instance.
    #[test]
    fn an_agreeing_list_pin_is_accepted() {
        let list_key = [0xcd; 32];
        let encoder = EncoderKind::PerListPath10 { list_key };
        super::enforce_encoder_list_key("ppoi", encoder, &list_key, "data_source.list_key")
            .unwrap_or_else(|e| panic!("{encoder:?} agrees with its list and must pass: {e}"));
    }

    /// A chain encoder pins no list; gating it on one would refuse every chain instance.
    #[test]
    fn a_chain_encoder_is_not_gated_on_the_list_key() {
        super::enforce_encoder_list_key(
            "tree-0",
            EncoderKind::PerLeafBc { tree_number: 0 },
            &[0xff; 32],
            "data_source.list_key",
        )
        .expect("a tree-pinned encoder pins no list and must not be gated on one");
    }
}
