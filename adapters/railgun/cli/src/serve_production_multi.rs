//! Boots N PIR instances from one TOML config onto a single axum router.

#![allow(clippy::too_many_lines, clippy::missing_errors_doc)]

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::bearer_token::{resolve_bearer_token, BEARER_TOKEN_ENV};
use anyhow::Context;
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::{InstanceId, ListKey};
use raven_railgun_engine::inspire::{
    setup_state, InspireServerState, LogicalLeafStore, RavenInspireScheme,
};
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine_multi, DataSourceFilter, InstanceConfig, MultiOrchestratorHandle,
    OrchestratorChannels, PerInstanceHandles, VerificationMode,
};
use raven_railgun_engine::persistence::{ConsumerMetrics, SnapshotPolicy};
use raven_railgun_engine::pir_table::EncoderKind;
use raven_railgun_engine::{Engine, InstanceRole};
use raven_railgun_http::{
    inspire_router, trusted_proxy::resolve_declared_ranges, AppState, HttpConfig,
};
use serde::Deserialize;

/// Optional `[auto_spawn]` TOML section.
#[derive(Debug, Clone, Deserialize, Default)]
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
    super::serve_production::DEFAULT_PRODUCTION_ENTRIES
}

fn default_auto_spawn_entry_bytes() -> usize {
    super::serve_production::DEFAULT_PRODUCTION_ENTRY_BYTES
}

#[derive(Debug, Deserialize)]
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
    #[serde(default)]
    ppoi_list_template: Vec<PpoiListTemplateToml>,
}

/// One `[[ppoi_list_template]]` row.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PpoiListTemplateToml {
    pub template_id: String,
    pub list_key: String,
    pub encoder: String,
    #[serde(default)]
    pub scheme_tag: String,
    /// Must contain `{list_key}`.
    pub data_dir_template: String,
    #[serde(default)]
    pub k_concurrency: u32,
    #[serde(default)]
    pub entries: usize,
    #[serde(default)]
    pub entry_bytes: usize,
}

/// One `[[instance_template]]` row.
#[derive(Debug, Clone, Deserialize, Default)]
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
struct GlobalSection {
    bind: SocketAddr,
    /// Mutually exclusive with `token_file` and [`BEARER_TOKEN_ENV`]; forces a
    /// 600-mode config file.
    #[serde(default)]
    token: Option<String>,
    /// 600-mode file holding the bearer token; the production path.
    #[serde(default)]
    token_file: Option<PathBuf>,
    rpc_url: String,
    railgun_proxy: String,
    chain_id: u64,
    start_block: u64,
    mirror_endpoint: String,
    #[serde(default)]
    max_concurrent_queries: Option<usize>,
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
    /// Layer 1 reorg-window cache sidecar; absent = ephemeral (rebuilt from RPC).
    #[serde(default)]
    reorg_window_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct InstanceSection {
    id: String,
    role: RoleString,
    encoder: EncoderString,
    #[serde(default)]
    tree_number: Option<u32>,
    #[serde(default)]
    list_key: Option<String>,
    data_dir: PathBuf,
    verification_mode: VerificationModeString,
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
    PerListStatus,
    PerListPath,
    PerListNode,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum VerificationModeString {
    ChainRootHistory,
    UpstreamSignature,
}

impl From<VerificationModeString> for VerificationMode {
    fn from(mode: VerificationModeString) -> Self {
        match mode {
            VerificationModeString::ChainRootHistory => Self::ChainRootHistory,
            VerificationModeString::UpstreamSignature => Self::UpstreamSignature,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum DataSourceSection {
    Indexer {
        filter: IndexerFilterSection,
    },
    Mirror {
        list_key: String,
        #[serde(default)]
        #[allow(dead_code)]
        what: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
struct IndexerFilterSection {
    tree_number: u32,
}

/// Operator-facing args for the multi-instance path.
#[derive(Debug, Clone)]
pub struct MultiServeOptions {
    pub bind: SocketAddr,
    pub token: String,
    pub rpc_url: String,
    pub railgun_proxy: String,
    pub chain_id: u64,
    pub start_block: u64,
    pub mirror_endpoint: String,
    pub max_concurrent_queries: usize,
    pub respond_timeout_secs: u64,
    pub instances: Vec<InstanceConfig>,
    /// Tests set this to skip the live RPC + indexer worker.
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
    pub ppoi_list_templates: Vec<PpoiListTemplateToml>,
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
    /// Indexer Layer 1 reorg-window cache path; absent = ephemeral.
    pub reorg_window_path: Option<PathBuf>,
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

pub const DEFAULT_PRODUCTION_ENTRIES: usize = super::serve_production::DEFAULT_PRODUCTION_ENTRIES;

const SCHEME_TAG_DEFAULT: &str = "raven-inspire-twopacking-inspiring-wp3-cache-session";

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
    let channel_capacity = parsed.global.channel_capacity.unwrap_or(1024);

    let mut instances: Vec<InstanceConfig> = Vec::with_capacity(parsed.instance.len());
    let mut instance_entries: HashMap<InstanceId, usize> =
        HashMap::with_capacity(parsed.instance.len());
    for raw in parsed.instance {
        let role: InstanceRole = raw.role.into();
        let verification_mode: VerificationMode = raw.verification_mode.into();
        let encoder = build_encoder_kind(raw.encoder, raw.tree_number, raw.list_key.as_deref())?;
        let data_source = build_data_source(&raw.data_source)?;
        enforce_verification_mode_matches_data_source(&data_source, verification_mode)?;
        enforce_encoder_matches_data_source(encoder, &data_source)?;
        let snapshot_policy = match role {
            InstanceRole::Static => SnapshotPolicy::static_default(),
            _ => SnapshotPolicy::default(),
        };
        // Verbatim so `validate_cell_shape` rejects a conflict instead of substituting.
        let record_size = raw.record_size.unwrap_or_else(|| {
            let effective = encoder.effective_record_size(fallback_record_size);
            crate::auto_spawn_driver::warn_on_record_size_override(
                encoder,
                fallback_record_size,
                effective,
            );
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
            verification_mode,
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

    for tpl in &parsed.ppoi_list_template {
        if tpl.template_id.trim().is_empty() {
            anyhow::bail!("[[ppoi_list_template]] requires non-empty template_id");
        }
        match tpl.encoder.as_str() {
            "per-list-status" | "per-list-path" | "per-list-node" => {}
            other => anyhow::bail!(
                "[[ppoi_list_template]] template_id={:?} encoder={other:?} is not a \
                 PPOI encoder (allowed: per-list-status, per-list-path, per-list-node)",
                tpl.template_id
            ),
        }
        if tpl.data_dir_template.trim().is_empty() {
            anyhow::bail!(
                "[[ppoi_list_template]] template_id={:?} requires non-empty data_dir_template",
                tpl.template_id
            );
        }
        if !tpl.data_dir_template.contains("{list_key}") {
            anyhow::bail!(
                "[[ppoi_list_template]] template_id={:?} data_dir_template must contain the \
                 literal substring '{{list_key}}' (got: {:?}); without it every list spawn \
                 would collide on the same on-disk path",
                tpl.template_id,
                tpl.data_dir_template
            );
        }
        let _ = parse_hex32(&tpl.list_key).map_err(|e| {
            anyhow::anyhow!(
                "[[ppoi_list_template]] template_id={:?} list_key parse error: {e}",
                tpl.template_id
            )
        })?;
    }

    let global_max_instance_count = parsed.global.max_instance_count;
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
            .find(|t| {
                matches!(
                    t.encoder.as_str(),
                    "per-leaf-bc" | "per-leaf-path" | "per-node"
                )
            })
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

    let bearer = resolve_bearer_token(
        parsed.global.token.as_deref(),
        parsed.global.token_file.as_deref(),
        std::env::var(BEARER_TOKEN_ENV).ok(),
        path,
    )?;
    tracing::info!(source = bearer.source.label(), "bearer token resolved");

    // Ahead of `HttpConfig::validate` so an exposed-origin posture is refused
    // before bootstrap does any chain work.
    resolve_declared_ranges(
        parsed.global.trust_proxy_header.unwrap_or(false),
        parsed.global.trusted_proxy_cidrs.as_deref().unwrap_or(&[]),
    )
    .map_err(|e| anyhow::anyhow!("[global] {e}"))?;

    Ok(MultiServeOptions {
        bind: parsed.global.bind,
        token: bearer.token,
        rpc_url: parsed.global.rpc_url,
        railgun_proxy: parsed.global.railgun_proxy,
        chain_id: parsed.global.chain_id,
        start_block: parsed.global.start_block,
        mirror_endpoint: parsed.global.mirror_endpoint,
        max_concurrent_queries: parsed.global.max_concurrent_queries.unwrap_or(4),
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
        ppoi_list_templates: parsed.ppoi_list_template,
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
    })
}

fn build_encoder_kind(
    kind: EncoderString,
    tree_number: Option<u32>,
    list_key: Option<&str>,
) -> anyhow::Result<EncoderKind> {
    match kind {
        EncoderString::PerLeafBc => Ok(EncoderKind::PerLeafBc { tree_number: 0 }),
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
        EncoderString::PerListStatus => {
            let lk = list_key
                .ok_or_else(|| anyhow::anyhow!("per-list-status encoder requires `list_key`"))?;
            Ok(EncoderKind::PerListStatus {
                list_key: parse_hex32(lk)?,
            })
        }
        EncoderString::PerListPath => {
            let lk = list_key
                .ok_or_else(|| anyhow::anyhow!("per-list-path encoder requires `list_key`"))?;
            Ok(EncoderKind::PerListPath {
                list_key: parse_hex32(lk)?,
            })
        }
        EncoderString::PerListNode => {
            let lk = list_key
                .ok_or_else(|| anyhow::anyhow!("per-list-node encoder requires `list_key`"))?;
            Ok(EncoderKind::PerListNode {
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
        DataSourceSection::Mirror { list_key, .. } => {
            Ok(DataSourceFilter::PpoiList(parse_hex32(list_key)?))
        }
    }
}

fn enforce_verification_mode_matches_data_source(
    data_source: &DataSourceFilter,
    mode: VerificationMode,
) -> anyhow::Result<()> {
    match (data_source, mode) {
        (DataSourceFilter::ChainTreeNumber(_), VerificationMode::ChainRootHistory)
        | (DataSourceFilter::PpoiList(_), VerificationMode::UpstreamSignature) => Ok(()),
        (DataSourceFilter::ChainTreeNumber(t), VerificationMode::UpstreamSignature) => {
            anyhow::bail!(
                "chain-tree instance (tree_number={t}) must use \
                 verification_mode = \"chain-root-history\""
            )
        }
        (DataSourceFilter::PpoiList(_), VerificationMode::ChainRootHistory) => {
            anyhow::bail!("ppoi-list instance must use verification_mode = \"upstream-signature\"")
        }
    }
}

fn enforce_encoder_matches_data_source(
    encoder: EncoderKind,
    data_source: &DataSourceFilter,
) -> anyhow::Result<()> {
    match (encoder, data_source) {
        (
            EncoderKind::PerLeafBc { .. }
            | EncoderKind::PerLeafPath { .. }
            | EncoderKind::PerNode { .. },
            DataSourceFilter::ChainTreeNumber(_),
        )
        | (
            EncoderKind::PerListStatus { .. }
            | EncoderKind::PerListPath { .. }
            | EncoderKind::PerListNode { .. },
            DataSourceFilter::PpoiList(_),
        ) => Ok(()),
        _ => anyhow::bail!(
            "encoder kind {} does not match data_source {:?}",
            encoder.label(),
            data_source
        ),
    }
}

fn parse_hex32(s: &str) -> anyhow::Result<[u8; 32]> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    if trimmed.len() != 64 {
        anyhow::bail!("expected 64 hex chars for list_key, got {}", trimmed.len());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = trimmed
            .as_bytes()
            .get(i * 2)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("list_key hex out-of-range"))?;
        let lo = trimmed
            .as_bytes()
            .get(i * 2 + 1)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("list_key hex out-of-range"))?;
        let nib = |c: u8| -> anyhow::Result<u8> {
            match c {
                b'0'..=b'9' => Ok(c - b'0'),
                b'a'..=b'f' => Ok(c - b'a' + 10),
                b'A'..=b'F' => Ok(c - b'A' + 10),
                other => anyhow::bail!("invalid hex byte {other:#x}"),
            }
        };
        *byte = (nib(hi)? << 4) | nib(lo)?;
    }
    Ok(out)
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

pub async fn run_with_listener<F: std::future::Future<Output = ()> + Send + 'static>(
    opts: MultiServeOptions,
    listener: tokio::net::TcpListener,
    shutdown: F,
) -> anyhow::Result<()> {
    if opts.instances.is_empty() {
        anyhow::bail!("multi-instance serve requires at least one [[instance]] config");
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

    let bootstrap = bootstrap_instances(&opts, fleet_default_entries, &params)?;

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

    let chain_workers = if opts.skip_chain_workers {
        None
    } else {
        Some(
            spawn_chain_indexer(
                &opts,
                min_effective_start_block,
                per_tree_start_blocks.clone(),
                resolved_reorg_window_path.clone(),
                bootstrap.handles.channels.indexer_tx.clone(),
            )
            .await?,
        )
    };
    let mirror_workers = if opts.skip_mirror_workers {
        None
    } else {
        Some(spawn_mirror_workers(&opts, &bootstrap.handles)?)
    };

    let mut http_config = HttpConfig::demo(opts.token.clone());
    http_config.max_concurrent_queries = opts.max_concurrent_queries.max(1);
    http_config.respond_timeout_secs = opts.respond_timeout_secs;
    if let Some(rps) = opts.rate_limit_rps {
        http_config.rate_limit_rps = rps;
    }
    if let Some(burst) = opts.rate_limit_burst {
        http_config.rate_limit_burst = burst;
    }
    if let Some(origins) = opts.cors_allowed_origins.clone() {
        http_config.cors_allowed_origins = origins;
    }
    if let Some(trust) = opts.trust_proxy_header {
        http_config.trust_proxy_header = trust;
    }
    if let Some(cidrs) = opts.trusted_proxy_cidrs.clone() {
        http_config.trusted_proxy_cidrs = cidrs;
    }
    if let Some(public) = opts.metrics_public {
        http_config.metrics_public = public;
    }
    if let Some(secs) = opts.session_eviction_interval_secs {
        http_config.session_eviction_interval_secs = secs;
    }

    let app_state =
        AppState::new(engine, http_config).map_err(|e| anyhow::anyhow!("AppState::new: {e}"))?;

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
        )?)
    } else {
        None
    };

    let ppoi_list_state: Option<PpoiListWiring> = if opts.ppoi_list_templates.is_empty() {
        None
    } else {
        Some(wire_ppoi_list_driver(
            &opts.ppoi_list_templates,
            &params,
            Arc::clone(&app_state.engine),
            Arc::clone(&bootstrap.handles.ppoi_list_routes),
            bootstrap.handles.list_observed.clone(),
            &bootstrap.handles.instances,
            opts.entries,
        )?)
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
                    run_sighup_reload_loop(reload_path, live_runtime, entries_default).await;
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
        }
    }
    let app_state = if let Some(metrics) = bootstrap.handles.instances.first() {
        app_state.with_consumer_metrics(Arc::clone(&metrics.metrics))
    } else {
        app_state
    };
    let app_state = app_state.with_instance_concurrency(k_map);
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

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await?;

    drop(bootstrap.handles.channels);
    for handle in bootstrap.handles.instances {
        let _ = handle
            .sender
            .send(raven_railgun_engine::persistence::ConsumerEvent::Shutdown)
            .await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle.consumer).await;
    }
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), bootstrap.handles.router).await;

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
        for handle in auto_spawned {
            let instance_id = handle.instance_id.clone();
            let _ = handle
                .consumer_sender
                .send(raven_railgun_engine::persistence::ConsumerEvent::Shutdown)
                .await;
            match tokio::time::timeout(std::time::Duration::from_secs(30), handle.consumer_join)
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(join_err)) => {
                    tracing::warn!(
                        instance_id = %instance_id,
                        error = %join_err,
                        "auto_spawn consumer join error on shutdown"
                    );
                }
                Err(_) => {
                    tracing::warn!(
                        instance_id = %instance_id,
                        timeout_secs = 30u64,
                        "auto_spawn consumer did not exit within shutdown timeout"
                    );
                }
            }
        }
        if drained > 0 {
            tracing::info!(drained, "auto_spawn: drained consumers on shutdown");
        }
        driver.abort();
    }

    if let Some(wiring) = ppoi_list_state {
        let PpoiListWiring {
            driver,
            registry,
            spawn_log_dir: _,
        } = wiring;
        let auto_spawned = registry.drain_auto_spawned();
        let drained = auto_spawned.len();
        for handle in auto_spawned {
            let instance_id = handle.instance_id.clone();
            let _ = handle
                .consumer_sender
                .send(raven_railgun_engine::persistence::ConsumerEvent::Shutdown)
                .await;
            match tokio::time::timeout(std::time::Duration::from_secs(30), handle.consumer_join)
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(join_err)) => {
                    tracing::warn!(
                        instance_id = %instance_id,
                        error = %join_err,
                        "ppoi_list auto_spawn consumer join error on shutdown"
                    );
                }
                Err(_) => {
                    tracing::warn!(
                        instance_id = %instance_id,
                        timeout_secs = 30u64,
                        "ppoi_list auto_spawn consumer did not exit within shutdown timeout"
                    );
                }
            }
        }
        if drained > 0 {
            tracing::info!(
                drained,
                "ppoi_list auto_spawn: drained consumers on shutdown"
            );
        }
        driver.abort();
    }

    // Cooperative so a panic surfaces as a join error rather than being aborted away.
    if let Some(mut workers) = chain_workers {
        workers
            .shutdown_mode_mirror(std::time::Duration::from_secs(5))
            .await;
        drop(workers);
    }
    drop(mirror_workers);

    Ok(())
}

struct AutoSpawnWiring {
    driver: tokio::task::JoinHandle<()>,
    registry: Arc<crate::auto_spawn_driver::SpawnRegistry>,
    live_runtime: Arc<arc_swap::ArcSwap<crate::auto_spawn_driver::AutoSpawnRuntime>>,
    spawn_log_dir: PathBuf,
}

#[cfg(unix)]
async fn run_sighup_reload_loop(
    config_path: PathBuf,
    live_runtime: Arc<arc_swap::ArcSwap<crate::auto_spawn_driver::AutoSpawnRuntime>>,
    entries_default: usize,
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
                let runtime = runtime_from_auto_spawn_section(&synthesized, entries_default);
                live_runtime.store(Arc::new(runtime));
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

struct TreeFillWatcherInputs {
    threshold: f32,
    instance_views: Vec<BootstrapInstanceView>,
    live_runtime: Arc<arc_swap::ArcSwap<crate::auto_spawn_driver::AutoSpawnRuntime>>,
    params: InspireParams,
    engine: Arc<Engine<RavenInspireScheme>>,
    chain_tree_routes: raven_railgun_engine::orchestrator::ChainTreeRoutes,
    registry: Arc<crate::auto_spawn_driver::SpawnRegistry>,
    spawn_log_dir: PathBuf,
}

async fn run_tree_fill_watcher(inputs: TreeFillWatcherInputs) {
    let TreeFillWatcherInputs {
        threshold,
        instance_views,
        live_runtime,
        params,
        engine,
        chain_tree_routes,
        registry,
        spawn_log_dir,
    } = inputs;
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
        let known: Vec<u32> = registry.known();
        let Some(active_tree) = known.into_iter().max() else {
            continue;
        };
        let Some(view) = instance_views.iter().find(|v| {
            v.data_source
                == raven_railgun_engine::orchestrator::DataSourceFilter::ChainTreeNumber(
                    active_tree,
                )
        }) else {
            continue;
        };
        let leaf_count = view.logical_store.lock().imt_leaf_count_for(active_tree);
        if leaf_count < trigger_at {
            continue;
        }
        let next_tree = active_tree.saturating_add(1);
        let runtime_snapshot = live_runtime.load_full();
        match crate::auto_spawn_driver::pre_spawn_for_tree(
            runtime_snapshot.as_ref(),
            &params,
            &engine,
            &chain_tree_routes,
            &registry,
            spawn_log_dir.clone(),
            None,
            next_tree,
        ) {
            Ok(true) => {
                tracing::info!(
                    active_tree,
                    next_tree,
                    leaf_count,
                    trigger_at,
                    "tree_fill_threshold: pre-spawned successor BEFORE chain rollover"
                );
            }
            Ok(false) => {
                tracing::trace!(
                    active_tree,
                    next_tree,
                    "tree_fill_threshold: successor already known to registry"
                );
            }
            Err(e) => {
                tracing::error!(
                    active_tree,
                    next_tree,
                    error = %e,
                    "tree_fill_threshold: pre-spawn failed; will retry on next tick"
                );
            }
        }
    }
}

fn runtime_from_auto_spawn_section(
    cfg: &AutoSpawnConfigToml,
    default_entries: usize,
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
    }
}

fn wire_auto_spawn(
    cfg: &AutoSpawnConfigToml,
    params: &InspireParams,
    engine: Arc<raven_railgun_engine::Engine<RavenInspireScheme>>,
    chain_tree_routes: raven_railgun_engine::orchestrator::ChainTreeRoutes,
    tree_observed: tokio::sync::broadcast::Sender<u32>,
    initial_handles: &[raven_railgun_engine::orchestrator::PerInstanceHandles],
    opts: &MultiServeOptions,
) -> anyhow::Result<AutoSpawnWiring> {
    use crate::auto_spawn_driver::{replay_spawn_log, run_driver_dynamic, SpawnRegistry};

    let runtime = runtime_from_auto_spawn_section(cfg, opts.entries);

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

struct PpoiListWiring {
    driver: tokio::task::JoinHandle<()>,
    registry: Arc<crate::auto_spawn_driver::PpoiListSpawnRegistry>,
    #[allow(dead_code)]
    spawn_log_dir: PathBuf,
}

#[allow(clippy::too_many_arguments)]
fn wire_ppoi_list_driver(
    templates: &[PpoiListTemplateToml],
    params: &InspireParams,
    engine: Arc<raven_railgun_engine::Engine<RavenInspireScheme>>,
    ppoi_list_routes: raven_railgun_engine::orchestrator::PpoiListRoutes,
    list_observed: tokio::sync::broadcast::Sender<[u8; 32]>,
    initial_handles: &[raven_railgun_engine::orchestrator::PerInstanceHandles],
    entries_default: usize,
) -> anyhow::Result<PpoiListWiring> {
    use crate::auto_spawn_driver::{
        replay_ppoi_list_spawn_log, run_ppoi_list_driver, PpoiListSpawnRegistry,
        PpoiListTemplateRuntime,
    };

    let runtimes: Vec<PpoiListTemplateRuntime> = templates
        .iter()
        .map(|t| ppoi_list_template_runtime(t, entries_default))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let spawn_log_dir = match initial_handles.first() {
        Some(h) => h
            .config
            .data_dir
            .parent()
            .map_or_else(|| h.config.data_dir.clone(), std::path::PathBuf::from),
        None => std::path::PathBuf::from("."),
    };

    let registry = Arc::new(PpoiListSpawnRegistry::new());

    let restored = replay_ppoi_list_spawn_log(
        &runtimes,
        params,
        &engine,
        &ppoi_list_routes,
        &registry,
        spawn_log_dir.clone(),
    )
    .with_context(|| "replay ppoi_list_spawn_log on startup")?;
    if !restored.is_empty() {
        tracing::info!(
            count = restored.len(),
            "ppoi_list auto_spawn: restored instances from spawn log"
        );
    }

    let receiver = list_observed.subscribe();
    let runtimes_for_task = runtimes.clone();
    let params_for_task = params.clone();
    let engine_for_task = engine;
    let routes_for_task = ppoi_list_routes;
    let registry_for_task = Arc::clone(&registry);
    let log_dir_for_task = spawn_log_dir.clone();
    let handle = tokio::spawn(async move {
        run_ppoi_list_driver(
            runtimes_for_task,
            params_for_task,
            engine_for_task,
            routes_for_task,
            registry_for_task,
            log_dir_for_task,
            receiver,
        )
        .await;
    });

    Ok(PpoiListWiring {
        driver: handle,
        registry,
        spawn_log_dir,
    })
}

fn ppoi_list_template_runtime(
    tpl: &PpoiListTemplateToml,
    entries_default: usize,
) -> anyhow::Result<crate::auto_spawn_driver::PpoiListTemplateRuntime> {
    let list_key = parse_hex32(&tpl.list_key)?;
    Ok(crate::auto_spawn_driver::PpoiListTemplateRuntime {
        template_id: tpl.template_id.clone(),
        list_key,
        encoder: tpl.encoder.clone(),
        scheme_tag: if tpl.scheme_tag.is_empty() {
            SCHEME_TAG_DEFAULT.to_owned()
        } else {
            tpl.scheme_tag.clone()
        },
        data_dir_template: tpl.data_dir_template.clone(),
        entries: if tpl.entries == 0 {
            entries_default
        } else {
            tpl.entries
        },
        entry_bytes: if tpl.entry_bytes == 0 {
            16 * 32
        } else {
            tpl.entry_bytes
        },
        channel_capacity: 1024,
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
) -> anyhow::Result<Bootstrap> {
    let mut state_holders: Vec<Option<InspireServerState>> =
        Vec::with_capacity(opts.instances.len());
    for cfg in &opts.instances {
        let entry_size = cfg.record_size.max(32);
        let entries = entries_for_instance(opts, cfg, fleet_default_entries);
        validate_instance_cell_shape(cfg, entries, params.ring_dim)?;
        let initial_db: Vec<u8> = (0..entries)
            .flat_map(|i| (0..entry_size).map(move |j| u8::try_from((i + j) % 251).unwrap_or(0)))
            .collect();
        let (state, _sk) = setup_state(params, &initial_db, entry_size, InspireVariant::TwoPacking)
            .map_err(|e| anyhow::anyhow!("setup_state: {e}"))?;
        state_holders.push(Some(state));
    }

    let order: Vec<InstanceId> = opts
        .instances
        .iter()
        .map(|c| c.instance_id.clone())
        .collect();

    let mut idx_lookup: HashMap<InstanceId, usize> = HashMap::with_capacity(order.len());
    for (i, id) in order.iter().enumerate() {
        if idx_lookup.insert(id.clone(), i).is_some() {
            anyhow::bail!("duplicate instance id in config: {id}");
        }
    }

    let mut taken = state_holders;
    let factory = |cfg: &InstanceConfig| {
        let i = idx_lookup.get(&cfg.instance_id).copied().ok_or_else(|| {
            raven_railgun_core::AdapterError::Internal(format!(
                "no state holder for instance {}",
                cfg.instance_id
            ))
        })?;
        taken.get_mut(i).and_then(Option::take).ok_or_else(|| {
            raven_railgun_core::AdapterError::Internal(format!(
                "state holder already consumed for instance {}",
                cfg.instance_id
            ))
        })
    };

    let handles = bootstrap_railgun_engine_multi(opts.instances.clone(), params.clone(), factory)
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

    let (chain_source, rpc_pool, chain_source_mode, mode_mirror) =
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
                let mirror = spawn_mode_mirror_pooled(
                    Arc::clone(&auto),
                    Arc::clone(&mode_flag),
                    mode_mirror_shutdown_rx,
                );
                (
                    DynChainSource::AutoFallbackPooled(auto),
                    Some(pool),
                    Some(mode_flag),
                    Some(mirror),
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
                let mirror = spawn_mode_mirror_single(
                    Arc::clone(&auto),
                    Arc::clone(&mode_flag),
                    mode_mirror_shutdown_rx,
                );
                (
                    DynChainSource::AutoFallbackSingle(auto),
                    None,
                    Some(mode_flag),
                    Some(mirror),
                )
            }
            (None, Some(pool_cfg)) if pool_cfg.urls.len() >= 2 => {
                let pool = build_pool(pool_cfg)?;
                let pooled = Arc::new(PooledRpcChainSource::new(
                    Arc::clone(&pool),
                    proxy_addr,
                    opts.chain_id,
                ));
                (DynChainSource::Pooled(pooled), Some(pool), None, None)
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
                (DynChainSource::Single(single), None, None, None)
            }
        };

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
    let worker = IndexerWorker::new(Arc::new(chain_source), indexer_tx);
    let worker_config = IndexerWorkerConfig {
        start_block: min_effective_start_block,
        poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
        reorg_window_path: resolved_reorg_window_path,
        per_tree_start_blocks,
        ..IndexerWorkerConfig::default()
    };
    let handle = tokio::spawn(async move {
        if let Err(e) = worker.run(worker_config).await {
            tracing::error!(error = %e, "chain indexer worker exiting");
        }
    });
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
}

fn spawn_mirror_workers(
    opts: &MultiServeOptions,
    handle: &MultiOrchestratorHandle,
) -> anyhow::Result<MirrorWorkers> {
    use raven_railgun_engine::pir_table::EncoderKind;
    use raven_railgun_ppoi_mirror::{MirrorConfig, MirrorCursor, MirrorKind, UpstreamPpoiMirror};

    let mirror_config = MirrorConfig {
        endpoint: opts.mirror_endpoint.clone(),
        ..MirrorConfig::default()
    };
    let mirror = Arc::new(
        UpstreamPpoiMirror::new(mirror_config)
            .map_err(|e| anyhow::anyhow!("ppoi mirror constructor: {e}"))?,
    );
    let mirror_tx = handle.channels.mirror_tx.clone();

    let mut handles = Vec::new();
    for inst in &handle.instances {
        if let DataSourceFilter::PpoiList(list_key) = inst.config.data_source {
            let mirror_clone = Arc::clone(&mirror);
            let tx = mirror_tx.clone();
            // per-list-path owns the path sidecar; every other kind uses status.
            let kind = match inst.config.encoder {
                EncoderKind::PerListPath { .. } => MirrorKind::Path,
                _ => MirrorKind::Status,
            };
            let fallback = {
                let store = inst.logical_store.lock();
                #[allow(clippy::cast_possible_truncation)]
                let count = store
                    .ppoi_imt(&list_key)
                    .map_or(0u64, |imt| imt.leaf_count() as u64);
                count
            };
            let cursor = MirrorCursor::new(inst.config.data_dir.clone(), kind, fallback);
            let h = tokio::spawn(async move {
                if let Err(e) = mirror_clone
                    .run_worker_with_cursor(ListKey(list_key), 0, Some(cursor), tx)
                    .await
                {
                    tracing::error!(error = %e, "ppoi mirror worker exiting");
                }
            });
            handles.push(h);
        }
    }
    Ok(MirrorWorkers { handles })
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
verification_mode = "chain-root-history"
data_source = { kind = "indexer", filter = { tree_number = 0 } }

[[instance]]
id = "ppoi-status"
role = "live"
encoder = "per-list-status"
list_key = "0000000000000000000000000000000000000000000000000000000000000001"
data_dir = "/tmp/raven-ppoi"
verification_mode = "upstream-signature"
data_source = { kind = "mirror", list_key = "0000000000000000000000000000000000000000000000000000000000000001", what = "status" }
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
            EncoderKind::PerListStatus { .. }
        ));
        assert!(matches!(
            opts.instances[1].data_source,
            DataSourceFilter::PpoiList(_)
        ));
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
verification_mode = "chain-root-history"
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
verification_mode = "chain-root-history"
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

    #[test]
    fn no_token_source_at_all_is_rejected() {
        let body = config_with_global_extras("");
        let f = write_temp_toml(&body);
        let err = load_options_from_toml(f.path()).expect_err("zero sources must be rejected");
        let msg = format!("{err:#}");
        assert!(msg.contains("RAVEN_BEARER_TOKEN"), "{msg}");
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
verification_mode = "chain-root-history"
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
data_dir = "/tmp/raven-tree-0"
verification_mode = "chain-root-history"
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
verification_mode = "chain-root-history"
data_source = { kind = "indexer", filter = { tree_number = 0 } }

[[instance]]
id = "ppoi-paths"
role = "live"
encoder = "per-list-node"
list_key = "0000000000000000000000000000000000000000000000000000000000000001"
data_dir = "/tmp/raven-ppoi-paths"
verification_mode = "upstream-signature"
data_source = { kind = "mirror", list_key = "0000000000000000000000000000000000000000000000000000000000000001" }

[[instance]]
id = "ppoi-status"
role = "live"
encoder = "per-list-status"
list_key = "0000000000000000000000000000000000000000000000000000000000000001"
data_dir = "/tmp/raven-ppoi-status"
verification_mode = "upstream-signature"
data_source = { kind = "mirror", list_key = "0000000000000000000000000000000000000000000000000000000000000001", what = "status" }

[[instance]]
id = "ppoi-status-wide"
role = "live"
encoder = "per-list-status"
list_key = "0000000000000000000000000000000000000000000000000000000000000001"
record_size = 128
data_dir = "/tmp/raven-ppoi-status-wide"
verification_mode = "upstream-signature"
data_source = { kind = "mirror", list_key = "0000000000000000000000000000000000000000000000000000000000000001", what = "status" }
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
            width("ppoi-paths"),
            node_hash,
            "per-list-node pins its canonical width over [global].record_size"
        );
        assert_eq!(
            width("ppoi-status"),
            512,
            "an encoder without a canonical width inherits [global].record_size"
        );
        assert_eq!(
            width("ppoi-status-wide"),
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
verification_mode = "chain-root-history"
data_source = {{ kind = "indexer", filter = {{ tree_number = {tree} }} }}
"#
            )
            .expect("String writes are infallible");
        }
        write!(
            body,
            r#"
[[instance]]
id = "ppoi-status-ofac"
role = "live"
encoder = "per-list-status"
list_key = "{OFAC_LIST_KEY}"
data_dir = "/tmp/raven-ppoi-status-ofac"
verification_mode = "upstream-signature"
data_source = {{ kind = "mirror", list_key = "{OFAC_LIST_KEY}", what = "status" }}

[[instance]]
id = "ppoi-paths-ofac"
role = "live"
encoder = "per-list-node"
list_key = "{OFAC_LIST_KEY}"
data_dir = "/tmp/raven-ppoi-paths-ofac"
verification_mode = "upstream-signature"
data_source = {{ kind = "mirror", list_key = "{OFAC_LIST_KEY}", what = "path" }}
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
        assert_eq!(resolved_entries(&opts, "ppoi-paths-ofac"), 131_072);
        assert_eq!(
            resolved_entries(&opts, "ppoi-status-ofac"),
            DEFAULT_PRODUCTION_ENTRIES,
            "leaf-keyed encoders keep the 65,536-row cell; a fleet-wide total would double it"
        );

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
                "ppoi-paths-ofac",
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
            resolved_entries(&opts, "ppoi-status-ofac"),
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
    fn ppoi_with_chain_root_history_rejected() {
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
id = "ppoi-bad"
role = "live"
encoder = "per-list-path"
list_key = "0000000000000000000000000000000000000000000000000000000000000001"
data_dir = "/tmp/raven-ppoi"
verification_mode = "chain-root-history"
data_source = { kind = "mirror", list_key = "0000000000000000000000000000000000000000000000000000000000000001" }
"#;
        let f = write_temp_toml(body);
        let err = load_options_from_toml(f.path()).expect_err("must reject");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("upstream-signature"),
            "expected verification_mode error, got: {msg}"
        );
    }

    #[test]
    fn empty_instance_list_rejected() {
        let body = r#"
[global]
bind = "127.0.0.1:0"
token = "test-token-padded-long-enough"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
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
verification_mode = "chain-root-history"
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
verification_mode = "chain-root-history"
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
verification_mode = "chain-root-history"
data_source = { kind = "indexer", filter = { tree_number = 0 } }
"#;
        let f = write_temp_toml(body);
        let opts = load_options_from_toml(f.path()).expect("parse");
        assert!(opts.rpc_pool.is_none(), "absent section should be None");
        assert_eq!(opts.rpc_url, "http://127.0.0.1:1");
    }
}
