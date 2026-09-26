//! Raven Railgun operator CLI.

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]
#![allow(
    missing_docs,
    clippy::large_enum_variant,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::net::SocketAddr;
use std::time::Duration;

use clap::{Parser, Subcommand};
use raven_railgun_cli::bearer_token::BEARER_TOKEN_ENV;

/// One-shot status timeout; matches the indexer's `MAX_RPC_TOTAL_ELAPSED_SECS`.
const STATUS_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Parser, Debug)]
#[command(
    name = "raven-railgun",
    version,
    about = "Raven Railgun PIR adapter operator CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Boot the HTTP server against a hardcoded toy InsPIRe instance (local dev / tests).
    Serve {
        /// Local address to bind the HTTP server.
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: SocketAddr,
        /// Bearer token clients must present in `Authorization: Bearer <token>`.
        #[arg(long, env = "RAVEN_BEARER_TOKEN")]
        token: String,
        /// Maximum concurrent in-flight respond ops across all instances.
        #[arg(long, default_value_t = 4)]
        max_concurrent_queries: usize,
        /// Per-IP rate limit (sustained requests per second).
        #[arg(long, default_value_t = 100)]
        rate_limit_rps: u64,
        /// Per-IP rate-limit burst budget (token-bucket capacity).
        #[arg(long, default_value_t = 200)]
        rate_limit_burst: u32,
        /// Session lifetime in seconds; at most the compiled default.
        #[arg(long, default_value_t = raven_railgun_http::config::DEFAULT_SESSION_TTL_SECS)]
        session_ttl_secs: u64,
        /// Sticky-session LRU cap.
        #[arg(long, default_value_t = 10_000)]
        session_lru_cap: usize,
    },
    /// Boot the production HTTP server against a real Ethereum RPC + upstream PPOI aggregator.
    ServeProduction {
        /// Multi-instance TOML config file; the single-instance flags are refused alongside it.
        #[arg(long, conflicts_with_all = [
            "rpc_url", "data_dir", "instance_id", "encoder",
            "list_key", "tree_number", "entries", "entry_bytes",
            "respond_timeout_secs", "max_concurrent_queries",
            "enable_fanout", "max_fanout_shards",
            "max_sessions_per_instance", "session_ttl_secs",
            "max_sse_connections", "max_sse_connections_per_peer",
            "railgun_proxy", "chain_id", "start_block", "mirror_endpoint",
            "token", "bind", "session_eviction_interval_secs",
        ])]
        config: Option<std::path::PathBuf>,
        /// Local address to bind the HTTP server.
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: SocketAddr,
        /// Bearer token for Authorization header. `RAVEN_BEARER_TOKEN` is read
        /// after arg parsing, not by clap, so it stays usable alongside `--config`.
        #[arg(long)]
        token: Option<String>,
        /// Ethereum JSON-RPC URL (mainnet / Sepolia / etc).
        #[arg(long, env = "RAVEN_RPC_URL", required_unless_present = "config")]
        rpc_url: Option<String>,
        /// Hex-encoded Railgun proxy contract address.
        #[arg(long, default_value = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9")]
        railgun_proxy: String,
        /// Chain ID.
        #[arg(long, default_value_t = 1)]
        chain_id: u64,
        /// Block to start scanning from (resume point).
        #[arg(long, default_value_t = 14_737_691)]
        start_block: u64,
        /// Upstream PPOI mirror endpoint.
        #[arg(long, default_value = "https://ppoi.fdi.network")]
        mirror_endpoint: String,
        /// Hex-encoded list key to mirror (default: OFAC).
        #[arg(
            long,
            default_value = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88"
        )]
        list_key: String,
        /// On-disk data directory for snapshots + WAL.
        #[arg(long, required_unless_present = "config")]
        data_dir: Option<std::path::PathBuf>,
        /// Instance id within Engine (operator-defined).
        #[arg(long, default_value = "commit-tree-live")]
        instance_id: String,
        /// Maximum concurrent in-flight respond ops.
        #[arg(long, default_value_t = 4)]
        max_concurrent_queries: usize,
        /// Per-query response timeout in seconds.
        #[arg(long, default_value_t = 30)]
        respond_timeout_secs: u64,
        /// PIR cell entry count. Single-instance only; `--config` carries
        /// `entries` per `[[instance]]` because encoder totals differ.
        #[arg(long, default_value_t = raven_railgun_cli::serve_production::DEFAULT_PRODUCTION_ENTRIES)]
        entries: usize,
        /// PIR cell record width in bytes.
        #[arg(long, default_value_t = raven_railgun_cli::serve_production::DEFAULT_PRODUCTION_ENTRY_BYTES)]
        entry_bytes: usize,
        /// Per-instance encoder label (per-leaf-bc, per-leaf-path, per-node, per-list-status,
        /// per-list-path, per-list-path10, per-list-node).
        #[arg(long, default_value = "per-leaf-bc")]
        encoder: String,
        /// Tree this instance's chain encoder is pinned to (ignored for per-list-* variants).
        #[arg(long, default_value_t = 0)]
        tree_number: u32,
        /// WebSocket RPC URL; overrides the TOML `ws_endpoint`. Multi-instance
        /// only - rejected at runtime without `--config`.
        #[arg(long)]
        ws_endpoint: Option<String>,
        /// Expose `/metrics` without bearer auth (default-deny). Affects auth
        /// only; `/metrics` always bypasses the per-IP rate limiter.
        #[arg(long, default_value_t = false)]
        metrics_public: bool,
        /// Heartbeat session-eviction interval in seconds; `0` disables. Each
        /// tick rebuilds `ServerSessionStore`, bounding memory but dropping
        /// live sessions.
        #[arg(long, default_value_t = 3600)]
        session_eviction_interval_secs: u64,
        /// Mount one-query multi-shard fanout. Disabled by default.
        #[arg(long, default_value_t = false)]
        enable_fanout: bool,
        /// Maximum shard ids accepted by one fanout request.
        #[arg(long, default_value_t = 16)]
        max_fanout_shards: usize,
        /// Packing-key seats per instance. Each seat holds the server-derived keys,
        /// about 24 MiB at a 512 B row, so this bounds session memory.
        #[arg(long, default_value_t = raven_railgun_engine::session_pool::DEFAULT_MAX_SESSIONS)]
        max_sessions_per_instance: usize,
        /// Seat and session-handle lifetime in seconds; at most the compiled default.
        #[arg(long, default_value_t = raven_railgun_http::config::DEFAULT_SESSION_TTL_SECS)]
        session_ttl_secs: u64,
        /// Concurrent `/v1/events` streams.
        #[arg(long, default_value_t = raven_railgun_http::config::DEFAULT_MAX_SSE_CONNECTIONS)]
        max_sse_connections: usize,
        /// Concurrent `/v1/events` streams one peer may hold.
        #[arg(
            long,
            default_value_t = raven_railgun_http::config::DEFAULT_MAX_SSE_CONNECTIONS_PER_PEER
        )]
        max_sse_connections_per_peer: usize,
    },
    /// Print engine status by curling /v1/status against a running server.
    Status {
        /// Server URL (e.g. http://127.0.0.1:8080).
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        url: String,
        /// Bearer token.
        #[arg(long, env = "RAVEN_BEARER_TOKEN")]
        token: String,
    },
    /// Dump on-disk snapshot metadata for a given data_dir.
    Dump {
        /// On-disk data directory for the instance.
        #[arg(long)]
        data_dir: std::path::PathBuf,
    },
    /// Bundle instance data_dirs into a zstd tarball for host-to-host migration.
    ExportSnapshot {
        /// Root directory containing one or more instance data_dirs.
        #[arg(long)]
        data_dir: std::path::PathBuf,
        /// Output tarball path (a `.sig` sidecar is written when `--sign` is set).
        #[arg(long)]
        output: std::path::PathBuf,
        /// Sign the export with an Ed25519 key; writes `<output>.sig`.
        #[arg(long)]
        sign: bool,
        /// Path to a 32-byte raw or 64-char hex Ed25519 seed (required with `--sign`).
        #[arg(long)]
        signing_key: Option<std::path::PathBuf>,
        /// Retain only the N newest `*.tar.zst` beside the output; `0` disables.
        #[arg(long, default_value_t = 3)]
        keep_snapshots: usize,
    },
    /// Trim the snapshot drop-zone to the N newest tarballs. Idempotent.
    PruneSnapshots {
        /// Directory containing `*.tar.zst` export tarballs.
        #[arg(long)]
        data_dir: std::path::PathBuf,
        /// Retention floor (N newest tarballs). `0` disables.
        #[arg(long, default_value_t = 3)]
        keep: usize,
    },
    /// Restore a signed export into `--data-dir`; nothing is swapped in unless it recovers to
    /// the state the export recorded.
    ImportSnapshot {
        /// Tarball produced by `export-snapshot`; its `.sig` sidecar must sit beside it.
        #[arg(long)]
        input: std::path::PathBuf,
        /// Destination root for the unpacked instance data_dirs.
        #[arg(long)]
        data_dir: std::path::PathBuf,
        /// Path to a 32-byte raw or 64-char hex Ed25519 verifying key.
        #[arg(long)]
        verifying_key: std::path::PathBuf,
        /// The `content_hash_hex` export-snapshot printed for this deploy's export.
        #[arg(long)]
        expect_content_hash: String,
        /// Permit importing over a non-empty data root; what it holds is moved to
        /// `<root>.pre-import.<ts>/` first, never deleted.
        #[arg(long, default_value_t = false)]
        allow_overwrite: bool,
    },
    /// Bootstrap commitment-tree instance state from a Subsquid checkpoint, verified
    /// against the chain ABI. Requires archival RPC state at
    /// `chain_head - checkpoint_depth`.
    ///
    /// Writes commitment trees only. PPOI lists are synced at runtime by `serve-production`,
    /// from each `[[instance]]` whose `data_source` kind is `mirror`.
    BootstrapFromSubsquid {
        /// Per-endpoint heterogeneous rpc-pool TOML.
        #[arg(long)]
        rpc_pool_config: std::path::PathBuf,
        /// Subsquid GraphQL endpoint.
        #[arg(
            long,
            default_value = "https://rail-squid.squids.live/squid-railgun-ethereum-v2/graphql"
        )]
        subsquid_url: String,
        /// Per-tree data_dir template; must contain `{N}`.
        #[arg(long)]
        data_dir_template: String,
        /// Comma-separated tree numbers to bootstrap.
        #[arg(long, default_value = "0,1,2,3", value_delimiter = ',')]
        tree_numbers: Vec<u32>,
        /// Block depth below chain head to anchor the checkpoint at.
        #[arg(long, default_value_t = 64)]
        checkpoint_depth: u64,
        /// Chain id every RPC pool endpoint must report; an endpoint on another chain is refused.
        #[arg(long, default_value_t = 1)]
        chain_id: u64,
        /// Scheme tag for the persisted manifest.
        #[arg(
            long,
            default_value = "raven-inspire-twopacking-inspiring-wp3-cache-session"
        )]
        scheme_tag: String,
        /// Removed: the encoder determines bootstrap cell rows.
        #[arg(long, value_parser = removed_bootstrap_entries)]
        entries: Option<usize>,
        /// Removed: the encoder determines bootstrap row width.
        #[arg(long, value_parser = removed_bootstrap_entry_bytes)]
        entry_bytes: Option<usize>,
        /// Wall-clock cap for the entire bootstrap loop.
        #[arg(long, default_value_t = 30)]
        max_bootstrap_wall_mins: u64,
        /// Hex-encoded proxy contract address for the chain-side oracle.
        #[arg(long, default_value = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9")]
        railgun_proxy: String,
        /// Block at which `--railgun-proxy` was deployed. Floors the closed-tree rollover
        /// search: below it the address has no code, an eth_call returns empty data, and the
        /// read fails in the ABI decoder rather than answering.
        #[arg(long, default_value_t = raven_railgun_cli::bootstrap_subsquid::COMMITMENTS_PROXY_START_BLOCK)]
        contract_start_block: u64,
        /// Row count above which boundary repair gap-walks. Tunes self-healing only; a tree
        /// below it is still refused by the closing-root comparison. Must not exceed the
        /// tree capacity, or it can never be reached.
        #[arg(long)]
        boundary_repair_trigger_threshold: Option<usize>,
        /// Encoder family stamped into each tree's manifest `encoder_label`:
        /// `per-leaf-bc`, `per-leaf-path`, or `per-node`.
        #[arg(long, default_value = "per-node")]
        encoder: String,
    },
    /// Re-encode an on-disk instance to a new encoder (server must be stopped first).
    MigrateEncoder {
        /// On-disk data directory for the instance to migrate.
        #[arg(long)]
        data_dir: std::path::PathBuf,
        /// Target encoder label (per-leaf-bc, per-leaf-path, per-node, per-list-status,
        /// per-list-path, per-list-path10, per-list-node).
        #[arg(long)]
        to: String,
        /// Tree number (required for per-node and per-leaf-path).
        #[arg(long, default_value_t = 0)]
        tree_number: u32,
        /// List key hex 64 chars (required for per-list-* encoders).
        #[arg(long, default_value = "")]
        list_key: String,
    },
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Serve {
            bind,
            token,
            max_concurrent_queries,
            rate_limit_rps,
            rate_limit_burst,
            session_ttl_secs,
            session_lru_cap,
        } => {
            let opts = ServeOptions {
                bind,
                token,
                max_concurrent_queries,
                rate_limit_rps,
                rate_limit_burst,
                session_ttl_secs,
                session_lru_cap,
            };
            serve_toy(opts).await
        }
        Commands::ServeProduction {
            config,
            bind,
            token,
            rpc_url,
            railgun_proxy,
            chain_id,
            start_block,
            mirror_endpoint,
            list_key,
            data_dir,
            instance_id,
            max_concurrent_queries,
            respond_timeout_secs,
            entries,
            entry_bytes,
            encoder,
            tree_number,
            ws_endpoint,
            metrics_public,
            session_eviction_interval_secs,
            enable_fanout,
            max_fanout_shards,
            max_sessions_per_instance,
            session_ttl_secs,
            max_sse_connections,
            max_sse_connections_per_peer,
        } => {
            if let Some(path) = config {
                let opts = multi_options_from_config(&path, ws_endpoint, metrics_public)?;
                return raven_railgun_cli::serve_production_multi::run(opts).await;
            }
            if ws_endpoint.is_some() {
                anyhow::bail!(
                    "--ws-endpoint is multi-instance only; pass --config <toml> alongside it. \
                     The single-instance path uses RpcChainSource directly without WS."
                );
            }
            let encoder_kind = parse_encoder_kind(&encoder, tree_number, &list_key)?;
            let token = token
                .or_else(|| std::env::var(BEARER_TOKEN_ENV).ok())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "no bearer token: pass --token or set {BEARER_TOKEN_ENV} \
                         (--config sources it from the TOML instead)"
                    )
                })?;
            let rpc_url = rpc_url
                .ok_or_else(|| anyhow::anyhow!("--rpc-url required when --config not set"))?;
            let data_dir = data_dir
                .ok_or_else(|| anyhow::anyhow!("--data-dir required when --config not set"))?;
            let opts = raven_railgun_cli::serve_production::ProductionServeOptions {
                bind,
                token,
                rpc_url,
                railgun_proxy,
                chain_id,
                start_block,
                mirror_endpoint,
                list_key,
                data_dir,
                instance_id,
                max_concurrent_queries,
                respond_timeout_secs,
                entries,
                entry_bytes,
                encoder: encoder_kind,
                session_eviction_interval_secs,
                metrics_public,
                enable_fanout,
                max_fanout_shards,
                session_capacity: raven_railgun_cli::serve_production::SessionCapacity {
                    max_sessions_per_instance,
                    session_ttl_secs,
                    max_sse_connections,
                    max_sse_connections_per_peer,
                },
            };
            raven_railgun_cli::serve_production::run(opts).await
        }
        Commands::Status { url, token } => {
            let client = reqwest::Client::builder()
                .timeout(STATUS_REQUEST_TIMEOUT)
                .build()
                .map_err(|e| anyhow::anyhow!("reqwest builder failed: {e}"))?;
            let resp = client
                .get(format!("{url}/v1/status"))
                .bearer_auth(&token)
                .send()
                .await?;
            let status = resp.status();
            let body = resp.text().await?;
            println!("HTTP {status}\n{body}");
            if status.is_success() {
                Ok(())
            } else {
                anyhow::bail!("status request returned {status}")
            }
        }
        Commands::ExportSnapshot {
            data_dir,
            output,
            sign,
            signing_key,
            keep_snapshots,
        } => {
            if sign && signing_key.is_none() {
                anyhow::bail!("--sign requires --signing-key");
            }
            if !sign && signing_key.is_some() {
                anyhow::bail!("--signing-key only meaningful with --sign");
            }
            let signing_key = if sign { signing_key } else { None };
            let opts = raven_railgun_cli::snapshot_port::ExportOptions {
                data_dir,
                output,
                signing_key,
                keep_snapshots,
            };
            let receipt = raven_railgun_cli::snapshot_port::run_export(opts)?;
            println!("{receipt}");
            Ok(())
        }
        Commands::PruneSnapshots { data_dir, keep } => raven_railgun_cli::snapshot_port::run_prune(
            raven_railgun_cli::snapshot_port::PruneOptions {
                data_dir,
                keep_snapshots: keep,
            },
        ),
        Commands::ImportSnapshot {
            input,
            data_dir,
            verifying_key,
            expect_content_hash,
            allow_overwrite,
        } => {
            let opts = raven_railgun_cli::snapshot_port::ImportOptions {
                input,
                data_dir,
                verifying_key,
                expected_content_hash: expect_content_hash,
                allow_overwrite,
            };
            let receipt = raven_railgun_cli::snapshot_port::run_import(opts)?;
            println!("{receipt}");
            Ok(())
        }
        Commands::BootstrapFromSubsquid {
            rpc_pool_config,
            subsquid_url,
            data_dir_template,
            tree_numbers,
            checkpoint_depth,
            chain_id,
            scheme_tag,
            entries: _,
            entry_bytes: _,
            max_bootstrap_wall_mins,
            railgun_proxy,
            contract_start_block,
            boundary_repair_trigger_threshold,
            encoder,
        } => {
            let chain_encoder_family = parse_chain_encoder_family(&encoder)?;
            let opts = BootstrapFromSubsquidOptions {
                rpc_pool_config,
                subsquid_url,
                data_dir_template,
                tree_numbers,
                checkpoint_depth,
                chain_id,
                scheme_tag,
                max_bootstrap_wall_mins,
                railgun_proxy,
                contract_start_block,
                boundary_repair_trigger_threshold,
                chain_encoder_family,
            };
            run_bootstrap_from_subsquid(opts).await
        }
        Commands::MigrateEncoder {
            data_dir,
            to,
            tree_number,
            list_key,
        } => {
            let target_kind = parse_encoder_kind(&to, tree_number, &list_key)
                .map_err(|e| anyhow::anyhow!("--to: {e}"))?;
            raven_railgun_cli::migrate_encoder::run(&data_dir, target_kind)
        }
        Commands::Dump { data_dir } => {
            let layout = raven_railgun_persistence::StoreLayout::open(&data_dir)?;
            let manifest_opt = raven_railgun_persistence::Manifest::load(&layout)?;
            match manifest_opt {
                Some(m) => {
                    println!("Manifest:");
                    println!("  schema_version       = {}", m.schema_version);
                    println!("  scheme_tag           = {}", m.scheme_tag);
                    println!("  instance_id          = {}", m.instance_id);
                    println!("  current_snapshot_id  = {:?}", m.current_snapshot_id);
                    println!("  current_snapshot_seq = {}", m.current_snapshot_seq);
                    println!("  current_block_height = {}", m.current_marker);
                }
                None => println!(
                    "(no manifest at {}; data_dir is empty / fresh)",
                    data_dir.display()
                ),
            }
            Ok(())
        }
    }
}

/// The two flags `--config` does not refuse; each overrides its TOML key.
fn multi_options_from_config(
    path: &std::path::Path,
    ws_endpoint: Option<String>,
    metrics_public: bool,
) -> anyhow::Result<raven_railgun_cli::serve_production_multi::MultiServeOptions> {
    let mut opts = raven_railgun_cli::serve_production_multi::load_options_from_toml(path)?;
    if ws_endpoint.is_some() {
        opts.ws_endpoint = ws_endpoint;
    }
    if metrics_public {
        opts.metrics_public = Some(true);
    }
    Ok(opts)
}

fn parse_encoder_kind(
    encoder: &str,
    tree_number: u32,
    list_key: &str,
) -> anyhow::Result<raven_railgun_engine::pir_table::EncoderKind> {
    use raven_railgun_engine::pir_table::EncoderKind;
    match encoder {
        "per-leaf-bc" => Ok(EncoderKind::PerLeafBc { tree_number }),
        "per-leaf-path" => Ok(EncoderKind::PerLeafPath { tree_number }),
        "per-node" => Ok(EncoderKind::PerNode { tree_number }),
        "per-list-status" => Ok(EncoderKind::PerListStatus {
            list_key: parse_list_key(list_key)?,
        }),
        "per-list-path" => Ok(EncoderKind::PerListPath {
            list_key: parse_list_key(list_key)?,
        }),
        "per-list-path10" => Ok(EncoderKind::PerListPath10 {
            list_key: parse_list_key(list_key)?,
        }),
        "per-list-node" => Ok(EncoderKind::PerListNode {
            list_key: parse_list_key(list_key)?,
        }),
        other => anyhow::bail!(
            "unknown --encoder {other}; expected one of \
             per-leaf-bc | per-leaf-path | per-node | \
             per-list-status | per-list-path | per-list-path10 | per-list-node"
        ),
    }
}

fn parse_list_key(s: &str) -> anyhow::Result<[u8; 32]> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    if trimmed.len() != 64 {
        anyhow::bail!(
            "list_key must be 32 bytes hex-encoded (64 chars, got {})",
            trimmed.len()
        );
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let pair = trimmed
            .get(i * 2..i * 2 + 2)
            .ok_or_else(|| anyhow::anyhow!("list_key hex parse: out of range at byte {i}"))?;
        *slot = u8::from_str_radix(pair, 16)
            .map_err(|e| anyhow::anyhow!("list_key hex parse at byte {i}: {e}"))?;
    }
    Ok(out)
}

struct ServeOptions {
    bind: SocketAddr,
    token: String,
    max_concurrent_queries: usize,
    rate_limit_rps: u64,
    rate_limit_burst: u32,
    session_ttl_secs: u64,
    session_lru_cap: usize,
}

async fn serve_toy(opts: ServeOptions) -> anyhow::Result<()> {
    let app_state =
        raven_railgun_cli::toy_server::build_toy_state_with_overrides(toy_overrides(&opts))
            .map_err(anyhow::Error::msg)?;
    let router = raven_railgun_http::inspire_router(app_state)
        .map_err(|e| anyhow::anyhow!("inspire_router: {e}"))?;

    let listener = tokio::net::TcpListener::bind(opts.bind).await?;
    tracing::info!(
        addr = %opts.bind,
        max_concurrent_queries = opts.max_concurrent_queries,
        rate_limit_rps = opts.rate_limit_rps,
        rate_limit_burst = opts.rate_limit_burst,
        session_ttl_secs = opts.session_ttl_secs,
        session_lru_cap = opts.session_lru_cap,
        "raven-railgun listening"
    );
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(anyhow::Error::from)
}

fn toy_overrides(opts: &ServeOptions) -> raven_railgun_cli::toy_server::ToyServerOverrides {
    raven_railgun_cli::toy_server::ToyServerOverrides {
        token: opts.token.clone(),
        max_concurrent_queries: opts.max_concurrent_queries,
        rate_limit_rps: opts.rate_limit_rps,
        rate_limit_burst: opts.rate_limit_burst,
        session_ttl_secs: opts.session_ttl_secs,
        session_lru_cap: opts.session_lru_cap,
    }
}

struct BootstrapFromSubsquidOptions {
    rpc_pool_config: std::path::PathBuf,
    subsquid_url: String,
    data_dir_template: String,
    tree_numbers: Vec<u32>,
    checkpoint_depth: u64,
    chain_id: u64,
    scheme_tag: String,
    max_bootstrap_wall_mins: u64,
    railgun_proxy: String,
    contract_start_block: u64,
    boundary_repair_trigger_threshold: Option<usize>,
    chain_encoder_family: ChainEncoderFamily,
}

fn removed_bootstrap_entries(_: &str) -> Result<usize, String> {
    Err("--entries was removed; bootstrap cell rows are derived from the encoder".to_owned())
}

fn removed_bootstrap_entry_bytes(_: &str) -> Result<usize, String> {
    Err("--entry-bytes was removed; bootstrap row width is derived from the encoder".to_owned())
}

#[derive(Debug, Clone, Copy)]
#[allow(clippy::enum_variant_names)]
enum ChainEncoderFamily {
    PerLeafBc,
    PerLeafPath,
    PerNode,
}

impl ChainEncoderFamily {
    fn for_tree(self, tree_number: u32) -> raven_railgun_engine::pir_table::EncoderKind {
        use raven_railgun_engine::pir_table::EncoderKind;
        match self {
            Self::PerLeafBc => EncoderKind::PerLeafBc { tree_number },
            Self::PerLeafPath => EncoderKind::PerLeafPath { tree_number },
            Self::PerNode => EncoderKind::PerNode { tree_number },
        }
    }
}

fn parse_chain_encoder_family(s: &str) -> anyhow::Result<ChainEncoderFamily> {
    match s {
        "per-leaf-bc" => Ok(ChainEncoderFamily::PerLeafBc),
        "per-leaf-path" => Ok(ChainEncoderFamily::PerLeafPath),
        "per-node" => Ok(ChainEncoderFamily::PerNode),
        other => anyhow::bail!(
            "unknown --encoder {other}; expected one of \
             per-leaf-bc | per-leaf-path | per-node (chain-tree encoders)"
        ),
    }
}

async fn run_bootstrap_from_subsquid(opts: BootstrapFromSubsquidOptions) -> anyhow::Result<()> {
    use raven_railgun_cli::bootstrap_subsquid::{
        bootstrap_one_tree_with_carry, resolve_data_dir_template, BootstrapTreeConfig,
        ChainSourceOracle, StowawayCarry, SubsquidLeavesClient,
    };
    use raven_railgun_cli::rpc_pool_array_config::RpcEndpointArrayConfig;
    use raven_railgun_indexer::rpc_pool::PooledRpcChainSource;
    use std::sync::Arc;

    let pool_cfg = RpcEndpointArrayConfig::load_from_path(&opts.rpc_pool_config)
        .map_err(|e| anyhow::anyhow!("rpc_pool_config: {e}"))?;
    let pool = Arc::new(
        pool_cfg
            .build_pool()
            .map_err(|e| anyhow::anyhow!("build pool: {e}"))?,
    );
    let proxy_addr: alloy::primitives::Address = opts
        .railgun_proxy
        .parse()
        .map_err(|e| anyhow::anyhow!("railgun_proxy: {e}"))?;
    let chain_source: Arc<dyn raven_railgun_indexer::ChainSource> = Arc::new(
        PooledRpcChainSource::new(Arc::clone(&pool), proxy_addr, opts.chain_id),
    );
    let chain_oracle = ChainSourceOracle::new(Arc::clone(&chain_source));
    let leaves_src = SubsquidLeavesClient::new(opts.subsquid_url.clone())
        .map_err(|error| anyhow::anyhow!("--subsquid-url: {error}"))?;

    {
        use raven_railgun_cli::bootstrap_subsquid::ChainOracle as _;
        let head = chain_oracle
            .chain_head()
            .await
            .map_err(|e| anyhow::anyhow!("rpc-pool chain_head probe: {e}"))?;
        let probe_block = head.saturating_sub(opts.checkpoint_depth);
        chain_oracle
            .archival_probe(probe_block)
            .await
            .map_err(|e| anyhow::anyhow!("archival probe: {e}"))?;
        tracing::info!(head, probe_block, "archival probe ok; bootstrap proceeds");
    }

    let mut sorted_trees: Vec<u32> = opts.tree_numbers.clone();
    sorted_trees.sort_unstable();
    let mut carry: StowawayCarry = StowawayCarry::new();
    let mut tree_reports = Vec::new();
    for tree in &sorted_trees {
        let data_dir = resolve_data_dir_template(&opts.data_dir_template, *tree)
            .map_err(|e| anyhow::anyhow!("data_dir_template: {e}"))?;
        let encoder_kind = opts.chain_encoder_family.for_tree(*tree);
        let mut cfg = BootstrapTreeConfig {
            tree_number: *tree,
            checkpoint_depth: opts.checkpoint_depth,
            data_dir,
            instance_id: format!("commit-tree-{tree}"),
            scheme_tag: opts.scheme_tag.clone(),
            max_wall_mins: opts.max_bootstrap_wall_mins,
            contract_start_block: opts.contract_start_block,
            encoder_kind,
            ..BootstrapTreeConfig::default()
        };
        if let Some(threshold) = opts.boundary_repair_trigger_threshold {
            cfg.repair_trigger_threshold = threshold;
        }
        let report =
            bootstrap_one_tree_with_carry(&cfg, &leaves_src, &chain_oracle, &mut carry).await?;
        tracing::info!(
            tree = report.tree_number,
            checkpoint = report.checkpoint_block,
            leaves = report.leaves,
            wall_secs = report.wall_clock_secs,
            "bootstrap-from-subsquid: tree complete"
        );
        tree_reports.push(report);
    }
    if !carry.is_empty() {
        let leftover: Vec<u32> = carry.keys().copied().collect();
        tracing::warn!(
            leftover_target_trees = ?leftover,
            "bootstrap-from-subsquid: cross-tree carry residue (target trees not configured for bootstrap)"
        );
    }

    println!(
        "bootstrap-from-subsquid: {} tree(s) complete",
        tree_reports.len()
    );
    for r in &tree_reports {
        println!(
            "  tree={} checkpoint={} leaves={} pages={} wall={:.3}s",
            r.tree_number, r.checkpoint_block, r.leaves, r.subsquid_pages, r.wall_clock_secs
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, FromArgMatches};
    use std::io::Write;

    const LIST_KEY: &str = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";

    /// `serve-production` arguments the multi-instance path applies on top of the file.
    const APPLIED_BESIDE_CONFIG: [&str; 3] = ["config", "ws_endpoint", "metrics_public"];

    /// The binary's parser with the `RAVEN_RPC_URL` fallback detached, so an exported value
    /// cannot decide a parse here.
    fn parse(argv: &[&str]) -> Result<Cli, clap::Error> {
        let matches = Cli::command()
            .mut_subcommand("serve-production", |cmd| {
                cmd.mut_arg("rpc_url", |arg| arg.env(None))
            })
            .try_get_matches_from(argv)?;
        Cli::from_arg_matches(&matches)
    }

    /// Enumerated from the parser, hidden arguments included, so an argument added later
    /// without a conflict entry is caught here rather than parsed and dropped.
    #[test]
    fn every_serve_production_flag_the_config_path_does_not_apply_is_refused_beside_it() {
        let cli = Cli::command();
        let serve = cli
            .find_subcommand("serve-production")
            .expect("serve-production");
        let mut refused = Vec::new();
        let mut dropped = Vec::new();
        for arg in serve.get_arguments() {
            let id = arg.get_id().as_str();
            if APPLIED_BESIDE_CONFIG.contains(&id) {
                continue;
            }
            let Some(long) = arg.get_long() else {
                dropped.push(format!("{id}: no long flag to pass beside --config"));
                continue;
            };
            let flag = format!("--{long}");
            let value = arg
                .get_default_values()
                .first()
                .map_or_else(|| "1".to_owned(), |v| v.to_string_lossy().into_owned());
            let mut argv = vec![
                "raven-railgun",
                "serve-production",
                "--config",
                "/unread.toml",
                &flag,
            ];
            if arg.get_action().takes_values() {
                argv.push(&value);
            }
            match parse(&argv) {
                Err(err)
                    if err.kind() == clap::error::ErrorKind::ArgumentConflict
                        && err.to_string().contains(&flag) =>
                {
                    refused.push(id);
                }
                Err(err) => dropped.push(format!("{flag}: {err}")),
                Ok(_) => dropped.push(format!("{flag}: parsed beside --config")),
            }
        }
        assert!(dropped.is_empty(), "{}", dropped.join("\n"));
        for id in ["bind", "session_eviction_interval_secs"] {
            assert!(
                refused.contains(&id),
                "the enumeration lost {id}: {refused:?}"
            );
        }
        for id in APPLIED_BESIDE_CONFIG {
            assert!(
                serve.get_arguments().any(|arg| arg.get_id() == id),
                "{id} is exempt but no longer declared"
            );
        }
    }

    fn options_for(extra: &[&str]) -> raven_railgun_cli::serve_production_multi::MultiServeOptions {
        let data = tempfile::tempdir().expect("tempdir");
        let body = format!(
            r#"
[global]
bind = "127.0.0.1:0"
token = "config-override-test-token-padded-long"
chain_id = 1
mirror_endpoint = "http://127.0.0.1:1"

[[instance]]
id = "ppoi-status"
role = "live"
encoder = "per-list-status"
list_key = "{LIST_KEY}"
data_dir = "{}"
verification_mode = "upstream-asserted"
[instance.data_source]
kind = "mirror"
list_key = "{LIST_KEY}"
"#,
            data.path().join("ppoi-status").display()
        );
        // NamedTempFile is 0600, which the inline token requires.
        let mut file = tempfile::NamedTempFile::new().expect("tempfile");
        file.write_all(body.as_bytes()).expect("write config");
        let config = file.path().to_str().expect("utf-8 path");
        let argv: Vec<&str> = ["raven-railgun", "serve-production", "--config", config]
            .into_iter()
            .chain(extra.iter().copied())
            .collect();
        let Commands::ServeProduction {
            config: Some(path),
            ws_endpoint,
            metrics_public,
            ..
        } = parse(&argv).expect("parse").command
        else {
            panic!("parsed as another command");
        };
        multi_options_from_config(&path, ws_endpoint, metrics_public).expect("load config")
    }

    /// Allowed beside `--config`, so each must land in the options the boot runs on.
    #[test]
    fn the_flags_allowed_beside_config_reach_the_loaded_options() {
        let bare = options_for(&[]);
        assert_eq!(
            (bare.ws_endpoint.as_deref(), bare.metrics_public),
            (None, None),
            "the fixture must not set either key itself"
        );
        let set = options_for(&["--ws-endpoint", "ws://127.0.0.1:1", "--metrics-public"]);
        assert_eq!(set.ws_endpoint.as_deref(), Some("ws://127.0.0.1:1"));
        assert_eq!(set.metrics_public, Some(true));
    }
}
