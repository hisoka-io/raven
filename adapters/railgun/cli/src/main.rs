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

/// Operator-CLI HTTP timeout for one-shot status requests. 30s matches the
/// indexer's `MAX_RPC_TOTAL_ELAPSED_SECS` posture and the
/// `SUBSQUID_REQUEST_TIMEOUT` precedent, preventing indefinite hangs on a
/// stalled server.
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
        /// Sticky-session TTL in seconds.
        #[arg(long, default_value_t = 3600)]
        session_ttl_secs: u64,
        /// Sticky-session LRU cap.
        #[arg(long, default_value_t = 10_000)]
        session_lru_cap: usize,
    },
    /// Boot the production HTTP server against a real Ethereum RPC + upstream PPOI aggregator.
    ServeProduction {
        /// Multi-instance TOML config file; when set, all single-instance flags are ignored.
        #[arg(long, conflicts_with_all = [
            "rpc_url", "data_dir", "instance_id", "encoder",
            "list_key", "tree_number", "entries", "entry_bytes",
            "respond_timeout_secs", "max_concurrent_queries",
            "railgun_proxy", "chain_id", "start_block", "mirror_endpoint",
            "token", "bind",
        ])]
        config: Option<std::path::PathBuf>,
        /// Local address to bind the HTTP server.
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: SocketAddr,
        /// Bearer token for Authorization header.
        #[arg(long, env = "RAVEN_BEARER_TOKEN", required_unless_present = "config")]
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
        #[arg(long, default_value = "https://poi.us.proxy.railwayapi.xyz")]
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
        /// PIR cell entry count.
        #[arg(long, default_value_t = raven_railgun_cli::serve_production::DEFAULT_PRODUCTION_ENTRIES)]
        entries: usize,
        /// PIR cell record width in bytes.
        #[arg(long, default_value_t = raven_railgun_cli::serve_production::DEFAULT_PRODUCTION_ENTRY_BYTES)]
        entry_bytes: usize,
        /// Per-instance encoder label (per-leaf-bc, per-leaf-path, per-node, per-list-status, per-list-path).
        #[arg(long, default_value = "per-leaf-bc")]
        encoder: String,
        /// Tree number for chain encoders (ignored for per-leaf-bc and per-list-* variants).
        #[arg(long, default_value_t = 0)]
        tree_number: u32,
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
        /// Capture `wal/current.log` in addition to archived WAL segments.
        #[arg(long, default_value_t = false)]
        include_current_wal: bool,
    },
    /// Restore an export tarball into `--data-dir`, verifying checksums before any disk write.
    ImportSnapshot {
        /// Tarball produced by `export-snapshot`.
        #[arg(long)]
        input: std::path::PathBuf,
        /// Destination root for the unpacked instance data_dirs.
        #[arg(long)]
        data_dir: std::path::PathBuf,
        /// Legacy alias: when set without `--verifying-key`, the import refuses to proceed.
        #[arg(long)]
        verify_sig: bool,
        /// Path to a 32-byte raw or 64-char hex Ed25519 verifying key (required unless `--unsafe-no-verify`).
        #[arg(long)]
        verifying_key: Option<std::path::PathBuf>,
        /// Bypass Ed25519 verification (prints a warning; use only for unsigned test fixtures).
        #[arg(long, default_value_t = false, conflicts_with = "verifying_key")]
        unsafe_no_verify: bool,
        /// Permit overwriting an existing populated data root (backs it up first).
        #[arg(long, default_value_t = false)]
        allow_overwrite: bool,
    },
    /// Re-encode an on-disk instance to a new encoder (server must be stopped first).
    MigrateEncoder {
        /// On-disk data directory for the instance to migrate.
        #[arg(long)]
        data_dir: std::path::PathBuf,
        /// Target encoder label (per-leaf-bc, per-leaf-path, per-node, per-list-status, per-list-path, per-list-node).
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
        } => {
            if let Some(path) = config {
                let opts =
                    raven_railgun_cli::serve_production_multi::load_options_from_toml(&path)?;
                return raven_railgun_cli::serve_production_multi::run(opts).await;
            }
            let encoder_kind = parse_encoder_kind(&encoder, tree_number, &list_key)?;
            let token =
                token.ok_or_else(|| anyhow::anyhow!("--token required when --config not set"))?;
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
            include_current_wal,
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
                include_current_wal,
            };
            raven_railgun_cli::snapshot_port::run_export(opts)
        }
        Commands::ImportSnapshot {
            input,
            data_dir,
            verify_sig,
            verifying_key,
            unsafe_no_verify,
            allow_overwrite,
        } => {
            if verify_sig && verifying_key.is_none() {
                anyhow::bail!(
                    "--verify-sig requires --verifying-key; pass --verifying-key <path> \
                     or use --unsafe-no-verify to opt out (not recommended)"
                );
            }
            if unsafe_no_verify && verifying_key.is_some() {
                anyhow::bail!("--unsafe-no-verify and --verifying-key are mutually exclusive");
            }
            if verifying_key.is_none() && !unsafe_no_verify {
                anyhow::bail!(
                    "import-snapshot requires Ed25519 verification by default: pass \
                     --verifying-key <path>, or explicitly opt out with \
                     --unsafe-no-verify (an attacker who replaces the tarball can \
                     swap your entire data_dir)"
                );
            }
            if unsafe_no_verify {
                eprintln!(
                    "WARNING: --unsafe-no-verify bypasses Ed25519 signature \
                     verification on import. The tarball contents WILL replace \
                     your data_dir without authentication. Only use this for \
                     unsigned test fixtures."
                );
            }
            let opts = raven_railgun_cli::snapshot_port::ImportOptions {
                input,
                data_dir,
                verifying_key,
                allow_overwrite,
                unsafe_no_verify,
            };
            raven_railgun_cli::snapshot_port::run_import(opts)
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
                    println!("  current_block_height = {}", m.current_block_height);
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

fn parse_encoder_kind(
    encoder: &str,
    tree_number: u32,
    list_key: &str,
) -> anyhow::Result<raven_railgun_engine::pir_table::EncoderKind> {
    use raven_railgun_engine::pir_table::EncoderKind;
    match encoder {
        "per-leaf-bc" => Ok(EncoderKind::PerLeafBc),
        "per-leaf-path" => Ok(EncoderKind::PerLeafPath { tree_number }),
        "per-node" => Ok(EncoderKind::PerNode { tree_number }),
        "per-list-status" => Ok(EncoderKind::PerListStatus {
            list_key: parse_list_key(list_key)?,
        }),
        "per-list-path" => Ok(EncoderKind::PerListPath {
            list_key: parse_list_key(list_key)?,
        }),
        "per-list-node" => Ok(EncoderKind::PerListNode {
            list_key: parse_list_key(list_key)?,
        }),
        other => anyhow::bail!(
            "unknown --encoder {other}; expected one of \
             per-leaf-bc | per-leaf-path | per-node | \
             per-list-status | per-list-path | per-list-node"
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
