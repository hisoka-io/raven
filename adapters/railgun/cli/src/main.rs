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
        /// Optional WebSocket RPC URL (e.g. `wss://...`). When set with
        /// `--config`, overrides the TOML's `ws_endpoint` global key so
        /// the chain source wraps a `WsChainSource` in
        /// `AutoFallbackChainSource` over the configured pool / single-RPC
        /// fallback. Multi-instance only: rejected at runtime when
        /// `--config` is not provided (the single-instance path uses
        /// `RpcChainSource` directly without WS).
        #[arg(long)]
        ws_endpoint: Option<String>,
        /// Expose `/metrics` without bearer auth. Default-deny posture
        /// (off): Prometheus scrapers must present the same bearer
        /// credential as wallet clients. Set this flag to opt-in for a
        /// scrape-only Prometheus instance with no shared secret.
        /// `/metrics` always bypasses the per-IP rate limiter; this
        /// flag controls only the auth requirement. Honored on both
        /// the `--config` (multi-instance) and single-instance paths
        /// via the TOML/CLI -> HttpConfig override plumbing.
        #[arg(long, default_value_t = false)]
        metrics_public: bool,
        /// Periodic heartbeat session-eviction interval (seconds).
        /// `0` disables. Default 3600. Symmetric with multi-instance:
        /// the runtime rebuilds the in-memory `ServerSessionStore` from
        /// scratch each tick so resident memory is bounded under
        /// sustained bearer churn at the cost of dropping live
        /// sessions once per interval.
        #[arg(long, default_value_t = 3600)]
        session_eviction_interval_secs: u64,
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
        /// Retain only the N newest `*.tar.zst` tarballs in the output's
        /// parent directory after a successful write (cron-friendly).
        /// `0` disables.
        #[arg(long, default_value_t = 3)]
        keep_snapshots: usize,
    },
    /// Standalone retention pass: trim the snapshot drop-zone to the N
    /// newest tarballs. Cron / systemd-timer friendly; idempotent.
    PruneSnapshots {
        /// Directory containing `*.tar.zst` export tarballs.
        #[arg(long)]
        data_dir: std::path::PathBuf,
        /// Retention floor (N newest tarballs). `0` disables.
        #[arg(long, default_value_t = 3)]
        keep: usize,
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
    /// Bootstrap on-disk instance state from a Subsquid checkpoint:
    /// page through `commitments` ordered by `treePosition_ASC`, build
    /// a local IMT, then verify against the chain ABI (live tree:
    /// byte-identity vs `merkleRoot()`; static tree: membership via
    /// `rootHistory(tree, root)`) and drop an initial snapshot stamped
    /// at the agreed checkpoint block. The chain oracle is mandatory;
    /// archival state at `chain_head - checkpoint_depth` is required
    /// (probe surfaces `NoArchivalRpc` early if the operator's pool
    /// has no archival endpoint). PPOI list bootstrap pulls upstream
    /// `validatedMerkleroot` events from Railway and asserts
    /// byte-identity against the local per-list IMT.
    BootstrapFromSubsquid {
        /// Per-endpoint heterogeneous rpc-pool TOML (B2 shape).
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
        /// Comma-separated PPOI list keys to bootstrap (hex, 64 chars
        /// each, optional `0x` prefix).
        #[arg(
            long,
            default_value = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88",
            value_delimiter = ','
        )]
        ppoi_list_keys: Vec<String>,
        /// PPOI per-list data_dir template; must contain `{LIST_KEY}`.
        #[arg(long)]
        ppoi_list_data_dir_template: Option<String>,
        /// Upstream Railway PPOI base URL(s). Repeatable; comma-
        /// separated values are also accepted. The list is walked in
        /// priority order with an 8-second per-URL timeout. Defaults
        /// to the three known Railway proxies; only the first
        /// reachable one is used.
        #[arg(
            long,
            default_values_t = raven_railgun_cli::bootstrap_subsquid::DEFAULT_RAILWAY_BASES
                .iter()
                .map(|s| (*s).to_owned())
                .collect::<Vec<String>>(),
            value_delimiter = ','
        )]
        ppoi_endpoint: Vec<String>,
        /// PPOI bootstrap resilience policy. `strict` (default)
        /// hard-stops on upstream unreachability; `skip-on-unreachable`
        /// emits a loud warn and seeds an EMPTY per-list IMT,
        /// signalling the upstream-signature gap.
        #[arg(long, default_value = "strict")]
        ppoi_bootstrap_mode: String,
        /// PPOI events source. `railway` (default) pulls signed
        /// events from the upstream Railway PPOI aggregator;
        /// `chainalysis-oracle` derives the OFAC list locally from
        /// the on-chain Chainalysis sanctions oracle.
        #[arg(long, default_value = "railway")]
        ppoi_source: String,
        /// Chainalysis OFAC oracle address (used when
        /// `--ppoi-source chainalysis-oracle`). Defaults to the
        /// canonical mainnet deployment.
        #[arg(
            long,
            default_value = raven_railgun_cli::bootstrap_chainalysis::CHAINALYSIS_ORACLE_MAINNET
        )]
        chainalysis_oracle: String,
        /// First block to scan for Chainalysis sanctions-added
        /// events. Defaults to the oracle's deployment block.
        #[arg(
            long,
            default_value_t = raven_railgun_cli::bootstrap_chainalysis::CHAINALYSIS_ORACLE_FIRST_BLOCK
        )]
        chainalysis_block_start: u64,
        /// Chain id for the PPOI endpoint path component.
        #[arg(long, default_value_t = 1)]
        chain_id: u64,
        /// Railgun PPOI chain-type path component (`0` = EVM).
        #[arg(long, default_value_t = 0)]
        chain_type: u32,
        /// Scheme tag for the persisted manifest.
        #[arg(
            long,
            default_value = "raven-inspire-twopacking-inspiring-wp3-cache-session"
        )]
        scheme_tag: String,
        /// PIR cell entry count (production cell default).
        #[arg(long, default_value_t = raven_railgun_cli::serve_production::DEFAULT_PRODUCTION_ENTRIES)]
        entries: usize,
        /// PIR cell entry size in bytes.
        #[arg(long, default_value_t = raven_railgun_cli::serve_production::DEFAULT_PRODUCTION_ENTRY_BYTES)]
        entry_bytes: usize,
        /// Strict 2/3-oracle byte-identity gate.
        #[arg(long, default_value_t = true)]
        strict_oracle_byte_identity: bool,
        /// Wall-clock cap for the entire bootstrap loop.
        #[arg(long, default_value_t = 30)]
        max_bootstrap_wall_mins: u64,
        /// Hex-encoded Railgun proxy contract address (used for the
        /// chain-side oracle). Defaults to mainnet proxy.
        #[arg(long, default_value = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9")]
        railgun_proxy: String,
        /// Per-chain-tree encoder family stamped into each tree's
        /// manifest `encoder_label`. One of `per-leaf-bc`,
        /// `per-leaf-path`, or `per-node`. Default `per-node` matches
        /// the production lock; the orchestrator binds the per-tree
        /// `tree_number` per iteration so a single CLI flag covers
        /// every bootstrapped tree.
        #[arg(long, default_value = "per-node")]
        encoder: String,
        /// PPOI per-list status encoder family. One of
        /// `per-list-status`, `per-list-path`, or `per-list-node`.
        #[arg(long, default_value = "per-list-status")]
        ppoi_status_encoder: String,
        /// PPOI per-list path encoder family. One of
        /// `per-list-status`, `per-list-path`, or `per-list-node`.
        #[arg(long, default_value = "per-list-node")]
        ppoi_path_encoder: String,
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
            ws_endpoint,
            metrics_public,
            session_eviction_interval_secs,
        } => {
            if let Some(path) = config {
                let mut opts =
                    raven_railgun_cli::serve_production_multi::load_options_from_toml(&path)?;
                if ws_endpoint.is_some() {
                    opts.ws_endpoint = ws_endpoint;
                }
                if metrics_public {
                    opts.metrics_public = Some(true);
                }
                return raven_railgun_cli::serve_production_multi::run(opts).await;
            }
            if ws_endpoint.is_some() {
                anyhow::bail!(
                    "--ws-endpoint is multi-instance only; pass --config <toml> alongside it. \
                     The single-instance path uses RpcChainSource directly without WS."
                );
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
                session_eviction_interval_secs,
                metrics_public,
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
                include_current_wal,
                keep_snapshots,
            };
            raven_railgun_cli::snapshot_port::run_export(opts)
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
        Commands::BootstrapFromSubsquid {
            rpc_pool_config,
            subsquid_url,
            data_dir_template,
            tree_numbers,
            checkpoint_depth,
            ppoi_list_keys,
            ppoi_list_data_dir_template,
            ppoi_endpoint,
            ppoi_bootstrap_mode,
            ppoi_source,
            chainalysis_oracle,
            chainalysis_block_start,
            chain_id,
            chain_type,
            scheme_tag,
            entries,
            entry_bytes,
            strict_oracle_byte_identity,
            max_bootstrap_wall_mins,
            railgun_proxy,
            encoder,
            ppoi_status_encoder,
            ppoi_path_encoder,
        } => {
            let chain_encoder_family = parse_chain_encoder_family(&encoder)?;
            let ppoi_status_family = parse_ppoi_encoder_family(&ppoi_status_encoder)
                .map_err(|e| anyhow::anyhow!("--ppoi-status-encoder: {e}"))?;
            let ppoi_path_family = parse_ppoi_encoder_family(&ppoi_path_encoder)
                .map_err(|e| anyhow::anyhow!("--ppoi-path-encoder: {e}"))?;
            let parsed_mode = raven_railgun_cli::bootstrap_subsquid::PpoiBootstrapMode::parse_cli(
                &ppoi_bootstrap_mode,
            )
            .map_err(|e| anyhow::anyhow!("--ppoi-bootstrap-mode: {e}"))?;
            let parsed_source = parse_ppoi_source(&ppoi_source)
                .map_err(|e| anyhow::anyhow!("--ppoi-source: {e}"))?;
            let parsed_oracle = raven_railgun_cli::bootstrap_chainalysis::parse_chainalysis_oracle(
                &chainalysis_oracle,
            )
            .map_err(|e| anyhow::anyhow!("--chainalysis-oracle: {e}"))?;
            let opts = BootstrapFromSubsquidOptions {
                rpc_pool_config,
                subsquid_url,
                data_dir_template,
                tree_numbers,
                checkpoint_depth,
                ppoi_list_keys,
                ppoi_list_data_dir_template,
                ppoi_endpoint,
                ppoi_bootstrap_mode: parsed_mode,
                ppoi_source: parsed_source,
                chainalysis_oracle: parsed_oracle,
                chainalysis_block_start,
                chain_id,
                chain_type,
                scheme_tag,
                entries,
                entry_bytes,
                strict_oracle_byte_identity,
                max_bootstrap_wall_mins,
                railgun_proxy,
                chain_encoder_family,
                ppoi_status_family,
                ppoi_path_family,
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

struct BootstrapFromSubsquidOptions {
    rpc_pool_config: std::path::PathBuf,
    subsquid_url: String,
    data_dir_template: String,
    tree_numbers: Vec<u32>,
    checkpoint_depth: u64,
    ppoi_list_keys: Vec<String>,
    ppoi_list_data_dir_template: Option<String>,
    ppoi_endpoint: Vec<String>,
    ppoi_bootstrap_mode: raven_railgun_cli::bootstrap_subsquid::PpoiBootstrapMode,
    ppoi_source: PpoiSourceKind,
    chainalysis_oracle: alloy::primitives::Address,
    chainalysis_block_start: u64,
    chain_id: u64,
    chain_type: u32,
    scheme_tag: String,
    entries: usize,
    entry_bytes: usize,
    strict_oracle_byte_identity: bool,
    max_bootstrap_wall_mins: u64,
    railgun_proxy: String,
    chain_encoder_family: ChainEncoderFamily,
    ppoi_status_family: PpoiEncoderFamily,
    ppoi_path_family: PpoiEncoderFamily,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PpoiSourceKind {
    Railway,
    ChainalysisOracle,
}

fn parse_ppoi_source(s: &str) -> Result<PpoiSourceKind, String> {
    match s {
        "railway" => Ok(PpoiSourceKind::Railway),
        "chainalysis-oracle" => Ok(PpoiSourceKind::ChainalysisOracle),
        other => Err(format!(
            "unknown ppoi-source {other}; expected one of railway | chainalysis-oracle"
        )),
    }
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
            Self::PerLeafBc => EncoderKind::PerLeafBc,
            Self::PerLeafPath => EncoderKind::PerLeafPath { tree_number },
            Self::PerNode => EncoderKind::PerNode { tree_number },
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(clippy::enum_variant_names)]
enum PpoiEncoderFamily {
    PerListStatus,
    PerListPath,
    PerListNode,
}

impl PpoiEncoderFamily {
    fn label(self) -> &'static str {
        use raven_railgun_engine::pir_table::labels;
        match self {
            Self::PerListStatus => labels::PER_LIST_STATUS,
            Self::PerListPath => labels::PER_LIST_PATH,
            Self::PerListNode => labels::PER_LIST_NODE,
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

fn parse_ppoi_encoder_family(s: &str) -> anyhow::Result<PpoiEncoderFamily> {
    match s {
        "per-list-status" => Ok(PpoiEncoderFamily::PerListStatus),
        "per-list-path" => Ok(PpoiEncoderFamily::PerListPath),
        "per-list-node" => Ok(PpoiEncoderFamily::PerListNode),
        other => anyhow::bail!(
            "unknown ppoi encoder {other}; expected one of \
             per-list-status | per-list-path | per-list-node"
        ),
    }
}

#[allow(clippy::too_many_lines)]
async fn run_bootstrap_from_subsquid(opts: BootstrapFromSubsquidOptions) -> anyhow::Result<()> {
    use raven_railgun_cli::bootstrap_subsquid::{
        bootstrap_one_list_with_mode, bootstrap_one_tree_with_carry, resolve_data_dir_template,
        resolve_ppoi_data_dir, BootstrapTreeConfig, ChainSourceOracle, RailwayPpoiClient,
        StowawayCarry, SubsquidLeavesClient,
    };
    use raven_railgun_cli::rpc_pool_array_config::RpcEndpointArrayConfig;
    use raven_railgun_indexer::rpc_pool::PooledRpcChainSource;
    use std::sync::Arc;

    if !opts.strict_oracle_byte_identity {
        anyhow::bail!(
            "--strict-oracle-byte-identity false is not supported in V1; the oracle gate is mandatory"
        );
    }
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
    let leaves_src = SubsquidLeavesClient::new(opts.subsquid_url.clone());

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
        let cfg = BootstrapTreeConfig {
            tree_number: *tree,
            checkpoint_depth: opts.checkpoint_depth,
            data_dir,
            instance_id: format!("commit-tree-{tree}"),
            scheme_tag: opts.scheme_tag.clone(),
            entries: opts.entries,
            entry_bytes: opts.entry_bytes,
            max_wall_mins: opts.max_bootstrap_wall_mins,
            encoder_kind,
            ..BootstrapTreeConfig::default()
        };
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

    if let Some(template) = &opts.ppoi_list_data_dir_template {
        match opts.ppoi_source {
            PpoiSourceKind::Railway => {
                let ppoi = RailwayPpoiClient::new_multi(
                    opts.ppoi_endpoint.clone(),
                    opts.chain_type,
                    opts.chain_id,
                )
                .map_err(|e| anyhow::anyhow!("--ppoi-endpoint: {e}"))?;
                let bases_for_log: Vec<String> = ppoi.bases().to_vec();
                for list_hex in &opts.ppoi_list_keys {
                    let key =
                        parse_list_key(list_hex).map_err(|e| anyhow::anyhow!("list_key: {e}"))?;
                    let _data_dir = resolve_ppoi_data_dir(template, key)
                        .map_err(|e| anyhow::anyhow!("ppoi_data_dir: {e}"))?;
                    let report = bootstrap_one_list_with_mode(
                        key,
                        &ppoi,
                        template,
                        opts.ppoi_bootstrap_mode,
                        &bases_for_log,
                    )
                    .await?;
                    tracing::info!(
                        events = report.events,
                        ppoi_source = "railway",
                        ppoi_status_encoder = opts.ppoi_status_family.label(),
                        ppoi_path_encoder = opts.ppoi_path_family.label(),
                        "bootstrap-from-subsquid: PPOI list complete"
                    );
                }
            }
            PpoiSourceKind::ChainalysisOracle => {
                use raven_railgun_cli::bootstrap_chainalysis::ChainalysisOnChainOracleSource;
                let chainalysis = ChainalysisOnChainOracleSource::new_live(
                    Arc::clone(&pool),
                    opts.chainalysis_oracle,
                    opts.chainalysis_block_start,
                    None,
                );
                let tried_log = vec![format!(
                    "chainalysis-oracle@{:#x} from_block={}",
                    opts.chainalysis_oracle, opts.chainalysis_block_start
                )];
                for list_hex in &opts.ppoi_list_keys {
                    let key =
                        parse_list_key(list_hex).map_err(|e| anyhow::anyhow!("list_key: {e}"))?;
                    let _data_dir = resolve_ppoi_data_dir(template, key)
                        .map_err(|e| anyhow::anyhow!("ppoi_data_dir: {e}"))?;
                    let report = bootstrap_one_list_with_mode(
                        key,
                        &chainalysis,
                        template,
                        opts.ppoi_bootstrap_mode,
                        &tried_log,
                    )
                    .await?;
                    tracing::info!(
                        events = report.events,
                        ppoi_source = "chainalysis-oracle",
                        ppoi_status_encoder = opts.ppoi_status_family.label(),
                        ppoi_path_encoder = opts.ppoi_path_family.label(),
                        "bootstrap-from-subsquid: PPOI list complete"
                    );
                }
            }
        }
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
