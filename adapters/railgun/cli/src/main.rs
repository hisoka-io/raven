//! Raven Railgun operator CLI.

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]
#![allow(
    missing_docs,
    clippy::large_enum_variant,
    clippy::print_stdout,
    clippy::print_stderr
)]

use clap::{Parser, Subcommand};

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
    /// Serve the instances a multi-instance TOML config declares.
    ServeProduction {
        /// Multi-instance TOML config file.
        #[arg(long)]
        config: std::path::PathBuf,
        /// WebSocket RPC URL; overrides the TOML `ws_endpoint`.
        #[arg(long)]
        ws_endpoint: Option<String>,
        /// Expose `/metrics` without bearer auth (default-deny); overrides the TOML key when set.
        /// Affects auth only; `/metrics` always bypasses the per-IP rate limiter.
        #[arg(long, default_value_t = false)]
        metrics_public: bool,
    },
    /// Dump on-disk snapshot metadata for a given data_dir.
    Dump {
        /// On-disk data directory for the instance.
        #[arg(long)]
        data_dir: std::path::PathBuf,
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::ServeProduction {
            config,
            ws_endpoint,
            metrics_public,
        } => {
            let opts = multi_options_from_config(&config, ws_endpoint, metrics_public)?;
            return_freed_heap_periodically();
            raven_railgun_cli::serve_production_multi::run(opts).await?;
            // A final commit the stop budget abandoned still occupies a runtime worker, and
            // dropping the runtime would wait for it past the budget.
            std::process::exit(0)
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
                    println!(
                        "  current_block_height = {} (resume floor: the last chain block whose \
                         leaves fully applied; mirror rows carry no block, so 0 on a \
                         mirror-fed instance)",
                        m.current_marker
                    );
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

/// glibc keeps freed heap pages resident: the buffers a boot decodes through, every commit's
/// re-encode and every query's scratch would otherwise hold resident memory near twice the live
/// heap for the life of the process. A timer returns them whatever freed them.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn return_freed_heap_periodically() {
    const INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
    let spawned = std::thread::Builder::new()
        .name("heap-return".to_owned())
        .spawn(|| loop {
            std::thread::sleep(INTERVAL);
            // SAFETY: malloc_trim takes no pointers; it only releases free pages glibc owns.
            #[allow(unsafe_code)]
            unsafe {
                libc::malloc_trim(0);
            }
        });
    if let Err(error) = spawned {
        tracing::warn!(%error, "freed heap will not be returned to the OS");
    }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn return_freed_heap_periodically() {}

/// Each flag beside `--config` overrides its TOML key.
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
    use clap::CommandFactory;
    use std::io::Write;

    const LIST_KEY: &str = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";

    /// Everything `serve-production` accepts: the config and the two keys it overrides.
    const SERVE_PRODUCTION_ARGS: [&str; 3] = ["config", "ws_endpoint", "metrics_public"];

    fn parse(argv: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(argv)
    }

    /// Enumerated from the parser, hidden arguments included, so a flag added later is named
    /// here rather than parsed beside a config that already carries its key.
    #[test]
    fn serve_production_takes_a_config_and_only_the_keys_it_overrides() {
        let cli = Cli::command();
        let serve = cli
            .find_subcommand("serve-production")
            .expect("serve-production");
        let declared: Vec<&str> = serve
            .get_arguments()
            .map(|arg| arg.get_id().as_str())
            .filter(|id| !["help", "version"].contains(id))
            .collect();
        assert_eq!(declared, SERVE_PRODUCTION_ARGS);
        let missing = parse(&["raven-railgun", "serve-production"])
            .expect_err("a boot with no config must be refused");
        assert_eq!(
            missing.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        for flag in ["--rpc-url", "--data-dir", "--token", "--bind", "--encoder"] {
            let err = parse(&[
                "raven-railgun",
                "serve-production",
                "--config",
                "/unread.toml",
                flag,
                "1",
            ])
            .expect_err("a single-instance flag must be refused");
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::UnknownArgument,
                "{flag}: {err}"
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
id = "ppoi-paths-0"
role = "live"
encoder = "per-list-path10"
list_key = "{LIST_KEY}"
data_dir = "{}"
[instance.data_source]
kind = "mirror"
list_key = "{LIST_KEY}"
block = 0
"#,
            data.path().join("ppoi-paths-0").display()
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
            config: path,
            ws_endpoint,
            metrics_public,
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
