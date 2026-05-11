//! Binary entry point for the synthetic mock PPOI service.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use raven_railgun_mock_ppoi::{
    list_key_from_hex, load_blocked_csv, seed_from_hex, serve, AppState, Corpus, CorpusConfig,
    DEFAULT_CORPUS_SEED_HEX, DEFAULT_CORPUS_SIZE, DEFAULT_LIST_KEY_HEX, SYNTHETIC_BANNER,
};

#[derive(Parser, Debug)]
#[command(
    name = "raven-railgun-mock-ppoi",
    about = "SYNTHETIC PPOI surface impersonator. Demo-only; never deploy to production."
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Bind a TCP socket and serve the synthetic PPOI surface.
    Serve {
        /// Address to bind for incoming HTTP traffic.
        #[arg(long, default_value = "0.0.0.0:8088")]
        bind: SocketAddr,
        /// 32-byte list key (lowercase hex, no 0x prefix). Defaults to
        /// the production OFAC list id.
        #[arg(long, default_value = DEFAULT_LIST_KEY_HEX)]
        list_key: String,
        /// Number of synthetic blinded commitments to generate.
        #[arg(long, default_value_t = DEFAULT_CORPUS_SIZE)]
        corpus_size: u32,
        /// 32-byte deterministic seed (lowercase hex, no 0x prefix).
        #[arg(long, default_value = DEFAULT_CORPUS_SEED_HEX)]
        corpus_seed: String,
        /// Optional path to a newline-delimited CSV of blinded
        /// commitments to flag as ShieldBlocked. One BC per line; lines
        /// starting with `#` are comments.
        #[arg(long)]
        blocked_bcs_csv: Option<PathBuf>,
    },
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = %err, "raven-railgun-mock-ppoi exited with error");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match cli.command {
        Cmd::Serve {
            bind,
            list_key,
            corpus_size,
            corpus_seed,
            blocked_bcs_csv,
        } => {
            tracing::warn!("{SYNTHETIC_BANNER}");
            let list_key_bytes = list_key_from_hex(&list_key)?.0;
            let seed = seed_from_hex(&corpus_seed)?;
            let blocked = match blocked_bcs_csv {
                Some(path) => {
                    tracing::info!(
                        path = %path.display(),
                        "loading blocked-bc CSV overrides"
                    );
                    load_blocked_csv(&path)?
                }
                None => Vec::new(),
            };
            let blocked_count = blocked.len();
            let corpus = Corpus::generate(CorpusConfig {
                list_key: list_key_bytes,
                seed,
                size: corpus_size,
                blocked,
            })?;
            tracing::info!(
                bind = %bind,
                list_key = %list_key,
                corpus_size = corpus.len(),
                blocked = blocked_count,
                "mock PPOI corpus ready"
            );
            let state = AppState::new(corpus);
            serve(bind, state).await?;
        }
    }
    Ok(())
}
