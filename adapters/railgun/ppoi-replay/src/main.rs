//! Serves a PPOI list capture folder over the upstream node's JSON-RPC methods.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use raven_railgun_ppoi_replay::{bind, serve, Capture, Replay, ReplayError};

#[derive(Parser, Debug)]
#[command(
    name = "raven-railgun-ppoi-replay",
    about = "Serve a recorded Railgun PPOI list capture over the upstream node's JSON-RPC methods."
)]
struct Cli {
    /// Capture folder: events.bin, manifest.json, node-status-end.json, and noncanonical.jsonl
    /// when the list has non-canonical rows.
    #[arg(long, env = "PPOI_REPLAY_CAPTURE")]
    capture: PathBuf,
    /// Address to serve on.
    #[arg(long, default_value = "127.0.0.1:8088")]
    bind: SocketAddr,
    /// Rows served at start; the whole capture when unset.
    #[arg(long)]
    rows: Option<usize>,
    /// Rows added every `--grow-interval-secs` until the capture is served whole.
    #[arg(long, default_value_t = 0)]
    grow_rows: usize,
    /// Seconds between growth steps.
    #[arg(long, default_value_t = 30)]
    grow_interval_secs: u64,
    /// A recorded `ppoi_node_status` response to serve instead of the folder's
    /// node-status-end.json.
    #[arg(long)]
    node_status: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "raven-railgun-ppoi-replay stopped");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), ReplayError> {
    let (capture, scope) = Capture::load_dir(&cli.capture)?;
    let status_path = cli
        .node_status
        .unwrap_or_else(|| cli.capture.join("node-status-end.json"));
    let status = std::fs::read(&status_path).map_err(|source| ReplayError::Io {
        path: status_path.display().to_string(),
        source,
    })?;
    let total = capture.rows().len();
    let replay = Arc::new(Replay::new(
        capture,
        scope,
        &status,
        cli.rows.unwrap_or(total),
    )?);
    let (listener, local) = bind(cli.bind).await?;
    tracing::info!(
        %local,
        capture = %cli.capture.display(),
        served = replay.served_rows(),
        total,
        "serving a recorded PPOI list"
    );
    if cli.grow_rows > 0 {
        let grower = Arc::clone(&replay);
        let every = Duration::from_secs(cli.grow_interval_secs.max(1));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.tick().await;
            while grower.served_rows() < total {
                tick.tick().await;
                let next = grower
                    .served_rows()
                    .saturating_add(cli.grow_rows)
                    .min(total);
                match grower.grow_to(next) {
                    Ok(()) => tracing::info!(served = next, total, "list grew"),
                    Err(error) => tracing::warn!(%error, "growth step refused"),
                }
            }
        });
    }
    serve(listener, replay).await
}
