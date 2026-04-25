mod config;
mod source;
mod subgraph;
mod types;

use std::process::ExitCode;

use tokio::signal;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::source::{CommitmentSource, SourceError, SubgraphSource};
use crate::types::{ScanCursor, TreeStatus};

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!("config error: {e}");
            return ExitCode::from(2);
        }
    };

    let http = match reqwest::Client::builder().build() {
        Ok(c) => c,
        Err(e) => {
            error!("failed to build http client: {e}");
            return ExitCode::from(2);
        }
    };

    let (source, status) = match SubgraphSource::new(cfg.subgraph_url.clone(), http).await {
        Ok(pair) => pair,
        Err(e) => {
            error!("startup discovery failed: {e}");
            return ExitCode::from(1);
        }
    };

    print_banner(&cfg, &status);

    let mut cursor = ScanCursor::empty();

    loop {
        tokio::select! {
            biased;
            _ = signal::ctrl_c() => {
                info!("ctrl-c received, shutting down");
                return ExitCode::SUCCESS;
            }
            res = source.poll_once(cursor) => {
                match res {
                    Ok((next, batch)) => {
                        for rec in &batch {
                            println!("{rec}");
                        }
                        if next.last_processed_leaf != cursor.last_processed_leaf {
                            info!(
                                tree = source.active_tree(),
                                tip = next.last_processed_leaf.unwrap_or(0),
                                count = batch.len(),
                                "advanced",
                            );
                        } else {
                            info!(
                                tree = source.active_tree(),
                                tip = cursor.last_processed_leaf.unwrap_or(0),
                                "polled — no new leaves",
                            );
                        }
                        cursor = next;
                    }
                    Err(SourceError::TreeFilled) => {
                        warn!(tree = source.active_tree(), "active tree filled; restart to pick up the next");
                        return ExitCode::SUCCESS;
                    }
                    Err(e) => {
                        warn!("poll failed: {e} (retrying after interval)");
                    }
                }
            }
        }
        tokio::time::sleep(cfg.poll_interval).await;
    }
}

fn print_banner(cfg: &Config, status: &TreeStatus) {
    let pct = (f64::from(status.size) / f64::from(TreeStatus::TREE_CAPACITY)) * 100.0;
    info!("raven-railgun: subgraph = {}", cfg.subgraph_url);
    info!("raven-railgun: latest tree = {}", status.tree_number);
    info!(
        "raven-railgun: tree {} size = {} leaves ({:.1}% of {})",
        status.tree_number,
        status.size,
        pct,
        TreeStatus::TREE_CAPACITY,
    );
    info!("raven-railgun: tree {} last update at block {}", status.tree_number, status.last_block);
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,raven_railgun=info"));
    fmt().with_env_filter(filter).with_target(false).init();
}
