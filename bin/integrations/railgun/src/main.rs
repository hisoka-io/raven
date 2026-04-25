mod config;
mod source;
mod subgraph;
mod types;

use std::process::ExitCode;

use raven_core::{Error, MemoryStore, Snapshot, StorageBackend};
use raven_indexer::Indexer;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::source::{CommitmentSource, SourceError, SubgraphSource};
use crate::types::{hex_lower, ScanCursor, TreeStatus};

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

    let indexer: Indexer<MemoryStore> = Indexer::new(MemoryStore::new());

    print_banner(&cfg, &status);

    let mut cursor = ScanCursor::empty();

    loop {
        match source.poll_once(cursor).await {
            Ok((next, batch)) => {
                let was_cold_start = cursor.last_processed_leaf.is_none();
                let gen = match indexer.put_many(
                    batch.iter().map(|r| (r.key(), r.to_bytes())),
                ) {
                    Ok(g) => g,
                    Err(e) => {
                        error!("{e}");
                        return ExitCode::from(1);
                    }
                };
                let stored = match indexer.len() {
                    Ok(n) => n,
                    Err(e) => {
                        error!("{e}");
                        return ExitCode::from(1);
                    }
                };

                if let (Some(first), Some(last)) = (batch.first(), batch.last()) {
                    if was_cold_start {
                        info!(
                            target: "poller",
                            from = first.leaf_index,
                            to = last.leaf_index,
                            added = batch.len(),
                            stored,
                            gen,
                            last_hash = %format!("0x{}", hex_lower(&last.hash)),
                            "synced",
                        );
                    } else {
                        for rec in &batch {
                            info!(
                                target: "poller",
                                leaf = rec.leaf_index,
                                hash = %format!("0x{}", hex_lower(&rec.hash)),
                            );
                        }
                        info!(
                            target: "poller",
                            tip = last.leaf_index,
                            added = batch.len(),
                            stored,
                            gen,
                            "advanced",
                        );
                    }
                    log_snapshot(&indexer, source.active_tree());
                } else {
                    info!(
                        target: "poller",
                        tip = cursor.last_processed_leaf.unwrap_or(0),
                        stored,
                        "idle",
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
        tokio::time::sleep(cfg.poll_interval).await;
    }
}

fn print_banner(cfg: &Config, status: &TreeStatus) {
    let pct = (f64::from(status.size) / f64::from(TreeStatus::TREE_CAPACITY)) * 100.0;
    info!("subgraph = {}", cfg.subgraph_url);
    info!("latest tree = {}", status.tree_number);
    info!(
        "digest=tree {} size = {} leaves ({:.1}% of {})",
        status.tree_number,
        status.size,
        pct,
        TreeStatus::TREE_CAPACITY,
    );
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,raven_railgun=info,poller=info,snapshot=info"));
    // Targets must be visible so `poller` vs `snapshot` lines are distinguishable.
    fmt().with_env_filter(filter).with_target(true).init();
}

fn log_snapshot(indexer: &Indexer<MemoryStore>, tree: u32) {
    let snap = match indexer.backend().snapshot() {
        Ok(s) => s,
        Err(e) => {
            error!(target: "snapshot", "{e}");
            return;
        }
    };
    let last_hash = match scan_last_hash(snap.as_ref()) {
        Ok(Some(h)) => format!("0x{}", hex_lower(&h)),
        Ok(None) => "none".to_owned(),
        Err(e) => {
            error!(target: "snapshot", "{e}");
            return;
        }
    };
    info!(
        target: "snapshot",
        tree,
        gen = snap.generation(),
        len = snap.len(),
        last_hash = %last_hash,
    );
}

/// Returns the value of the highest-keyed row, or `None` if the snapshot is empty.
/// `Snapshot::scan` yields rows in key order, so the final row carries the max key.
fn scan_last_hash(snap: &dyn Snapshot) -> Result<Option<[u8; 32]>, Error> {
    let mut out: Option<[u8; 32]> = None;
    for row in snap.scan() {
        let (_, v) = row?;
        out = <[u8; 32]>::try_from(&v[..]).ok();
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn scan_last_hash_returns_highest_keyed_value() -> Result<(), Error> {
        let store = MemoryStore::new();
        assert!(scan_last_hash(store.snapshot()?.as_ref())?.is_none());

        let mut txn = store.begin()?;
        txn.insert(0, Bytes::from_static(&[0xAA; 32]))?;
        txn.insert(7, Bytes::from_static(&[0xBB; 32]))?;
        txn.commit()?;

        assert_eq!(
            scan_last_hash(store.snapshot()?.as_ref())?,
            Some([0xBB; 32]),
        );
        Ok(())
    }
}
