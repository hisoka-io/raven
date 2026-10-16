//! The Howl node: follows a pool on chain, keeps its discovery table, and serves wallets.
//!
//! [`follow::Follower`] reads the pool's tree events into the table as blocks arrive,
//! [`engine::Engine`] publishes the table as one view at a time, and [`http::router`]
//! answers the wire in `howl-wire` from the view.

#![deny(missing_docs)]

pub mod chain;
pub mod engine;
pub mod follow;
pub mod http;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use howl_indexer::IndexerConfig;
use howl_store::NoteStore;
use raven_inspire_session::SessionStoreLimits;

use chain::Chain;
use engine::{Engine, EngineError, Pir};
use follow::{FollowError, Follower, Step};

/// Why the node could not start.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// The table could not be opened.
    #[error(transparent)]
    Store(#[from] howl_store::StoreError),
    /// The engine could not be built.
    #[error(transparent)]
    Engine(#[from] EngineError),
    /// The follower could not resume.
    #[error(transparent)]
    Follow(#[from] FollowError),
}

/// What a node serves and where it keeps it.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Directory of the table and the node's key material.
    pub data_dir: PathBuf,
    /// Chain, pool and deployment block.
    pub chain_id: u64,
    /// The pool's address.
    pub pool: [u8; 20],
    /// Block the pool was deployed in.
    pub deployment_block: u64,
    /// Blocks one chain read covers at most.
    pub max_range: u64,
    /// Seats for sessions, and how long one lives after its last use.
    pub sessions: SessionStoreLimits,
    /// Fixes the key material a new directory gets; tests only.
    pub seed: Option<[u8; 32]>,
}

impl NodeConfig {
    /// The indexer's settings: the newest block is read as soon as it exists.
    #[must_use]
    pub const fn indexer(&self) -> IndexerConfig {
        IndexerConfig {
            chain_id: self.chain_id,
            pool: self.pool,
            deployment_block: self.deployment_block,
            finality_depth: 0,
        }
    }
}

/// Open the table and the engine, publish the table as it stands, and return the follower
/// that keeps it current.
///
/// # Errors
/// [`StartError`] when the table, the key material or the resume point is unusable.
pub fn open<C: Chain>(
    config: &NodeConfig,
    chain: C,
) -> Result<(Follower<C>, Arc<Engine>), StartError> {
    let store = NoteStore::open(config.data_dir.join("table"), config.chain_id, config.pool)?;
    let pir = Pir::open(&config.data_dir.join("pir"), config.sessions, config.seed)?;
    let follower = Follower::new(chain, store, config.indexer(), config.max_range)?;
    let engine = Arc::new(Engine::new(pir));
    engine.refresh(follower.store(), follower.upper(), 0)?;
    Ok((follower, engine))
}

/// Apply one step's outcome to the served view.
///
/// # Errors
/// [`EngineError`] when the view cannot be rebuilt; the previous view stays served.
pub fn publish<C: Chain>(
    follower: &Follower<C>,
    engine: &Engine,
    step: &Step,
) -> Result<(), EngineError> {
    match step {
        Step::Read { leaves, .. } | Step::Rewound { leaves, .. } => {
            engine.refresh(follower.store(), follower.upper(), leaves.start)
        }
        // A refresh that failed is retried with the range it was asked for.
        Step::Idle { .. } | Step::Moved if engine.unpublished() => {
            engine.refresh(follower.store(), follower.upper(), u64::MAX)
        }
        Step::Idle { .. } | Step::Moved => Ok(()),
    }
}

/// Follow the chain until `stop` is set: a step every `poll` while at the head, back to back
/// while behind. Runs on the calling thread.
pub fn follow_until<C: Chain>(
    mut follower: Follower<C>,
    engine: &Engine,
    poll: Duration,
    stop: &AtomicBool,
) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        tracing::error!("could not start the follower's runtime");
        return;
    };
    let mut swept = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        let wait = match runtime.block_on(follower.step()) {
            Ok(step) => {
                if let Err(e) = publish(&follower, engine, &step) {
                    tracing::error!(error = %e, "publishing the table failed");
                }
                match step {
                    Step::Read { leaves, block } => {
                        tracing::info!(
                            block,
                            leaves = leaves.end,
                            added = leaves.end - leaves.start,
                            "read"
                        );
                        Duration::ZERO
                    }
                    Step::Rewound { leaves, block } => {
                        tracing::warn!(
                            ?block,
                            dropped = leaves.end - leaves.start,
                            "chain reorganised; table rewound"
                        );
                        Duration::ZERO
                    }
                    Step::Idle { .. } | Step::Moved => poll,
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "follow step failed; retrying");
                poll
            }
        };
        if swept.elapsed() >= Duration::from_secs(60) {
            engine.pir().sweep();
            swept = Instant::now();
        }
        std::thread::sleep(wait);
    }
}

/// Stop flag shared between the follower thread and whoever shuts it down.
pub type StopFlag = Arc<AtomicBool>;
