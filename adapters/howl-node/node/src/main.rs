//! `howl-node`: serve one Howl pool.
//!
//! ```text
//! HOWL_NODE_RPC_URL=<endpoint> howl-node --data-dir DIR --chain-id N --pool 0x.. \
//!     --deployment-block N [--listen 127.0.0.1:8545] [--poll-ms 2000] [--max-range 2000] \
//!     [--max-sessions 2048] [--session-ttl-secs 3600] [--concurrent N] [--param-set 1|2]
//! ```
//!
//! The endpoint is read from the environment so that a key in its URL stays out of the
//! process list.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use howl_node::chain::{unhex, RpcChain};
use howl_node::http::{router, Served};
use howl_node::NodeConfig;
use raven_inspire_session::SessionStoreLimits;

struct Args {
    node: NodeConfig,
    listen: SocketAddr,
    poll: Duration,
    concurrent: usize,
}

fn parse(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut data_dir = None;
    let mut chain_id = None;
    let mut pool = None;
    let mut deployment_block = None;
    let mut listen: SocketAddr = ([127, 0, 0, 1], 8645).into();
    let mut poll = Duration::from_millis(2_000);
    let mut max_range = 2_000u64;
    let mut sessions = SessionStoreLimits {
        max_sessions: 2_048,
        ttl: Duration::from_secs(3_600),
    };
    let mut concurrent = std::thread::available_parallelism().map_or(4, usize::from);
    let mut param_set = howl_wire::PARAM_SET_D2048_CELL256;
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        let number = |text: String| {
            text.parse::<u64>()
                .map_err(|_| format!("{flag}: not a number"))
        };
        match flag.as_str() {
            "--data-dir" => data_dir = Some(PathBuf::from(value()?)),
            "--chain-id" => chain_id = Some(number(value()?)?),
            "--pool" => {
                pool = Some(
                    unhex(&value()?)
                        .and_then(|bytes| <[u8; 20]>::try_from(bytes).ok())
                        .ok_or("--pool: not a 20-byte 0x address")?,
                );
            }
            "--deployment-block" => deployment_block = Some(number(value()?)?),
            "--listen" => listen = value()?.parse().map_err(|_| "--listen: not an address")?,
            "--poll-ms" => poll = Duration::from_millis(number(value()?)?),
            "--max-range" => max_range = number(value()?)?,
            "--max-sessions" => {
                sessions.max_sessions =
                    usize::try_from(number(value()?)?).map_err(|_| "--max-sessions: too large")?;
            }
            "--session-ttl-secs" => sessions.ttl = Duration::from_secs(number(value()?)?),
            "--concurrent" => {
                concurrent =
                    usize::try_from(number(value()?)?).map_err(|_| "--concurrent: too large")?;
            }
            "--param-set" => {
                param_set =
                    u16::try_from(number(value()?)?).map_err(|_| "--param-set: too large")?;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(Args {
        node: NodeConfig {
            data_dir: data_dir.ok_or("--data-dir is required")?,
            chain_id: chain_id.ok_or("--chain-id is required")?,
            pool: pool.ok_or("--pool is required")?,
            deployment_block: deployment_block.ok_or("--deployment-block is required")?,
            max_range,
            sessions,
            param_set,
            seed: None,
        },
        listen,
        poll,
        concurrent,
    })
}

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            tracing::error!("{message}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = parse(std::env::args().skip(1))?;
    let url = std::env::var("HOWL_NODE_RPC_URL").map_err(|_| "HOWL_NODE_RPC_URL is not set")?;
    let chain = RpcChain::new(url, args.node.pool).map_err(|e| e.to_string())?;
    let (follower, engine) = howl_node::open(&args.node, chain).map_err(|e| e.to_string())?;
    tracing::info!(
        leaves = engine.view().leaf_count,
        block = engine.view().block,
        "table opened"
    );

    let stop = Arc::new(AtomicBool::new(false));
    let following = {
        let engine = Arc::clone(&engine);
        let stop = Arc::clone(&stop);
        let poll = args.poll;
        std::thread::Builder::new()
            .name("follow".to_owned())
            .spawn(move || howl_node::follow_until(follower, &engine, poll, &stop))
            .map_err(|e| e.to_string())?
    };

    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let served = runtime.block_on(async {
        let app = router(Served::new(engine, args.concurrent)).layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
                .allow_headers([axum::http::header::CONTENT_TYPE]),
        );
        let listener = tokio::net::TcpListener::bind(args.listen)
            .await
            .map_err(|e| format!("cannot listen on {}: {e}", args.listen))?;
        tracing::info!(listen = %args.listen, "serving");
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await
            .map_err(|e| e.to_string())
    });
    stop.store(true, Ordering::Relaxed);
    let _ = following.join();
    served
}
