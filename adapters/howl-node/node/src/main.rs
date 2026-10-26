//! `howl-node`: serve one Howl pool.
//!
//! ```text
//! HOWL_NODE_RPC_URL=<endpoint> howl-node --data-dir DIR --chain-id N --pool 0x.. \
//!     --deployment-block N [--listen 127.0.0.1:8545] [--poll-ms 2000] [--max-range 50000] \
//!     [--max-sessions 2048] [--session-ttl-secs 3600] [--concurrent N] [--param-set 1|2]
//!     [--walk-blocks 64] [--respond-threads N] [--rate 5000] [--rate-burst 10000]
//!     [--session-rate 4] [--session-burst 64] [--queued N] [--permit-wait-ms 20000]
//!     [--bodies N] [--body-timeout-ms 30000]
//! ```
//!
//! `--concurrent` bounds the batches answered at once and `--respond-threads` the threads that
//! compute set-2 responses for all of them (both default to the cores). `--walk-blocks` is the
//! depth below the head within which every header and the pool's count are read; it must be at
//! least 1 and lie within the recent state the endpoint keeps. `--max-range` caps the blocks one
//! log read asks for; a read the endpoint refuses is halved, so it need not match the endpoint.
//!
//! `--rate`/`--rate-burst` bound the requests of all callers together on each route, every route
//! with a bucket of its own (health and status are exempt), `--session-rate`/`--session-burst`
//! the sessions opened, `--queued` the batches waiting for a permit (eight per permit by
//! default), `--permit-wait-ms` how long one waits, `--bodies` the session and batch bodies held
//! at once (twice the permits and queue places by default), and `--body-timeout-ms` how long one
//! body may take to arrive.
//!
//! The endpoint is read from the environment so that a key in its URL stays out of the
//! process list, and so is `HOWL_NODE_OPERATOR_TOKEN`, the bearer token of the status route
//! (16 bytes at least; unset, the route stays closed).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use howl_node::chain::{unhex, RpcChain};
use howl_node::http::{router, Served};
use howl_node::limit::Limits;
use howl_node::{NodeConfig, Tuning};
use raven_inspire_session::SessionStoreLimits;

struct Args {
    node: NodeConfig,
    tuning: Tuning,
    listen: SocketAddr,
    poll: Duration,
    limits: Limits,
}

fn parse(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut data_dir = None;
    let mut chain_id = None;
    let mut pool = None;
    let mut deployment_block = None;
    let mut listen: SocketAddr = ([127, 0, 0, 1], 8645).into();
    let mut poll = Duration::from_millis(2_000);
    let mut max_range = 50_000u64;
    let mut sessions = SessionStoreLimits {
        max_sessions: 2_048,
        ttl: Duration::from_secs(3_600),
    };
    let mut concurrent = std::thread::available_parallelism().map_or(4, usize::from);
    let mut param_set = howl_wire::PARAM_SET_D2048_CELL256;
    let mut tuning = Tuning::default();
    let mut requests = None;
    let mut sessions_opened = None;
    let mut queued = None;
    let mut permit_wait = None;
    let mut bodies = None;
    let mut body_timeout = None;
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        let number = |text: String| {
            text.parse::<u64>()
                .map_err(|_| format!("{flag}: not a number"))
        };
        let small = |text: String| {
            text.parse::<u32>()
                .map_err(|_| format!("{flag}: not a number up to {}", u32::MAX))
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
            "--walk-blocks" => {
                tuning.walk_blocks = number(value()?)?;
                if tuning.walk_blocks == 0 {
                    // No walk would leave every count and header link unchecked.
                    return Err("--walk-blocks: at least 1".to_owned());
                }
            }
            "--respond-threads" => {
                tuning.respond_threads = usize::try_from(number(value()?)?)
                    .map_err(|_| "--respond-threads: too large")?;
            }
            "--rate" => requests.get_or_insert(Limits::new(1).requests).per_sec = small(value()?)?,
            "--rate-burst" => {
                requests.get_or_insert(Limits::new(1).requests).burst = small(value()?)?
            }
            "--session-rate" => {
                sessions_opened
                    .get_or_insert(Limits::new(1).sessions)
                    .per_sec = small(value()?)?;
            }
            "--session-burst" => {
                sessions_opened.get_or_insert(Limits::new(1).sessions).burst = small(value()?)?;
            }
            "--queued" => {
                queued =
                    Some(usize::try_from(number(value()?)?).map_err(|_| "--queued: too large")?);
            }
            "--permit-wait-ms" => permit_wait = Some(Duration::from_millis(number(value()?)?)),
            "--bodies" => {
                bodies =
                    Some(usize::try_from(number(value()?)?).map_err(|_| "--bodies: too large")?);
            }
            "--body-timeout-ms" => body_timeout = Some(Duration::from_millis(number(value()?)?)),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let defaults = Limits::new(concurrent);
    let queued = queued.unwrap_or(defaults.queued);
    let limits = Limits {
        queued,
        bodies: bodies
            .unwrap_or_else(|| defaults.concurrent.saturating_add(queued).saturating_mul(2)),
        body_timeout: body_timeout.unwrap_or(defaults.body_timeout),
        permit_wait: permit_wait.unwrap_or(defaults.permit_wait),
        requests: requests.unwrap_or(defaults.requests),
        sessions: sessions_opened.unwrap_or(defaults.sessions),
        ..defaults
    };
    limits.validate()?;
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
        tuning,
        listen,
        poll,
        limits,
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
    let mut args = parse(std::env::args().skip(1))?;
    args.limits.operator_token = std::env::var("HOWL_NODE_OPERATOR_TOKEN")
        .ok()
        .filter(|token| !token.is_empty());
    args.limits.validate()?;
    let url = std::env::var("HOWL_NODE_RPC_URL").map_err(|_| "HOWL_NODE_RPC_URL is not set")?;
    let chain = RpcChain::new(url, args.node.pool).map_err(|e| e.to_string())?;
    let (follower, engine) =
        howl_node::open_with(&args.node, chain, args.tuning).map_err(|e| e.to_string())?;
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
        let app = router(Served::with_limits(engine, args.limits));
        let listener = tokio::net::TcpListener::bind(args.listen)
            .await
            .map_err(|e| format!("cannot listen on {}: {e}", args.listen))?;
        tracing::info!(listen = %args.listen, "serving");
        axum::serve(listener, app)
            .with_graceful_shutdown(stopped())
            .await
            .map_err(|e| e.to_string())
    });
    stop.store(true, Ordering::Relaxed);
    let _ = following.join();
    served
}

/// Ctrl-C, or the SIGTERM a container runtime sends to stop the node.
async fn stopped() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::time::Duration;

    use super::parse;

    fn args(extra: &[&str]) -> impl Iterator<Item = String> {
        let pool = format!("0x{}", "11".repeat(20));
        let base = [
            "--data-dir",
            "/tmp/x",
            "--chain-id",
            "1",
            "--pool",
            pool.as_str(),
            "--deployment-block",
            "5",
        ];
        base.iter()
            .chain(extra)
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn a_walk_of_no_blocks_is_refused() {
        let refused = parse(args(&["--walk-blocks", "0"])).err().expect("refused");
        assert!(refused.contains("--walk-blocks"), "{refused}");
        let one = parse(args(&["--walk-blocks", "1"])).expect("one block");
        assert_eq!(one.tuning.walk_blocks, 1);
    }

    #[test]
    fn the_default_range_needs_no_flag() {
        let parsed = parse(args(&[])).expect("parses");
        assert_eq!(parsed.node.max_range, 50_000);
    }

    #[test]
    fn the_limits_default_from_the_permits_and_take_each_flag() {
        let parsed = parse(args(&["--concurrent", "3"])).expect("parses");
        assert_eq!(parsed.limits.concurrent, 3);
        assert_eq!(parsed.limits.queued, 24);
        assert_eq!(parsed.limits.bodies, 54);
        assert_eq!(parsed.limits.requests.per_sec, 5_000);
        assert!(parsed.limits.operator_token.is_none());
        let set = parse(args(&[
            "--rate",
            "10",
            "--rate-burst",
            "20",
            "--session-rate",
            "1",
            "--session-burst",
            "2",
            "--queued",
            "5",
            "--permit-wait-ms",
            "250",
            "--bodies",
            "7",
            "--body-timeout-ms",
            "900",
        ]))
        .expect("parses");
        assert_eq!(
            (set.limits.requests.per_sec, set.limits.requests.burst),
            (10, 20)
        );
        assert_eq!(
            (set.limits.sessions.per_sec, set.limits.sessions.burst),
            (1, 2)
        );
        assert_eq!(set.limits.queued, 5);
        assert_eq!(set.limits.permit_wait, Duration::from_millis(250));
        assert_eq!(set.limits.bodies, 7);
        assert_eq!(set.limits.body_timeout, Duration::from_millis(900));
        let follows = parse(args(&["--concurrent", "2", "--queued", "3"])).expect("parses");
        assert_eq!(
            follows.limits.bodies, 10,
            "twice the permits and queue places"
        );
    }

    #[test]
    fn a_rate_of_zero_is_refused() {
        for flag in [
            "--rate",
            "--rate-burst",
            "--session-rate",
            "--session-burst",
        ] {
            let refused = parse(args(&[flag, "0"])).err().expect("refused");
            assert!(refused.contains("at least 1"), "{flag}: {refused}");
        }
        assert!(parse(args(&["--permit-wait-ms", "0"])).is_err());
        assert!(parse(args(&["--bodies", "0"])).is_err());
        assert!(parse(args(&["--body-timeout-ms", "0"])).is_err());
    }
}
