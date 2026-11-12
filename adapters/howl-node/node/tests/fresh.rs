//! Readiness: the ready route answers `200` only while the follower keeps the view at the head,
//! an idle chain stays ready, and liveness stays `200` throughout.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

#[path = "../../../howl/indexer/tests/support/mod.rs"]
mod chain;
mod support;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body as HttpBody;
use axum::http::{header, Request, StatusCode};
use chain::Fixture;
use howl_node::chain::{BlockLog, Chain, ChainError, Header};
use howl_node::engine::Engine;
use howl_node::follow::{Follower, Step};
use howl_node::http::{router, Served};
use howl_node::limit::Limits;
use howl_node::NodeConfig;
use raven_inspire_session::SessionStoreLimits;
use support::{extend, fixture_tree, FakeChain, Http};

const TOKEN: &str = "an-operator-token-of-32-bytes-ok";

fn config(dir: &std::path::Path, fixture: &Fixture) -> NodeConfig {
    NodeConfig {
        data_dir: dir.to_path_buf(),
        chain_id: fixture.chain_id,
        pool: fixture.pool,
        deployment_block: fixture.first_block,
        max_range: 1_000,
        sessions: SessionStoreLimits {
            max_sessions: 8,
            ttl: Duration::from_secs(3_600),
        },
        param_set: howl_wire::PARAM_SET_D2048_CELL256,
        seed: Some([7; 32]),
    }
}

fn app(engine: &Arc<Engine>, stale_after: Duration) -> Http {
    Http(router(Served::with_limits(
        Arc::clone(engine),
        Limits {
            stale_after,
            operator_token: Some(TOKEN.to_owned()),
            ..Limits::new(2)
        },
    )))
}

async fn text(http: &Http, path: &str) -> (StatusCode, String) {
    let request = Request::get(path)
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(HttpBody::empty())
        .expect("request");
    let (status, body) = http.send(request).await;
    (status, String::from_utf8(body).expect("text"))
}

async fn settle<C: Chain>(follower: &mut Follower<C>, engine: &Engine) {
    for _ in 0..1_000 {
        let step = follower.step().await.expect("step");
        howl_node::publish(follower, engine, &step).expect("publish");
        if matches!(step, Step::Idle { .. }) {
            return;
        }
    }
    panic!("no idle step");
}

fn field<'a>(body: &'a str, name: &str) -> &'a str {
    body.split_whitespace()
        .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
        .unwrap_or_else(|| panic!("{name} missing: {body}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_follower_that_stops_while_the_chain_moves_goes_unready_within_the_bound() {
    let fixture = Fixture::load();
    let chain = FakeChain::new(
        fixture.pool,
        fixture.first_block,
        fixture.logs.clone(),
        fixture.head,
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut follower, engine) =
        howl_node::open(&config(dir.path(), &fixture), chain.clone()).expect("open");
    let bound = Duration::from_millis(400);
    let http = app(&engine, bound);
    let (status, body) = text(&http, "/howl/v1/ready").await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "never at the head: {body}"
    );

    settle(&mut follower, &engine).await;
    let (status, body) = text(&http, "/howl/v1/ready").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.starts_with("ready "), "{body}");

    // The chain moves on and nothing reads it.
    let (mut tree, _) = fixture_tree(&fixture);
    let ext = extend(fixture.pool, &mut tree, fixture.head + 1, 4, 2, 0x51);
    chain.fork(fixture.head + 1, ext.logs);
    chain.set_head(ext.last_block);
    let stopped = Instant::now();
    loop {
        let (status, body) = text(&http, "/howl/v1/ready").await;
        if status == StatusCode::SERVICE_UNAVAILABLE {
            assert!(body.starts_with("stale "), "{body}");
            break;
        }
        assert!(
            stopped.elapsed() < bound + Duration::from_secs(2),
            "still ready long past the bound: {body}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(stopped.elapsed() + Duration::from_millis(50) >= bound);
    let (status, health) = text(&http, "/howl/v1/health").await;
    assert_eq!(status, StatusCode::OK, "liveness stays separate");
    assert!(health.starts_with("ok leaves="), "{health}");

    // A step that reads the new blocks makes it ready again, and the status says where it stands.
    settle(&mut follower, &engine).await;
    let (status, body) = text(&http, "/howl/v1/ready").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = text(&http, "/howl/v1/status").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(field(&body, "head"), ext.last_block.to_string(), "{body}");
    assert_eq!(field(&body, "block"), ext.last_block.to_string(), "{body}");
    assert_eq!(field(&body, "behind"), "0", "{body}");
    assert_eq!(field(&body, "ready"), "1", "{body}");
    let age: u64 = field(&body, "step_age_ms").parse().expect("age");
    assert!(age < 2_000, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_idle_chain_stays_ready_past_the_bound() {
    let fixture = Fixture::load();
    let chain = FakeChain::new(
        fixture.pool,
        fixture.first_block,
        fixture.logs.clone(),
        fixture.head,
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut follower, engine) =
        howl_node::open(&config(dir.path(), &fixture), chain).expect("open");
    let bound = Duration::from_millis(300);
    let http = app(&engine, bound);
    settle(&mut follower, &engine).await;
    let start = Instant::now();
    while start.elapsed() < bound * 3 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let step = follower.step().await.expect("step");
        assert!(matches!(step, Step::Idle { .. }), "{step:?}");
        howl_node::publish(&follower, &engine, &step).expect("publish");
        let (status, body) = text(&http, "/howl/v1/ready").await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn under_a_head_stall_bound_an_endpoint_stuck_at_one_head_goes_unready() {
    let fixture = Fixture::load();
    let chain = FakeChain::new(
        fixture.pool,
        fixture.first_block,
        fixture.logs.clone(),
        fixture.head,
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut follower, engine) =
        howl_node::open(&config(dir.path(), &fixture), chain.clone()).expect("open");
    let stall = Duration::from_millis(400);
    let http = Http(router(Served::with_limits(
        Arc::clone(&engine),
        Limits {
            stale_after: Duration::from_secs(60),
            head_stall: Some(stall),
            operator_token: Some(TOKEN.to_owned()),
            ..Limits::new(2)
        },
    )));
    // The catch-up itself may outlast the bound; a head that grows right after it is ready.
    settle(&mut follower, &engine).await;
    chain.set_head(fixture.head + 1);
    settle(&mut follower, &engine).await;
    let (status, body) = text(&http, "/howl/v1/ready").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Every step ends at the endpoint's head, which never grows.
    let stuck = Instant::now();
    loop {
        let step = follower.step().await.expect("step");
        assert!(matches!(step, Step::Idle { .. }), "{step:?}");
        howl_node::publish(&follower, &engine, &step).expect("publish");
        let (status, body) = text(&http, "/howl/v1/ready").await;
        if status == StatusCode::SERVICE_UNAVAILABLE {
            assert!(body.starts_with("stale "), "{body}");
            break;
        }
        assert!(
            stuck.elapsed() < stall + Duration::from_secs(2),
            "still ready long past the stall bound: {body}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(stuck.elapsed() + Duration::from_millis(50) >= stall);
    let (_, body) = text(&http, "/howl/v1/status").await;
    assert_eq!(field(&body, "ready"), "0", "{body}");
    // A head that grows makes it ready again.
    chain.set_head(fixture.head + 2);
    settle(&mut follower, &engine).await;
    let (status, body) = text(&http, "/howl/v1/ready").await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A source whose every read fails while `down` is set: an endpoint gone away.
#[derive(Clone)]
struct Flaky {
    chain: FakeChain,
    down: Arc<AtomicBool>,
}

impl Flaky {
    fn up(&self) -> Result<(), ChainError> {
        if self.down.load(Ordering::Relaxed) {
            Err(ChainError::Transport("could not connect".to_owned()))
        } else {
            Ok(())
        }
    }
}

impl Chain for Flaky {
    async fn head(&self) -> Result<u64, ChainError> {
        self.up()?;
        self.chain.head().await
    }

    async fn header(&self, number: u64) -> Result<Option<Header>, ChainError> {
        self.up()?;
        self.chain.header(number).await
    }

    async fn logs(&self, from: u64, to: u64) -> Result<Vec<BlockLog>, ChainError> {
        self.up()?;
        self.chain.logs(from, to).await
    }

    async fn leaf_count(&self, block: [u8; 32]) -> Result<Option<u64>, ChainError> {
        self.up()?;
        self.chain.leaf_count(block).await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_running_follower_whose_reads_fail_goes_unready_and_counts_the_failures() {
    let fixture = Fixture::load();
    let flaky = Flaky {
        chain: FakeChain::new(
            fixture.pool,
            fixture.first_block,
            fixture.logs.clone(),
            fixture.head,
        ),
        down: Arc::new(AtomicBool::new(false)),
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let (follower, engine) =
        howl_node::open(&config(dir.path(), &fixture), flaky.clone()).expect("open");
    let bound = Duration::from_millis(400);
    let http = app(&engine, bound);
    let stop = Arc::new(AtomicBool::new(false));
    let following = {
        let engine = Arc::clone(&engine);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            howl_node::follow_until(follower, &engine, Duration::from_millis(20), &stop)
        })
    };
    let wait_for = |want: StatusCode| {
        let http = &http;
        async move {
            let start = Instant::now();
            loop {
                let (status, body) = text(http, "/howl/v1/ready").await;
                if status == want {
                    return start.elapsed();
                }
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "never {want}: {body}"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    };
    wait_for(StatusCode::OK).await;
    flaky.down.store(true, Ordering::Relaxed);
    let took = wait_for(StatusCode::SERVICE_UNAVAILABLE).await;
    assert!(took < bound + Duration::from_secs(2), "{took:?}");
    let (status, body) = text(&http, "/howl/v1/status").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        field(&body, "step_errors").parse::<u64>().expect("n") > 0,
        "{body}"
    );
    assert_eq!(field(&body, "ready"), "0", "{body}");
    assert_eq!(text(&http, "/howl/v1/health").await.0, StatusCode::OK);

    flaky.down.store(false, Ordering::Relaxed);
    wait_for(StatusCode::OK).await;
    stop.store(true, Ordering::Relaxed);
    following
        .join()
        .expect("joined")
        .expect("the runtime started");
}

/// A chain that makes `per_read` blocks before each head read answers: blocks arrive while
/// every step runs.
#[derive(Clone)]
struct Racing {
    chain: FakeChain,
    per_read: u64,
}

impl Chain for Racing {
    async fn head(&self) -> Result<u64, ChainError> {
        self.chain.set_head(self.chain.head_now() + self.per_read);
        self.chain.head().await
    }

    async fn header(&self, number: u64) -> Result<Option<Header>, ChainError> {
        self.chain.header(number).await
    }

    async fn logs(&self, from: u64, to: u64) -> Result<Vec<BlockLog>, ChainError> {
        self.chain.logs(from, to).await
    }

    async fn leaf_count(&self, block: [u8; 32]) -> Result<Option<u64>, ChainError> {
        self.chain.leaf_count(block).await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_chain_that_makes_blocks_during_each_step_is_followed_to_its_head() {
    let fixture = Fixture::load();
    let walk = howl_node::follow::WALK_BLOCKS;
    // The table starts far behind, so the first steps read deep.
    let chain = FakeChain::new(
        fixture.pool,
        fixture.first_block,
        fixture.logs.clone(),
        fixture.head + 20 * walk,
    );
    chain.keep_state_for(walk);
    let racing = Racing {
        chain: chain.clone(),
        per_read: 3,
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = config(dir.path(), &fixture);
    config.max_range = 50_000;
    let (mut follower, engine) = howl_node::open(&config, racing).expect("open");
    let http = app(&engine, Duration::from_secs(60));
    let mut reached = None;
    for n in 0..256 {
        let step = follower.step().await.expect("step");
        howl_node::publish(&follower, &engine, &step).expect("publish");
        if let Step::Read { block, .. } = step {
            if Some(block) == follower.head_seen() {
                reached = Some(n);
                break;
            }
        }
    }
    reached.expect("never read up to the head it saw");
    assert!(chain.count_reads() > 0, "the count was never read");
    assert_eq!(text(&http, "/howl/v1/ready").await.0, StatusCode::OK);
}
