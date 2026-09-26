//! A mirrored PPOI list has three states an operator acts on differently: caught up and idle,
//! never fed, and upstream refusing. Readiness has to tell them apart, and the container
//! HEALTHCHECK reads readiness, so it inherits whatever readiness says and nothing more.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;

use raven_railgun_core::{InstanceId, Result as RailgunResult};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance, PirScheme};
use raven_railgun_http::status::{MirrorFeedState, MirrorFeedView};
use raven_railgun_http::{router, AppState, HealthReadyResponse, HttpConfig};
use serde::{Deserialize, Serialize};

const TOKEN: &str = "readiness-mirror-feed-token-padded-1";
const INSTANCE: &str = "readiness-mirror-feed-instance";

#[derive(Debug)]
struct StubScheme;

#[derive(Debug, Default)]
struct StubState;

#[derive(Serialize, Deserialize, Debug)]
struct StubQuery;

#[derive(Serialize, Deserialize, Debug)]
struct StubResponse;

impl PirScheme for StubScheme {
    type ServerState = StubState;
    type Query = StubQuery;
    type Response = StubResponse;
    fn respond(_state: &Self::ServerState, _query: &Self::Query) -> RailgunResult<Self::Response> {
        Ok(StubResponse)
    }
    fn state_shape(_state: &Self::ServerState) -> raven_railgun_engine::StateShape {
        raven_railgun_engine::StateShape {
            entry_size_bytes: 1,
            rows_per_shard: u64::MAX,
        }
    }
}

type Feeds = Arc<parking_lot::Mutex<Vec<MirrorFeedView>>>;

fn view(list: u8, state: MirrorFeedState) -> MirrorFeedView {
    let refusing = state == MirrorFeedState::UpstreamRefusing;
    MirrorFeedView {
        list_key: format!("{list:02x}").repeat(32),
        state,
        rows_held: if state == MirrorFeedState::NeverFed {
            0
        } else {
            1_010
        },
        upstream_rows: (state == MirrorFeedState::CaughtUp).then_some(1_010),
        next_index: 1_010,
        consecutive_failures: u64::from(refusing),
        last_failure: refusing.then(|| "answered HTTP 500".to_owned()),
        seconds_since_answer: Some(4),
    }
}

async fn serve(feeds: Option<Feeds>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let mut engine: Engine<StubScheme> = Engine::new();
    engine
        .register_instance(Arc::new(PirInstance::new(
            InstanceId::new(INSTANCE),
            InstanceRole::Live,
            StubState,
        )))
        .expect("register instance");
    let mut state = AppState::new(engine, HttpConfig::demo(TOKEN)).expect("appstate");
    if let Some(feeds) = feeds {
        state = state.with_mirror_feeds(Arc::new(move || feeds.lock().clone()));
    }
    let app = router::<StubScheme>(state).expect("router");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let serve = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    (addr, serve)
}

/// Uncredentialed, as a container HEALTHCHECK calls it.
async fn probe(addr: SocketAddr) -> (u16, String) {
    let response = reqwest::Client::new()
        .get(format!("http://{addr}/v1/health/ready"))
        .send()
        .await
        .expect("readiness probe");
    let code = response.status().as_u16();
    (code, response.text().await.expect("readiness body"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readiness_tells_caught_up_from_never_fed_from_upstream_refusing() {
    let feeds = Feeds::default();
    let (addr, server) = serve(Some(Arc::clone(&feeds))).await;

    // `(state, HTTP status, what the body says)`: the wire name is what an operator greps for.
    let cases = [
        (MirrorFeedState::CaughtUp, 200, "caught_up"),
        (MirrorFeedState::Syncing, 200, "syncing"),
        (MirrorFeedState::UpstreamRefusing, 200, "upstream_refusing"),
        (MirrorFeedState::NeverFed, 503, "never_fed"),
        (MirrorFeedState::Stopped, 503, "stopped"),
    ];
    for (state, expected_code, wire) in cases {
        *feeds.lock() = vec![view(1, state)];
        let (code, body) = probe(addr).await;
        assert_eq!(code, expected_code, "{wire}: {body}");
        assert!(
            body.contains(&format!("\"state\":\"{wire}\"")),
            "the body must name the state as {wire}: {body}"
        );
        let parsed: HealthReadyResponse = serde_json::from_str(&body).expect("decode body");
        assert_eq!(parsed.mirror_feeds, vec![view(1, state)]);
        assert_eq!(
            parsed.status,
            if expected_code == 200 {
                "ready"
            } else {
                "not_ready"
            }
        );
        assert!(
            parsed.stalled_consumer_instances.is_empty()
                && parsed.router_unrouted_targets.is_empty(),
            "the mirror feed is the only reason in play: {body}"
        );
    }

    let (_, body) = {
        *feeds.lock() = vec![view(2, MirrorFeedState::UpstreamRefusing)];
        probe(addr).await
    };
    let parsed: HealthReadyResponse = serde_json::from_str(&body).expect("decode body");
    let refusing = parsed.mirror_feeds.first().expect("one feed");
    assert_eq!(
        (
            refusing.consecutive_failures,
            refusing.last_failure.as_deref()
        ),
        (1, Some("answered HTTP 500")),
        "refusing says how, without naming the endpoint"
    );

    *feeds.lock() = vec![
        view(1, MirrorFeedState::CaughtUp),
        view(2, MirrorFeedState::NeverFed),
    ];
    let (code, body) = probe(addr).await;
    assert_eq!(code, 503, "one list never fed takes the node out: {body}");

    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_with_no_mirrored_list_reports_none_and_is_ready() {
    let (addr, server) = serve(None).await;
    let (code, body) = probe(addr).await;
    assert_eq!(code, 200, "{body}");
    assert!(
        !body.contains("mirror_feeds"),
        "no feed wired, no field: {body}"
    );
    server.abort();
}

/// The image's HEALTHCHECK is the only thing Docker knows of readiness. `-f` turns every state
/// readiness refuses into a failed check; on a 200 curl prints the body, which Docker keeps in
/// the container's health log, so caught up and upstream refusing are both on record there.
#[test]
fn the_container_healthcheck_fails_with_readiness_and_keeps_its_body() {
    let dockerfile = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../Dockerfile");
    let body = std::fs::read_to_string(&dockerfile).expect("read the image's Dockerfile");
    let joined = body.replace("\\\n", " ");
    let checks: Vec<&str> = joined
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("HEALTHCHECK"))
        .collect();
    let [check] = checks.as_slice() else {
        panic!("expected exactly one HEALTHCHECK, found {checks:?}");
    };
    let command = check
        .split_once(" CMD ")
        .map(|(_, command)| command)
        .expect("HEALTHCHECK runs a command");
    let words: Vec<&str> = command.split_whitespace().collect();
    assert_eq!(words.first(), Some(&"curl"), "{command}");
    assert!(
        words.iter().any(|word| word.ends_with("/v1/health/ready")),
        "the check must read readiness: {command}"
    );
    assert!(
        words.iter().any(|word| {
            matches!(*word, "--fail" | "--fail-with-body")
                || (word.starts_with('-') && !word.starts_with("--") && word.contains('f'))
        }),
        "an HTTP 503 must fail the check: {command}"
    );
    for dropped in ["-o", "--output", "-I", "--head", ">", "1>", "&>"] {
        assert!(
            !words.contains(&dropped),
            "{dropped} drops the body that says which state the node is in: {command}"
        );
    }
}
