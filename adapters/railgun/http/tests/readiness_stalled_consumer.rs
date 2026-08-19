//! A consumer stuck on a repeating apply failure serves a tree that is missing
//! chain state. `/v1/health/ready` must take it out of rotation: the lag gauges
//! cannot see the stall, because a heartbeat holds the scan watermark at the tip
//! while nothing applies.

#![allow(
    dead_code,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use raven_railgun_core::{InstanceId, Result as RailgunResult};
use raven_railgun_engine::persistence::ConsumerMetrics;
use raven_railgun_engine::{Engine, InstanceRole, PirInstance, PirScheme};
use raven_railgun_http::{router, AppState, HealthReadyResponse, HttpConfig};
use serde::{Deserialize, Serialize};

const TOKEN: &str = "readiness-stalled-consumer-token-12";
const HEALTHY: &str = "readiness-healthy-instance";
const STALLED: &str = "readiness-stalled-instance";

static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

type MetricsCell = Arc<parking_lot::Mutex<ConsumerMetrics>>;

/// A consumer caught up at the tip with nothing to complain about.
fn caught_up_at_tip() -> MetricsCell {
    Arc::new(parking_lot::Mutex::new(ConsumerMetrics {
        last_applied_block: 21_000_000,
        last_scanned_block: 21_000_000,
        last_applied_leaf_block: 21_000_000,
        last_known_chain_head: 21_000_000,
        events_processed: 900,
        reorgs_handled: 0,
        commits_fired: 90,
        consumer_errors: 0,
        consecutive_event_errors: 0,
        unapplied_leaves: 0,
        first_abandoned_block: None,
    }))
}

struct Fixture {
    addr: SocketAddr,
    serve: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn probe(&self) -> (u16, HealthReadyResponse) {
        let resp = reqwest::Client::new()
            .get(format!("http://{}/v1/health/ready", self.addr))
            .send()
            .await
            .expect("send readiness probe");
        let code = resp.status().as_u16();
        let body: HealthReadyResponse = resp.json().await.expect("decode readiness body");
        (code, body)
    }

    async fn shutdown(self) {
        self.serve.abort();
        let _ = self.serve.await;
    }
}

async fn spawn(
    ids: &[&str],
    build: impl FnOnce(AppState<StubScheme>) -> AppState<StubScheme>,
) -> Fixture {
    let mut engine: Engine<StubScheme> = Engine::new();
    for id in ids {
        engine
            .register_instance(Arc::new(PirInstance::new(
                InstanceId::new(*id),
                InstanceRole::Live,
                StubState,
            )))
            .expect("register instance");
    }
    let state = {
        let _g = APPSTATE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        AppState::new(engine, HttpConfig::demo(TOKEN)).expect("appstate")
    };
    let r = router::<StubScheme>(build(state)).expect("router");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let serve = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            r.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    tokio::task::yield_now().await;
    Fixture { addr, serve }
}

/// Mirrors the multi-instance wiring in `serve_production_multi`: every instance
/// hands the router the same `ConsumerMetrics` cell its consumer task mutates.
/// `record_consumer_error` in `run_consumer_task` is what raises the run this
/// asserts on; `ConsumerMetrics::record_applied_event` is what ends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn readiness_fails_closed_while_an_instance_consumer_is_stalled() {
    let healthy = caught_up_at_tip();
    let stalled = caught_up_at_tip();
    let mut per_instance: HashMap<InstanceId, MetricsCell> = HashMap::new();
    per_instance.insert(InstanceId::new(HEALTHY), Arc::clone(&healthy));
    per_instance.insert(InstanceId::new(STALLED), Arc::clone(&stalled));

    let fixture = spawn(&[HEALTHY, STALLED], |state| {
        state.with_instance_metrics(per_instance)
    })
    .await;

    let (code, body) = fixture.probe().await;
    assert_eq!(code, 200, "two caught-up consumers must be ready");
    assert!(
        body.stalled_consumer_instances.is_empty(),
        "no stall was recorded; got {:?}",
        body.stalled_consumer_instances
    );

    stalled.lock().consecutive_event_errors = 1;
    let (code, body) = fixture.probe().await;
    assert_eq!(
        code, 503,
        "an instance dropping every event serves a tree missing chain state \
         and must leave rotation, even though its lag gauges read zero"
    );
    assert_eq!(body.status, "not_ready");
    assert_eq!(
        body.stalled_consumer_instances,
        vec![STALLED.to_owned()],
        "the body must name the stalled instance, not just refuse"
    );
    let lag = body.consumer.as_ref().map_or(0, |c| {
        c.indexer_lag_blocks + c.blocks_since_last_applied_event
    });
    assert_eq!(
        lag, 0,
        "premise of this gate: both lag gauges stay zero through the stall"
    );

    stalled.lock().record_applied_event(21_000_001);
    let (code, body) = fixture.probe().await;
    assert_eq!(
        code, 200,
        "a successful apply ends the run, so readiness must come back on its own"
    );
    assert!(body.stalled_consumer_instances.is_empty());

    fixture.shutdown().await;
}

/// Mirrors `serve_production`'s single-cell wiring, where `instance_metrics` may
/// be empty and the one shared cell is the only consumer view.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn readiness_fails_closed_on_the_single_consumer_cell() {
    let cell = caught_up_at_tip();
    let fixture = spawn(&[HEALTHY], |state| {
        state.with_consumer_metrics(Arc::clone(&cell))
    })
    .await;

    let (code, _) = fixture.probe().await;
    assert_eq!(code, 200, "a caught-up consumer must be ready");

    cell.lock().consecutive_event_errors = 3;
    let (code, body) = fixture.probe().await;
    assert_eq!(
        code, 503,
        "the single-cell deployment must fail closed on a stalled consumer too"
    );
    assert_eq!(body.stalled_consumer_instances, vec![HEALTHY.to_owned()]);

    fixture.shutdown().await;
}

/// An unwired consumer is not evidence of a stall.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn readiness_stays_ready_without_consumer_metrics() {
    let fixture = spawn(&[HEALTHY], |state| state).await;
    let (code, body) = fixture.probe().await;
    assert_eq!(
        code, 200,
        "no consumer wiring means no stall signal, not a refusal"
    );
    assert!(body.stalled_consumer_instances.is_empty());
    fixture.shutdown().await;
}

/// A transient error self-heals; a contiguity gap does not.
///
/// `consecutive_event_errors` is cleared by ANY applied event, which is correct for a single
/// failure the next event fixes and wrong for a per-leaf loop that broke and left leaves behind.
/// Every later leaf then fails the contiguity guard while unrelated events keep clearing the run,
/// so the tree is wedged and `/health/ready` says 200.
#[tokio::test]
async fn abandoned_leaves_keep_an_instance_out_of_rotation_after_the_error_run_clears() {
    const ABANDONED_AT: u64 = 21_000_050;
    let healthy = caught_up_at_tip();
    let stalled = caught_up_at_tip();
    let mut per_instance = HashMap::new();
    per_instance.insert(InstanceId::new(HEALTHY), Arc::clone(&healthy));
    per_instance.insert(InstanceId::new(STALLED), Arc::clone(&stalled));
    let fixture = spawn(&[HEALTHY, STALLED], |state| {
        state.with_instance_metrics(per_instance)
    })
    .await;

    let (code, _) = fixture.probe().await;
    assert_eq!(code, 200, "both consumers start ready");

    // A per-leaf loop broke: the event errored AND left leaves unapplied.
    {
        let mut m = stalled.lock();
        m.consecutive_event_errors = 1;
        m.record_abandoned_leaves(4, ABANDONED_AT);
    }
    let (code, body) = fixture.probe().await;
    assert_eq!(code, 503, "a contiguity gap must leave rotation");
    assert_eq!(body.stalled_consumer_instances, vec![STALLED.to_owned()]);

    // An unrelated event applies. This clears the error run - and MUST NOT restore readiness,
    // because the abandoned leaves are still missing from the tree.
    stalled.lock().record_applied_event(21_000_002);
    assert_eq!(
        stalled.lock().consecutive_event_errors,
        0,
        "premise: the applied event really did clear the self-healing signal"
    );
    let (code, body) = fixture.probe().await;
    assert_eq!(
        code, 503,
        "an unrelated success does not re-apply the abandoned leaves, so the instance is \
         still serving a tree with a hole in it"
    );
    assert_eq!(body.stalled_consumer_instances, vec![STALLED.to_owned()]);

    // A rewind AT the abandoned block redelivers nothing missing: the indexer rescans from
    // `height + 1`. Clearing on it would discard a gap that cannot be re-derived.
    stalled
        .lock()
        .clear_abandoned_leaves_reopened_by(ABANDONED_AT);
    let (code, body) = fixture.probe().await;
    assert_eq!(
        code, 503,
        "a rewind that does not reach below the abandoned block leaves the hole in place"
    );
    assert_eq!(body.stalled_consumer_instances, vec![STALLED.to_owned()]);

    // Only a rewind BELOW it redelivers those leaves. That is the reorg rewind's job.
    stalled
        .lock()
        .clear_abandoned_leaves_reopened_by(ABANDONED_AT - 1);
    let (code, body) = fixture.probe().await;
    assert_eq!(
        code, 200,
        "once the gap is closed the instance returns to rotation"
    );
    assert!(body.stalled_consumer_instances.is_empty());

    fixture.shutdown().await;
}

/// The inverse, so the latch cannot be a permanent 503 dressed up as a guard: a break that
/// abandoned NOTHING still self-heals on the next applied event.
#[tokio::test]
async fn an_error_that_abandoned_no_leaves_still_self_heals() {
    let healthy = caught_up_at_tip();
    let stalled = caught_up_at_tip();
    let mut per_instance = HashMap::new();
    per_instance.insert(InstanceId::new(HEALTHY), Arc::clone(&healthy));
    per_instance.insert(InstanceId::new(STALLED), Arc::clone(&stalled));
    let fixture = spawn(&[HEALTHY, STALLED], |state| {
        state.with_instance_metrics(per_instance)
    })
    .await;

    stalled.lock().consecutive_event_errors = 3;
    let (code, _) = fixture.probe().await;
    assert_eq!(code, 503, "a live error run takes the instance out");

    stalled.lock().record_applied_event(21_000_003);
    let (code, body) = fixture.probe().await;
    assert_eq!(
        code, 200,
        "with no leaves abandoned there is no gap, so the next success must restore readiness"
    );
    assert!(body.stalled_consumer_instances.is_empty());

    fixture.shutdown().await;
}
