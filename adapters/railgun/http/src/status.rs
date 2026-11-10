//! Status, metrics, and health-probe handlers.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use raven_railgun_engine::persistence::ConsumerMetrics;
use raven_railgun_engine::PirScheme;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

/// JSON shape returned by `GET /v1/status`.
#[derive(Serialize, Deserialize, Debug)]
pub struct StatusResponse {
    /// Scheme identifier.
    pub scheme: String,
    /// One entry per registered instance.
    pub instances: Vec<InstanceStatus>,
    /// Consumer metrics merged across every instance (see [`ConsumerStatus`]); omitted when
    /// not wired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer: Option<ConsumerStatus>,
}

/// Per-instance status row.
#[derive(Serialize, Deserialize, Debug)]
pub struct InstanceStatus {
    /// Instance id.
    pub id: String,
    /// Current snapshot epoch.
    pub epoch: u64,
    /// `"static"`, `"live"`, or `"sidecar"`; observational only, does not affect routing.
    pub role: String,
    /// `"active"`, `"draining"`, or `"drained"`. Routing MUST reject non-`"active"` instances.
    pub drain_state: String,
    /// In-flight query count at response time.
    pub in_flight: u64,
    /// Resolved per-instance K; falls back to `HttpConfig::max_concurrent_queries`.
    pub active_k_concurrency: u32,
    /// This instance's own consumer; omitted when it has none wired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumer: Option<ConsumerStatus>,
}

/// Live consumer-task metrics; mirrors [`raven_railgun_engine::persistence::ConsumerMetrics`].
///
/// On an instance row these are that instance's numbers. The node-level block merges every
/// instance, because the first instance is often a sealed block that ingests nothing: heights
/// are the highest any instance reached, counts are summed, and the lag is the worst instance's.
#[derive(Serialize, Deserialize, Debug)]
pub struct ConsumerStatus {
    /// Last block height applied by the consumer task.
    pub last_applied_block: u64,
    /// Highest block height the indexer has scanned.
    pub last_scanned_block: u64,
    /// Last block height reported as the chain tip.
    pub last_known_chain_head: u64,
    /// `last_known_chain_head - last_scanned_block`, saturating at 0. Node-level: the largest
    /// across instances, so one stuck scanner is not hidden by a healthy one.
    pub indexer_lag_blocks: u64,
    /// `last_known_chain_head - last_applied_block`, saturating; grows on a quiet
    /// chain even when caught up.
    pub blocks_since_last_applied_event: u64,
    /// Total chain events applied since process start.
    pub events_processed: u64,
    /// Total snapshot commits driven.
    pub commits_fired: u64,
    /// Total chain reorgs handled.
    pub reorgs_handled: u64,
    /// Per-event errors the consumer continued past.
    pub consumer_errors: u64,
}

impl ConsumerStatus {
    fn of(snap: &ConsumerMetrics) -> Self {
        Self {
            last_applied_block: snap.last_applied_block,
            last_scanned_block: snap.last_scanned_block,
            last_known_chain_head: snap.last_known_chain_head,
            indexer_lag_blocks: snap.indexer_lag_blocks(),
            blocks_since_last_applied_event: snap.blocks_since_last_applied_event(),
            events_processed: snap.events_processed,
            commits_fired: snap.commits_fired,
            reorgs_handled: snap.reorgs_handled,
            consumer_errors: snap.consumer_errors,
        }
    }

    /// Node-level view over `cells`; `None` when there are none.
    fn merged(cells: &[&MetricsCell]) -> Option<Self> {
        let mut unique: Vec<&MetricsCell> = Vec::with_capacity(cells.len());
        for cell in cells {
            // Wirings that share one cell between instances must not count its events twice.
            if !unique.iter().any(|seen| Arc::ptr_eq(seen, cell)) {
                unique.push(cell);
            }
        }
        let mut snaps = unique.iter().map(|cell| *cell.lock());
        let mut merged = Self::of(&snaps.next()?);
        for snap in snaps {
            merged.last_applied_block = merged.last_applied_block.max(snap.last_applied_block);
            merged.last_scanned_block = merged.last_scanned_block.max(snap.last_scanned_block);
            merged.last_known_chain_head =
                merged.last_known_chain_head.max(snap.last_known_chain_head);
            merged.indexer_lag_blocks = merged.indexer_lag_blocks.max(snap.indexer_lag_blocks());
            merged.events_processed = merged
                .events_processed
                .saturating_add(snap.events_processed);
            merged.commits_fired = merged.commits_fired.saturating_add(snap.commits_fired);
            merged.reorgs_handled = merged.reorgs_handled.saturating_add(snap.reorgs_handled);
            merged.consumer_errors = merged.consumer_errors.saturating_add(snap.consumer_errors);
        }
        // Since ANY instance applied an event: the node is ingesting while one block is.
        merged.blocks_since_last_applied_event = merged
            .last_known_chain_head
            .saturating_sub(merged.last_applied_block);
        Some(merged)
    }
}

type MetricsCell = Arc<parking_lot::Mutex<ConsumerMetrics>>;

/// Each registered instance with its consumer cell from the per-instance map.
fn instance_consumer_cells<S: PirScheme>(
    app: &AppState<S>,
    instances: &[Arc<raven_railgun_engine::PirInstance<S>>],
) -> Vec<Option<MetricsCell>> {
    let per_instance = app.instance_metrics.read();
    instances
        .iter()
        .map(|instance| per_instance.get(&instance.id).cloned())
        .collect()
}

/// The node-level consumer block shared by `/v1/status` and `/v1/health/ready`.
fn node_consumer_status<S: PirScheme>(app: &AppState<S>) -> Option<ConsumerStatus> {
    let instances = app.engine.instances();
    let cells = instance_consumer_cells(app, &instances);
    let wired: Vec<&MetricsCell> = cells.iter().flatten().collect();
    ConsumerStatus::merged(&wired)
}

/// `X-Raven-Freshness` for a response `instance_id` served: that instance's own consumer, since
/// the bytes came from its snapshot alone. An instance with no cell of its own gets the node
/// view `/v1/status` reports, never another instance's.
pub(crate) fn freshness_reading<S: PirScheme>(
    app: &AppState<S>,
    instance_id: &raven_railgun_core::InstanceId,
) -> Option<crate::FreshnessReading> {
    let own = app.instance_metrics.read().get(instance_id).cloned();
    match own {
        Some(cell) => {
            let snap = *cell.lock();
            Some(crate::FreshnessReading {
                lag_blocks: snap.indexer_lag_blocks(),
                applied_height: snap.last_applied_block,
            })
        }
        None => node_consumer_status(app).map(|node| crate::FreshnessReading {
            lag_blocks: node.indexer_lag_blocks,
            applied_height: node.last_applied_block,
        }),
    }
}

pub(crate) async fn status_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
) -> Json<StatusResponse> {
    Json(build_status_response(&app))
}

/// Operator-observable engine state for `/v1/status`.
fn build_status_response<S: PirScheme>(app: &AppState<S>) -> StatusResponse {
    let fallback_k = u32::try_from(app.config.max_concurrent_queries.max(1)).unwrap_or(u32::MAX);
    let engine_instances = app.engine.instances();
    let cells = instance_consumer_cells(app, &engine_instances);
    let instances = engine_instances
        .iter()
        .zip(&cells)
        .map(|(inst, cell)| InstanceStatus {
            id: inst.id.to_string(),
            epoch: inst.current_epoch().0,
            role: inst.role().label().to_owned(),
            drain_state: inst.drain_state().label().to_owned(),
            in_flight: inst.in_flight_count(),
            active_k_concurrency: app
                .instance_concurrency
                .get(&inst.id)
                .copied()
                .unwrap_or(fallback_k),
            consumer: cell.as_ref().map(|cell| ConsumerStatus::of(&cell.lock())),
        })
        .collect();
    let wired: Vec<&MetricsCell> = cells.iter().flatten().collect();
    let consumer = ConsumerStatus::merged(&wired);
    StatusResponse {
        scheme: (*app.scheme_name).clone(),
        instances,
        consumer,
    }
}

pub(crate) async fn metrics_handler<S: raven_railgun_engine::PirScheme>(
    State(app): State<AppState<S>>,
) -> impl IntoResponse {
    refresh_dynamic_metrics(&app);
    let body = app.metrics_handle.render();
    (
        StatusCode::OK,
        [(http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
}

/// Per-scrape gauge values; HELP/TYPE are registered once at `AppState::new`.
fn refresh_dynamic_metrics<S: raven_railgun_engine::PirScheme>(app: &AppState<S>) {
    use std::time::Instant;
    let uptime_secs = Instant::now()
        .saturating_duration_since(app.process_started_at)
        .as_secs();
    #[allow(clippy::cast_precision_loss)]
    let uptime_f = uptime_secs as f64;
    metrics::gauge!("raven_railgun_uptime_seconds").set(uptime_f);

    #[allow(clippy::cast_precision_loss)]
    let sessions_active = app.sessions.len() as f64;
    metrics::gauge!("raven_railgun_sessions_active").set(sessions_active);
    #[allow(clippy::cast_precision_loss)]
    let permits_avail = app.semaphore.available_permits() as f64;
    metrics::gauge!("raven_railgun_semaphore_permits_available").set(permits_avail);

    let instances = app.engine.instances();
    let per_instance = app.instance_metrics.read().clone();
    for instance in &instances {
        let instance_id = instance.id.as_str().to_owned();
        emit_per_instance_engine_gauges(&instance_id, instance);

        if let Some(consumer) = per_instance.get(&instance.id) {
            let snap = *consumer.lock();
            emit_instance_consumer_gauges(&instance_id, &snap);
        }
    }
}

fn emit_per_instance_engine_gauges<S: raven_railgun_engine::PirScheme>(
    instance_id: &str,
    instance: &raven_railgun_engine::PirInstance<S>,
) {
    let label = instance_id.to_owned();
    let drain = instance.drain_state();
    #[allow(clippy::cast_precision_loss)]
    let drain_val = f64::from(u8::from(drain.is_active()));
    metrics::gauge!(
        "raven_railgun_drain_state",
        "instance" => label.clone(),
        "label" => drain.label(),
    )
    .set(drain_val);

    #[allow(clippy::cast_precision_loss)]
    let in_flight_f = instance.in_flight_count() as f64;
    metrics::gauge!(
        "raven_railgun_in_flight",
        "instance" => label.clone()
    )
    .set(in_flight_f);

    let epoch = instance.current_epoch();
    #[allow(clippy::cast_precision_loss)]
    let epoch_f = epoch.0 as f64;
    metrics::gauge!(
        "raven_railgun_epoch",
        "instance" => label.clone()
    )
    .set(epoch_f);

    let role = instance.role();
    metrics::gauge!(
        "raven_railgun_role",
        "instance" => label,
        "label" => role.label(),
    )
    .set(1.0);
}

fn emit_instance_consumer_gauges(
    instance_id: &str,
    snap: &raven_railgun_engine::persistence::ConsumerMetrics,
) {
    let label = instance_id.to_owned();
    #[allow(clippy::cast_precision_loss)]
    let to_f = |v: u64| v as f64;
    metrics::gauge!(
        "raven_railgun_consumer_last_applied_block",
        "instance" => label.clone()
    )
    .set(to_f(snap.last_applied_block));
    metrics::gauge!(
        "raven_railgun_consumer_last_scanned_block",
        "instance" => label.clone()
    )
    .set(to_f(snap.last_scanned_block));
    metrics::gauge!(
        "raven_railgun_consumer_last_known_chain_head",
        "instance" => label.clone()
    )
    .set(to_f(snap.last_known_chain_head));
    metrics::gauge!(
        "raven_railgun_consumer_indexer_lag_blocks",
        "instance" => label.clone()
    )
    .set(to_f(snap.indexer_lag_blocks()));
    metrics::gauge!(
        "raven_railgun_consumer_blocks_since_last_applied_event",
        "instance" => label.clone()
    )
    .set(to_f(snap.blocks_since_last_applied_event()));
    metrics::gauge!(
        "raven_railgun_consumer_events_processed",
        "instance" => label.clone()
    )
    .set(to_f(snap.events_processed));
    metrics::gauge!(
        "raven_railgun_consumer_commits_fired",
        "instance" => label.clone()
    )
    .set(to_f(snap.commits_fired));
    metrics::gauge!(
        "raven_railgun_consumer_reorgs_handled",
        "instance" => label.clone()
    )
    .set(to_f(snap.reorgs_handled));
    metrics::gauge!(
        "raven_railgun_consumer_errors",
        "instance" => label.clone()
    )
    .set(to_f(snap.consumer_errors));
    // The two signals that stay honest when leaf application wedges: every other
    // gauge here is advanced by any event, including ones that never touch the tree.
    metrics::gauge!(
        "raven_railgun_consumer_last_applied_leaf_block",
        "instance" => label.clone()
    )
    .set(to_f(snap.last_applied_leaf_block));
    metrics::gauge!(
        "raven_railgun_consumer_consecutive_event_errors",
        "instance" => label.clone()
    )
    .set(to_f(snap.consecutive_event_errors));
    metrics::gauge!(
        "raven_railgun_consumer_unapplied_leaves",
        "instance" => label
    )
    .set(to_f(snap.unapplied_leaves));
}

pub(crate) async fn health_live_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "ok",
    )
}

/// JSON body returned by `GET /v1/health/ready`.
#[derive(Serialize, Deserialize, Debug)]
pub struct HealthReadyResponse {
    /// `"ready"` on 200, `"not_ready"` on 503.
    pub status: String,
    /// Number of registered PIR instances.
    pub instances: usize,
    /// Consumer metrics; omitted when not wired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer: Option<HealthConsumerView>,
    /// `"subscribe"` or `"polling"`; omitted when not wired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_source_mode: Option<String>,
    /// RPC pool snapshot; omitted for single-endpoint deployments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_pool: Option<RpcPoolHealthView>,
    /// Instances whose tree the Layer 2 verifier proved out of sync and could
    /// not repair. Non-empty forces 503.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub layer2_divergent_instances: Vec<String>,
    /// Instances whose last WAL replay left an entry unapplied, so the served
    /// tree is behind its own WAL. Non-empty forces 503.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wal_replay_skipped_instances: Vec<String>,
    /// Instances whose consumer has dropped every event since its last applied
    /// one, so the served tree is missing chain state. Non-empty forces 503.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stalled_consumer_instances: Vec<String>,
    /// Routing targets not currently receiving events: no route accepts them, or the
    /// bound consumer's channel is gone. Non-empty forces 503.
    ///
    /// The mark is self-healing — a delivery clears it — so this gates readiness without
    /// latching on the ordinary block rollover, where a fully provisioned list misses for
    /// exactly one event while the next block's route is installed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub router_unrouted_targets: Vec<String>,
    /// One entry per mirrored PPOI list; omitted when no feed is wired. A list in
    /// [`MirrorFeedState::NeverFed`] or [`MirrorFeedState::Stopped`] forces 503.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mirror_feeds: Vec<MirrorFeedView>,
    /// Per instance, commits since process start whose snapshot was published but whose
    /// retention pass failed, leaving superseded snapshots on disk. Does not gate readiness:
    /// the node still serves, and the count is for a disk alert.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub retention_failures: std::collections::BTreeMap<String, u64>,
}

/// Where one PPOI list's upstream feed stands. The first that applies, in this order.
///
/// The HTTP status carries the two that fail readiness, so `curl -f` in a container
/// HEALTHCHECK reports them as unhealthy. It carries the other three as ready, and `curl` then
/// prints the body, so the container's health log still records which one it was.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MirrorFeedState {
    /// The feed stopped for good, so the list cannot advance until a restart. Fails readiness.
    Stopped,
    /// No instance on the list holds a row: every query would read as absent. Fails readiness,
    /// including when upstream answers with an empty list, which is what a wrong list key gets.
    NeverFed,
    /// The node holds rows and upstream's last request failed. Readiness holds: the rows served
    /// are still upstream's, and only rows newer than the last answer are missing. Taking the
    /// node out would make a third party's outage this node's outage.
    UpstreamRefusing,
    /// Upstream's last answer was short of a full page, and every row it held is applied in
    /// every instance that holds its index. Healthy and idle. This is the trigger to wait for
    /// before stopping the process to export a snapshot: a graceful stop then commits every row
    /// upstream had.
    CaughtUp,
    /// The node holds rows and is still paging toward upstream's tip, or applying the rows its
    /// last answer delivered.
    Syncing,
}

impl MirrorFeedState {
    /// Whether this state takes the node out of rotation.
    #[must_use]
    pub const fn fails_readiness(self) -> bool {
        matches!(self, Self::Stopped | Self::NeverFed)
    }
}

/// One PPOI list's upstream feed in [`HealthReadyResponse`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct MirrorFeedView {
    /// Lowercase hex list key.
    pub list_key: String,
    /// See [`MirrorFeedState`].
    pub state: MirrorFeedState,
    /// One past the highest list-wide index any instance on the list has applied.
    pub rows_held: u64,
    /// Upstream's row count as of its last answer, when that answer was short of a full page.
    pub upstream_rows: Option<u64>,
    /// Upstream's row count as its latest answers give it, taken or not: exact after a page
    /// that shows where the list ends, else the larger of one past the last row served and
    /// the count upstream's node status last stated. `upstream_rows_seen - rows_held` is how
    /// far the node trails upstream while it syncs, while upstream refuses and while the node
    /// is still applying. Unsigned by upstream, so no state here rests on it.
    pub upstream_rows_seen: Option<u64>,
    /// List-wide index the feed asks upstream for next.
    pub next_index: u64,
    /// Requests upstream has failed since it last answered.
    pub consecutive_failures: u64,
    /// Class of the latest failure, naming no endpoint; `None` once upstream answers.
    pub last_failure: Option<String>,
    /// Seconds since upstream last answered; `None` if it has not in this process.
    pub seconds_since_answer: Option<u64>,
}

/// Indexer-consumer view in [`HealthReadyResponse`]; the same node-level merge as `/v1/status`.
#[derive(Serialize, Deserialize, Debug)]
pub struct HealthConsumerView {
    /// Saturating chain-tip-minus-scanned lag in blocks.
    pub indexer_lag_blocks: u64,
    /// Last applied block height.
    pub last_applied_block: u64,
    /// Highest scanned block height.
    pub last_scanned_block: u64,
    /// Last known chain tip.
    pub last_known_chain_head: u64,
    /// Saturating chain-tip-minus-applied distance in blocks.
    pub blocks_since_last_applied_event: u64,
}

/// RPC pool view in [`HealthReadyResponse`].
#[derive(Serialize, Deserialize, Debug)]
pub struct RpcPoolHealthView {
    /// Per-endpoint health rows in pool order.
    pub endpoints: Vec<RpcEndpointHealthView>,
}

/// Per-endpoint health row in [`RpcPoolHealthView`].
#[derive(Serialize, Deserialize, Debug)]
pub struct RpcEndpointHealthView {
    /// Host-only URL (API key redacted).
    pub url: String,
    /// `"healthy"`, `"degraded"`, or `"cooling_down"`.
    pub status: String,
    /// In-flight requests at snapshot time (informational).
    pub in_flight: u32,
    /// Steady-state RPS cap.
    pub rps: u32,
    /// Burst cap.
    pub burst: u32,
}

/// Whether this consumer must be taken out of rotation.
///
/// Two conditions, and they answer different questions. `consecutive_event_errors > 0` means
/// every event since the last applied one has failed; it is self-healing on purpose, because
/// a single transient failure that the next event fixes is not an outage. `unapplied_leaves > 0`
/// means a per-leaf loop broke and left leaves behind, so the tree has a contiguity gap that no
/// unrelated success repairs - only a reorg rewind does.
///
/// Neither number is a tuned threshold. One failed event is a real failure and one abandoned
/// leaf is a real gap, so the comparison is against zero because zero is the whole of the safe
/// set, not because zero was picked from a range.
fn consumer_is_stalled(m: &raven_railgun_engine::persistence::ConsumerMetrics) -> bool {
    m.consecutive_event_errors > 0
        || m.unapplied_leaves > 0
        || m.indexer_lag_blocks() >= crate::FRESHNESS_HORIZON_BLOCKS
}

/// Instances whose consumer has failed every event since its last applied one, or is carrying
/// leaves a broken per-leaf loop abandoned.
///
/// Reads the same cells the consumer tasks mutate. An instance without a cell counts as stalled
/// only when consumer telemetry is required.
fn stalled_consumer_instances<S: PirScheme>(app: &AppState<S>) -> Vec<String> {
    let instances = app.engine.instances();
    let per_instance = app.instance_metrics.read().clone();
    let mut stalled: Vec<String> = instances
        .iter()
        .filter(|instance| match per_instance.get(&instance.id) {
            Some(cell) => consumer_is_stalled(&cell.lock()),
            None => app.consumer_metrics_required,
        })
        .map(|instance| instance.id.as_str().to_owned())
        .collect();
    stalled.sort();
    stalled
}

pub(crate) async fn health_ready_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
) -> impl IntoResponse {
    let instance_count = app.engine.instances().len();
    if instance_count == 0 {
        let body = HealthReadyResponse {
            status: "not_ready".to_owned(),
            instances: 0,
            consumer: None,
            chain_source_mode: None,
            rpc_pool: None,
            layer2_divergent_instances: Vec::new(),
            wal_replay_skipped_instances: Vec::new(),
            stalled_consumer_instances: Vec::new(),
            router_unrouted_targets: Vec::new(),
            mirror_feeds: Vec::new(),
            retention_failures: raven_railgun_engine::persistence::retention_failures(),
        };
        return (StatusCode::SERVICE_UNAVAILABLE, Json(body));
    }
    let unrouted_targets = raven_railgun_engine::orchestrator::router_unrouted_targets();
    let divergent = raven_railgun_engine::persistence::layer2_divergent_instances();
    let replay_skipped = raven_railgun_engine::persistence::wal_replay_skipped_instances();
    let stalled = stalled_consumer_instances(&app);
    let mirror_feeds = app
        .mirror_feeds
        .as_ref()
        .map(|probe| probe())
        .unwrap_or_default();
    let consumer = node_consumer_status(&app).map(|merged| HealthConsumerView {
        indexer_lag_blocks: merged.indexer_lag_blocks,
        last_applied_block: merged.last_applied_block,
        last_scanned_block: merged.last_scanned_block,
        last_known_chain_head: merged.last_known_chain_head,
        blocks_since_last_applied_event: merged.blocks_since_last_applied_event,
    });
    let chain_source_mode = app
        .chain_source_mode
        .as_ref()
        .as_ref()
        .map(|flag| match flag.get() {
            raven_railgun_indexer::ChainSourceMode::Subscribe => "subscribe".to_owned(),
            raven_railgun_indexer::ChainSourceMode::Polling => "polling".to_owned(),
        });
    let rpc_pool = app
        .rpc_pool
        .as_ref()
        .as_ref()
        .map(build_rpc_pool_health_view);
    // Known divergence fails closed: the tree this endpoint would answer from is
    // provably not the chain's, not even its own WAL's, missing every event its consumer
    // has dropped since the last one it applied, or missing events no route accepts.
    //
    // The last of those gates safely only because the mark is self-healing. Route
    // installation is ASYNCHRONOUS -- auto-spawn reacts to an observed key and publishes
    // the route afterwards -- so a newly observed tree, and every list crossing a block
    // boundary, legitimately misses for a short window. A latching mark would turn that
    // routine window into a permanent 503; a mark the next delivery clears does not.
    //
    // A mirrored list with no row answers every query as absent, and a stopped feed never
    // advances again; both fail closed. An upstream refusing a node that holds rows does not.
    let (code, status) = if divergent.is_empty()
        && replay_skipped.is_empty()
        && stalled.is_empty()
        && unrouted_targets.is_empty()
        && !mirror_feeds.iter().any(|feed| feed.state.fails_readiness())
    {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not_ready")
    };
    let body = HealthReadyResponse {
        status: status.to_owned(),
        instances: instance_count,
        consumer,
        chain_source_mode,
        rpc_pool,
        layer2_divergent_instances: divergent,
        wal_replay_skipped_instances: replay_skipped,
        stalled_consumer_instances: stalled,
        router_unrouted_targets: unrouted_targets,
        mirror_feeds,
        retention_failures: raven_railgun_engine::persistence::retention_failures(),
    };
    (code, Json(body))
}

fn build_rpc_pool_health_view(
    pool: &Arc<raven_railgun_indexer::rpc_pool::RpcEndpointPool>,
) -> RpcPoolHealthView {
    let endpoints = pool
        .health_snapshot()
        .into_iter()
        .map(|snap| {
            let status = match snap.health {
                raven_railgun_indexer::rpc_pool::EndpointHealth::Healthy => "healthy",
                raven_railgun_indexer::rpc_pool::EndpointHealth::Degraded => "degraded",
                raven_railgun_indexer::rpc_pool::EndpointHealth::CoolingDown { .. } => {
                    "cooling_down"
                }
            };
            RpcEndpointHealthView {
                url: snap.url_redacted,
                status: status.to_owned(),
                in_flight: snap.in_flight,
                rps: snap.rps,
                burst: snap.burst,
            }
        })
        .collect();
    RpcPoolHealthView { endpoints }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{
        build_status_response, health_ready_handler, ConsumerStatus, HealthReadyResponse,
        StatusResponse,
    };
    use crate::config::HttpConfig;
    use crate::state::AppState;
    use axum::extract::State;
    use axum::response::IntoResponse;
    use raven_railgun_core::InstanceId;
    use raven_railgun_engine::persistence::ConsumerMetrics;
    use raven_railgun_engine::persistence::{
        clear_layer2_divergent, clear_wal_replay_skipped, mark_layer2_divergent,
        mark_wal_replay_skipped,
    };
    use raven_railgun_engine::{Engine, InstanceRole, PirInstance, PirScheme};
    use std::collections::HashMap;
    use std::sync::Arc;

    #[derive(Debug, Default)]
    struct StubScheme;
    #[derive(Debug, Default)]
    struct StubState;
    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    struct StubQuery;
    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    struct StubResponse;

    impl PirScheme for StubScheme {
        type ServerState = StubState;
        type Query = StubQuery;
        type Response = StubResponse;
        fn respond(
            _state: &Self::ServerState,
            _query: &Self::Query,
        ) -> raven_railgun_core::Result<Self::Response> {
            Err(raven_railgun_core::AdapterError::Scheme("stub".to_owned()))
        }
        fn state_shape(_state: &Self::ServerState) -> raven_railgun_engine::StateShape {
            raven_railgun_engine::StateShape {
                entry_size_bytes: 1,
                rows_per_shard: u64::MAX,
            }
        }
    }

    fn state_with_one_instance(id: &str) -> AppState<StubScheme> {
        let mut engine: Engine<StubScheme> = Engine::new();
        engine
            .register_instance(Arc::new(PirInstance::new(
                InstanceId::new(id),
                InstanceRole::Live,
                StubState,
            )))
            .expect("register instance");
        AppState::new(engine, HttpConfig::demo("health-gate-token")).expect("appstate")
    }

    async fn ready_probe(app: AppState<StubScheme>) -> (http::StatusCode, HealthReadyResponse) {
        let response = health_ready_handler(State(app)).await.into_response();
        let code = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let body: HealthReadyResponse = serde_json::from_slice(&bytes).expect("decode body");
        (code, body)
    }

    /// Both registries are process-wide, so the two gates share one test rather
    /// than racing each other's probes. `InspirePersistence::open` is what fills
    /// the replay-skip registry in production; the engine-side
    /// `poisoned_wal_replay_skipped_marks_the_instance_unready` covers that half.
    #[tokio::test]
    async fn ready_probe_fails_closed_on_every_known_divergence() {
        const ID: &str = "health-gate-divergent-instance";
        clear_layer2_divergent(ID);
        clear_wal_replay_skipped(ID);

        let (code, body) = ready_probe(state_with_one_instance(ID)).await;
        assert_eq!(
            code,
            http::StatusCode::OK,
            "a registered instance with no divergence must be ready"
        );
        assert_eq!(body.status, "ready");
        assert!(body.layer2_divergent_instances.is_empty());
        assert!(body.wal_replay_skipped_instances.is_empty());

        mark_layer2_divergent(ID);
        let (code, body) = ready_probe(state_with_one_instance(ID)).await;
        assert_eq!(
            code,
            http::StatusCode::SERVICE_UNAVAILABLE,
            "a known Layer 2 divergence must take the endpoint out of rotation"
        );
        assert_eq!(body.status, "not_ready");
        assert_eq!(body.layer2_divergent_instances, vec![ID.to_owned()]);

        clear_layer2_divergent(ID);
        let (code, body) = ready_probe(state_with_one_instance(ID)).await;
        assert_eq!(
            code,
            http::StatusCode::OK,
            "clearing the divergence must restore readiness"
        );
        assert!(body.layer2_divergent_instances.is_empty());

        // A target no route accepts must take the endpoint out of rotation, and a
        // delivery must put it back: the mark is self-healing, which is what makes
        // gating on it safe across a block rollover.
        let target = "list:health-gate-router-drop";
        raven_railgun_engine::orchestrator::clear_router_unrouted_target(target);
        raven_railgun_engine::orchestrator::mark_router_unrouted_target(target);
        let (code, body) = ready_probe(state_with_one_instance(ID)).await;
        assert_eq!(
            code,
            http::StatusCode::SERVICE_UNAVAILABLE,
            "a target that is not currently receiving events must fail readiness closed"
        );
        assert_eq!(body.status, "not_ready");
        assert_eq!(body.router_unrouted_targets, vec![target.to_owned()]);

        raven_railgun_engine::orchestrator::clear_router_unrouted_target(target);
        let (code, body) = ready_probe(state_with_one_instance(ID)).await;
        assert_eq!(
            code,
            http::StatusCode::OK,
            "a delivery clears the mark, so readiness returns without a restart -- the \
             property that makes this gate safe on the ordinary block rollover"
        );
        assert!(body.router_unrouted_targets.is_empty());

        mark_wal_replay_skipped(ID);
        let (code, body) = ready_probe(state_with_one_instance(ID)).await;
        assert_eq!(
            code,
            http::StatusCode::SERVICE_UNAVAILABLE,
            "a tree behind its own WAL must take the endpoint out of rotation"
        );
        assert_eq!(body.status, "not_ready");
        assert_eq!(body.wal_replay_skipped_instances, vec![ID.to_owned()]);

        clear_wal_replay_skipped(ID);
        let (code, body) = ready_probe(state_with_one_instance(ID)).await;
        assert_eq!(
            code,
            http::StatusCode::OK,
            "clearing the replay-skip mark must restore readiness"
        );
        assert!(body.wal_replay_skipped_instances.is_empty());
    }

    type Cell = Arc<parking_lot::Mutex<ConsumerMetrics>>;

    fn cell(m: ConsumerMetrics) -> Cell {
        Arc::new(parking_lot::Mutex::new(m))
    }

    fn state_with(ids: &[&str]) -> AppState<StubScheme> {
        let mut engine: Engine<StubScheme> = Engine::new();
        for id in ids {
            engine
                .register_instance(Arc::new(PirInstance::new(
                    InstanceId::new(*id),
                    InstanceRole::Static,
                    StubState,
                )))
                .expect("register instance");
        }
        AppState::new(engine, HttpConfig::demo("status-counter-token"))
            .expect("appstate")
            .require_consumer_metrics()
    }

    fn per_instance(pairs: &[(&str, &Cell)]) -> HashMap<InstanceId, Cell> {
        pairs
            .iter()
            .map(|(id, c)| (InstanceId::new(*id), Arc::clone(c)))
            .collect()
    }

    /// A sealed mirror block, as the first instance on a mainnet-shaped node: nothing to ingest.
    fn sealed() -> ConsumerMetrics {
        ConsumerMetrics {
            commits_fired: 1,
            ..ConsumerMetrics::default()
        }
    }

    /// The live mirror block: mirror rows carry height 0, so only the counters move.
    fn live() -> ConsumerMetrics {
        ConsumerMetrics {
            events_processed: 5_400,
            commits_fired: 3,
            consumer_errors: 2,
            ..ConsumerMetrics::default()
        }
    }

    fn assert_reports_the_ingesting_instance(status: &StatusResponse, live_id: &str) {
        let node = status.consumer.as_ref().expect("node consumer block");
        assert_eq!(
            node.events_processed, 5_400,
            "the node block must count what the live instance ingests"
        );
        assert_eq!(node.commits_fired, 4);
        assert_eq!(node.consumer_errors, 2);
        let row = status
            .instances
            .iter()
            .find(|row| row.id == live_id)
            .expect("live row");
        assert_eq!(
            row.consumer.as_ref().map(|c| c.events_processed),
            Some(5_400)
        );
    }

    #[test]
    fn status_counts_the_live_instance_when_the_first_is_sealed() {
        const SEALED: &str = "status-counter-ofac-0";
        const LIVE: &str = "status-counter-ofac-6";
        let (sealed, live) = (cell(sealed()), cell(live()));
        let app = state_with(&[SEALED, LIVE])
            .with_instance_metrics(per_instance(&[(SEALED, &sealed), (LIVE, &live)]));

        let status = build_status_response(&app);
        assert_reports_the_ingesting_instance(&status, LIVE);
        assert_eq!(
            status.instances[0]
                .consumer
                .as_ref()
                .map(|c| c.events_processed),
            Some(0),
            "the sealed row keeps its own number"
        );

        // Planted control: a report of the first instance's cell alone fails the same check.
        let first_cell = ConsumerStatus::of(&sealed.lock());
        let old = StatusResponse {
            consumer: Some(first_cell),
            ..build_status_response(&app)
        };
        let caught = std::panic::catch_unwind(|| assert_reports_the_ingesting_instance(&old, LIVE));
        assert!(
            caught.is_err(),
            "the check must reject the first-instance report"
        );
        assert_eq!(old.consumer.map(|c| c.events_processed), Some(0));
    }

    #[test]
    fn node_lag_is_the_worst_instance_and_recency_the_newest() {
        const AHEAD: &str = "status-counter-ahead";
        const BEHIND: &str = "status-counter-behind";
        let ahead = cell(ConsumerMetrics {
            last_known_chain_head: 1_000,
            last_scanned_block: 1_000,
            last_applied_block: 990,
            ..ConsumerMetrics::default()
        });
        let behind = cell(ConsumerMetrics {
            last_known_chain_head: 1_000,
            last_scanned_block: 700,
            last_applied_block: 650,
            ..ConsumerMetrics::default()
        });
        let app = state_with(&[AHEAD, BEHIND])
            .with_instance_metrics(per_instance(&[(AHEAD, &ahead), (BEHIND, &behind)]));
        let node = build_status_response(&app).consumer.expect("node block");
        assert_eq!(
            node.indexer_lag_blocks, 300,
            "a healthy scanner must not hide a stuck one"
        );
        assert_eq!(node.blocks_since_last_applied_event, 10);
        assert_eq!(node.last_scanned_block, 1_000);
        assert_eq!(node.last_applied_block, 990);
    }

    #[test]
    fn a_cell_shared_by_two_instances_counts_once() {
        const A: &str = "status-counter-shared-a";
        const B: &str = "status-counter-shared-b";
        let shared = cell(live());
        let app =
            state_with(&[A, B]).with_instance_metrics(per_instance(&[(A, &shared), (B, &shared)]));
        let node = build_status_response(&app).consumer.expect("node block");
        assert_eq!(node.events_processed, 5_400);

        // Planted control: two distinct cells with the same numbers do add up.
        let other = cell(live());
        let app =
            state_with(&[A, B]).with_instance_metrics(per_instance(&[(A, &shared), (B, &other)]));
        let node = build_status_response(&app).consumer.expect("node block");
        assert_eq!(node.events_processed, 10_800);
    }

    #[test]
    fn an_unwired_node_reports_no_consumer_block() {
        const ONLY: &str = "status-counter-single-a";
        let unwired = build_status_response(&state_with(&[ONLY]));
        let json = serde_json::to_value(&unwired).expect("json");
        assert!(json.get("consumer").is_none());
        assert!(json["instances"][0].get("consumer").is_none());
    }

    #[tokio::test]
    async fn readiness_keeps_its_meaning_and_reports_the_same_block() {
        const SEALED: &str = "status-counter-ready-ofac-0";
        const LIVE: &str = "status-counter-ready-ofac-6";
        let (sealed, live) = (cell(sealed()), cell(live()));
        // Heights only the live instance has, so a first-cell view cannot pass by accident.
        {
            let mut m = live.lock();
            m.last_known_chain_head = 500;
            m.last_scanned_block = 500;
            m.last_applied_block = 480;
        }
        let app = state_with(&[SEALED, LIVE])
            .with_instance_metrics(per_instance(&[(SEALED, &sealed), (LIVE, &live)]));

        let (code, body) = ready_probe(app.clone()).await;
        assert_eq!(code, http::StatusCode::OK);
        let node = build_status_response(&app).consumer.expect("node block");
        let view = body.consumer.expect("health consumer view");
        assert_eq!(view.last_applied_block, 480);
        assert_eq!(view.indexer_lag_blocks, node.indexer_lag_blocks);
        assert_eq!(view.last_applied_block, node.last_applied_block);
        assert_eq!(
            view.blocks_since_last_applied_event,
            node.blocks_since_last_applied_event
        );

        // The gate stays per instance: a stalled live block still fails, and is named.
        live.lock().consecutive_event_errors = 1;
        let (code, body) = ready_probe(app.clone()).await;
        assert_eq!(code, http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.stalled_consumer_instances, vec![LIVE.to_owned()]);

        // And an instance without telemetry still fails closed under the production flag.
        let app =
            state_with(&[SEALED, LIVE]).with_instance_metrics(per_instance(&[(SEALED, &sealed)]));
        let (code, body) = ready_probe(app).await;
        assert_eq!(code, http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.stalled_consumer_instances, vec![LIVE.to_owned()]);
    }

    #[test]
    fn metrics_carry_the_live_instance_under_the_same_names() {
        const SEALED: &str = "status-counter-metrics-ofac-0";
        const LIVE: &str = "status-counter-metrics-ofac-6";
        let (sealed, live) = (cell(sealed()), cell(live()));
        let app = state_with(&[SEALED, LIVE])
            .with_instance_metrics(per_instance(&[(SEALED, &sealed), (LIVE, &live)]));
        super::refresh_dynamic_metrics(&app);
        let body = app.metrics_handle.render();
        let line = |id: &str| {
            body.lines()
                .find(|l| {
                    l.starts_with("raven_railgun_consumer_events_processed{")
                        && l.contains(&format!("instance=\"{id}\""))
                })
                .map(str::to_owned)
        };
        assert!(line(LIVE).is_some_and(|l| l.ends_with(" 5400")), "{body}");
        assert!(line(SEALED).is_some_and(|l| l.ends_with(" 0")), "{body}");
    }
}
