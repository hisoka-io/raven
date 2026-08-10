//! Status, metrics, and health-probe handlers.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
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
    /// Consumer metrics; omitted when not wired.
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
}

/// Live consumer-task metrics; mirrors [`raven_railgun_engine::persistence::ConsumerMetrics`].
#[derive(Serialize, Deserialize, Debug)]
pub struct ConsumerStatus {
    /// Last block height applied by the consumer task.
    pub last_applied_block: u64,
    /// Highest block height the indexer has scanned.
    pub last_scanned_block: u64,
    /// Last block height reported as the chain tip.
    pub last_known_chain_head: u64,
    /// `last_known_chain_head - last_scanned_block`, saturating at 0.
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

pub(crate) async fn status_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
) -> Json<StatusResponse> {
    Json(build_status_response(&app))
}

/// Operator-observable engine state, shared by `/v1/status` and `/v1/events`.
pub(crate) fn build_status_response<S: PirScheme>(app: &AppState<S>) -> StatusResponse {
    let fallback_k = u32::try_from(app.config.max_concurrent_queries.max(1)).unwrap_or(u32::MAX);
    let instances = app
        .engine
        .instances()
        .into_iter()
        .map(|inst| InstanceStatus {
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
        })
        .collect();
    let consumer = app.consumer_metrics.as_ref().as_ref().map(|m| {
        let snap = *m.lock();
        ConsumerStatus {
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
    });
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
/// An empty `instance_metrics` falls back to the single cell.
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
    for instance in &instances {
        let instance_id = instance.id.as_str().to_owned();
        emit_per_instance_engine_gauges(&instance_id, instance);

        if let Some(consumer) = app.instance_metrics.get(&instance.id) {
            let snap = *consumer.lock();
            emit_instance_consumer_gauges(&instance_id, &snap);
        }
    }

    if app.instance_metrics.is_empty() {
        if let Some(cell) = app.consumer_metrics.as_ref().as_ref() {
            if let Some(first) = instances.first() {
                let snap = *cell.lock();
                emit_instance_consumer_gauges(first.id.as_str(), &snap);
            }
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
        "instance" => label
    )
    .set(to_f(snap.consumer_errors));
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
}

/// Indexer-consumer view in [`HealthReadyResponse`].
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
        };
        return (StatusCode::SERVICE_UNAVAILABLE, Json(body));
    }
    let divergent = raven_railgun_engine::persistence::layer2_divergent_instances();
    let consumer = app.consumer_metrics.as_ref().as_ref().map(|m| {
        let snap = *m.lock();
        HealthConsumerView {
            indexer_lag_blocks: snap.indexer_lag_blocks(),
            last_applied_block: snap.last_applied_block,
            last_scanned_block: snap.last_scanned_block,
            last_known_chain_head: snap.last_known_chain_head,
            blocks_since_last_applied_event: snap.blocks_since_last_applied_event(),
        }
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
    // provably not the chain's.
    let (code, status) = if divergent.is_empty() {
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
    use super::{health_ready_handler, HealthReadyResponse};
    use crate::config::HttpConfig;
    use crate::state::AppState;
    use axum::extract::State;
    use axum::response::IntoResponse;
    use raven_railgun_core::InstanceId;
    use raven_railgun_engine::persistence::{clear_layer2_divergent, mark_layer2_divergent};
    use raven_railgun_engine::{Engine, InstanceRole, PirInstance, PirScheme};
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

    #[tokio::test]
    async fn ready_probe_fails_closed_while_an_instance_is_layer2_divergent() {
        const ID: &str = "health-gate-divergent-instance";
        clear_layer2_divergent(ID);

        let (code, body) = ready_probe(state_with_one_instance(ID)).await;
        assert_eq!(
            code,
            http::StatusCode::OK,
            "a registered instance with no divergence must be ready"
        );
        assert_eq!(body.status, "ready");
        assert!(body.layer2_divergent_instances.is_empty());

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
    }
}
