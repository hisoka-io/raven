//! Status, metrics, and health-probe handlers.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use raven_railgun_engine::inspire::RavenInspireScheme;
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
    /// `"static"`, `"live"`, or `"sidecar"` — observational only, does not affect routing.
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
    /// Last block height reported as the chain tip.
    pub last_known_chain_head: u64,
    /// `last_known_chain_head - last_applied_block`, saturating at 0.
    pub indexer_lag_blocks: u64,
    /// Total chain events applied since process start.
    pub events_processed: u64,
    /// Total snapshot commits driven.
    pub commits_fired: u64,
    /// Total chain reorgs handled.
    pub reorgs_handled: u64,
    /// Per-event errors the consumer continued past. Alert when rising while `events_processed` stalls.
    pub consumer_errors: u64,
}

pub(crate) async fn status_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
) -> Json<StatusResponse> {
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
            last_known_chain_head: snap.last_known_chain_head,
            indexer_lag_blocks: snap.indexer_lag_blocks(),
            events_processed: snap.events_processed,
            commits_fired: snap.commits_fired,
            reorgs_handled: snap.reorgs_handled,
            consumer_errors: snap.consumer_errors,
        }
    });
    Json(StatusResponse {
        scheme: (*app.scheme_name).clone(),
        instances,
        consumer,
    })
}

pub(crate) async fn metrics_handler(
    State(app): State<AppState<RavenInspireScheme>>,
) -> impl IntoResponse {
    let body = app.metrics_handle.render();
    (
        StatusCode::OK,
        [(http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
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
}

/// Indexer-consumer view in [`HealthReadyResponse`].
#[derive(Serialize, Deserialize, Debug)]
pub struct HealthConsumerView {
    /// Saturating lag in blocks.
    pub indexer_lag_blocks: u64,
    /// Last applied block height.
    pub last_applied_block: u64,
    /// Last known chain tip.
    pub last_known_chain_head: u64,
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
        };
        return (StatusCode::SERVICE_UNAVAILABLE, Json(body));
    }
    let consumer = app.consumer_metrics.as_ref().as_ref().map(|m| {
        let snap = *m.lock();
        HealthConsumerView {
            indexer_lag_blocks: snap.indexer_lag_blocks(),
            last_applied_block: snap.last_applied_block,
            last_known_chain_head: snap.last_known_chain_head,
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
    let body = HealthReadyResponse {
        status: "ready".to_owned(),
        instances: instance_count,
        consumer,
        chain_source_mode,
        rpc_pool,
    };
    (StatusCode::OK, Json(body))
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
