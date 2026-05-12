//! Single-query and batch handlers, plus the cross-query dispatcher.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use bytes::Bytes;
use raven_railgun_core::InstanceId;
use raven_railgun_engine::{DrainState, PirInstance, PirScheme, Snapshot};
use tokio::sync::Semaphore;

use crate::state::AppState;
use crate::versioned::{read_versioned, write_batch_response_versioned, write_versioned};
use crate::{attach_freshness_header, build_response_headers};

pub(crate) async fn query_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Bytes), StatusCode> {
    let instance_id = InstanceId::new(id);
    let instance = app
        .engine
        .instance(&instance_id)
        .ok_or(StatusCode::NOT_FOUND)?;
    if instance.drain_state() != DrainState::Active {
        tracing::info!(
            instance_id = %instance.id,
            drain_state = instance.drain_state().label(),
            "query refused: instance is not active"
        );
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    let permit = app
        .semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let query: S::Query = read_versioned(&body).map_err(|err| {
        tracing::warn!(?err, "query versioned-bincode deserialize failed");
        StatusCode::BAD_REQUEST
    })?;

    let started = Instant::now();
    let respond_timeout = Duration::from_secs(app.config.respond_timeout_secs.max(1));
    // spawn_blocking + timeout: pathological queries release their permit instead of
    // blocking subsequent requests indefinitely (AUDIT fix).
    let instance_clone = Arc::clone(&instance);
    let join = tokio::task::spawn_blocking(move || instance_clone.query_active_tracked(&query));
    let (epoch, response) = match tokio::time::timeout(respond_timeout, join).await {
        Ok(Ok(Ok(pair))) => pair,
        Ok(Ok(Err(raven_railgun_core::AdapterError::NoActiveInstance { instance_id: id }))) => {
            tracing::info!(
                instance_id = %id,
                "single-query refused: instance drained mid-acquire"
            );
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        Ok(Ok(Err(err))) => {
            tracing::error!(?err, "single-query respond failed");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        Ok(Err(join_err)) => {
            tracing::error!(error = %join_err, "single-query worker panicked");
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        Err(_elapsed) => {
            tracing::warn!(
                secs = respond_timeout.as_secs(),
                "single-query respond timed out"
            );
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    let elapsed = started.elapsed();
    drop(permit);

    metrics::histogram!(
        "raven_railgun_respond_seconds",
        "instance" => instance_id.to_string(),
        "kind" => "single"
    )
    .record(elapsed.as_secs_f64());
    metrics::counter!(
        "raven_railgun_queries_total",
        "instance" => instance_id.to_string(),
        "kind" => "single"
    )
    .increment(1);

    let body_bytes = write_versioned(&response).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut headers = build_response_headers(epoch.0, &app.scheme_name)?;
    attach_freshness_header(
        &mut headers,
        app.consumer_metrics.as_ref().as_ref().map(AsRef::as_ref),
        epoch.0,
    );
    Ok((StatusCode::OK, headers, body_bytes.into()))
}

pub(crate) async fn batch_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Bytes), StatusCode> {
    let instance_id = InstanceId::new(id);
    let instance = app
        .engine
        .instance(&instance_id)
        .ok_or(StatusCode::NOT_FOUND)?;
    if instance.drain_state() != DrainState::Active {
        tracing::info!(
            instance_id = %instance.id,
            drain_state = instance.drain_state().label(),
            "batch refused: instance is not active"
        );
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    let queries: Vec<S::Query> = read_versioned(&body).map_err(|err| {
        tracing::warn!(?err, "batch versioned-bincode deserialize failed");
        StatusCode::BAD_REQUEST
    })?;
    if queries.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let started = Instant::now();
    // Capture `(epoch, state)` ONCE for the whole batch. Every worker
    // dispatched below serves from this exact snapshot, so a 17-row
    // commit-tree path fanout cannot straddle a concurrent
    // `swap_state` and produce a Frankenstein fold root that chain
    // `rootHistory` would reject.
    let snapshot_for_batch = instance.current_snapshot();
    let epoch_at_start = snapshot_for_batch.epoch;

    let k = app.config.max_concurrent_queries.max(1);
    let respond_timeout = Duration::from_secs(app.config.respond_timeout_secs.max(1));

    let responses_result = dispatch_batch::<S>(
        queries,
        Arc::clone(&instance),
        snapshot_for_batch,
        Arc::clone(&app.semaphore),
        k,
        respond_timeout,
    )
    .await;

    let elapsed = started.elapsed();

    let responses = responses_result.map_err(|err| {
        tracing::error!(error = %err, "batch dispatch failed");
        err.status()
    })?;

    metrics::histogram!(
        "raven_railgun_respond_seconds",
        "instance" => instance_id.to_string(),
        "kind" => "batch"
    )
    .record(elapsed.as_secs_f64());
    metrics::counter!(
        "raven_railgun_queries_total",
        "instance" => instance_id.to_string(),
        "kind" => "batch"
    )
    .increment(responses.len() as u64);
    #[allow(clippy::cast_precision_loss)]
    let batch_len_f64 = responses.len() as f64;
    metrics::histogram!(
        "raven_railgun_batch_size",
        "instance" => instance_id.to_string()
    )
    .record(batch_len_f64);

    let body_bytes = write_batch_response_versioned(&responses)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut headers = build_response_headers(epoch_at_start.0, &app.scheme_name)?;
    attach_freshness_header(
        &mut headers,
        app.consumer_metrics.as_ref().as_ref().map(AsRef::as_ref),
        epoch_at_start.0,
    );
    Ok((StatusCode::OK, headers, body_bytes.into()))
}

/// Failure mode of a [`dispatch_batch`] call.
#[derive(Debug, thiserror::Error)]
pub enum BatchError {
    /// `S::respond` returned a typed error at `index`.
    #[error("respond failed at index {index}: {detail}")]
    Respond {
        /// 0-based slot index.
        index: usize,
        /// Display-formatted scheme error.
        detail: String,
    },
    /// Per-query timeout fired; permits are released on `Elapsed`.
    #[error("respond timed out at index {index} after {secs}s")]
    Timeout {
        /// 0-based slot index.
        index: usize,
        /// Timeout budget in seconds.
        secs: u64,
    },
    /// `spawn_blocking` panicked or was cancelled.
    #[error("worker task aborted at index {index}")]
    WorkerAborted {
        /// 0-based slot index.
        index: usize,
    },
    /// Semaphore closed (graceful shutdown path).
    #[error("concurrency semaphore closed")]
    SemaphoreClosed,
    /// Internal post-condition violation; should never fire.
    #[error("invariant: {0}")]
    Invariant(&'static str),
}

impl BatchError {
    /// Map to HTTP status: `Respond`/`Invariant` → 500; others → 503.
    pub fn status(&self) -> StatusCode {
        match self {
            BatchError::Respond { .. } | BatchError::Invariant(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            BatchError::WorkerAborted { .. }
            | BatchError::SemaphoreClosed
            | BatchError::Timeout { .. } => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// Low-cardinality class label safe to log (avoids echoing attacker-influenced detail strings).
    pub fn class(&self) -> &'static str {
        match self {
            BatchError::Respond { .. } => "respond",
            BatchError::Timeout { .. } => "timeout",
            BatchError::WorkerAborted { .. } => "worker_aborted",
            BatchError::SemaphoreClosed => "semaphore_closed",
            BatchError::Invariant(_) => "invariant",
        }
    }
}

type WorkerOutcome<R> = (usize, Result<R, BatchError>);

/// Cross-query K-concurrent dispatcher.
///
/// Uses `tokio::task::JoinSet` of K `spawn_blocking` workers. `rayon::par_iter`
/// regresses ~2x on the HTTP path when nested inside `spawn_blocking`
/// (see `research/K4_HTTP_DISPATCHER_BENCH.md`).
/// Returns responses in input order; short-circuits on first error.
///
/// Every worker spawned below borrows the same `Arc<Snapshot<S>>` so all
/// rows in the batch are byte-for-byte served from the SAME `(epoch, state)`
/// pair, even if a concurrent `swap_state` fires mid-batch.
pub(crate) async fn dispatch_batch<S: PirScheme>(
    queries: Vec<S::Query>,
    instance: Arc<PirInstance<S>>,
    snapshot: Arc<Snapshot<S>>,
    semaphore: Arc<Semaphore>,
    k: usize,
    respond_timeout: Duration,
) -> Result<Vec<S::Response>, BatchError> {
    use tokio::task::JoinSet;

    let n = queries.len();
    let mut responses: Vec<Option<S::Response>> = (0..n).map(|_| None).collect();
    let mut join: JoinSet<WorkerOutcome<S::Response>> = JoinSet::new();

    let mut next_idx = 0usize;
    let mut queries_iter: std::vec::IntoIter<S::Query> = queries.into_iter();

    while next_idx < k.min(n) {
        let Some(q) = queries_iter.next() else {
            break;
        };
        let inst = Arc::clone(&instance);
        let sem = Arc::clone(&semaphore);
        let snap = Arc::clone(&snapshot);
        let idx = next_idx;
        join.spawn(async move { worker::<S>(idx, q, inst, snap, sem, respond_timeout).await });
        next_idx += 1;
    }

    let mut first_error: Option<BatchError> = None;
    while let Some(joined) = join.join_next().await {
        let outcome = match joined {
            Ok(o) => o,
            Err(join_err) => {
                let detail = format!("{join_err}");
                tracing::warn!(error = %detail, "JoinSet task panicked / aborted");
                if first_error.is_none() {
                    first_error = Some(BatchError::WorkerAborted { index: usize::MAX });
                }
                continue;
            }
        };
        let (idx, res) = outcome;
        match res {
            Ok(r) if first_error.is_none() => {
                if let Some(slot) = responses.get_mut(idx) {
                    *slot = Some(r);
                } else {
                    first_error = Some(BatchError::Invariant("response idx out of range"));
                }
            }
            Ok(_) => {
                tracing::warn!(
                    dropped_idx = idx,
                    "dropped successful sibling response after batch error short-circuit"
                );
            }
            Err(e) => {
                // Log class+index only; `Respond { detail }` may carry attacker-influenced text.
                tracing::warn!(
                    failed_idx = idx,
                    class = e.class(),
                    "batch worker returned error"
                );
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
        if first_error.is_none() {
            if let Some(q) = queries_iter.next() {
                let inst = Arc::clone(&instance);
                let sem = Arc::clone(&semaphore);
                let snap = Arc::clone(&snapshot);
                let idx = next_idx;
                join.spawn(
                    async move { worker::<S>(idx, q, inst, snap, sem, respond_timeout).await },
                );
                next_idx += 1;
            }
        }
    }

    if let Some(e) = first_error {
        return Err(e);
    }
    let collected: Option<Vec<S::Response>> = responses.into_iter().collect();
    collected.ok_or(BatchError::Invariant("response collect produced None"))
}

/// One in-flight batch worker. Acquires a permit, runs
/// `query_active_tracked_with_snapshot` against the batch-captured
/// `Arc<Snapshot<S>>` on `spawn_blocking` under `tokio::time::timeout`.
/// Permit is released on timeout.
async fn worker<S: PirScheme>(
    idx: usize,
    q: S::Query,
    instance: Arc<PirInstance<S>>,
    snapshot: Arc<Snapshot<S>>,
    sem: Arc<Semaphore>,
    respond_timeout: Duration,
) -> WorkerOutcome<S::Response> {
    let Ok(_permit) = sem.acquire_owned().await else {
        return (idx, Err(BatchError::SemaphoreClosed));
    };
    let join = tokio::task::spawn_blocking(move || {
        instance.query_active_tracked_with_snapshot(&snapshot, &q)
    });
    match tokio::time::timeout(respond_timeout, join).await {
        Ok(Ok(Ok((_epoch, r)))) => (idx, Ok(r)),
        Ok(Ok(Err(scheme_err))) => (
            idx,
            Err(BatchError::Respond {
                index: idx,
                detail: format!("{scheme_err}"),
            }),
        ),
        Ok(Err(_)) => (idx, Err(BatchError::WorkerAborted { index: idx })),
        Err(_elapsed) => (
            idx,
            Err(BatchError::Timeout {
                index: idx,
                secs: respond_timeout.as_secs(),
            }),
        ),
    }
}
