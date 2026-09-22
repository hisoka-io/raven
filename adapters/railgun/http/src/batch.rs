//! Single-query and batch handlers, plus the cross-query dispatcher.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use bytes::Bytes;
use raven_inspire::SeededClientQuery;
use raven_railgun_core::batch_ladder::check_batch_len;
use raven_railgun_core::InstanceId;
use raven_railgun_engine::{Engine, PirInstance, PirScheme, Snapshot};
use tokio::sync::Semaphore;

/// Merkle levels carried IN the path-10 row; the rest ride in the addendum.
const PATH10_LEVELS: usize = raven_railgun_engine::pir_table::list::PATH10_LEVELS;
/// Levels 11..15, the upper siblings that are constant across a shard.
const ADDENDUM_LEVELS: usize = raven_railgun_engine::imt::TREE_DEPTH - PATH10_LEVELS;
/// The engine derives the addendum now; this is the width it must hand back. A short one folds to
/// a wrong root, which is the failure this whole path exists to make impossible.
const ADDENDUM_BYTES: usize = ADDENDUM_LEVELS * 32;

use crate::auth::validate_session_binding;
use crate::state::{
    AppState, ADDENDUM_SKEW_STALE_PROVENANCE, ADDENDUM_SKEW_SWAPPED_MID_REQUEST,
    ADDENDUM_SKEW_UNSEEDED,
};
use crate::versioned::{read_versioned, write_batch_response_versioned, write_versioned};
use crate::{attach_freshness_header, build_response_headers};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionRefusal {
    Missing,
    Drained(raven_railgun_engine::DrainState),
    Unavailable,
}

impl AdmissionRefusal {
    pub(crate) const fn status(self) -> StatusCode {
        match self {
            Self::Missing => StatusCode::NOT_FOUND,
            Self::Drained(_) | Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    pub(crate) fn detail(self) -> String {
        match self {
            Self::Missing => "unknown instance".to_owned(),
            Self::Drained(state) => format!("instance is {}", state.label()),
            Self::Unavailable => "instance stopped serving during admission".to_owned(),
        }
    }
}

pub(crate) fn admit_instance<S: PirScheme>(
    engine: &Engine<S>,
    instance_id: &InstanceId,
    operation: &'static str,
) -> Result<Arc<PirInstance<S>>, AdmissionRefusal> {
    let serving = engine.serving_instance(instance_id);
    if serving.is_missing() {
        return Err(AdmissionRefusal::Missing);
    }
    if let Some(state) = serving.drain_state() {
        tracing::info!(
            %operation,
            instance_id = %instance_id,
            drain_state = state.label(),
            "request refused: instance is not active"
        );
        return Err(AdmissionRefusal::Drained(state));
    }
    serving
        .into_available()
        .ok_or(AdmissionRefusal::Unavailable)
}

pub(crate) async fn query_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Bytes), StatusCode> {
    let instance_id = InstanceId::new(id);
    let instance =
        admit_instance(&app.engine, &instance_id, "query").map_err(AdmissionRefusal::status)?;

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
    let instance_clone = Arc::clone(&instance);
    let mut join = tokio::task::spawn_blocking(move || instance_clone.query_active_tracked(&query));
    let (epoch, response) = match tokio::time::timeout(respond_timeout, &mut join).await {
        Ok(Ok(Ok(pair))) => pair,
        Ok(Ok(Err(raven_railgun_core::AdapterError::NoActiveInstance { instance_id: id }))) => {
            tracing::info!(
                instance_id = %id,
                "single-query refused: instance drained mid-acquire"
            );
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        Ok(Ok(Err(err @ raven_railgun_core::AdapterError::SessionHandleRejected { .. }))) => {
            tracing::info!(%err, "single-query refused: session handle is stale");
            return Err(StatusCode::CONFLICT);
        }
        Ok(Ok(Err(err @ raven_railgun_core::AdapterError::InvalidQuery(_)))) => {
            tracing::info!(%err, "single-query refused: caller-side defect");
            return Err(StatusCode::BAD_REQUEST);
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
            hold_permit_until_detached(join, permit, "single");
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

pub(crate) async fn inspire_query_handler(
    State(app): State<AppState<raven_railgun_engine::inspire::RavenInspireScheme>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Bytes), StatusCode> {
    let instance_id = InstanceId::new(id.clone());
    admit_instance(&app.engine, &instance_id, "query").map_err(AdmissionRefusal::status)?;
    let query: SeededClientQuery = read_versioned(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    validate_session_binding(
        &headers,
        app.sessions.as_ref(),
        &instance_id,
        query.session_handle,
    )?;
    query_handler(State(app), Path(id), body).await
}

pub(crate) async fn batch_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Bytes), StatusCode> {
    let instance_id = InstanceId::new(id);
    let instance =
        admit_instance(&app.engine, &instance_id, "batch").map_err(AdmissionRefusal::status)?;

    let queries: Vec<S::Query> = read_versioned(&body).map_err(|err| {
        tracing::warn!(?err, "batch versioned-bincode deserialize failed");
        StatusCode::BAD_REQUEST
    })?;
    // Serving an off-ladder length would publish the caller's exact query count.
    if let Err(violation) = check_batch_len(queries.len()) {
        tracing::warn!(
            instance_id = %instance.id,
            violation = %violation,
            "batch refused: length is off the fixed-size ladder"
        );
        metrics::counter!(
            "raven_railgun_batch_off_ladder_total",
            "instance" => instance_id.to_string()
        )
        .increment(1);
        return Err(StatusCode::BAD_REQUEST);
    }

    let started = Instant::now();
    // Captured ONCE so the batch cannot straddle a concurrent `swap_state`.
    let snapshot_for_batch = instance.current_snapshot();
    let epoch_at_start = snapshot_for_batch.epoch;

    let k = app.config.max_concurrent_queries.max(1);
    let respond_timeout = Duration::from_secs(app.config.respond_timeout_secs.max(1));

    let responses_result = dispatch_batch::<S, S::Query>(
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

pub(crate) async fn inspire_batch_handler(
    State(app): State<AppState<raven_railgun_engine::inspire::RavenInspireScheme>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Bytes), StatusCode> {
    let instance_id = InstanceId::new(id.clone());
    let instance =
        admit_instance(&app.engine, &instance_id, "batch").map_err(AdmissionRefusal::status)?;
    let queries: Vec<SeededClientQuery> =
        read_versioned(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    for handle in queries.iter().filter_map(|query| query.session_handle) {
        validate_session_binding(&headers, app.sessions.as_ref(), &instance_id, Some(handle))?;
    }
    // The addendum comes from the table the commit driver derives from the tree a state was
    // encoded from -- NOT from the live store, which runs a commit cadence ahead (1000 appends /
    // 300 s) and cannot be shown to share a state with the row. The table is keyed by shard id, so
    // no width arithmetic happens on this path.
    //
    // Selecting by `query.shard_id` works only because the shard id is cleartext (SECURITY.md
    // G7), and leaks nothing beyond it: levels 11..15 are constant across a shard. Hide the shard
    // and this path goes with it -- the upper siblings must then travel inside the PIR row.
    //
    // Provenance is the `encoded_db` Arc, NOT the epoch. `heartbeat_session_eviction` bumps the
    // epoch every session-eviction interval while carrying `encoded_db` by `Arc::clone`; an epoch
    // equality check therefore refused every frozen block forever, one hour after boot. A commit
    // replaces the Arc; nothing else does.
    let addenda = match app.instance_logical_stores.get(&instance_id) {
        None => None,
        Some((list_key, store)) => {
            let before = instance.current_snapshot();
            let store = store.lock();
            if !store.committed_addenda_derived_from(&before.state.encoded_db) {
                // Two operator situations hide behind one `false`. An instance that has never
                // committed a tree is a correct transient; a superseded database is the narrow
                // publish_recommitted_state -> refresh window and must not read as one.
                let reason = if store.has_committed_addenda_provenance() {
                    ADDENDUM_SKEW_STALE_PROVENANCE
                } else {
                    ADDENDUM_SKEW_UNSEEDED
                };
                tracing::warn!(
                    instance_id = %instance_id,
                    epoch = before.epoch.0,
                    reason,
                    "batch refused: committed addenda were not derived alongside the served state"
                );
                metrics::counter!(
                    "raven_railgun_addendum_provenance_skew_total",
                    "instance" => instance_id.to_string(),
                    "reason" => reason,
                )
                .increment(1);
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
            let mut out = Vec::with_capacity(queries.len());
            for query in &queries {
                // An unpopulated shard is ABSENT, never an empty addendum: an empty one folds to
                // a wrong root with HTTP 200, which is the defect, not the refusal.
                let addendum = store
                    .committed_addendum(list_key, query.shard_id)
                    .ok_or_else(|| {
                        tracing::warn!(
                            instance_id = %instance_id,
                            shard_id = query.shard_id,
                            "batch refused: no committed upper-sibling addendum for shard"
                        );
                        metrics::counter!(
                            "raven_railgun_addendum_missing_total",
                            "instance" => instance_id.to_string()
                        )
                        .increment(1);
                        StatusCode::SERVICE_UNAVAILABLE
                    })?;
                if addendum.len() != ADDENDUM_BYTES {
                    tracing::warn!(
                        instance_id = %instance_id,
                        shard_id = query.shard_id,
                        len = addendum.len(),
                        expected = ADDENDUM_BYTES,
                        "batch refused: committed addendum has the wrong width"
                    );
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
                out.push(addendum.to_vec());
            }
            Some((before, out))
        }
    };
    let (status, headers, response) = batch_handler(State(app), Path(id), body).await?;
    let Some((before, addenda)) = addenda else {
        return Ok((status, headers, response));
    };
    // `batch_handler` takes its own snapshot between these two reads. If the encoded database is the
    // same Arc before AND after, the one it served from was that same Arc -- so the row and the
    // addenda share a tree. A commit landing mid-request changes it, and that pair is refused.
    let after = instance.current_snapshot();
    if !Arc::ptr_eq(&before.state.encoded_db, &after.state.encoded_db) {
        tracing::warn!(
            instance_id = %instance_id,
            epoch_before = before.epoch.0,
            epoch_after = after.epoch.0,
            "batch refused: a commit replaced the served state mid-request"
        );
        metrics::counter!(
            "raven_railgun_addendum_provenance_skew_total",
            "instance" => instance_id.to_string(),
            "reason" => ADDENDUM_SKEW_SWAPPED_MID_REQUEST,
        )
        .increment(1);
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let reframed = append_batch_addenda(&response, &addenda)
        .map_err(|()| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((status, headers, reframed.into()))
}

fn append_batch_addenda(bytes: &[u8], addenda: &[Vec<u8>]) -> Result<Vec<u8>, ()> {
    if bytes.len() < 10 {
        return Err(());
    }
    let mut out = bytes.get(..10).ok_or(())?.to_vec();
    let mut offset = 10usize;
    for addendum in addenda {
        let len_end = offset.checked_add(8).ok_or(())?;
        let len_bytes = bytes.get(offset..len_end).ok_or(())?;
        let mut len_buf = [0u8; 8];
        len_buf.copy_from_slice(len_bytes);
        let len = usize::try_from(u64::from_le_bytes(len_buf)).map_err(|_| ())?;
        let body_end = len_end.checked_add(len).ok_or(())?;
        let body = bytes.get(len_end..body_end).ok_or(())?;
        let new_len = u64::try_from(len.checked_add(addendum.len()).ok_or(())?).map_err(|_| ())?;
        out.extend_from_slice(&new_len.to_le_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(addendum);
        offset = body_end;
    }
    if offset != bytes.len() {
        return Err(());
    }
    Ok(out)
}

/// Keep the concurrency permit with the work, not with the request.
///
/// A timeout only drops the `JoinHandle`; `spawn_blocking` has no cancellation,
/// so the respond keeps a blocking thread and its `Arc<Snapshot>` alive.
/// Returning the permit at the deadline would let `max_concurrent_queries`
/// admit fresh work on top of it, unbounded, while the permit gauge reads free.
fn hold_permit_until_detached<T: Send + 'static>(
    join: tokio::task::JoinHandle<T>,
    permit: tokio::sync::OwnedSemaphorePermit,
    kind: &'static str,
) {
    metrics::counter!(
        "raven_railgun_respond_detached_total",
        "kind" => kind
    )
    .increment(1);
    tokio::spawn(async move {
        let _ = join.await;
        drop(permit);
    });
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
    /// The slot at `index` was rejected as caller-side malformed.
    #[error("slot {index} rejected: {detail}")]
    InvalidSlot {
        /// 0-based slot index.
        index: usize,
        /// Display-formatted scheme error.
        detail: String,
    },
    /// The slot referenced a session handle the current instance no longer serves.
    #[error("slot {index} referenced a stale session handle")]
    SessionHandleRejected {
        /// 0-based slot index.
        index: usize,
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
    /// Map typed failures to their wire status.
    pub fn status(&self) -> StatusCode {
        match self {
            BatchError::Respond { .. } | BatchError::Invariant(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            BatchError::InvalidSlot { .. } => StatusCode::BAD_REQUEST,
            BatchError::SessionHandleRejected { .. } => StatusCode::CONFLICT,
            BatchError::WorkerAborted { .. }
            | BatchError::SemaphoreClosed
            | BatchError::Timeout { .. } => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// 0-based slot the failure is attributed to; `None` when unattributable.
    #[must_use]
    pub fn index(&self) -> Option<usize> {
        match self {
            BatchError::Respond { index, .. }
            | BatchError::InvalidSlot { index, .. }
            | BatchError::SessionHandleRejected { index }
            | BatchError::Timeout { index, .. }
            | BatchError::WorkerAborted { index } => {
                if *index == usize::MAX {
                    None
                } else {
                    Some(*index)
                }
            }
            BatchError::SemaphoreClosed | BatchError::Invariant(_) => None,
        }
    }

    /// Low-cardinality class label safe to log (avoids echoing attacker-influenced detail strings).
    pub fn class(&self) -> &'static str {
        match self {
            BatchError::Respond { .. } => "respond",
            BatchError::InvalidSlot { .. } => "invalid_slot",
            BatchError::SessionHandleRejected { .. } => "session_handle_rejected",
            BatchError::Timeout { .. } => "timeout",
            BatchError::WorkerAborted { .. } => "worker_aborted",
            BatchError::SemaphoreClosed => "semaphore_closed",
            BatchError::Invariant(_) => "invariant",
        }
    }
}

type WorkerOutcome<R> = (usize, Result<R, BatchError>);

/// Cross-query K-concurrent dispatcher; responses in input order,
/// short-circuits on first error.
///
/// Uses K `spawn_blocking` workers directly: nesting `rayon::par_iter` inside
/// `spawn_blocking` regresses ~2x on the HTTP path. Every worker borrows the
/// same `Arc<Snapshot<S>>` so the whole batch serves one `(epoch, state)` even
/// under a concurrent `swap_state`.
///
/// A slot becomes an `S::Query` inside the worker, after its permit: a caller
/// fanning one shared upload across slots pays at most `k` live copies, not one
/// per slot. `/batch` owns its queries outright and converts through the
/// identity `Into`.
pub(crate) async fn dispatch_batch<S, Q>(
    slots: Vec<Q>,
    instance: Arc<PirInstance<S>>,
    snapshot: Arc<Snapshot<S>>,
    semaphore: Arc<Semaphore>,
    k: usize,
    respond_timeout: Duration,
) -> Result<Vec<S::Response>, BatchError>
where
    S: PirScheme,
    Q: Into<S::Query> + Send + 'static,
{
    use tokio::task::JoinSet;

    let n = slots.len();
    let mut responses: Vec<Option<S::Response>> = (0..n).map(|_| None).collect();
    let mut join: JoinSet<WorkerOutcome<S::Response>> = JoinSet::new();

    let mut next_idx = 0usize;
    let mut slots_iter: std::vec::IntoIter<Q> = slots.into_iter();

    while next_idx < k.min(n) {
        let Some(slot) = slots_iter.next() else {
            break;
        };
        let inst = Arc::clone(&instance);
        let sem = Arc::clone(&semaphore);
        let snap = Arc::clone(&snapshot);
        let idx = next_idx;
        join.spawn(
            async move { worker::<S, Q>(idx, slot, inst, snap, sem, respond_timeout).await },
        );
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
                // `Respond { detail }` may carry attacker-influenced text.
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
            if let Some(slot) = slots_iter.next() {
                let inst = Arc::clone(&instance);
                let sem = Arc::clone(&semaphore);
                let snap = Arc::clone(&snapshot);
                let idx = next_idx;
                join.spawn(async move {
                    worker::<S, Q>(idx, slot, inst, snap, sem, respond_timeout).await
                });
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
/// A timed-out slot keeps its permit until the detached respond ends. The slot
/// materializes under the permit, so an unacquired worker holds no query-sized
/// allocation.
async fn worker<S, Q>(
    idx: usize,
    slot: Q,
    instance: Arc<PirInstance<S>>,
    snapshot: Arc<Snapshot<S>>,
    sem: Arc<Semaphore>,
    respond_timeout: Duration,
) -> WorkerOutcome<S::Response>
where
    S: PirScheme,
    Q: Into<S::Query> + Send + 'static,
{
    let Ok(permit) = sem.acquire_owned().await else {
        return (idx, Err(BatchError::SemaphoreClosed));
    };
    let mut join = tokio::task::spawn_blocking(move || {
        let query = slot.into();
        instance.query_active_tracked_with_snapshot(&snapshot, &query)
    });
    match tokio::time::timeout(respond_timeout, &mut join).await {
        Ok(Ok(Ok((_epoch, r)))) => (idx, Ok(r)),
        Ok(Ok(Err(raven_railgun_core::AdapterError::SessionHandleRejected { .. }))) => {
            (idx, Err(BatchError::SessionHandleRejected { index: idx }))
        }
        Ok(Ok(Err(scheme_err @ raven_railgun_core::AdapterError::InvalidQuery(_)))) => (
            idx,
            Err(BatchError::InvalidSlot {
                index: idx,
                detail: format!("{scheme_err}"),
            }),
        ),
        Ok(Ok(Err(scheme_err))) => (
            idx,
            Err(BatchError::Respond {
                index: idx,
                detail: format!("{scheme_err}"),
            }),
        ),
        Ok(Err(_)) => (idx, Err(BatchError::WorkerAborted { index: idx })),
        Err(_elapsed) => {
            hold_permit_until_detached(join, permit, "batch");
            (
                idx,
                Err(BatchError::Timeout {
                    index: idx,
                    secs: respond_timeout.as_secs(),
                }),
            )
        }
    }
}

#[cfg(test)]
mod append_addenda_tests {
    use super::append_batch_addenda;
    use crate::versioned::{write_batch_response_versioned, WIRE_SCHEMA_PREFIX_LEN};

    /// Rebuild the framing `append_batch_addenda` rewrites, independently of the function
    /// under test: header, then `{u64 LE len, body}` per slot. Comparing the function to
    /// itself is the self-oracle this batch has already withdrawn one result over.
    fn split_slots(bytes: &[u8]) -> Vec<Vec<u8>> {
        let header = WIRE_SCHEMA_PREFIX_LEN + 8;
        let count = u64::from_le_bytes(
            bytes[WIRE_SCHEMA_PREFIX_LEN..header]
                .try_into()
                .expect("count"),
        );
        let mut out = Vec::new();
        let mut offset = header;
        for _ in 0..count {
            let len = usize::try_from(u64::from_le_bytes(
                bytes[offset..offset + 8].try_into().expect("len"),
            ))
            .expect("len fits");
            offset += 8;
            out.push(bytes[offset..offset + len].to_vec());
            offset += len;
        }
        assert_eq!(offset, bytes.len(), "trailing bytes after {count} slots");
        out
    }

    fn framed(slots: &[Vec<u8>]) -> Vec<u8> {
        write_batch_response_versioned(slots).expect("frame")
    }

    #[test]
    fn appends_each_addendum_to_its_own_slot_and_preserves_order() {
        // Distinct lengths AND distinct bytes, so a swapped or shared addendum shows up.
        let slots = vec![vec![0xaa_u8; 512], vec![0xbb; 512], vec![0xcc; 512]];
        let addenda = vec![vec![0x11_u8; 160], vec![0x22; 160], vec![0x33; 160]];
        let out = append_batch_addenda(&framed(&slots), &addenda).expect("append");

        let got = split_slots(&out);
        assert_eq!(got.len(), 3);
        for (i, slot) in got.iter().enumerate() {
            // bincode prefixes a Vec<u8> with its length, so compare the TAIL, which is
            // what `runClientPirQueryBatch` slices off, not the whole body.
            assert_eq!(slot.len(), 512 + 8 + 160, "slot {i} length");
            assert_eq!(
                &slot[slot.len() - 160..],
                &addenda[i][..],
                "slot {i} addendum"
            );
            assert!(
                slot[slot.len() - 161] == 0xaa + u8::try_from(i).expect("i") * 0x11,
                "slot {i} body must still end with its own bytes"
            );
        }
    }

    /// The cover-query shape: a batch padded to the fixed-size ladder.
    #[test]
    fn handles_a_padded_cover_batch_of_four() {
        let slots = vec![vec![0x01_u8; 512]; 4];
        let addenda = vec![vec![0x09_u8; 160]; 4];
        let out = append_batch_addenda(&framed(&slots), &addenda).expect("append");
        let got = split_slots(&out);
        assert_eq!(got.len(), 4);
        assert!(got.iter().all(|s| s.len() == 512 + 8 + 160));
    }

    /// The planted mutation: one addendum too short. The function must still frame
    /// consistently, and the test must SEE the difference -- this is the check that would
    /// have caught a truncated addendum being served with HTTP 200.
    #[test]
    fn a_short_addendum_changes_the_framed_length() {
        let slots = vec![vec![0xaa_u8; 512]];
        let full = append_batch_addenda(&framed(&slots), &[vec![0x11_u8; 160]]).expect("append");
        let short = append_batch_addenda(&framed(&slots), &[vec![0x11_u8; 159]]).expect("append");
        assert_ne!(
            split_slots(&full)[0].len(),
            split_slots(&short)[0].len(),
            "a 159-byte addendum must not frame identically to a 160-byte one"
        );
    }

    #[test]
    fn refuses_a_body_shorter_than_the_header() {
        assert!(append_batch_addenda(&[0u8; 9], &[vec![0u8; 160]]).is_err());
    }

    #[test]
    fn refuses_when_a_declared_slot_length_runs_past_the_body() {
        let mut bytes = framed(&[vec![0xaa_u8; 512]]);
        let offset = WIRE_SCHEMA_PREFIX_LEN + 8;
        bytes[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(append_batch_addenda(&bytes, &[vec![0x11_u8; 160]]).is_err());
    }

    #[test]
    fn refuses_trailing_bytes_after_the_last_slot() {
        let mut bytes = framed(&[vec![0xaa_u8; 512]]);
        bytes.push(0xff);
        assert!(append_batch_addenda(&bytes, &[vec![0x11_u8; 160]]).is_err());
    }

    /// Fewer addenda than slots leaves slots unvisited, so `offset != bytes.len()`.
    #[test]
    fn refuses_when_addenda_do_not_cover_every_slot() {
        let slots = vec![vec![0xaa_u8; 512], vec![0xbb; 512]];
        assert!(append_batch_addenda(&framed(&slots), &[vec![0x11_u8; 160]]).is_err());
    }
}

#[cfg(test)]
mod swapped_mid_request_metric_tests {
    //! The third `reason` on `raven_railgun_addendum_provenance_skew_total`, the one that only
    //! fires after a batch has already been served: the row is correct, and the commit that
    //! landed while it was in flight is what makes the addenda no longer its own.
    //!
    //! Driven at the handler rather than the router because the refusal needs a commit to land
    //! strictly between the handler's two provenance reads. `join_next` awaits a spawned task,
    //! which on a current-thread runtime cannot run before this task yields, so a commit
    //! applied at the first pending poll is exactly a commit landing mid-request.

    use std::collections::HashMap;
    use std::future::Future;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};

    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, StatusCode};
    use raven_inspire::math::GaussianSampler;
    use raven_inspire::params::{InspireParams, InspireVariant, SecurityLevel};
    use raven_inspire::{query_seeded, EncodedDatabase, ServerCrs};
    use raven_railgun_core::{Epoch, InstanceId};
    use raven_railgun_engine::inspire::{
        apply_wal_entry, setup_state, swap_state, LogicalLeafStore, RavenInspireScheme,
    };
    use raven_railgun_engine::pir_table::PerListPath10Encoder;
    use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
    use raven_railgun_persistence::{PpoiEventType, WalEntryPayload};

    use super::inspire_batch_handler;
    use crate::config::HttpConfig;
    use crate::state::AppState;
    use crate::versioned::write_versioned;

    const TOKEN: &str = "addendum-swap-mid-request-token-123456";
    const INSTANCE: &str = "addendum-swapped-mid-request";
    const LIST_KEY: [u8; 32] = [0x3a; 32];
    const ENTRY_BYTES: usize = 32;
    const ROWS: usize = 32;
    const ENTRIES_PER_SHARD: u32 = 2_048;
    const SKEW: &str = "raven_railgun_addendum_provenance_skew_total";

    /// Every counter increment the handler emits, in order, keyed by the rendered metric key.
    ///
    /// Reads the emit rather than a `/metrics` scrape because metrics 0.24.5 mis-buckets
    /// `Registry` entries after a resize (metrics-rs #694): a scrape can render a duplicate of
    /// the same series and report 0 for an increment that did happen.
    #[derive(Clone, Debug, Default)]
    struct EmitLog(Arc<parking_lot::Mutex<Vec<(String, u64)>>>);

    impl EmitLog {
        /// Increments recorded against the skew counter for one `reason`, oldest first.
        fn skew(&self, reason: &str) -> Vec<u64> {
            let name = format!("Key({SKEW}");
            let label = format!("reason = {reason}");
            self.0
                .lock()
                .iter()
                .filter(|(key, _)| key.starts_with(&name) && key.contains(&label))
                .map(|(_, value)| *value)
                .collect()
        }
    }

    #[derive(Debug)]
    struct LoggedCounter {
        key: String,
        log: Arc<parking_lot::Mutex<Vec<(String, u64)>>>,
    }

    impl metrics::CounterFn for LoggedCounter {
        fn increment(&self, value: u64) {
            self.log.lock().push((self.key.clone(), value));
        }

        fn absolute(&self, value: u64) {
            self.log.lock().push((self.key.clone(), value));
        }
    }

    impl metrics::Recorder for EmitLog {
        fn describe_counter(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }

        fn describe_gauge(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }

        fn describe_histogram(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }

        fn register_counter(
            &self,
            key: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Counter {
            metrics::Counter::from_arc(Arc::new(LoggedCounter {
                key: key.to_string(),
                log: Arc::clone(&self.0),
            }))
        }

        fn register_gauge(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
            metrics::Gauge::noop()
        }

        fn register_histogram(
            &self,
            _: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Histogram {
            metrics::Histogram::noop()
        }
    }

    struct Fixture {
        app: AppState<RavenInspireScheme>,
        instance: Arc<PirInstance<RavenInspireScheme>>,
        upload: Vec<u8>,
        /// A second encoded database of the same shape, for the commit that lands mid-request.
        recommitted: (ServerCrs, EncodedDatabase),
    }

    fn params() -> InspireParams {
        InspireParams {
            ring_dim: 256,
            q: 1_152_921_504_606_830_593,
            crt_moduli: vec![1_152_921_504_606_830_593],
            p: 65_537,
            sigma: 6.4,
            gadget_base: 1 << 20,
            query_gadget_len: 3,
            packing_gadget_len: 3,
            security_level: SecurityLevel::Bits128,
        }
    }

    /// A store holding one PPOI leaf, so shard 0 has a real upper-sibling addendum at the served
    /// width; without it the batch refuses on the missing counter instead.
    fn seeded_store() -> LogicalLeafStore {
        let encoder = PerListPath10Encoder::new(ENTRIES_PER_SHARD, LIST_KEY).expect("path-10");
        let mut store = LogicalLeafStore::new();
        apply_wal_entry(
            &mut store,
            &WalEntryPayload::PpoiListLeafAdded {
                list_key: LIST_KEY,
                list_index: 0,
                blinded_commitment: [0x11; 32],
                status: 0,
                event_type: PpoiEventType::Shield,
                signature: vec![0; 64],
                validated_merkleroot: [0; 32],
            },
            100,
            &encoder,
        )
        .expect("append ppoi leaf");
        store
    }

    fn fixture() -> Fixture {
        let params = params();
        let db = raven_railgun_testkit::toy_db(ROWS, ENTRY_BYTES);
        let (state, secret_key) =
            setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("toy state");

        let mut sampler = GaussianSampler::with_seed(params.sigma, 0x3a);
        let (_, query) = query_seeded(
            &state.crs,
            0,
            state.shard_config(),
            &secret_key,
            &mut sampler,
        )
        .expect("seeded query for shard 0");
        assert!(
            query.session_handle.is_none(),
            "the fixture uploads its packing keys inline; a handle would need a session"
        );
        let upload = write_versioned(&vec![query]).expect("versioned batch upload");

        let recommitted = ((*state.crs).clone(), (*state.encoded_db).clone());

        let mut store = seeded_store();
        store.refresh_committed_addenda(&state.encoded_db, ENTRIES_PER_SHARD);
        assert!(
            store.committed_addendum(&LIST_KEY, 0).is_some(),
            "the fixture must clear the missing-addendum guard, or it proves the wrong refusal"
        );

        let instance_id = InstanceId::new(INSTANCE);
        let instance = Arc::new(PirInstance::new(
            instance_id.clone(),
            InstanceRole::Live,
            state,
        ));
        let engine: Engine<RavenInspireScheme> = Engine::new();
        engine
            .add_live(Arc::clone(&instance))
            .expect("register instance");

        let mut stores = HashMap::new();
        stores.insert(
            instance_id,
            (LIST_KEY, Arc::new(parking_lot::Mutex::new(store))),
        );
        let app = AppState::new(engine, HttpConfig::demo(TOKEN))
            .expect("app state")
            .with_instance_logical_stores(stores);

        Fixture {
            app,
            instance,
            upload,
            recommitted,
        }
    }

    /// Run `body` on a current-thread runtime with every metric emit captured.
    fn with_emit_log<F>(body: impl FnOnce(EmitLog) -> F)
    where
        F: Future<Output = ()>,
    {
        let log = EmitLog::default();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
        let captured = log.clone();
        metrics::with_local_recorder(&log, || runtime.block_on(body(captured)));
    }

    /// Control for the refusal below: the same fixture, with nothing committed mid-request,
    /// serves the batch. Without it a green refusal proves only that the fixture is broken.
    #[test]
    fn the_same_fixture_serves_when_no_commit_lands_mid_request() {
        with_emit_log(|log| async move {
            let fixture = fixture();
            let served = inspire_batch_handler(
                State(fixture.app),
                Path(INSTANCE.to_owned()),
                HeaderMap::new(),
                fixture.upload.into(),
            )
            .await;
            let (status, _, body) = served.expect("the fixture must serve when no commit lands");
            assert_eq!(status, StatusCode::OK);
            assert!(!body.is_empty());
            assert_eq!(
                log.skew("swapped_mid_request"),
                vec![0],
                "a served batch must leave the series at its zero-init and nothing more"
            );
        });
    }

    #[test]
    fn a_commit_landing_mid_request_refuses_under_its_own_reason() {
        with_emit_log(|log| async move {
            let fixture = fixture();
            let instance = Arc::clone(&fixture.instance);
            let (recommitted_crs, recommitted_db) = fixture.recommitted;

            // The zero-init, on the exact label set the refusal below increments. Without it an
            // alert on this series reads "no data" and cannot tell a silent server from an
            // unscraped one.
            assert_eq!(log.skew("swapped_mid_request"), vec![0]);

            let served_db = Arc::clone(&instance.current_snapshot().state.encoded_db);
            let batch = inspire_batch_handler(
                State(fixture.app),
                Path(INSTANCE.to_owned()),
                HeaderMap::new(),
                fixture.upload.into(),
            );
            tokio::pin!(batch);
            let mut cx = Context::from_waker(Waker::noop());
            assert!(
                matches!(batch.as_mut().poll(&mut cx), Poll::Pending),
                "the batch must still be in flight; a commit applied after it returned proves \
                 nothing"
            );

            swap_state(
                &instance,
                recommitted_crs,
                recommitted_db,
                InspireVariant::TwoPacking,
                ENTRY_BYTES,
                Epoch(1),
            )
            .expect("commit lands while the batch is in flight");
            assert!(
                !Arc::ptr_eq(&served_db, &instance.current_snapshot().state.encoded_db),
                "the commit must replace the served database, or the fixture proves nothing"
            );

            assert_eq!(
                batch
                    .await
                    .expect_err("a row and addenda from two trees must be refused"),
                StatusCode::SERVICE_UNAVAILABLE
            );

            assert_eq!(
                log.skew("swapped_mid_request"),
                vec![0, 1],
                "the refusal must land on its own reason, after the zero-init"
            );
            assert_eq!(log.skew("unseeded"), vec![0]);
            assert_eq!(log.skew("stale_provenance"), vec![0]);
        });
    }
}
