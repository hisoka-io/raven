//! The routes. Every answer is read from one view and starts with its header.
//!
//! | Route | Answer |
//! |---|---|
//! | `GET /howl/v1/params` | parameters and the key material clients build under |
//! | `GET /howl/v1/prefixes?since=N` | feed rows from `N` to the next segment boundary or the end |
//! | `GET /howl/v1/block/{b}` | the leaves of block `b` present at the answer's leaf count |
//! | `GET /howl/v1/upper?since=K` | level-10 nodes of full blocks from `K` |
//! | `GET /howl/v1/sync?since=N&upper=K&held=H` | the feed from `N`, the upper nodes from `K` and the newest block's leaves from `H` |
//! | `POST /howl/v1/session` | seat a packing key; returns a handle |
//! | `POST /howl/v1/notes` | answer a padded batch, by handle or with the key inline |
//!
//! A read that names a position past the node's state is refused with `409` and a
//! [`Body::Stale`] answer whose header says where the node stands.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use howl_wire::{
    Body, Notes, Params, RequestPrefix, Session, CELL_BYTES, LADDER_CAP, REQUEST_PREFIX_BYTES,
    ROWS_PER_SHARD,
};
use tokio::sync::Semaphore;
use tokio::task::JoinError;

use crate::engine::{Engine, Pir, Refusal, View};

/// Upper bound on one batch body beyond its key: sixteen seeded queries with room to spare.
const QUERY_BYTES_LIMIT: usize = 1 << 20;

/// Shared state of the routes.
#[derive(Debug)]
pub struct Served {
    engine: Arc<Engine>,
    // Each batch occupies a blocking thread and the cores its responds use; beyond this many
    // a caller waits.
    respond_permits: Arc<Semaphore>,
}

impl Served {
    /// Routes over `engine`, answering at most `concurrent` batches at once.
    #[must_use]
    pub fn new(engine: Arc<Engine>, concurrent: usize) -> Arc<Self> {
        Arc::new(Self {
            engine,
            respond_permits: Arc::new(Semaphore::new(concurrent.max(1))),
        })
    }
}

fn octets(status: StatusCode, bytes: Vec<u8>) -> Response {
    let mut response = (status, bytes).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
}

fn answer(view: &View, body: Body) -> Response {
    octets(StatusCode::OK, view.answer(body).encode())
}

fn stale(view: &View) -> Response {
    octets(StatusCode::CONFLICT, view.answer(Body::Stale).encode())
}

fn refuse(status: StatusCode, message: impl Into<String>) -> Response {
    (status, message.into()).into_response()
}

/// A request refused before any state is read.
type Bad = (StatusCode, String);

fn number(query: &HashMap<String, String>, key: &str) -> Result<u64, Bad> {
    match query.get(key) {
        None => Ok(0),
        Some(text) => text
            .parse()
            .map_err(|_| (StatusCode::BAD_REQUEST, format!("{key} is not a number"))),
    }
}

/// `work` on a blocking thread under one of `permits`; `None` once they are closed. The permit
/// goes with the work, so a caller that disconnects frees it only when the work is done: the
/// work in flight stays bounded by the permits whatever the callers do.
async fn gated<T: Send + 'static>(
    permits: &Arc<Semaphore>,
    work: impl FnOnce() -> T + Send + 'static,
) -> Option<Result<T, JoinError>> {
    let permit = Arc::clone(permits).acquire_owned().await.ok()?;
    Some(
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work()
        })
        .await,
    )
}

/// The router over `served`.
pub fn router(served: Arc<Served>) -> Router {
    let key_limit = served.engine.pir().key_upload_limit();
    Router::new()
        .route("/howl/v1/params", get(params))
        .route("/howl/v1/prefixes", get(prefixes))
        .route("/howl/v1/block/:index", get(block))
        .route("/howl/v1/upper", get(upper))
        .route("/howl/v1/sync", get(sync))
        .route(
            "/howl/v1/session",
            post(session).layer(DefaultBodyLimit::max(REQUEST_PREFIX_BYTES + key_limit)),
        )
        .route(
            "/howl/v1/notes",
            post(notes).layer(DefaultBodyLimit::max(
                REQUEST_PREFIX_BYTES + key_limit + QUERY_BYTES_LIMIT,
            )),
        )
        .route("/howl/v1/health", get(health))
        .with_state(served)
}

async fn params(State(served): State<Arc<Served>>) -> Response {
    let view = served.engine.view();
    let pir = served.engine.pir();
    answer(
        &view,
        Body::Params(Params {
            entry_bytes: CELL_BYTES as u32,
            rows_per_shard: ROWS_PER_SHARD as u32,
            ladder_cap: LADDER_CAP as u16,
            session_ttl_secs: u32::try_from(pir.session_ttl().as_secs()).unwrap_or(u32::MAX),
            crs: pir.crs_bytes().to_vec(),
        }),
    )
}

async fn prefixes(
    State(served): State<Arc<Served>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let since = match number(&query, "since") {
        Ok(since) => since,
        Err(bad) => return bad.into_response(),
    };
    let view = served.engine.view();
    match view.prefixes(since) {
        Some(segment) => answer(&view, Body::Prefixes(segment)),
        None => stale(&view),
    }
}

async fn block(State(served): State<Arc<Served>>, Path(index): Path<u32>) -> Response {
    let view = served.engine.view();
    match view.block(index) {
        Some(block) => answer(&view, Body::Block(block)),
        None => stale(&view),
    }
}

async fn upper(
    State(served): State<Arc<Served>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let since = match number(&query, "since") {
        Ok(since) => since,
        Err(bad) => return bad.into_response(),
    };
    let view = served.engine.view();
    match view.upper(since) {
        Some(nodes) => answer(&view, Body::Upper(nodes)),
        None => stale(&view),
    }
}

async fn sync(
    State(served): State<Arc<Served>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let read = |key| number(&query, key);
    let (since, upper_since, held) = match (read("since"), read("upper"), read("held")) {
        (Ok(since), Ok(upper), Ok(held)) => (since, upper, held),
        (Err(bad), _, _) | (_, Err(bad), _) | (_, _, Err(bad)) => return bad.into_response(),
    };
    let view = served.engine.view();
    match (
        view.prefixes(since),
        view.upper(upper_since),
        view.newest(held),
    ) {
        (Some(prefixes), Some(upper), Some(newest)) => answer(
            &view,
            Body::Sync {
                prefixes,
                upper,
                newest,
            },
        ),
        _ => stale(&view),
    }
}

fn payload<'a>(pir: &Pir, body: &'a [u8]) -> Result<&'a [u8], Bad> {
    let (prefix, rest) =
        RequestPrefix::decode(body).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    if prefix.param_set != pir.param_set() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "parameter set {} is not the {} this node serves",
                prefix.param_set,
                pir.param_set()
            ),
        ));
    }
    Ok(rest)
}

fn bad(message: String) -> Bad {
    (StatusCode::BAD_REQUEST, message)
}

async fn session(State(served): State<Arc<Served>>, body: Bytes) -> Response {
    let pir = served.engine.pir();
    let keys = match payload(pir, &body).and_then(|rest| pir.decode_key(rest).map_err(bad)) {
        Ok(keys) => keys,
        Err(bad) => return bad.into_response(),
    };
    let engine = Arc::clone(&served.engine);
    let Some(seated) = gated(&served.respond_permits, move || engine.pir().register(keys)).await
    else {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, "shutting down");
    };
    let view = served.engine.view();
    match seated {
        Ok(Ok(handle)) => answer(
            &view,
            Body::Session(Session {
                handle: handle.0,
                ttl_secs: u32::try_from(pir.session_ttl().as_secs()).unwrap_or(u32::MAX),
            }),
        ),
        Ok(Err(refusal)) => refusal_response(&view, &refusal),
        Err(_) => refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "registration did not finish",
        ),
    }
}

fn refusal_response(view: &View, refusal: &Refusal) -> Response {
    match refusal {
        Refusal::Stale { .. } => stale(view),
        Refusal::NotALadderStep(_) | Refusal::Malformed(_) => {
            refuse(StatusCode::UNPROCESSABLE_ENTITY, refusal.to_string())
        }
        Refusal::Session(_) => refuse(StatusCode::GONE, refusal.to_string()),
        Refusal::Full(_) => refuse(StatusCode::SERVICE_UNAVAILABLE, refusal.to_string()),
    }
}

async fn notes(State(served): State<Arc<Served>>, body: Bytes) -> Response {
    let pir = served.engine.pir();
    let batch = match payload(pir, &body)
        .and_then(|rest| pir.decode_batch(rest, QUERY_BYTES_LIMIT).map_err(bad))
    {
        Ok(batch) => batch,
        Err(bad) => return bad.into_response(),
    };
    // One view for the whole batch, so every response is read from one table.
    let view = served.engine.view();
    let engine = Arc::clone(&served.engine);
    let read = Arc::clone(&view);
    let Some(answered) = gated(&served.respond_permits, move || {
        engine.pir().respond(&read, &batch)
    })
    .await
    else {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, "shutting down");
    };
    match answered {
        Ok(Ok(responses)) => answer(&view, Body::Notes(Notes { responses })),
        Ok(Err(refusal)) => refusal_response(&view, &refusal),
        Err(_) => refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the batch did not finish",
        ),
    }
}

async fn health(State(served): State<Arc<Served>>) -> Response {
    let view = served.engine.view();
    format!(
        "ok leaves={} block={} shards={} sessions={}\n",
        view.leaf_count,
        view.block,
        view.shards.len(),
        served.engine.pir().session_count()
    )
    .into_response()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use tokio::sync::Semaphore;

    use super::gated;

    async fn until(what: &str, done: impl Fn() -> bool) {
        let start = Instant::now();
        while !done() {
            assert!(start.elapsed() < Duration::from_secs(10), "{what}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_dropped_caller_keeps_its_permit_until_the_work_ends() {
        let permits = Arc::new(Semaphore::new(1));
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let started = Arc::new(AtomicBool::new(false));
        let caller = {
            let permits = Arc::clone(&permits);
            let started = Arc::clone(&started);
            tokio::spawn(async move {
                gated(&permits, move || {
                    started.store(true, Ordering::SeqCst);
                    wait.recv()
                })
                .await
            })
        };
        // Wait for the work itself: a caller dropped before the task is spawned frees its permit.
        until("the work never started", || started.load(Ordering::SeqCst)).await;
        // The caller goes away, as when a client disconnects mid-batch.
        caller.abort();
        assert!(caller.await.expect_err("aborted").is_cancelled());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(permits.available_permits(), 0, "freed while its work runs");
        release.send(()).expect("work waits");
        until("never freed after the work", || {
            permits.available_permits() == 1
        })
        .await;
    }
}
