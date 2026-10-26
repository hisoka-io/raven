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
//! | `GET /howl/v1/health` | plain text: the leaf count, block and shards served |
//! | `GET /howl/v1/status` | plain text for the operator, under a bearer token: seats, refusals |
//!
//! A read that names a position past the node's state is refused with `409` and a
//! [`Body::Stale`] answer whose header says where the node stands. A caller over a route's
//! request rate or the session rate is answered `429`, and one that finds the body places or the
//! respond queue full, or waits out its bound, `503`; both carry `Retry-After`, which browsers
//! may read. A body that does not arrive within its time is answered `408`. See [`crate::limit`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{MatchedPath, Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use howl_wire::{
    Body, Notes, Params, RequestPrefix, Session, CELL_BYTES, LADDER_CAP, REQUEST_PREFIX_BYTES,
    ROWS_PER_SHARD,
};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::engine::{Engine, Pir, Refusal, View};
use crate::limit::{operator_token_matches, retry_after_secs, Bucket, Limits};

/// Upper bound on one batch body beyond its key: sixteen seeded queries with room to spare.
const QUERY_BYTES_LIMIT: usize = 1 << 20;

const PARAMS: &str = "/howl/v1/params";
const PREFIXES: &str = "/howl/v1/prefixes";
const BLOCK: &str = "/howl/v1/block/:index";
const UPPER: &str = "/howl/v1/upper";
const SYNC: &str = "/howl/v1/sync";
const NOTES: &str = "/howl/v1/notes";
const HEALTH: &str = "/howl/v1/health";
const STATUS: &str = "/howl/v1/status";
const SESSION: &str = "/howl/v1/session";

/// The routes under the request rate, each with a bucket of its own.
const RATED: [&str; 6] = [PARAMS, PREFIXES, BLOCK, UPPER, SYNC, NOTES];

/// Shared state of the routes.
#[derive(Debug)]
pub struct Served {
    engine: Arc<Engine>,
    gate: Gate,
    operator_token: Option<String>,
    requests: [Bucket; RATED.len()],
    sessions: Bucket,
    bodies: Arc<Semaphore>,
    body_timeout: Duration,
    refused_rate: AtomicU64,
    refused_session_rate: AtomicU64,
    refused_bodies: AtomicU64,
    refused_body_timeout: AtomicU64,
}

/// Each batch or registration occupies a blocking thread and the cores its work uses; beyond
/// `permits` a caller waits, and beyond `queued` waiting callers one is refused.
#[derive(Debug)]
struct Gate {
    permits: Arc<Semaphore>,
    waiting: AtomicUsize,
    queued: usize,
    wait: Duration,
    refused_queue_full: AtomicU64,
    refused_wait: AtomicU64,
}

impl Gate {
    fn new(concurrent: usize, queued: usize, wait: Duration) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(concurrent.max(1))),
            waiting: AtomicUsize::new(0),
            queued,
            wait,
            refused_queue_full: AtomicU64::new(0),
            refused_wait: AtomicU64::new(0),
        }
    }

    /// `work` on a blocking thread under a permit. Only the wait for the permit is timed. The
    /// permit goes with the work, so a caller that disconnects frees it only when the work is
    /// done: the work in flight stays bounded by the permits whatever the callers do.
    async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, Unserved> {
        let permit = match Arc::clone(&self.permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(TryAcquireError::Closed) => return Err(Unserved::Closed),
            Err(TryAcquireError::NoPermits) => {
                let place = self.waiting.fetch_add(1, Ordering::AcqRel);
                let _queued = Queued(&self.waiting);
                if place >= self.queued {
                    self.refused_queue_full.fetch_add(1, Ordering::Relaxed);
                    return Err(Unserved::QueueFull);
                }
                let acquire = Arc::clone(&self.permits).acquire_owned();
                match tokio::time::timeout(self.wait, acquire).await {
                    Ok(Ok(permit)) => permit,
                    Ok(Err(_)) => return Err(Unserved::Closed),
                    Err(_) => {
                        self.refused_wait.fetch_add(1, Ordering::Relaxed);
                        return Err(Unserved::Waited);
                    }
                }
            }
        };
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work()
        })
        .await
        .map_err(|_| Unserved::Failed)
    }
}

impl Served {
    /// Routes over `engine`, answering at most `concurrent` batches at once, under the default
    /// [`Limits`] otherwise.
    #[must_use]
    pub fn new(engine: Arc<Engine>, concurrent: usize) -> Arc<Self> {
        Self::with_limits(engine, Limits::new(concurrent))
    }

    /// Routes over `engine` under `limits`; see [`Limits::validate`] for the bounds a node
    /// should be given.
    #[must_use]
    pub fn with_limits(engine: Arc<Engine>, limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            engine,
            gate: Gate::new(limits.concurrent, limits.queued, limits.permit_wait),
            requests: RATED.map(|_| Bucket::new(limits.requests)),
            sessions: Bucket::new(limits.sessions),
            bodies: Arc::new(Semaphore::new(limits.bodies.max(1))),
            body_timeout: limits.body_timeout,
            operator_token: limits.operator_token,
            refused_rate: AtomicU64::new(0),
            refused_session_rate: AtomicU64::new(0),
            refused_bodies: AtomicU64::new(0),
            refused_body_timeout: AtomicU64::new(0),
        })
    }

    /// A session or batch body, read whole under a body place, `cap` bytes and the body timeout.
    /// The place is taken before the first byte and returned with the body: it is held until
    /// the answer, so a body waiting for a permit still counts.
    async fn read_body(
        &self,
        request: Request,
        cap: usize,
    ) -> Result<(OwnedSemaphorePermit, Bytes), StatusCode> {
        let Ok(place) = Arc::clone(&self.bodies).try_acquire_owned() else {
            self.refused_bodies.fetch_add(1, Ordering::Relaxed);
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        };
        let declared = request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
        if declared.is_some_and(|n| n > cap as u64) {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        let read = Limited::new(request.into_body(), cap).collect();
        match tokio::time::timeout(self.body_timeout, read).await {
            Ok(Ok(collected)) => Ok((place, collected.to_bytes())),
            Ok(Err(e)) if e.downcast_ref::<LengthLimitError>().is_some() => {
                Err(StatusCode::PAYLOAD_TOO_LARGE)
            }
            Ok(Err(_)) => Err(StatusCode::BAD_REQUEST),
            Err(_) => {
                self.refused_body_timeout.fetch_add(1, Ordering::Relaxed);
                Err(StatusCode::REQUEST_TIMEOUT)
            }
        }
    }
}

/// Why gated work did not run.
enum Unserved {
    /// The permits are closed: the node is stopping.
    Closed,
    /// The queue for a permit is full.
    QueueFull,
    /// No permit came within the wait.
    Waited,
    /// The work itself panicked.
    Failed,
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

/// Decrements the queue count however the wait ends, a dropped caller included.
struct Queued<'a>(&'a AtomicUsize);

impl Drop for Queued<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn unserved(why: &Unserved, failed: &'static str) -> Response {
    match why {
        Unserved::Closed => refuse(StatusCode::SERVICE_UNAVAILABLE, "shutting down"),
        Unserved::QueueFull | Unserved::Waited => {
            busy(StatusCode::SERVICE_UNAVAILABLE, Duration::from_secs(1))
        }
        Unserved::Failed => refuse(StatusCode::INTERNAL_SERVER_ERROR, failed),
    }
}

/// A refusal to retry later. The body is left unread, so the connection is closed rather than
/// returned to a client's pool with bytes still in it.
fn busy(status: StatusCode, wait: Duration) -> Response {
    let mut response = unread(status);
    response.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from(retry_after_secs(wait)),
    );
    response
}

/// The answer to a body [`Served::read_body`] did not take.
fn body_refused(status: StatusCode) -> Response {
    if status == StatusCode::SERVICE_UNAVAILABLE {
        busy(status, Duration::from_secs(1))
    } else {
        unread(status)
    }
}

/// A refusal sent with the body unread, or read only in part.
fn unread(status: StatusCode) -> Response {
    let mut response = status.into_response();
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    response
}

/// Health and status are never rate limited: the platform and the operator must reach them
/// while the node is loaded. Opening a session takes a session token; every other route a token
/// from its own bucket.
async fn admit(State(served): State<Arc<Served>>, request: Request, next: Next) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("", MatchedPath::as_str);
    let now = Instant::now();
    let rated = RATED
        .iter()
        .zip(&served.requests)
        .find(|(r, _)| **r == route);
    let taken = if route == SESSION && request.method() == Method::POST {
        served.sessions.take(now).inspect_err(|_| {
            served.refused_session_rate.fetch_add(1, Ordering::Relaxed);
        })
    } else if let Some((_, bucket)) = rated {
        bucket.take(now).inspect_err(|_| {
            served.refused_rate.fetch_add(1, Ordering::Relaxed);
        })
    } else {
        Ok(())
    };
    match taken {
        Ok(()) => next.run(request).await,
        Err(wait) => busy(StatusCode::TOO_MANY_REQUESTS, wait),
    }
}

/// Any origin may call; a browser wallet may read `Retry-After` on a refusal.
pub fn cors() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::any())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE])
        .expose_headers([header::RETRY_AFTER])
}

/// The router over `served`, CORS included.
pub fn router(served: Arc<Served>) -> Router {
    Router::new()
        .route(PARAMS, get(params))
        .route(PREFIXES, get(prefixes))
        .route(BLOCK, get(block))
        .route(UPPER, get(upper))
        .route(SYNC, get(sync))
        .route(SESSION, post(session))
        .route(NOTES, post(notes))
        .route(HEALTH, get(health))
        .route(STATUS, get(status))
        .route_layer(middleware::from_fn_with_state(Arc::clone(&served), admit))
        .with_state(served)
        .layer(cors())
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

async fn session(State(served): State<Arc<Served>>, request: Request) -> Response {
    let pir = served.engine.pir();
    let cap = REQUEST_PREFIX_BYTES + pir.key_upload_limit();
    let (_place, body) = match served.read_body(request, cap).await {
        Ok(read) => read,
        Err(refused) => return body_refused(refused),
    };
    let keys = match payload(pir, &body).and_then(|rest| pir.decode_key(rest).map_err(bad)) {
        Ok(keys) => keys,
        Err(bad) => return bad.into_response(),
    };
    let engine = Arc::clone(&served.engine);
    let seated = match served.gate.run(move || engine.pir().register(keys)).await {
        Ok(seated) => seated,
        Err(why) => return unserved(&why, "registration did not finish"),
    };
    let view = served.engine.view();
    match seated {
        Ok(handle) => answer(
            &view,
            Body::Session(Session {
                handle: handle.0,
                ttl_secs: u32::try_from(pir.session_ttl().as_secs()).unwrap_or(u32::MAX),
            }),
        ),
        Err(refusal) => refusal_response(&view, &refusal),
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

async fn notes(State(served): State<Arc<Served>>, request: Request) -> Response {
    let pir = served.engine.pir();
    let cap = REQUEST_PREFIX_BYTES + pir.key_upload_limit() + QUERY_BYTES_LIMIT;
    let (_place, body) = match served.read_body(request, cap).await {
        Ok(read) => read,
        Err(refused) => return body_refused(refused),
    };
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
    let answered = match served
        .gate
        .run(move || engine.pir().respond(&read, &batch))
        .await
    {
        Ok(answered) => answered,
        Err(why) => return unserved(&why, "the batch did not finish"),
    };
    match answered {
        Ok(responses) => answer(&view, Body::Notes(Notes { responses })),
        Err(refusal) => refusal_response(&view, &refusal),
    }
}

/// What any answer's header already says; nothing about the node's load.
async fn health(State(served): State<Arc<Served>>) -> Response {
    let view = served.engine.view();
    format!(
        "ok leaves={} block={} shards={}\n",
        view.leaf_count,
        view.block,
        view.shards.len(),
    )
    .into_response()
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// The node's load, for its operator only.
async fn status(State(served): State<Arc<Served>>, headers: HeaderMap) -> Response {
    if !operator_token_matches(served.operator_token.as_deref(), bearer(&headers)) {
        let mut response = StatusCode::UNAUTHORIZED.into_response();
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        return response;
    }
    let view = served.engine.view();
    let pir = served.engine.pir();
    let gate = &served.gate;
    let count = |n: &AtomicU64| n.load(Ordering::Relaxed);
    format!(
        "ok leaves={} block={} shards={} sessions={} seats={} queued={} refused_rate={} \
         refused_session_rate={} refused_bodies={} refused_body_timeout={} refused_queue_full={} \
         refused_wait={}\n",
        view.leaf_count,
        view.block,
        view.shards.len(),
        pir.session_count(),
        pir.session_limits().max_sessions,
        gate.waiting.load(Ordering::Relaxed),
        count(&served.refused_rate),
        count(&served.refused_session_rate),
        count(&served.refused_bodies),
        count(&served.refused_body_timeout),
        count(&gate.refused_queue_full),
        count(&gate.refused_wait),
    )
    .into_response()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::{Gate, Unserved};

    async fn until(what: &str, done: impl Fn() -> bool) {
        let start = Instant::now();
        while !done() {
            assert!(start.elapsed() < Duration::from_secs(10), "{what}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Takes the gate's one permit with work that runs until the sender is used.
    async fn hold(gate: &Arc<Gate>) -> Sender<()> {
        let (release, wait): (Sender<()>, Receiver<()>) = channel();
        let started = Arc::new(AtomicBool::new(false));
        {
            let gate = Arc::clone(gate);
            let started = Arc::clone(&started);
            tokio::spawn(async move {
                let _ = gate
                    .run(move || {
                        started.store(true, Ordering::SeqCst);
                        wait.recv()
                    })
                    .await;
            });
        }
        until("the held work never started", || {
            started.load(Ordering::SeqCst)
        })
        .await;
        release
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_dropped_caller_keeps_its_permit_until_the_work_ends() {
        let gate = Arc::new(Gate::new(1, 4, Duration::from_secs(10)));
        let (release, wait) = channel::<()>();
        let started = Arc::new(AtomicBool::new(false));
        let caller = {
            let gate = Arc::clone(&gate);
            let started = Arc::clone(&started);
            tokio::spawn(async move {
                gate.run(move || {
                    started.store(true, Ordering::SeqCst);
                    wait.recv()
                })
                .await
                .is_ok()
            })
        };
        // Wait for the work itself: a caller dropped before the task is spawned frees its permit.
        until("the work never started", || started.load(Ordering::SeqCst)).await;
        // The caller goes away, as when a client disconnects mid-batch.
        caller.abort();
        assert!(caller.await.expect_err("aborted").is_cancelled());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            gate.permits.available_permits(),
            0,
            "freed while its work runs"
        );
        release.send(()).expect("work waits");
        until("never freed after the work", || {
            gate.permits.available_permits() == 1
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_full_queue_refuses_at_once_and_a_long_wait_is_cut() {
        // One permit, held; one place in the queue, waited for 100 ms.
        let gate = Arc::new(Gate::new(1, 1, Duration::from_millis(100)));
        let release = hold(&gate).await;
        let waiter = {
            let gate = Arc::clone(&gate);
            tokio::spawn(async move { gate.run(|| ()).await })
        };
        until("the waiter never queued", || {
            gate.waiting.load(Ordering::SeqCst) == 1
        })
        .await;
        let start = Instant::now();
        assert!(matches!(gate.run(|| ()).await, Err(Unserved::QueueFull)));
        assert!(
            start.elapsed() < Duration::from_millis(50),
            "refused only after a wait"
        );
        assert!(matches!(
            waiter.await.expect("joins"),
            Err(Unserved::Waited)
        ));
        assert_eq!(gate.refused_queue_full.load(Ordering::SeqCst), 1);
        assert_eq!(gate.refused_wait.load(Ordering::SeqCst), 1);
        assert_eq!(
            gate.waiting.load(Ordering::SeqCst),
            0,
            "a refused waiter left its place"
        );

        // Control: once the permit is free the same calls are served.
        release.send(()).expect("work waits");
        until("never freed", || gate.permits.available_permits() == 1).await;
        assert!(gate.run(|| ()).await.is_ok());
    }

    #[test]
    fn a_full_queue_or_a_long_wait_is_answered_503_with_a_retry() {
        use axum::http::{header, StatusCode};
        for why in [Unserved::QueueFull, Unserved::Waited] {
            let response = super::unserved(&why, "unused");
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.headers()[header::RETRY_AFTER], "1");
            assert_eq!(response.headers()[header::CONNECTION], "close");
        }
        let closed = super::unserved(&Unserved::Closed, "unused");
        assert!(!closed.headers().contains_key(header::RETRY_AFTER));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_waiter_within_its_bound_is_served() {
        let gate = Arc::new(Gate::new(1, 1, Duration::from_secs(10)));
        let release = hold(&gate).await;
        let waiter = {
            let gate = Arc::clone(&gate);
            tokio::spawn(async move { gate.run(|| 7).await })
        };
        until("the waiter never queued", || {
            gate.waiting.load(Ordering::SeqCst) == 1
        })
        .await;
        release.send(()).expect("work waits");
        assert!(matches!(waiter.await.expect("joins"), Ok(7)));
        assert_eq!(gate.refused_wait.load(Ordering::SeqCst), 0);
    }
}
