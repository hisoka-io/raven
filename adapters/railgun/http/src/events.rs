//! Server-sent events for the operator dashboard.
//!
//! Emits a `status` event at 5 s cadence carrying the same JSON shape
//! as `/v1/status`. A 15 s keep-alive comment keeps the connection
//! alive across reverse-proxy idle timeouts (Cloudflare Tunnel, nginx).
//!
//! Per-connection only; no shared broadcast channel. One long-lived
//! HTTP/2 stream per browser tab replaces the previous
//! `(StatusPill + MetricsPanel + /metrics)` polling triad.

use std::convert::Infallible;
use std::time::Duration;

use axum::{
    body::Body,
    extract::State,
    middleware,
    response::sse::{Event as SseEvent, KeepAlive, Sse},
    response::Response,
};
use http::Request;
use raven_railgun_engine::PirScheme;
use tokio_stream::Stream;

use crate::state::AppState;
use crate::status::build_status_response;

/// Cadence at which `status` SSE events are emitted.
const SSE_CADENCE: Duration = Duration::from_secs(5);
/// Interval for SSE keep-alive comment lines (proxy idle-timeout guard).
const SSE_KEEPALIVE: Duration = Duration::from_secs(15);

/// `GET /v1/events` -- Server-Sent Events stream of operator-observable
/// state.
///
/// Sends an immediate `status` event on connect, then one every
/// [`SSE_CADENCE`]. A keep-alive comment fires every [`SSE_KEEPALIVE`]
/// so reverse proxies (Cloudflare Tunnel, nginx) don't idle-close the
/// connection. Payload shape matches [`crate::status::StatusResponse`].
pub(crate) async fn events_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let stream = async_stream::stream! {
        // Immediate first emit so subscribers don't wait 5s for the
        // first payload.
        let payload = build_status_response(&app);
        match serde_json::to_string(&payload) {
            Ok(json) => yield Ok(SseEvent::default().event("status").data(json)),
            Err(err) => {
                tracing::warn!(?err, "events_handler initial status serialize failed");
            }
        }

        let mut ticker = tokio::time::interval(SSE_CADENCE);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Drop the immediate first tick (the initial emit above already
        // covered the t=0 sample).
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let payload = build_status_response(&app);
            match serde_json::to_string(&payload) {
                Ok(json) => yield Ok(SseEvent::default().event("status").data(json)),
                Err(err) => {
                    tracing::warn!(?err, "events_handler status serialize failed");
                }
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::new().interval(SSE_KEEPALIVE).text("keepalive"))
}

/// Cloudflare Tunnel client-IP rewrite middleware.
///
/// Through `cloudflared`, the `x-forwarded-for` chain is either absent
/// or starts with a CF edge IP that is identical for every visitor in
/// a region. Without this middleware every visitor through the tunnel
/// keys to the same `SmartIpKeyExtractor` bucket and a single demo
/// session can exhaust the per-IP burst for the entire world.
///
/// Behaviour:
///
/// - If `cf-connecting-ip` is present, REPLACE `x-forwarded-for` with
///   it (the leftmost-IP semantics `SmartIpKeyExtractor` expects).
/// - If `cf-connecting-ip` is absent, leave the headers alone -- the
///   request is not transiting CF Tunnel and `SmartIpKeyExtractor` can
///   fall back to `x-forwarded-for` (real reverse proxy) or peer IP
///   (direct).
///
/// Should be mounted only when `trust_proxy_header = true`.
/// Direct-port callers without CF in the path see no change.
pub(crate) async fn cf_connecting_ip_to_xff(
    mut req: Request<Body>,
    next: middleware::Next,
) -> Response {
    if let Some(cf_ip) = req.headers().get("cf-connecting-ip").cloned() {
        req.headers_mut().insert(
            http::header::HeaderName::from_static("x-forwarded-for"),
            cf_ip,
        );
    }
    next.run(req).await
}
