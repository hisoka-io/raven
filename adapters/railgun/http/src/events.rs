//! Server-sent events for the operator dashboard.
//!
//! Emits a `status` event (same shape as `/v1/status`) at 5 s cadence with a
//! 15 s keep-alive against reverse-proxy idle timeouts. Per-connection; no
//! shared broadcast channel.

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

/// `GET /v1/events` SSE stream; immediate `status` on connect then one every
/// [`SSE_CADENCE`], with a [`SSE_KEEPALIVE`] keep-alive.
pub(crate) async fn events_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let stream = async_stream::stream! {
        // Immediate first emit so subscribers don't wait a full cadence.
        let payload = build_status_response(&app);
        match serde_json::to_string(&payload) {
            Ok(json) => yield Ok(SseEvent::default().event("status").data(json)),
            Err(err) => {
                tracing::warn!(?err, "events_handler initial status serialize failed");
            }
        }

        let mut ticker = tokio::time::interval(SSE_CADENCE);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Drop the t=0 tick; the initial emit above already covered it.
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
/// Through `cloudflared` the `x-forwarded-for` chain starts with a per-region
/// CF edge IP, so without this rewrite every tunnel visitor keys to one
/// `SmartIpKeyExtractor` bucket and a single session exhausts the global burst.
/// Replaces `x-forwarded-for` with `cf-connecting-ip` when present; otherwise
/// no-op. Mount only when `trust_proxy_header = true`.
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
