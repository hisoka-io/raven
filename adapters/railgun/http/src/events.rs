//! Per-connection SSE `status` events on a 5 s cadence, with a 15 s keep-alive
//! against reverse-proxy idle timeouts.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Body,
    extract::State,
    response::sse::{Event as SseEvent, KeepAlive, Sse},
    response::{IntoResponse, Response},
};
use http::{Request, StatusCode};
use parking_lot::Mutex;
use raven_railgun_engine::PirScheme;
use tower_governor::key_extractor::KeyExtractor;

use crate::state::AppState;
use crate::status::build_status_response;
use crate::trusted_proxy::TrustedProxyIpKeyExtractor;

/// Cadence at which `status` SSE events are emitted.
const SSE_CADENCE: Duration = Duration::from_secs(5);
/// Interval for SSE keep-alive comment lines (proxy idle-timeout guard).
const SSE_KEEPALIVE: Duration = Duration::from_secs(15);

/// Streams held per peer, keyed like the rate limiter.
#[derive(Debug)]
pub(crate) struct SsePeerStreams {
    key: TrustedProxyIpKeyExtractor,
    per_peer: usize,
    held: Mutex<HashMap<IpAddr, usize>>,
}

/// One held stream's claim on its peer's share; released on drop.
#[derive(Debug)]
pub(crate) struct PeerStreamSlot {
    streams: Arc<SsePeerStreams>,
    peer: IpAddr,
}

impl SsePeerStreams {
    pub(crate) fn new(key: TrustedProxyIpKeyExtractor, per_peer: usize) -> Self {
        Self {
            key,
            per_peer,
            held: Mutex::new(HashMap::new()),
        }
    }

    fn admit(self: &Arc<Self>, peer: IpAddr) -> Option<PeerStreamSlot> {
        let mut held = self.held.lock();
        let count = held.entry(peer).or_insert(0);
        if *count >= self.per_peer {
            return None;
        }
        *count += 1;
        Some(PeerStreamSlot {
            streams: Arc::clone(self),
            peer,
        })
    }
}

impl Drop for PeerStreamSlot {
    fn drop(&mut self) {
        let mut held = self.streams.held.lock();
        if let Some(count) = held.get_mut(&self.peer) {
            *count = count.saturating_sub(1);
            // Only peers holding a stream stay mapped; the map never grows with every address seen.
            if *count == 0 {
                held.remove(&self.peer);
            }
        }
    }
}

fn refuse_stream(status: StatusCode, reason: &'static str) -> Response {
    (status, [(http::header::RETRY_AFTER, "5")], reason).into_response()
}

/// `GET /v1/events` SSE stream; immediate `status` on connect then one every
/// [`SSE_CADENCE`], with a [`SSE_KEEPALIVE`] keep-alive.
///
/// Capped at `max_sse_connections` concurrent streams, and the cap is the point: this route
/// carries no credential, and a rate limit bounds how fast connections ARRIVE, not how many are
/// HELD. Each stream owns a task, two timers and an `AppState` clone until the client goes away.
/// The permit is moved into the stream, so it returns when the connection does -- including on a
/// client disconnect, which drops the stream without running any cleanup path of ours.
///
/// Each peer may hold only `max_sse_connections_per_peer` of them, checked before the global
/// permit is taken, so a refused peer spends none of the shared pool.
pub(crate) async fn events_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
    request: Request<Body>,
) -> Response {
    let Ok(peer) = app.sse_peers.key.extract(&request) else {
        return refuse_stream(
            StatusCode::INTERNAL_SERVER_ERROR,
            "event stream refused: the connection carries no peer address to bound it by\n",
        );
    };
    let Some(slot) = app.sse_peers.admit(peer) else {
        return refuse_stream(
            StatusCode::TOO_MANY_REQUESTS,
            "too many concurrent event streams from this peer\n",
        );
    };
    let Ok(permit) = Arc::clone(&app.sse_permits).try_acquire_owned() else {
        return refuse_stream(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many concurrent event streams\n",
        );
    };
    let stream = async_stream::stream! {
        // Held for the life of the stream. Named `_permit` rather than dropped, because binding
        // it to `_` would release it here and make the cap a no-op that still tests green.
        let _permit = permit;
        let _slot = slot;
        let payload = build_status_response(&app);
        match serde_json::to_string(&payload) {
            Ok(json) => yield Ok::<SseEvent, Infallible>(
                SseEvent::default().event("status").data(json),
            ),
            Err(err) => {
                tracing::warn!(?err, "events_handler initial status serialize failed");
            }
        }

        let mut ticker = tokio::time::interval(SSE_CADENCE);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The t=0 tick duplicates the initial emit.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let payload = build_status_response(&app);
            match serde_json::to_string(&payload) {
                Ok(json) => yield Ok::<SseEvent, Infallible>(
                    SseEvent::default().event("status").data(json),
                ),
                Err(err) => {
                    tracing::warn!(?err, "events_handler status serialize failed");
                }
            }
        }
    };
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(SSE_KEEPALIVE).text("keepalive"))
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use axum::extract::ConnectInfo;
    use http_body_util::BodyExt;
    use raven_railgun_core::{InstanceId, Result as RailgunResult};
    use raven_railgun_engine::{Engine, InstanceRole, PirInstance, StateShape};
    use serde::{Deserialize, Serialize};
    use tower::ServiceExt;

    use super::*;
    use crate::HttpConfig;

    #[derive(Debug)]
    struct EchoScheme;

    #[derive(Serialize, Deserialize, Debug)]
    struct Echo;

    impl PirScheme for EchoScheme {
        type ServerState = ();
        type Query = Echo;
        type Response = Echo;
        fn respond(_state: &(), _query: &Echo) -> RailgunResult<Echo> {
            Ok(Echo)
        }
        fn state_shape(_state: &()) -> StateShape {
            StateShape {
                entry_size_bytes: 1,
                rows_per_shard: 1,
            }
        }
    }

    fn router_with(configure: impl FnOnce(&mut HttpConfig)) -> axum::Router {
        let mut engine: Engine<EchoScheme> = Engine::new();
        engine
            .register_instance(Arc::new(PirInstance::new(
                InstanceId::new("sse-peer"),
                InstanceRole::Static,
                (),
            )))
            .expect("register instance");
        let mut config = HttpConfig::demo("sse-peer-token-padded-to-length");
        config.rate_limit_rps = 1_000;
        config.rate_limit_burst = 1_000;
        configure(&mut config);
        crate::router(AppState::new(engine, config).expect("app state")).expect("router")
    }

    fn events_request(peer: &str, forwarded_for: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().uri("/v1/events");
        if let Some(client) = forwarded_for {
            builder = builder.header("x-forwarded-for", client);
        }
        let mut request = builder.body(Body::empty()).expect("request");
        let addr: SocketAddr = peer.parse().expect("peer");
        request.extensions_mut().insert(ConnectInfo(addr));
        request
    }

    /// Pulls the first frame so the generator, and the claims moved into it, are resident.
    async fn open(router: &axum::Router, peer: &str, forwarded_for: Option<&str>) -> Response {
        let mut response = router
            .clone()
            .oneshot(events_request(peer, forwarded_for))
            .await
            .expect("dispatch");
        if response.status() == StatusCode::OK {
            let frame = tokio::time::timeout(Duration::from_secs(5), response.body_mut().frame())
                .await
                .expect("first status event arrives");
            assert!(frame.is_some(), "an accepted stream emits its first event");
        }
        response
    }

    #[tokio::test]
    async fn one_peer_holds_only_its_share_and_regains_it_on_close() {
        let router = router_with(|config| {
            config.max_sse_connections = 8;
            config.max_sse_connections_per_peer = 2;
        });
        let first = open(&router, "203.0.113.5:40001", None).await;
        let second = open(&router, "203.0.113.5:40002", None).await;
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);

        let third = open(&router, "203.0.113.5:40003", None).await;
        assert_eq!(
            third.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "a peer past its share is refused while the global pool still has room"
        );
        assert_eq!(
            third
                .headers()
                .get(http::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("5")
        );
        assert_eq!(
            open(&router, "198.51.100.8:40001", None).await.status(),
            StatusCode::OK,
            "another peer keeps its own share"
        );

        drop(first);
        assert_eq!(
            open(&router, "203.0.113.5:40004", None).await.status(),
            StatusCode::OK,
            "a closed stream returns its share, or the bound becomes a lifetime quota"
        );
    }

    /// Keyed like the rate limiter: behind a declared proxy each forwarded client is its own
    /// peer, and a forged header from anyone else keys to the socket.
    #[tokio::test]
    async fn clients_behind_a_trusted_proxy_are_bounded_one_by_one() {
        let router = router_with(|config| {
            config.max_sse_connections_per_peer = 1;
            config.trust_proxy_header = true;
            config.trusted_proxy_cidrs = vec!["10.0.0.0/8".to_owned()];
        });
        let proxy = "10.1.2.3:443";
        let held = open(&router, proxy, Some("198.51.100.20")).await;
        assert_eq!(held.status(), StatusCode::OK);
        assert_eq!(
            open(&router, proxy, Some("198.51.100.20")).await.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "the forwarded client, not the proxy, is the peer"
        );
        assert_eq!(
            open(&router, proxy, Some("198.51.100.21")).await.status(),
            StatusCode::OK,
            "a second client behind the same proxy has its own share"
        );

        let direct = open(&router, "203.0.113.30:40000", Some("198.51.100.40")).await;
        assert_eq!(direct.status(), StatusCode::OK);
        assert_eq!(
            open(&router, "203.0.113.30:40001", Some("198.51.100.41"))
                .await
                .status(),
            StatusCode::TOO_MANY_REQUESTS,
            "an untrusted peer cannot mint new shares by rewriting the header"
        );
    }

    #[test]
    fn a_peer_leaves_the_map_when_its_last_stream_closes() {
        let streams = Arc::new(SsePeerStreams::new(
            TrustedProxyIpKeyExtractor::new(Vec::new().into()),
            2,
        ));
        let peer: IpAddr = "203.0.113.9".parse().expect("ip");
        let first = streams.admit(peer).expect("first");
        let second = streams.admit(peer).expect("second");
        assert!(streams.admit(peer).is_none());
        drop(first);
        assert_eq!(streams.held.lock().get(&peer), Some(&1));
        drop(second);
        assert!(
            streams.held.lock().is_empty(),
            "a closed peer must not stay mapped, or the map grows with every address ever seen"
        );
    }
}
