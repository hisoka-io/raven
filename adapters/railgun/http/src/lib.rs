//! HTTP layer for the PIR engine.
//!
//! Versioned bincode wire format (see [`WIRE_SCHEMA_VERSION`]).
//! No `CompressionLayer`: PIR ciphertext is incompressible.
//! `trust_proxy_header` + `trusted_proxy_cidrs` gate whether forwarding headers
//! are read at all; an untrusted peer always keys to its socket address.

#![cfg_attr(
    test,
    allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used
    )
)]
#![deny(missing_docs)]

pub mod admin;
pub mod auth;
pub mod batch;
pub mod config;
pub mod events;
pub mod fanout;
pub mod poi_shim;
pub mod state;
pub mod status;
pub mod trusted_proxy;
pub mod versioned;

pub use admin::{DrainAdminResponse, InstanceParams, SessionEstablishResponse};
pub use auth::AuthScope;
pub use batch::BatchError;
pub use config::HttpConfig;
pub use fanout::{FanoutError, FanoutRequest};
pub use state::AppState;
pub use status::{
    ConsumerStatus, HealthConsumerView, HealthReadyResponse, InstanceStatus, RpcEndpointHealthView,
    RpcPoolHealthView, StatusResponse,
};
pub use trusted_proxy::{CidrParseError, IpCidr, TrustedProxyIpKeyExtractor};
pub use versioned::{
    read_batch_response_versioned, read_versioned, write_batch_response_versioned, write_versioned,
    VersionedDecodeError, WIRE_SCHEMA_PREFIX_LEN, WIRE_SCHEMA_VERSION, X_RAVEN_SCHEMA_VERSION,
};

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::{
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit},
    http::{header::HeaderName, HeaderMap, HeaderValue, Request, StatusCode},
    middleware,
    response::Response,
    routing::{get, post},
    Router,
};
use raven_railgun_engine::inspire::RavenInspireScheme;
use raven_railgun_engine::PirScheme;
use std::net::SocketAddr;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::Span;

use crate::admin::{
    admin_drain_handler, admin_undrain_handler, params_handler, session_establish_handler,
};
use crate::auth::bearer_auth;
use crate::batch::{batch_handler, query_handler};
use crate::events::{cf_connecting_ip_to_xff, events_handler};
use crate::fanout::fanout_handler;
use crate::status::{health_live_handler, health_ready_handler, metrics_handler, status_handler};
use crate::versioned::X_RAVEN_SCHEMA_VERSION_HEADER;

pub(crate) const X_RAVEN_EPOCH: HeaderName = HeaderName::from_static("x-raven-epoch");
pub(crate) const X_RAVEN_SCHEME: HeaderName = HeaderName::from_static("x-raven-scheme");
pub(crate) const X_RAVEN_SESSION: HeaderName = HeaderName::from_static("x-raven-session");
pub(crate) const X_RAVEN_FRESHNESS: HeaderName = HeaderName::from_static("x-raven-freshness");

/// Build the production axum router. `Err` only if `tower-governor` rejects the
/// clamped `(rps, burst)` config.
pub fn router<S: PirScheme>(state: AppState<S>) -> Result<Router, String> {
    let trusted_proxies = resolve_trusted_proxies(&state.config)?;
    let rps = state.config.rate_limit_rps.max(1);
    let burst = state.config.rate_limit_burst.max(1);
    let max_body = state.config.max_body_bytes;
    let cors_layer = build_cors_layer(&state.config.cors_allowed_origins);

    let auth_layer = middleware::from_fn_with_state(state.clone(), bearer_auth::<S>);

    let poi_routes = poi_shim::poi_shim_routes(state.clone());

    let rate_limited = Router::new()
        .route("/v1/status", get(status_handler::<S>))
        .route("/v1/instance/:id/query", post(query_handler::<S>))
        .route("/v1/instance/:id/batch", post(batch_handler::<S>))
        .route(
            "/v1/admin/instances/drain/:id",
            post(admin_drain_handler::<S>),
        )
        .route(
            "/v1/admin/instances/undrain/:id",
            post(admin_undrain_handler::<S>),
        )
        .with_state(state.clone())
        .merge(poi_routes)
        .layer(auth_layer.clone())
        .layer(DefaultBodyLimit::max(max_body));

    let rate_limited = if let Some(extractor) = trusted_proxies.clone() {
        rate_limited.layer(build_governor_layer_trusted(rps, burst, extractor)?)
    } else {
        rate_limited.layer(build_governor_layer_peer(rps, burst))
    };

    // Bypasses Governor so scrape + SSE never exhaust the per-IP burst.
    let public = Router::new()
        .route("/v1/health/live", get(health_live_handler))
        .route("/v1/health/ready", get(health_ready_handler::<S>))
        .route("/v1/events", get(events_handler::<S>))
        .route("/metrics", get(metrics_handler::<S>))
        .with_state(state)
        .layer(auth_layer);

    let base = rate_limited.merge(public);

    let base = if let Some(extractor) = trusted_proxies {
        base.layer(middleware::from_fn(move |req, next| {
            cf_connecting_ip_to_xff(extractor.clone(), req, next)
        }))
    } else {
        base
    };

    let with_cors = if let Some(layer) = cors_layer {
        base.layer(layer)
    } else {
        base
    };

    Ok(with_cors.layer(
        TraceLayer::new_for_http()
            .make_span_with(|request: &Request<Body>| {
                tracing::info_span!(
                    "http_request",
                    method = %request.method(),
                    uri = %request.uri(),
                    status = tracing::field::Empty,
                    latency_us = tracing::field::Empty,
                )
            })
            .on_response(|response: &Response, latency: Duration, span: &Span| {
                span.record("status", response.status().as_u16());
                let micros = u64::try_from(latency.as_micros()).unwrap_or(u64::MAX);
                span.record("latency_us", micros);
            }),
    ))
}

/// Inspire router; adds `/session` and `/params`. Splits into a Governor-limited
/// scope and a public scope so scrapes and SSE cannot exhaust the per-IP burst.
pub fn inspire_router(state: AppState<RavenInspireScheme>) -> Result<Router, String> {
    let trusted_proxies = resolve_trusted_proxies(&state.config)?;
    let rps = state.config.rate_limit_rps.max(1);
    let burst = state.config.rate_limit_burst.max(1);
    let max_body = state.config.max_body_bytes;
    let cors_layer = build_cors_layer(&state.config.cors_allowed_origins);

    let auth_layer =
        middleware::from_fn_with_state(state.clone(), bearer_auth::<RavenInspireScheme>);

    // CRS bincode is incompressible and per-request Accept-Encoding would break the
    // `ETag = SHA-256(raw body)` cache contract.
    let params_route = Router::new()
        .route("/v1/instance/:id/params", get(params_handler))
        .with_state(state.clone());

    let rate_limited = Router::new()
        .route("/v1/status", get(status_handler::<RavenInspireScheme>))
        .route(
            "/v1/instance/:id/query",
            post(query_handler::<RavenInspireScheme>),
        )
        .route(
            "/v1/instance/:id/batch",
            post(batch_handler::<RavenInspireScheme>),
        )
        .route("/v1/instance/:id/fanout", post(fanout_handler))
        .route(
            "/v1/admin/instances/drain/:id",
            post(admin_drain_handler::<RavenInspireScheme>),
        )
        .route(
            "/v1/admin/instances/undrain/:id",
            post(admin_undrain_handler::<RavenInspireScheme>),
        )
        .route("/v1/instance/:id/session", post(session_establish_handler))
        .with_state(state.clone())
        .merge(params_route)
        .merge(poi_shim::poi_shim_routes(state.clone()))
        .layer(auth_layer.clone())
        .layer(DefaultBodyLimit::max(max_body));

    let rate_limited = if let Some(extractor) = trusted_proxies.clone() {
        rate_limited.layer(build_governor_layer_trusted(rps, burst, extractor)?)
    } else {
        rate_limited.layer(build_governor_layer_peer(rps, burst))
    };

    // Bypasses Governor only; `bearer_auth` still applies.
    let public = Router::new()
        .route("/v1/health/live", get(health_live_handler))
        .route(
            "/v1/health/ready",
            get(health_ready_handler::<RavenInspireScheme>),
        )
        .route("/v1/events", get(events_handler::<RavenInspireScheme>))
        .route("/metrics", get(metrics_handler::<RavenInspireScheme>))
        .with_state(state)
        .layer(auth_layer);

    let base = rate_limited.merge(public);

    // Cloudflare Tunnel real-IP rewrite; mounted only when trust is declared.
    let base = if let Some(extractor) = trusted_proxies {
        base.layer(middleware::from_fn(move |req, next| {
            cf_connecting_ip_to_xff(extractor.clone(), req, next)
        }))
    } else {
        base
    };

    let with_cors = if let Some(layer) = cors_layer {
        base.layer(layer)
    } else {
        base
    };

    Ok(with_cors.layer(
        TraceLayer::new_for_http()
            .make_span_with(|request: &Request<Body>| {
                tracing::info_span!(
                    "http_request",
                    method = %request.method(),
                    uri = %request.uri(),
                    status = tracing::field::Empty,
                    latency_us = tracing::field::Empty,
                )
            })
            .on_response(|response: &Response, latency: Duration, span: &Span| {
                span.record("status", response.status().as_u16());
                let micros = u64::try_from(latency.as_micros()).unwrap_or(u64::MAX);
                span.record("latency_us", micros);
            }),
    ))
}

type RavenGovernorLayerPeer = tower_governor::GovernorLayer<
    tower_governor::key_extractor::PeerIpKeyExtractor,
    governor::middleware::NoOpMiddleware,
>;

type RavenGovernorLayerTrusted =
    tower_governor::GovernorLayer<TrustedProxyIpKeyExtractor, governor::middleware::NoOpMiddleware>;

/// `None` when proxy trust is off, so the caller keeps `PeerIpKeyExtractor`.
fn resolve_trusted_proxies(
    config: &HttpConfig,
) -> Result<Option<TrustedProxyIpKeyExtractor>, String> {
    let ranges = config.resolve_trusted_proxy_ranges()?;
    if ranges.is_empty() {
        return Ok(None);
    }
    Ok(Some(TrustedProxyIpKeyExtractor::new(ranges.into())))
}

fn build_governor_layer_peer(rps: u64, burst: u32) -> RavenGovernorLayerPeer {
    use tower_governor::governor::GovernorConfigBuilder;
    use tower_governor::GovernorLayer;
    let cfg = GovernorConfigBuilder::default()
        .per_second(rps)
        .burst_size(burst)
        .finish();
    let cfg = match cfg {
        Some(c) => c,
        None => GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(1)
            .finish()
            .unwrap_or_default(),
    };
    GovernorLayer {
        config: Arc::new(cfg),
    }
}

/// `Err` only if `tower-governor` rejects a `(rps >= 1, burst >= 1)` config.
fn build_governor_layer_trusted(
    rps: u64,
    burst: u32,
    extractor: TrustedProxyIpKeyExtractor,
) -> Result<RavenGovernorLayerTrusted, String> {
    use tower_governor::governor::GovernorConfigBuilder;
    use tower_governor::GovernorLayer;
    let rps = rps.max(1);
    let burst = burst.max(1);
    let cfg = GovernorConfigBuilder::default()
        .key_extractor(extractor)
        .per_second(rps)
        .burst_size(burst)
        .finish()
        .ok_or_else(|| {
            format!(
                "tower-governor rejected trusted-proxy config (rps={rps}, burst={burst}); \
                 upstream invariant changed - file against tower-governor"
            )
        })?;
    Ok(GovernorLayer {
        config: Arc::new(cfg),
    })
}

/// CORS layer exposing `X-Raven-*` over GET + POST; `None` when no origins are set.
fn build_cors_layer(allowed_origins: &[String]) -> Option<CorsLayer> {
    use http::header::{AUTHORIZATION, CONTENT_TYPE};
    use http::HeaderValue;
    use http::Method;
    if allowed_origins.is_empty() {
        return None;
    }
    let parsed: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    if parsed.is_empty() {
        return None;
    }
    Some(
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(parsed))
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([AUTHORIZATION, CONTENT_TYPE])
            .expose_headers([
                http::HeaderName::from_static("x-raven-epoch"),
                http::HeaderName::from_static("x-raven-scheme"),
                http::HeaderName::from_static("x-raven-schema-version"),
                http::HeaderName::from_static("x-raven-session"),
                // tower_governor 0.4 emits `x-ratelimit-after`, not `retry-after`.
                http::HeaderName::from_static("x-ratelimit-after"),
            ]),
    )
}

pub(crate) fn build_response_headers(epoch: u64, scheme: &str) -> Result<HeaderMap, StatusCode> {
    let mut headers = HeaderMap::new();
    headers.insert(
        X_RAVEN_EPOCH,
        HeaderValue::from_str(&epoch.to_string()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    headers.insert(
        X_RAVEN_SCHEME,
        HeaderValue::from_str(scheme).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    if let Ok(name) = http::header::HeaderName::from_bytes(X_RAVEN_SCHEMA_VERSION_HEADER.as_bytes())
    {
        if let Ok(value) = HeaderValue::from_str(&WIRE_SCHEMA_VERSION.to_string()) {
            headers.insert(name, value);
        }
    }
    Ok(headers)
}

/// `X-Raven-Freshness`: `confidence = 1.0 - clamp(lag / 256.0, 0, 1)`.
fn freshness_header_value(
    metrics: Option<&parking_lot::Mutex<raven_railgun_engine::persistence::ConsumerMetrics>>,
    epoch: u64,
) -> String {
    let (lag, applied) = if let Some(m) = metrics {
        let snap = *m.lock();
        (snap.indexer_lag_blocks(), snap.last_applied_block)
    } else {
        (0, 0)
    };
    #[allow(clippy::cast_precision_loss)]
    let lag_f = lag as f64;
    let confidence = (1.0 - (lag_f / 256.0)).clamp(0.0, 1.0);
    format!("lag_blocks={lag} applied_height={applied} epoch={epoch} confidence={confidence:.3}")
}

/// Best-effort: failures are logged and dropped (freshness is non-critical).
pub(crate) fn attach_freshness_header(
    headers: &mut HeaderMap,
    metrics: Option<&parking_lot::Mutex<raven_railgun_engine::persistence::ConsumerMetrics>>,
    epoch: u64,
) {
    let value = freshness_header_value(metrics, epoch);
    match HeaderValue::from_str(&value) {
        Ok(v) => {
            headers.insert(X_RAVEN_FRESHNESS, v);
        }
        Err(err) => {
            tracing::warn!(?err, "failed to encode X-Raven-Freshness header");
        }
    }
}

#[allow(dead_code)]
fn extract_client_ip(req: &Request<Body>) -> Option<IpAddr> {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(sa)| sa.ip())
}

/// Install or return the process-global Prometheus recorder (idempotent via `OnceLock`).
pub(crate) fn global_prometheus_handle(
) -> Result<Arc<metrics_exporter_prometheus::PrometheusHandle>, String> {
    static HANDLE: OnceLock<Arc<metrics_exporter_prometheus::PrometheusHandle>> = OnceLock::new();
    if let Some(h) = HANDLE.get() {
        return Ok(Arc::clone(h));
    }
    let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
    match builder.install_recorder() {
        Ok(handle) => {
            let arc = Arc::new(handle);
            match HANDLE.set(Arc::clone(&arc)) {
                Ok(()) => Ok(arc),
                Err(_) => HANDLE
                    .get()
                    .cloned()
                    .ok_or_else(|| "OnceLock race produced no handle".to_owned()),
            }
        }
        Err(install_err) => {
            if let Some(h) = HANDLE.get() {
                return Ok(Arc::clone(h));
            }
            Err(format!(
                "metrics-exporter-prometheus install_recorder: {install_err}"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{ct_eq_str, stable_hash_token, EvictionOutcome, SessionKey, SessionMap};
    use crate::config::{HTTP_MAX_BODY_CEILING, HTTP_MAX_FANOUT_CEILING};
    use raven_inspire::ServerSessionHandle;
    use raven_railgun_core::InstanceId;
    use raven_railgun_engine::PirInstance;

    #[test]
    fn ct_eq_str_equal_inputs_returns_true() {
        let a = b"super-secret-token";
        let b = b"super-secret-token";
        let choice = ct_eq_str(a, b);
        let yes: bool = choice.into();
        assert!(yes);
    }

    #[test]
    fn ct_eq_str_differing_byte_returns_false() {
        let a = b"super-secret-token";
        let b = b"super-secret-tokeN";
        let choice = ct_eq_str(a, b);
        let yes: bool = choice.into();
        assert!(!yes);
    }

    #[test]
    fn ct_eq_str_unequal_lengths_returns_false() {
        let a = b"short";
        let b = b"a much longer string";
        let choice = ct_eq_str(a, b);
        let yes: bool = choice.into();
        assert!(!yes);
    }

    #[test]
    fn ct_eq_str_empty_inputs_match() {
        let choice = ct_eq_str(b"", b"");
        let yes: bool = choice.into();
        assert!(yes);
    }

    #[test]
    fn batch_error_status_internal_for_respond_and_invariant() {
        let respond_err = BatchError::Respond {
            index: 7,
            detail: "scheme respond failed".to_owned(),
        };
        assert_eq!(respond_err.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let inv = BatchError::Invariant("test invariant");
        assert_eq!(inv.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn batch_error_status_unavailable_for_worker_and_semaphore() {
        let worker_err = BatchError::WorkerAborted { index: 3 };
        assert_eq!(worker_err.status(), StatusCode::SERVICE_UNAVAILABLE);

        let sem_err = BatchError::SemaphoreClosed;
        assert_eq!(sem_err.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn batch_error_display_includes_index_and_detail() {
        let err = BatchError::Respond {
            index: 12,
            detail: "scheme err".to_owned(),
        };
        let s = format!("{err}");
        assert!(s.contains("12"), "Display must include the index: {s}");
        assert!(s.contains("scheme err"), "Display must include detail: {s}");
    }

    #[test]
    fn batch_error_index_resolves_slot_and_drops_the_unattributed_sentinel() {
        assert_eq!(
            BatchError::Respond {
                index: 5,
                detail: "x".to_owned()
            }
            .index(),
            Some(5)
        );
        assert_eq!(BatchError::Timeout { index: 2, secs: 1 }.index(), Some(2));
        assert_eq!(
            BatchError::WorkerAborted { index: usize::MAX }.index(),
            None,
            "the JoinSet-level sentinel must not be reported as slot usize::MAX"
        );
        assert_eq!(BatchError::SemaphoreClosed.index(), None);
        assert_eq!(BatchError::Invariant("x").index(), None);
    }

    #[test]
    fn fanout_error_validation_variants_map_to_400() {
        assert_eq!(FanoutError::NoShards.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            FanoutError::TooManyShards { got: 99, cap: 16 }.status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            FanoutError::ShardOutOfRange {
                shard_id: 7,
                index: 1,
                shard_count: 3
            }
            .status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn fanout_error_dispatch_delegates_status_and_names_the_shard() {
        let err = FanoutError::Dispatch {
            shard_id: 11,
            index: 2,
            source: BatchError::Timeout { index: 2, secs: 30 },
        };
        assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.class(), "timeout");
        let rendered = format!("{err}");
        assert!(
            rendered.contains("shard 11"),
            "Display must name the failing shard: {rendered}"
        );
    }

    #[test]
    fn http_config_validate_rejects_zero_max_fanout_shards() {
        let mut cfg = HttpConfig::demo("test-token-padded-long-enough-1234");
        cfg.max_fanout_shards = 0;
        let err = cfg
            .validate()
            .expect_err("zero max_fanout_shards must reject");
        assert!(err.contains("max_fanout_shards"), "err = {err}");
    }

    #[test]
    fn http_config_validate_rejects_oversize_max_fanout_shards() {
        let mut cfg = HttpConfig::demo("test-token-padded-long-enough-1234");
        cfg.max_fanout_shards = HTTP_MAX_FANOUT_CEILING + 1;
        let err = cfg
            .validate()
            .expect_err("oversize max_fanout_shards must reject");
        assert!(err.contains("max_fanout_shards"), "err = {err}");
    }

    #[test]
    fn session_key_stable_hash_is_deterministic() {
        let h1 = stable_hash_token("alpha-token");
        let h2 = stable_hash_token("alpha-token");
        let h3 = stable_hash_token("beta-token");
        assert_eq!(h1, h2, "same input must produce same hash");
        assert_ne!(h1, h3, "different inputs must produce different hashes");
    }

    #[test]
    fn session_key_eq_round_trips_via_stable_hash() {
        let id = InstanceId::new("toy");
        let zero = [0u8; 16];
        let a = SessionKey::new("token-X", id.clone(), zero);
        let b = SessionKey::new("token-X", id.clone(), zero);
        let c = SessionKey::new("token-Y", id, zero);
        assert_eq!(a, b, "same token + instance must produce equal keys");
        assert_ne!(a, c, "different token must differentiate");
    }

    #[test]
    fn http_config_demo_defaults_are_sensible() {
        let token = "test-token-padded-to-meet-min-length";
        let cfg = HttpConfig::demo(token);
        assert_eq!(cfg.read_token, token);
        assert_eq!(cfg.max_concurrent_queries, 4);
        assert_eq!(cfg.session_ttl_secs, 60 * 60);
        assert_eq!(cfg.session_lru_cap, 10_000);
        assert_eq!(cfg.rate_limit_rps, 200);
        assert_eq!(cfg.rate_limit_burst, 400);
        assert!(!cfg.metrics_public);
        assert_eq!(cfg.session_eviction_interval_secs, 3600);
        assert!(cfg.admin_token.is_none());
        cfg.validate().expect("padded token must validate");
    }

    #[test]
    fn http_config_validate_rejects_short_read_token() {
        let cfg = HttpConfig::demo("short");
        let err = cfg
            .validate()
            .expect_err("token below MIN_TOKEN_LEN must be rejected");
        assert!(err.contains("read_token too short"), "err = {err}");
    }

    #[test]
    fn http_config_validate_rejects_short_admin_token() {
        let mut cfg = HttpConfig::demo("test-token-padded-long");
        cfg.admin_token = Some("nope".to_owned());
        let err = cfg
            .validate()
            .expect_err("short admin_token must be rejected");
        assert!(err.contains("admin_token too short"), "err = {err}");
    }

    #[test]
    fn http_config_validate_rejects_wildcard_cors_origin() {
        let mut cfg = HttpConfig::demo("test-token-padded-long");
        cfg.cors_allowed_origins = vec!["*".to_owned()];
        let err = cfg
            .validate()
            .expect_err("wildcard CORS origin must be rejected");
        assert!(err.contains("must not contain `*`"), "err = {err}");
    }

    #[test]
    fn http_config_validate_rejects_empty_cors_origin() {
        let mut cfg = HttpConfig::demo("test-token-padded-long");
        cfg.cors_allowed_origins = vec![String::new()];
        let err = cfg
            .validate()
            .expect_err("empty CORS origin must be rejected");
        assert!(err.contains("must not be empty"), "err = {err}");
    }

    #[test]
    fn build_cors_layer_returns_none_for_empty_origins() {
        assert!(super::build_cors_layer(&[]).is_none());
    }

    #[test]
    fn build_cors_layer_returns_some_for_real_origin() {
        let origins = vec!["https://wallet.example.com".to_owned()];
        assert!(super::build_cors_layer(&origins).is_some());
    }

    #[test]
    fn resolve_trusted_proxies_defaults_to_the_peer_extractor() {
        let config = HttpConfig::demo("read-token-padded-long-enough");
        assert!(super::resolve_trusted_proxies(&config)
            .expect("default config resolves")
            .is_none());
    }

    #[test]
    fn resolve_trusted_proxies_refuses_a_bare_boolean() {
        let mut config = HttpConfig::demo("read-token-padded-long-enough");
        config.trust_proxy_header = true;
        let err = super::resolve_trusted_proxies(&config)
            .expect_err("router construction must refuse unscoped proxy trust");
        assert!(err.contains("trusted_proxy_cidrs"), "{err}");
    }

    #[test]
    fn resolve_trusted_proxies_builds_an_extractor_from_declared_ranges() {
        let mut config = HttpConfig::demo("read-token-padded-long-enough");
        config.trust_proxy_header = true;
        config.trusted_proxy_cidrs = vec!["172.16.0.0/12".to_owned()];
        let extractor = super::resolve_trusted_proxies(&config)
            .expect("declared ranges resolve")
            .expect("proxy trust is on");
        assert!(extractor.trusts("172.17.0.1".parse().expect("parses")));
        assert!(!extractor.trusts("203.0.113.9".parse().expect("parses")));
    }

    #[tokio::test]
    async fn cors_layer_accepts_allowed_origin_and_rejects_others() {
        use axum::body::Body;
        use axum::http::{Method, Request, StatusCode};
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        let allowed = "https://wallet.example.com";
        let cors = super::build_cors_layer(&[allowed.to_owned()])
            .expect("CorsLayer expected for non-empty allowlist");
        let app: Router = Router::new()
            .route("/v1/status", get(|| async { "ok" }))
            .layer(cors);

        let allowed_req = Request::builder()
            .method(Method::OPTIONS)
            .uri("/v1/status")
            .header("Origin", allowed)
            .header("Access-Control-Request-Method", "GET")
            .body(Body::empty())
            .expect("build allowed preflight");
        let resp = app
            .clone()
            .oneshot(allowed_req)
            .await
            .expect("allowed preflight");
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::NO_CONTENT,
            "allowed preflight should be 200/204, got {}",
            resp.status()
        );
        let allow_origin = resp
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        assert_eq!(
            allow_origin.as_deref(),
            Some(allowed),
            "preflight from allowed origin must echo Access-Control-Allow-Origin"
        );

        // CORS reject is enforced by the browser via header absence, not HTTP status.
        let evil_req = Request::builder()
            .method(Method::OPTIONS)
            .uri("/v1/status")
            .header("Origin", "https://evil.example.com")
            .header("Access-Control-Request-Method", "GET")
            .body(Body::empty())
            .expect("build evil preflight");
        let evil_resp = app.oneshot(evil_req).await.expect("evil preflight");
        let evil_allow_origin = evil_resp
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        assert!(
            evil_allow_origin.is_none(),
            "preflight from disallowed origin must NOT carry \
             Access-Control-Allow-Origin (got {evil_allow_origin:?})"
        );
    }

    #[test]
    fn session_map_eviction_outcome_pressure_when_cap_full_with_live_entries() {
        use std::time::{Duration, Instant};
        let map = SessionMap::new();
        let now = Instant::now();
        let ttl = Duration::from_secs(3600);
        let zero = [0u8; 16];
        let k1 = SessionKey::new("a", InstanceId::new("toy"), zero);
        let k2 = SessionKey::new("b", InstanceId::new("toy"), zero);
        let k3 = SessionKey::new("c", InstanceId::new("toy"), zero);
        let h = ServerSessionHandle(1);
        let _ = map.upsert(k1, h, now + ttl, 2, now);
        let _ = map.upsert(k2, h, now + ttl + Duration::from_secs(1), 2, now);
        let outcome = map.upsert(k3, h, now + ttl + Duration::from_secs(2), 2, now);
        assert!(matches!(outcome, EvictionOutcome::Pressure));
    }

    #[test]
    fn session_map_get_returns_none_when_expired() {
        use std::time::{Duration, Instant};
        let map = SessionMap::new();
        let now = Instant::now();
        let k = SessionKey::new("a", InstanceId::new("toy"), [0u8; 16]);
        let h = ServerSessionHandle(7);
        let past = now
            .checked_sub(Duration::from_secs(1))
            .expect("not at boot epoch");
        let _ = map.upsert(k.clone(), h, past, 100, now);
        assert!(map.get(&k, now).is_none());
        assert_eq!(map.len(), 0, "expired entry must be pruned on get");
    }

    #[test]
    fn status_response_consumer_field_omitted_when_no_metrics_attached() {
        let resp = StatusResponse {
            scheme: "raven-inspire".to_owned(),
            instances: vec![],
            consumer: None,
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        assert!(
            !json.contains("consumer"),
            "consumer field must be omitted when None: {json}"
        );
    }

    #[test]
    fn status_response_consumer_field_serialises_when_present() {
        let resp = StatusResponse {
            scheme: "raven-inspire".to_owned(),
            instances: vec![],
            consumer: Some(ConsumerStatus {
                last_applied_block: 100,
                last_scanned_block: 200,
                last_known_chain_head: 200,
                indexer_lag_blocks: 0,
                blocks_since_last_applied_event: 100,
                events_processed: 5,
                commits_fired: 1,
                reorgs_handled: 0,
                consumer_errors: 0,
            }),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        assert!(json.contains("\"indexer_lag_blocks\":0"));
        assert!(json.contains("\"blocks_since_last_applied_event\":100"));
        assert!(json.contains("\"last_applied_block\":100"));
        assert!(json.contains("\"last_scanned_block\":200"));
        assert!(json.contains("\"last_known_chain_head\":200"));
    }

    #[derive(Debug, Default)]
    struct SlowableScheme;

    #[derive(Debug, Default)]
    struct SlowableState {
        sleep_ms_per_query: parking_lot::Mutex<std::collections::HashMap<u32, u64>>,
    }

    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    struct SlowableQuery {
        tag: u32,
    }

    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    struct SlowableResponse {
        echo_tag: u32,
    }

    impl raven_railgun_engine::PirScheme for SlowableScheme {
        type ServerState = SlowableState;
        type Query = SlowableQuery;
        type Response = SlowableResponse;
        fn respond(
            state: &Self::ServerState,
            query: &Self::Query,
        ) -> raven_railgun_core::Result<Self::Response> {
            let sleep_ms = state
                .sleep_ms_per_query
                .lock()
                .get(&query.tag)
                .copied()
                .unwrap_or(0);
            if sleep_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
            }
            Ok(SlowableResponse {
                echo_tag: query.tag,
            })
        }
    }

    fn build_slowable_instance(state: SlowableState) -> Arc<PirInstance<SlowableScheme>> {
        use raven_railgun_engine::InstanceRole;
        Arc::new(PirInstance::<SlowableScheme>::new(
            raven_railgun_core::InstanceId::new("test-batch-instance"),
            InstanceRole::Live,
            state,
        ))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dispatch_batch_timeout_attributes_correct_slot() {
        // Slot 2 sleeps 5 s; timeout = 250 ms; slots 0, 1, 3 are fast.
        const SLOW_SLOT: usize = 2;
        const SLOW_TAG: u32 = 4242;
        let state = SlowableState::default();
        state.sleep_ms_per_query.lock().insert(SLOW_TAG, 5_000);
        let instance = build_slowable_instance(state);
        let queries: Vec<SlowableQuery> = vec![
            SlowableQuery { tag: 1 },
            SlowableQuery { tag: 2 },
            SlowableQuery { tag: SLOW_TAG },
            SlowableQuery { tag: 3 },
        ];

        let semaphore = Arc::new(tokio::sync::Semaphore::new(4));
        let snapshot = instance.current_snapshot();
        let started = std::time::Instant::now();
        let result = crate::batch::dispatch_batch::<SlowableScheme, SlowableQuery>(
            queries,
            Arc::clone(&instance),
            snapshot,
            semaphore,
            4,
            std::time::Duration::from_millis(250),
        )
        .await;
        let elapsed = started.elapsed();

        let err = result.expect_err("slow slot must time out");
        match err {
            BatchError::Timeout { index, secs: _ } => {
                assert_eq!(
                    index, SLOW_SLOT,
                    "timeout index must point at the slow slot, not a sibling"
                );
            }
            other => panic!("expected BatchError::Timeout, got {other:?}"),
        }
        assert_eq!(err_status_for_timeout(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "dispatch_batch must short-circuit on timeout; ran for {elapsed:?}"
        );
    }

    fn err_status_for_timeout() -> StatusCode {
        BatchError::Timeout { index: 0, secs: 1 }.status()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dispatch_batch_success_path_preserves_order() {
        let instance = build_slowable_instance(SlowableState::default());
        let queries: Vec<SlowableQuery> = (10u32..14u32).map(|tag| SlowableQuery { tag }).collect();

        let semaphore = Arc::new(tokio::sync::Semaphore::new(4));
        let snapshot = instance.current_snapshot();
        let result = crate::batch::dispatch_batch::<SlowableScheme, SlowableQuery>(
            queries,
            instance,
            snapshot,
            semaphore,
            4,
            std::time::Duration::from_secs(2),
        )
        .await;
        let responses = result.expect("all-fast batch must succeed");
        let tags: Vec<u32> = responses.iter().map(|r| r.echo_tag).collect();
        assert_eq!(tags, vec![10, 11, 12, 13]);
    }

    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
    struct VarLenItem {
        tag: u32,
        payload: Vec<u8>,
    }

    fn make_varlen_item(seed: u32, payload_len: usize) -> VarLenItem {
        let mut payload = Vec::with_capacity(payload_len);
        for i in 0..payload_len {
            payload.push(((seed.wrapping_add(i as u32)) & 0xff) as u8);
        }
        VarLenItem { tag: seed, payload }
    }

    fn assert_batch_round_trip_at_k(k: usize) {
        // Varied sizes exercise per-element length prefixing.
        let items: Vec<VarLenItem> = (0..k)
            .map(|i| make_varlen_item(i as u32, 1 + (i * 13) % 257))
            .collect();
        let bytes = super::write_batch_response_versioned(&items)
            .expect("write_batch_response_versioned must succeed");

        assert_eq!(
            &bytes[0..2],
            &super::WIRE_SCHEMA_VERSION.to_be_bytes(),
            "schema prefix must be u16 BE WIRE_SCHEMA_VERSION at K={k}"
        );
        let mut count_buf = [0u8; 8];
        count_buf.copy_from_slice(&bytes[2..10]);
        assert_eq!(
            u64::from_le_bytes(count_buf),
            k as u64,
            "u64 LE count must equal K={k}"
        );

        let decoded: Vec<VarLenItem> =
            super::read_batch_response_versioned(&bytes).expect("decode must succeed");
        assert_eq!(decoded, items, "round-trip equality must hold at K={k}");

        let bytes2 =
            super::write_batch_response_versioned(&decoded).expect("re-encode must succeed");
        assert_eq!(bytes, bytes2, "encoder must be deterministic at K={k}");
    }

    #[test]
    fn write_batch_response_versioned_round_trips_at_k1() {
        assert_batch_round_trip_at_k(1);
    }

    #[test]
    fn write_batch_response_versioned_round_trips_at_k4() {
        assert_batch_round_trip_at_k(4);
    }

    #[test]
    fn write_batch_response_versioned_round_trips_at_k16() {
        assert_batch_round_trip_at_k(16);
    }

    #[test]
    fn write_batch_response_versioned_round_trips_at_k256() {
        assert_batch_round_trip_at_k(256);
    }

    #[test]
    fn write_batch_response_versioned_emits_expected_bytes_k4() {
        let items: Vec<VarLenItem> = (0..4u32)
            .map(|i| make_varlen_item(i, 1 + ((i as usize) * 13) % 257))
            .collect();
        let bytes = super::write_batch_response_versioned(&items).expect("write");

        let mut expected: Vec<u8> = Vec::new();
        expected.extend_from_slice(&super::WIRE_SCHEMA_VERSION.to_be_bytes()); // u16 BE
        expected.extend_from_slice(&(4u64).to_le_bytes()); // u64 LE count
        for item in &items {
            let body = bincode::serialize(item).expect("bincode");
            expected.extend_from_slice(&(body.len() as u64).to_le_bytes()); // u64 LE elem-len
            expected.extend_from_slice(&body);
        }
        assert_eq!(
            bytes, expected,
            "write_batch_response_versioned must emit \
             [u16 BE schema][u64 LE count][per-elem u64 LE len][bincode] \
             concatenated; deviation breaks SDK decoder"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dispatch_batch_drain_during_batch_blocks_late_queries() {
        let state = SlowableState::default();
        // Slots 0-1 hold in-flight guards across the drain flip; later slots acquire
        // after it and must surface NoActiveInstance.
        state.sleep_ms_per_query.lock().insert(100, 250);
        state.sleep_ms_per_query.lock().insert(101, 250);
        let instance = build_slowable_instance(state);

        let queries: Vec<SlowableQuery> = vec![
            SlowableQuery { tag: 100 },
            SlowableQuery { tag: 101 },
            SlowableQuery { tag: 1 },
            SlowableQuery { tag: 2 },
            SlowableQuery { tag: 3 },
            SlowableQuery { tag: 4 },
            SlowableQuery { tag: 5 },
            SlowableQuery { tag: 6 },
        ];

        let semaphore = Arc::new(tokio::sync::Semaphore::new(2));
        let inst_for_drain = Arc::clone(&instance);
        let drain_handle = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            inst_for_drain.set_drain_state(raven_railgun_engine::DrainState::Draining);
        });

        let snapshot = instance.current_snapshot();
        let result = crate::batch::dispatch_batch::<SlowableScheme, SlowableQuery>(
            queries,
            Arc::clone(&instance),
            snapshot,
            semaphore,
            2,
            std::time::Duration::from_secs(5),
        )
        .await;
        drain_handle.await.expect("drain task must finish");

        let err = result.expect_err("dispatch must short-circuit once drain hits");
        match err {
            BatchError::Respond { detail, .. } => {
                assert!(
                    detail.contains("draining") || detail.contains("drained"),
                    "expected NoActiveInstance respond error \
                     (\"draining or drained\"), got: {detail}"
                );
            }
            other => panic!("expected BatchError::Respond(NoActiveInstance), got {other:?}"),
        }
    }

    #[test]
    fn http_config_validate_rejects_zero_max_body_bytes() {
        let mut cfg = HttpConfig::demo("test-token-padded-long-enough-1234");
        cfg.max_body_bytes = 0;
        let err = cfg.validate().expect_err("zero max_body_bytes must reject");
        assert!(
            err.contains("max_body_bytes"),
            "error must mention max_body_bytes: {err}"
        );
    }

    #[test]
    fn http_config_validate_rejects_oversize_max_body_bytes() {
        let mut cfg = HttpConfig::demo("test-token-padded-long-enough-1234");
        cfg.max_body_bytes = HTTP_MAX_BODY_CEILING + 1;
        let err = cfg
            .validate()
            .expect_err("oversize max_body_bytes must reject");
        assert!(
            err.contains("max_body_bytes"),
            "error must mention max_body_bytes: {err}"
        );
    }

    #[test]
    fn http_config_validate_accepts_max_body_bytes_at_ceiling() {
        let mut cfg = HttpConfig::demo("test-token-padded-long-enough-1234");
        cfg.max_body_bytes = HTTP_MAX_BODY_CEILING;
        cfg.validate()
            .expect("max_body_bytes at the ceiling must validate");
    }
}
