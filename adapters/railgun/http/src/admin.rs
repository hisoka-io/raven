//! Admin drain/undrain handlers and inspire-specific session/params handlers.

use std::time::{Duration, Instant};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    Json,
};
use bytes::Bytes;
use raven_inspire::inspiring::ClientPackingKeys;
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{InspireServerState, RavenInspireScheme};
use raven_railgun_engine::{DrainState, PirScheme};
use serde::{Deserialize, Serialize};

use crate::auth::{ct_eq_str, EvictionOutcome, SessionKey};
use crate::state::AppState;
use crate::versioned::{read_versioned, write_versioned, WIRE_SCHEMA_VERSION};
use crate::{X_RAVEN_EPOCH, X_RAVEN_SCHEME, X_RAVEN_SESSION};

/// JSON body returned by drain/undrain admin routes.
#[derive(Serialize, Deserialize, Debug)]
pub struct DrainAdminResponse {
    /// Echoed instance id.
    pub instance_id: String,
    /// Post-transition drain state label.
    pub drain_state: String,
    /// In-flight count at response time.
    pub in_flight: u64,
}

pub(crate) fn admin_token_matches<S: PirScheme>(app: &AppState<S>, headers: &HeaderMap) -> bool {
    let Some(admin) = app.admin_token.as_ref().as_ref() else {
        // Dummy compare keeps the no-admin path the same cost as the with-admin path.
        let _ = ct_eq_str(b"", b"");
        return false;
    };
    let supplied = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or_default();
    ct_eq_str(supplied.as_bytes(), admin.as_bytes()).into()
}

/// Max time in ms to wait for in-flight count to reach zero after flipping to Draining.
pub(crate) const DRAIN_PROMOTE_BUDGET_MS: u64 = 30_000;
pub(crate) const DRAIN_PROMOTE_POLL_INTERVAL_MS: u64 = 50;

pub(crate) async fn admin_drain_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<DrainAdminResponse>, StatusCode> {
    if !admin_token_matches(&app, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let instance_id = InstanceId::new(id);
    let instance = app
        .engine
        .instance(&instance_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    let current = instance.drain_state();
    if matches!(current, DrainState::Active | DrainState::Draining) {
        instance.set_drain_state(DrainState::Draining);
    }

    let deadline = Instant::now() + Duration::from_millis(DRAIN_PROMOTE_BUDGET_MS);
    while Instant::now() < deadline {
        if instance.in_flight_count() == 0 {
            // Guard against a concurrent undrain racing in.
            if instance.drain_state() == DrainState::Draining {
                instance.set_drain_state(DrainState::Drained);
            }
            break;
        }
        tokio::time::sleep(Duration::from_millis(DRAIN_PROMOTE_POLL_INTERVAL_MS)).await;
    }

    let final_state = instance.drain_state();
    let in_flight = instance.in_flight_count();
    Ok(Json(DrainAdminResponse {
        instance_id: instance.id.to_string(),
        drain_state: final_state.label().to_owned(),
        in_flight,
    }))
}

pub(crate) async fn admin_undrain_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<DrainAdminResponse>, StatusCode> {
    if !admin_token_matches(&app, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let instance_id = InstanceId::new(id);
    let instance = app
        .engine
        .instance(&instance_id)
        .ok_or(StatusCode::NOT_FOUND)?;
    instance.set_drain_state(DrainState::Active);
    Ok(Json(DrainAdminResponse {
        instance_id: instance.id.to_string(),
        drain_state: DrainState::Active.label().to_owned(),
        in_flight: instance.in_flight_count(),
    }))
}

// Inspire-specific routes: session establish + params

/// JSON returned by `POST /v1/instance/{id}/session`.
#[derive(Serialize, Deserialize, Debug)]
pub struct SessionEstablishResponse {
    /// Opaque server-side session handle; embed in subsequent queries.
    pub handle: u64,
    /// Unix-epoch second at which this session expires.
    pub expires_at_unix_secs: u64,
}

/// Wire-format instance parameters returned by `GET /v1/instance/{id}/params`.
#[derive(Serialize, Deserialize, Debug)]
pub struct InstanceParams {
    /// Server's wire schema version; wallets validate at bootstrap.
    pub wire_schema_version: u16,
    /// Bincode-encoded [`raven_inspire::ServerCrs`].
    pub crs_bincode: Vec<u8>,
    /// Bincode-encoded [`raven_inspire::params::ShardConfig`].
    pub shard_config_bincode: Vec<u8>,
    /// Plaintext entry size in bytes.
    pub entry_size: usize,
    /// InsPIRe variant the server is running.
    pub variant: String,
    /// Current snapshot epoch.
    pub epoch: u64,
}

pub(crate) async fn session_establish_handler(
    State(app): State<AppState<RavenInspireScheme>>,
    Path(id): Path<String>,
    headers_in: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Json<SessionEstablishResponse>), StatusCode> {
    let instance_id = InstanceId::new(id);
    let instance = app
        .engine
        .instance(&instance_id)
        .ok_or(StatusCode::NOT_FOUND)?;
    let state = instance.current_state();
    let state: &InspireServerState = state.as_ref();

    let token = headers_in
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let keys: ClientPackingKeys = read_versioned(&body).map_err(|err| {
        tracing::warn!(
            ?err,
            "session establish versioned-bincode deserialize failed"
        );
        StatusCode::BAD_REQUEST
    })?;
    let pack_params = state.cache.pack_params();
    let ctx = state.crs.params.ntt_context();
    let handle = state
        .session_store
        .register_server_side(keys, pack_params, &ctx)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let session_key = SessionKey::new(token, instance_id.clone());
    let ttl = Duration::from_secs(app.config.session_ttl_secs);
    let now = Instant::now();
    let expires_at = now + ttl;
    let outcome = app.sessions.upsert(
        session_key,
        handle,
        expires_at,
        app.config.session_lru_cap,
        now,
    );

    metrics::counter!(
        "raven_railgun_sessions_established_total",
        "instance" => instance_id.to_string()
    )
    .increment(1);
    // session_lru_cap < 2^32 by default; cast is safe.
    #[allow(clippy::cast_precision_loss)]
    let occupancy = app.sessions.len() as f64;
    metrics::gauge!(
        "raven_railgun_sessions_occupancy",
        "instance" => instance_id.to_string()
    )
    .set(occupancy);
    if matches!(outcome, EvictionOutcome::Pressure) {
        metrics::counter!(
            "raven_railgun_session_eviction_pressure_total",
            "instance" => instance_id.to_string()
        )
        .increment(1);
    }

    let expires_at_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .saturating_add(app.config.session_ttl_secs);

    let mut hdrs = HeaderMap::new();
    hdrs.insert(
        X_RAVEN_SESSION,
        HeaderValue::from_str(&handle.0.to_string())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    hdrs.insert(
        X_RAVEN_SCHEME,
        HeaderValue::from_str(&app.scheme_name).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    Ok((
        StatusCode::OK,
        hdrs,
        Json(SessionEstablishResponse {
            handle: handle.0,
            expires_at_unix_secs,
        }),
    ))
}

pub(crate) async fn params_handler(
    State(app): State<AppState<RavenInspireScheme>>,
    Path(id): Path<String>,
) -> Result<(StatusCode, HeaderMap, Bytes), StatusCode> {
    let instance_id = InstanceId::new(id);
    let instance = app
        .engine
        .instance(&instance_id)
        .ok_or(StatusCode::NOT_FOUND)?;
    let state = instance.current_state();
    let state: &InspireServerState = state.as_ref();
    let crs_bincode =
        bincode::serialize(&state.crs).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let shard_config_bincode = bincode::serialize(&state.encoded_db.config)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let payload = InstanceParams {
        wire_schema_version: WIRE_SCHEMA_VERSION,
        crs_bincode,
        shard_config_bincode,
        entry_size: state.entry_size,
        variant: format!("{:?}", state.variant),
        epoch: instance.current_epoch().0,
    };
    let body = write_versioned(&payload).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut hdrs = HeaderMap::new();
    hdrs.insert(
        X_RAVEN_EPOCH,
        HeaderValue::from_str(&instance.current_epoch().0.to_string())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    hdrs.insert(
        X_RAVEN_SCHEME,
        HeaderValue::from_str(&app.scheme_name).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    Ok((StatusCode::OK, hdrs, body.into()))
}
