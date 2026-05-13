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

use crate::auth::{ct_eq_str, parse_client_id_header, EvictionOutcome, SessionKey};
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
    /// Bincode-encoded [`raven_inspire::params::InspireParams`]. Sourced
    /// from the live [`InspireServerState`]'s CRS so the bytes always
    /// match the operator-configured cell shape (rather than re-deriving
    /// from a hard-coded preset). Wallets feed this directly into the
    /// WASM client's `build_instance_params_blob` helper to derive the
    /// RLWE secret key and assemble a [`raven_inspire::ClientSession`]
    /// without needing a side-channel param distribution.
    pub inspire_params_bincode: Vec<u8>,
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

    let client_id = parse_client_id_header(&headers_in);
    let session_key = SessionKey::new(token, instance_id.clone(), client_id);
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
        .map_or(0, |d| d.as_secs())
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

#[allow(clippy::too_many_lines)]
pub(crate) async fn params_handler(
    State(app): State<AppState<RavenInspireScheme>>,
    Path(id): Path<String>,
    headers_in: HeaderMap,
) -> Result<(StatusCode, HeaderMap, Bytes), StatusCode> {
    let instance_id = InstanceId::new(id);
    let instance = app
        .engine
        .instance(&instance_id)
        .ok_or(StatusCode::NOT_FOUND)?;
    let epoch = instance.current_epoch();

    // Fast-path 304: when the cache already has a SHA for the current
    // `(instance_id, epoch)` AND the caller's `If-None-Match` matches,
    // we can skip body serialization entirely. CRS bincode at the
    // production cell is multi-MB; this saves both the CPU + the
    // allocation on every revalidation against an unchanged epoch.
    let cached_etag_value = {
        let guard = app.params_etag_cache.read();
        guard
            .get(&instance_id)
            .filter(|(stored_epoch, _)| *stored_epoch == epoch)
            .map(|(_, hash)| format!("\"{}\"", to_hex_lower(hash)))
    };
    let if_none_match = headers_in
        .get(http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    if let (Some(cached_value), Some(provided)) =
        (cached_etag_value.as_ref(), if_none_match.as_ref())
    {
        if cached_value == provided {
            let mut hdrs = HeaderMap::new();
            hdrs.insert(
                X_RAVEN_EPOCH,
                HeaderValue::from_str(&epoch.0.to_string())
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            );
            hdrs.insert(
                X_RAVEN_SCHEME,
                HeaderValue::from_str(&app.scheme_name)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            );
            hdrs.insert(
                http::header::ETAG,
                HeaderValue::from_str(cached_value)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            );
            hdrs.insert(
                http::header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=86400, immutable"),
            );
            hdrs.insert(
                http::header::VARY,
                HeaderValue::from_static("Authorization"),
            );
            hdrs.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            return Ok((StatusCode::NOT_MODIFIED, hdrs, Bytes::new()));
        }
    }

    // Cache miss OR caller's ETag is stale: serialize the body and
    // populate the cache so the next revalidation against the same
    // epoch hits the fast-path above.
    let state = instance.current_state();
    let state: &InspireServerState = state.as_ref();
    let crs_bincode =
        bincode::serialize(&state.crs).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let shard_config_bincode = bincode::serialize(&state.encoded_db.config)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let inspire_params_bincode =
        bincode::serialize(&state.crs.params).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let payload = InstanceParams {
        wire_schema_version: WIRE_SCHEMA_VERSION,
        crs_bincode,
        shard_config_bincode,
        inspire_params_bincode,
        entry_size: state.entry_size,
        variant: format!("{:?}", state.variant),
        epoch: epoch.0,
    };
    let body = write_versioned(&payload).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // ETag = SHA-256 of the body. Cache keyed on `InstanceId` with
    // `(epoch, sha256)` payload so an epoch bump invalidates the prior
    // entry without growing the map; the cache lives on the per-process
    // `AppState` so test isolation matches production isolation.
    let sha = if let Some(value) = cached_etag_value.as_ref() {
        // Cache hit on epoch but ETag string did not match the caller's
        // If-None-Match (or no If-None-Match was supplied). Re-derive
        // the bytes by re-parsing the cached hex — cheap relative to
        // re-hashing the freshly-serialized body.
        parse_hex_sha(value).unwrap_or_else(|| sha256_of(&body))
    } else {
        let fresh = sha256_of(&body);
        let mut guard = app.params_etag_cache.write();
        guard.insert(instance_id.clone(), (epoch, fresh));
        fresh
    };
    let etag_value = format!("\"{}\"", to_hex_lower(&sha));

    let etag_matches = if_none_match.as_deref().is_some_and(|v| v == etag_value);

    let mut hdrs = HeaderMap::new();
    hdrs.insert(
        X_RAVEN_EPOCH,
        HeaderValue::from_str(&epoch.0.to_string())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    hdrs.insert(
        X_RAVEN_SCHEME,
        HeaderValue::from_str(&app.scheme_name).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    hdrs.insert(
        http::header::ETAG,
        HeaderValue::from_str(&etag_value).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    hdrs.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400, immutable"),
    );
    hdrs.insert(
        http::header::VARY,
        HeaderValue::from_static("Authorization"),
    );
    hdrs.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );

    if etag_matches {
        return Ok((StatusCode::NOT_MODIFIED, hdrs, Bytes::new()));
    }
    Ok((StatusCode::OK, hdrs, body.into()))
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

fn parse_hex_sha(quoted: &str) -> Option<[u8; 32]> {
    let inner = quoted.strip_prefix('"').and_then(|s| s.strip_suffix('"'))?;
    if inner.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, dst) in out.iter_mut().enumerate() {
        let hi = char_to_nibble(inner.as_bytes().get(i * 2).copied()?)?;
        let lo = char_to_nibble(inner.as_bytes().get(i * 2 + 1).copied()?)?;
        *dst = (hi << 4) | lo;
    }
    Some(out)
}

fn char_to_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Lowercase hex encoding of a 32-byte SHA-256 digest. Avoids pulling
/// the `hex` crate just for the ETag-formatting path. Bounded loop
/// over fixed-length input; never panics.
fn to_hex_lower(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        // `b >> 4` and `b & 0x0f` are bounded to 0..16, well within
        // the radix-16 contract of `from_digit`; the `unwrap_or('0')`
        // branch is unreachable but keeps the path panic-free.
        let hi = char::from_digit(u32::from(b >> 4), 16).unwrap_or('0');
        let lo = char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0');
        out.push(hi);
        out.push(lo);
    }
    out
}
