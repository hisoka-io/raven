//! The client handshake: `GET /params` for the CRS and `POST /session` for a packing-key seat.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    body::{Body, HttpBody},
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    Json,
};
use bytes::Bytes;
use raven_inspire::inspiring::ClientPackingKeys;
use raven_inspire::params::InspireParams;
use raven_inspire::{ServerCrs, ServerSessionHandle};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{InspireServerState, RavenInspireScheme};
use serde::{Deserialize, Serialize};

use crate::auth::{require_client_id_header, EvictionOutcome, SessionKey};
use crate::state::AppState;
use crate::versioned::{read_versioned, write_versioned, WIRE_SCHEMA_VERSION};
use crate::{X_RAVEN_EPOCH, X_RAVEN_SCHEME, X_RAVEN_SESSION};

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
    /// Bincode-encoded [`raven_inspire::params::InspireParams`], sourced from
    /// the live CRS so the bytes always match the operator-configured cell
    /// shape; wallets derive the RLWE secret key from this.
    pub inspire_params_bincode: Vec<u8>,
    /// Plaintext entry size in bytes.
    pub entry_size: usize,
    /// InsPIRe variant the server is running.
    pub variant: String,
    /// Current snapshot epoch.
    pub epoch: u64,
}

/// Wire CRS. Empties `galois_keys` - 99.98% of the bytes, read only by the server's own
/// [`raven_inspire::PackingMode::Tree`] path - and the two `#[serde(skip)]` `inspiring_*`
/// options, which never reach the wire either way. Field-by-field so a CRS layout change
/// fails to compile rather than silently re-inflating.
fn crs_wire_bytes(crs: &ServerCrs) -> raven_inspire::pir::Result<Vec<u8>> {
    ServerCrs {
        params: crs.params.clone(),
        galois_keys: Vec::new(),
        rgsw_gadget: crs.rgsw_gadget.clone(),
        inspiring_pack_params: None,
        inspiring_packing_key: None,
        inspiring_w_seed: crs.inspiring_w_seed,
        inspiring_v_seed: crs.inspiring_v_seed,
        inspiring_num_columns: crs.inspiring_num_columns,
    }
    .to_versioned_bytes()
}

fn count_establish_refusal(instance_id: &InstanceId, reason: &'static str) {
    metrics::counter!(
        "raven_railgun_session_establish_refused_total",
        "instance" => instance_id.to_string(),
        "reason" => reason
    )
    .increment(1);
}

/// What a handshake's blocking derivation hands back.
enum Derivation {
    Registered(ServerSessionHandle),
    /// Every seat is held by a live session or a derivation in flight; the caller should retry
    /// later.
    PoolFull(raven_railgun_core::AdapterError),
    Failed(raven_railgun_core::AdapterError),
}

/// Release a seat on a blocking thread: removal waits for the store's write lock, which a sweep
/// holds for its whole pass.
async fn release_seat(state: Arc<InspireServerState>, handle: ServerSessionHandle) {
    if let Err(join) = tokio::task::spawn_blocking(move || state.session_store.remove(handle)).await
    {
        tracing::error!(%join, "session seat release failed");
    }
}

/// Largest packing-key upload an honest client sends under `params`: `y_body` and, for full
/// packing, `z_body`, each `packing_gadget_len` polys of `ring_dim` coefficients per CRT
/// modulus at the fixed-width 8 bytes, plus framing. A queued handshake holds its body, so
/// this, not `max_body_bytes`, bounds what a flood of them can pin.
pub(crate) fn packing_key_upload_limit(params: &InspireParams) -> usize {
    const FRAMING_BYTES: usize = 4096;
    2usize
        .saturating_mul(params.packing_gadget_len)
        .saturating_mul(params.ring_dim)
        .saturating_mul(params.crt_moduli.len().max(1))
        .saturating_mul(8)
        .saturating_add(FRAMING_BYTES)
}

/// Buffers at most `limit` bytes; the size hint refuses a declared oversize body unread.
async fn read_capped(mut body: Body, limit: usize) -> Result<Vec<u8>, StatusCode> {
    let declared = usize::try_from(HttpBody::size_hint(&body).lower()).unwrap_or(usize::MAX);
    if declared > limit {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let mut buffered = Vec::with_capacity(declared);
    while let Some(frame) =
        std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await
    {
        let frame = frame.map_err(|_| StatusCode::BAD_REQUEST)?;
        if let Ok(data) = frame.into_data() {
            if buffered.len().saturating_add(data.len()) > limit {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            buffered.extend_from_slice(&data);
        }
    }
    Ok(buffered)
}

/// Derive the server-side set on a blocking thread: the key expansion is CPU-bound, and on an
/// async worker it would stall every route that worker serves.
/// The permit is held until the work ends, even when the handler has stopped waiting, because
/// `spawn_blocking` cannot be cancelled.
async fn derive_off_the_workers(
    app: &AppState<RavenInspireScheme>,
    instance_id: &InstanceId,
    state: Arc<InspireServerState>,
    keys: ClientPackingKeys,
) -> Result<Derivation, StatusCode> {
    let permit = match tokio::time::timeout(
        app.config.respond_permit_wait(),
        Arc::clone(&app.handshake_permits).acquire_owned(),
    )
    .await
    {
        Ok(Ok(permit)) => permit,
        Ok(Err(_closed)) => return Err(StatusCode::SERVICE_UNAVAILABLE),
        Err(_elapsed) => {
            count_establish_refusal(instance_id, "busy");
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    let owner = Arc::clone(&state);
    let mut derivation = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let ctx = state.crs.params.ntt_context();
        match state
            .session_store
            .register_server_side(keys, state.cache.pack_params(), &ctx)
        {
            Ok(handle) => Derivation::Registered(handle),
            // A re-handshake counts its own old seat too: that seat stays usable until a new one
            // replaces it.
            Err(error @ raven_railgun_core::AdapterError::AtCapacity(_)) => {
                Derivation::PoolFull(error)
            }
            Err(error) => Derivation::Failed(error),
        }
    });
    let limit = Duration::from_secs(app.config.respond_timeout_secs.max(1));
    match tokio::time::timeout(limit, &mut derivation).await {
        Ok(Ok(derived)) => Ok(derived),
        Ok(Err(join)) => {
            tracing::error!(%join, "session derivation task failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(_elapsed) => {
            count_establish_refusal(instance_id, "timeout");
            // Nobody will learn the handle, so its seat is released when the derivation lands.
            tokio::spawn(async move {
                if let Ok(Derivation::Registered(handle)) = derivation.await {
                    release_seat(owner, handle).await;
                }
            });
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

pub(crate) async fn session_establish_handler(
    State(app): State<AppState<RavenInspireScheme>>,
    Path(id): Path<String>,
    headers_in: HeaderMap,
    body: Body,
) -> Result<(StatusCode, HeaderMap, Json<SessionEstablishResponse>), StatusCode> {
    let instance_id = InstanceId::new(id);
    let instance = app
        .engine
        .instance(&instance_id)
        .ok_or(StatusCode::NOT_FOUND)?;
    let snapshot = instance.current_snapshot();

    // No credential: `x-raven-client-id` is the whole session identity.
    let client_id = require_client_id_header(&headers_in).map_err(|()| StatusCode::BAD_REQUEST)?;
    let session_key = SessionKey::new(instance_id.clone(), client_id);

    let state = Arc::clone(&snapshot.state);
    // Decoded before a derivation permit is sought, so a body that cannot decode never queues.
    let limit = packing_key_upload_limit(&state.crs.params).min(app.config.max_body_bytes);
    let body = read_capped(body, limit).await?;
    let keys: ClientPackingKeys = read_versioned(&body).map_err(|err| {
        tracing::warn!(
            ?err,
            "session establish versioned-bincode deserialize failed"
        );
        StatusCode::BAD_REQUEST
    })?;
    drop(body);
    let handle = match derive_off_the_workers(&app, &instance_id, Arc::clone(&state), keys).await? {
        Derivation::Registered(handle) => handle,
        // At the ceiling the store refuses rather than retiring another caller's keys, so the
        // caller is being asked to wait, not told the server broke.
        Derivation::PoolFull(error) => {
            tracing::warn!(%error, "session establish refused");
            count_establish_refusal(&instance_id, "pool");
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        Derivation::Failed(error) => {
            tracing::warn!(%error, "session establish refused");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    if instance.current_epoch() != snapshot.epoch {
        release_seat(state, handle).await;
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    // The binding must not lapse before the seat it names: a re-handshake after that finds
    // nothing to replace, and the old seat stays held until the store's own expiry.
    let ttl = state.session_store.limits().ttl;
    let now = Instant::now();
    let Some(expires_at) = now.checked_add(ttl) else {
        release_seat(state, handle).await;
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let (outcome, superseded) = app.sessions.upsert(
        session_key,
        handle,
        expires_at,
        app.config.session_lru_cap,
        now,
    );
    if outcome == EvictionOutcome::AtCapacity {
        release_seat(state, handle).await;
        count_establish_refusal(&instance_id, "binding");
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    // Released only now, so a re-handshake that failed above left the caller its working seat.
    if let Some(superseded) = superseded {
        release_seat(state, superseded).await;
    }

    metrics::counter!(
        "raven_railgun_sessions_established_total",
        "instance" => instance_id.to_string()
    )
    .increment(1);
    #[allow(clippy::cast_precision_loss)]
    let occupancy = app.sessions.len() as f64;
    metrics::gauge!(
        "raven_railgun_sessions_occupancy",
        "instance" => instance_id.to_string()
    )
    .set(occupancy);

    let expires_at_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        .saturating_add(ttl.as_secs());

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

/// Stored, but revalidated against the ETag on every use. The CRS is regenerated by a redeploy
/// and the epoch restarts at zero, so a cache holding the body for any fixed time could serve
/// the previous deploy's parameters; a revalidation costs a 304 with no body.
const PARAMS_CACHE_CONTROL: &str = "public, no-cache";

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

    // Skips multi-MB CRS serialization on an If-None-Match hit.
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
                HeaderValue::from_static(PARAMS_CACHE_CONTROL),
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

    let state = instance.current_state();
    let state: &InspireServerState = state.as_ref();
    let crs_bincode = crs_wire_bytes(&state.crs).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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

    // Cached as `(epoch, sha)` so an epoch bump invalidates without growing the map.
    let sha = if let Some(value) = cached_etag_value.as_ref() {
        // Re-parse the cached hex rather than re-hash the fresh body.
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
        HeaderValue::from_static(PARAMS_CACHE_CONTROL),
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
    raven_railgun_core::hex::decode_hex(inner)
}

/// Lowercase hex encoding of a 32-byte SHA-256 digest.
fn to_hex_lower(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        // Nibbles are 0..16, within `from_digit`'s radix-16 contract.
        let hi = char::from_digit(u32::from(b >> 4), 16).unwrap_or('0');
        let lo = char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0');
        out.push(hi);
        out.push(lo);
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use axum::extract::ConnectInfo;
    use axum::http::{header, Method, Request};
    use http_body_util::BodyExt;
    use raven_inspire::math::GaussianSampler;
    use raven_inspire::params::{InspireVariant, SecurityLevel};
    use raven_railgun_engine::inspire::setup_state;
    use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
    use tower::ServiceExt;

    use super::*;
    use crate::config::HttpConfig;

    const INSTANCE: &str = "session-body-bounds";
    const ENTRY_BYTES: usize = 32;

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

    /// The app and one honest packing-key upload for its instance.
    fn fixture(respond_permit_wait_ms: u64) -> (AppState<RavenInspireScheme>, Vec<u8>) {
        let params = params();
        let db = raven_railgun_testkit::toy_db(256, ENTRY_BYTES);
        let (state, secret_key) =
            setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("toy state");
        let mut sampler = GaussianSampler::with_seed(params.sigma, 0x5e);
        let upload = write_versioned(&ClientPackingKeys::generate(
            &secret_key,
            state.cache.pack_params(),
            state.crs.inspiring_w_seed,
            &mut sampler,
        ))
        .expect("versioned keys");
        let engine: Engine<RavenInspireScheme> = Engine::new();
        engine
            .add_live(Arc::new(PirInstance::new(
                InstanceId::new(INSTANCE),
                InstanceRole::Live,
                state,
            )))
            .expect("register instance");
        let mut config = HttpConfig::demo("session-body-bounds-token-0123456789");
        config.respond_permit_wait_ms = respond_permit_wait_ms;
        (AppState::new(engine, config).expect("app state"), upload)
    }

    async fn establish(app: &AppState<RavenInspireScheme>, body: Body) -> StatusCode {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(format!("/v1/instance/{INSTANCE}/session"))
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header("x-raven-client-id", "22222222222222222222222222222222")
            .body(body)
            .expect("request");
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            12_345,
        )));
        crate::inspire_router(app.clone())
            .expect("router")
            .oneshot(request)
            .await
            .expect("dispatch")
            .status()
    }

    /// Past the key size, whether the length is declared or only discovered while reading.
    #[tokio::test]
    async fn a_session_body_larger_than_a_packing_key_upload_is_refused_413() {
        let (app, upload) = fixture(1_000);
        let limit = packing_key_upload_limit(&params());
        assert!(upload.len() <= limit, "{} > {limit}", upload.len());
        assert!(limit < app.config.max_body_bytes);
        let oversize = vec![0u8; limit + 1];
        assert_eq!(
            establish(&app, Body::from(oversize.clone())).await,
            StatusCode::PAYLOAD_TOO_LARGE,
            "declared length"
        );
        let undeclared = http_body_util::Full::new(Bytes::from(oversize)).map_frame(|frame| frame);
        assert_eq!(
            establish(&app, Body::new(undeclared)).await,
            StatusCode::PAYLOAD_TOO_LARGE,
            "undeclared length"
        );
        assert_eq!(establish(&app, Body::from(upload)).await, StatusCode::OK);
    }

    /// With every derivation permit held, a body that cannot decode is still answered at once
    /// instead of queueing behind derivations for the permit wait.
    #[tokio::test]
    async fn an_undecodable_body_does_not_queue_for_a_derivation_permit() {
        let (app, _) = fixture(2_000);
        let permits = u32::try_from(app.config.max_concurrent_handshakes.max(1)).expect("u32");
        let _held = Arc::clone(&app.handshake_permits)
            .acquire_many_owned(permits)
            .await
            .expect("hold every permit");
        assert_eq!(
            establish(&app, Body::from(vec![0u8; 64])).await,
            StatusCode::BAD_REQUEST
        );
    }
}
