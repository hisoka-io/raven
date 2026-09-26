//! Authentication scopes, sticky-session map, and bearer-auth middleware.
//!
//! The read path carries NO credential: the PPOI list is public data and the routes that
//! serve it answer a third party that holds nothing. A bearer is required only for
//! `/v1/admin/*` and for `/metrics` while it is default-deny.

use std::collections::HashMap;
use std::time::Instant;

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use parking_lot::Mutex;
use raven_inspire::ServerSessionHandle;
use raven_railgun_core::InstanceId;
use raven_railgun_engine::PirScheme;

use crate::state::AppState;

/// Authentication scope decoded from the bearer token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthScope {
    /// Opens `/metrics` while it is default-deny. Queries, batch, session, params and
    /// status need no scope at all.
    Read,
    /// The control plane: `/v1/admin/*`. Also satisfies [`AuthScope::Read`].
    Admin,
}

/// Sticky-session identity keyed by `(instance_id, client_id)`.
///
/// `client_id` is the whole discriminator. The bearer that used to be hashed into this
/// key was ONE value shared by every caller, so it never separated two of them; the read
/// path now carries none at all. Not an auth check - a handle presented under the wrong
/// `client_id` is a 409, not a 401.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SessionKey {
    instance_id: InstanceId,
    client_id: [u8; 16],
}

impl SessionKey {
    pub(crate) fn new(instance_id: InstanceId, client_id: [u8; 16]) -> Self {
        Self {
            instance_id,
            client_id,
        }
    }
}

/// Header name scoping a sticky-session entry to a client; missing header
/// falls back to the all-zero id.
pub const X_RAVEN_CLIENT_ID: &str = "X-Raven-Client-Id";

/// Parse `X-Raven-Client-Id` into a 16-byte client id.
///
/// Accepts `[0-9a-fA-F]{32}` with optional `-` separators (UUID shape);
/// returns the all-zero id when the header is absent or malformed.
pub fn parse_client_id_header(headers: &http::HeaderMap) -> [u8; 16] {
    decode_client_id_header(headers).unwrap_or([0u8; 16])
}

pub(crate) fn require_client_id_header(headers: &http::HeaderMap) -> Result<[u8; 16], ()> {
    decode_client_id_header(headers).ok_or(())
}

fn decode_client_id_header(headers: &http::HeaderMap) -> Option<[u8; 16]> {
    let raw = headers
        .get(X_RAVEN_CLIENT_ID)
        .and_then(|v| v.to_str().ok())?;
    let stripped: String = raw.chars().filter(|c| *c != '-').collect();
    if stripped.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        let byte_str = stripped.get(i * 2..i * 2 + 2)?;
        *slot = u8::from_str_radix(byte_str, 16).ok()?;
    }
    Some(out)
}

#[derive(Clone, Debug)]
struct SessionEntry {
    handle: ServerSessionHandle,
    expires_at: Instant,
}

/// In-memory sticky-session map bounded by `session_lru_cap`.
/// Entries leave only by expiry or by their own caller re-handshaking; a full map
/// refuses a new caller rather than displacing one.
/// Stale inner `ServerSessionStore` handles linger until `swap_state` drops `InspireServerState`.
#[derive(Debug, Default)]
pub(crate) struct SessionMap {
    inner: Mutex<HashMap<SessionKey, SessionEntry>>,
}

impl SessionMap {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn get(&self, key: &SessionKey, now: Instant) -> Option<ServerSessionHandle> {
        let mut guard = self.inner.lock();
        let entry = guard.get(key)?;
        if entry.expires_at <= now {
            guard.remove(key);
            return None;
        }
        Some(entry.handle)
    }

    /// Stop serving `key`, returning the handle it was bound to.
    pub(crate) fn take(&self, key: &SessionKey) -> Option<ServerSessionHandle> {
        self.inner.lock().remove(key).map(|entry| entry.handle)
    }

    /// Insert or refresh a session, reclaiming expired entries to make room.
    ///
    /// A caller that already owns `key` always keeps it. A new key is refused once the
    /// map is full of other callers' live entries: an establish carries no credential,
    /// so evicting one here would hand any caller the power to retire another's session.
    pub(crate) fn upsert(
        &self,
        key: SessionKey,
        handle: ServerSessionHandle,
        expires_at: Instant,
        cap: usize,
        now: Instant,
    ) -> EvictionOutcome {
        let mut guard = self.inner.lock();
        let mut outcome = EvictionOutcome::None;
        if guard.len() >= cap && !guard.contains_key(&key) {
            let before = guard.len();
            guard.retain(|_, v| v.expires_at > now);
            if guard.len() < before {
                outcome = EvictionOutcome::ExpiredOnly;
            }
            if guard.len() >= cap {
                return EvictionOutcome::AtCapacity;
            }
        }
        guard.insert(key, SessionEntry { handle, expires_at });
        outcome
    }

    pub(crate) fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Drop every entry expired at or before `now`, returning the count removed.
    /// Without this, expired entries are only purged lazily on `get`, so a
    /// once-churned token lingers until process restart.
    pub(crate) fn sweep_expired(&self, now: Instant) -> usize {
        let mut guard = self.inner.lock();
        let before = guard.len();
        guard.retain(|_, v| v.expires_at > now);
        before - guard.len()
    }
}

pub(crate) fn validate_session_binding(
    headers: &HeaderMap,
    sessions: &SessionMap,
    instance_id: &InstanceId,
    handle: Option<ServerSessionHandle>,
) -> Result<(), StatusCode> {
    let Some(handle) = handle else {
        return Ok(());
    };
    let client_id = require_client_id_header(headers).map_err(|()| StatusCode::BAD_REQUEST)?;
    let key = SessionKey::new(instance_id.clone(), client_id);
    if sessions.get(&key, Instant::now()) == Some(handle) {
        Ok(())
    } else {
        Err(StatusCode::CONFLICT)
    }
}

/// Outcome of a [`SessionMap::upsert`] call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EvictionOutcome {
    None,
    ExpiredOnly,
    /// Nothing was inserted: the map is full of other callers' live entries.
    AtCapacity,
}

/// The scope a path demands, or `None` when it is public.
///
/// Default-public, because the read path is the public one. Only the control plane and
/// the default-deny scrape are named here, and `/v1/admin` is matched on the path axum
/// itself routes on, so a segment that does not match this prefix cannot reach an admin
/// handler either.
fn required_scope(path: &str, metrics_public: bool) -> Option<AuthScope> {
    if path == "/v1/admin" || path.starts_with("/v1/admin/") {
        return Some(AuthScope::Admin);
    }
    if path == "/metrics" && !metrics_public {
        return Some(AuthScope::Read);
    }
    None
}

pub(crate) async fn bearer_auth<S: PirScheme>(
    State(app): State<AppState<S>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let Some(required) = required_scope(request.uri().path(), app.config.metrics_public) else {
        return Ok(next.run(request).await);
    };

    let bearer = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let token = bearer.unwrap_or_default();

    // Both compares always evaluate; the snapshot keeps the lock off the compare.
    // The `is_empty` guards are on the CONFIGURED token, so they branch on nothing secret:
    // `set_read_token` takes any string, unlike `HttpConfig::validate`, and an empty one
    // would otherwise be cleared by `Authorization: Bearer ` with nothing after it.
    let active_read_token: String = app.read_token.read().clone();
    let read_match: bool = !active_read_token.is_empty()
        && bool::from(ct_eq_str(token.as_bytes(), active_read_token.as_bytes()));
    let admin_match: bool = if let Some(admin) = app.admin_token.as_ref().as_ref() {
        !admin.is_empty() && bool::from(ct_eq_str(token.as_bytes(), admin.as_bytes()))
    } else {
        // Keeps the no-admin path equal-cost. An absent admin token grants nothing, so an
        // admin path with none configured refuses every caller.
        let _ = ct_eq_str(token.as_bytes(), &[]);
        false
    };

    // A header that is absent or not `Bearer ` grants nothing at all.
    let granted = if bearer.is_none() {
        None
    } else if admin_match {
        Some(AuthScope::Admin)
    } else if read_match {
        Some(AuthScope::Read)
    } else {
        None
    };

    let cleared = matches!(
        (required, granted),
        (AuthScope::Admin, Some(AuthScope::Admin)) | (AuthScope::Read, Some(_))
    );
    if !cleared {
        return Ok(unauthorized_close());
    }
    metrics::counter!(
        "raven_railgun_auth_ok_total",
        "scope" => scope_label(required)
    )
    .increment(1);
    Ok(next.run(request).await)
}

/// Rejecting on headers leaves the request body unread, so the connection is not
/// reusable. Draining it would be amplification on an unauthenticated path, so the
/// peer is told instead: without this the socket goes back into a client pool the
/// server is about to close.
fn unauthorized_close() -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    response.headers_mut().insert(
        http::header::CONNECTION,
        http::HeaderValue::from_static("close"),
    );
    response
}

/// Constant-time byte-slice equality; returns `Choice(0)` on length mismatch.
/// Length is not secret: tokens are required to be >= [`HttpConfig::MIN_TOKEN_LEN`].
#[inline]
pub(crate) fn ct_eq_str(a: &[u8], b: &[u8]) -> subtle::Choice {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return subtle::Choice::from(0u8);
    }
    a.ct_eq(b)
}

pub(crate) fn scope_label(scope: AuthScope) -> &'static str {
    match scope {
        AuthScope::Read => "read",
        AuthScope::Admin => "admin",
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderName, HeaderValue};
    use raven_inspire::ServerSessionHandle;
    use std::time::Duration;

    #[test]
    fn parse_client_id_header_accepts_hyphenated_uuid() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-raven-client-id"),
            HeaderValue::from_static("0102030405060708-090a0b0c0d0e0f10"),
        );
        let id = parse_client_id_header(&headers);
        assert_eq!(
            id,
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10,
            ]
        );
    }

    #[test]
    fn parse_client_id_header_accepts_unhyphenated_hex() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-raven-client-id"),
            HeaderValue::from_static("550e8400e29b41d4a716446655440000"),
        );
        let id = parse_client_id_header(&headers);
        assert_eq!(
            id,
            [
                0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
                0x00, 0x00,
            ]
        );
    }

    #[test]
    fn parse_client_id_header_accepts_canonical_uuid_form() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-raven-client-id"),
            HeaderValue::from_static("550e8400-e29b-41d4-a716-446655440000"),
        );
        let id = parse_client_id_header(&headers);
        assert_eq!(
            id,
            [
                0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
                0x00, 0x00,
            ]
        );
    }

    #[test]
    fn parse_client_id_header_absent_returns_zero() {
        let headers = HeaderMap::new();
        assert_eq!(parse_client_id_header(&headers), [0u8; 16]);
    }

    #[test]
    fn parse_client_id_header_rejects_short_returns_zero() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-raven-client-id"),
            HeaderValue::from_static("0102030405060708090a0b0c0d0e0f"),
        );
        assert_eq!(parse_client_id_header(&headers), [0u8; 16]);
    }

    #[test]
    fn parse_client_id_header_rejects_garbage_returns_zero() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-raven-client-id"),
            HeaderValue::from_static("not-a-uuid"),
        );
        assert_eq!(parse_client_id_header(&headers), [0u8; 16]);
    }

    #[test]
    fn parse_client_id_header_rejects_non_hex_chars_returns_zero() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-raven-client-id"),
            HeaderValue::from_static("z102030405060708090a0b0c0d0e0f10"),
        );
        assert_eq!(parse_client_id_header(&headers), [0u8; 16]);
    }

    #[test]
    fn session_key_distinguishes_client_id_on_one_instance() {
        let id = InstanceId::new("toy");
        let alice = SessionKey::new(id.clone(), [0xaa; 16]);
        let bob = SessionKey::new(id.clone(), [0xbb; 16]);
        assert_ne!(alice, bob, "distinct client_ids must produce distinct keys");

        let legacy_a = SessionKey::new(id.clone(), [0u8; 16]);
        let legacy_b = SessionKey::new(id, [0u8; 16]);
        assert_eq!(
            legacy_a, legacy_b,
            "absent-header back-compat must collapse to the same key"
        );
    }

    #[test]
    fn equal_numeric_handles_are_scoped_to_their_instance() {
        let map = SessionMap::new();
        let now = Instant::now();
        let handle = ServerSessionHandle(7);
        let client_id = [0x44; 16];
        let first = InstanceId::new("first");
        let second = InstanceId::new("second");
        let key = SessionKey::new(first.clone(), client_id);
        map.upsert(key, handle, now + Duration::from_secs(60), 8, now);
        map.upsert(
            SessionKey::new(second.clone(), [0x55; 16]),
            handle,
            now + Duration::from_secs(60),
            8,
            now,
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-raven-client-id"),
            HeaderValue::from_static("44444444444444444444444444444444"),
        );

        assert_eq!(
            validate_session_binding(&headers, &map, &first, Some(handle)),
            Ok(())
        );
        assert_eq!(
            validate_session_binding(&headers, &map, &second, Some(handle)),
            Err(StatusCode::CONFLICT),
            "the same bare handle on another instance must not authorize"
        );
        headers.insert(
            HeaderName::from_static("x-raven-client-id"),
            HeaderValue::from_static("55555555555555555555555555555555"),
        );
        assert_eq!(
            validate_session_binding(&headers, &map, &second, Some(handle)),
            Ok(()),
            "the equal handle must serve its own instance and client"
        );
    }

    #[test]
    fn session_map_sweep_expired_removes_only_past_ttl() {
        let map = SessionMap::new();
        let t0 = Instant::now();
        let ttl = Duration::from_secs(60);
        let h = ServerSessionHandle(1);
        let cap = 100;

        let dead_a = SessionKey::new(InstanceId::new("dead-a"), [0u8; 16]);
        let dead_b = SessionKey::new(InstanceId::new("dead-b"), [0u8; 16]);
        let _ = map.upsert(dead_a, h, t0 + ttl, cap, t0);
        let _ = map.upsert(dead_b, h, t0 + ttl, cap, t0);

        let alive = SessionKey::new(InstanceId::new("alive"), [0u8; 16]);
        let _ = map.upsert(alive.clone(), h, t0 + Duration::from_secs(3600), cap, t0);

        assert_eq!(map.len(), 3, "sanity: 3 sessions inserted");

        let later = t0 + ttl + Duration::from_secs(1);
        let removed = map.sweep_expired(later);
        assert_eq!(removed, 2, "exactly the 2 expired entries should be swept");
        assert_eq!(map.len(), 1, "only the long-lived entry remains");
        assert_eq!(
            map.get(&alive, later),
            Some(h),
            "the surviving entry is still resolvable"
        );
    }

    #[test]
    fn session_map_sweep_expired_no_op_when_all_live() {
        let map = SessionMap::new();
        let t0 = Instant::now();
        let ttl = Duration::from_secs(3600);
        let h = ServerSessionHandle(2);
        for i in 0..3 {
            let k = SessionKey::new(InstanceId::new(format!("live-{i}")), [0u8; 16]);
            let _ = map.upsert(k, h, t0 + ttl, 100, t0);
        }
        let removed = map.sweep_expired(t0 + Duration::from_secs(60));
        assert_eq!(removed, 0, "sweep must NOT touch live entries");
        assert_eq!(map.len(), 3, "all live entries must remain");
    }
}
