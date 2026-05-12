//! Authentication scopes, sticky-session map, and bearer-auth middleware.

use std::collections::HashMap;
use std::time::Instant;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
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
    /// Grants access to queries, session-establish, status, metrics, params.
    Read,
    /// Reserved for future control-plane endpoints.
    Admin,
}

/// Sticky-session identity keyed by `(sha256_truncated_token, instance_id, client_id)`.
///
/// The bearer token is hashed (SHA-256 truncated to 8 bytes) before being
/// used as a key component so raw bearer values never appear in map keys
/// or telemetry. The hash is **stable across calls**: same input -> same
/// `u64`, so subsequent requests from the same client land on the same
/// key.
///
/// `client_id` is parsed from the `X-Raven-Client-Id` request header
/// (16 bytes; UUID-shaped hex with or without `-` separators). Two
/// clients sharing a single bearer token (e.g. an operator-shared scrape
/// credential against several wallets) MUST send distinct client ids so
/// they do not collide on the same session entry: without it the second
/// `/session` establish would overwrite the first client's CRS state and
/// both clients would race on the same handle. Absent header maps to the
/// all-zero id and preserves back-compat with single-client deploys.
///
/// Not a cryptographic auth check; bearer validation happens in
/// [`bearer_auth`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SessionKey {
    token_hash: u64,
    instance_id: InstanceId,
    client_id: [u8; 16],
}

impl SessionKey {
    pub(crate) fn new(token: &str, instance_id: InstanceId, client_id: [u8; 16]) -> Self {
        Self {
            token_hash: stable_hash_token(token),
            instance_id,
            client_id,
        }
    }
}

/// Header name carrying the per-client identifier that scopes the
/// sticky-session entry. Two clients sharing a single bearer token MUST
/// send distinct values so their session state does not collide in the
/// [`SessionMap`]. Missing header falls back to the all-zero id.
pub const X_RAVEN_CLIENT_ID: &str = "X-Raven-Client-Id";

/// Parse `X-Raven-Client-Id` into a 16-byte client id.
///
/// Accepts `[0-9a-fA-F]{32}` with optional `-` separators (UUID shape;
/// e.g. `550e8400-e29b-41d4-a716-446655440000` or
/// `550e8400e29b41d4a716446655440000`). Returns the all-zero id when the
/// header is absent or malformed — callers that want stricter validation
/// should reject malformed ids at the edge.
pub fn parse_client_id_header(headers: &http::HeaderMap) -> [u8; 16] {
    let Some(raw) = headers.get(X_RAVEN_CLIENT_ID).and_then(|v| v.to_str().ok()) else {
        return [0u8; 16];
    };
    let stripped: String = raw.chars().filter(|c| *c != '-').collect();
    if stripped.len() != 32 {
        return [0u8; 16];
    }
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        let Some(byte_str) = stripped.get(i * 2..i * 2 + 2) else {
            return [0u8; 16];
        };
        let Ok(byte) = u8::from_str_radix(byte_str, 16) else {
            return [0u8; 16];
        };
        *slot = byte;
    }
    out
}

/// SHA-256-derived 64-bit hash; deterministic unlike `RandomState` (which seeds per call).
pub(crate) fn stable_hash_token(token: &str) -> u64 {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(token.as_bytes());
    let mut bytes = [0u8; 8];
    let head = digest.get(..8).unwrap_or(&[0u8; 8]);
    bytes.copy_from_slice(head);
    u64::from_le_bytes(bytes)
}

#[derive(Clone, Debug)]
struct SessionEntry {
    handle: ServerSessionHandle,
    expires_at: Instant,
}

/// In-memory sticky-session map bounded by `session_lru_cap`.
/// Eviction policy: soonest `expires_at` (NOT classical LRU).
/// Stale inner `ServerSessionStore` handles linger until `swap_state` drops `InspireServerState`.
#[derive(Debug, Default)]
pub(crate) struct SessionMap {
    inner: Mutex<HashMap<SessionKey, SessionEntry>>,
}

impl SessionMap {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub(crate) fn get(&self, key: &SessionKey, now: Instant) -> Option<ServerSessionHandle> {
        let mut guard = self.inner.lock();
        let entry = guard.get(key)?;
        if entry.expires_at <= now {
            guard.remove(key);
            return None;
        }
        Some(entry.handle)
    }

    /// Insert or refresh a session. Evicts the soonest-expiring entry when at cap.
    /// Returns `Pressure` when the evicted entry was still live (cap exhaustion signal).
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
            // O(n) scan acceptable at cap = 10k default.
            if let Some((oldest_key, oldest_expires)) = guard
                .iter()
                .min_by_key(|(_, v)| v.expires_at)
                .map(|(k, v)| (k.clone(), v.expires_at))
            {
                outcome = if oldest_expires > now {
                    EvictionOutcome::Pressure
                } else {
                    EvictionOutcome::ExpiredOnly
                };
                guard.remove(&oldest_key);
            }
        }
        guard.insert(key, SessionEntry { handle, expires_at });
        outcome
    }

    pub(crate) fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Drop every entry whose `expires_at` is at or before `now`.
    ///
    /// Called by the periodic sweeper task spawned by the orchestrator.
    /// Without it, expired entries past [`HttpConfig::session_ttl_secs`]
    /// are only purged lazily on `get` against the same key — a token
    /// that churns once and never repeats stays in the map until the
    /// process restarts.
    ///
    /// Returns the count of entries removed (used to label a per-sweep
    /// eviction counter).
    pub(crate) fn sweep_expired(&self, now: Instant) -> usize {
        let mut guard = self.inner.lock();
        let before = guard.len();
        guard.retain(|_, v| v.expires_at > now);
        before - guard.len()
    }
}

/// Outcome of a [`SessionMap::upsert`] call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EvictionOutcome {
    None,
    ExpiredOnly,
    Pressure,
}

pub(crate) async fn bearer_auth<S: PirScheme>(
    State(app): State<AppState<S>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = request.uri().path();
    // Health probes + SSE events stream are always unauthenticated. The SSE
    // stream is the demo UI's status feed; auth happens at the gateway tier.
    if matches!(path, "/v1/health/live" | "/v1/health/ready" | "/v1/events") {
        return Ok(next.run(request).await);
    }
    // `/metrics` is default-deny (bearer required). Operators opt in to
    // public scrape via `metrics_public = true` (`HttpConfig.metrics_public`).
    if path == "/metrics" && app.config.metrics_public {
        return Ok(next.run(request).await);
    }

    let header = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    let scope = if let Some(token) = header.strip_prefix("Bearer ") {
        // Constant-time via `subtle::ConstantTimeEq`; raw `==` is variable-time.
        // Always evaluate both read + admin compares so total work is constant.
        // Snapshot under read-lock so the comparison doesn't hold the lock.
        let active_read_token: String = app.read_token.read().clone();
        let read_match: bool = ct_eq_str(token.as_bytes(), active_read_token.as_bytes()).into();
        let admin_match: bool = if let Some(admin) = app.admin_token.as_ref().as_ref() {
            ct_eq_str(token.as_bytes(), admin.as_bytes()).into()
        } else {
            // Fixed-cost dummy compare so the no-admin path doesn't short-circuit earlier.
            let _ = ct_eq_str(token.as_bytes(), &[]);
            false
        };

        if read_match {
            Some(AuthScope::Read)
        } else if admin_match {
            Some(AuthScope::Admin)
        } else {
            None
        }
    } else {
        // Pay constant-time cost even on missing-prefix path.
        let active_read_token: String = app.read_token.read().clone();
        let _ = ct_eq_str(b"", active_read_token.as_bytes());
        if let Some(admin) = app.admin_token.as_ref().as_ref() {
            let _ = ct_eq_str(b"", admin.as_bytes());
        }
        None
    };

    let Some(scope) = scope else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    metrics::counter!(
        "raven_railgun_auth_ok_total",
        "scope" => scope_label(scope)
    )
    .increment(1);
    Ok(next.run(request).await)
}

/// Constant-time byte-slice equality; returns `Choice(0)` on length mismatch.
/// Length is not secret: tokens are required to be ≥ [`HttpConfig::MIN_TOKEN_LEN`].
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
        // 30 hex chars - below the 32-char floor.
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
        // 32 chars but contains non-hex 'z'.
        headers.insert(
            HeaderName::from_static("x-raven-client-id"),
            HeaderValue::from_static("z102030405060708090a0b0c0d0e0f10"),
        );
        assert_eq!(parse_client_id_header(&headers), [0u8; 16]);
    }

    #[test]
    fn session_key_distinguishes_client_id_under_shared_bearer() {
        // Two clients sharing one bearer + one instance MUST land on
        // distinct SessionMap entries when they advertise distinct
        // client_ids. Without the third tuple element the map would
        // resolve client A's bearer to client B's handle and both
        // clients would race on the same in-memory CRS state.
        let id = InstanceId::new("toy");
        let alice = SessionKey::new("shared-bearer", id.clone(), [0xaa; 16]);
        let bob = SessionKey::new("shared-bearer", id.clone(), [0xbb; 16]);
        assert_ne!(alice, bob, "distinct client_ids must produce distinct keys");

        // Back-compat: legacy single-client wallets that never send
        // X-Raven-Client-Id map to the same all-zero key under one
        // bearer + instance.
        let legacy_a = SessionKey::new("legacy-bearer", id.clone(), [0u8; 16]);
        let legacy_b = SessionKey::new("legacy-bearer", id, [0u8; 16]);
        assert_eq!(
            legacy_a, legacy_b,
            "absent-header back-compat must collapse to the same key"
        );
    }

    #[test]
    fn session_map_sweep_expired_removes_only_past_ttl() {
        let map = SessionMap::new();
        let t0 = Instant::now();
        let ttl = Duration::from_secs(60);
        let h = ServerSessionHandle(1);
        let cap = 100;

        // Two soon-to-be-expired entries.
        let dead_a = SessionKey::new("dead-a", InstanceId::new("toy"), [0u8; 16]);
        let dead_b = SessionKey::new("dead-b", InstanceId::new("toy"), [0u8; 16]);
        let _ = map.upsert(dead_a, h, t0 + ttl, cap, t0);
        let _ = map.upsert(dead_b, h, t0 + ttl, cap, t0);

        // One long-lived entry.
        let alive = SessionKey::new("alive", InstanceId::new("toy"), [0u8; 16]);
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
            let k = SessionKey::new(&format!("live-{i}"), InstanceId::new("toy"), [0u8; 16]);
            let _ = map.upsert(k, h, t0 + ttl, 100, t0);
        }
        let removed = map.sweep_expired(t0 + Duration::from_secs(60));
        assert_eq!(removed, 0, "sweep must NOT touch live entries");
        assert_eq!(map.len(), 3, "all live entries must remain");
    }
}
