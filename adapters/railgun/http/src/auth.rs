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

/// Sticky-session identity keyed by `(sha256_truncated_token, instance_id)`.
/// Token is hashed so raw bearer values never appear in map keys or telemetry.
/// Not a cryptographic auth check; bearer validation happens in [`bearer_auth`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SessionKey {
    token_hash: u64,
    instance_id: InstanceId,
}

impl SessionKey {
    pub(crate) fn new(token: &str, instance_id: InstanceId) -> Self {
        Self {
            token_hash: stable_hash_token(token),
            instance_id,
        }
    }
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
    // Health/metrics probes are unauthenticated; operators layer gateway auth at the proxy.
    if matches!(path, "/metrics" | "/v1/health/live" | "/v1/health/ready") {
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
        let read_match: bool =
            ct_eq_str(token.as_bytes(), active_read_token.as_bytes()).into();
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
