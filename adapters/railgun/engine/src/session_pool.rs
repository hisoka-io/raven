//! Occupancy-bounded wrapper around [`ServerSessionStore`].
//!
//! `ServerSessionStore` allocates handles monotonically and exposes no
//! per-entry removal, so the only reclamation primitive available is dropping
//! the whole store. Bounding therefore has two layers: TTL bookkeeping decides
//! which handles are still *serviceable*, and a backstop flush - triggered on
//! the inner store's own length, never on the serviceable count - decides when
//! the bytes are actually reclaimed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use raven_inspire::inspiring::{ClientPackingKeys, PackParams};
use raven_inspire::math::NttContext;
use raven_inspire::{ClientSession, ServerSessionHandle, ServerSessionStore};
use raven_railgun_core::AdapterError;

use super::Result;

/// Serviceable-session ceiling before the backstop flush fires.
///
/// A registered session costs 11.94 MiB of packing keys at gamma=128 and 23.98
/// MiB at gamma=256, so this constant is a memory ceiling in disguise: 64
/// sessions is ~764 MiB / ~1.50 GiB respectively. It is deliberately three
/// orders of magnitude below the HTTP layer's `session_lru_cap`, which bounds
/// the sticky-token map (a handle each, not keys) and would be a 116 GiB
/// ceiling if it were ever applied here.
pub const DEFAULT_MAX_SESSIONS: usize = 64;

/// Serviceable lifetime of a registered session.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(3600);

/// Occupancy and lifetime bounds for a [`BoundedSessionStore`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionStoreLimits {
    /// Inner-store length at which the backstop flush fires.
    pub max_sessions: usize,
    /// How long a handle stays serviceable after registration.
    pub ttl: Duration,
}

impl Default for SessionStoreLimits {
    fn default() -> Self {
        Self {
            max_sessions: DEFAULT_MAX_SESSIONS,
            ttl: DEFAULT_SESSION_TTL,
        }
    }
}

struct Generation {
    store: Arc<ServerSessionStore>,
    expiry: HashMap<u64, Instant>,
}

impl Generation {
    fn fresh() -> Self {
        Self {
            store: Arc::new(ServerSessionStore::new()),
            expiry: HashMap::new(),
        }
    }
}

/// Bounded, metered session store.
///
/// Handles are serviceable only while [`resolve`](Self::resolve) says so:
/// unknown, removed, and expired handles fail closed rather than reaching the
/// inner store. Reclamation is a whole-generation flush, so a handle registered
/// before a flush is not merely unserviceable but genuinely gone; an in-flight
/// request is unaffected because [`resolve`](Self::resolve) hands back an
/// `Arc` that keeps the pre-flush generation alive for the request's duration.
///
/// Handle numbering restarts at zero in the fresh generation, so a low
/// pre-flush handle can be reissued. A stale client presenting one is answered
/// under the new holder's packing keys, which it cannot decrypt - the
/// denial-of-useful-response already documented for handle guessing, not a key
/// disclosure. Per-entry removal in the inner store would close that window.
pub struct BoundedSessionStore {
    limits: SessionStoreLimits,
    current: RwLock<Generation>,
    evicted_total: AtomicU64,
    flushes_total: AtomicU64,
}

impl std::fmt::Debug for BoundedSessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundedSessionStore")
            .field("max_sessions", &self.limits.max_sessions)
            .field("ttl_secs", &self.limits.ttl.as_secs())
            .field("len", &self.len())
            .field("serviceable", &self.serviceable_len())
            .field("evicted_total", &self.evicted_total())
            .field("flushes_total", &self.flushes_total())
            .finish_non_exhaustive()
    }
}

impl Default for BoundedSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BoundedSessionStore {
    /// Build an empty store with [`SessionStoreLimits::default`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(SessionStoreLimits::default())
    }

    /// Build an empty store with operator-chosen limits.
    #[must_use]
    pub fn with_limits(limits: SessionStoreLimits) -> Self {
        Self {
            limits,
            current: RwLock::new(Generation::fresh()),
            evicted_total: AtomicU64::new(0),
            flushes_total: AtomicU64::new(0),
        }
    }

    /// Configured bounds.
    #[must_use]
    pub fn limits(&self) -> SessionStoreLimits {
        self.limits
    }

    /// Packing-key sets held by the inner store; the memory-occupancy figure.
    #[must_use]
    pub fn len(&self) -> usize {
        self.current.read().store.len()
    }

    /// Whether the inner store holds no packing keys.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Handles that [`resolve`](Self::resolve) would still accept, ignoring TTL.
    #[must_use]
    pub fn serviceable_len(&self) -> usize {
        self.current.read().expiry.len()
    }

    /// Sessions dropped by expiry, explicit removal, or flush.
    #[must_use]
    pub fn evicted_total(&self) -> u64 {
        self.evicted_total.load(Ordering::Relaxed)
    }

    /// Backstop flushes performed.
    #[must_use]
    pub fn flushes_total(&self) -> u64 {
        self.flushes_total.load(Ordering::Relaxed)
    }

    /// Register wire-delivered packing keys, deriving the server-side NTT form.
    ///
    /// # Errors
    /// Returns [`AdapterError::Scheme`] if the inner store's lock is poisoned
    /// or derivation rejects the keys.
    pub fn register_server_side(
        &self,
        keys: ClientPackingKeys,
        pack_params: &PackParams,
        ctx: &NttContext,
    ) -> Result<ServerSessionHandle> {
        self.register_server_side_at(keys, pack_params, ctx, Instant::now())
    }

    /// [`register_server_side`](Self::register_server_side) against an explicit clock.
    ///
    /// # Errors
    /// Returns [`AdapterError::Scheme`] if the inner store's lock is poisoned
    /// or derivation rejects the keys.
    pub fn register_server_side_at(
        &self,
        keys: ClientPackingKeys,
        pack_params: &PackParams,
        ctx: &NttContext,
        now: Instant,
    ) -> Result<ServerSessionHandle> {
        let expires_at = now + self.limits.ttl;
        let mut gen = self.current.write();
        self.make_room(&mut gen, now);
        let handle = gen
            .store
            .register_server_side(keys, pack_params, ctx)
            .map_err(|e| AdapterError::Scheme(format!("session register_server_side: {e}")))?;
        gen.expiry.insert(handle.0, expires_at);
        Self::publish_occupancy(&gen);
        Ok(handle)
    }

    /// Register an in-process [`ClientSession`] through the same bounds.
    ///
    /// Returns `Ok(None)` when the session carries no packing keys to upload.
    ///
    /// # Errors
    /// Returns [`AdapterError::Scheme`] if the inner store rejects the keys.
    pub fn register_client_session_at(
        &self,
        session: &mut ClientSession,
        now: Instant,
    ) -> Result<Option<ServerSessionHandle>> {
        let expires_at = now + self.limits.ttl;
        let mut gen = self.current.write();
        self.make_room(&mut gen, now);
        let handle = session
            .register_with_server_derivation(gen.store.as_ref())
            .map_err(|e| AdapterError::Scheme(format!("session register: {e}")))?;
        if let Some(h) = handle {
            gen.expiry.insert(h.0, expires_at);
        }
        Self::publish_occupancy(&gen);
        Ok(handle)
    }

    /// Resolve the store a respond call should read `handle` from.
    ///
    /// `None` selects the current generation without a serviceability check -
    /// the inline-packing-keys path never consults the store.
    ///
    /// # Errors
    /// Returns [`AdapterError::InvalidQuery`] when the handle is unknown,
    /// removed, or past its TTL.
    pub fn resolve(
        &self,
        handle: Option<ServerSessionHandle>,
        now: Instant,
    ) -> Result<Arc<ServerSessionStore>> {
        let gen = self.current.read();
        let Some(h) = handle else {
            return Ok(Arc::clone(&gen.store));
        };
        match gen.expiry.get(&h.0) {
            Some(expires_at) if *expires_at > now => Ok(Arc::clone(&gen.store)),
            Some(_) => Err(AdapterError::InvalidQuery(format!(
                "session handle {} expired (ttl {}s); re-run the session handshake",
                h.0,
                self.limits.ttl.as_secs()
            ))),
            None => Err(AdapterError::InvalidQuery(format!(
                "session handle {} is not registered on this instance ({} serviceable, \
                 {} evicted since start); re-run the session handshake",
                h.0,
                gen.expiry.len(),
                self.evicted_total()
            ))),
        }
    }

    /// Stop serving `handle`. Returns whether it was serviceable.
    ///
    /// The keys stay resident until the next flush; the frozen inner store has
    /// no per-entry removal.
    pub fn remove(&self, handle: ServerSessionHandle) -> bool {
        let mut gen = self.current.write();
        let removed = gen.expiry.remove(&handle.0).is_some();
        if removed {
            self.evicted_total.fetch_add(1, Ordering::Relaxed);
            metrics::counter!("raven_railgun_session_evictions_total", "reason" => "removed")
                .increment(1);
        }
        Self::publish_occupancy(&gen);
        removed
    }

    /// Drop every handle whose TTL elapsed at or before `now`, returning the count.
    pub fn sweep_expired(&self, now: Instant) -> usize {
        let mut gen = self.current.write();
        let swept = Self::sweep_locked(&mut gen, now);
        if swept > 0 {
            self.evicted_total
                .fetch_add(swept as u64, Ordering::Relaxed);
            metrics::counter!("raven_railgun_session_evictions_total", "reason" => "expired")
                .increment(swept as u64);
        }
        Self::publish_occupancy(&gen);
        swept
    }

    fn sweep_locked(gen: &mut Generation, now: Instant) -> usize {
        let before = gen.expiry.len();
        gen.expiry.retain(|_, expires_at| *expires_at > now);
        before - gen.expiry.len()
    }

    /// Reclaim if the inner store - not the serviceable count - is at the cap.
    ///
    /// Gating on `store.len()` is load-bearing: expired handles leave the
    /// bookkeeping map but their keys stay resident, so a serviceable-count
    /// gate would let the resident set grow without bound.
    fn make_room(&self, gen: &mut Generation, now: Instant) {
        let swept = Self::sweep_locked(gen, now);
        if swept > 0 {
            self.evicted_total
                .fetch_add(swept as u64, Ordering::Relaxed);
            metrics::counter!("raven_railgun_session_evictions_total", "reason" => "expired")
                .increment(swept as u64);
        }
        if gen.store.len() < self.limits.max_sessions {
            return;
        }
        let dropped = gen.store.len() as u64;
        *gen = Generation::fresh();
        self.evicted_total.fetch_add(dropped, Ordering::Relaxed);
        self.flushes_total.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("raven_railgun_session_evictions_total", "reason" => "flushed")
            .increment(dropped);
        metrics::counter!("raven_railgun_session_store_flushes_total").increment(1);
        tracing::warn!(
            dropped,
            max_sessions = self.limits.max_sessions,
            "session store hit its occupancy cap; flushed every registered session"
        );
    }

    #[allow(clippy::cast_precision_loss)]
    fn publish_occupancy(gen: &Generation) {
        metrics::gauge!("raven_railgun_session_store_occupancy").set(gen.store.len() as f64);
        metrics::gauge!("raven_railgun_session_store_serviceable").set(gen.expiry.len() as f64);
    }
}

#[cfg(test)]
mod tests {
    use super::{BoundedSessionStore, SessionStoreLimits};
    use raven_inspire::inspiring::ClientPackingKeys;
    use raven_inspire::ServerSessionHandle;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// Structurally empty keys: the store never inspects them, and the
    /// production-shaped 11.94 MiB payload would make cap tests unaffordable.
    fn keys() -> ClientPackingKeys {
        ClientPackingKeys {
            y_body: Vec::new(),
            z_body: Vec::new(),
            y_all: Vec::new(),
            y_all_ntt: Vec::new(),
            y_bar_all: Vec::new(),
            y_bar_all_ntt: Vec::new(),
            full_key: false,
            num_to_pack: 1,
        }
    }

    fn store(max_sessions: usize) -> BoundedSessionStore {
        BoundedSessionStore::with_limits(SessionStoreLimits {
            max_sessions,
            ttl: Duration::from_secs(3600),
        })
    }

    fn register(s: &BoundedSessionStore, now: Instant) -> ServerSessionHandle {
        let mut gen = s.current.write();
        s.make_room(&mut gen, now);
        let handle = gen.store.register(keys()).expect("register");
        gen.expiry.insert(handle.0, now + s.limits.ttl);
        handle
    }

    #[test]
    fn occupancy_never_exceeds_the_cap_under_churn() {
        let s = store(8);
        let t0 = Instant::now();
        for i in 0..200u32 {
            register(&s, t0 + Duration::from_millis(u64::from(i)));
            assert!(
                s.len() <= 8,
                "inner occupancy {} exceeded cap 8 after {i} registrations",
                s.len()
            );
        }
        assert!(
            s.flushes_total() >= 24,
            "200 registrations at cap 8 must flush repeatedly; got {}",
            s.flushes_total()
        );
    }

    #[test]
    fn flush_frees_the_packing_keys_it_evicted() {
        let s = store(4);
        let t0 = Instant::now();
        let h = register(&s, t0);
        let inner = s.resolve(Some(h), t0).expect("resolve");
        let held = inner.get(h).expect("get").expect("present");
        assert_eq!(Arc::strong_count(&held), 2, "store + local clone");

        for i in 1..8u32 {
            register(&s, t0 + Duration::from_millis(u64::from(i)));
        }
        assert!(s.flushes_total() >= 1, "cap 4 must have flushed");
        drop(inner);
        assert_eq!(
            Arc::strong_count(&held),
            1,
            "flushed generation must be the last owner of the evicted keys"
        );
    }

    /// The fresh generation restarts handle numbering, so only a handle above
    /// the reissue window is provably gone.
    #[test]
    fn evicted_handles_fail_closed_instead_of_resolving() {
        let s = store(4);
        let t0 = Instant::now();
        let mut last = None;
        for i in 0..4u32 {
            last = Some(register(&s, t0 + Duration::from_millis(u64::from(i))));
        }
        let top = last.expect("four registrations");
        register(&s, t0 + Duration::from_millis(4));
        assert_eq!(s.flushes_total(), 1);
        assert_eq!(
            s.len(),
            1,
            "the fresh generation holds only the newest session"
        );

        let err = s
            .resolve(Some(top), t0 + Duration::from_secs(1))
            .expect_err("flushed handle must not resolve");
        assert!(
            format!("{err}").contains("not registered"),
            "error must name the missing registration: {err}"
        );
    }

    #[test]
    fn remove_stops_service_and_counts_an_eviction() {
        let s = store(64);
        let t0 = Instant::now();
        let h = register(&s, t0);
        assert!(s.resolve(Some(h), t0).is_ok());
        assert!(s.remove(h), "first remove reports the handle was present");
        assert!(!s.remove(h), "second remove is a no-op");
        assert_eq!(s.evicted_total(), 1);
        assert!(
            s.resolve(Some(h), t0).is_err(),
            "removed handle fails closed"
        );
    }

    #[test]
    fn ttl_expiry_stops_service_and_sweeps() {
        let s = BoundedSessionStore::with_limits(SessionStoreLimits {
            max_sessions: 64,
            ttl: Duration::from_secs(10),
        });
        let t0 = Instant::now();
        let h = register(&s, t0);
        assert!(s.resolve(Some(h), t0 + Duration::from_secs(9)).is_ok());
        assert!(
            s.resolve(Some(h), t0 + Duration::from_secs(11)).is_err(),
            "past-TTL handle must fail closed"
        );
        assert_eq!(s.sweep_expired(t0 + Duration::from_secs(11)), 1);
        assert_eq!(s.serviceable_len(), 0);
    }

    #[test]
    fn an_in_flight_resolve_survives_a_concurrent_flush() {
        let s = store(4);
        let t0 = Instant::now();
        let h = register(&s, t0);
        let in_flight = s.resolve(Some(h), t0).expect("resolve before flush");
        for i in 1..8u32 {
            register(&s, t0 + Duration::from_millis(u64::from(i)));
        }
        assert!(s.flushes_total() >= 1);
        let keys = in_flight
            .get(h)
            .expect("lock")
            .expect("in-flight request must still see its own session after a flush");
        assert_eq!(keys.num_to_pack, 1);
    }

    #[test]
    fn no_handle_resolves_without_a_serviceability_check() {
        let s = store(4);
        s.resolve(None, Instant::now())
            .expect("the inline-keys path never consults the bookkeeping map");
    }
}
