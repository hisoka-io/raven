//! Occupancy-bounded wrapper around [`ServerSessionStore`].
//!
//! The inner store has no per-entry removal, so bounding is two layers: TTL
//! bookkeeping decides which handles stay serviceable, and a backstop flush -
//! gated on the inner length, never the serviceable count - reclaims bytes.

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

/// Session ceiling before the backstop flush fires. A memory ceiling in
/// disguise: packing keys cost 11.94 MiB per session at gamma=128, so this is
/// deliberately far below the HTTP layer's `session_lru_cap`, which bounds only
/// handles.
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

/// Externally-visible handles are never reused for the life of the process.
///
/// The inner store has no way to seed or offset its allocator, so every fresh generation numbers
/// from zero and a stale handle would otherwise collide with a live one. Reserving a disjoint
/// external range per generation makes a retired handle smaller than the current base, which is a
/// property arithmetic can decide - and the client still holds one flat opaque u64.
///
/// Process-global rather than per-store because several sites build a whole new
/// `BoundedSessionStore`, so a per-store counter would restart with it.
///
/// External ids start above [`EXTERNAL_HANDLE_BASE`] so they are DISJOINT from inner ids, which the
/// occupancy cap keeps in the tens. `resolve` therefore reads which namespace it was handed instead
/// of inferring it: the wire path presents an external id and gets the never-reused guarantee, while
/// the in-process helper presents the inner id its `ClientSession` baked in and keeps today's
/// semantics.
static EXTERNAL_HANDLE_FLOOR: AtomicU64 = AtomicU64::new(EXTERNAL_HANDLE_BASE);

/// Floor of the external handle namespace. Far above any inner id: the inner allocator is bounded
/// by [`SessionStoreLimits::max_sessions`], a memory ceiling measured in tens of sessions because
/// one session's packing keys cost ~11.94 MiB.
const EXTERNAL_HANDLE_BASE: u64 = 1 << 32;

struct Generation {
    store: Arc<ServerSessionStore>,
    /// Keyed by EXTERNAL handle; the value carries the inner handle to translate back to.
    expiry: HashMap<u64, (ServerSessionHandle, Instant)>,
    /// External handles in this generation are `base + inner`.
    base: u64,
}

impl Generation {
    fn fresh(reserve: u64) -> Self {
        Self {
            store: Arc::new(ServerSessionStore::new()),
            expiry: HashMap::new(),
            // Saturating, so an exhausted space stops advancing rather than wrapping onto a live
            // range. At that point every later handle collides within one generation, which the
            // inner allocator already permits, and no reuse across generations is introduced.
            base: EXTERNAL_HANDLE_FLOOR.fetch_add(reserve.max(1), Ordering::Relaxed),
        }
    }

    fn external(&self, inner: ServerSessionHandle) -> ServerSessionHandle {
        ServerSessionHandle(self.base.saturating_add(inner.0))
    }
}

/// Bounded, metered session store. Unknown, removed, and expired handles fail
/// closed in [`resolve`](Self::resolve) rather than reaching the inner store.
///
/// Reclamation is a whole-generation flush; in-flight requests are unaffected
/// because `resolve` returns an `Arc` pinning the pre-flush generation. Handle
/// numbering restarts at zero, so a stale client presenting a reissued handle
/// is answered under keys it cannot decrypt - a denial of useful response, not
/// a key disclosure.
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
            current: RwLock::new(Generation::fresh(limits.max_sessions as u64)),
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
    /// [`AdapterError::Scheme`] on a poisoned lock or rejected derivation.
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
    /// [`AdapterError::Scheme`] on a poisoned lock or rejected derivation.
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
        let inner = gen
            .store
            .register_server_side(keys, pack_params, ctx)
            .map_err(|e| AdapterError::Scheme(format!("session register_server_side: {e}")))?;
        let external = gen.external(inner);
        gen.expiry.insert(external.0, (inner, expires_at));
        Self::publish_occupancy(&gen);
        Ok(external)
    }

    /// Register an in-process [`ClientSession`]; `Ok(None)` when it carries no
    /// packing keys.
    ///
    /// # Errors
    /// [`AdapterError::Scheme`] if the inner store rejects the keys.
    pub fn register_client_session_at(
        &self,
        session: &mut ClientSession,
        now: Instant,
    ) -> Result<Option<ServerSessionHandle>> {
        let expires_at = now + self.limits.ttl;
        let mut gen = self.current.write();
        self.make_room(&mut gen, now);
        // The in-process helper is registered under BOTH names: `ClientSession` bakes the inner
        // handle in and its field is private in the submodule, so a query built from that session
        // presents the inner value. Registering the external one too keeps the wire path's
        // never-reused guarantee while leaving this path exactly as it behaves today.
        let inner = session
            .register_with_server_derivation(gen.store.as_ref())
            .map_err(|e| AdapterError::Scheme(format!("session register: {e}")))?;
        let external = inner.map(|h| gen.external(h));
        if let (Some(i), Some(e)) = (inner, external) {
            gen.expiry.insert(e.0, (i, expires_at));
            if e.0 != i.0 {
                gen.expiry.insert(i.0, (i, expires_at));
            }
        }
        Self::publish_occupancy(&gen);
        Ok(external)
    }

    /// Store a respond call should read `handle` from. `None` skips the
    /// serviceability check; the inline-packing-keys path never consults it.
    ///
    /// # Errors
    /// [`AdapterError::InvalidQuery`] when the handle is unknown, removed, or
    /// past its TTL.
    pub fn resolve(
        &self,
        handle: Option<ServerSessionHandle>,
        now: Instant,
    ) -> Result<(Arc<ServerSessionStore>, Option<ServerSessionHandle>)> {
        let gen = self.current.read();
        let Some(h) = handle else {
            return Ok((Arc::clone(&gen.store), None));
        };
        // An EXTERNAL handle below this generation's base was minted by a retired one. Refusing it
        // by arithmetic is what makes reissue fail CLOSED: without it the value collides with a live
        // handle and the respond path serves another caller's packing keys at HTTP 200. The bound
        // check is what distinguishes a wire handle from an in-process one, whose id is an inner
        // value below the namespace floor and is looked up directly.
        if h.0 >= EXTERNAL_HANDLE_BASE && h.0 < gen.base {
            return Err(AdapterError::InvalidQuery(format!(
                "session handle {} was issued by a retired session generation (current range \
                 starts at {}, {} flushes since start); re-run the session handshake",
                h.0,
                gen.base,
                self.flushes_total()
            )));
        }
        match gen.expiry.get(&h.0) {
            Some((inner, expires_at)) if *expires_at > now => {
                Ok((Arc::clone(&gen.store), Some(*inner)))
            }
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

    /// Stop serving `handle`. Keys stay resident until the next flush - the
    /// inner store has no per-entry removal.
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
        gen.expiry.retain(|_, (_, expires_at)| *expires_at > now);
        before - gen.expiry.len()
    }

    /// Reclaim when the inner store is at the cap. Gating on `store.len()` is
    /// load-bearing: expired handles leave the map but their keys stay
    /// resident, so a serviceable-count gate grows without bound.
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
        *gen = Generation::fresh(self.limits.max_sessions as u64);
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

    /// Empty keys; the store never inspects them and 11.94 MiB each would make
    /// cap tests unaffordable.
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

    /// Returns the EXTERNAL handle, which is what a caller holds.
    fn register(s: &BoundedSessionStore, now: Instant) -> ServerSessionHandle {
        let mut gen = s.current.write();
        s.make_room(&mut gen, now);
        let inner = gen.store.register(keys()).expect("register");
        let external = gen.external(inner);
        gen.expiry.insert(external.0, (inner, now + s.limits.ttl));
        external
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
        let (inner_store, inner_h) = s.resolve(Some(h), t0).expect("resolve");
        let held = inner_store
            .get(inner_h.expect("a resolved handle translates"))
            .expect("get")
            .expect("present");
        assert_eq!(Arc::strong_count(&held), 2, "store + local clone");

        for i in 1..8u32 {
            register(&s, t0 + Duration::from_millis(u64::from(i)));
        }
        assert!(s.flushes_total() >= 1, "cap 4 must have flushed");
        drop(inner_store);
        assert_eq!(
            Arc::strong_count(&held),
            1,
            "flushed generation must be the last owner of the evicted keys"
        );
    }

    /// A flushed handle is refused for HAVING BEEN flushed, not merely for being absent.
    ///
    /// The distinction is the whole property. An absent-handle message also appears for a handle
    /// that was never issued at all, so asserting only that a refusal happened cannot tell a
    /// working guard from a coincidence.
    ///
    /// This test previously checked only the highest handle, because numbering restarted and the
    /// lower ones were reissued to later callers. External ids are never reused now, so EVERY
    /// flushed handle is provably gone and all four are asserted.
    #[test]
    fn evicted_handles_fail_closed_instead_of_resolving() {
        let s = store(4);
        let t0 = Instant::now();
        let mut flushed = Vec::new();
        for i in 0..4u32 {
            flushed.push(register(&s, t0 + Duration::from_millis(u64::from(i))));
        }
        let survivor = register(&s, t0 + Duration::from_millis(4));
        assert_eq!(s.flushes_total(), 1);
        assert_eq!(
            s.len(),
            1,
            "the fresh generation holds only the newest session"
        );

        for h in &flushed {
            let err = s
                .resolve(Some(*h), t0 + Duration::from_secs(1))
                .expect_err("every flushed handle must fail closed");
            assert!(
                format!("{err}").contains("retired session generation"),
                "the refusal must name the RETIRED GENERATION rather than a missing \
                 registration, which is also what an id that was never issued would report: {err}"
            );
            assert_ne!(
                h.0, survivor.0,
                "a flushed id must never be reissued to the session that replaced it"
            );
        }

        assert!(
            s.resolve(Some(survivor), t0 + Duration::from_secs(1)).is_ok(),
            "the surviving session must still resolve; a guard that refuses everything is not a guard"
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
        let (in_flight, in_flight_h) = s.resolve(Some(h), t0).expect("resolve before flush");
        for i in 1..8u32 {
            register(&s, t0 + Duration::from_millis(u64::from(i)));
        }
        assert!(s.flushes_total() >= 1);
        let keys = in_flight
            .get(in_flight_h.expect("a resolved handle translates"))
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
