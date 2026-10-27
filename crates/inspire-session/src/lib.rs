//! Bounded server sessions for InsPIRe.
//!
//! The store keeps scheme-specific packing keys out of `raven-server`, issues external handles
//! drawn at random, so no caller can name another caller's seat, and reports mutations as typed
//! observations. Metrics and operator namespaces remain the caller's policy.
//!
//! ```
//! use raven_inspire_session::{BoundedSessionStore, SessionStoreLimits};
//!
//! let store = BoundedSessionStore::with_limits(SessionStoreLimits::default());
//! assert!(store.is_empty());
//! ```

#![deny(missing_docs)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use raven_inspire::inspiring::{ClientPackingKeys, PackParams};
use raven_inspire::math::NttContext;
use raven_inspire::{ClientSession, PackingKeySeat, ServerSessionHandle, ServerSessionStore};
use sha2::{Digest, Sha256};

/// Session ceiling: wire registration is refused above it, and the in-process path
/// reclaims a whole generation. A memory bound: a seat holds one ring polynomial per
/// packing-key row at any gamma, 48 KiB for three rows at `d = 2048` and 32 KiB for the two
/// of the approximate gadget, so a full store holds 48 MiB or 32 MiB of keys.
pub const DEFAULT_MAX_SESSIONS: usize = 1024;

/// Serviceable lifetime of a registered session.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(3600);

/// Broad handling category for a typed [`SessionStoreError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionStoreErrorClass {
    /// The OS random source the handles are drawn from failed.
    Entropy,
    /// InsPIRe rejected packing-key registration or client-handle installation.
    Inspire,
    /// Store limits cannot satisfy the requested operation.
    Configuration,
    /// The presented external handle is absent or expired.
    HandleRejected,
}

/// Failures from the bounded session mechanism.
#[derive(Debug, thiserror::Error)]
pub enum SessionStoreError {
    /// The configured occupancy ceiling cannot admit any session.
    #[error(
        "session store max_sessions is {max_sessions}, expected at least 1; refusing registration before allocating a handle"
    )]
    InvalidLimits {
        /// Configured occupancy ceiling.
        max_sessions: usize,
    },
    /// Live sessions and registrations in progress fill the ceiling.
    #[error(
        "session store is at its configured ceiling of {max_sessions} live sessions, counting registrations in progress; refusing registration rather than retiring another caller's keys, retry after a session expires (ttl {ttl_secs}s)"
    )]
    AtCapacity {
        /// Configured occupancy ceiling.
        max_sessions: usize,
        /// Serviceable lifetime a resident session is counted for.
        ttl_secs: u64,
    },
    /// The OS random source the handle key is drawn from failed.
    #[error(
        "session handle key: {detail}; refusing registration rather than issue guessable handles"
    )]
    Entropy {
        /// The entropy failure.
        detail: String,
    },
    /// InsPIRe rejected a session operation.
    #[error("{operation}: {source}")]
    Inspire {
        /// Operation being performed.
        operation: &'static str,
        /// Scheme error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The expiry instant could not represent the configured TTL.
    #[error("session expiry overflows Instant for ttl {ttl_secs}s; refusing registration")]
    ExpiryOverflow {
        /// Configured TTL in seconds.
        ttl_secs: u64,
    },
    /// An external handle is absent, removed, or expired.
    #[error("{detail}")]
    HandleRejected {
        /// Actionable refusal detail.
        detail: String,
    },
}

impl SessionStoreError {
    /// Return the handling category without parsing the display string.
    #[must_use]
    pub const fn class(&self) -> SessionStoreErrorClass {
        match self {
            Self::InvalidLimits { .. } | Self::AtCapacity { .. } => {
                SessionStoreErrorClass::Configuration
            }
            Self::Entropy { .. } => SessionStoreErrorClass::Entropy,
            Self::Inspire { .. } | Self::ExpiryOverflow { .. } => SessionStoreErrorClass::Inspire,
            Self::HandleRejected { .. } => SessionStoreErrorClass::HandleRejected,
        }
    }

    /// Borrow handle-refusal detail when this is a handle error.
    #[must_use]
    pub fn handle_rejection_detail(&self) -> Option<&str> {
        match self {
            Self::HandleRejected { detail } => Some(detail),
            Self::InvalidLimits { .. }
            | Self::AtCapacity { .. }
            | Self::Entropy { .. }
            | Self::Inspire { .. }
            | Self::ExpiryOverflow { .. } => None,
        }
    }
}

/// Result returned by the session mechanism.
pub type Result<T, E = SessionStoreError> = std::result::Result<T, E>;

/// Occupancy and lifetime bounds for a [`BoundedSessionStore`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionStoreLimits {
    /// Inner-store length at which wire registration is refused and the in-process
    /// path reclaims a whole generation.
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

/// Current resident and serviceable session counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionCounts {
    /// Packing-key sets resident in the inner store.
    pub occupancy: usize,
    /// External handles accepted by `resolve`, ignoring TTL passage after observation.
    pub serviceable: usize,
}

/// Eviction deltas produced by one operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionEvictions {
    /// Explicitly removed external bindings.
    pub removed: u64,
    /// External bindings removed after TTL expiry.
    pub expired: u64,
    /// Packing-key sets and bindings dropped by a cap-triggered generation flush.
    pub flushed: u64,
}

/// Ordered metric-neutral facts produced by one mutation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionObservation {
    /// Store-local operation order; larger values supersede older gauge snapshots.
    pub sequence: u64,
    /// Eviction deltas for this operation only.
    pub evictions: SessionEvictions,
    /// Cap-triggered whole-generation flushes performed by this operation.
    pub flushes: u64,
    /// Current counts after operations that change or explicitly observe occupancy.
    pub counts: Option<SessionCounts>,
}

/// Recoverable inner-store failure observed while serviceability still changed.
#[derive(Debug, thiserror::Error)]
pub enum SessionWarning {
    /// Removing an expired or explicit binding failed in the inner store.
    #[error("session key removal failed for external handle {handle}: {source}")]
    RemovalFailed {
        /// External handle whose binding was removed.
        handle: u64,
        /// Inner-store failure.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// An outcome paired with the exact observation and recoverable warnings it produced.
#[must_use]
pub struct Observed<T> {
    outcome: Result<T>,
    observation: SessionObservation,
    warnings: Vec<SessionWarning>,
}

impl<T> Observed<T> {
    /// Split the domain result, observation, and recoverable warnings.
    pub fn into_parts(self) -> (Result<T>, SessionObservation, Vec<SessionWarning>) {
        (self.outcome, self.observation, self.warnings)
    }
}

struct Generation {
    store: Arc<ServerSessionStore>,
    expiry: HashMap<u64, SessionEntry>,
}

struct SessionEntry {
    inner: ServerSessionHandle,
    expires_at: Instant,
}

impl Generation {
    fn fresh() -> Self {
        Self {
            store: Arc::new(ServerSessionStore::new()),
            expiry: HashMap::new(),
        }
    }

    fn counts(&self) -> SessionCounts {
        SessionCounts {
            occupancy: self.store.len(),
            serviceable: self.expiry.len(),
        }
    }
}

/// External handles: SHA-256 of a secret key and a counter, truncated to 64 bits. A handle
/// says nothing about any other, so holding one names no other caller's seat, and a guess hits
/// a live seat with odds of the live count over 2^64.
struct RandomHandles {
    stream: Mutex<HandleStream>,
}

struct HandleStream {
    /// Drawn at the first registration, so building a store needs no entropy.
    key: Option<[u8; 32]>,
    counter: u64,
    #[cfg(test)]
    entropy_fails: bool,
}

impl std::fmt::Debug for RandomHandles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RandomHandles").finish_non_exhaustive()
    }
}

impl RandomHandles {
    fn new() -> Self {
        Self {
            stream: Mutex::new(HandleStream {
                key: None,
                counter: 0,
                #[cfg(test)]
                entropy_fails: false,
            }),
        }
    }

    #[cfg(test)]
    fn without_entropy() -> Self {
        let handles = Self::new();
        handles.stream.lock().entropy_fails = true;
        handles
    }

    /// A handle no live binding of `taken` holds.
    fn draw(&self, taken: &HashMap<u64, SessionEntry>) -> Result<ServerSessionHandle> {
        let mut stream = self.stream.lock();
        #[cfg(test)]
        if stream.entropy_fails {
            return Err(SessionStoreError::Entropy {
                detail: "test source refused".to_owned(),
            });
        }
        let key = if let Some(key) = stream.key {
            key
        } else {
            let key =
                raven_inspire::math::gaussian::os_seed("session handle key").map_err(|e| {
                    SessionStoreError::Entropy {
                        detail: e.to_string(),
                    }
                })?;
            stream.key = Some(key);
            key
        };
        loop {
            stream.counter = stream.counter.wrapping_add(1);
            let mut hasher = Sha256::new();
            hasher.update(key);
            hasher.update(stream.counter.to_be_bytes());
            let digest = hasher.finalize();
            let mut word = [0u8; 8];
            word.copy_from_slice(digest.get(..8).unwrap_or(&[0u8; 8]));
            let handle = u64::from_be_bytes(word);
            if !taken.contains_key(&handle) {
                return Ok(ServerSessionHandle(handle));
            }
        }
    }
}

/// A seat counted against the ceiling while its keys are checked outside the store lock.
struct SeatReservation<'a> {
    owner: Option<&'a BoundedSessionStore>,
}

impl SeatReservation<'_> {
    /// Hand the seat back under the lock that also inserts its keys, so no admission check
    /// sees it twice or not at all.
    fn release(mut self, _locked: &mut Generation) {
        if let Some(owner) = self.owner.take() {
            owner.pending_seats.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl Drop for SeatReservation<'_> {
    fn drop(&mut self) {
        // Reached only by unwinding out of the key check; the lock keeps the count exact.
        if let Some(owner) = self.owner.take() {
            let _generation = owner.current.write();
            owner.pending_seats.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Occupancy-bounded session store with random external handles.
///
/// In-process reclamation replaces a whole generation. A resolved request retains an `Arc` to its
/// generation, so an in-flight response can finish while every later request rejects its retired
/// handle. Wire registration never reclaims: at the ceiling it refuses, because its caller is
/// unauthenticated and would otherwise discard sessions it does not own.
pub struct BoundedSessionStore {
    limits: SessionStoreLimits,
    current: RwLock<Generation>,
    /// Wire registrations admitted but not yet seated. Changed and read only under
    /// `current`'s write lock, so admission counts it exactly.
    pending_seats: AtomicUsize,
    handles: Arc<RandomHandles>,
    evicted_total: AtomicU64,
    flushes_total: AtomicU64,
    observation_sequence: Arc<AtomicU64>,
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
    /// Build an in-memory store with default limits.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(SessionStoreLimits::default())
    }

    /// Build an in-memory store with caller-selected limits.
    #[must_use]
    pub fn with_limits(limits: SessionStoreLimits) -> Self {
        Self {
            limits,
            current: RwLock::new(Generation::fresh()),
            pending_seats: AtomicUsize::new(0),
            handles: Arc::new(RandomHandles::new()),
            evicted_total: AtomicU64::new(0),
            flushes_total: AtomicU64::new(0),
            observation_sequence: Arc::new(AtomicU64::new(0)),
        }
    }

    /// [`Self::open_with_limits`] with default limits.
    ///
    /// # Errors
    ///
    /// The default limits are refused, which they never are.
    pub fn open(data_dir: &Path) -> Result<Self> {
        Self::open_with_limits(data_dir, SessionStoreLimits::default())
    }

    /// A store for an instance's data directory, with its limits checked up front.
    ///
    /// Nothing is read from or written to `data_dir`: a random handle repeats across a restart
    /// only by a 64-bit collision, so no issuance history has to survive one. A directory written
    /// by an earlier build that kept a handle floor there is left as it is.
    ///
    /// # Errors
    ///
    /// [`SessionStoreError::InvalidLimits`] when `limits` admits no session.
    pub fn open_with_limits(data_dir: &Path, limits: SessionStoreLimits) -> Result<Self> {
        let _ = data_dir;
        Self::validate_registration_limits(limits)?;
        Ok(Self::with_limits(limits))
    }

    /// Build an empty generation retaining the same limits and handle stream.
    #[must_use]
    pub fn empty_successor(&self) -> Self {
        Self {
            limits: self.limits,
            current: RwLock::new(Generation::fresh()),
            pending_seats: AtomicUsize::new(0),
            handles: Arc::clone(&self.handles),
            evicted_total: AtomicU64::new(0),
            flushes_total: AtomicU64::new(0),
            observation_sequence: Arc::clone(&self.observation_sequence),
        }
    }

    /// Configured limits.
    #[must_use]
    pub fn limits(&self) -> SessionStoreLimits {
        self.limits
    }

    /// Resident packing-key sets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.current.read().store.len()
    }

    /// Whether no packing-key set is resident.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Handles that would pass the serviceability lookup before a TTL comparison.
    #[must_use]
    pub fn serviceable_len(&self) -> usize {
        self.current.read().expiry.len()
    }

    /// Sessions retired by expiry, explicit removal, or flush.
    #[must_use]
    pub fn evicted_total(&self) -> u64 {
        self.evicted_total.load(Ordering::Relaxed)
    }

    /// Cap-triggered generation flushes.
    #[must_use]
    pub fn flushes_total(&self) -> u64 {
        self.flushes_total.load(Ordering::Relaxed)
    }

    /// Check wire-delivered packing keys against the server's packing shape and seat them.
    ///
    /// Refuses with [`SessionStoreError::AtCapacity`] once `max_sessions` live sessions, counting
    /// registrations in progress, are resident, rather than retiring any of them.
    pub fn register_server_side(
        &self,
        keys: ClientPackingKeys,
        pack_params: &PackParams,
        context: &NttContext,
    ) -> Observed<ServerSessionHandle> {
        self.register_server_side_at(keys, pack_params, context, Instant::now())
    }

    /// Register wire-delivered packing keys against an explicit clock.
    ///
    /// Refuses with [`SessionStoreError::AtCapacity`] once `max_sessions` live sessions, counting
    /// registrations in progress, are resident, rather than retiring any of them.
    pub fn register_server_side_at(
        &self,
        keys: ClientPackingKeys,
        pack_params: &PackParams,
        context: &NttContext,
        now: Instant,
    ) -> Observed<ServerSessionHandle> {
        let expires_at = match self.registration_expiry(now) {
            Ok(expires_at) => expires_at,
            Err(error) => return self.failed_observation(error),
        };
        let mut observation = SessionObservation::default();
        let mut warnings = Vec::new();
        let seat = {
            let mut generation = self.current.write();
            self.reclaim_expired(&mut generation, now, &mut observation, &mut warnings);
            // Wire-delivered keys arrive from a caller that presented no credential, so
            // whole-generation reclamation here would let any one of them discard every other
            // caller's packing keys.
            let pending = self.pending_seats.load(Ordering::Relaxed);
            if generation.store.len().saturating_add(pending) >= self.limits.max_sessions {
                return self.at_capacity(&generation, observation, warnings);
            }
            self.pending_seats.store(pending + 1, Ordering::Relaxed);
            SeatReservation { owner: Some(self) }
        };
        // The key transforms run unlocked: under the lock they would stall every query's resolve.
        let prepared = PackingKeySeat::from_wire(keys, pack_params, context).map_err(|source| {
            SessionStoreError::Inspire {
                operation: "session register_server_side",
                source: Box::new(source),
            }
        });
        let mut generation = self.current.write();
        seat.release(&mut generation);
        let outcome =
            prepared.and_then(|seat| {
                let handle = self.handles.draw(&generation.expiry)?;
                let inner = generation.store.register(seat).map_err(|source| {
                    SessionStoreError::Inspire {
                        operation: "session register_server_side",
                        source: Box::new(source),
                    }
                })?;
                generation
                    .expiry
                    .insert(handle.0, SessionEntry { inner, expires_at });
                Ok(handle)
            });
        observation.counts = Some(generation.counts());
        self.finish_observation(&mut observation);
        Observed {
            outcome,
            observation,
            warnings,
        }
    }

    /// Register an in-process client and install the external handle it must send.
    ///
    /// Once live sessions and wire registrations in progress fill every seat, the generation is
    /// flushed: every resident session is retired and this one starts the next generation.
    /// Refuses with [`SessionStoreError::AtCapacity`] when wire registrations in progress hold
    /// every seat, since a flush cannot free those.
    pub fn register_client_session_at(
        &self,
        session: &mut ClientSession,
        now: Instant,
    ) -> Observed<Option<ServerSessionHandle>> {
        let expires_at = match self.registration_expiry(now) {
            Ok(expires_at) => expires_at,
            Err(error) => return self.failed_observation(error),
        };
        let mut generation = self.current.write();
        let mut observation = SessionObservation::default();
        let mut warnings = Vec::new();
        let Some(ceiling) = self.flushable_ceiling() else {
            return self.at_capacity(&generation, observation, warnings);
        };
        if Self::would_flush_after_sweep(&generation, now, ceiling) {
            let outcome = (|| {
                let external = self.handles.draw(&generation.expiry)?;
                let replacement = Arc::new(ServerSessionStore::new());
                let inner = session
                    .register_with(replacement.as_ref())
                    .map_err(|source| SessionStoreError::Inspire {
                        operation: "session register",
                        source: Box::new(source),
                    })?;
                let binding = match inner {
                    Some(inner) => {
                        session
                            .install_server_session_handle(external)
                            .map_err(|source| SessionStoreError::Inspire {
                                operation: "session handle install",
                                source: Box::new(source),
                            })?;
                        Some((external, inner))
                    }
                    None => None,
                };
                if let Some((external, inner)) = binding {
                    self.make_room(&mut generation, now, &mut observation, &mut warnings);
                    generation.store = replacement;
                    generation
                        .expiry
                        .insert(external.0, SessionEntry { inner, expires_at });
                }
                Ok(binding.map(|(external, _inner)| external))
            })();
            observation.counts = Some(generation.counts());
            self.finish_observation(&mut observation);
            return Observed {
                outcome,
                observation,
                warnings,
            };
        }
        self.make_room(&mut generation, now, &mut observation, &mut warnings);
        let outcome = (|| {
            let external = self.handles.draw(&generation.expiry)?;
            let inner = session
                .register_with(generation.store.as_ref())
                .map_err(|source| SessionStoreError::Inspire {
                    operation: "session register",
                    source: Box::new(source),
                })?;
            let binding = match inner {
                Some(inner) => {
                    if let Err(source) = session.install_server_session_handle(external) {
                        if let Err(source) = generation.store.remove(inner) {
                            warnings.push(SessionWarning::RemovalFailed {
                                handle: external.0,
                                source: Box::new(source),
                            });
                        }
                        return Err(SessionStoreError::Inspire {
                            operation: "session handle install",
                            source: Box::new(source),
                        });
                    }
                    Some((external, inner))
                }
                None => None,
            };
            if let Some((external, inner)) = binding {
                generation
                    .expiry
                    .insert(external.0, SessionEntry { inner, expires_at });
            }
            Ok(binding.map(|(external, _inner)| external))
        })();
        observation.counts = Some(generation.counts());
        self.finish_observation(&mut observation);
        Observed {
            outcome,
            observation,
            warnings,
        }
    }

    /// Resolve an external handle into the generation and inner handle a responder must use.
    ///
    /// `None` represents an inline-key request and bypasses serviceability bookkeeping.
    pub fn resolve(
        &self,
        handle: Option<ServerSessionHandle>,
        now: Instant,
    ) -> Result<(Arc<ServerSessionStore>, Option<ServerSessionHandle>)> {
        let generation = self.current.read();
        let Some(handle) = handle else {
            return Ok((Arc::clone(&generation.store), None));
        };
        match generation.expiry.get(&handle.0) {
            Some(entry) if entry.expires_at > now => {
                Ok((Arc::clone(&generation.store), Some(entry.inner)))
            }
            entry => Err(self.rejected(handle, entry.is_some(), &generation)),
        }
    }

    /// [`Self::resolve`] for a handle in use: a serviceable handle's expiry moves to
    /// `now + ttl`, so a session stays registered while it is used and lapses one TTL after
    /// its last use.
    ///
    /// # Errors
    ///
    /// The handle is expired or unknown, or the renewed expiry overflows `Instant`.
    pub fn resolve_renewing(
        &self,
        handle: ServerSessionHandle,
        now: Instant,
    ) -> Result<(Arc<ServerSessionStore>, ServerSessionHandle)> {
        let renewed = self.expiry_at(now)?;
        let mut generation = self.current.write();
        let store = Arc::clone(&generation.store);
        match generation.expiry.get_mut(&handle.0) {
            Some(entry) if entry.expires_at > now => {
                entry.expires_at = entry.expires_at.max(renewed);
                Ok((store, entry.inner))
            }
            entry => {
                let expired = entry.is_some();
                Err(self.rejected(handle, expired, &generation))
            }
        }
    }

    fn rejected(
        &self,
        handle: ServerSessionHandle,
        expired: bool,
        generation: &Generation,
    ) -> SessionStoreError {
        let detail = if expired {
            format!(
                "session handle {} expired (ttl {}s); re-run the session handshake",
                handle.0,
                self.limits.ttl.as_secs()
            )
        } else {
            format!(
                "session handle {} is not registered on this instance ({} serviceable, {} evicted since start); re-run the session handshake",
                handle.0,
                generation.expiry.len(),
                self.evicted_total()
            )
        };
        SessionStoreError::HandleRejected { detail }
    }

    /// Stop serving an external handle and release its inner packing keys.
    pub fn remove(&self, handle: ServerSessionHandle) -> Observed<bool> {
        let mut generation = self.current.write();
        let mut observation = SessionObservation::default();
        let mut warnings = Vec::new();
        let Some(entry) = generation.expiry.remove(&handle.0) else {
            observation.counts = Some(generation.counts());
            self.finish_observation(&mut observation);
            return Observed {
                outcome: Ok(false),
                observation,
                warnings,
            };
        };
        match generation.store.remove(entry.inner) {
            Ok(_) => {}
            Err(source) => {
                warnings.push(SessionWarning::RemovalFailed {
                    handle: handle.0,
                    source: Box::new(source),
                });
            }
        }
        self.evicted_total.fetch_add(1, Ordering::Relaxed);
        observation.evictions.removed = 1;
        observation.counts = Some(generation.counts());
        self.finish_observation(&mut observation);
        Observed {
            outcome: Ok(true),
            observation,
            warnings,
        }
    }

    /// Drop every external binding whose TTL elapsed at or before `now`.
    pub fn sweep_expired(&self, now: Instant) -> Observed<usize> {
        let mut generation = self.current.write();
        let mut observation = SessionObservation::default();
        let (swept, warnings) = Self::sweep_locked(&mut generation, now);
        if swept > 0 {
            let swept_u64 = u64::try_from(swept).unwrap_or(u64::MAX);
            self.evicted_total.fetch_add(swept_u64, Ordering::Relaxed);
            observation.evictions.expired = swept_u64;
        }
        observation.counts = Some(generation.counts());
        self.finish_observation(&mut observation);
        Observed {
            outcome: Ok(swept),
            observation,
            warnings,
        }
    }

    fn registration_expiry(&self, now: Instant) -> Result<Instant> {
        Self::validate_registration_limits(self.limits)?;
        self.expiry_at(now)
    }

    /// Seats a flush can free: the ceiling less the wire registrations in flight, `None` when
    /// those hold every seat. Read under `current`'s write lock.
    fn flushable_ceiling(&self) -> Option<usize> {
        let pending = self.pending_seats.load(Ordering::Relaxed);
        self.limits
            .max_sessions
            .checked_sub(pending)
            .filter(|seats| *seats > 0)
    }

    fn expiry_at(&self, now: Instant) -> Result<Instant> {
        now.checked_add(self.limits.ttl)
            .ok_or(SessionStoreError::ExpiryOverflow {
                ttl_secs: self.limits.ttl.as_secs(),
            })
    }

    fn validate_registration_limits(limits: SessionStoreLimits) -> Result<()> {
        if limits.max_sessions == 0 {
            return Err(SessionStoreError::InvalidLimits {
                max_sessions: limits.max_sessions,
            });
        }
        Ok(())
    }

    fn at_capacity<T>(
        &self,
        generation: &Generation,
        mut observation: SessionObservation,
        warnings: Vec<SessionWarning>,
    ) -> Observed<T> {
        observation.counts = Some(generation.counts());
        self.finish_observation(&mut observation);
        Observed {
            outcome: Err(SessionStoreError::AtCapacity {
                max_sessions: self.limits.max_sessions,
                ttl_secs: self.limits.ttl.as_secs(),
            }),
            observation,
            warnings,
        }
    }

    fn failed_observation<T>(&self, error: SessionStoreError) -> Observed<T> {
        let mut observation = SessionObservation::default();
        self.finish_observation(&mut observation);
        Observed {
            outcome: Err(error),
            observation,
            warnings: Vec::new(),
        }
    }

    fn sweep_locked(generation: &mut Generation, now: Instant) -> (usize, Vec<SessionWarning>) {
        let expired: Vec<(ServerSessionHandle, ServerSessionHandle)> = generation
            .expiry
            .iter()
            .filter_map(|(handle, entry)| {
                (entry.expires_at <= now).then_some((ServerSessionHandle(*handle), entry.inner))
            })
            .collect();
        let removed = expired.len();
        let mut warnings = Vec::new();
        for (external, inner) in expired {
            generation.expiry.remove(&external.0);
            match generation.store.remove(inner) {
                Ok(_) => {}
                Err(source) => warnings.push(SessionWarning::RemovalFailed {
                    handle: external.0,
                    source: Box::new(source),
                }),
            }
        }
        (removed, warnings)
    }

    fn reclaim_expired(
        &self,
        generation: &mut Generation,
        now: Instant,
        observation: &mut SessionObservation,
        warnings: &mut Vec<SessionWarning>,
    ) {
        let (swept, sweep_warnings) = Self::sweep_locked(generation, now);
        warnings.extend(sweep_warnings);
        if swept > 0 {
            let swept_u64 = u64::try_from(swept).unwrap_or(u64::MAX);
            self.evicted_total.fetch_add(swept_u64, Ordering::Relaxed);
            observation.evictions.expired = swept_u64;
        }
    }

    fn make_room(
        &self,
        generation: &mut Generation,
        now: Instant,
        observation: &mut SessionObservation,
        warnings: &mut Vec<SessionWarning>,
    ) {
        self.reclaim_expired(generation, now, observation, warnings);
        if generation.store.len() < self.flushable_ceiling().unwrap_or(0) {
            return;
        }
        let dropped = u64::try_from(generation.store.len()).unwrap_or(u64::MAX);
        *generation = Generation::fresh();
        self.evicted_total.fetch_add(dropped, Ordering::Relaxed);
        self.flushes_total.fetch_add(1, Ordering::Relaxed);
        observation.evictions.flushed = dropped;
        observation.flushes = 1;
    }

    fn would_flush_after_sweep(generation: &Generation, now: Instant, max_sessions: usize) -> bool {
        let mut occupancy_after_sweep = generation.store.len();
        for entry in generation
            .expiry
            .values()
            .filter(|entry| entry.expires_at <= now)
        {
            match generation.store.get(entry.inner) {
                Ok(Some(_)) => occupancy_after_sweep = occupancy_after_sweep.saturating_sub(1),
                Ok(None) => {}
                Err(_) => return true,
            }
        }
        occupancy_after_sweep >= max_sessions
    }

    fn finish_observation(&self, observation: &mut SessionObservation) {
        let prior = self
            .observation_sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |sequence| {
                Some(sequence.saturating_add(1))
            })
            .unwrap_or(u64::MAX);
        observation.sequence = prior.saturating_add(1);
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]
mod tests {
    use super::{BoundedSessionStore, SessionEntry, SessionObservation, SessionStoreLimits};
    use raven_inspire::inspiring::{ClientPackingKeys, PackParams};
    use raven_inspire::math::GaussianSampler;
    use raven_inspire::params::InspireParams;
    use raven_inspire::rlwe::RlweSecretKey;
    use raven_inspire::{setup, ClientSession, PackingKeySeat, ServerSessionHandle};
    use std::sync::{Arc, OnceLock};
    use std::time::{Duration, Instant};

    fn registration_material(
        gamma: usize,
        seed: u64,
    ) -> (
        ClientPackingKeys,
        PackParams,
        raven_inspire::math::NttContext,
    ) {
        registration_material_for(&InspireParams::d2048(), gamma, seed)
    }

    fn registration_material_for(
        params: &InspireParams,
        gamma: usize,
        seed: u64,
    ) -> (
        ClientPackingKeys,
        PackParams,
        raven_inspire::math::NttContext,
    ) {
        let params = params.clone();
        let mut sampler = GaussianSampler::with_seed(params.sigma, seed);
        let secret_key = RlweSecretKey::generate(&params, &mut sampler);
        let pack_params = PackParams::try_new(&params, gamma).expect("pack params");
        let keys = ClientPackingKeys::generate(&secret_key, &params, gamma, [7; 32], &mut sampler)
            .expect("packing keys");
        (keys, pack_params, params.ntt_context())
    }

    fn real_registration_material() -> (
        ClientPackingKeys,
        PackParams,
        raven_inspire::math::NttContext,
    ) {
        registration_material(16, 117)
    }

    fn resident_seat() -> PackingKeySeat {
        static MATERIAL: OnceLock<(
            ClientPackingKeys,
            PackParams,
            raven_inspire::math::NttContext,
        )> = OnceLock::new();
        let (keys, pack_params, context) = MATERIAL.get_or_init(real_registration_material);
        PackingKeySeat::from_wire(keys.clone(), pack_params, context).expect("seat")
    }

    fn store(max_sessions: usize) -> BoundedSessionStore {
        BoundedSessionStore::with_limits(SessionStoreLimits {
            max_sessions,
            ttl: Duration::from_secs(3600),
        })
    }

    fn register(
        store: &BoundedSessionStore,
        now: Instant,
    ) -> (ServerSessionHandle, SessionObservation) {
        let mut generation = store.current.write();
        let mut observation = SessionObservation::default();
        let mut warnings = Vec::new();
        store.make_room(&mut generation, now, &mut observation, &mut warnings);
        assert!(warnings.is_empty());
        let handle = generation
            .store
            .register(resident_seat())
            .expect("register");
        generation.expiry.insert(
            handle.0,
            SessionEntry {
                inner: handle,
                expires_at: now + store.limits.ttl,
            },
        );
        observation.counts = Some(generation.counts());
        store.finish_observation(&mut observation);
        (handle, observation)
    }

    #[test]
    fn occupancy_never_exceeds_the_cap_under_churn() {
        let store = store(8);
        let start = Instant::now();
        for index in 0..200u32 {
            register(&store, start + Duration::from_millis(u64::from(index)));
            assert!(store.len() <= 8);
        }
        assert!(store.flushes_total() >= 24);
    }

    #[test]
    fn flush_frees_the_packing_keys_it_evicted() {
        let store = store(4);
        let start = Instant::now();
        let (handle, _observation) = register(&store, start);
        let (inner_store, inner_handle) = store.resolve(Some(handle), start).expect("resolve");
        let held = inner_store
            .get(inner_handle.expect("translated handle"))
            .expect("get")
            .expect("present");
        assert_eq!(Arc::strong_count(&held), 2);
        for index in 1..8u32 {
            register(&store, start + Duration::from_millis(u64::from(index)));
        }
        drop(inner_store);
        assert_eq!(Arc::strong_count(&held), 1);
    }

    #[test]
    fn evicted_handles_fail_closed_instead_of_resolving() {
        let store = store(4);
        let start = Instant::now();
        let flushed: Vec<_> = (0..4u32)
            .map(|index| register(&store, start + Duration::from_millis(u64::from(index))).0)
            .collect();
        let survivor = register(&store, start + Duration::from_millis(4)).0;
        assert_eq!(store.flushes_total(), 1);
        for handle in flushed {
            assert!(store
                .resolve(Some(handle), start + Duration::from_secs(1))
                .is_err());
            assert_ne!(handle, survivor);
        }
        assert!(store
            .resolve(Some(survivor), start + Duration::from_secs(1))
            .is_ok());
    }

    #[test]
    fn remove_stops_service_and_counts_one_eviction() {
        let store = store(64);
        let start = Instant::now();
        let handle = register(&store, start).0;
        let (first, observation, warnings) = store.remove(handle).into_parts();
        assert!(first.expect("first remove"));
        assert!(warnings.is_empty());
        assert_eq!(observation.evictions.removed, 1);
        assert!(!store.remove(handle).into_parts().0.expect("second remove"));
        assert_eq!(store.len(), 0);
        assert_eq!(store.evicted_total(), 1);
        assert!(store.resolve(Some(handle), start).is_err());
    }

    #[test]
    fn ttl_expiry_stops_service_and_reports_the_sweep() {
        let store = BoundedSessionStore::with_limits(SessionStoreLimits {
            max_sessions: 64,
            ttl: Duration::from_secs(10),
        });
        let start = Instant::now();
        let handle = register(&store, start).0;
        assert!(store
            .resolve(Some(handle), start + Duration::from_secs(9))
            .is_ok());
        assert!(store
            .resolve(Some(handle), start + Duration::from_secs(10))
            .is_err());
        let (swept, observation, warnings) = store
            .sweep_expired(start + Duration::from_secs(10))
            .into_parts();
        assert_eq!(swept.expect("sweep"), 1);
        assert!(warnings.is_empty());
        assert_eq!(observation.evictions.expired, 1);
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn use_renews_a_session_and_idleness_still_expires_it() {
        let store = BoundedSessionStore::with_limits(SessionStoreLimits {
            max_sessions: 64,
            ttl: Duration::from_secs(10),
        });
        let start = Instant::now();
        let handle = register(&store, start).0;
        let (_, inner) = store
            .resolve_renewing(handle, start + Duration::from_secs(9))
            .expect("live");
        assert!(store
            .resolve(Some(handle), start + Duration::from_secs(18))
            .is_ok());
        assert_eq!(
            store
                .resolve(Some(handle), start + Duration::from_secs(18))
                .expect("live")
                .1,
            Some(inner)
        );
        assert!(store
            .resolve(Some(handle), start + Duration::from_secs(19))
            .is_err());
        let late = store
            .resolve_renewing(handle, start + Duration::from_secs(19))
            .expect_err("an expired handle is not revived");
        assert!(late.to_string().contains("expired"));
        let unknown = store
            .resolve_renewing(ServerSessionHandle(1u64 << 40), start)
            .expect_err("unknown");
        assert!(unknown.to_string().contains("not registered"));
    }

    #[test]
    fn a_high_handle_is_an_ordinary_typed_refusal() {
        let store = store(64);
        let error = store
            .resolve(Some(ServerSessionHandle(1u64 << 32)), Instant::now())
            .expect_err("unknown handle");
        assert_eq!(error.class(), super::SessionStoreErrorClass::HandleRejected);
        assert!(error.to_string().contains("not registered"));
    }

    #[test]
    fn an_in_flight_resolve_survives_a_concurrent_flush() {
        let store = store(4);
        let start = Instant::now();
        let handle = register(&store, start).0;
        let (in_flight, inner) = store.resolve(Some(handle), start).expect("resolve");
        for index in 1..8u32 {
            register(&store, start + Duration::from_millis(u64::from(index)));
        }
        assert!(in_flight.get(inner.expect("inner")).expect("get").is_some());
    }

    #[test]
    fn no_handle_resolves_without_a_serviceability_check() {
        store(4).resolve(None, Instant::now()).expect("inline path");
    }

    #[test]
    fn concurrent_observations_account_for_every_flush_without_duplicate_sequences() {
        let store = Arc::new(store(8));
        let start = Instant::now();
        let mut workers = Vec::new();
        for worker in 0..8u64 {
            let store = Arc::clone(&store);
            workers.push(std::thread::spawn(move || {
                (0..10u64)
                    .map(|offset| {
                        register(&store, start + Duration::from_millis(worker * 10 + offset)).1
                    })
                    .collect::<Vec<_>>()
            }));
        }
        let mut observations: Vec<_> = workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("worker"))
            .collect();
        observations.sort_by_key(|observation| observation.sequence);
        assert_eq!(observations.len(), 80);
        assert!(observations
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence));
        let dropped_by_flush: u64 = observations
            .iter()
            .map(|observation| observation.evictions.flushed)
            .sum();
        let flush_events: u64 = observations
            .iter()
            .map(|observation| observation.flushes)
            .sum();
        assert_eq!(dropped_by_flush, store.evicted_total());
        assert_eq!(flush_events, store.flushes_total());
        assert!(observations.iter().all(|observation| {
            observation
                .counts
                .is_some_and(|counts| counts.occupancy <= 8 && counts.serviceable <= 8)
        }));
    }

    #[test]
    fn successor_observations_continue_the_donor_order() {
        let store = store(8);
        let start = Instant::now();
        let first = register(&store, start).1;
        let successor = store.empty_successor();
        let second = register(&successor, start + Duration::from_millis(1)).1;

        assert!(second.sequence > first.sequence);
    }

    #[test]
    fn zero_cap_refuses_registration_before_allocating_or_mutating() {
        let params = InspireParams::d2048();
        let database = vec![0u8; params.ring_dim * 32];
        let mut sampler = GaussianSampler::with_seed(params.sigma, 91);
        let (crs, _server_key, secret_key) =
            setup(&params, &database, 32, &mut sampler).expect("setup");
        let mut client = ClientSession::new(crs, secret_key, &mut sampler).expect("client session");
        let store = store(0);

        let (outcome, observation, warnings) = store
            .register_client_session_at(&mut client, Instant::now())
            .into_parts();

        assert!(matches!(
            outcome,
            Err(super::SessionStoreError::InvalidLimits { max_sessions: 0 })
        ));
        assert!(warnings.is_empty());
        assert_eq!(observation.evictions, super::SessionEvictions::default());
        assert_eq!(observation.counts, None);
        assert_eq!(store.len(), 0);
        assert_eq!(store.serviceable_len(), 0);
    }

    #[test]
    fn removing_a_binding_counts_even_when_its_inner_key_is_already_absent() {
        let store = store(4);
        let now = Instant::now();
        let handle = register(&store, now).0;
        let (inner_store, inner) = store.resolve(Some(handle), now).expect("resolve");
        assert!(inner_store
            .remove(inner.expect("inner"))
            .expect("inner remove"));

        let (outcome, observation, warnings) = store.remove(handle).into_parts();

        assert!(outcome.expect("external binding existed"));
        assert!(warnings.is_empty());
        assert_eq!(observation.evictions.removed, 1);
        assert_eq!(store.serviceable_len(), 0);
        assert_eq!(store.evicted_total(), 1);
    }

    #[test]
    fn sweeping_counts_expired_bindings_when_an_inner_key_is_already_absent() {
        let store = BoundedSessionStore::with_limits(SessionStoreLimits {
            max_sessions: 4,
            ttl: Duration::from_secs(10),
        });
        let now = Instant::now();
        let handle = register(&store, now).0;
        let (inner_store, inner) = store.resolve(Some(handle), now).expect("resolve");
        assert!(inner_store
            .remove(inner.expect("inner"))
            .expect("inner remove"));

        let (outcome, observation, warnings) = store
            .sweep_expired(now + Duration::from_secs(10))
            .into_parts();

        assert_eq!(outcome.expect("sweep"), 1);
        assert!(warnings.is_empty());
        assert_eq!(observation.evictions.expired, 1);
        assert_eq!(store.serviceable_len(), 0);
        assert_eq!(store.evicted_total(), 1);
    }

    #[test]
    fn a_wire_registration_at_capacity_is_refused_and_keeps_every_live_session() {
        let (keys, pack_params, context) = real_registration_material();
        let store = store(2);
        let now = Instant::now();
        let residents: Vec<_> = (0..2)
            .map(|index| {
                store
                    .register_server_side_at(keys.clone(), &pack_params, &context, now)
                    .outcome
                    .unwrap_or_else(|error| panic!("resident {index}: {error}"))
            })
            .collect();

        let (refused, observation, warnings) = store
            .register_server_side_at(keys.clone(), &pack_params, &context, now)
            .into_parts();

        assert!(
            matches!(refused, Err(super::SessionStoreError::AtCapacity { max_sessions, .. }) if max_sessions == 2),
            "a full pool must refuse by capacity, not by flushing"
        );
        assert!(warnings.is_empty());
        assert_eq!(observation.evictions, super::SessionEvictions::default());
        assert_eq!(observation.flushes, 0);
        assert_eq!(store.flushes_total(), 0);
        assert_eq!(store.evicted_total(), 0);
        assert_eq!(store.len(), 2);
        for (index, handle) in residents.iter().enumerate() {
            assert!(
                store.resolve(Some(*handle), now).is_ok(),
                "resident {index} must still serve"
            );
        }

        // The seat frees only when its own TTL elapses.
        let after_ttl = now + store.limits.ttl + Duration::from_secs(1);
        let readmitted = store
            .register_server_side_at(keys, &pack_params, &context, after_ttl)
            .outcome;
        assert!(readmitted.is_ok(), "expiry must free the pool again");
    }

    #[test]
    fn a_rejected_key_set_below_capacity_preserves_the_live_session() {
        let (keys, pack_params, context) = real_registration_material();
        let store = store(4);
        let now = Instant::now();
        let (first, _, _) = store
            .register_server_side_at(keys.clone(), &pack_params, &context, now)
            .into_parts();
        let first = first.expect("first registration");
        let mut invalid = keys;
        invalid.y_body.pop();

        let (second, observation, warnings) = store
            .register_server_side_at(invalid, &pack_params, &context, now)
            .into_parts();

        assert!(second.is_err());
        assert!(warnings.is_empty());
        assert_eq!(observation.evictions, super::SessionEvictions::default());
        assert_eq!(observation.flushes, 0);
        assert_eq!(
            observation.counts,
            Some(super::SessionCounts {
                occupancy: 1,
                serviceable: 1,
            })
        );
        assert_eq!(store.len(), 1);
        assert_eq!(store.serviceable_len(), 1);
        assert_eq!(store.evicted_total(), 0);
        assert_eq!(store.flushes_total(), 0);
        assert!(store.resolve(Some(first), now).is_ok());
    }

    #[test]
    fn refused_client_registration_at_capacity_preserves_the_live_session() {
        let params = InspireParams::d2048();
        let database = vec![0u8; params.ring_dim * 32];
        let mut sampler = GaussianSampler::with_seed(params.sigma, 119);
        let (crs, _encoded, secret_key) =
            setup(&params, &database, 32, &mut sampler).expect("setup");
        let mut client = ClientSession::new(crs, secret_key, &mut sampler).expect("client session");
        let mut store = BoundedSessionStore::with_limits(SessionStoreLimits {
            max_sessions: 1,
            ttl: Duration::from_secs(3600),
        });
        let now = Instant::now();
        let first = register(&store, now).0;
        store.handles = Arc::new(super::RandomHandles::without_entropy());

        let (outcome, observation, warnings) = store
            .register_client_session_at(&mut client, now)
            .into_parts();

        assert!(matches!(
            outcome,
            Err(super::SessionStoreError::Entropy { .. })
        ));
        assert!(warnings.is_empty());
        assert_eq!(observation.evictions, super::SessionEvictions::default());
        assert_eq!(observation.flushes, 0);
        assert_eq!(
            observation.counts,
            Some(super::SessionCounts {
                occupancy: 1,
                serviceable: 1,
            })
        );
        assert_eq!(store.len(), 1);
        assert_eq!(store.serviceable_len(), 1);
        assert_eq!(store.evicted_total(), 0);
        assert_eq!(store.flushes_total(), 0);
        assert!(store.resolve(Some(first), now).is_ok());
        assert_eq!(client.session_handle(), None);
    }

    #[test]
    fn concurrent_handshakes_never_admit_past_the_ceiling() {
        let (keys, pack_params, context) = registration_material(64, 121);
        let store = store(3);
        let now = Instant::now();
        let start = std::sync::Barrier::new(8);
        let outcomes: Vec<_> = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        start.wait();
                        store
                            .register_server_side_at(keys.clone(), &pack_params, &context, now)
                            .outcome
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().expect("handshake thread"))
                .collect()
        });

        let admitted = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
        let refused = outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(super::SessionStoreError::AtCapacity { .. })))
            .count();
        assert_eq!(
            (admitted, refused),
            (3, 5),
            "exactly the ceiling is admitted"
        );
        assert_eq!(store.len(), 3);
        assert_eq!(store.serviceable_len(), 3);
        assert_eq!(
            store
                .pending_seats
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        let admitted_handle = outcomes
            .iter()
            .find_map(|outcome| outcome.as_ref().ok().copied());
        let resolved = store
            .resolve(admitted_handle, now)
            .expect("an admitted handle resolves");
        let inner = resolved.1.expect("inner handle");
        let held = resolved.0.get(inner).expect("store").expect("seat");
        assert_eq!(held.num_to_pack(), 64);
    }

    // A seat's size is what the session ceiling budgets, at every packing width.
    #[test]
    fn a_seat_holds_one_polynomial_per_key_row_at_every_width() {
        for (params, rows, payload, resident_ceiling) in [
            (InspireParams::d2048(), 3, 49_152, 49_664),
            (InspireParams::d2048_approximate_gadget(), 2, 32_768, 33_280),
        ] {
            assert_eq!(params.packing_key_rows(), rows);
            seats_hold_their_rows(&params, rows, payload, resident_ceiling);
        }
    }

    fn seats_hold_their_rows(
        params: &InspireParams,
        rows: usize,
        payload: usize,
        resident_ceiling: usize,
    ) {
        for gamma in [16, 128, 256] {
            let (keys, pack_params, context) = registration_material_for(params, gamma, 131);
            let store = store(2);
            let handle = store
                .register_server_side_at(keys, &pack_params, &context, Instant::now())
                .outcome
                .expect("registration");
            let (inner_store, inner) = store
                .resolve(Some(handle), Instant::now())
                .expect("resolve");
            let seat = inner_store
                .get(inner.expect("inner handle"))
                .expect("store")
                .expect("seat");
            assert_eq!(seat.payload_bytes(), rows * params.ring_dim * 8);
            assert_eq!(seat.payload_bytes(), payload, "gamma {gamma}");
            assert!(
                seat.resident_bytes() <= resident_ceiling,
                "gamma {gamma}: {} bytes resident",
                seat.resident_bytes()
            );
        }
    }

    #[test]
    fn a_full_default_store_stays_inside_its_documented_key_memory() {
        let (keys, pack_params, context) = registration_material(256, 133);
        let seat = PackingKeySeat::from_wire(keys, &pack_params, &context).expect("seat");
        let full = seat.resident_bytes() * super::DEFAULT_MAX_SESSIONS;
        assert!(
            full <= 49 << 20,
            "{} sessions hold {full} bytes of keys",
            super::DEFAULT_MAX_SESSIONS
        );
    }

    #[test]
    fn an_in_process_registration_leaves_room_for_a_wire_registration_in_flight() {
        let params = InspireParams::d2048();
        let database = vec![0u8; params.ring_dim * 32];
        let mut sampler = GaussianSampler::with_seed(params.sigma, 123);
        let (crs, _encoded, secret_key) =
            setup(&params, &database, 32, &mut sampler).expect("setup");
        let mut client = ClientSession::new(crs, secret_key, &mut sampler).expect("client session");
        let store = store(2);
        let now = Instant::now();
        register(&store, now);
        // The state register_server_side_at leaves while its keys are checked unlocked.
        let seat = {
            let _generation = store.current.write();
            store
                .pending_seats
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            super::SeatReservation {
                owner: Some(&store),
            }
        };

        store
            .register_client_session_at(&mut client, now)
            .outcome
            .expect("in-process registration");
        let mut generation = store.current.write();
        seat.release(&mut generation);
        generation
            .store
            .register(resident_seat())
            .expect("wire keys land");
        let occupancy = generation.store.len();
        drop(generation);

        assert!(
            occupancy <= 2,
            "{occupancy} sessions resident against a ceiling of 2"
        );
    }

    #[test]
    fn an_in_process_registration_is_refused_while_wire_registrations_hold_every_seat() {
        let params = InspireParams::d2048();
        let database = vec![0u8; params.ring_dim * 32];
        let mut sampler = GaussianSampler::with_seed(params.sigma, 123);
        let (crs, _encoded, secret_key) =
            setup(&params, &database, 32, &mut sampler).expect("setup");
        let mut client = ClientSession::new(crs, secret_key, &mut sampler).expect("client session");
        let store = store(1);
        let now = Instant::now();
        let seat = {
            let _generation = store.current.write();
            store
                .pending_seats
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            super::SeatReservation {
                owner: Some(&store),
            }
        };

        let refused = store.register_client_session_at(&mut client, now).outcome;
        seat.release(&mut store.current.write());

        assert!(
            matches!(
                refused,
                Err(super::SessionStoreError::AtCapacity {
                    max_sessions: 1,
                    ..
                })
            ),
            "{refused:?}"
        );
        assert_eq!(store.len(), 0);
    }

    /// The old allocator's handles, for the control: consecutive from a floor.
    fn sequential(count: u64) -> Vec<u64> {
        (1024..1024 + count).collect()
    }

    /// Handles a stranger could enumerate: any two within 2^20 of each other, or all below 2^32.
    fn enumerable(handles: &[u64]) -> bool {
        let mut sorted = handles.to_vec();
        sorted.sort_unstable();
        sorted.windows(2).any(|pair| pair[1] - pair[0] < 1 << 20)
            || handles.iter().all(|handle| *handle < 1 << 32)
    }

    /// Wire handles are drawn at random: distinct, nowhere near each other, using the whole
    /// 64-bit space. The predicate flags the sequential handles a floor allocator issued.
    #[test]
    fn wire_handles_are_unguessable() {
        assert!(
            enumerable(&sequential(64)),
            "control: the predicate must flag a counter"
        );
        let (keys, pack_params, context) = real_registration_material();
        let store = store(64);
        let now = Instant::now();
        let handles: Vec<u64> = (0..64)
            .map(|_| {
                store
                    .register_server_side_at(keys.clone(), &pack_params, &context, now)
                    .outcome
                    .expect("seat")
                    .0
            })
            .collect();
        assert!(!enumerable(&handles), "{handles:?}");
        let ones: u32 = handles.iter().map(|handle| handle.count_ones()).sum();
        // 64 handles of 64 fair bits: 2,048 ones expected, sd 32.
        assert!((1_848..=2_248).contains(&ones), "{ones} set bits");
    }

    /// Two stores on one data directory, as across a restart, issue unrelated handles, and
    /// opening touches nothing a previous build left there.
    #[test]
    fn a_restart_issues_unrelated_handles_and_writes_nothing() {
        let (keys, pack_params, context) = real_registration_material();
        let directory = tempfile::tempdir().expect("data dir");
        let left_behind = directory.path().join("session-handle-floor-v1.bin");
        std::fs::write(&left_behind, b"an older build's floor").expect("old floor");
        let mut issued = Vec::new();
        for _ in 0..2 {
            let store = BoundedSessionStore::open_with_limits(
                directory.path(),
                SessionStoreLimits {
                    max_sessions: 8,
                    ttl: Duration::from_secs(3600),
                },
            )
            .expect("open");
            for _ in 0..8 {
                issued.push(
                    store
                        .register_server_side_at(
                            keys.clone(),
                            &pack_params,
                            &context,
                            Instant::now(),
                        )
                        .outcome
                        .expect("seat")
                        .0,
                );
            }
        }
        assert!(!enumerable(&issued), "{issued:?}");
        assert_eq!(
            std::fs::read(&left_behind).expect("old floor"),
            b"an older build's floor"
        );
        assert_eq!(std::fs::read_dir(directory.path()).expect("dir").count(), 1);
    }

    /// A guessed handle neither resolves nor renews: the victim's seat lapses on its own TTL
    /// while strangers try its neighbours. Control: the victim's own use renews it.
    #[test]
    fn a_guessed_handle_cannot_use_or_renew_another_seat() {
        let (keys, pack_params, context) = real_registration_material();
        let ttl = Duration::from_secs(10);
        for victim_renews in [false, true] {
            let store = BoundedSessionStore::with_limits(SessionStoreLimits {
                max_sessions: 4,
                ttl,
            });
            let start = Instant::now();
            let victim = store
                .register_server_side_at(keys.clone(), &pack_params, &context, start)
                .outcome
                .expect("victim seat");
            let later = start + Duration::from_secs(9);
            let guesses = (1..=512u64)
                .flat_map(|delta| [victim.0.wrapping_add(delta), victim.0.wrapping_sub(delta)])
                .chain((0..512u64).map(|bit| victim.0 ^ (1 << (bit % 64))))
                .chain(0..512u64)
                .filter(|guess| *guess != victim.0);
            for guess in guesses {
                assert!(store
                    .resolve_renewing(ServerSessionHandle(guess), later)
                    .is_err());
                assert!(store
                    .resolve(Some(ServerSessionHandle(guess)), later)
                    .is_err());
            }
            if victim_renews {
                store.resolve_renewing(victim, later).expect("own use");
            }
            assert_eq!(
                store.resolve(Some(victim), start + ttl).is_ok(),
                victim_renews,
                "renewed by its own use: {victim_renews}"
            );
        }
    }
}
