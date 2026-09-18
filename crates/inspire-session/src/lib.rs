//! Durable bounded server sessions for InsPIRe.
//!
//! The store keeps scheme-specific packing keys out of `raven-server`, reserves restart-safe
//! external handles before issuing them, and reports mutations as typed observations. Metrics and
//! operator namespaces remain the caller's policy.
//!
//! ```
//! use raven_inspire_session::{BoundedSessionStore, SessionStoreLimits};
//!
//! let store = BoundedSessionStore::with_limits(SessionStoreLimits::default());
//! assert!(store.is_empty());
//! ```

#![deny(missing_docs)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use raven_inspire::inspiring::{ClientPackingKeys, PackParams};
use raven_inspire::math::NttContext;
use raven_inspire::{ClientSession, ServerSessionHandle, ServerSessionStore};
use raven_storage::{atomic_write, ExclusiveLock, PersistenceError, StoreLayout};
use sha2::{Digest, Sha256};

/// Session ceiling before whole-generation reclamation.
pub const DEFAULT_MAX_SESSIONS: usize = 64;

/// Serviceable lifetime of a registered session.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(3600);

const HANDLE_FLOOR_FILE: &str = "session-handle-floor-v1.bin";
const HANDLE_WITNESS_FILE: &str = "session-handle-issuance-v1.bin";
const HANDLE_FLOOR_LOCK: &str = ".session-handle-floor.lock";
const HANDLE_FLOOR_MAGIC: [u8; 8] = *b"RVNHNDL1";
const HANDLE_WITNESS_MAGIC: [u8; 8] = *b"RVNHISS1";
const HANDLE_FLOOR_VERSION: u16 = 1;
const HANDLE_FLOOR_PREFIX_BYTES: usize = 18;
const HANDLE_FLOOR_BYTES: usize = HANDLE_FLOOR_PREFIX_BYTES + 32;
const HANDLE_RESERVATION_SIZE: u64 = 1024;

/// Broad handling category for a typed [`SessionStoreError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionStoreErrorClass {
    /// Persistent allocator state could not prove non-reuse.
    Durability,
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
    /// The short reservation lock could not be acquired.
    #[error("session handle floor lock failed under {}: {source}", data_dir.display())]
    FloorLock {
        /// Instance data directory.
        data_dir: PathBuf,
        /// Lock failure.
        #[source]
        source: PersistenceError,
    },
    /// The floor record could not be read.
    #[error("session handle floor read failed at {}: {source}", path.display())]
    FloorRead {
        /// Floor file path.
        path: PathBuf,
        /// Read failure.
        #[source]
        source: std::io::Error,
    },
    /// Prior issuance evidence exists but the authoritative floor is missing.
    #[error(
        "session handle floor missing at {} after {reason}; restore the floor from a trusted backup before serving handles",
        path.display()
    )]
    FloorMissing {
        /// Missing floor path.
        path: PathBuf,
        /// Evidence that makes zero unsafe.
        reason: &'static str,
    },
    /// A present floor is older than an independent issued-range witness.
    #[error(
        "session handle floor regressed at {}: found {observed}, required at least {required}; restore a current floor before serving handles",
        path.display()
    )]
    FloorRegressed {
        /// Floor file path.
        path: PathBuf,
        /// Observed floor value.
        observed: u64,
        /// Smallest safe floor value.
        required: u64,
    },
    /// The fixed-width floor record was truncated or extended.
    #[error(
        "session handle floor at {} has {actual} bytes, expected {expected}; refusing startup because reuse cannot be excluded",
        path.display()
    )]
    FloorLength {
        /// Floor file path.
        path: PathBuf,
        /// Observed byte length.
        actual: usize,
        /// Required byte length.
        expected: usize,
    },
    /// The floor record magic was not recognized.
    #[error(
        "session handle floor at {} has invalid magic; refusing startup because reuse cannot be excluded",
        path.display()
    )]
    FloorMagic {
        /// Floor file path.
        path: PathBuf,
    },
    /// The floor record version is unsupported.
    #[error(
        "session handle floor at {} has version {actual}, expected {expected}; refusing startup",
        path.display()
    )]
    FloorVersion {
        /// Floor file path.
        path: PathBuf,
        /// Observed version.
        actual: u16,
        /// Supported version.
        expected: u16,
    },
    /// A fixed-width field could not be recovered after length validation.
    #[error("session handle floor at {} has an invalid {field} field", path.display())]
    FloorField {
        /// Floor file path.
        path: PathBuf,
        /// Field name.
        field: &'static str,
    },
    /// The floor checksum did not match the prefix.
    #[error(
        "session handle floor checksum mismatch at {}; refusing startup because reuse cannot be excluded",
        path.display()
    )]
    FloorChecksum {
        /// Floor file path.
        path: PathBuf,
    },
    /// Reserving another range would wrap the public handle namespace.
    #[error("session handle floor exhausted at {next}; refusing registration to prevent reuse")]
    FloorExhausted {
        /// First value the failed range would issue.
        next: u64,
    },
    /// The advanced floor could not be durably published.
    #[error(
        "session handle floor publish failed at {}: {source}; refusing registration because the reserved range is not durable",
        path.display()
    )]
    FloorPublish {
        /// Floor file path.
        path: PathBuf,
        /// Atomic write failure.
        #[source]
        source: std::io::Error,
    },
    /// The independent issued-range witness could not be validated.
    #[error("session handle issuance witness invalid at {}: {source}", path.display())]
    WitnessInvalid {
        /// Witness file path.
        path: PathBuf,
        /// Record validation failure.
        #[source]
        source: Box<SessionStoreError>,
    },
    /// The independent issued-range witness could not be published.
    #[error(
        "session handle issuance witness publish failed at {}: {source}; refusing registration because the reserved range is not fully durable",
        path.display()
    )]
    WitnessPublish {
        /// Witness file path.
        path: PathBuf,
        /// Atomic write failure.
        #[source]
        source: std::io::Error,
    },
    /// The storage history signal could not be inspected.
    #[error("session handle history probe failed at {}: {source}; refusing allocation", path.display())]
    HistoryRead {
        /// Manifest path.
        path: PathBuf,
        /// Probe failure.
        #[source]
        source: std::io::Error,
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
            Self::InvalidLimits { .. } => SessionStoreErrorClass::Configuration,
            Self::FloorLock { .. }
            | Self::FloorRead { .. }
            | Self::FloorMissing { .. }
            | Self::FloorRegressed { .. }
            | Self::FloorLength { .. }
            | Self::FloorMagic { .. }
            | Self::FloorVersion { .. }
            | Self::FloorField { .. }
            | Self::FloorChecksum { .. }
            | Self::FloorExhausted { .. }
            | Self::FloorPublish { .. }
            | Self::WitnessInvalid { .. }
            | Self::WitnessPublish { .. }
            | Self::HistoryRead { .. } => SessionStoreErrorClass::Durability,
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
            | Self::FloorLock { .. }
            | Self::FloorRead { .. }
            | Self::FloorMissing { .. }
            | Self::FloorRegressed { .. }
            | Self::FloorLength { .. }
            | Self::FloorMagic { .. }
            | Self::FloorVersion { .. }
            | Self::FloorField { .. }
            | Self::FloorChecksum { .. }
            | Self::FloorExhausted { .. }
            | Self::FloorPublish { .. }
            | Self::WitnessInvalid { .. }
            | Self::WitnessPublish { .. }
            | Self::HistoryRead { .. }
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
    /// Inner-store length at which whole-generation reclamation fires.
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

#[derive(Debug)]
struct DurableHandleAllocator {
    data_dir: PathBuf,
    next: AtomicU64,
    end: AtomicU64,
    refill: Mutex<()>,
}

impl DurableHandleAllocator {
    fn open(data_dir: &Path) -> Result<Self> {
        let (next, end) = reserve_handle_range(data_dir, None)?;
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            next: AtomicU64::new(next),
            end: AtomicU64::new(end),
            refill: Mutex::new(()),
        })
    }

    fn allocate(&self) -> Result<ServerSessionHandle> {
        loop {
            let end = self.end.load(Ordering::Acquire);
            if let Ok(handle) =
                self.next
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
                        (next < end).then(|| next + 1)
                    })
            {
                return Ok(ServerSessionHandle(handle));
            }

            let _refill = self.refill.lock();
            if self.next.load(Ordering::Acquire) >= self.end.load(Ordering::Acquire) {
                let minimum_floor = self.end.load(Ordering::Acquire);
                let (next, end) = reserve_handle_range(&self.data_dir, Some(minimum_floor))?;
                self.next.store(next, Ordering::Release);
                self.end.store(end, Ordering::Release);
            }
        }
    }
}

fn reserve_handle_range(data_dir: &Path, minimum_floor: Option<u64>) -> Result<(u64, u64)> {
    let _lock = ExclusiveLock::acquire(data_dir.join(HANDLE_FLOOR_LOCK)).map_err(|source| {
        SessionStoreError::FloorLock {
            data_dir: data_dir.to_path_buf(),
            source,
        }
    })?;
    let floor_path = data_dir.join(HANDLE_FLOOR_FILE);
    let witness_path = data_dir.join(HANDLE_WITNESS_FILE);
    let floor = read_handle_record(&floor_path, HANDLE_FLOOR_MAGIC)?;
    let witness = read_handle_record(&witness_path, HANDLE_WITNESS_MAGIC).map_err(|source| {
        SessionStoreError::WitnessInvalid {
            path: witness_path.clone(),
            source: Box::new(source),
        }
    })?;
    let next = if let Some(floor) = floor {
        let required = witness.unwrap_or(0).max(minimum_floor.unwrap_or(0));
        if floor < required {
            return Err(SessionStoreError::FloorRegressed {
                path: floor_path,
                observed: floor,
                required,
            });
        }
        floor
    } else {
        if witness.is_some() || minimum_floor.is_some() {
            return Err(SessionStoreError::FloorMissing {
                path: floor_path,
                reason: "a prior reserved range",
            });
        }
        let manifest_path = StoreLayout::inspect(data_dir).manifest_path();
        match std::fs::metadata(&manifest_path) {
            Ok(_) => {
                return Err(SessionStoreError::FloorMissing {
                    path: floor_path,
                    reason: "a persisted instance manifest",
                });
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => 0,
            Err(source) => {
                return Err(SessionStoreError::HistoryRead {
                    path: manifest_path,
                    source,
                });
            }
        }
    };
    let end = next
        .checked_add(HANDLE_RESERVATION_SIZE)
        .ok_or(SessionStoreError::FloorExhausted { next })?;
    let floor_bytes = encode_handle_record(end, HANDLE_FLOOR_MAGIC);
    atomic_write(&floor_path, &floor_bytes).map_err(|source| SessionStoreError::FloorPublish {
        path: floor_path,
        source,
    })?;
    let witness_bytes = encode_handle_record(end, HANDLE_WITNESS_MAGIC);
    atomic_write(&witness_path, &witness_bytes).map_err(|source| {
        SessionStoreError::WitnessPublish {
            path: witness_path,
            source,
        }
    })?;
    Ok((next, end))
}

fn read_handle_record(path: &Path, magic: [u8; 8]) -> Result<Option<u64>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(SessionStoreError::FloorRead {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    if bytes.len() != HANDLE_FLOOR_BYTES {
        return Err(SessionStoreError::FloorLength {
            path: path.to_path_buf(),
            actual: bytes.len(),
            expected: HANDLE_FLOOR_BYTES,
        });
    }
    if bytes.get(..8) != Some(magic.as_slice()) {
        return Err(SessionStoreError::FloorMagic {
            path: path.to_path_buf(),
        });
    }
    let version_bytes: [u8; 2] = bytes
        .get(8..10)
        .and_then(|field| field.try_into().ok())
        .ok_or_else(|| SessionStoreError::FloorField {
            path: path.to_path_buf(),
            field: "version",
        })?;
    let version = u16::from_be_bytes(version_bytes);
    if version != HANDLE_FLOOR_VERSION {
        return Err(SessionStoreError::FloorVersion {
            path: path.to_path_buf(),
            actual: version,
            expected: HANDLE_FLOOR_VERSION,
        });
    }
    let prefix =
        bytes
            .get(..HANDLE_FLOOR_PREFIX_BYTES)
            .ok_or_else(|| SessionStoreError::FloorField {
                path: path.to_path_buf(),
                field: "checksum prefix",
            })?;
    let stored_checksum =
        bytes
            .get(HANDLE_FLOOR_PREFIX_BYTES..)
            .ok_or_else(|| SessionStoreError::FloorField {
                path: path.to_path_buf(),
                field: "checksum",
            })?;
    if Sha256::digest(prefix).as_slice() != stored_checksum {
        return Err(SessionStoreError::FloorChecksum {
            path: path.to_path_buf(),
        });
    }
    let floor_bytes: [u8; 8] = bytes
        .get(10..18)
        .and_then(|field| field.try_into().ok())
        .ok_or_else(|| SessionStoreError::FloorField {
            path: path.to_path_buf(),
            field: "floor",
        })?;
    Ok(Some(u64::from_be_bytes(floor_bytes)))
}

fn encode_handle_record(floor: u64, magic: [u8; 8]) -> [u8; HANDLE_FLOOR_BYTES] {
    let mut bytes = [0u8; HANDLE_FLOOR_BYTES];
    bytes[..8].copy_from_slice(&magic);
    bytes[8..10].copy_from_slice(&HANDLE_FLOOR_VERSION.to_be_bytes());
    bytes[10..18].copy_from_slice(&floor.to_be_bytes());
    let checksum = Sha256::digest(&bytes[..HANDLE_FLOOR_PREFIX_BYTES]);
    bytes[HANDLE_FLOOR_PREFIX_BYTES..].copy_from_slice(&checksum);
    bytes
}

/// Occupancy-bounded session store with optional restart-safe external handles.
///
/// Reclamation replaces a whole generation. A resolved request retains an `Arc` to its generation,
/// so an in-flight response can finish while every later request rejects its retired handle.
pub struct BoundedSessionStore {
    limits: SessionStoreLimits,
    current: RwLock<Generation>,
    durable_handles: Option<Arc<DurableHandleAllocator>>,
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
            durable_handles: None,
            evicted_total: AtomicU64::new(0),
            flushes_total: AtomicU64::new(0),
            observation_sequence: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Open an empty store whose external handles do not repeat while durable history survives.
    ///
    /// # Errors
    ///
    /// Returns a typed durability error when the floor cannot be locked, validated, advanced, or
    /// atomically published.
    pub fn open(data_dir: &Path) -> Result<Self> {
        Self::open_with_limits(data_dir, SessionStoreLimits::default())
    }

    /// Open a store with caller-selected limits and the same durable-history requirement.
    ///
    /// # Errors
    ///
    /// Returns a typed durability error when the floor cannot be locked, validated, advanced, or
    /// atomically published.
    pub fn open_with_limits(data_dir: &Path, limits: SessionStoreLimits) -> Result<Self> {
        Self::validate_registration_limits(limits)?;
        Ok(Self {
            limits,
            current: RwLock::new(Generation::fresh()),
            durable_handles: Some(Arc::new(DurableHandleAllocator::open(data_dir)?)),
            evicted_total: AtomicU64::new(0),
            flushes_total: AtomicU64::new(0),
            observation_sequence: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Build an empty generation retaining the same limits and durable allocator.
    #[must_use]
    pub fn empty_successor(&self) -> Self {
        Self {
            limits: self.limits,
            current: RwLock::new(Generation::fresh()),
            durable_handles: self.durable_handles.clone(),
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

    /// Register wire-delivered packing keys and derive the server-side representation.
    pub fn register_server_side(
        &self,
        keys: ClientPackingKeys,
        pack_params: &PackParams,
        context: &NttContext,
    ) -> Observed<ServerSessionHandle> {
        self.register_server_side_at(keys, pack_params, context, Instant::now())
    }

    /// Register wire-delivered packing keys against an explicit clock.
    pub fn register_server_side_at(
        &self,
        keys: ClientPackingKeys,
        pack_params: &PackParams,
        context: &NttContext,
        now: Instant,
    ) -> Observed<ServerSessionHandle> {
        if let Err(error) = Self::validate_registration_limits(self.limits) {
            return self.failed_observation(error);
        }
        let expires_at = match self.expiry_at(now) {
            Ok(expires_at) => expires_at,
            Err(error) => return self.failed_observation(error),
        };
        let mut generation = self.current.write();
        let mut observation = SessionObservation::default();
        let mut warnings = Vec::new();
        if Self::would_flush_after_sweep(&generation, now, self.limits.max_sessions) {
            let replacement = Arc::new(ServerSessionStore::new());
            let outcome = replacement
                .register_server_side(keys, pack_params, context)
                .map_err(|source| SessionStoreError::Inspire {
                    operation: "session register_server_side",
                    source: Box::new(source),
                })
                .and_then(|inner| {
                    let external = self
                        .durable_handles
                        .as_ref()
                        .map(|allocator| allocator.allocate())
                        .transpose()?;
                    self.make_room(&mut generation, now, &mut observation, &mut warnings);
                    generation.store = replacement;
                    let handle = external.unwrap_or(inner);
                    generation
                        .expiry
                        .insert(handle.0, SessionEntry { inner, expires_at });
                    Ok(handle)
                });
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
            let external = self
                .durable_handles
                .as_ref()
                .map(|allocator| allocator.allocate())
                .transpose()?;
            let inner = generation
                .store
                .register_server_side(keys, pack_params, context)
                .map_err(|source| SessionStoreError::Inspire {
                    operation: "session register_server_side",
                    source: Box::new(source),
                })?;
            let handle = external.unwrap_or(inner);
            generation
                .expiry
                .insert(handle.0, SessionEntry { inner, expires_at });
            Ok(handle)
        })();
        observation.counts = Some(generation.counts());
        self.finish_observation(&mut observation);
        Observed {
            outcome,
            observation,
            warnings,
        }
    }

    /// Register an in-process client and install the external handle it must send.
    pub fn register_client_session_at(
        &self,
        session: &mut ClientSession,
        now: Instant,
    ) -> Observed<Option<ServerSessionHandle>> {
        if let Err(error) = Self::validate_registration_limits(self.limits) {
            return self.failed_observation(error);
        }
        let expires_at = match self.expiry_at(now) {
            Ok(expires_at) => expires_at,
            Err(error) => return self.failed_observation(error),
        };
        let mut generation = self.current.write();
        let mut observation = SessionObservation::default();
        let mut warnings = Vec::new();
        if Self::would_flush_after_sweep(&generation, now, self.limits.max_sessions) {
            let outcome = (|| {
                let external = self
                    .durable_handles
                    .as_ref()
                    .map(|allocator| allocator.allocate())
                    .transpose()?;
                let replacement = Arc::new(ServerSessionStore::new());
                let inner = session
                    .register_with_server_derivation(replacement.as_ref())
                    .map_err(|source| SessionStoreError::Inspire {
                        operation: "session register",
                        source: Box::new(source),
                    })?;
                let binding = match (inner, external) {
                    (Some(inner), Some(external)) => {
                        session
                            .install_server_session_handle(external)
                            .map_err(|source| SessionStoreError::Inspire {
                                operation: "session handle install",
                                source: Box::new(source),
                            })?;
                        Some((external, inner))
                    }
                    (Some(inner), None) => Some((inner, inner)),
                    (None, Some(_) | None) => None,
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
            let external = self
                .durable_handles
                .as_ref()
                .map(|allocator| allocator.allocate())
                .transpose()?;
            let inner = session
                .register_with_server_derivation(generation.store.as_ref())
                .map_err(|source| SessionStoreError::Inspire {
                    operation: "session register",
                    source: Box::new(source),
                })?;
            let binding = match (inner, external) {
                (Some(inner), Some(external)) => {
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
                (Some(inner), None) => Some((inner, inner)),
                (None, Some(_) | None) => None,
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
            Some(_) => Err(SessionStoreError::HandleRejected {
                detail: format!(
                    "session handle {} expired (ttl {}s); re-run the session handshake",
                    handle.0,
                    self.limits.ttl.as_secs()
                ),
            }),
            None => Err(SessionStoreError::HandleRejected {
                detail: format!(
                    "session handle {} is not registered on this instance ({} serviceable, {} evicted since start); re-run the session handshake",
                    handle.0,
                    generation.expiry.len(),
                    self.evicted_total()
                ),
            }),
        }
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

    fn make_room(
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
        if generation.store.len() < self.limits.max_sessions {
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
    use raven_inspire::{setup, ClientSession, ServerSessionHandle};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

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

    fn real_registration_material() -> (
        ClientPackingKeys,
        PackParams,
        raven_inspire::math::NttContext,
    ) {
        let params = InspireParams::secure_128_d2048();
        let database = vec![0u8; params.ring_dim * 32];
        let mut sampler = GaussianSampler::with_seed(params.sigma, 117);
        let (crs, _encoded, secret_key) =
            setup(&params, &database, 32, &mut sampler).expect("setup");
        let pack_params = PackParams::try_new(&params, 16).expect("pack params");
        let keys = ClientPackingKeys::generate(
            &secret_key,
            &pack_params,
            crs.inspiring_w_seed,
            &mut sampler,
        );
        (keys, pack_params, params.ntt_context())
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
        let handle = generation.store.register(keys()).expect("register");
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
        let params = InspireParams::secure_128_d2048();
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
    fn refused_registration_at_capacity_preserves_the_live_session() {
        let (keys, pack_params, context) = real_registration_material();
        let store = store(1);
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
        let params = InspireParams::secure_128_d2048();
        let database = vec![0u8; params.ring_dim * 32];
        let mut sampler = GaussianSampler::with_seed(params.sigma, 119);
        let (crs, _encoded, secret_key) =
            setup(&params, &database, 32, &mut sampler).expect("setup");
        let mut client = ClientSession::new(crs, secret_key, &mut sampler).expect("client session");
        let directory = tempfile::tempdir().expect("temporary floor directory");
        let store = BoundedSessionStore::open_with_limits(
            directory.path(),
            SessionStoreLimits {
                max_sessions: 1,
                ttl: Duration::from_secs(3600),
            },
        )
        .expect("durable store");
        let now = Instant::now();
        let first = register(&store, now).0;
        let allocator = store.durable_handles.as_ref().expect("durable allocator");
        allocator.next.store(
            allocator.end.load(std::sync::atomic::Ordering::Acquire),
            std::sync::atomic::Ordering::Release,
        );
        std::fs::write(directory.path().join(super::HANDLE_FLOOR_FILE), b"bad")
            .expect("corrupt floor");

        let (outcome, observation, warnings) = store
            .register_client_session_at(&mut client, now)
            .into_parts();

        assert!(matches!(
            outcome,
            Err(super::SessionStoreError::FloorLength { .. })
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
    fn missing_floor_after_issue_refuses_restart_and_refill() {
        let directory = tempfile::tempdir().expect("temporary floor directory");
        let allocator = super::DurableHandleAllocator::open(directory.path()).expect("first open");
        assert_eq!(allocator.allocate().expect("first issue").0, 0);
        std::fs::remove_file(directory.path().join(super::HANDLE_FLOOR_FILE))
            .expect("remove floor only");

        let restart = super::DurableHandleAllocator::open(directory.path())
            .expect_err("lost floor must refuse restart");
        assert_eq!(restart.class(), super::SessionStoreErrorClass::Durability);

        for expected in 1..super::HANDLE_RESERVATION_SIZE {
            assert_eq!(allocator.allocate().expect("reserved issue").0, expected);
        }
        let refill = allocator
            .allocate()
            .expect_err("lost floor must refuse refill");
        assert_eq!(refill.class(), super::SessionStoreErrorClass::Durability);
    }

    #[test]
    fn deleting_both_files_during_a_live_allocator_cannot_rewind_refill() {
        let directory = tempfile::tempdir().expect("temporary floor directory");
        let allocator = super::DurableHandleAllocator::open(directory.path()).expect("first open");
        assert_eq!(allocator.allocate().expect("first issue").0, 0);
        std::fs::remove_file(directory.path().join(super::HANDLE_FLOOR_FILE))
            .expect("remove floor");
        std::fs::remove_file(directory.path().join("session-handle-issuance-v1.bin"))
            .expect("remove witness");
        for expected in 1..super::HANDLE_RESERVATION_SIZE {
            assert_eq!(allocator.allocate().expect("reserved issue").0, expected);
        }

        let error = allocator
            .allocate()
            .expect_err("live refill cannot restart at zero");
        assert_eq!(error.class(), super::SessionStoreErrorClass::Durability);
    }
}
