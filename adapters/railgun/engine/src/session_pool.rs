//! Railgun metric facade over the bounded InsPIRe session mechanism.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use raven_inspire::inspiring::{ClientPackingKeys, PackParams};
use raven_inspire::math::NttContext;
use raven_inspire::{ClientSession, ServerSessionHandle, ServerSessionStore};
use raven_inspire_session::{
    Observed, SessionObservation, SessionStoreError, SessionStoreErrorClass, SessionWarning,
};
use raven_railgun_core::AdapterError;

use super::Result;

pub use raven_inspire_session::{SessionStoreLimits, DEFAULT_MAX_SESSIONS, DEFAULT_SESSION_TTL};

/// Occupancy-bounded InsPIRe sessions with Railgun's operator metrics.
///
/// State, durability, and handle binding live in `raven-inspire-session`. This facade maps its
/// typed errors into the adapter error contract and emits the existing `raven_railgun_*` series.
pub struct BoundedSessionStore {
    inner: raven_inspire_session::BoundedSessionStore,
    metric_sequence: Arc<Mutex<u64>>,
}

impl std::fmt::Debug for BoundedSessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundedSessionStore")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl Default for BoundedSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BoundedSessionStore {
    /// Build an empty in-memory store with default limits.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(SessionStoreLimits::default())
    }

    /// Build an empty in-memory store with caller-selected limits.
    #[must_use]
    pub fn with_limits(limits: SessionStoreLimits) -> Self {
        Self::from_inner(raven_inspire_session::BoundedSessionStore::with_limits(
            limits,
        ))
    }

    /// Open a restart-safe store with default limits.
    ///
    /// # Errors
    ///
    /// [`AdapterError::Internal`] when the durable floor cannot prove handle non-reuse.
    pub fn open(data_dir: &Path) -> Result<Self> {
        raven_inspire_session::BoundedSessionStore::open(data_dir)
            .map(Self::from_inner)
            .map_err(map_error)
    }

    /// Open a restart-safe store with caller-selected limits.
    ///
    /// # Errors
    ///
    /// [`AdapterError::Internal`] when the durable floor cannot prove handle non-reuse.
    pub fn open_with_limits(data_dir: &Path, limits: SessionStoreLimits) -> Result<Self> {
        raven_inspire_session::BoundedSessionStore::open_with_limits(data_dir, limits)
            .map(Self::from_inner)
            .map_err(map_error)
    }

    fn from_inner(inner: raven_inspire_session::BoundedSessionStore) -> Self {
        Self {
            inner,
            metric_sequence: Arc::new(Mutex::new(0)),
        }
    }

    pub(crate) fn empty_successor(&self) -> Self {
        Self {
            inner: self.inner.empty_successor(),
            metric_sequence: Arc::clone(&self.metric_sequence),
        }
    }

    /// Configured bounds.
    #[must_use]
    pub fn limits(&self) -> SessionStoreLimits {
        self.inner.limits()
    }

    /// Packing-key sets resident in the mechanism.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the mechanism holds no packing-key sets.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Handles currently present in the external-to-inner binding map.
    #[must_use]
    pub fn serviceable_len(&self) -> usize {
        self.inner.serviceable_len()
    }

    /// Packing-key sets removed by expiry, explicit removal, or flush.
    #[must_use]
    pub fn evicted_total(&self) -> u64 {
        self.inner.evicted_total()
    }

    /// Cap-triggered generation flushes.
    #[must_use]
    pub fn flushes_total(&self) -> u64 {
        self.inner.flushes_total()
    }

    /// Register wire-delivered packing keys, deriving the server-side representation.
    ///
    /// # Errors
    ///
    /// Returns an actionable adapter error when durability or InsPIRe rejects registration.
    pub fn register_server_side(
        &self,
        keys: ClientPackingKeys,
        pack_params: &PackParams,
        context: &NttContext,
    ) -> Result<ServerSessionHandle> {
        self.finish(self.inner.register_server_side(keys, pack_params, context))
    }

    /// Register wire-delivered packing keys against an explicit clock.
    ///
    /// # Errors
    ///
    /// Returns an actionable adapter error when durability or InsPIRe rejects registration.
    pub fn register_server_side_at(
        &self,
        keys: ClientPackingKeys,
        pack_params: &PackParams,
        context: &NttContext,
        now: Instant,
    ) -> Result<ServerSessionHandle> {
        self.finish(
            self.inner
                .register_server_side_at(keys, pack_params, context, now),
        )
    }

    /// Register an in-process client session and install its external handle.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::Scheme`] when InsPIRe rejects registration or installation.
    pub fn register_client_session_at(
        &self,
        session: &mut ClientSession,
        now: Instant,
    ) -> Result<Option<ServerSessionHandle>> {
        self.finish(self.inner.register_client_session_at(session, now))
    }

    /// Resolve an external handle into the generation and inner handle used by the responder.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::SessionHandleRejected`] for absent, removed, or expired handles.
    pub fn resolve(
        &self,
        handle: Option<ServerSessionHandle>,
        now: Instant,
    ) -> Result<(
        std::sync::Arc<ServerSessionStore>,
        Option<ServerSessionHandle>,
    )> {
        self.inner.resolve(handle, now).map_err(map_error)
    }

    /// Stop serving `handle` and free its packing keys.
    pub fn remove(&self, handle: ServerSessionHandle) -> bool {
        let (outcome, observation, warnings) = self.inner.remove(handle).into_parts();
        self.emit(observation, warnings);
        outcome.unwrap_or_else(|error| {
            tracing::error!(%error, handle = handle.0, "session key removal failed");
            false
        })
    }

    /// Drop every handle whose TTL elapsed at or before `now`.
    pub fn sweep_expired(&self, now: Instant) -> usize {
        let (outcome, observation, warnings) = self.inner.sweep_expired(now).into_parts();
        self.emit(observation, warnings);
        outcome.unwrap_or_else(|error| {
            tracing::error!(%error, "expired session sweep failed");
            0
        })
    }

    fn finish<T>(&self, observed: Observed<T>) -> Result<T> {
        let (outcome, observation, warnings) = observed.into_parts();
        self.emit(observation, warnings);
        outcome.map_err(map_error)
    }

    fn emit(&self, observation: SessionObservation, warnings: Vec<SessionWarning>) {
        for warning in warnings {
            tracing::error!(%warning, "session store recovered from an inner removal failure");
        }
        increment_evictions("removed", observation.evictions.removed);
        increment_evictions("expired", observation.evictions.expired);
        increment_evictions("flushed", observation.evictions.flushed);
        if observation.flushes > 0 {
            metrics::counter!("raven_railgun_session_store_flushes_total")
                .increment(observation.flushes);
            tracing::warn!(
                dropped = observation.evictions.flushed,
                max_sessions = self.limits().max_sessions,
                "session store hit its occupancy cap; flushed every registered session"
            );
        }
        let Some(counts) = observation.counts else {
            return;
        };
        let mut published = self.metric_sequence.lock();
        if observation.sequence <= *published {
            return;
        }
        #[allow(clippy::cast_precision_loss)]
        metrics::gauge!("raven_railgun_session_store_occupancy").set(counts.occupancy as f64);
        #[allow(clippy::cast_precision_loss)]
        metrics::gauge!("raven_railgun_session_store_serviceable").set(counts.serviceable as f64);
        *published = observation.sequence;
    }
}

fn increment_evictions(reason: &'static str, count: u64) {
    if count > 0 {
        metrics::counter!("raven_railgun_session_evictions_total", "reason" => reason)
            .increment(count);
    }
}

fn map_error(error: SessionStoreError) -> AdapterError {
    match error.class() {
        SessionStoreErrorClass::Durability | SessionStoreErrorClass::Configuration => {
            AdapterError::Internal(error.to_string())
        }
        SessionStoreErrorClass::Inspire => AdapterError::Scheme(error.to_string()),
        SessionStoreErrorClass::HandleRejected => AdapterError::SessionHandleRejected {
            detail: error
                .handle_rejection_detail()
                .map_or_else(|| error.to_string(), str::to_owned),
        },
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        map_error, AdapterError, BoundedSessionStore, SessionStoreError, SessionStoreLimits,
        DEFAULT_SESSION_TTL,
    };
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use raven_inspire::inspiring::{ClientPackingKeys, PackParams};
    use raven_inspire::math::GaussianSampler;
    use raven_inspire::params::InspireParams;
    use raven_inspire::setup;
    use raven_inspire_session::{SessionCounts, SessionEvictions, SessionObservation};
    use std::time::Instant;

    #[test]
    fn typed_handle_refusal_maps_without_parsing_display_text() {
        let error = SessionStoreError::HandleRejected {
            detail: "replace this session".to_owned(),
        };
        assert!(matches!(
            map_error(error),
            AdapterError::SessionHandleRejected { detail } if detail == "replace this session"
        ));
    }

    fn metric_value<'a>(
        snapshot: &'a [(
            metrics_util::CompositeKey,
            Option<metrics::Unit>,
            Option<metrics::SharedString>,
            DebugValue,
        )],
        name: &str,
        reason: Option<&str>,
    ) -> &'a DebugValue {
        snapshot
            .iter()
            .find_map(|(key, _unit, _description, value)| {
                let same_reason = reason.is_none_or(|expected| {
                    key.key()
                        .labels()
                        .any(|label| label.key() == "reason" && label.value() == expected)
                });
                (key.key().name() == name && same_reason).then_some(value)
            })
            .unwrap_or_else(|| panic!("missing metric {name} with reason {reason:?}"))
    }

    fn assert_gauge(value: &DebugValue, expected: f64) {
        match value {
            DebugValue::Gauge(actual) => {
                assert_eq!(actual.into_inner().to_bits(), expected.to_bits());
            }
            other => panic!("expected gauge {expected}, got {other:?}"),
        }
    }

    fn real_registration_material() -> (
        ClientPackingKeys,
        PackParams,
        raven_inspire::math::NttContext,
    ) {
        let params = InspireParams::secure_128_d2048();
        let database = vec![0u8; params.ring_dim * 32];
        let mut sampler = GaussianSampler::with_seed(params.sigma, 118);
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

    #[test]
    fn typed_observation_emits_each_existing_series_once() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let store = BoundedSessionStore::new();
        metrics::with_local_recorder(&recorder, || {
            store.emit(
                SessionObservation {
                    sequence: 1,
                    evictions: SessionEvictions {
                        removed: 2,
                        expired: 3,
                        flushed: 4,
                    },
                    flushes: 1,
                    counts: Some(SessionCounts {
                        occupancy: 5,
                        serviceable: 6,
                    }),
                },
                Vec::new(),
            );
        });
        let snapshot = snapshotter.snapshot().into_vec();
        assert_eq!(
            metric_value(
                &snapshot,
                "raven_railgun_session_evictions_total",
                Some("removed")
            ),
            &DebugValue::Counter(2)
        );
        assert_eq!(
            metric_value(
                &snapshot,
                "raven_railgun_session_evictions_total",
                Some("expired")
            ),
            &DebugValue::Counter(3)
        );
        assert_eq!(
            metric_value(
                &snapshot,
                "raven_railgun_session_evictions_total",
                Some("flushed")
            ),
            &DebugValue::Counter(4)
        );
        assert_eq!(
            metric_value(&snapshot, "raven_railgun_session_store_flushes_total", None),
            &DebugValue::Counter(1)
        );
        assert_gauge(
            metric_value(&snapshot, "raven_railgun_session_store_occupancy", None),
            5.0,
        );
        assert_gauge(
            metric_value(&snapshot, "raven_railgun_session_store_serviceable", None),
            6.0,
        );
    }

    #[test]
    fn late_observation_keeps_its_counter_delta_without_overwriting_newer_gauges() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let store = BoundedSessionStore::new();
        metrics::with_local_recorder(&recorder, || {
            store.emit(
                SessionObservation {
                    sequence: 2,
                    evictions: SessionEvictions {
                        expired: 2,
                        ..SessionEvictions::default()
                    },
                    flushes: 0,
                    counts: Some(SessionCounts {
                        occupancy: 2,
                        serviceable: 2,
                    }),
                },
                Vec::new(),
            );
            store.emit(
                SessionObservation {
                    sequence: 1,
                    evictions: SessionEvictions {
                        removed: 3,
                        ..SessionEvictions::default()
                    },
                    flushes: 0,
                    counts: Some(SessionCounts {
                        occupancy: 9,
                        serviceable: 9,
                    }),
                },
                Vec::new(),
            );
        });
        let snapshot = snapshotter.snapshot().into_vec();
        assert_eq!(
            metric_value(
                &snapshot,
                "raven_railgun_session_evictions_total",
                Some("expired")
            ),
            &DebugValue::Counter(2)
        );
        assert_eq!(
            metric_value(
                &snapshot,
                "raven_railgun_session_evictions_total",
                Some("removed")
            ),
            &DebugValue::Counter(3)
        );
        assert_gauge(
            metric_value(&snapshot, "raven_railgun_session_store_occupancy", None),
            2.0,
        );
        assert_gauge(
            metric_value(&snapshot, "raven_railgun_session_store_serviceable", None),
            2.0,
        );
    }

    #[test]
    fn successor_shares_the_gauge_publication_cursor() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let store = BoundedSessionStore::new();
        let successor = store.empty_successor();
        metrics::with_local_recorder(&recorder, || {
            successor.emit(
                SessionObservation {
                    sequence: 2,
                    counts: Some(SessionCounts {
                        occupancy: 2,
                        serviceable: 2,
                    }),
                    ..SessionObservation::default()
                },
                Vec::new(),
            );
            store.emit(
                SessionObservation {
                    sequence: 1,
                    counts: Some(SessionCounts {
                        occupancy: 9,
                        serviceable: 9,
                    }),
                    ..SessionObservation::default()
                },
                Vec::new(),
            );
        });
        let snapshot = snapshotter.snapshot().into_vec();
        assert_gauge(
            metric_value(&snapshot, "raven_railgun_session_store_occupancy", None),
            2.0,
        );
        assert_gauge(
            metric_value(&snapshot, "raven_railgun_session_store_serviceable", None),
            2.0,
        );
    }

    #[test]
    fn missing_remove_publishes_zero_counts_without_an_eviction() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let store = BoundedSessionStore::new();
        metrics::with_local_recorder(&recorder, || {
            assert!(!store.remove(raven_inspire::ServerSessionHandle(77)));
        });
        let snapshot = snapshotter.snapshot().into_vec();
        assert_gauge(
            metric_value(&snapshot, "raven_railgun_session_store_occupancy", None),
            0.0,
        );
        assert_gauge(
            metric_value(&snapshot, "raven_railgun_session_store_serviceable", None),
            0.0,
        );
        assert!(snapshot
            .iter()
            .all(|(key, _, _, _)| { key.key().name() != "raven_railgun_session_evictions_total" }));
    }

    #[test]
    fn failed_registration_at_capacity_preserves_live_gauges_without_flush() {
        let (keys, pack_params, context) = real_registration_material();
        let store = BoundedSessionStore::with_limits(SessionStoreLimits {
            max_sessions: 1,
            ttl: DEFAULT_SESSION_TTL,
        });
        let first = store
            .register_server_side_at(keys.clone(), &pack_params, &context, Instant::now())
            .expect("first registration");
        let mut invalid = keys;
        invalid.y_body.pop();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        metrics::with_local_recorder(&recorder, || {
            assert!(store
                .register_server_side_at(invalid, &pack_params, &context, Instant::now())
                .is_err());
        });

        let snapshot = snapshotter.snapshot().into_vec();
        assert!(snapshot.iter().all(|(key, _, _, _)| {
            !matches!(
                key.key().name(),
                "raven_railgun_session_store_flushes_total"
                    | "raven_railgun_session_evictions_total"
            )
        }));
        assert_gauge(
            metric_value(&snapshot, "raven_railgun_session_store_occupancy", None),
            1.0,
        );
        assert_gauge(
            metric_value(&snapshot, "raven_railgun_session_store_serviceable", None),
            1.0,
        );
        assert!(store.resolve(Some(first), Instant::now()).is_ok());
    }
}
