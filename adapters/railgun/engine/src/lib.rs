//! PIR engine: scheme trait, instance registry, snapshot pattern, and the inspire adapter.

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]
#![deny(missing_docs)]

pub mod imt;
pub mod inspire;
pub mod layer_two;
pub mod offline_packing_keys_cache;
pub mod orchestrator;
pub mod persistence;
pub mod pir_table;
pub mod tree_fill_watcher;

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use raven_railgun_core::{AdapterError, Epoch, InstanceId, Result};
use serde::{de::DeserializeOwned, Serialize};

/// Contract every PIR scheme must satisfy.
pub trait PirScheme: Send + Sync + 'static {
    /// Server-side preprocessed state (CRS, encoded DB, caches, etc.).
    type ServerState: Send + Sync + 'static;

    /// Wire query type. Must round-trip through bincode.
    type Query: Serialize + DeserializeOwned + Send + Sync;

    /// Wire response type. Must round-trip through bincode.
    type Response: Serialize + DeserializeOwned + Send + Sync;

    /// Server compute. Pure function of state and query.
    fn respond(state: &Self::ServerState, query: &Self::Query) -> Result<Self::Response>;
}

/// Role of an engine instance — informs the orchestrator's re-preprocess schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceRole {
    /// Filled, immutable.
    Static,
    /// Currently filling. Re-preprocess on a schedule.
    Live,
    /// Sidecar mode for incremental schemes. Reserved for V2.
    Sidecar,
}

impl InstanceRole {
    /// Stable lowercase label for HTTP serialization.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Live => "live",
            Self::Sidecar => "sidecar",
        }
    }
}

/// Operator-driven maintenance state of an engine instance.
///
/// Distinct from [`InstanceRole`]: drain_state is operator-driven and route-affecting —
/// routing layers MUST skip instances whose drain_state is not `Active`.
/// Encoded as `AtomicU8` (0=Active, 1=Draining, 2=Drained) for wait-free routing reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrainState {
    /// Routing layers MUST consider this instance for new queries.
    Active,
    /// Operator-initiated maintenance. Routing layers MUST refuse new queries.
    Draining,
    /// In-flight count has reached zero. Routing layers MUST refuse queries.
    Drained,
}

impl DrainState {
    /// Stable lowercase label for HTTP serialization.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Drained => "drained",
        }
    }

    /// Returns `true` if this state accepts new queries.
    #[must_use]
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    fn from_u8(raw: u8) -> Self {
        match raw {
            0 => Self::Active,
            1 => Self::Draining,
            _ => Self::Drained,
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::Active => 0,
            Self::Draining => 1,
            Self::Drained => 2,
        }
    }
}

/// One PIR instance holding a scheme + DB + snapshot pointer.
///
/// `(epoch, state)` are packed into a single [`Snapshot`] cell and loaded atomically.
pub struct PirInstance<S: PirScheme> {
    /// Operator-assigned identifier. Immutable.
    pub id: InstanceId,
    role: parking_lot::RwLock<InstanceRole>,
    drain_state: AtomicU8,
    in_flight: AtomicU64,
    snapshot: ArcSwap<Snapshot<S>>,
}

/// Atomic `(epoch, state)` pair. Both fields move together on `swap_state`.
pub struct Snapshot<S: PirScheme> {
    /// Epoch counter. Bumps on every `swap_state`.
    pub epoch: Epoch,
    /// Server state.
    pub state: Arc<S::ServerState>,
}

impl<S: PirScheme> std::fmt::Debug for Snapshot<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshot")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl<S: PirScheme> std::fmt::Debug for PirInstance<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PirInstance")
            .field("id", &self.id)
            .field("role", &self.role())
            .field("epoch", &self.current_epoch())
            .finish_non_exhaustive()
    }
}

impl<S: PirScheme> PirInstance<S> {
    /// Construct a fresh instance at epoch 0.
    pub fn new(id: InstanceId, role: InstanceRole, state: S::ServerState) -> Self {
        Self {
            id,
            role: parking_lot::RwLock::new(role),
            drain_state: AtomicU8::new(DrainState::Active.as_u8()),
            in_flight: AtomicU64::new(0),
            snapshot: ArcSwap::from_pointee(Snapshot {
                epoch: Epoch::ZERO,
                state: Arc::new(state),
            }),
        }
    }

    /// Current epoch.
    pub fn current_epoch(&self) -> Epoch {
        self.snapshot.load().epoch
    }

    /// Current instance role.
    #[must_use]
    pub fn role(&self) -> InstanceRole {
        *self.role.read()
    }

    /// Atomically update the instance role. Does NOT affect query routing.
    pub fn set_role(&self, new_role: InstanceRole) {
        *self.role.write() = new_role;
    }

    /// Current operator-driven [`DrainState`].
    #[must_use]
    pub fn drain_state(&self) -> DrainState {
        DrainState::from_u8(self.drain_state.load(Ordering::Acquire))
    }

    /// Atomically transition the [`DrainState`].
    pub fn set_drain_state(&self, new: DrainState) {
        let prev = self.drain_state.swap(new.as_u8(), Ordering::AcqRel);
        let prev = DrainState::from_u8(prev);
        if prev != new {
            tracing::info!(
                instance_id = %self.id,
                from = prev.label(),
                to = new.label(),
                in_flight = self.in_flight_count(),
                "drain_state transition"
            );
        }
    }

    /// Current in-flight query count.
    #[must_use]
    pub fn in_flight_count(&self) -> u64 {
        self.in_flight.load(Ordering::Acquire)
    }

    /// Acquire an [`InFlightGuard`]. Returns `None` when not [`DrainState::Active`].
    #[must_use]
    pub fn acquire_in_flight_guard(self: &Arc<Self>) -> Option<InFlightGuard<S>> {
        if self.drain_state() != DrainState::Active {
            return None;
        }
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        Some(InFlightGuard {
            instance: Arc::clone(self),
        })
    }

    /// Current server state.
    pub fn current_state(&self) -> Arc<S::ServerState> {
        Arc::clone(&self.snapshot.load().state)
    }

    /// Load the current `(epoch, state)` pair atomically.
    pub fn current_snapshot(&self) -> Arc<Snapshot<S>> {
        self.snapshot.load_full()
    }

    /// Run a PIR query. Returns `(epoch, response)`.
    pub fn query(&self, q: &S::Query) -> Result<(Epoch, S::Response)> {
        if !self.drain_state().is_active() {
            return Err(AdapterError::NoActiveInstance {
                instance_id: self.id.clone(),
            });
        }
        let snap = self.snapshot.load();
        let epoch = snap.epoch;
        let response = S::respond(&snap.state, q)?;
        Ok((epoch, response))
    }

    /// Like [`query`] but increments the in-flight counter via [`InFlightGuard`].
    pub fn query_active_tracked(self: &Arc<Self>, q: &S::Query) -> Result<(Epoch, S::Response)> {
        let _guard =
            self.acquire_in_flight_guard()
                .ok_or_else(|| AdapterError::NoActiveInstance {
                    instance_id: self.id.clone(),
                })?;
        let snap = self.snapshot.load();
        let epoch = snap.epoch;
        let response = S::respond(&snap.state, q)?;
        Ok((epoch, response))
    }

    /// Swap in a new server state and bump the epoch.
    pub fn swap_state(&self, new_state: S::ServerState, new_epoch: Epoch) {
        self.snapshot.store(Arc::new(Snapshot {
            epoch: new_epoch,
            state: Arc::new(new_state),
        }));
    }
}

/// RAII guard that decrements the per-instance in-flight counter on drop.
pub struct InFlightGuard<S: PirScheme> {
    instance: Arc<PirInstance<S>>,
}

impl<S: PirScheme> std::fmt::Debug for InFlightGuard<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InFlightGuard")
            .field("instance_id", &self.instance.id)
            .finish()
    }
}

impl<S: PirScheme> Drop for InFlightGuard<S> {
    fn drop(&mut self) {
        self.instance.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Registry of [`PirInstance<S>`] keyed by [`InstanceId`].
pub struct Engine<S: PirScheme> {
    instances: arc_swap::ArcSwap<Vec<Arc<PirInstance<S>>>>,
}

impl<S: PirScheme> std::fmt::Debug for Engine<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("instance_count", &self.instances.load().len())
            .finish()
    }
}

impl<S: PirScheme> Default for Engine<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: PirScheme> Engine<S> {
    /// Build an empty engine.
    pub fn new() -> Self {
        Self {
            instances: arc_swap::ArcSwap::from_pointee(Vec::new()),
        }
    }

    /// Register an owned instance. Refuses duplicates.
    pub fn add_instance(&mut self, instance: PirInstance<S>) -> Result<()> {
        self.register_instance(Arc::new(instance))
    }

    /// Register a shared instance. Refuses duplicates.
    pub fn register_instance(&mut self, instance: Arc<PirInstance<S>>) -> Result<()> {
        self.add_live(instance)
    }

    /// Live-register a shared instance through `&self`. Uses `ArcSwap::rcu` to avoid lost-updates.
    ///
    /// # Errors
    /// Returns [`AdapterError::Internal`] if an instance with the same id is already registered.
    pub fn add_live(&self, instance: Arc<PirInstance<S>>) -> Result<()> {
        let target_id = instance.id.clone();
        let prev = self.instances.rcu(|cur| {
            if cur.iter().any(|i| i.id == target_id) {
                Arc::clone(cur)
            } else {
                let mut next: Vec<Arc<PirInstance<S>>> = (**cur).clone();
                next.push(Arc::clone(&instance));
                Arc::new(next)
            }
        });
        if prev.iter().any(|i| i.id == target_id) {
            return Err(AdapterError::Internal(format!(
                "duplicate instance id: {target_id}"
            )));
        }
        Ok(())
    }

    /// Look up an instance by id.
    pub fn instance(&self, id: &InstanceId) -> Option<Arc<PirInstance<S>>> {
        self.instances
            .load()
            .iter()
            .find(|i| &i.id == id)
            .map(Arc::clone)
    }

    /// Look up an active (non-draining) instance by id.
    pub fn active_instance(&self, id: &InstanceId) -> Option<Arc<PirInstance<S>>> {
        self.instance(id)
            .filter(|inst| inst.drain_state() == DrainState::Active)
    }

    /// All registered instances.
    pub fn instances(&self) -> Vec<Arc<PirInstance<S>>> {
        self.instances.load().iter().map(Arc::clone).collect()
    }

    /// All active (non-draining) instances.
    pub fn active_instances(&self) -> Vec<Arc<PirInstance<S>>> {
        self.instances
            .load()
            .iter()
            .filter(|i| i.drain_state() == DrainState::Active)
            .map(Arc::clone)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_railgun_core::InstanceId;

    #[derive(Debug)]
    struct EchoScheme;

    impl PirScheme for EchoScheme {
        type ServerState = Vec<u8>;
        type Query = usize;
        type Response = u8;

        fn respond(state: &Self::ServerState, query: &Self::Query) -> Result<Self::Response> {
            state
                .get(*query)
                .copied()
                .ok_or_else(|| AdapterError::InvalidQuery(format!("index {query} OOB")))
        }
    }

    #[test]
    fn instance_query_returns_current_epoch_and_response() {
        let inst: PirInstance<EchoScheme> = PirInstance::new(
            InstanceId::new("toy"),
            InstanceRole::Static,
            vec![10, 20, 30],
        );
        assert_eq!(inst.current_epoch(), Epoch::ZERO);
        let (epoch, value) = inst.query(&1).expect("query");
        assert_eq!(epoch, Epoch::ZERO);
        assert_eq!(value, 20);
    }

    #[test]
    fn swap_state_bumps_epoch_and_visible_immediately() {
        let inst: PirInstance<EchoScheme> =
            PirInstance::new(InstanceId::new("toy"), InstanceRole::Live, vec![10, 20, 30]);
        inst.swap_state(vec![1, 2, 3], Epoch(1));
        let (epoch, value) = inst.query(&0).expect("query");
        assert_eq!(epoch, Epoch(1));
        assert_eq!(value, 1);
    }

    #[test]
    fn engine_rejects_duplicate_instance_id() {
        let mut engine: Engine<EchoScheme> = Engine::new();
        engine
            .add_instance(PirInstance::new(
                InstanceId::new("a"),
                InstanceRole::Static,
                vec![],
            ))
            .expect("first add");
        let err = engine
            .add_instance(PirInstance::new(
                InstanceId::new("a"),
                InstanceRole::Static,
                vec![],
            ))
            .expect_err("second add should fail");
        assert!(matches!(err, AdapterError::Internal(_)));
    }

    #[test]
    fn engine_register_instance_arc_path_rejects_duplicates() {
        let mut engine: Engine<EchoScheme> = Engine::new();
        let instance_a = Arc::new(PirInstance::new(
            InstanceId::new("a"),
            InstanceRole::Static,
            vec![],
        ));
        engine
            .register_instance(Arc::clone(&instance_a))
            .expect("first register");
        let err = engine
            .register_instance(Arc::clone(&instance_a))
            .expect_err("re-register same arc must fail");
        assert!(matches!(err, AdapterError::Internal(_)));
        let dup = Arc::new(PirInstance::new(
            InstanceId::new("a"),
            InstanceRole::Static,
            vec![1, 2, 3],
        ));
        let err = engine.register_instance(dup).expect_err("dup id must fail");
        assert!(matches!(err, AdapterError::Internal(_)));
    }

    /// Regression (C12): `add_live` without `rcu` could lose instances
    /// under concurrent calls; the fix uses `ArcSwap::rcu` to retry.
    #[test]
    fn engine_add_live_concurrent_does_not_lose_instances() {
        use std::sync::Arc;
        use std::sync::Barrier;
        use std::thread;

        for trial in 0..32 {
            let engine: Arc<Engine<EchoScheme>> = Arc::new(Engine::new());
            let barrier = Arc::new(Barrier::new(2));

            let inst_a = Arc::new(PirInstance::new(
                InstanceId::new(format!("a-{trial}")),
                InstanceRole::Static,
                vec![1u8],
            ));
            let inst_b = Arc::new(PirInstance::new(
                InstanceId::new(format!("b-{trial}")),
                InstanceRole::Static,
                vec![2u8],
            ));

            let engine_a = Arc::clone(&engine);
            let inst_a_clone = Arc::clone(&inst_a);
            let bar_a = Arc::clone(&barrier);
            let h_a = thread::spawn(move || {
                bar_a.wait();
                engine_a
                    .add_live(inst_a_clone)
                    .expect("thread A add_live must succeed");
            });

            let engine_b = Arc::clone(&engine);
            let inst_b_clone = Arc::clone(&inst_b);
            let bar_b = Arc::clone(&barrier);
            let h_b = thread::spawn(move || {
                bar_b.wait();
                engine_b
                    .add_live(inst_b_clone)
                    .expect("thread B add_live must succeed");
            });

            h_a.join().expect("thread A join");
            h_b.join().expect("thread B join");

            let snapshot = engine.instances();
            assert_eq!(
                snapshot.len(),
                2,
                "trial {trial}: both instances must survive concurrent add_live"
            );
            let ids: Vec<String> = snapshot.iter().map(|i| i.id.to_string()).collect();
            assert!(
                ids.iter().any(|id| id == &format!("a-{trial}")),
                "trial {trial}: instance a must be present, got {ids:?}"
            );
            assert!(
                ids.iter().any(|id| id == &format!("b-{trial}")),
                "trial {trial}: instance b must be present, got {ids:?}"
            );
        }
    }

    #[test]
    fn engine_lookup_finds_existing_instance() {
        let mut engine: Engine<EchoScheme> = Engine::new();
        engine
            .add_instance(PirInstance::new(
                InstanceId::new("a"),
                InstanceRole::Static,
                vec![1],
            ))
            .expect("add");
        assert!(engine.instance(&InstanceId::new("a")).is_some());
        assert!(engine.instance(&InstanceId::new("b")).is_none());
    }

    #[test]
    fn pad_record_round_trips() {
        let payload = b"\x01\x02\x03\x04";
        let padded = inspire::pad_record(payload).expect("pad");
        assert_eq!(padded.len(), inspire::MIN_SAFE_RECORD_BYTES);
        assert_eq!(padded.get(..4), Some(payload.as_slice()));
        assert!(padded.iter().skip(4).all(|b| *b == 0));
        let recovered = inspire::unpad_record(&padded, 4).expect("unpad");
        assert_eq!(recovered, payload);
    }

    #[test]
    fn pad_record_rejects_oversized_payload() {
        let oversized = vec![0u8; inspire::MIN_SAFE_RECORD_BYTES + 1];
        assert!(inspire::pad_record(&oversized).is_none());
    }

    #[test]
    fn unpad_record_rejects_wrong_length() {
        let wrong_size = vec![0u8; inspire::MIN_SAFE_RECORD_BYTES - 1];
        assert!(inspire::unpad_record(&wrong_size, 4).is_none());
    }

    #[test]
    fn snapshot_then_restore_recovers_byte_identical_query_response() {
        use raven_inspire::params::{InspireParams, InspireVariant};
        use raven_railgun_persistence::{Snapshot, SnapshotId, StoreLayout};

        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");

        let params = InspireParams::secure_128_d2048();
        let entries = 256usize;
        let entry_size = 256usize;
        let db: Vec<u8> = (0..entries)
            .flat_map(|i| (0..entry_size).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
            .collect();
        let (state_a, sk) =
            inspire::setup_state(&params, &db, entry_size, InspireVariant::TwoPacking)
                .expect("setup state");

        let bytes = inspire::snapshot_inspire_state(&state_a).expect("serialize");
        let snap = Snapshot::build(bytes);
        snap.save(&layout, SnapshotId(1)).expect("save");

        let snap_loaded = Snapshot::load(&layout, SnapshotId(1)).expect("load");
        let state_b = inspire::restore_inspire_state(&snap_loaded.data).expect("restore");

        let mut client_session_a =
            inspire::build_client_session((*state_a.crs).clone(), sk.clone(), &params)
                .expect("client session a");
        inspire::register_client_session(&mut client_session_a, &state_a).expect("register a");
        let target = 42u64;
        let (cs, q) =
            inspire::build_seeded_query(&client_session_a, state_a.shard_config(), target, &params)
                .expect("query a");

        let resp_a =
            <inspire::RavenInspireScheme as PirScheme>::respond(&state_a, &q).expect("respond a");

        let mut client_session_b =
            inspire::build_client_session((*state_b.crs).clone(), sk.clone(), &params)
                .expect("client session b");
        inspire::register_client_session(&mut client_session_b, &state_b).expect("register b");
        let (cs_b, q_b) =
            inspire::build_seeded_query(&client_session_b, state_b.shard_config(), target, &params)
                .expect("query b");
        let resp_b =
            <inspire::RavenInspireScheme as PirScheme>::respond(&state_b, &q_b).expect("respond b");

        let plaintext_a =
            inspire::extract_response(&state_a.crs, &cs, &resp_a, entry_size).expect("extract a");
        let plaintext_b =
            inspire::extract_response(&state_b.crs, &cs_b, &resp_b, entry_size).expect("extract b");
        assert_eq!(
            plaintext_a, plaintext_b,
            "snapshot+restore must preserve query semantics"
        );
        let target_idx = usize::try_from(target).expect("fits");
        let expected = db
            .get(target_idx * entry_size..(target_idx + 1) * entry_size)
            .expect("planted slice");
        assert_eq!(
            plaintext_a.get(..entry_size),
            Some(expected),
            "byte-equality with planted DB"
        );
    }
}
