//! PIR server runtime: the scheme trait, instance lifecycle, atomic state-swap, and registry.

#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::panic,
        clippy::unwrap_used,
        clippy::similar_names
    )
)]
#![deny(missing_docs)]

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use raven_core::server_error::Result;
use raven_core::{Epoch, InstanceId, ServerError};
use serde::{de::DeserializeOwned, Serialize};

/// Contract every PIR scheme must satisfy.
///
/// ```
/// use raven_server::{InstanceRole, PirInstance, PirScheme};
/// use raven_core::server_error::Result;
/// use raven_core::{InstanceId, ServerError};
///
/// struct Echo;
/// impl PirScheme for Echo {
///     type ServerState = Vec<u8>;
///     type Query = usize;
///     type Response = u8;
///     fn respond(state: &Vec<u8>, q: &usize) -> Result<u8> {
///         state.get(*q).copied().ok_or_else(|| ServerError::InvalidQuery(format!("index {q} OOB")))
///     }
/// }
///
/// let inst: PirInstance<Echo> =
///     PirInstance::new(InstanceId::new("demo"), InstanceRole::Static, vec![10, 20, 30]);
/// let (_epoch, value) = inst.query(&1).expect("query");
/// assert_eq!(value, 20);
/// ```
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

/// Role of an engine instance - informs the orchestrator's re-preprocess schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceRole {
    /// Filled, immutable.
    Static,
    /// Currently filling. Re-preprocess on a schedule.
    Live,
    /// Sidecar mode for incremental schemes.
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
/// Route-affecting: routing layers MUST skip instances whose state is not
/// `Active`. Encoded `AtomicU8` (0=Active,1=Draining,2=Drained) for wait-free reads.
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
            return Err(ServerError::NoActiveInstance {
                instance_id: self.id.clone(),
            });
        }
        let snap = self.snapshot.load();
        let epoch = snap.epoch;
        let response = S::respond(&snap.state, q)?;
        Ok((epoch, response))
    }

    /// Like [`query`](Self::query) but increments the in-flight counter via [`InFlightGuard`].
    pub fn query_active_tracked(self: &Arc<Self>, q: &S::Query) -> Result<(Epoch, S::Response)> {
        let _guard =
            self.acquire_in_flight_guard()
                .ok_or_else(|| ServerError::NoActiveInstance {
                    instance_id: self.id.clone(),
                })?;
        let snap = self.snapshot.load();
        let epoch = snap.epoch;
        let response = S::respond(&snap.state, q)?;
        Ok((epoch, response))
    }

    /// Run a PIR query against a PRE-CAPTURED snapshot rather than the
    /// current `ArcSwap` cell. Returns `(snap.epoch, response)`.
    ///
    /// Lets a multi-row batch pin one `(epoch, state)` so a concurrent
    /// `swap_state` cannot straddle the batch and mix rows from two states.
    /// Drain-aware like [`query_active_tracked`](Self::query_active_tracked): refuses with
    /// [`ServerError::NoActiveInstance`] if not active at guard-acquire.
    pub fn query_active_tracked_with_snapshot(
        self: &Arc<Self>,
        snap: &Arc<Snapshot<S>>,
        q: &S::Query,
    ) -> Result<(Epoch, S::Response)> {
        let _guard =
            self.acquire_in_flight_guard()
                .ok_or_else(|| ServerError::NoActiveInstance {
                    instance_id: self.id.clone(),
                })?;
        let response = S::respond(&snap.state, q)?;
        Ok((snap.epoch, response))
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
    /// Returns [`ServerError::Internal`] if an instance with the same id is already registered.
    // by-value Arc signals ownership transfer of the registered instance
    #[allow(clippy::needless_pass_by_value)]
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
            return Err(ServerError::Internal(format!(
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
                .ok_or_else(|| ServerError::InvalidQuery(format!("index {query} OOB")))
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
        assert!(matches!(err, ServerError::Internal(_)));
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
        assert!(matches!(err, ServerError::Internal(_)));
        let dup = Arc::new(PirInstance::new(
            InstanceId::new("a"),
            InstanceRole::Static,
            vec![1, 2, 3],
        ));
        let err = engine.register_instance(dup).expect_err("dup id must fail");
        assert!(matches!(err, ServerError::Internal(_)));
    }

    #[test]
    fn engine_add_live_concurrent_does_not_lose_instances() {
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
    fn query_active_tracked_with_snapshot_pins_epoch_across_mid_batch_swap() {
        let inst: Arc<PirInstance<EchoScheme>> = Arc::new(PirInstance::new(
            InstanceId::new("batch"),
            InstanceRole::Live,
            vec![10, 20, 30, 40, 50],
        ));
        let snap = inst.current_snapshot();
        let snap_epoch = snap.epoch;

        let (e0, r0) = inst
            .query_active_tracked_with_snapshot(&snap, &0)
            .expect("row 0 must serve from captured snapshot");
        assert_eq!(e0, snap_epoch);
        assert_eq!(r0, 10);

        inst.swap_state(vec![99, 99, 99, 99, 99], Epoch(snap_epoch.0 + 1));
        assert_eq!(inst.current_epoch(), Epoch(snap_epoch.0 + 1));

        for idx in 1..5 {
            let (epoch, value) = inst
                .query_active_tracked_with_snapshot(&snap, &idx)
                .expect("row must serve from captured snapshot");
            assert_eq!(
                epoch, snap_epoch,
                "row {idx} epoch must equal captured snapshot epoch despite mid-batch swap"
            );
            let expected = 10u8 + (u8::try_from(idx).expect("< 256")) * 10;
            assert_eq!(
                value, expected,
                "row {idx} value must come from captured snapshot, not the swapped state"
            );
        }

        let (e_after, r_after) = inst.query_active_tracked(&0).expect("post-swap query");
        assert_eq!(e_after, Epoch(snap_epoch.0 + 1));
        assert_eq!(r_after, 99);
    }

    #[test]
    fn query_active_tracked_with_snapshot_refuses_when_drained() {
        let inst: Arc<PirInstance<EchoScheme>> = Arc::new(PirInstance::new(
            InstanceId::new("drain"),
            InstanceRole::Live,
            vec![7],
        ));
        let snap = inst.current_snapshot();
        inst.set_drain_state(DrainState::Drained);
        let err = inst
            .query_active_tracked_with_snapshot(&snap, &0)
            .expect_err("drained instance must refuse new queries");
        assert!(matches!(err, ServerError::NoActiveInstance { .. }));
    }
}
