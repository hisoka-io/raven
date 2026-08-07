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

/// The cell geometry a client's query is bound to.
///
/// A client decomposes its index against these two numbers, so a state may only
/// replace another when they agree. Corpus growth is legal and deliberately not
/// represented here: new indices become valid, old ones still map the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateShape {
    /// Bytes per record.
    pub entry_size_bytes: usize,
    /// Rows per shard.
    pub rows_per_shard: u64,
}

/// Contract every PIR scheme must satisfy.
///
/// ```
/// use raven_core::server_error::Result;
/// use raven_core::{InstanceId, ServerError};
/// use raven_server::{InstanceRole, PirInstance, PirScheme, StateShape};
/// struct Echo;
/// impl PirScheme for Echo {
///     type ServerState = Vec<u8>;
///     type Query = usize;
///     type Response = u8;
///     fn respond(state: &Vec<u8>, q: &usize) -> Result<u8> {
///         state.get(*q).copied().ok_or_else(|| ServerError::InvalidQuery(format!("index {q} OOB")))
///     }
///     fn state_shape(_state: &Vec<u8>) -> StateShape {
///         StateShape { entry_size_bytes: 1, rows_per_shard: u64::MAX }
///     }
/// }
/// let inst = PirInstance::<Echo>::new(
///     InstanceId::new("demo"), InstanceRole::Static, vec![10, 20, 30]);
/// assert_eq!(inst.query(&1).expect("query").1, 20);
/// ```
pub trait PirScheme: Send + Sync + 'static {
    /// Preprocessed server state - CRS, encoded DB, caches.
    type ServerState: Send + Sync + 'static;

    /// Must round-trip through bincode.
    type Query: Serialize + DeserializeOwned + Send + Sync;

    /// Must round-trip through bincode.
    type Response: Serialize + DeserializeOwned + Send + Sync;

    /// Must be a pure function of `state` and `query`.
    fn respond(state: &Self::ServerState, query: &Self::Query) -> Result<Self::Response>;

    /// Cell geometry of `state`, checked on every [`PirInstance::swap_state`].
    ///
    /// Required rather than defaulted: a scheme that cannot answer this cannot
    /// be gated, and an ungated swap returns wrong bytes with no error.
    fn state_shape(state: &Self::ServerState) -> StateShape;
}

/// Informs the orchestrator's re-preprocess schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceRole {
    /// Filled and immutable.
    Static,
    /// Still filling; re-preprocessed on a schedule.
    Live,
    /// Sidecar for incremental schemes.
    Sidecar,
}

impl InstanceRole {
    /// Stable wire label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Live => "live",
            Self::Sidecar => "sidecar",
        }
    }
}

/// Operator-driven maintenance state. Routing layers MUST refuse new queries
/// for anything but `Active`. Stored as `AtomicU8` for wait-free reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrainState {
    /// Serving.
    Active,
    /// Operator-initiated maintenance; in-flight queries still running.
    Draining,
    /// Drain complete: in-flight count reached zero.
    Drained,
}

impl DrainState {
    /// Stable wire label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Drained => "drained",
        }
    }

    /// Whether new queries are accepted.
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

/// One PIR instance. `(epoch, state)` share a single [`Snapshot`] cell so
/// readers never observe a half-applied swap.
pub struct PirInstance<S: PirScheme> {
    /// Immutable after construction.
    pub id: InstanceId,
    role: parking_lot::RwLock<InstanceRole>,
    drain_state: AtomicU8,
    in_flight: AtomicU64,
    snapshot: ArcSwap<Snapshot<S>>,
}

/// Both fields move together on every `swap_state`.
pub struct Snapshot<S: PirScheme> {
    /// Bumped on each swap.
    pub epoch: Epoch,
    /// State this epoch describes.
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
    /// Starts at [`Epoch::ZERO`] and [`DrainState::Active`].
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

    /// Epoch of the currently-published snapshot.
    pub fn current_epoch(&self) -> Epoch {
        self.snapshot.load().epoch
    }

    /// Current role.
    #[must_use]
    pub fn role(&self) -> InstanceRole {
        *self.role.read()
    }

    /// Does not affect query routing.
    pub fn set_role(&self, new_role: InstanceRole) {
        *self.role.write() = new_role;
    }

    /// Current drain state.
    #[must_use]
    pub fn drain_state(&self) -> DrainState {
        DrainState::from_u8(self.drain_state.load(Ordering::Acquire))
    }

    /// Transition the drain state, logging any change.
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

    /// Queries currently executing under a guard.
    #[must_use]
    pub fn in_flight_count(&self) -> u64 {
        self.in_flight.load(Ordering::Acquire)
    }

    /// `None` unless [`DrainState::Active`].
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

    /// State of the currently-published snapshot.
    pub fn current_state(&self) -> Arc<S::ServerState> {
        Arc::clone(&self.snapshot.load().state)
    }

    /// The published `(epoch, state)` pair, loaded atomically.
    pub fn current_snapshot(&self) -> Arc<Snapshot<S>> {
        self.snapshot.load_full()
    }

    /// Untracked query; refuses unless active.
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

    /// As [`query`](Self::query), but counted in `in_flight`.
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

    /// Serves from a pre-captured snapshot so a multi-row batch cannot
    /// straddle a concurrent `swap_state` and mix rows from two states.
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

    /// Publish a new state at `new_epoch`, rejecting a change of cell geometry.
    ///
    /// # Errors
    /// [`ServerError::StateShapeMismatch`] when the incoming state would move
    /// live clients onto a geometry their queries were not built against.
    pub fn swap_state(&self, new_state: S::ServerState, new_epoch: Epoch) -> Result<()> {
        let live = S::state_shape(&self.snapshot.load().state);
        let incoming = S::state_shape(&new_state);
        if live != incoming {
            return Err(ServerError::StateShapeMismatch {
                live_entry_size: live.entry_size_bytes,
                live_rows: live.rows_per_shard,
                new_entry_size: incoming.entry_size_bytes,
                new_rows: incoming.rows_per_shard,
            });
        }
        self.snapshot.store(Arc::new(Snapshot {
            epoch: new_epoch,
            state: Arc::new(new_state),
        }));
        Ok(())
    }
}

/// Decrements the instance's in-flight counter on drop.
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

/// Instance registry, looked up by [`InstanceId`].
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
    /// Empty registry.
    pub fn new() -> Self {
        Self {
            instances: arc_swap::ArcSwap::from_pointee(Vec::new()),
        }
    }

    /// Refuses a duplicate id.
    pub fn add_instance(&mut self, instance: PirInstance<S>) -> Result<()> {
        self.register_instance(Arc::new(instance))
    }

    /// Refuses a duplicate id.
    pub fn register_instance(&mut self, instance: Arc<PirInstance<S>>) -> Result<()> {
        self.add_live(instance)
    }

    /// Registers through `&self`; `ArcSwap::rcu` is what keeps concurrent
    /// registrations from losing each other's updates.
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

    /// Any instance with this id, draining or not.
    pub fn instance(&self, id: &InstanceId) -> Option<Arc<PirInstance<S>>> {
        self.instances
            .load()
            .iter()
            .find(|i| &i.id == id)
            .map(Arc::clone)
    }

    /// Only if [`DrainState::Active`].
    pub fn active_instance(&self, id: &InstanceId) -> Option<Arc<PirInstance<S>>> {
        self.instance(id)
            .filter(|inst| inst.drain_state() == DrainState::Active)
    }

    /// Every registered instance.
    pub fn instances(&self) -> Vec<Arc<PirInstance<S>>> {
        self.instances.load().iter().map(Arc::clone).collect()
    }

    /// Only those in [`DrainState::Active`].
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

        fn state_shape(_state: &Self::ServerState) -> StateShape {
            // flat vector, index used directly: no decomposition to invalidate
            StateShape {
                entry_size_bytes: 1,
                rows_per_shard: u64::MAX,
            }
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
        inst.swap_state(vec![1, 2, 3], Epoch(1))
            .expect("same shape");
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

        inst.swap_state(vec![99, 99, 99, 99, 99], Epoch(snap_epoch.0 + 1))
            .expect("same shape");
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

    /// A scheme whose shape follows its state, so a swap can change geometry.
    #[derive(Debug)]
    struct ShapedScheme;

    impl PirScheme for ShapedScheme {
        type ServerState = (usize, u64);
        type Query = usize;
        type Response = u8;

        fn respond(_state: &Self::ServerState, _query: &Self::Query) -> Result<Self::Response> {
            Ok(0)
        }

        fn state_shape(state: &Self::ServerState) -> StateShape {
            StateShape {
                entry_size_bytes: state.0,
                rows_per_shard: state.1,
            }
        }
    }

    #[test]
    fn swap_state_rejects_a_changed_entry_size() {
        let inst = PirInstance::<ShapedScheme>::new(
            InstanceId::new("shape"),
            InstanceRole::Live,
            (32, 2048),
        );
        let err = inst
            .swap_state((64, 2048), Epoch(1))
            .expect_err("a changed entry_size must be refused");
        assert!(
            matches!(err, ServerError::StateShapeMismatch { .. }),
            "got {err:?}"
        );
        assert_eq!(
            inst.snapshot.load().epoch,
            Epoch(0),
            "state must not publish"
        );
    }

    #[test]
    fn swap_state_rejects_changed_rows_per_shard() {
        let inst = PirInstance::<ShapedScheme>::new(
            InstanceId::new("shape"),
            InstanceRole::Live,
            (32, 2048),
        );
        assert!(inst.swap_state((32, 4096), Epoch(1)).is_err());
    }

    /// Corpus growth is the normal case and must stay legal.
    #[test]
    fn swap_state_accepts_the_same_geometry() {
        let inst = PirInstance::<ShapedScheme>::new(
            InstanceId::new("shape"),
            InstanceRole::Live,
            (32, 2048),
        );
        inst.swap_state((32, 2048), Epoch(1))
            .expect("identical geometry must publish");
        assert_eq!(inst.snapshot.load().epoch, Epoch(1));
    }
}
