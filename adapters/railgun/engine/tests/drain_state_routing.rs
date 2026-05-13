//! Engine-level drain-state routing tests. Distinct from `set_role` which is
//! observational; drain state is the operator-driven, route-affecting signal.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing
)]

use std::sync::Arc;
use std::time::Duration;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::{AdapterError, InstanceId};
use raven_railgun_engine::inspire::{setup_state, InspireServerState, RavenInspireScheme};
use raven_railgun_engine::{DrainState, Engine, InstanceRole, PirInstance};

const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_SIZE: usize = 256;

fn build_toy_state() -> raven_railgun_core::Result<InspireServerState> {
    let params = InspireParams::secure_128_d2048();
    let db: Vec<u8> = (0..TOY_ENTRIES)
        .flat_map(|i| (0..TOY_ENTRY_SIZE).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
        .collect();
    let (state, _sk) = setup_state(&params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking)?;
    Ok(state)
}

fn build_instance(id: &str, role: InstanceRole) -> Arc<PirInstance<RavenInspireScheme>> {
    let state = build_toy_state().expect("toy state");
    Arc::new(PirInstance::<RavenInspireScheme>::new(
        InstanceId::new(id),
        role,
        state,
    ))
}

#[test]
fn fresh_instance_defaults_to_active_with_zero_in_flight() {
    let inst = build_instance("toy-default", InstanceRole::Live);
    assert_eq!(inst.drain_state(), DrainState::Active);
    assert_eq!(inst.in_flight_count(), 0);
    assert!(DrainState::Active.is_active());
    assert!(!DrainState::Draining.is_active());
    assert!(!DrainState::Drained.is_active());
}

#[test]
fn set_role_does_not_touch_drain_state() {
    let inst = build_instance("toy-role-orthogonal", InstanceRole::Live);
    assert_eq!(inst.drain_state(), DrainState::Active);
    inst.set_role(InstanceRole::Static);
    assert_eq!(
        inst.drain_state(),
        DrainState::Active,
        "set_role must NOT alter drain_state"
    );
    inst.set_drain_state(DrainState::Draining);
    inst.set_role(InstanceRole::Live);
    assert_eq!(
        inst.drain_state(),
        DrainState::Draining,
        "set_role must NOT alter drain_state"
    );
}

#[test]
fn drain_active_instance_routes_new_queries_to_other() {
    let inst_a = build_instance("commit-tree-0-A", InstanceRole::Live);
    let inst_b = build_instance("commit-tree-0-B", InstanceRole::Live);
    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    engine
        .register_instance(Arc::clone(&inst_a))
        .expect("register A");
    engine
        .register_instance(Arc::clone(&inst_b))
        .expect("register B");
    let engine = Arc::new(engine);

    assert_eq!(engine.active_instances().len(), 2);

    inst_a.set_drain_state(DrainState::Draining);

    assert!(
        engine
            .active_instance(&InstanceId::new("commit-tree-0-A"))
            .is_none(),
        "active_instance must skip draining instance"
    );
    assert!(
        engine
            .active_instance(&InstanceId::new("commit-tree-0-B"))
            .is_some(),
        "active_instance must return B"
    );

    let actives = engine.active_instances();
    assert_eq!(actives.len(), 1, "exactly one active instance after drain");
    assert_eq!(
        actives[0].id,
        InstanceId::new("commit-tree-0-B"),
        "the active one is B"
    );

    for _ in 0..5 {
        let picked = engine
            .active_instances()
            .into_iter()
            .next()
            .expect("at least one active instance");
        assert_eq!(picked.id, InstanceId::new("commit-tree-0-B"));
    }

    inst_a.set_drain_state(DrainState::Drained);
    assert!(engine
        .active_instance(&InstanceId::new("commit-tree-0-A"))
        .is_none());
    assert_eq!(engine.active_instances().len(), 1);
}

#[tokio::test]
async fn drain_single_instance_returns_no_active_instance_error() {
    let inst = build_instance("commit-tree-7", InstanceRole::Live);
    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    engine
        .register_instance(Arc::clone(&inst))
        .expect("register");
    let engine = Arc::new(engine);

    assert!(engine
        .active_instance(&InstanceId::new("commit-tree-7"))
        .is_some());

    inst.set_drain_state(DrainState::Draining);

    assert!(
        engine
            .active_instance(&InstanceId::new("commit-tree-7"))
            .is_none(),
        "drained single instance must not appear in active_instance"
    );
    assert!(engine.active_instances().is_empty());

    let q = build_real_query(&inst);
    let err = inst
        .query_active_tracked(&q)
        .expect_err("query against draining instance must error");
    match err {
        AdapterError::NoActiveInstance { instance_id } => {
            assert_eq!(instance_id, InstanceId::new("commit-tree-7"));
        }
        other => panic!("expected NoActiveInstance, got {other:?}"),
    }
    assert_eq!(
        inst.in_flight_count(),
        0,
        "refused query must not bump the in-flight counter"
    );
}

#[tokio::test]
async fn in_flight_query_finishes_on_snapshot_after_drain() {
    let inst_a = build_instance("commit-tree-A", InstanceRole::Live);
    let inst_b = build_instance("commit-tree-B", InstanceRole::Live);
    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    engine
        .register_instance(Arc::clone(&inst_a))
        .expect("register A");
    engine
        .register_instance(Arc::clone(&inst_b))
        .expect("register B");
    let engine = Arc::new(engine);

    let guard_a = inst_a
        .acquire_in_flight_guard()
        .expect("guard acquires while Active");
    assert_eq!(inst_a.in_flight_count(), 1);

    inst_a.set_drain_state(DrainState::Draining);
    assert_eq!(inst_a.drain_state(), DrainState::Draining);
    assert_eq!(
        inst_a.in_flight_count(),
        1,
        "drain must not pre-decrement in-flight; the guard is still alive"
    );

    assert!(engine
        .active_instance(&InstanceId::new("commit-tree-A"))
        .is_none());
    let next_target = engine
        .active_instances()
        .into_iter()
        .next()
        .expect("at least one active instance");
    assert_eq!(next_target.id, InstanceId::new("commit-tree-B"));

    assert!(
        inst_a.acquire_in_flight_guard().is_none(),
        "Draining must refuse NEW guard acquisitions"
    );

    drop(guard_a);
    assert_eq!(
        inst_a.in_flight_count(),
        0,
        "guard drop decrements in-flight"
    );

    assert!(inst_a.acquire_in_flight_guard().is_none());
}

#[tokio::test]
async fn undrain_active_again_serves_queries() {
    let inst = build_instance("commit-tree-11", InstanceRole::Live);
    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    engine
        .register_instance(Arc::clone(&inst))
        .expect("register");
    let engine = Arc::new(engine);

    inst.set_drain_state(DrainState::Draining);
    inst.set_drain_state(DrainState::Drained);
    assert!(
        engine
            .active_instance(&InstanceId::new("commit-tree-11"))
            .is_none(),
        "Drained instance is not route-eligible"
    );

    inst.set_drain_state(DrainState::Active);
    assert!(
        engine
            .active_instance(&InstanceId::new("commit-tree-11"))
            .is_some(),
        "undrain MUST restore route-eligibility"
    );

    let q = build_real_query(&inst);
    let _result = inst
        .query_active_tracked(&q)
        .expect("post-undrain query succeeds");
    assert_eq!(
        inst.in_flight_count(),
        0,
        "guard must be dropped by query_active_tracked completion"
    );
}

#[tokio::test]
async fn drain_state_transition_is_idempotent() {
    let inst = build_instance("commit-tree-noop", InstanceRole::Live);
    inst.set_drain_state(DrainState::Active);
    assert_eq!(inst.drain_state(), DrainState::Active);
    inst.set_drain_state(DrainState::Active);
    assert_eq!(inst.drain_state(), DrainState::Active);
    inst.set_drain_state(DrainState::Draining);
    inst.set_drain_state(DrainState::Draining);
    assert_eq!(inst.drain_state(), DrainState::Draining);
    // Idle wait so the trait test runtime doesn't shut the runtime
    // down before the (background) tracing event sink has flushed.
    tokio::time::sleep(Duration::from_millis(10)).await;
}

// Helpers

fn build_real_query(
    inst: &Arc<PirInstance<RavenInspireScheme>>,
) -> raven_inspire::SeededClientQuery {
    use raven_railgun_engine::inspire::{
        build_client_session, build_seeded_query, register_client_session,
    };
    let params = InspireParams::secure_128_d2048();
    let snap = inst.current_state();
    // Build a fresh sk-bearing state pair off-side just to obtain a
    // matching RlweSecretKey. The CRS is the one belonging to the
    // server snapshot so packing keys derive against the same CRS.
    let (_off_state, sk) = {
        let db: Vec<u8> = (0..TOY_ENTRIES)
            .flat_map(|i| {
                (0..TOY_ENTRY_SIZE).map(move |j| u8::try_from((i + j) % 251).expect("< 251"))
            })
            .collect();
        setup_state(&params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking).expect("toy")
    };
    let crs_clone = (*snap.crs).clone();
    let mut session = build_client_session(crs_clone, sk, &params).expect("client session");
    // Register against the SAME session store that respond will read
    // (the instance's current snapshot). This is the wiring pattern
    // production tests use — the client session stores packing keys
    // on the server's session store before issuing a seeded query.
    register_client_session(&mut session, snap.as_ref()).expect("register");
    let shard_config = snap.shard_config().clone();
    let (_state, query) =
        build_seeded_query(&session, &shard_config, 0, &params).expect("build query");
    query
}
