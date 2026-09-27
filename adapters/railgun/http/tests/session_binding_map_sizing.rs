//! The session binding map is shared by every instance, so a map sized for one pool refuses
//! handshakes the other pools still have seats for. The inspire router is the first place the
//! http layer sees the booted instance count, and it refuses to build under that size.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::PoisonError;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{setup_state, RavenInspireScheme};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
use raven_railgun_http::{inspire_router, AppState, HttpConfig};

const READ_TOKEN: &str = "BEARER-BINDING-MAP-SIZING-padded-ab";
const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_BYTES: usize = 256;
const SEATS: usize = 3;
const INSTANCES: usize = 2;

static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn build(session_lru_cap: usize) -> Result<axum::Router, String> {
    let params = InspireParams::secure_128_d2048();
    let db = raven_railgun_testkit::toy_db(TOY_ENTRIES, TOY_ENTRY_BYTES);
    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    for index in 0..INSTANCES {
        let (state, _sk) = setup_state(&params, &db, TOY_ENTRY_BYTES, InspireVariant::TwoPacking)
            .expect("toy state");
        engine
            .add_instance(PirInstance::new(
                InstanceId::new(format!("binding-map-{index}")),
                InstanceRole::Live,
                state,
            ))
            .expect("register instance");
    }
    let mut config = HttpConfig::demo(READ_TOKEN);
    config.max_sessions_per_instance = SEATS;
    config.session_lru_cap = session_lru_cap;
    let app_state = {
        let _g = APPSTATE_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        AppState::new(engine, config).expect("one pool fits, so the state builds")
    };
    inspire_router(app_state)
}

#[test]
fn a_binding_map_below_every_booted_pool_refuses_to_build_the_router() {
    let cap = SEATS * INSTANCES - 1;
    let err = build(cap).expect_err("a map one short of both pools must refuse");
    for number in [cap, SEATS, INSTANCES, SEATS * INSTANCES] {
        assert!(
            err.contains(&number.to_string()),
            "the refusal names {number}: {err}"
        );
    }
    assert!(err.contains("session_lru_cap"), "names the knob: {err}");
}

#[test]
fn a_binding_map_holding_every_booted_pool_builds_the_router() {
    let _router = build(SEATS * INSTANCES).expect("a map exactly as large as both pools builds");
}
