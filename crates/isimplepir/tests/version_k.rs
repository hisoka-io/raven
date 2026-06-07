#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Version-k discipline: out-of-order `StateUpdate` calls MUST produce
//! `IsimplePirError::VersionMismatch`, not silent success.

use raven_isimplepir::{db_update_modify, setup, state_update_entry, IsimplePirError, LweParams};

fn toy_params() -> LweParams {
    LweParams {
        n: 128,
        log2_q: 32,
        p: 991,
        l: 4,
        m: 4,
        bits_per_element: 9,
    }
}

#[test]
fn out_of_order_update_rejected() {
    let params = toy_params();
    let db = vec![0u32; params.l * params.m];
    let out = setup(&db, params, Some([0u8; 32])).expect("setup");
    let mut hint = out.hint.clone();
    let a_seed = out.server.a_seed;
    let mut state = out.server;

    let _d1 = db_update_modify(&mut state, 0, 0, 1).expect("d1");
    let d2 = db_update_modify(&mut state, 0, 1, 2).expect("d2");

    // d2 applied without d1.
    let update_result = state_update_entry(&mut hint, &a_seed, &params, &d2);
    assert!(matches!(
        update_result,
        Err(IsimplePirError::VersionMismatch { .. }),
    ));
}

#[test]
fn duplicate_update_rejected() {
    let params = toy_params();
    let db = vec![0u32; params.l * params.m];
    let out = setup(&db, params, Some([0u8; 32])).expect("setup");
    let mut hint = out.hint.clone();
    let a_seed = out.server.a_seed;
    let mut state = out.server;

    let d1 = db_update_modify(&mut state, 0, 0, 1).expect("d1");

    state_update_entry(&mut hint, &a_seed, &params, &d1).expect("first apply should succeed");

    // replay guard: re-applying d1 must fail.
    let replay_result = state_update_entry(&mut hint, &a_seed, &params, &d1);
    assert!(matches!(
        replay_result,
        Err(IsimplePirError::VersionMismatch { .. }),
    ));
}

#[test]
fn in_order_updates_succeed() {
    let params = toy_params();
    let db = vec![0u32; params.l * params.m];
    let out = setup(&db, params, Some([0u8; 32])).expect("setup");
    let mut hint = out.hint.clone();
    let a_seed = out.server.a_seed;
    let mut state = out.server;

    for step in 0..8 {
        let delta = db_update_modify(
            &mut state,
            step % params.l,
            step % params.m,
            (step as u32 + 1) % params.p,
        )
        .expect("modify");
        state_update_entry(&mut hint, &a_seed, &params, &delta)
            .expect("in-order apply should succeed");
        assert_eq!(hint.version, state.version);
    }
}
