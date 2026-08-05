//! A flat-state scheme served by a main plus a sidecar engine, read through the client
//! fan-out. Response byte-length uniformity across the two engines is the size-channel control.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::sync::Arc;

use futures::executor::block_on;

use eth_state::{
    build_flat_state, build_session, read_balance_consume_both, AnsweringEngine, EngineHandle,
    FlatBalanceScheme, ENTRY_SIZE,
};
use raven_client::build_seeded_query_rust;
use raven_core::InstanceId;
use raven_inspire::params::InspireParams;
use raven_server::{Engine, InstanceRole, PirInstance};

fn expected_be(balance: u128) -> [u8; ENTRY_SIZE] {
    let mut rec = [0u8; ENTRY_SIZE];
    rec[0] = eth_state::PRESENT_TAG;
    rec[16..].copy_from_slice(&balance.to_be_bytes());
    rec
}

fn build_db(balances: &[u128]) -> Vec<u8> {
    let mut db = Vec::with_capacity(balances.len() * ENTRY_SIZE);
    for &b in balances {
        db.extend_from_slice(&expected_be(b));
    }
    db
}

#[test]
fn sidecar_wiring() {
    let params = InspireParams::secure_128_d2048();

    // The sidecar holds only the changed leaf 2; every other sidecar leaf reads as absent.
    let main_db = build_db(&[100, 200, 300, 0]);
    let mut side_db = vec![0u8; 4 * ENTRY_SIZE];
    side_db[2 * ENTRY_SIZE..3 * ENTRY_SIZE].copy_from_slice(&expected_be(999));

    let (main_state, main_sk) =
        build_flat_state(&params, &main_db, ENTRY_SIZE, 0x00A1_1CE0).expect("main setup");
    let (side_state, side_sk) =
        build_flat_state(&params, &side_db, ENTRY_SIZE, 0x0000_B0B0).expect("sidecar setup");

    let main_session =
        build_session(&main_state.crs, main_sk, params.sigma, 1).expect("main session");
    let side_session =
        build_session(&side_state.crs, side_sk, params.sigma, 2).expect("sidecar session");

    let main_shard = main_state.encoded_db.config.clone();
    let side_shard = side_state.encoded_db.config.clone();
    let main_crs = main_state.crs.clone();
    let side_crs = side_state.crs.clone();

    let main_inst = Arc::new(PirInstance::<FlatBalanceScheme>::new(
        InstanceId::new("main"),
        InstanceRole::Live,
        main_state,
    ));
    let side_inst = Arc::new(PirInstance::<FlatBalanceScheme>::new(
        InstanceId::new("sidecar"),
        InstanceRole::Sidecar,
        side_state,
    ));

    let engine = Engine::<FlatBalanceScheme>::new();
    engine.add_live(main_inst.clone()).expect("register main");
    engine
        .add_live(side_inst.clone())
        .expect("register sidecar");

    let main_h = EngineHandle {
        instance: &main_inst,
        session: &main_session,
        crs: &main_crs,
        params: &params,
        shard_config: &main_shard,
    };
    let side_h = EngineHandle {
        instance: &side_inst,
        session: &side_session,
        crs: &side_crs,
        params: &params,
        shard_config: &side_shard,
    };

    let (bytes0, eng0) =
        block_on(read_balance_consume_both(&main_h, &side_h, 0)).expect("read leaf 0");
    assert_eq!(
        eng0,
        AnsweringEngine::Main,
        "main-only leaf must select main"
    );
    assert_eq!(
        bytes0.as_ref(),
        expected_be(100),
        "leaf 0 balance byte-identical"
    );

    let (bytes2, eng2) =
        block_on(read_balance_consume_both(&main_h, &side_h, 2)).expect("read leaf 2");
    assert_eq!(
        eng2,
        AnsweringEngine::Sidecar,
        "sidecar-held leaf must select sidecar"
    );
    assert_eq!(
        bytes2.as_ref(),
        expected_be(999),
        "leaf 2 balance byte-identical"
    );

    // A response-size observer must not be able to infer which engine answered.
    let (_sm, q_m) =
        build_seeded_query_rust(&main_session, &params, &main_shard, 2).expect("main query");
    let (_es, r_m) = main_inst.query(&q_m).expect("main respond");
    let (_ss, q_s) =
        build_seeded_query_rust(&side_session, &params, &side_shard, 2).expect("sidecar query");
    let (_es2, r_s) = side_inst.query(&q_s).expect("sidecar respond");
    assert_eq!(
        bincode::serialized_size(&r_m).expect("size main"),
        bincode::serialized_size(&r_s).expect("size sidecar"),
        "main and sidecar responses must be byte-length-uniform"
    );
}
