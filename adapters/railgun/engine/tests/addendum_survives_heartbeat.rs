//! A session-eviction heartbeat must not take a frozen block's path queries down.
//!
//! `heartbeat_session_eviction` republishes the same `encoded_db` by `Arc::clone` under a NEW epoch,
//! every session-eviction interval (3,600 s by default). A block marked `role = "static"` never
//! commits again, so anything that keys addendum validity on the epoch refuses it forever one hour
//! after boot. Five of six PPOI blocks in the shipped topology are static. This file is the
//! reddening case for that outage, and the proof that the replacement signal survives it.

#![allow(clippy::expect_used)]

use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{
    apply_wal_entry, heartbeat_session_eviction, setup_state, InspireServerState, LogicalLeafStore,
    RavenInspireScheme,
};
use raven_railgun_engine::pir_table::{PerListPath10Encoder, PirTableEncoder};
use raven_railgun_engine::{InstanceRole, PirInstance};
use raven_railgun_persistence::WalEntryPayload;

const LIST_KEY: [u8; 32] = [0xab; 32];
const ENTRIES_PER_SHARD: u32 = 2_048;

fn toy_state() -> InspireServerState {
    let params = InspireParams::secure_128_d2048();
    let db = raven_railgun_testkit::toy_db(raven_railgun_testkit::TOY_ENTRIES, 32);
    let (state, _sk) =
        setup_state(&params, &db, 32, InspireVariant::TwoPacking).expect("toy setup_state");
    state
}

fn frozen_block_store(encoder: &dyn PirTableEncoder) -> LogicalLeafStore {
    let mut store = LogicalLeafStore::default();
    let mut bc = [0u8; 32];
    bc[31] = 0x01;
    apply_wal_entry(
        &mut store,
        &WalEntryPayload::PpoiListLeafAdded {
            list_key: LIST_KEY,
            list_index: 0,
            blinded_commitment: bc,
            status: 0,
            event_type: raven_railgun_persistence::PpoiEventType::Shield,
            signature: vec![0; 64],
            validated_merkleroot: [0; 32],
        },
        0,
        encoder,
    )
    .expect("append");
    store
}

#[test]
fn a_heartbeat_bumps_the_epoch_but_the_addenda_still_match_the_served_state() {
    let instance: Arc<PirInstance<RavenInspireScheme>> = Arc::new(PirInstance::new(
        InstanceId::new("frozen-block"),
        InstanceRole::Static,
        toy_state(),
    ));
    let encoder = PerListPath10Encoder::new(ENTRIES_PER_SHARD, LIST_KEY).expect("encoder");
    let mut store = frozen_block_store(&encoder);

    // The commit driver's refresh, against the state as published.
    let at_commit = instance.current_snapshot();
    store.refresh_committed_addenda(&at_commit.state.encoded_db, ENTRIES_PER_SHARD);
    assert!(store.committed_addenda_derived_from(&at_commit.state.encoded_db));

    // One hour passes. Nothing is appended -- this block is frozen -- and the heartbeat fires.
    heartbeat_session_eviction(&instance).expect("heartbeat");
    let after_heartbeat = instance.current_snapshot();

    // THE REDDENING CASE for the epoch check: the epoch moved with no data change.
    assert_ne!(
        at_commit.epoch, after_heartbeat.epoch,
        "the heartbeat must advance the epoch, or this test proves nothing about it"
    );
    assert!(
        Arc::ptr_eq(
            &at_commit.state.encoded_db,
            &after_heartbeat.state.encoded_db
        ),
        "the heartbeat must carry the encoded database by Arc::clone"
    );

    // THE PROPERTY: the served state is the tree the addenda came from, so they still match and
    // the block keeps serving. An epoch equality check would have refused here, forever.
    assert!(
        store.committed_addenda_derived_from(&after_heartbeat.state.encoded_db),
        "a frozen block must serve indefinitely across heartbeats"
    );

    // And a real commit -- a NEW encoded database -- is the only thing that invalidates them.
    let recommitted = toy_state();
    instance
        .swap_state(recommitted, after_heartbeat.epoch.next())
        .expect("swap to a recommitted state");
    let after_commit = instance.current_snapshot();
    assert!(
        !store.committed_addenda_derived_from(&after_commit.state.encoded_db),
        "a commit replaces the tree, so stale addenda must be refused until refreshed"
    );
}
