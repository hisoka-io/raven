//! T1 PPOI status PIR closure-rule property test: PIR plaintext
//! byte-equals `LogicalLeafStore::ppoi_status` for the queried BC.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::items_after_statements
)]

use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::ClientSession;
use raven_railgun_engine::inspire::{
    apply_wal_entry, build_client_session, build_seeded_query, extract_response, re_encode_shard,
    register_client_session, setup_state, LogicalLeafStore,
};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_engine::PirScheme;
use raven_railgun_persistence::WalEntryPayload;

const ENTRY_BYTES: usize = 32;
const ENTRIES: usize = 65_536;
const ENTRIES_PER_SHARD: u32 = 2048;
const LIST_KEY: [u8; 32] = [0xab; 32];
const LEAVES_PRELOADED: u32 = 64;

fn bc_for(idx: u32) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0..4].copy_from_slice(&idx.to_be_bytes());
    b[31] = u8::try_from(idx & 0xff).unwrap_or(0).saturating_add(1);
    b
}

fn status_for(idx: u32) -> u8 {
    u8::try_from(idx % 4).unwrap_or(0)
}

fn build_zero_db() -> Vec<u8> {
    vec![0u8; ENTRIES * ENTRY_BYTES]
}

fn build_state_session() -> (
    raven_railgun_engine::inspire::InspireServerState,
    ClientSession,
    LogicalLeafStore,
    InspireParams,
) {
    let params = InspireParams::secure_128_d2048();
    let db = build_zero_db();
    let (server_state, secret_key) =
        setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("setup_state");

    let kind = EncoderKind::PerListStatus { list_key: LIST_KEY };
    let encoder: Arc<dyn PirTableEncoder> = kind
        .build(ENTRY_BYTES, ENTRIES_PER_SHARD)
        .expect("encoder build");

    let mut store = LogicalLeafStore::new();
    for i in 0..LEAVES_PRELOADED {
        let payload = WalEntryPayload::PpoiListLeafAdded {
            list_key: LIST_KEY,
            list_index: i,
            blinded_commitment: bc_for(i),
            status: status_for(i),
        };
        apply_wal_entry(&mut store, &payload, 100 + u64::from(i), encoder.as_ref())
            .expect("apply leaf");
    }

    let dirty: Vec<u32> = store.dirty_shards().iter().copied().collect();
    let mut encoded_db = (*server_state.encoded_db).clone();
    for shard_id in dirty {
        let bytes = encoder.materialize_shard(shard_id, &store);
        re_encode_shard(&mut encoded_db, &params, shard_id, &bytes, ENTRY_BYTES)
            .expect("re_encode_shard");
    }

    let live_state = raven_railgun_engine::inspire::InspireServerState {
        crs: Arc::clone(&server_state.crs),
        encoded_db: Arc::new(encoded_db),
        cache: Arc::clone(&server_state.cache),
        session_store: Arc::clone(&server_state.session_store),
        variant: server_state.variant,
        entry_size: server_state.entry_size,
    };

    let mut client_session =
        build_client_session((*live_state.crs).clone(), secret_key, &params).expect("client");
    register_client_session(&mut client_session, &live_state).expect("register session");
    (live_state, client_session, store, params)
}

#[test]
#[ignore = "production-cell setup is heavy (~12s); T1 status PIR closure"]
fn t1_pir_query_recovers_status_byte_byte_identical_to_logical_store() {
    let (live_state, client_session, store, params) = build_state_session();

    for &target_idx in &[0u32, 7, 33, 63] {
        let target_bc = bc_for(target_idx);
        let expected_status = store
            .ppoi_status(&LIST_KEY, &target_bc)
            .expect("status present in store");
        let expected_idx = store
            .ppoi_index_of(&LIST_KEY, &target_bc)
            .expect("BC -> idx present in store");
        assert_eq!(
            expected_idx, target_idx,
            "T1 ordering oracle: BC -> idx must round-trip"
        );

        let (client_state, query) = build_seeded_query(
            &client_session,
            live_state.shard_config(),
            u64::from(target_idx),
            &params,
        )
        .expect("build_seeded_query");
        let response = <raven_railgun_engine::inspire::RavenInspireScheme as PirScheme>::respond(
            &live_state,
            &query,
        )
        .expect("respond");
        let plaintext = extract_response(&live_state.crs, &client_state, &response, ENTRY_BYTES)
            .expect("extract");
        let recovered_status = *plaintext.first().expect("status byte");
        let recovered_bc_tail = plaintext.get(1..32).expect("BC tail slice");

        assert_eq!(
            recovered_status, expected_status,
            "T1 PIR plaintext status byte at idx={target_idx} must byte-equal LogicalLeafStore.ppoi_status"
        );
        assert_eq!(
            recovered_bc_tail,
            &target_bc[..31],
            "T1 PIR plaintext BC tail at idx={target_idx} must byte-equal queried BC"
        );
    }
}
