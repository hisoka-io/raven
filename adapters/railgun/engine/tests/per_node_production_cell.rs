//! Per-node encoder end-to-end production-cell test: PIR plaintext at
//! three Merkle levels (leaf, level-1, mid-tree level-8) byte-equals
//! `Imt::node(level, idx)`.

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
use raven_railgun_engine::imt::TREE_DEPTH;
use raven_railgun_engine::inspire::{
    apply_wal_entry, build_client_session, build_seeded_query, extract_response, re_encode_shard,
    register_client_session, setup_state, LogicalLeafStore,
};
use raven_railgun_engine::pir_table::{EncoderKind, PerNodeEncoder, PirTableEncoder};
use raven_railgun_persistence::WalEntryPayload;

const ENTRY_BYTES: usize = 32;
const ENTRIES: usize = 1 << (TREE_DEPTH + 1);
const TREE_NUMBER: u32 = 0;
const LEAVES_PRELOADED: u32 = 64;

fn canonical(seed: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = seed.max(1);
    b
}

fn build_zero_db() -> Vec<u8> {
    vec![0u8; ENTRIES * ENTRY_BYTES]
}

fn build_live_state_and_session() -> (
    raven_railgun_engine::inspire::InspireServerState,
    ClientSession,
    LogicalLeafStore,
    InspireParams,
) {
    let params = InspireParams::secure_128_d2048();
    let db = build_zero_db();
    let (server_state, secret_key) =
        setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("setup_state");

    let encoder_kind = EncoderKind::PerNode {
        tree_number: TREE_NUMBER,
    };
    let encoder: Arc<dyn PirTableEncoder> = encoder_kind
        .build(ENTRY_BYTES, 2048)
        .expect("encoder build");

    let mut store = LogicalLeafStore::new();
    for i in 0..LEAVES_PRELOADED {
        let payload = WalEntryPayload::AppendLeaf {
            tree_number: TREE_NUMBER,
            leaf_index: i,
            commitment: canonical(u8::try_from(i % 250).unwrap_or(0).saturating_add(1)),
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

fn pir_query_at_flat(
    flat: u32,
    live_state: &raven_railgun_engine::inspire::InspireServerState,
    client_session: &ClientSession,
    params: &InspireParams,
) -> Vec<u8> {
    let (client_state, query) = build_seeded_query(
        client_session,
        live_state.shard_config(),
        u64::from(flat),
        params,
    )
    .expect("build_seeded_query");
    use raven_railgun_engine::PirScheme;
    let response = <raven_railgun_engine::inspire::RavenInspireScheme as PirScheme>::respond(
        live_state, &query,
    )
    .expect("respond");
    extract_response(&live_state.crs, &client_state, &response, ENTRY_BYTES).expect("extract")
}

#[test]
#[ignore = "production-cell setup is heavy (~12s); per-node E2E byte-identity at multiple levels"]
fn per_node_query_recovers_internal_nodes_at_levels_0_1_and_8() {
    let (live_state, client_session, store, params) = build_live_state_and_session();
    let imt = store.imt(TREE_NUMBER).expect("tree present");

    for (level, idx) in [(0u32, 7u32), (1u32, 0u32), (8u32, 0u32)] {
        let flat = PerNodeEncoder::flat_index(level, idx);
        let expected = imt.node(level as usize, idx as usize);
        let plaintext = pir_query_at_flat(flat, &live_state, &client_session, &params);
        let recovered = plaintext.get(..32).expect("recovered slice");
        assert_eq!(
            recovered, &expected,
            "PerNodeEncoder PIR plaintext at flat={flat} (level={level}, idx={idx}) \
             must byte-equal Imt::node oracle"
        );
    }
}
