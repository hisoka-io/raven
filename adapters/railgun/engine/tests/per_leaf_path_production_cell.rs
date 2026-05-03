//! Per-leaf-path encoder end-to-end production-cell test.

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
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_poseidon::merkle_node;

const PATH_RECORD_BYTES: usize = TREE_DEPTH * 32;
const ENTRIES: usize = 1 << TREE_DEPTH;
const TREE_NUMBER: u32 = 0;
const LEAVES_PRELOADED: u32 = 32;

fn canonical(seed: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = seed.max(1);
    b
}

fn build_zero_db() -> Vec<u8> {
    vec![0u8; ENTRIES * PATH_RECORD_BYTES]
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
        setup_state(&params, &db, PATH_RECORD_BYTES, InspireVariant::TwoPacking)
            .expect("setup_state");

    let encoder_kind = EncoderKind::PerLeafPath {
        tree_number: TREE_NUMBER,
    };
    let encoder: Arc<dyn PirTableEncoder> = encoder_kind
        .build(PATH_RECORD_BYTES, 2048)
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
    let mut encoded_db = server_state.encoded_db.clone();
    for shard_id in dirty {
        let bytes = encoder.materialize_shard(shard_id, &store);
        re_encode_shard(
            &mut encoded_db,
            &params,
            shard_id,
            &bytes,
            PATH_RECORD_BYTES,
        )
        .expect("re_encode_shard");
    }

    let live_state = raven_railgun_engine::inspire::InspireServerState {
        crs: Arc::clone(&server_state.crs),
        encoded_db,
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

fn pir_query_leaf_row(
    leaf_index: u32,
    live_state: &raven_railgun_engine::inspire::InspireServerState,
    client_session: &ClientSession,
    params: &InspireParams,
) -> Vec<u8> {
    let (client_state, query) = build_seeded_query(
        client_session,
        live_state.shard_config(),
        u64::from(leaf_index),
        params,
    )
    .expect("build_seeded_query");
    use raven_railgun_engine::PirScheme;
    let response = <raven_railgun_engine::inspire::RavenInspireScheme as PirScheme>::respond(
        live_state, &query,
    )
    .expect("respond");
    extract_response(&live_state.crs, &client_state, &response, PATH_RECORD_BYTES).expect("extract")
}

#[test]
#[ignore = "production-cell setup is heavy (~12s); per-leaf-path E2E sibling-walk byte-identity"]
fn per_leaf_path_query_recovers_sibling_walk_and_root_for_target_leaves() {
    let (live_state, client_session, store, params) = build_live_state_and_session();
    let imt = store.imt(TREE_NUMBER).expect("tree present");

    for leaf_idx in [0u32, 1, 7, 16, 31] {
        let plaintext = pir_query_leaf_row(leaf_idx, &live_state, &client_session, &params);
        let row = plaintext
            .get(..PATH_RECORD_BYTES)
            .expect("row plaintext present");

        // Sibling-walk oracle: independently compute each level's
        // sibling index from leaf_idx and read it directly from the
        // IMT via Imt::node — bypassing Imt::merkle_proof which the
        // encoder itself consumes (closure-rule independence).
        let mut path_idx = leaf_idx as usize;
        let mut current = canonical(u8::try_from(leaf_idx % 250).unwrap_or(0).saturating_add(1));
        for level in 0..TREE_DEPTH {
            let sibling_idx_at_level = path_idx ^ 1;
            let bit = path_idx & 1;
            path_idx >>= 1;

            let expected_sibling = imt.node(level, sibling_idx_at_level);
            let recovered = row
                .get(level * 32..(level + 1) * 32)
                .expect("sibling slice present");
            assert_eq!(
                recovered, &expected_sibling,
                "leaf_idx={leaf_idx} level={level}: sibling byte mismatch \
                 (expected Imt::node({level}, {sibling_idx_at_level}))"
            );

            // G5'.A IMT-rooted reconstruction: hash up the path with
            // the recovered sibling, mirroring the wallet-side
            // verifier path.
            current = if bit == 1 {
                merkle_node(expected_sibling, current).expect("hash right")
            } else {
                merkle_node(current, expected_sibling).expect("hash left")
            };
        }
        let expected_root = imt.root();
        assert_eq!(
            current, expected_root,
            "leaf_idx={leaf_idx}: reconstructed root does not match Imt::root"
        );
    }
}
