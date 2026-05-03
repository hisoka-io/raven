//! T2 PPOI auth-path PIR closure-rule property test: PIR-derived
//! 16-sibling path byte-equals `ppoi_merkle_proof.elements` and
//! reconstructs the per-list IMT root.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::items_after_statements,
    clippy::indexing_slicing,
    clippy::needless_range_loop
)]

use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::ClientSession;
use raven_railgun_core::MerkleProof;
use raven_railgun_engine::imt::TREE_DEPTH;
use raven_railgun_engine::inspire::{
    apply_wal_entry, build_client_session, build_seeded_query, extract_response, re_encode_shard,
    register_client_session, setup_state, LogicalLeafStore,
};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_engine::PirScheme;
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_poseidon::merkle_node;

const ENTRY_BYTES: usize = 16 * 32;
const ENTRIES: usize = 65_536;
const ENTRIES_PER_SHARD: u32 = 2048;
const LIST_KEY: [u8; 32] = [0x42; 32];
const LEAVES_PRELOADED: u32 = 32;

fn bc_for(idx: u32) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[28..32].copy_from_slice(&idx.saturating_add(1).to_be_bytes());
    b
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

    let kind = EncoderKind::PerListPath { list_key: LIST_KEY };
    let encoder: Arc<dyn PirTableEncoder> = kind
        .build(ENTRY_BYTES, ENTRIES_PER_SHARD)
        .expect("encoder build");

    let mut store = LogicalLeafStore::new();
    for i in 0..LEAVES_PRELOADED {
        let payload = WalEntryPayload::PpoiListLeafAdded {
            list_key: LIST_KEY,
            list_index: i,
            blinded_commitment: bc_for(i),
            status: 0,
        };
        apply_wal_entry(&mut store, &payload, 100 + u64::from(i), encoder.as_ref())
            .expect("apply leaf");
    }

    let dirty: Vec<u32> = store.dirty_shards().iter().copied().collect();
    let mut encoded_db = server_state.encoded_db.clone();
    for shard_id in dirty {
        let bytes = encoder.materialize_shard(shard_id, &store);
        re_encode_shard(&mut encoded_db, &params, shard_id, &bytes, ENTRY_BYTES)
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

fn unpack_path(plaintext: &[u8]) -> [[u8; 32]; TREE_DEPTH] {
    let mut elements = [[0u8; 32]; TREE_DEPTH];
    for level in 0..TREE_DEPTH {
        let s = level * 32;
        let slice = plaintext.get(s..s + 32).expect("path slice");
        elements[level].copy_from_slice(slice);
    }
    elements
}

fn reconstruct_root(leaf: [u8; 32], leaf_index: u32, path: &MerkleProof) -> [u8; 32] {
    let mut current = leaf;
    for level in 0..TREE_DEPTH {
        let bit = (leaf_index >> level) & 1;
        let sibling = path.elements[level];
        current = if bit == 1 {
            merkle_node(sibling, current).expect("hash")
        } else {
            merkle_node(current, sibling).expect("hash")
        };
    }
    current
}

#[test]
#[ignore = "production-cell setup is heavy (~12s); T2 path PIR closure"]
fn t2_pir_query_recovers_auth_path_byte_identical_and_root_reconstructs() {
    let (live_state, client_session, store, params) = build_state_session();

    let imt_root = store
        .ppoi_imt_root(&LIST_KEY)
        .expect("per-list IMT root present");

    for &target_idx in &[0u32, 1, 7, 16, 31] {
        let oracle = store
            .ppoi_merkle_proof(&LIST_KEY, target_idx)
            .expect("per-list proof present");

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

        let pir_path = unpack_path(&plaintext);
        assert_eq!(
            pir_path, oracle.elements,
            "T2 PIR path at idx={target_idx} must byte-equal LogicalLeafStore::ppoi_merkle_proof.elements"
        );

        let leaf = bc_for(target_idx);
        let reconstructed = reconstruct_root(
            leaf,
            target_idx,
            &MerkleProof {
                root: oracle.root,
                indices: oracle.indices,
                elements: pir_path,
            },
        );
        assert_eq!(
            reconstructed, imt_root,
            "T2 PIR path at idx={target_idx} must reconstruct to per-list IMT root"
        );
    }
}
