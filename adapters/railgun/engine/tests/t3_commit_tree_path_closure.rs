//! T3 commit-tree auth-path PIR closure-rule property test:
//! PIR-derived siblings byte-equal `Imt::node(level, sibling_idx)` and
//! reconstruct to `Imt::root`.

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
const TREE_NUMBER: u32 = 0;
const LEAVES_PRELOADED: u32 = 32;

fn canonical(seed: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = seed.max(1);
    b
}

fn build_zero_db() -> Vec<u8> {
    vec![0u8; ENTRIES * ENTRY_BYTES]
}

#[test]
#[ignore = "production-cell setup is heavy (~12s); T3 commit-tree path PIR closure"]
fn t3_pir_query_recovers_path_byte_identical_and_reconstructs_imt_root() {
    let params = InspireParams::secure_128_d2048();
    let db = build_zero_db();
    let (server_state, secret_key) =
        setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("setup_state");

    let kind = EncoderKind::PerLeafPath {
        tree_number: TREE_NUMBER,
    };
    let encoder: Arc<dyn PirTableEncoder> = kind
        .build(ENTRY_BYTES, ENTRIES_PER_SHARD)
        .expect("encoder build");

    let mut store = LogicalLeafStore::new();
    let mut leaves = vec![[0u8; 32]; LEAVES_PRELOADED as usize];
    for i in 0..LEAVES_PRELOADED {
        let leaf = canonical(u8::try_from(i % 250).unwrap_or(0).saturating_add(1));
        leaves[i as usize] = leaf;
        let payload = WalEntryPayload::AppendLeaf {
            tree_number: TREE_NUMBER,
            leaf_index: i,
            commitment: leaf,
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

    let imt = store.imt(TREE_NUMBER).expect("tree present");
    let imt_root = imt.root();

    for &target_idx in &[0u32, 1, 7, 16, 31] {
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

        // Independent oracle: imt.node walked directly, not
        // imt.merkle_proof, so a self-consistent encoder bug fails.
        let mut pir_siblings = [[0u8; 32]; TREE_DEPTH];
        for level in 0..TREE_DEPTH {
            let s = level * 32;
            let slice = plaintext.get(s..s + 32).expect("path slice");
            pir_siblings[level].copy_from_slice(slice);
            let sibling_idx = ((target_idx as usize) >> level) ^ 1;
            let independent = imt.node(level, sibling_idx);
            assert_eq!(
                pir_siblings[level], independent,
                "T3 PIR sibling at idx={target_idx} level={level} byte-mismatch \
                 against independent imt.node walk"
            );
        }

        let reconstructed = {
            let mut cur = leaves[target_idx as usize];
            for level in 0..TREE_DEPTH {
                let bit = ((target_idx as usize) >> level) & 1;
                let sib = pir_siblings[level];
                cur = if bit == 1 {
                    merkle_node(sib, cur).expect("hash")
                } else {
                    merkle_node(cur, sib).expect("hash")
                };
            }
            cur
        };
        assert_eq!(
            reconstructed, imt_root,
            "T3 PIR path at idx={target_idx} must reconstruct to per-tree IMT root"
        );

        // Sanity: PerLeafPathEncoder byte-agrees with Imt::merkle_proof.
        let oracle = imt.merkle_proof(target_idx as usize).expect("imt proof");
        let oracle_proof = MerkleProof {
            root: oracle.root,
            indices: oracle.indices,
            elements: oracle.elements,
        };
        assert_eq!(
            pir_siblings, oracle_proof.elements,
            "T3 PIR siblings byte-equal Imt::merkle_proof.elements at idx={target_idx}"
        );
    }
}
