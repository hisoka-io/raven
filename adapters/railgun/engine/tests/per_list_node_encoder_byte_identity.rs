//! Byte-identity tests for `PerListNodeEncoder` against an independent
//! `Imt::node(level, idx)` oracle, plus a cross-encoder migration guard
//! between `PerListPathEncoder` and `PerListNodeEncoder`.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::items_after_statements,
    clippy::needless_range_loop
)]

use proptest::prelude::*;
use raven_railgun_engine::imt::TREE_DEPTH;
use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::{
    PerListNodeEncoder, PerListPathEncoder, PerNodeEncoder, PirTableEncoder,
};
use raven_railgun_persistence::WalEntryPayload;

const NODE_BYTES: usize = 32;
const PATH_RECORD_BYTES: usize = TREE_DEPTH * NODE_BYTES;
const LIST_KEY: [u8; 32] = [0xA7; 32];
const LEAVES: u32 = 256;
// small so a single shard spans many flat rows, exercising row-offset math at every level
const ENTRIES_PER_SHARD: u32 = 64;

fn bc_for(idx: u32) -> [u8; 32] {
    // Fr-canonical (high bytes zero) to pass Poseidon's canonicality check
    let mut b = [0u8; 32];
    b[28..32].copy_from_slice(&idx.saturating_add(1).to_be_bytes());
    b
}

fn ppoi_payload(list_index: u32) -> WalEntryPayload {
    WalEntryPayload::PpoiListLeafAdded {
        list_key: LIST_KEY,
        list_index,
        blinded_commitment: bc_for(list_index),
        status: 0,
    }
}

fn build_store(leaves: u32) -> (LogicalLeafStore, PerListNodeEncoder) {
    let encoder = PerListNodeEncoder::new(ENTRIES_PER_SHARD, LIST_KEY).expect("encoder");
    let mut store = LogicalLeafStore::new();
    for i in 0..leaves {
        apply_wal_entry(&mut store, &ppoi_payload(i), 100 + u64::from(i), &encoder)
            .expect("apply ppoi leaf");
    }
    (store, encoder)
}

fn read_row(
    encoder: &PerListNodeEncoder,
    store: &LogicalLeafStore,
    flat_index: u32,
) -> [u8; NODE_BYTES] {
    let shard_id = flat_index / ENTRIES_PER_SHARD;
    let row_offset = (flat_index % ENTRIES_PER_SHARD) as usize;
    let buf = encoder.materialize_shard(shard_id, store);
    let start = row_offset * NODE_BYTES;
    let mut out = [0u8; NODE_BYTES];
    out.copy_from_slice(&buf[start..start + NODE_BYTES]);
    out
}

#[test]
fn per_list_node_row_byte_identity_vs_imt_node_walk_at_level_0() {
    let (store, encoder) = build_store(LEAVES);
    let imt = store.ppoi_imt(&LIST_KEY).expect("per-list IMT present");

    for leaf_idx in 0u32..LEAVES {
        let flat = PerNodeEncoder::flat_index(0, leaf_idx);
        let row = read_row(&encoder, &store, flat);
        let expected = imt.node(0, leaf_idx as usize);
        assert_eq!(
            row, expected,
            "level-0 row at leaf_idx {leaf_idx} (flat {flat}) byte mismatch"
        );
        assert_eq!(
            row,
            bc_for(leaf_idx),
            "level-0 row at leaf_idx {leaf_idx} must equal blinded commitment"
        );
    }
}

#[test]
fn per_list_node_row_byte_identity_at_level_1_and_level_8() {
    let (store, encoder) = build_store(LEAVES);
    let imt = store.ppoi_imt(&LIST_KEY).expect("per-list IMT present");

    let level1_indices: Vec<u32> = (0u32..16)
        .chain(((LEAVES / 2).saturating_sub(8))..(LEAVES / 2))
        .collect();
    for idx in level1_indices {
        let flat = PerNodeEncoder::flat_index(1, idx);
        let row = read_row(&encoder, &store, flat);
        let expected = imt.node(1, idx as usize);
        assert_eq!(
            row, expected,
            "level-1 row at idx {idx} (flat {flat}) byte mismatch"
        );
        // non-zero guard: returning the per-level zero hash for a populated subtree would pass == but fail here
        if (idx as usize) < (LEAVES as usize / 2) {
            assert_ne!(
                row, [0u8; NODE_BYTES],
                "level-1 idx {idx} should be a populated node, not the zero placeholder"
            );
        }
    }

    // with LEAVES = 2^8, level 8 has exactly one populated node; the rest exercise the zero-cache fall-through
    let level8_indices: Vec<u32> = (0u32..16).collect();
    let mut populated_seen = false;
    for idx in level8_indices {
        let flat = PerNodeEncoder::flat_index(8, idx);
        let row = read_row(&encoder, &store, flat);
        let expected = imt.node(8, idx as usize);
        assert_eq!(
            row, expected,
            "level-8 row at idx {idx} (flat {flat}) byte mismatch"
        );
        if row != [0u8; NODE_BYTES] {
            populated_seen = true;
        }
    }
    assert!(
        populated_seen,
        "expected at least one populated level-8 node within first 16 positions"
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        ..ProptestConfig::default()
    })]

    #[test]
    fn per_list_node_row_byte_identity_via_random_property_test(
        leaf_idx in 0u32..LEAVES,
    ) {
        let (store, encoder) = build_store(LEAVES);
        let imt = store.ppoi_imt(&LIST_KEY).expect("per-list IMT present");

        for level in 0..TREE_DEPTH {
            let sibling_idx_at_level = (leaf_idx >> level) ^ 1;
            let flat = PerNodeEncoder::flat_index(
                u32::try_from(level).unwrap_or(u32::MAX),
                sibling_idx_at_level,
            );
            let encoder_sibling = read_row(&encoder, &store, flat);
            let oracle_sibling = imt.node(level, sibling_idx_at_level as usize);
            prop_assert_eq!(
                encoder_sibling,
                oracle_sibling,
                "leaf {} level {} sibling-idx {} byte mismatch (flat {})",
                leaf_idx, level, sibling_idx_at_level, flat
            );
        }
    }
}

#[test]
fn per_list_node_and_per_list_path_agree_on_auth_path_bytes() {
    let path_encoder = PerListPathEncoder::new(PATH_RECORD_BYTES, ENTRIES_PER_SHARD, LIST_KEY)
        .expect("per-list-path encoder");
    let node_encoder = PerListNodeEncoder::new(ENTRIES_PER_SHARD, LIST_KEY).expect("encoder");

    let mut store = LogicalLeafStore::new();
    for i in 0..LEAVES {
        // any encoder yields correct store state; the dirty-shard set differs but IMT growth does not
        apply_wal_entry(
            &mut store,
            &ppoi_payload(i),
            100 + u64::from(i),
            &node_encoder,
        )
        .expect("apply ppoi leaf");
    }

    let leaves_to_check = [0u32, 1, 7, 17, 64, 128, 200, LEAVES - 1];

    for leaf_idx in leaves_to_check {
        let path_shard_id = leaf_idx / ENTRIES_PER_SHARD;
        let path_row_offset = (leaf_idx % ENTRIES_PER_SHARD) as usize;
        let path_buf = path_encoder.materialize_shard(path_shard_id, &store);
        let row_start = path_row_offset * PATH_RECORD_BYTES;
        let mut path_siblings = [[0u8; NODE_BYTES]; TREE_DEPTH];
        for level in 0..TREE_DEPTH {
            let s = row_start + level * NODE_BYTES;
            path_siblings[level].copy_from_slice(&path_buf[s..s + NODE_BYTES]);
        }

        let mut node_siblings = [[0u8; NODE_BYTES]; TREE_DEPTH];
        for level in 0..TREE_DEPTH {
            let sibling_idx_at_level = (leaf_idx >> level) ^ 1;
            let flat = PerNodeEncoder::flat_index(
                u32::try_from(level).unwrap_or(u32::MAX),
                sibling_idx_at_level,
            );
            node_siblings[level] = read_row(&node_encoder, &store, flat);
        }

        for level in 0..TREE_DEPTH {
            assert_eq!(
                path_siblings[level], node_siblings[level],
                "leaf {leaf_idx} level {level}: per-list-path vs per-list-node sibling byte mismatch"
            );
        }
    }
}
