//! End-to-end block test: `2^BLOCK_K` commitments at 32 bytes, served by plain
//! indexed fetch rather than PIR because the resulting record is far outside the
//! legal cell widths (see `pir_cell_width_law.rs`).
//!
//! Covers the bytes a client fetches, the subtree it recomputes, and the path it
//! splices onto the public upper tree. The oracle is independent of the block
//! encoder: everything is checked against `Imt::node` and `Imt::merkle_proof`.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::cast_possible_truncation
)]

use std::sync::Arc;

use raven_inspire::params::InspireParams;
use raven_railgun_engine::imt::TREE_DEPTH;
use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_poseidon::{merkle_node, railgun_merkle_zero_value};

/// Block exponent from the read-path design.
const BLOCK_K: usize = 10;
/// Leaf commitments per block.
const BLOCK_LEAVES: usize = 1 << BLOCK_K;
/// 1024 commitments at 32 bytes.
const BLOCK_BYTES: usize = BLOCK_LEAVES * 32;

const TREE_NUMBER: u32 = 0;
const ENTRIES_PER_SHARD: u32 = 2048;
/// Blocks 0 and 1 are full and frozen; block 2 holds 52 leaves and is the dirty tail.
const LEAVES_PRELOADED: u32 = 2_100;
const FULL_BLOCKS: usize = 2;
const PARTIAL_BLOCK: usize = 2;

fn canonical(seed: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = seed.max(1);
    b
}

fn commitment_for(leaf_index: u32) -> [u8; 32] {
    canonical(
        u8::try_from(leaf_index % 250)
            .unwrap_or(0)
            .saturating_add(1),
    )
}

fn seed_store(leaves: u32) -> LogicalLeafStore {
    let encoder: Arc<dyn PirTableEncoder> = EncoderKind::PerLeafBc
        .build(32, ENTRIES_PER_SHARD)
        .expect("encoder build");
    let mut store = LogicalLeafStore::new();
    for i in 0..leaves {
        let payload = WalEntryPayload::AppendLeaf {
            tree_number: TREE_NUMBER,
            leaf_index: i,
            commitment: commitment_for(i),
        };
        apply_wal_entry(&mut store, &payload, 100 + u64::from(i), encoder.as_ref())
            .expect("apply leaf");
    }
    store
}

/// Serialize block `block_index` from the leaf map, empty slots carrying the
/// level-0 zero value. Never reads the IMT node maps, so `Imt::node` stays an
/// independent oracle.
fn materialize_block(store: &LogicalLeafStore, block_index: usize) -> Vec<u8> {
    let mut buf = vec![0u8; BLOCK_BYTES];
    let base = block_index * BLOCK_LEAVES;
    for slot in 0..BLOCK_LEAVES {
        let leaf_index = u32::try_from(base + slot).unwrap_or(u32::MAX);
        let value = store
            .leaf(TREE_NUMBER, leaf_index)
            .copied()
            .unwrap_or_else(railgun_merkle_zero_value);
        let at = slot * 32;
        let dst = buf.get_mut(at..at + 32).expect("block slot in range");
        dst.copy_from_slice(&value);
    }
    buf
}

fn block_slot(block: &[u8], slot: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(block.get(slot * 32..slot * 32 + 32).expect("slot in range"));
    out
}

/// Recompute one block's internal nodes bottom up: `levels[0]` the leaves,
/// `levels[BLOCK_K]` the subtree root. `2^BLOCK_K - 1` hashes of client work.
fn recompute_subtree(block: &[u8]) -> Vec<Vec<[u8; 32]>> {
    let mut levels: Vec<Vec<[u8; 32]>> = Vec::with_capacity(BLOCK_K + 1);
    levels.push((0..BLOCK_LEAVES).map(|s| block_slot(block, s)).collect());
    for level in 1..=BLOCK_K {
        let below = levels.get(level - 1).expect("level below present");
        let mut current = Vec::with_capacity(below.len() / 2);
        for pair in below.chunks_exact(2) {
            let left = *pair.first().expect("left present");
            let right = *pair.get(1).expect("right present");
            current.push(merkle_node(left, right).expect("subtree hash"));
        }
        levels.push(current);
    }
    levels
}

#[test]
fn block_bytes_are_byte_identical_to_the_imt_node_oracle() {
    let store = seed_store(LEAVES_PRELOADED);
    let imt = store.imt(TREE_NUMBER).expect("tree present");

    for block_index in 0..=PARTIAL_BLOCK {
        let block = materialize_block(&store, block_index);
        assert_eq!(
            block.len(),
            BLOCK_BYTES,
            "block {block_index} must be exactly {BLOCK_BYTES} bytes"
        );
        for slot in 0..BLOCK_LEAVES {
            let expected = imt.node(0, block_index * BLOCK_LEAVES + slot);
            assert_eq!(
                block_slot(&block, slot),
                expected,
                "block {block_index} slot {slot} must byte-equal \
                 Imt::node(0, {})",
                block_index * BLOCK_LEAVES + slot
            );
        }
    }
}

#[test]
fn recomputed_subtree_root_matches_the_upper_tree_node() {
    let store = seed_store(LEAVES_PRELOADED);
    let imt = store.imt(TREE_NUMBER).expect("tree present");

    for block_index in 0..=PARTIAL_BLOCK {
        let block = materialize_block(&store, block_index);
        let levels = recompute_subtree(&block);
        let roots = levels.get(BLOCK_K).expect("subtree root level present");
        assert_eq!(roots.len(), 1, "block subtree must collapse to one root");
        let recomputed = *roots.first().expect("subtree root present");
        assert_eq!(
            recomputed,
            imt.node(BLOCK_K, block_index),
            "block {block_index}: subtree recomputed from the fetched bytes must equal \
             Imt::node({BLOCK_K}, {block_index})"
        );
    }
}

#[test]
fn spliced_path_is_byte_identical_to_the_merkle_proof_oracle() {
    let store = seed_store(LEAVES_PRELOADED);
    let imt = store.imt(TREE_NUMBER).expect("tree present");

    // First, interior, both sides of a block boundary, and the rightmost leaf.
    for leaf_index in [0u32, 511, 1_023, 1_024, 2_047, LEAVES_PRELOADED - 1] {
        let block_index = leaf_index as usize / BLOCK_LEAVES;
        let block = materialize_block(&store, block_index);
        let levels = recompute_subtree(&block);

        let mut spliced = [[0u8; 32]; TREE_DEPTH];
        let mut idx_in_block = leaf_index as usize % BLOCK_LEAVES;
        for level in 0..BLOCK_K {
            let sibling = *levels
                .get(level)
                .expect("level present")
                .get(idx_in_block ^ 1)
                .expect("sibling present");
            let slot = spliced.get_mut(level).expect("path slot present");
            *slot = sibling;
            idx_in_block >>= 1;
        }
        let mut idx_in_upper = leaf_index as usize >> BLOCK_K;
        for level in BLOCK_K..TREE_DEPTH {
            let slot = spliced.get_mut(level).expect("path slot present");
            *slot = imt.node(level, idx_in_upper ^ 1);
            idx_in_upper >>= 1;
        }

        let oracle = imt
            .merkle_proof(leaf_index as usize)
            .expect("oracle proof")
            .elements;
        assert_eq!(
            spliced, oracle,
            "leaf {leaf_index}: path spliced from block {block_index} plus the upper tree \
             is not byte-identical to Imt::merkle_proof"
        );

        let mut current = block_slot(&block, leaf_index as usize % BLOCK_LEAVES);
        for (level, sibling) in spliced.iter().enumerate() {
            let bit = (leaf_index as usize >> level) & 1;
            current = if bit == 1 {
                merkle_node(*sibling, current).expect("hash right")
            } else {
                merkle_node(current, *sibling).expect("hash left")
            };
        }
        assert_eq!(
            current,
            imt.root(),
            "leaf {leaf_index}: spliced path does not fold to Imt::root"
        );
    }
}

#[test]
fn full_blocks_freeze_and_only_the_tail_block_changes_on_append() {
    let before = seed_store(LEAVES_PRELOADED);
    let frozen: Vec<Vec<u8>> = (0..FULL_BLOCKS)
        .map(|b| materialize_block(&before, b))
        .collect();
    let tail_before = materialize_block(&before, PARTIAL_BLOCK);

    let after = seed_store(LEAVES_PRELOADED + 64);
    for block_index in 0..FULL_BLOCKS {
        assert_eq!(
            frozen.get(block_index).expect("frozen block captured"),
            &materialize_block(&after, block_index),
            "block {block_index} is full and must never change once sealed"
        );
    }
    assert_ne!(
        tail_before,
        materialize_block(&after, PARTIAL_BLOCK),
        "the rightmost partial block must change when leaves are appended; \
         if it does not, the fixture is not exercising the dirty tail"
    );
}

/// Pin `BLOCK_K` itself: the structural tests derive boundaries from it on both
/// sides and stay green at any `k`, but it is a wire-format parameter that
/// changes the bytes every client fetches.
#[test]
fn block_exponent_and_payload_are_pinned_to_the_read_path_design() {
    assert_eq!(
        BLOCK_K, 10,
        "the block exponent is a wire-format parameter and an owner decision, not a \
         tunable. Changing it resizes every fetched block and the public upper tree. \
         The structural tests in this file will NOT catch the change; re-derive the \
         payload and anonymity-set figures before editing this pin"
    );
    assert_eq!(
        BLOCK_LEAVES, 1_024,
        "block must carry 2^10 leaf commitments (anonymity set 1,024)"
    );
    assert_eq!(
        BLOCK_BYTES, 32_768,
        "block payload must be 32 KB: 1,024 commitments at 32 bytes"
    );
}

#[test]
fn db2_block_is_outside_the_pir_cell_width_range() {
    let ring_dim = InspireParams::secure_128_d2048().ring_dim;
    let num_columns = BLOCK_BYTES.div_ceil(2);
    assert!(
        num_columns > ring_dim,
        "a {BLOCK_BYTES}-byte block induces {num_columns} InspiRING columns against a \
         {ring_dim}-entry generator-power table. If this ever stops holding, the claim \
         that DB2 cannot be served by the PIR path must be re-measured, not assumed"
    );
}
