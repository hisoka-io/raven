//! Pre-mainnet hardening: per-list IMT cache coherency under a
//! Layer-1 reorg.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use raven_railgun_engine::imt::TREE_DEPTH;
use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::{PerListNodeEncoder, PerNodeEncoder, PirTableEncoder};
use raven_railgun_persistence::WalEntryPayload;

const LIST_KEY: [u8; 32] = [0x77; 32];
const ENTRIES_PER_SHARD: u32 = 64;
const NODE_BYTES: usize = 32;

const TOTAL_LEAVES: u32 = 100;
/// Surviving leaf count after the synthetic L1 reorg. Pinned to the
/// hardening-spec target of 70 BC. The rewind value below is derived
/// from this so the on-disk math stays internally consistent: heights
/// are dense (one block per leaf), so dropping `TOTAL_LEAVES -
/// REORG_BOUNDARY = 30` indices means rewinding the same 30 blocks
/// from the chain tip.
const REORG_BOUNDARY: u32 = 70;
/// Size of the synthetic Layer-1 rewind in blocks. Equals
/// `TOTAL_LEAVES - REORG_BOUNDARY` because every per-list leaf was
/// applied at a distinct height (one per block); a deeper rewind on
/// the same dense layout would drop more leaves.
const REORG_REWIND_BLOCKS: u64 = (TOTAL_LEAVES - REORG_BOUNDARY) as u64;

const FIRST_LEAF_HEIGHT: u64 = 100;

fn old_bc_for(idx: u32) -> [u8; 32] {
    // BN254-Fr-canonical encoding (high bytes zero so Poseidon's
    // canonicality check inside `Imt::insert_leaves` accepts the leaf).
    // Tag the OLD generation in byte 27 so a stale-cache regression
    // (returning OLD bytes when the test expects NEW) surfaces
    // immediately on a byte compare.
    let mut b = [0u8; 32];
    b[27] = 0xAA;
    b[28..32].copy_from_slice(&(idx + 1).to_be_bytes());
    b
}

fn new_bc_for(idx: u32) -> [u8; 32] {
    // Same Fr-canonical layout, distinct generation tag in byte 27.
    let mut b = [0u8; 32];
    b[27] = 0xBB;
    b[28..32].copy_from_slice(&(idx + 1).to_be_bytes());
    b
}

fn ppoi_payload_with(list_index: u32, bc: [u8; 32]) -> WalEntryPayload {
    WalEntryPayload::PpoiListLeafAdded {
        list_key: LIST_KEY,
        list_index,
        blinded_commitment: bc,
        status: 0,
    }
}

/// Read the row at `flat_index` from the encoder's materialized shard.
/// Mirror of the helper in `per_list_node_encoder_byte_identity.rs`.
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
fn per_list_imt_reorg_coherency_drops_and_reinserts_without_stale_cache_hits() {
    let encoder = PerListNodeEncoder::new(ENTRIES_PER_SHARD, LIST_KEY).expect("encoder");
    let mut store = LogicalLeafStore::new();

    // Stage 1: seed 100 leaves at heights 100..199 (one per block).
    for i in 0..TOTAL_LEAVES {
        let height = FIRST_LEAF_HEIGHT + u64::from(i);
        apply_wal_entry(
            &mut store,
            &ppoi_payload_with(i, old_bc_for(i)),
            height,
            &encoder,
        )
        .expect("seed leaf");
    }
    assert_eq!(
        store
            .ppoi_imt(&LIST_KEY)
            .expect("per-list IMT present")
            .leaf_count(),
        TOTAL_LEAVES as usize,
        "all 100 leaves applied"
    );

    let pre_root = store.ppoi_imt_root(&LIST_KEY).expect("pre-reorg root");

    for i in 0..TOTAL_LEAVES {
        let proof = store.ppoi_merkle_proof(&LIST_KEY, i).expect("path");
        assert_eq!(
            proof.root, pre_root,
            "pre-reorg path at idx {i} must reconstruct to pre-reorg root"
        );
    }

    // Capture the OLD leaf-row bytes at indices 70..99 from the
    // materialized shard. Used post-reorg to assert NEW bytes are
    // surfaced (stale-cache-hit regression guard).
    let mut old_leaf_rows = [[0u8; NODE_BYTES]; (TOTAL_LEAVES - REORG_BOUNDARY) as usize];
    for (slot, idx) in (REORG_BOUNDARY..TOTAL_LEAVES).enumerate() {
        let flat = PerNodeEncoder::flat_index(0, idx);
        old_leaf_rows[slot] = read_row(&encoder, &store, flat);
    }

    // Stage 2: synthetic Layer-1 reorg. Rewind 30 blocks from the chain
    // tip (199) -> reorg-height = 169. Engine drops every per-list leaf
    // with block_height > 169 (heights 170..=199 = indices 70..=99 = 30
    // leaves), truncating the per-list IMT to REORG_BOUNDARY = 70.
    let chain_tip = FIRST_LEAF_HEIGHT + u64::from(TOTAL_LEAVES - 1);
    let reorg_height = chain_tip - REORG_REWIND_BLOCKS;
    apply_wal_entry(
        &mut store,
        &WalEntryPayload::Reorg {
            height: reorg_height,
        },
        reorg_height,
        &encoder,
    )
    .expect("reorg");

    // Compute the surviving leaf count. Leaves applied at
    // height `FIRST_LEAF_HEIGHT + i` survive iff
    // `FIRST_LEAF_HEIGHT + i <= reorg_height`, i.e.
    // `i <= reorg_height - FIRST_LEAF_HEIGHT`. So survivors are
    // `i in [0, reorg_height - FIRST_LEAF_HEIGHT]` inclusive
    // (count = reorg_height - FIRST_LEAF_HEIGHT + 1).
    let survivors = u32::try_from(reorg_height - FIRST_LEAF_HEIGHT + 1).expect("u32");
    assert_eq!(
        store
            .ppoi_imt(&LIST_KEY)
            .expect("per-list IMT survives reorg")
            .leaf_count() as u32,
        survivors,
        "post-reorg per-list IMT must hold exactly {survivors} leaves",
    );

    let post_reorg_root = store
        .ppoi_imt_root(&LIST_KEY)
        .expect("post-reorg root present");
    assert_ne!(
        pre_root, post_reorg_root,
        "post-reorg root MUST differ from pre-reorg root (truncated leaves changed the tree)"
    );

    for i in survivors..TOTAL_LEAVES {
        let res = store.ppoi_merkle_proof(&LIST_KEY, i);
        assert!(
            res.is_err(),
            "path query at dropped idx {i} must Err post-reorg, got Ok"
        );
    }
    for i in 0..survivors {
        let proof = store
            .ppoi_merkle_proof(&LIST_KEY, i)
            .expect("survivor path");
        assert_eq!(
            proof.root, post_reorg_root,
            "surviving path at idx {i} must reconstruct to post-reorg root"
        );
    }

    // Stage 3: re-insert NEW commitments at the dropped indices with
    // distinct BC tags + post-reorg block heights. A stale-cache
    // regression (leftover OLD bytes in the materialized shard buffer)
    // surfaces here as a byte mismatch against new_bc_for().
    let next_height = chain_tip + 1;
    for (slot, idx) in (survivors..TOTAL_LEAVES).enumerate() {
        let height = next_height + u64::from(slot as u32);
        apply_wal_entry(
            &mut store,
            &ppoi_payload_with(idx, new_bc_for(idx)),
            height,
            &encoder,
        )
        .expect("reinsert leaf");
    }
    assert_eq!(
        store
            .ppoi_imt(&LIST_KEY)
            .expect("per-list IMT")
            .leaf_count() as u32,
        TOTAL_LEAVES,
        "all 100 leaves restored post-reinsert"
    );

    let post_reinsert_root = store.ppoi_imt_root(&LIST_KEY).expect("post-reinsert root");
    assert_ne!(
        post_reorg_root, post_reinsert_root,
        "post-reinsert root must differ from post-reorg-truncated root"
    );
    assert_ne!(
        pre_root, post_reinsert_root,
        "post-reinsert root must differ from pre-reorg root (different commitments)"
    );

    // Stage 3 path-query invariant: every index 0..100 succeeds, AND
    // the per-list `(list_index -> blinded_commitment)` lookup
    // returns the right generation. `MerkleProof` carries only
    // `(root, indices, elements)`; the leaf bytes live in the store's
    // `ppoi_bc_at` map. A stale-cache regression would surface as
    // either a wrong root/elements (path mis-reconstructs) OR a wrong
    // BC at the re-inserted indices.
    for i in 0..TOTAL_LEAVES {
        let proof = store
            .ppoi_merkle_proof(&LIST_KEY, i)
            .expect("post-reinsert path");
        assert_eq!(
            proof.root, post_reinsert_root,
            "post-reinsert path at idx {i} must reconstruct to the latest root"
        );
        let leaf_bc = store.ppoi_bc_at(&LIST_KEY, i).expect("bc at idx");
        if i < survivors {
            // OLD-generation BC at unchanged indices.
            assert_eq!(
                leaf_bc,
                old_bc_for(i),
                "surviving idx {i} must still hold the OLD-generation BC bytes"
            );
        } else {
            // NEW-generation BC at re-inserted indices. THIS is the
            // stale-cache-hit guard: a regression that returns
            // old_bc_for(i) here would mean the per-list maps held
            // onto the pre-reorg commitment under the same index.
            assert_eq!(
                leaf_bc,
                new_bc_for(i),
                "re-inserted idx {i} must reflect the NEW-generation BC bytes; \
                 a regression returning old_bc_for({i}) would indicate a stale \
                 cache hit / reorg-cleanup gap in the per-list BC map"
            );
        }
    }

    // Stage 3 byte-level invariant: the materialized shard rows at
    // indices >= survivors hold the NEW BC bytes, NOT the captured
    // OLD bytes from stage 1.
    for (slot, idx) in (survivors..TOTAL_LEAVES).enumerate() {
        let flat = PerNodeEncoder::flat_index(0, idx);
        let post_reinsert_row = read_row(&encoder, &store, flat);
        assert_ne!(
            post_reinsert_row, old_leaf_rows[slot],
            "materialized shard row at idx {idx} must NOT be byte-identical to \
             the pre-reorg row; a regression that re-uses the OLD shard buffer \
             would surface here"
        );
        assert_eq!(
            post_reinsert_row,
            new_bc_for(idx),
            "materialized shard row at re-inserted idx {idx} must hold the NEW BC bytes"
        );
    }

    // Stage 4: dirty-shard tracking. The encoder's
    // `affected_shards_for_ppoi_leaf(list_key, list_index)` MUST return
    // at least the leaf-row's shard id for every re-inserted index. The
    // store's `dirty_shards()` set must be a superset of every per-leaf
    // affected shard for the indices we inserted + reorged.
    let dirty: &std::collections::BTreeSet<u32> = store.dirty_shards();
    let depth = u32::try_from(TREE_DEPTH).expect("depth fits in u32");
    for idx in survivors..TOTAL_LEAVES {
        // Walk the affected_shards_for_ppoi_leaf return value: the
        // leaf row + every ancestor up the tree. Each shard id MUST
        // be in dirty_shards().
        let affected = encoder.affected_shards_for_ppoi_leaf(&LIST_KEY, idx);
        assert!(
            !affected.is_empty(),
            "affected_shards_for_ppoi_leaf at idx {idx} must mark at least one shard"
        );
        for shard in &affected {
            assert!(
                dirty.contains(shard),
                "dirty_shards() must contain shard {shard} for re-inserted idx {idx} \
                 (per-list-node encoder dirties the leaf row + each of its {} ancestors)",
                depth + 1
            );
        }
    }

    // Sanity: the re-inserted indices' leaf rows live in shards whose
    // ids are deterministic from the per-node flat layout. Compute
    // the expected leaf-row shard id directly + assert it's marked
    // dirty (independent oracle for the affected-set check above).
    for idx in survivors..TOTAL_LEAVES {
        let leaf_flat = PerNodeEncoder::flat_index(0, idx);
        let expected_shard = leaf_flat / ENTRIES_PER_SHARD;
        assert!(
            dirty.contains(&expected_shard),
            "leaf-row shard {expected_shard} for re-inserted idx {idx} must be \
             dirty (independent compute, not via encoder.affected_shards_for_ppoi_leaf)"
        );
    }
}
