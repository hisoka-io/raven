//! A row the server materialized, plus the addendum that same commit derived, folds to the root
//! that commit published.
//!
//! A wallet gets eleven siblings inside the PPOI v2 row and five beside it; nothing closed the
//! pair against a root before this file. Leaves are chosen here and never read back from the
//! store, and the root is rebuilt outside `Imt`, so a tree that is wrong the same way everywhere
//! still fails.
//!
//! `entries_per_shard == 2^PATH10_LEVELS` is load-bearing rather than incidental: it is the
//! shipped width and the only one at which two shards sit in different level-11 subtrees. Any
//! narrower and every shard shares one addendum, which hides a shard misalignment entirely.

#![allow(clippy::expect_used, clippy::indexing_slicing)]

use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_engine::imt::TREE_DEPTH;
use raven_railgun_engine::inspire::{apply_wal_entry, setup_state, LogicalLeafStore};
use raven_railgun_engine::orchestrator::LEAVES_PER_PPOI_BLOCK;
use raven_railgun_engine::pir_table::list::{PATH10_LEVELS, PATH10_MAGIC};
use raven_railgun_engine::pir_table::{PerListPath10Encoder, PirTableEncoder, PATH10_RECORD_BYTES};
use raven_railgun_persistence::{PpoiEventType, WalEntryPayload};
use raven_railgun_poseidon::merkle_node;

mod naive_imt;

const LIST_KEY: [u8; 32] = [0x71; 32];
const BLOCK: u32 = 1;
const ENTRIES_PER_SHARD: u32 = 1 << PATH10_LEVELS;
const LEAVES: u32 = ENTRIES_PER_SHARD + 37;
const NODE_BYTES: usize = 32;
const MAGIC_AT: usize = 34;
const SIBLINGS_AT: usize = 38;
const ADDENDUM_BYTES: usize = (TREE_DEPTH - PATH10_LEVELS) * NODE_BYTES;

// A second shard must be populated, or the shard-misalignment property has nothing to compare.
const _: () = assert!(LEAVES > ENTRIES_PER_SHARD);
// A block-0 fixture would hold the global indices unchanged and exercise no localization.
const _: () = assert!(BLOCK != 0);

/// First and last row of each shard, and both sides of the shard boundary.
const TARGETS: [u32; 6] = [
    0,
    1,
    ENTRIES_PER_SHARD - 1,
    ENTRIES_PER_SHARD,
    ENTRIES_PER_SHARD + 1,
    LEAVES - 1,
];

/// Root of the tree below, from the naive rebuild. If `merkle_node`, the zero value or the fold
/// order drift, the rebuild moves with them and this constant is what still fails.
const PINNED_ROOT: [u8; 32] = [
    0x15, 0x36, 0x94, 0xd0, 0x6b, 0x9a, 0x11, 0x0c, 0x9c, 0xa8, 0x24, 0x89, 0x62, 0x05, 0xf3, 0x4a,
    0x76, 0xa4, 0x50, 0x42, 0xd7, 0xf2, 0xf7, 0xd3, 0x2b, 0x80, 0xd3, 0x84, 0x7b, 0x40, 0x73, 0x92,
];

/// The global list index a block-`BLOCK` instance stores at local index `local`, the inverse of
/// the router's `list_index % LEAVES_PER_PPOI_BLOCK`.
fn global_index(local: u32) -> u32 {
    BLOCK
        .saturating_mul(LEAVES_PER_PPOI_BLOCK)
        .saturating_add(local)
}

/// Fr-canonical by construction.
fn bc_for_global(global: u32) -> [u8; 32] {
    let mut bc = [0u8; 32];
    bc[28..32].copy_from_slice(&global.saturating_add(1).to_be_bytes());
    bc
}

/// Keyed on the GLOBAL index, so the fixture is this block's and not block 0's.
fn leaf_value(local: u32) -> [u8; 32] {
    bc_for_global(global_index(local))
}

/// Provenance is pointer identity; the fold never reads these bytes.
fn committed_database() -> Arc<raven_inspire::EncodedDatabase> {
    let params = InspireParams::secure_128_d2048();
    let db = raven_railgun_testkit::toy_db(raven_railgun_testkit::TOY_ENTRIES, 32);
    let (state, _secret_key) =
        setup_state(&params, &db, 32, InspireVariant::TwoPacking).expect("toy setup_state");
    state.encoded_db
}

/// A block instance filled through the WAL path, then committed the way `drive_commit` commits:
/// publish, then derive the addenda from the tree that publication was encoded from.
fn committed_store() -> (LogicalLeafStore, PerListPath10Encoder) {
    let encoder = PerListPath10Encoder::new(ENTRIES_PER_SHARD, LIST_KEY).expect("path10 encoder");
    let mut store = LogicalLeafStore::new();
    for local in 0..LEAVES {
        apply_wal_entry(
            &mut store,
            &WalEntryPayload::PpoiListLeafAdded {
                list_key: LIST_KEY,
                list_index: local,
                blinded_commitment: leaf_value(local),
                event_type: PpoiEventType::Shield,
                validated_merkleroot: [0; 32],
            },
            u64::from(local),
            &encoder,
        )
        .expect("append localized block leaf");
    }
    store.refresh_committed_addenda(&committed_database(), ENTRIES_PER_SHARD);
    (store, encoder)
}

fn row_of(shard: &[u8], local: u32) -> &[u8] {
    let start = (local % ENTRIES_PER_SHARD) as usize * PATH10_RECORD_BYTES;
    shard
        .get(start..start + PATH10_RECORD_BYTES)
        .expect("row within materialized shard")
}

fn addendum_of(store: &LogicalLeafStore, shard_id: u32) -> Vec<u8> {
    store
        .committed_addendum(&LIST_KEY, shard_id)
        .expect("committed addendum for a populated shard")
        .to_vec()
}

/// Levels 0..=10 ride in the row and 11..=15 ride beside it. This split IS the level cut.
fn sibling_at(row: &[u8], addendum: &[u8], level: usize) -> [u8; 32] {
    let bytes = if level < PATH10_LEVELS {
        let at = SIBLINGS_AT + level * NODE_BYTES;
        row.get(at..at + NODE_BYTES)
    } else {
        let at = (level - PATH10_LEVELS) * NODE_BYTES;
        addendum.get(at..at + NODE_BYTES)
    };
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes.expect("sibling within the served pair"));
    out
}

/// The wallet's fold: the LOCAL index supplies the path bits, exactly as the SDK folds it.
fn fold_to_root(local: u32, leaf: [u8; 32], row: &[u8], addendum: &[u8]) -> [u8; 32] {
    let mut current = leaf;
    for level in 0..TREE_DEPTH {
        let sibling = sibling_at(row, addendum, level);
        current = if (local >> level) & 1 == 1 {
            merkle_node(sibling, current)
        } else {
            merkle_node(current, sibling)
        }
        .expect("fold");
    }
    current
}

#[test]
fn a_served_row_and_its_committed_addendum_fold_to_the_committed_root() {
    let (store, encoder) = committed_store();
    let committed_root = store.ppoi_imt_root(&LIST_KEY).expect("per-list root");

    let zeros = naive_imt::zero_chain();
    let leaves: Vec<[u8; 32]> = (0..LEAVES).map(leaf_value).collect();
    let levels = naive_imt::naive_levels(&leaves, &zeros);
    assert_eq!(
        committed_root,
        naive_imt::naive_root(&levels),
        "the committed root disagrees with a rebuild of the same {LEAVES} leaves"
    );

    let shards = [
        encoder.materialize_shard(0, &store),
        encoder.materialize_shard(1, &store),
    ];

    for local in TARGETS {
        let shard_id = local / ENTRIES_PER_SHARD;
        let row = row_of(&shards[shard_id as usize], local);
        let addendum = addendum_of(&store, shard_id);

        assert_eq!(
            &row[..NODE_BYTES],
            leaf_value(local).as_slice(),
            "leaf {local}: the served row carries a different blinded commitment"
        );
        assert_eq!(
            &row[MAGIC_AT..SIBLINGS_AT],
            &PATH10_MAGIC,
            "leaf {local}: the served row is not a PPOI v2 row"
        );
        assert_eq!(
            addendum.len(),
            ADDENDUM_BYTES,
            "leaf {local}: a short addendum folds to a wrong root"
        );

        for level in 0..TREE_DEPTH {
            assert_eq!(
                sibling_at(row, &addendum, level),
                naive_imt::naive_sibling(&levels, &zeros, local as usize, level),
                "leaf {local} level {level}: served sibling differs from the rebuilt tree"
            );
        }

        assert_eq!(
            fold_to_root(local, leaf_value(local), row, &addendum),
            committed_root,
            "leaf {local}: the served pair folds to a root this commit never published"
        );
    }
}

#[test]
fn a_row_folded_with_the_other_shards_addendum_does_not_close() {
    let (store, encoder) = committed_store();
    let committed_root = store.ppoi_imt_root(&LIST_KEY).expect("per-list root");
    let shard_zero = encoder.materialize_shard(0, &store);
    let own = addendum_of(&store, 0);
    let foreign = addendum_of(&store, 1);

    // Without this the mismatch below could hold vacuously, on two shards that share an addendum.
    assert_ne!(
        own, foreign,
        "the two shards must sit in different level-11 subtrees, or this proves nothing"
    );
    assert_ne!(
        fold_to_root(0, leaf_value(0), row_of(&shard_zero, 0), &foreign),
        committed_root,
        "a row served the wrong shard's upper siblings must not reach the committed root"
    );
}

#[test]
fn a_block_zero_leaf_does_not_close_against_this_blocks_root() {
    let (store, encoder) = committed_store();
    let committed_root = store.ppoi_imt_root(&LIST_KEY).expect("per-list root");
    let shard_zero = encoder.materialize_shard(0, &store);
    let addendum = addendum_of(&store, 0);

    // Localization drops the high bits, so block 0 and block 1 fold over identical path bits and
    // differ only in the commitments they hold. That difference is the whole of the block.
    assert_ne!(
        fold_to_root(0, bc_for_global(0), row_of(&shard_zero, 0), &addendum),
        committed_root,
        "the commitment a block-0 instance holds at this position must not close here"
    );
}

#[test]
fn the_committed_root_is_pinned_against_primitive_drift() {
    let zeros = naive_imt::zero_chain();
    let leaves: Vec<[u8; 32]> = (0..LEAVES).map(leaf_value).collect();
    let root = naive_imt::naive_root(&naive_imt::naive_levels(&leaves, &zeros));
    assert_eq!(
        root,
        PINNED_ROOT,
        "the rebuilt root moved off its pinned vector: merkle_node, the zero value or the fold \
         order changed. If intentional, re-pin: [{}]",
        root.map(|b| format!("0x{b:02x}")).join(", ")
    );
}
