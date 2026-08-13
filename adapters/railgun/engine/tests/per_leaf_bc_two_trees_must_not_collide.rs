//! Tree-local row indexing is safe ONLY when one `LogicalLeafStore` holds one tree.
//!
//! `leaves` is a `BTreeMap<(tree, leaf), [u8; 32]>` and iterates key-ascending, so if the
//! row index discards the tree, `(1, 5)` overwrites row 5 after `(0, 5)` - the higher tree
//! silently wins a row that was previously correct. The single-instance bridge
//! (`orchestrator.rs` `indexer_to_consumer_bridge`) applies no tree filter, so a store CAN
//! hold two trees on that path. The invariant therefore has to live in the encoder, which
//! is why `PerLeafBc` carries its tree.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::{PerLeafCommitmentEncoder, PirTableEncoder};
use raven_railgun_persistence::WalEntryPayload;

const RECORD: usize = 32;
const EPS: u32 = 2048;
const SHARED_LEAF: u32 = 5;

fn enc_for(tree_number: u32) -> PerLeafCommitmentEncoder {
    PerLeafCommitmentEncoder::new(RECORD, EPS, tree_number).expect("encoder")
}

fn commitment(seed: u8) -> [u8; 32] {
    let mut c = [0u8; 32];
    c[31] = seed;
    c
}

fn append(tree: u32, leaf: u32, seed: u8) -> WalEntryPayload {
    WalEntryPayload::AppendLeaf {
        tree_number: tree,
        leaf_index: leaf,
        commitment: commitment(seed),
    }
}

fn row(bytes: &[u8], idx: usize) -> &[u8] {
    bytes
        .get(idx * RECORD..(idx + 1) * RECORD)
        .expect("row in range")
}

/// The regression: a tree-1 leaf at the same index must not overwrite tree 0's row.
#[test]
fn a_foreign_tree_leaf_does_not_overwrite_this_trees_row() {
    let encoder = enc_for(0);
    let mut store = LogicalLeafStore::new();

    // Contiguous fill so both trees legitimately hold leaf SHARED_LEAF.
    for leaf in 0..=SHARED_LEAF {
        apply_wal_entry(
            &mut store,
            &append(0, leaf, 0x10 + u8::try_from(leaf).expect("<6")),
            100,
            &encoder,
        )
        .expect("tree 0 leaf applies");
    }
    let before = encoder.materialize_shard(0, &store);
    let tree0_row = row(&before, SHARED_LEAF as usize).to_vec();
    assert_eq!(
        tree0_row,
        commitment(0x10 + u8::try_from(SHARED_LEAF).expect("<6")),
        "precondition: tree 0's row holds tree 0's commitment"
    );

    // The single-instance bridge forwards every tree, so this reaches the same store.
    for leaf in 0..=SHARED_LEAF {
        apply_wal_entry(
            &mut store,
            &append(1, leaf, 0xA0 + u8::try_from(leaf).expect("<6")),
            200,
            &encoder,
        )
        .expect("a tree-1 leaf reaches the store on the unfiltered path");
    }

    let after = encoder.materialize_shard(0, &store);
    assert_eq!(
        row(&after, SHARED_LEAF as usize),
        &tree0_row[..],
        "a tree-1 leaf overwrote tree 0's row: the encoder must serve only the tree it is \
         pinned to, or a single-instance deployment silently publishes another tree's \
         commitment at this index"
    );
    assert_eq!(
        after, before,
        "no tree-1 leaf may change any byte of a tree-0 shard"
    );
}

/// An encoder pinned to tree 1 serves tree 1's rows from the same shared store.
#[test]
fn an_encoder_pinned_to_tree_one_serves_tree_one() {
    let e0 = enc_for(0);
    let e1 = enc_for(1);
    let mut store = LogicalLeafStore::new();
    for leaf in 0..=SHARED_LEAF {
        let s = u8::try_from(leaf).expect("<6");
        apply_wal_entry(&mut store, &append(0, leaf, 0x10 + s), 100, &e0).expect("t0");
        apply_wal_entry(&mut store, &append(1, leaf, 0xA0 + s), 200, &e0).expect("t1");
    }
    assert_eq!(
        row(&e0.materialize_shard(0, &store), SHARED_LEAF as usize),
        &commitment(0x10 + u8::try_from(SHARED_LEAF).expect("<6"))[..],
    );
    assert_eq!(
        row(&e1.materialize_shard(0, &store), SHARED_LEAF as usize),
        &commitment(0xA0 + u8::try_from(SHARED_LEAF).expect("<6"))[..],
        "the tree-1 encoder must serve tree 1's commitment at the same row index"
    );
}

/// A foreign-tree insert dirties nothing, so a commit cannot be driven by it.
#[test]
fn a_foreign_tree_leaf_dirties_no_shard() {
    let encoder = enc_for(0);
    assert!(
        encoder.affected_shards_for_leaf(1, SHARED_LEAF).is_empty(),
        "tree 1 is outside this encoder's pin and must dirty nothing"
    );
    assert_eq!(
        encoder
            .affected_shards_for_leaf(0, SHARED_LEAF)
            .into_iter()
            .collect::<Vec<_>>(),
        vec![0],
        "its own tree still dirties the shard holding that row"
    );
}
