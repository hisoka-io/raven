//! Chain marks and rewinds: the table goes back to a point it held, durably, and grows
//! again from there as if it had never been past it.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

mod support;

use howl_indexer::Batch;
use howl_store::{Mark, NoteStore, StoreError, MAX_MARKS};
use support::{batch, fingerprint, CHAIN_ID, POOL};

fn open(dir: &tempfile::TempDir) -> NoteStore {
    NoteStore::open(dir.path(), CHAIN_ID, POOL).expect("open")
}

fn hash(block: u64, fork: u8) -> [u8; 32] {
    let mut out = [fork; 32];
    out[..8].copy_from_slice(&block.to_be_bytes());
    out
}

/// The same positions with other leaves: what a reorganised chain inserts there.
fn other(mut batch: Batch) -> Batch {
    for leaf in &mut batch.leaves {
        leaf.commitment[31] ^= 0xff;
        leaf.cell[10] ^= 0xff;
        if let Some(tag) = leaf.tag.as_mut() {
            tag[31] ^= 0xff;
        }
    }
    batch.checkpoint.root[0] ^= 1;
    batch
}

/// Sizes of the batches of the test chain: they cross the first seal and end in the third shard.
const SIZES: [usize; 6] = [700, 900, 800, 1_500, 600, 300];

fn chain(fork_from: usize) -> Vec<(Batch, [u8; 32])> {
    let mut first = 0;
    SIZES
        .iter()
        .enumerate()
        .map(|(i, size)| {
            let block = 100 + i as u64;
            let mut made = batch(first, *size, block);
            first += *size as u64;
            let fork = if i >= fork_from {
                made = other(made);
                1
            } else {
                0
            };
            (made, hash(block, fork))
        })
        .collect()
}

#[test]
fn a_rewind_into_a_sealed_shard_is_durable_and_the_table_grows_again() {
    let a = chain(usize::MAX);
    let b = chain(2);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(&dir);
    for (made, hash) in &a {
        store.append_at(made, *hash).expect("append");
    }
    assert_eq!(store.marks().len(), SIZES.len());
    assert_eq!(store.shard_count(), 3);

    // Back to the end of batch 1: 1,600 leaves, inside shard 0, which had sealed.
    let keep = &a[1].0.checkpoint;
    let rewound = store.rewind(keep).expect("rewind");
    assert_eq!(rewound.leaves, 1_600..a[5].0.checkpoint.leaf_count);
    assert_eq!(store.leaf_count(), 1_600);
    assert_eq!(store.resume_point(), keep);
    assert_eq!(
        store.marks(),
        &[
            Mark {
                block: 100,
                hash: a[0].1,
                leaf_count: 700
            },
            Mark {
                block: 101,
                hash: a[1].1,
                leaf_count: 1_600
            },
        ]
    );

    let mut reference = tempfile::tempdir().map(|d| (open(&d), d)).expect("tempdir");
    for (made, hash) in &b[..2] {
        reference.0.append_at(made, *hash).expect("append");
    }
    assert_eq!(fingerprint(&store), fingerprint(&reference.0));
    drop(store);
    let mut store = open(&dir);
    assert_eq!(
        fingerprint(&store),
        fingerprint(&reference.0),
        "the rewind survives a restart"
    );
    assert_eq!(store.marks(), reference.0.marks());

    for (made, hash) in &b[2..] {
        store.append_at(made, *hash).expect("append");
        reference.0.append_at(made, *hash).expect("append");
        assert_eq!(fingerprint(&store), fingerprint(&reference.0));
    }
    drop(store);
    let store = open(&dir);
    assert_eq!(fingerprint(&store), fingerprint(&reference.0));
    assert_eq!(store.marks(), reference.0.marks());
}

#[test]
fn a_rewind_to_nothing_empties_the_table() {
    let a = chain(usize::MAX);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(&dir);
    for (made, hash) in &a {
        store.append_at(made, *hash).expect("append");
    }
    let empty = howl_indexer::Checkpoint {
        leaf_count: 0,
        final_block: None,
        root: [0u8; 32],
        frontier: [[0u8; 32]; howl_indexer::TREE_DEPTH],
    };
    store.rewind(&empty).expect("rewind");
    drop(store);
    let mut store = open(&dir);
    assert_eq!((store.leaf_count(), store.shard_count()), (0, 0));
    assert!(store.marks().is_empty());
    let (made, hash) = &a[0];
    store.append_at(made, *hash).expect("the table grows again");
    assert_eq!(store.leaf_count(), 700);
}

#[test]
fn a_rewind_forward_is_refused_and_changes_nothing() {
    let a = chain(usize::MAX);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(&dir);
    for (made, hash) in &a[..3] {
        store.append_at(made, *hash).expect("append");
    }
    let before = fingerprint(&store);
    for ahead in [&a[3].0.checkpoint, &{
        let mut later_block = a[1].0.checkpoint.clone();
        later_block.final_block = Some(500);
        later_block
    }] {
        assert!(matches!(
            store.rewind(ahead),
            Err(StoreError::RewindForward { .. })
        ));
        assert_eq!(fingerprint(&store), before);
    }
}

#[test]
fn marks_are_bounded_and_survive_checkpoints_and_restarts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(&dir);
    let batches = MAX_MARKS + 61;
    for i in 0..batches {
        let made = batch(i as u64 * 3, 3, 10 + i as u64);
        if i % 7 == 0 {
            // A batch with no hash is no mark.
            store.append(&made).expect("append");
        } else {
            store
                .append_at(&made, hash(10 + i as u64, 0))
                .expect("append");
        }
        if i % 50 == 0 {
            store.checkpoint().expect("checkpoint");
        }
    }
    let marks = store.marks().to_vec();
    assert_eq!(marks.len(), MAX_MARKS);
    let newest = marks.last().expect("a mark");
    assert_eq!(newest.leaf_count, store.leaf_count());
    assert!(marks.windows(2).all(|w| w[0].block < w[1].block));
    drop(store);
    assert_eq!(open(&dir).marks(), marks.as_slice());
}
