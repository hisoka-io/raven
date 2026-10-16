//! The table end to end: chain logs in, and a wallet reads its own notes back out.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

#[path = "../../../howl/indexer/tests/support/mod.rs"]
mod chain;
mod support;
#[path = "../../../howl/indexer/tests/support/wallet.rs"]
mod wallet;

use ark_bn254::Fr;
use chain::{Fixture, Rng};
use howl_indexer::Indexer;
use howl_prefix_feed::PrefixIndex;
use howl_record::{decode, CELL_BYTES, RECORD_BYTES, RECORD_KIND_INCOMING, RECORD_KIND_SELF};
use howl_store::{
    NoteStore, Recovery, StoreError, LEAF_BLOCK_ROWS, MAX_BATCH_ROWS, MAX_LOG_BYTES,
    ROWS_PER_SHARD, SHARD_BYTES,
};
use raven_storage::PersistenceError;
use support::{batch, fingerprint, leaf, references, schedule, CHAIN_ID, POOL};

fn open(dir: &tempfile::TempDir) -> NoteStore {
    NoteStore::open(dir.path(), CHAIN_ID, POOL).expect("open")
}

/// Index the fixture chain into a store a few blocks at a time, restarting part-way.
fn indexed(fixture: &Fixture, dir: &tempfile::TempDir) -> NoteStore {
    let open = || NoteStore::open(dir.path(), fixture.chain_id, fixture.pool).expect("open");
    let mut store = open();
    let mut indexer = Indexer::new(fixture.config(3));
    let mut head = fixture.first_block;
    while store.leaf_count() < fixture.leaf_count {
        head += 11;
        if head.is_multiple_of(4) {
            // A restart: the indexer continues from what the table recorded.
            drop(store);
            store = open();
            indexer = Indexer::resume(fixture.config(3), store.resume_point()).expect("resume");
        }
        let batch = indexer.ingest(head, &fixture.logs, None).expect("ingest");
        store.append(&batch).expect("append");
    }
    store
}

fn cell_of(store: &NoteStore, position: u64) -> [u8; CELL_BYTES] {
    let shard = store
        .shard(u32::try_from(position / ROWS_PER_SHARD as u64).expect("shard"))
        .expect("shard");
    let row = (position % ROWS_PER_SHARD as u64) as usize;
    shard.cells[row * CELL_BYTES..(row + 1) * CELL_BYTES]
        .try_into()
        .expect("one cell")
}

/// The tree root over `leaves`: pairs hashed with their level, an odd node carried up.
fn fold(leaves: &[u8]) -> [u8; 32] {
    let mut nodes: Vec<Fr> = leaves
        .as_chunks::<32>()
        .0
        .iter()
        .map(wallet::scalar)
        .collect();
    let mut level = 0u64;
    while nodes.len() > 1 {
        nodes = nodes
            .chunks(2)
            .map(|pair| match pair {
                [left, right] => howl_poseidon2::hash(&[*left, *right, Fr::from(level)]),
                _ => pair[0],
            })
            .collect();
        level += 1;
    }
    wallet::bytes(nodes[0])
}

#[test]
fn a_wallet_reads_its_notes_from_the_table_the_chain_produced() {
    let fixture = Fixture::load();
    let dir = tempfile::tempdir().expect("tempdir");
    let store = indexed(&fixture, &dir);
    assert_eq!(store.leaf_count(), fixture.leaf_count);
    assert_eq!(store.resume_point().root, fixture.root);

    // Row i is leaf i, byte for byte the cell Howl's encoder writes.
    for expected in &fixture.leaves {
        let cell = cell_of(&store, u64::from(expected.leaf_index));
        match &expected.cell {
            Some(bytes) => assert_eq!(cell.as_slice(), bytes.as_slice()),
            None => assert_eq!(cell, [0u8; CELL_BYTES], "the genesis row"),
        }
    }

    for owner in &fixture.wallets {
        let mut index = PrefixIndex::new();
        loop {
            let part = store
                .prefix_segment(index.resume_cursor())
                .expect("segment");
            index.absorb(&part).expect("absorb");
            if part.is_frontier() {
                break;
            }
        }
        let tags = wallet::candidate_tags(
            &owner.sk_view,
            owner.self_keys.len() as u64,
            owner.incoming_keys.len() as u64,
        );
        let found = index.matches(&tags, 0);
        let mut owned = owner.owned_leaves.clone();
        owned.sort_unstable();
        assert_eq!(
            found.iter().map(|m| m.position as u32).collect::<Vec<_>>(),
            owned,
            "{}",
            owner.label
        );

        let own_tags = owner.self_keys.len();
        for hit in found {
            let record = decode(&cell_of(&store, hit.position)).expect("a note cell decodes");
            let leaf = &fixture.leaves[hit.position as usize];
            assert_eq!(u64::from(record.leaf_index), hit.position);
            assert_eq!(record.commitment_prefix, leaf.commitment[..16]);
            // A note found under one of the wallet's own ephemerals is a self note.
            let self_tag = owner.self_keys[..own_tags]
                .iter()
                .any(|key| key.even_y && Some(key.x) == leaf.tag);
            assert_eq!(
                record.record_kind,
                if self_tag {
                    RECORD_KIND_SELF
                } else {
                    RECORD_KIND_INCOMING
                }
            );
        }
    }
}

#[test]
fn the_published_index_is_the_expected_row_of_every_leaf() {
    let fixture = Fixture::load();
    let dir = tempfile::tempdir().expect("tempdir");
    let store = indexed(&fixture, &dir);

    // Every row the store publishes, read from row 0, against the rows the fixture
    // generator wrote: not only the rows a fixture wallet looks up.
    let served = fingerprint(&store).prefixes;
    assert_eq!(served.len() as u64, fixture.leaf_count * 6);
    assert_eq!(served[..6], [0u8; 6], "the genesis row");
    for (expected, row) in fixture.leaves.iter().zip(served.as_chunks::<6>().0) {
        assert_eq!(*row, expected.prefix, "leaf {}", expected.leaf_index);
        if let Some(tag) = &expected.tag {
            assert_eq!(row, &tag[26..32], "leaf {}", expected.leaf_index);
        }
    }
    assert_eq!(served, fixture.prefix_feed());

    drop(store);
    let reopened = NoteStore::open(dir.path(), fixture.chain_id, fixture.pool).expect("open");
    assert_eq!(fingerprint(&reopened).prefixes, fixture.prefix_feed());
}

#[test]
fn every_row_keeps_its_cell_when_a_batch_crosses_a_seal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(&dir);
    let rows = ROWS_PER_SHARD as u64;
    // The second batch fills the first shard and starts the next; the third fills two more.
    let mut held = 0u64;
    for (block, count) in [1_500usize, 1_000, 4_200, 1].into_iter().enumerate() {
        store
            .append(&batch(held, count, block as u64 + 1))
            .expect("append");
        held += count as u64;
        for restarted in [false, true] {
            if restarted {
                drop(store);
                store = open(&dir);
            }
            assert_eq!(u64::from(store.shard_count()), held.div_ceil(rows));
            for index in 0..store.shard_count() {
                let first = u64::from(index) * rows;
                let filled = held.min(first + rows) - first;
                // Each cell built on its own from the row number, not read back from a store.
                let mut expected = vec![0u8; SHARD_BYTES];
                for row in 0..filled {
                    let at = row as usize * CELL_BYTES;
                    expected[at..at + CELL_BYTES].copy_from_slice(&leaf(first + row).cell);
                }
                let shard = store.shard(index).expect("shard");
                assert_eq!(u64::from(shard.rows), filled);
                assert!(
                    shard.cells == expected,
                    "shard {index} after {held} leaves, restarted: {restarted}"
                );
            }
        }
    }
    assert_eq!(store.shard_count(), 4);
}

#[test]
fn every_cell_is_a_246_byte_record_in_256_bytes() {
    let fixture = Fixture::load();
    let dir = tempfile::tempdir().expect("tempdir");
    let store = indexed(&fixture, &dir);
    let shard = store.shard(0).expect("shard");
    assert_eq!(shard.cells.len(), SHARD_BYTES);
    assert_eq!(shard.rows as u64, fixture.leaf_count);
    assert!(!shard.is_sealed());
    for (row, cell) in shard.cells.as_chunks::<CELL_BYTES>().0.iter().enumerate() {
        assert!(
            cell[RECORD_BYTES..].iter().all(|byte| *byte == 0),
            "row {row}: the ten bytes after the record"
        );
        let filled = (1..fixture.leaf_count as usize).contains(&row);
        assert_eq!(decode(cell).is_ok(), filled, "row {row}");
        if !filled {
            assert!(cell.iter().all(|byte| *byte == 0), "row {row} is unused");
        }
    }
}

#[test]
fn an_append_changes_the_newest_shard_and_no_other() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(&dir);
    let mut rng = Rng(0x7ab1_e5ee);
    let mut sealed_files: Vec<Vec<u8>> = Vec::new();
    let mut next = 0u64;
    let mut block = 1;

    while next < 3 * ROWS_PER_SHARD as u64 + 500 {
        // Mostly single leaves and small batches; now and then one that crosses a shard.
        let count = match rng.below(8) {
            0 => 1 + rng.below(1_500) as usize,
            1..=3 => 1,
            _ => 1 + rng.below(40) as usize,
        };
        let before = fingerprint(&store).shards;
        let appended = store.append(&batch(next, count, block)).expect("append");
        let after = fingerprint(&store).shards;

        let end = next + count as u64;
        assert_eq!(appended.leaves, next..end);
        let touched = appended.shards.expect("rows were added");
        assert_eq!(*touched.start(), (next / ROWS_PER_SHARD as u64) as u32);
        assert_eq!(*touched.end(), ((end - 1) / ROWS_PER_SHARD as u64) as u32);
        if count == 1 {
            assert_eq!(touched.start(), touched.end(), "one leaf, one shard");
        }
        for (index, shard) in after.iter().enumerate() {
            let changed = before.get(index) != Some(shard);
            assert_eq!(
                changed,
                touched.contains(&(index as u32)),
                "shard {index} after leaves {next}..{end}"
            );
        }

        // A sealed shard's file is written once and stays as written.
        let sealed = (end / ROWS_PER_SHARD as u64) as usize;
        for index in 0..sealed {
            let bytes = std::fs::read(dir.path().join(format!("shards/shard-{index:08}.bin")))
                .expect("sealed shard file");
            match sealed_files.get(index) {
                Some(first) => assert_eq!(&bytes, first, "sealed shard {index} was rewritten"),
                None => sealed_files.push(bytes),
            }
            assert!(store.shard(index as u32).expect("shard").is_sealed());
        }
        next = end;
        block += 1;
    }
    assert_eq!(sealed_files.len(), 3);
    assert_eq!(
        std::fs::read_dir(dir.path().join("shards"))
            .expect("shards")
            .count(),
        3
    );
}

#[test]
fn a_restart_or_a_torn_log_loses_nothing_that_was_acknowledged() {
    let mut batches = schedule(&[900, 300, 1_200, 40, 2_500, 77]);
    batches.push(batch(5_017, 25, 2_000));
    let expected = references(&batches);
    let last = batches.pop().expect("the batch that is torn");
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(&dir);
    for (done, batch) in batches.iter().enumerate() {
        store.append(batch).expect("append");
        drop(store);
        store = open(&dir);
        assert_eq!(fingerprint(&store), expected[done], "batch {done}");
    }

    // The process dies inside the next write: the frame is cut short on disk.
    assert_eq!(last.leaves[0].leaf_index as u64, store.leaf_count());
    let log = dir.path().join("wal/current.log");
    let before = std::fs::metadata(&log).expect("log").len();
    store.append(&last).expect("append");
    drop(store);
    let after = std::fs::metadata(&log).expect("log").len();
    assert!(after > before);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&log)
        .expect("log")
        .set_len(after - 100)
        .expect("truncate");

    // The table is the one before that batch, and says so, so the indexer repeats it.
    let mut store = open(&dir);
    assert_eq!(fingerprint(&store), expected[5]);
    assert_eq!(store.recovery().cut_bytes, after - 100 - before);
    assert_eq!(store.resume_point(), &batches[5].checkpoint);
    store.append(&last).expect("the batch again");
    assert_eq!(fingerprint(&store), expected[6]);
}

#[test]
fn batches_without_leaves_leave_a_bounded_log() {
    const POLLS: u64 = 3_000;
    let size = |path: &std::path::Path| std::fs::metadata(path).expect("file").len();
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("wal/current.log");
    let mut store = open(&dir);
    store.append(&batch(0, 100, 1)).expect("append");
    let table = fingerprint(&store);

    let before = size(&log);
    store.append(&batch(100, 0, 2)).expect("append");
    let frame = size(&log) - before;
    assert!(
        POLLS * frame > 3 * MAX_LOG_BYTES,
        "the polls alone outgrow the bound several times"
    );

    // A driver that polls a quiet chain: the final block moves and no leaf arrives.
    let mut largest = 0;
    for poll in 0..POLLS {
        let appended = store.append(&batch(100, 0, 3 + poll)).expect("append");
        assert_eq!((appended.leaves, appended.shards), (100..100, None));
        largest = largest.max(size(&log));
    }
    assert!(
        largest <= MAX_LOG_BYTES,
        "the log reached {largest} bytes between two seals"
    );
    // What was retired is kept in pieces of the same bound.
    let retired: Vec<u64> = std::fs::read_dir(dir.path().join("wal/archived"))
        .expect("retired logs")
        .map(|entry| size(&entry.expect("entry").path()))
        .collect();
    assert!((3..=16).contains(&retired.len()), "{retired:?}");
    assert!(
        retired.iter().all(|bytes| *bytes <= MAX_LOG_BYTES + frame),
        "{retired:?}"
    );

    // A restart reads no more than the bound, and loses neither the table nor the block.
    drop(store);
    let store = open(&dir);
    let recovery = store.recovery();
    assert!(recovery.log_bytes <= MAX_LOG_BYTES, "{recovery:?}");
    assert!(
        recovery.replayed_batches as u64 <= MAX_LOG_BYTES / frame + 1,
        "{recovery:?}"
    );
    assert_eq!(recovery.cut_bytes, 0);
    assert_eq!(store.resume_point().final_block, Some(2 + POLLS));
    let after = fingerprint(&store);
    assert_eq!(
        (after.leaf_count, after.shards, after.prefixes, after.leaves),
        (table.leaf_count, table.shards, table.prefixes, table.leaves)
    );
}

#[test]
fn a_log_cut_on_open_is_reported() {
    let batches = schedule(&[100, 100, 100, 100]);
    let expected = references(&batches);
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("wal/current.log");
    let mut store = open(&dir);
    assert_eq!(
        store.recovery(),
        Recovery {
            replayed_batches: 0,
            log_bytes: 0,
            cut_bytes: 0
        }
    );
    let mut ends = Vec::new();
    for batch in &batches {
        store.append(batch).expect("append");
        ends.push(std::fs::metadata(&log).expect("log").len());
    }
    drop(store);

    // A clean restart replays every batch and cuts nothing.
    assert_eq!(
        open(&dir).recovery(),
        Recovery {
            replayed_batches: 4,
            log_bytes: ends[3],
            cut_bytes: 0
        }
    );

    // One bit flips inside the second batch. That batch and the two after it are gone.
    let mut bytes = std::fs::read(&log).expect("log");
    bytes[ends[0] as usize + 500] ^= 1;
    std::fs::write(&log, &bytes).expect("write");
    let mut store = open(&dir);
    assert_eq!(fingerprint(&store), expected[0]);
    assert_eq!(
        store.recovery(),
        Recovery {
            replayed_batches: 1,
            log_bytes: ends[0],
            cut_bytes: ends[3] - ends[0]
        }
    );

    // The indexer reads them from the chain again, and the next open has nothing to report.
    for batch in &batches[1..] {
        store.append(batch).expect("append");
    }
    assert_eq!(fingerprint(&store), expected[3]);
    drop(store);
    assert_eq!(open(&dir).recovery().cut_bytes, 0);
}

#[test]
fn leaves_are_served_in_blocks_of_1024() {
    let rows = 2 * LEAF_BLOCK_ROWS + 452;
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(&dir);
    let made = batch(0, rows, 7);
    store.append(&made).expect("append");

    for block in 0..4u32 {
        let got = store.leaf_block(block);
        let first = block as usize * LEAF_BLOCK_ROWS;
        let expected: Vec<u8> = made
            .leaves
            .iter()
            .skip(first)
            .take(LEAF_BLOCK_ROWS)
            .flat_map(|leaf| leaf.commitment)
            .collect();
        assert_eq!(got.block_index, block);
        assert_eq!(got.leaves, expected.as_slice(), "block {block}");
        assert_eq!(got.len(), [1_024, 1_024, 452, 0][block as usize]);
        assert_eq!(got.is_full(), block < 2);
        assert_eq!(got.is_empty(), block == 3);
        assert_eq!(got.leaf_count, rows as u64);
        assert_eq!(got.root, made.checkpoint.root);
    }
    assert!(store.leaf_block(u32::MAX).is_empty());
}

#[test]
fn the_served_leaves_fold_to_the_root_of_howls_tree() {
    let fixture = Fixture::load();
    let dir = tempfile::tempdir().expect("tempdir");
    let store = indexed(&fixture, &dir);

    assert_eq!(
        LEAF_BLOCK_ROWS as u64, fixture.leaf_block_size,
        "Howl's block size"
    );
    let block = store.leaf_block(0);
    assert_eq!(block.len() as u64, fixture.leaf_count);
    // Each leaf is a canonical scalar, the form Howl's `Fr` reads.
    for leaf in block.leaves.as_chunks::<32>().0 {
        assert_eq!(&wallet::bytes(wallet::scalar(leaf)), leaf);
    }
    assert_eq!(
        block.leaves[..32],
        fixture.leaves[0].commitment,
        "leaf 0 is genesis"
    );
    assert_eq!(block.root, fixture.root);
    assert_eq!(fold(block.leaves), fixture.root);

    // The fold can fail: one leaf out of place is another root.
    let mut swapped = block.leaves.to_vec();
    swapped.swap(32 * 5, 32 * 6);
    assert_ne!(fold(&swapped), fixture.root);
}

#[test]
fn a_batch_that_does_not_fit_the_table_is_refused_and_nothing_is_written() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(&dir);
    store.append(&batch(0, 10, 5)).expect("append");
    let held = fingerprint(&store);

    assert!(matches!(
        store.append(&batch(11, 3, 6)),
        Err(StoreError::NotContiguous {
            found: 11,
            expected: 10
        })
    ));
    assert!(matches!(
        store.append(&batch(9, 3, 6)),
        Err(StoreError::NotContiguous {
            found: 9,
            expected: 10
        })
    ));
    let mut miscounted = batch(10, 3, 6);
    miscounted.checkpoint.leaf_count = 14;
    assert!(matches!(
        store.append(&miscounted),
        Err(StoreError::CheckpointMismatch {
            checkpoint: 14,
            table: 13
        })
    ));
    assert!(matches!(
        store.append(&batch(10, 3, 4)),
        Err(StoreError::BlockRegression {
            found: Some(4),
            held: Some(5)
        })
    ));
    assert!(matches!(
        store.append(&batch(10, MAX_BATCH_ROWS + 1, 6)),
        Err(StoreError::BatchTooLarge { .. })
    ));
    assert!(matches!(
        store.shard(1),
        Err(StoreError::NoSuchShard { shard: 1, count: 1 })
    ));

    assert_eq!(fingerprint(&store), held);
    drop(store);
    assert_eq!(fingerprint(&open(&dir)), held);

    // A batch with no leaves moves the block the indexer resumes from.
    let mut store = open(&dir);
    let idle = batch(10, 0, 9);
    let appended = store.append(&idle).expect("append");
    assert_eq!((appended.leaves, appended.shards), (10..10, None));
    drop(store);
    assert_eq!(open(&dir).resume_point().final_block, Some(9));
}

#[test]
fn a_directory_serves_one_deployment_and_one_process() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir);
    assert!(matches!(
        NoteStore::open(dir.path(), CHAIN_ID, POOL),
        Err(StoreError::Persistence(PersistenceError::LockHeld(_)))
    ));
    drop(store);

    let mut other_pool = POOL;
    other_pool[19] ^= 1;
    for (chain_id, pool) in [(CHAIN_ID + 1, POOL), (CHAIN_ID, other_pool)] {
        assert!(matches!(
            NoteStore::open(dir.path(), chain_id, pool),
            Err(StoreError::Persistence(PersistenceError::Invariant(_)))
        ));
    }
    open(&dir);
}

#[test]
fn a_sealed_shard_that_changed_on_disk_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(&dir);
    store
        .append(&batch(0, ROWS_PER_SHARD + 9, 1))
        .expect("append");
    let path = dir.path().join("shards/shard-00000000.bin");
    let good = std::fs::read(&path).expect("sealed shard");

    // One cell byte flipped under a running store, then under a restart.
    let mut bad = good.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    std::fs::write(&path, &bad).expect("write");
    // Named as damage: the file no longer agrees with itself.
    let damaged = "header or checksum does not match the contents";
    assert!(matches!(
        store.shard(0),
        Err(StoreError::SealedShard { shard: 0, reason }) if reason == damaged
    ));
    assert!(store.shard(1).is_ok(), "the newest shard is unaffected");
    drop(store);
    assert!(matches!(
        NoteStore::open(dir.path(), CHAIN_ID, POOL),
        Err(StoreError::SealedShard { shard: 0, reason }) if reason == damaged
    ));

    std::fs::remove_file(&path).expect("remove");
    assert!(matches!(
        NoteStore::open(dir.path(), CHAIN_ID, POOL),
        Err(StoreError::SealedShard {
            shard: 0,
            reason: "file is missing"
        })
    ));

    std::fs::write(&path, &good).expect("restore");
    assert_eq!(open(&dir).leaf_count(), ROWS_PER_SHARD as u64 + 9);
}

#[test]
fn a_sealed_shard_replaced_by_another_well_formed_file_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(&dir);
    store
        .append(&batch(0, ROWS_PER_SHARD + 9, 1))
        .expect("append");
    let path = dir.path().join("shards/shard-00000000.bin");
    let good = std::fs::read(&path).expect("sealed shard");

    // The file another table sealed in the same slot: one leaf, tag and cell differ, and
    // its own checksum holds.
    let elsewhere = tempfile::tempdir().expect("tempdir");
    let mut other = batch(0, ROWS_PER_SHARD + 9, 1);
    other.leaves[5].commitment[3] ^= 1;
    other.leaves[5].tag = Some([9u8; 32]);
    other.leaves[5].cell[40] ^= 1;
    open(&elsewhere).append(&other).expect("append");
    let foreign =
        std::fs::read(elsewhere.path().join("shards/shard-00000000.bin")).expect("sealed shard");
    assert_eq!(foreign.len(), good.len());
    assert_ne!(foreign, good);

    std::fs::write(&path, &foreign).expect("replace");
    assert!(matches!(
        store.shard(0),
        Err(StoreError::SealedShard { shard: 0, .. })
    ));
    drop(store);
    // Named as a replacement: the file agrees with itself and is not the one sealed here.
    assert!(matches!(
        NoteStore::open(dir.path(), CHAIN_ID, POOL),
        Err(StoreError::SealedShard {
            shard: 0,
            reason: "file is not the one that was sealed"
        })
    ));

    std::fs::write(&path, &good).expect("restore");
    assert_eq!(open(&dir).leaf_count(), ROWS_PER_SHARD as u64 + 9);
}
