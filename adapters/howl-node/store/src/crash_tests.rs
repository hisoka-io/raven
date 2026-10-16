//! Stops an append at each point where a process could die, reopens the directory, and
//! requires the table an uninterrupted run produces.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

#[path = "../tests/support/mod.rs"]
mod support;

use crate::{CrashPoint, NoteStore, StoreError, ROWS_PER_SHARD};
use raven_storage::RetentionPolicy;
use support::{batch, fingerprint, references, schedule, CHAIN_ID, POOL};

/// A log bound a handful of leafless batches pass, so a test reaches many retirements.
const SMALL_LOG: u64 = 4_096;

/// The batches of a quiet chain: `leaves` leaves once, then `polls` batches without any.
fn quiet(leaves: usize, polls: u64) -> Vec<howl_indexer::Batch> {
    let mut batches = vec![batch(0, leaves, 1)];
    batches.extend((0..polls).map(|poll| batch(leaves as u64, 0, 2 + poll)));
    batches
}

fn entries(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir).expect("directory").count()
}

/// A batch inside a shard, one that crosses into the next, one that ends exactly on a
/// boundary, a single leaf, and one that crosses two boundaries.
const SIZES: [usize; 6] = [700, 1_500, 1_896, 1, 4_500, 300];

fn fills_a_shard(batch: usize) -> bool {
    let before: usize = SIZES[..batch].iter().sum();
    before / ROWS_PER_SHARD != (before + SIZES[batch]) / ROWS_PER_SHARD
}

#[test]
fn a_crash_at_any_point_of_an_append_recovers_the_uninterrupted_table() {
    let batches = schedule(&SIZES);
    let expected = references(&batches);
    let whole = &expected[batches.len() - 1];
    assert!(whole.shards.len() > 4, "the schedule spans several shards");

    let mut crashes = 0;
    for point in [
        CrashPoint::AfterLog,
        CrashPoint::AfterSeal,
        CrashPoint::AfterSnapshot,
        CrashPoint::AfterCommit,
    ] {
        for victim in 0..batches.len() {
            // Only the log point is reached by a batch that fills no shard.
            let reached = point == CrashPoint::AfterLog || fills_a_shard(victim);
            let dir = tempfile::tempdir().expect("tempdir");
            let mut store = NoteStore::open(dir.path(), CHAIN_ID, POOL).expect("open");
            for batch in &batches[..victim] {
                store.append(batch).expect("append");
            }
            store.crash_at = Some(point);
            match store.append(&batches[victim]) {
                Err(StoreError::Injected(at)) => {
                    assert!(reached && at == point, "{point:?} in batch {victim}");
                    crashes += 1;
                    drop(store);
                    store = NoteStore::open(dir.path(), CHAIN_ID, POOL).expect("reopen");
                    // The batch was in the log before any of these points.
                    assert_eq!(
                        fingerprint(&store),
                        expected[victim],
                        "{point:?} in batch {victim}"
                    );
                }
                Ok(_) => {
                    assert!(!reached, "{point:?} in batch {victim} was never reached");
                    continue;
                }
                Err(other) => panic!("{point:?} in batch {victim}: {other}"),
            }
            for batch in &batches[victim + 1..] {
                store.append(batch).expect("append after recovery");
            }
            assert_eq!(&fingerprint(&store), whole, "{point:?} in batch {victim}");
            drop(store);
            let reopened = NoteStore::open(dir.path(), CHAIN_ID, POOL).expect("final reopen");
            assert_eq!(
                &fingerprint(&reopened),
                whole,
                "{point:?} in batch {victim}"
            );
        }
    }
    let sealing = (0..SIZES.len())
        .filter(|batch| fills_a_shard(*batch))
        .count();
    assert_eq!((sealing, crashes), (3, SIZES.len() + 3 * sealing));
}

#[test]
fn a_crash_inside_an_explicit_checkpoint_recovers_too() {
    let batches = schedule(&[500, 400]);
    let expected = references(&batches);
    for point in [CrashPoint::AfterSnapshot, CrashPoint::AfterCommit] {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = NoteStore::open(dir.path(), CHAIN_ID, POOL).expect("open");
        store.append(&batches[0]).expect("append");
        store.crash_at = Some(point);
        assert!(matches!(store.checkpoint(), Err(StoreError::Injected(_))));
        drop(store);

        let mut store = NoteStore::open(dir.path(), CHAIN_ID, POOL).expect("reopen");
        assert_eq!(fingerprint(&store), expected[0], "{point:?}");
        store.append(&batches[1]).expect("append");
        store.checkpoint().expect("checkpoint");
        assert_eq!(fingerprint(&store), expected[1], "{point:?}");
    }
}

#[test]
fn a_quiet_chain_holds_a_bounded_number_of_logs_and_snapshots() {
    let batches = quiet(300, 400);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = NoteStore::open(dir.path(), CHAIN_ID, POOL).expect("open");
    store.log_limit = SMALL_LOG;
    let log = dir.path().join("wal/current.log");
    let mut retired = 0;
    let mut last = 0;
    for batch in &batches {
        store.append(batch).expect("append");
        let size = std::fs::metadata(&log).expect("log").len();
        assert!(size <= SMALL_LOG, "the log holds {size} bytes");
        retired += usize::from(size < last);
        last = size;
    }
    let policy = RetentionPolicy::default();
    assert!(
        retired > 4 * policy.archived_wals_retain,
        "{retired} retirements"
    );
    assert!(entries(&dir.path().join("wal/archived")) <= policy.archived_wals_retain);
    assert!(entries(&dir.path().join("snapshots")) <= policy.snapshots_retain + 1);

    let held = fingerprint(&store);
    assert_eq!(&held, &references(&batches)[batches.len() - 1]);
    drop(store);
    let reopened = NoteStore::open(dir.path(), CHAIN_ID, POOL).expect("reopen");
    assert_eq!(fingerprint(&reopened), held);
}

#[test]
fn a_crash_while_a_quiet_log_is_retired_recovers_too() {
    let batches = quiet(300, 12);
    let expected = references(&batches);
    for point in [CrashPoint::AfterSnapshot, CrashPoint::AfterCommit] {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = NoteStore::open(dir.path(), CHAIN_ID, POOL).expect("open");
        store.log_limit = SMALL_LOG;
        store.append(&batches[0]).expect("append");

        // No shard fills, so the next checkpoint is the one a long log asks for.
        store.crash_at = Some(point);
        let mut victim = None;
        for (done, batch) in batches.iter().enumerate().skip(1) {
            match store.append(batch) {
                Ok(_) => {}
                Err(StoreError::Injected(at)) => {
                    assert_eq!(at, point);
                    victim = Some(done);
                    break;
                }
                Err(other) => panic!("{point:?} in batch {done}: {other}"),
            }
        }
        let victim = victim.expect("the log was never retired");
        assert!(victim > 1, "several leafless batches came first");

        // The batch was in the log before the crash, so its block is not lost.
        drop(store);
        let mut store = NoteStore::open(dir.path(), CHAIN_ID, POOL).expect("reopen");
        assert_eq!(fingerprint(&store), expected[victim], "{point:?}");
        store.log_limit = SMALL_LOG;
        for batch in &batches[victim + 1..] {
            store.append(batch).expect("append after recovery");
        }
        drop(store);
        let reopened = NoteStore::open(dir.path(), CHAIN_ID, POOL).expect("final reopen");
        assert_eq!(&fingerprint(&reopened), &expected[batches.len() - 1]);
    }
}
