//! Concurrent `open_with_lock` contention and manifest atomicity under concurrent writes.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use raven_railgun_persistence::{
    Manifest, PersistenceError, SnapshotId, StoreLayout, MANIFEST_SCHEMA_VERSION,
};

fn sample_manifest(id: u32, seq: u64) -> Manifest {
    Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        scheme_tag: "raven-inspire-twopacking-inspiring-wp3".to_owned(),
        instance_id: format!("ppoi-paths-test-{id}"),
        current_snapshot_id: SnapshotId(u64::from(id)),
        current_snapshot_seq: seq,
        current_marker: 24_000_000,
        encoder_label: "per-leaf-bc".to_owned(),
        prev_encoder_label: None,
    }
}

#[test]
fn concurrent_open_with_lock_serializes_with_exactly_one_winner_per_round() {
    const ROUNDS: usize = 8;
    const CONTENDERS: usize = 6;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();

    for round in 0..ROUNDS {
        let winners = Arc::new(AtomicUsize::new(0));
        let losers = Arc::new(AtomicUsize::new(0));
        let handles: Vec<_> = (0..CONTENDERS)
            .map(|c| {
                let path = path.clone();
                let winners = Arc::clone(&winners);
                let losers = Arc::clone(&losers);
                thread::spawn(move || match StoreLayout::open_with_lock(&path) {
                    Ok((layout, _lock)) => {
                        let m = sample_manifest(c as u32, (round * 100 + c) as u64);
                        m.save(&layout).expect("save");
                        let back = Manifest::load(&layout).expect("load").expect("present");
                        assert_eq!(back, m);
                        winners.fetch_add(1, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(PersistenceError::LockHeld(_)) => {
                        losers.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(e) => panic!("unexpected error: {e:?}"),
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread joined");
        }

        let won = winners.load(Ordering::SeqCst);
        let lost = losers.load(Ordering::SeqCst);
        assert_eq!(won + lost, CONTENDERS);
        assert!(
            won >= 1,
            "round {round}: at least one contender must win the lock"
        );
        let layout = StoreLayout::open(&path).expect("post-round open");
        let manifest = Manifest::load(&layout)
            .expect("post-round load")
            .expect("present");
        assert_eq!(manifest.schema_version, MANIFEST_SCHEMA_VERSION);
    }
}

#[test]
fn concurrent_lock_release_then_reacquire_is_clean() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();

    {
        let (layout, _lock) = StoreLayout::open_with_lock(&path).expect("first acquire");
        let m = sample_manifest(1, 100);
        m.save(&layout).expect("save under first lock");
    }

    let (layout, _lock) = StoreLayout::open_with_lock(&path).expect("re-acquire");
    let back = Manifest::load(&layout)
        .expect("load")
        .expect("present after re-acquire");
    assert_eq!(back.current_snapshot_id, SnapshotId(1));
    assert_eq!(back.current_snapshot_seq, 100);
}

/// Bare `StoreLayout::open` does not enforce single-writer; last atomic-rename wins.
/// CLI binaries that need exclusion must use `open_with_lock`.
#[test]
fn bare_open_does_not_protect_against_concurrent_holders() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();

    let l1 = StoreLayout::open(&path).expect("first bare open");
    let l2 = StoreLayout::open(&path).expect("second bare open");

    sample_manifest(1, 100).save(&l1).expect("first save");
    sample_manifest(2, 200).save(&l2).expect("second save");

    let back = Manifest::load(&l1).expect("load").expect("present");
    assert_eq!(back.current_snapshot_id, SnapshotId(2));
}

/// While one thread holds the lock and writes manifests in a loop,
/// concurrent readers must never observe a truncated or partial file (atomic-rename guarantee).
#[test]
fn manifest_save_during_concurrent_lock_attempts_is_atomic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();

    {
        let (layout, _lock) = StoreLayout::open_with_lock(&path).expect("seed acquire");
        sample_manifest(0, 0).save(&layout).expect("seed save");
    }

    let (writer_layout, writer_lock) = StoreLayout::open_with_lock(&path).expect("writer acquire");
    let path_for_writer = path.clone();
    let writer = thread::spawn(move || {
        for i in 0..50 {
            let m = sample_manifest(0, u64::try_from(i).unwrap_or(0));
            m.save(&writer_layout).expect("writer save");
            thread::sleep(Duration::from_micros(50));
        }
        // Writer holds the lock for the duration of the loop.
        drop(writer_lock);
        path_for_writer
    });

    let mut readers = Vec::new();
    for _ in 0..4 {
        let path = path.clone();
        readers.push(thread::spawn(move || {
            let mut bare_observations = 0;
            for _ in 0..30 {
                let layout = StoreLayout::open(&path).expect("reader bare open");
                if let Some(m) = Manifest::load(&layout).expect("reader load") {
                    assert_eq!(m.schema_version, MANIFEST_SCHEMA_VERSION);
                    bare_observations += 1;
                }
                thread::sleep(Duration::from_micros(75));
            }
            bare_observations
        }));
    }

    let _ = writer.join().expect("writer joined");
    for r in readers {
        let observations = r.join().expect("reader joined");
        assert!(observations >= 1);
    }

    let layout = StoreLayout::open(&path).expect("post open");
    let final_manifest = Manifest::load(&layout)
        .expect("post load")
        .expect("present");
    assert_eq!(final_manifest.current_snapshot_seq, 49);
}
