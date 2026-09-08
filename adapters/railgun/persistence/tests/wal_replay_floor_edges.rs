//! WAL replay floor semantics: fresh bootstrap yields no floor, replay hands
//! back the whole on-disk log (the CALLER filters below the snapshot floor), a
//! corrupt mid-stream truncates cleanly, and a floor above the tail is refused.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::fs::OpenOptions;
use std::io::Write;

use raven_railgun_persistence::{StoreLayout, Wal, WalEntryPayload};

fn make_layout() -> (tempfile::TempDir, StoreLayout) {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("open");
    (dir, layout)
}

fn payload(idx: u32) -> WalEntryPayload {
    WalEntryPayload::AppendLeaf {
        tree_number: 0,
        leaf_index: idx,
        commitment: [(idx & 0xff) as u8; 32],
    }
}

#[test]
fn fresh_bootstrap_replays_every_wal_entry_from_seq_zero() {
    let (_d, layout) = make_layout();
    {
        let wal = Wal::open(&layout, None).expect("open fresh");
        for i in 0..5u32 {
            wal.append(&payload(i), 100 + u64::from(i)).expect("append");
        }
    }

    let wal2 = Wal::open(&layout, None).expect("reopen");
    let replay = wal2.replay().expect("replay");
    assert_eq!(replay.entries.len(), 5);
    assert_eq!(replay.next_seq, 5);
    for (i, entry) in replay.entries.iter().enumerate() {
        assert_eq!(entry.seq, i as u64);
    }
}

#[test]
fn wal_entries_below_snapshot_floor_are_filterable_in_replay() {
    let (_d, layout) = make_layout();
    {
        let wal = Wal::open(&layout, None).expect("open");
        for i in 0..10u32 {
            wal.append(&payload(i), 100 + u64::from(i)).expect("append");
        }
    }

    // Snapshot taken after seq 7; WAL still contains seqs 0..10.
    let wal2 = Wal::open(&layout, Some(7)).expect("reopen with floor");
    // On-disk tail (10) wins over the floor (8).
    assert_eq!(wal2.next_seq(), 10);

    let replay = wal2.replay().expect("replay");
    // The floor filters nothing on disk: replay hands back the whole log and the caller
    // decides. Without this the filter below is satisfied by an empty replay too.
    assert_eq!(
        replay.entries.len(),
        10,
        "a floor must not drop on-disk entries"
    );
    assert_eq!(replay.truncated_at, None);
    for (i, e) in replay.entries.iter().enumerate() {
        assert_eq!(e.seq, i as u64, "seqs must stay contiguous from 0");
    }

    // Caller-side floor filtering (seq >= snapshot floor) is implied by the two
    // pins above: len == 10 and contiguous seqs from 0 fully determine it.
    let next = wal2.append(&payload(99), 999).expect("append after replay");
    assert_eq!(next, 10);
}

#[test]
fn corrupted_mid_stream_truncates_at_gap_recoverable_prefix_intact() {
    let (_d, layout) = make_layout();
    {
        let wal = Wal::open(&layout, None).expect("open");
        for i in 0..5u32 {
            wal.append(&payload(i), 100 + u64::from(i)).expect("append");
        }
    }

    let path = layout.wal_current_path();
    {
        let mut f = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open for append");
        f.write_all(&[0xAB; 100]).expect("write garbage");
        f.sync_all().expect("sync");
    }

    let wal2 = Wal::open(&layout, None).expect("reopen with garbage tail");
    let replay = wal2.replay().expect("replay");
    assert_eq!(replay.entries.len(), 5);
    assert_eq!(replay.next_seq, 5);
    // Wal::open truncates the torn tail at open time; replay sees a clean file.
    assert_eq!(replay.truncated_at, None);

    let next = wal2
        .append(&payload(50), 500)
        .expect("append after recovery");
    assert_eq!(next, 5);
}

#[test]
fn no_entries_to_replay_when_snapshot_captures_every_wal_entry() {
    let (_d, layout) = make_layout();
    {
        let wal = Wal::open(&layout, None).expect("open");
        for i in 0..3u32 {
            wal.append(&payload(i), 100 + u64::from(i)).expect("append");
        }
    }

    // Snapshot took every entry: current_snapshot_seq = 3; all on-disk seqs < 3.
    let wal2 = Wal::open(&layout, Some(2)).expect("reopen with floor");
    let replay = wal2.replay().expect("replay");
    // `to_apply.len() == 0` alone is satisfied by a replay that lost the log, which is the
    // opposite outcome. Pin the entries that must still be there first.
    assert_eq!(
        replay.entries.len(),
        3,
        "a fully-capturing snapshot does not entitle replay to drop the log"
    );
    assert_eq!(replay.next_seq, 3);
    for (i, e) in replay.entries.iter().enumerate() {
        assert_eq!(e.seq, i as u64);
        assert_eq!(e.marker, 100 + i as u64);
    }

    // Caller-side filtering at floor 3 leaving nothing to apply is implied by
    // the pins above: len == 3 with contiguous seqs 0..2 has no seq >= 3.
    let next = wal2.append(&payload(99), 999).expect("append after replay");
    assert_eq!(next, 3);
}

// Floor-vs-tail refusal (a floor above the logged tail, and the None floor from
// `current_snapshot_seq = 0`) is covered at the raven_storage seam this crate
// re-exports: the proptest and recovery-shaped example in
// crates/storage/tests/wal_resume_floor_refusal.rs, with the replay-from-seq-0
// axis held by fresh_bootstrap_replays_every_wal_entry_from_seq_zero above.
