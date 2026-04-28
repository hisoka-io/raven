//! WAL replay floor edge cases.
//!
//! Locks the four manifest schema-v2 floor semantics: fresh bootstrap (None floor),
//! pre-snapshot entries are filterable, corrupt mid-stream truncates cleanly,
//! and snapshot-captures-everything leaves zero entries to apply.

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
    let snapshot_seq: u64 = 8;
    let to_apply: Vec<_> = replay
        .entries
        .iter()
        .filter(|e| e.seq >= snapshot_seq)
        .collect();
    assert_eq!(to_apply.len(), 2);
    if let Some(first) = to_apply.first() {
        assert_eq!(first.seq, 8);
    }
    if let Some(last) = to_apply.last() {
        assert_eq!(last.seq, 9);
    }

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

    let next = wal2.append(&payload(50), 500).expect("append after recovery");
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
    let snapshot_seq: u64 = 3;
    let to_apply: Vec<_> = replay.entries.iter().filter(|e| e.seq >= snapshot_seq).collect();
    assert_eq!(to_apply.len(), 0);

    let next = wal2.append(&payload(99), 999).expect("append after replay");
    assert_eq!(next, 3);
}

/// Regression guard: `current_snapshot_seq = 0` must produce `None` floor, not `Some(0)`.
/// A previous bug passed `Some(0)` which silently skipped the seq-0 entry.
#[test]
fn init_path_does_not_skip_seq_zero_entry() {
    let (_d, layout) = make_layout();
    {
        let wal = Wal::open(&layout, None).expect("open");
        wal.append(&payload(0), 100).expect("append seq 0");
    }
    let manifest_current_snapshot_seq: u64 = 0;
    let wal_floor = manifest_current_snapshot_seq.checked_sub(1);
    assert_eq!(wal_floor, None);

    let wal2 = Wal::open(&layout, wal_floor).expect("reopen");
    let replay = wal2.replay().expect("replay");
    let to_apply: Vec<_> = replay
        .entries
        .iter()
        .filter(|e| e.seq >= manifest_current_snapshot_seq)
        .collect();
    assert_eq!(to_apply.len(), 1);
}
