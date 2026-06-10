//! WAL append/replay and snapshot save/load are faithful round-trips over arbitrary
//! payloads and markers.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use proptest::prelude::*;
use raven_storage::{SnapshotFile, SnapshotId, StoreLayout, Wal};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn wal_append_replay_round_trips(
        entries in proptest::collection::vec(
            (proptest::collection::vec(any::<u8>(), 0..256), any::<u64>()),
            0..24usize,
        ),
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let wal = Wal::open(&layout, None).expect("wal open");
        for (payload, marker) in &entries {
            wal.append(payload, *marker).expect("append");
        }
        let replay = wal.replay().expect("replay");
        prop_assert_eq!(replay.entries.len(), entries.len());
        prop_assert_eq!(replay.truncated_at, None);
        for (i, (orig_payload, orig_marker)) in entries.iter().enumerate() {
            let entry = &replay.entries[i];
            prop_assert_eq!(entry.seq, i as u64);
            prop_assert_eq!(entry.marker, *orig_marker);
            let decoded: Vec<u8> = bincode::deserialize(&entry.payload).expect("decode");
            prop_assert_eq!(&decoded, orig_payload);
        }
        if let Some((_, last_marker)) = entries.last() {
            prop_assert_eq!(replay.last_marker, *last_marker);
            prop_assert_eq!(replay.next_seq, entries.len() as u64);
        }
    }

    #[test]
    fn snapshot_build_save_load_round_trips(
        payload in proptest::collection::vec(any::<u8>(), 0..4096),
        magic in any::<[u8; 16]>(),
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let snap = SnapshotFile::build(payload.clone(), magic);
        prop_assert_eq!(snap.header.data_len, payload.len() as u64);
        snap.save(&layout, SnapshotId(1)).expect("save");
        let back = SnapshotFile::load(&layout, SnapshotId(1), magic).expect("load");
        prop_assert_eq!(back.data, payload);
        prop_assert_eq!(back.header.magic, magic);
    }
}
