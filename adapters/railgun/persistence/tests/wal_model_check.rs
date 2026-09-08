//! Property tests for the WAL recovery path: random truncation must preserve intact-prefix semantics.
//! 100 trials x 3 seeds; runs in CI.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use proptest::prelude::*;
use raven_railgun_persistence::{StoreLayout, Wal, WalEntryPayload};

fn payload_strategy() -> impl Strategy<Value = WalEntryPayload> {
    prop_oneof![
        (0u32..256, 0u32..65_536, any::<[u8; 32]>()).prop_map(
            |(tree_number, leaf_index, commitment)| WalEntryPayload::AppendLeaf {
                tree_number,
                leaf_index,
                commitment,
            }
        ),
        (any::<[u8; 32]>(), any::<[u8; 32]>(), 0u8..4).prop_map(
            |(list_key, blinded_commitment, status)| WalEntryPayload::PpoiStatus {
                list_key,
                blinded_commitment,
                status,
            }
        ),
        any::<u64>().prop_map(|height| WalEntryPayload::Reorg { height }),
        (any::<[u8; 32]>(), 0u32..65_536, any::<[u8; 32]>(), 0u8..4).prop_map(
            |(list_key, list_index, blinded_commitment, status)| {
                WalEntryPayload::PpoiListLeafAdded {
                    list_key,
                    list_index,
                    blinded_commitment,
                    status,
                }
            }
        ),
        any::<u64>().prop_map(|wallclock_unix_ms| WalEntryPayload::Heartbeat { wallclock_unix_ms }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 100,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_truncate_preserves_prefix(
        payloads in prop::collection::vec(payload_strategy(), 1..50),
        cut_fraction in 0u32..=1000u32,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let path = layout.wal_current_path();

        // `append` fsyncs each frame, so the file length after it IS that frame's end
        // offset. Recording it here makes the survivor count below an independent oracle
        // instead of a restatement of whatever `replay` chose to return.
        let wal = Wal::open(&layout, None).expect("open wal");
        let mut written = Vec::new();
        for (i, p) in payloads.iter().enumerate() {
            let block_height = u64::try_from(i).unwrap_or(0) * 10 + 100;
            let seq = wal.append(p, block_height).expect("append");
            let frame_end = std::fs::metadata(&path).expect("meta").len();
            written.push((seq, block_height, p.clone(), frame_end));
        }
        drop(wal);

        let total = std::fs::metadata(&path).expect("meta").len();
        let cut_at = total * u64::from(cut_fraction) / 1000;
        {
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open write");
            f.set_len(cut_at).expect("set_len");
            f.sync_all().expect("sync");
        }

        // Every whole frame below the cut must come back, and nothing above it may.
        let expected_len = written.iter().filter(|row| row.3 <= cut_at).count();

        let wal2 = Wal::open(&layout, None).expect("reopen after truncate");
        let replay = wal2.replay().expect("replay");

        prop_assert_eq!(
            replay.entries.len(),
            expected_len,
            "cut at {} of {} bytes keeps {} whole frames; replay returned {}",
            cut_at,
            total,
            expected_len,
            replay.entries.len()
        );
        for (i, recovered) in replay.entries.iter().enumerate() {
            let row = written.get(i).expect("written index in range");
            prop_assert_eq!(recovered.seq, row.0);
            prop_assert_eq!(recovered.marker, row.1);
            let parsed: WalEntryPayload =
                bincode::deserialize(&recovered.payload).expect("deser");
            prop_assert_eq!(&parsed, &row.2);
        }

        // `open` rewinds the torn tail, so the log it hands back has no gap left in it.
        prop_assert_eq!(replay.truncated_at, None);
        prop_assert_eq!(replay.next_seq, expected_len as u64);
        prop_assert_eq!(wal2.next_seq(), expected_len as u64);

        // A recovered log must still be writable, at the seq the survivors end on.
        let appended = wal2
            .append(&WalEntryPayload::Heartbeat { wallclock_unix_ms: 1 }, u64::MAX)
            .expect("append after recovery");
        prop_assert_eq!(appended, expected_len as u64);
    }

    #[test]
    fn archive_then_truncate_preserves_archived(
        before in prop::collection::vec(payload_strategy(), 1..20),
        after in prop::collection::vec(payload_strategy(), 1..20),
        cut_fraction in 0u32..=1000u32,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let path = layout.wal_current_path();

        let wal = Wal::open(&layout, None).expect("open wal");
        for (i, p) in before.iter().enumerate() {
            wal.append(p, u64::try_from(i).unwrap_or(0) * 10 + 100).expect("append");
        }
        let sealed_bytes = std::fs::metadata(&path).expect("meta").len();
        let last_archived_seq = wal.next_seq().saturating_sub(1);
        let from_seq = 0;
        wal.archive(from_seq, last_archived_seq).expect("archive");

        // The seal is a rename, so the archived file must hold every sealed byte. A
        // path-exists check passes just as well over an empty or half-copied file.
        let archived = layout.wal_archived_path(from_seq, last_archived_seq);
        prop_assert_eq!(
            std::fs::metadata(&archived).expect("archived meta").len(),
            sealed_bytes
        );
        prop_assert_eq!(std::fs::metadata(&path).expect("current meta").len(), 0);

        let mut written = Vec::new();
        for (i, p) in after.iter().enumerate() {
            let marker = u64::try_from(i).unwrap_or(0) * 10 + 1000;
            let seq = wal.append(p, marker).expect("append");
            let frame_end = std::fs::metadata(&path).expect("meta").len();
            written.push((seq, marker, p.clone(), frame_end));
        }
        drop(wal);

        let total = std::fs::metadata(&path).expect("meta").len();
        let cut_at = total * u64::from(cut_fraction) / 1000;
        {
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open");
            f.set_len(cut_at).expect("set_len");
            f.sync_all().expect("sync");
        }

        // Truncating current.log must not reach the sealed range at all.
        prop_assert_eq!(
            std::fs::metadata(&archived).expect("archived meta").len(),
            sealed_bytes
        );

        let expected_len = written.iter().filter(|row| row.3 <= cut_at).count();
        let wal2 = Wal::open(&layout, Some(last_archived_seq)).expect("reopen");
        let replay = wal2.replay().expect("replay");

        prop_assert_eq!(replay.entries.len(), expected_len);
        prop_assert_eq!(replay.truncated_at, None);
        for (i, recovered) in replay.entries.iter().enumerate() {
            let row = written.get(i).expect("written index in range");
            // Post-archive seqs continue past the sealed range; restarting them at 0
            // would make replay read the survivors as a torn tail.
            prop_assert_eq!(recovered.seq, row.0);
            prop_assert!(recovered.seq > last_archived_seq);
            prop_assert_eq!(recovered.marker, row.1);
            let parsed: WalEntryPayload =
                bincode::deserialize(&recovered.payload).expect("deser");
            prop_assert_eq!(&parsed, &row.2);
        }

        // The resume floor is the sealed tail, so the next append lands above it whether
        // or not anything in current.log survived.
        let expected_next = last_archived_seq
            .saturating_add(1)
            .saturating_add(expected_len as u64);
        prop_assert_eq!(wal2.next_seq(), expected_next);
        let appended = wal2
            .append(&WalEntryPayload::Heartbeat { wallclock_unix_ms: 2 }, u64::MAX)
            .expect("append after recovery");
        prop_assert_eq!(appended, expected_next);
    }
}
