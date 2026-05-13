//! Property tests for the WAL recovery path: random truncation must preserve intact-prefix semantics.
//! 100 trials × 3 seeds; runs in CI.

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
        cut_fraction in 0u32..1000u32,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");

        let wal = Wal::open(&layout, None).expect("open wal");
        let mut written = Vec::new();
        for (i, p) in payloads.iter().enumerate() {
            let block_height = u64::try_from(i).unwrap_or(0) * 10 + 100;
            let seq = wal.append(p, block_height).expect("append");
            written.push((seq, block_height, p.clone()));
        }
        drop(wal);

        let path = layout.wal_current_path();
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

        let wal2 = Wal::open(&layout, None).expect("reopen after truncate");
        let replay = wal2.replay().expect("replay");

        prop_assert!(
            replay.entries.len() <= written.len(),
            "replay has more entries ({}) than were written ({})",
            replay.entries.len(),
            written.len()
        );
        for (i, recovered) in replay.entries.iter().enumerate() {
            let row = written.get(i).expect("written index in range");
            prop_assert_eq!(recovered.seq, row.0);
            prop_assert_eq!(recovered.block_height, row.1);
            let parsed: WalEntryPayload =
                bincode::deserialize(&recovered.payload).expect("deser");
            prop_assert_eq!(&parsed, &row.2);
        }

        let expected_next = match replay.entries.last() {
            Some(e) => e.seq + 1,
            None => 0,
        };
        prop_assert_eq!(replay.next_seq, expected_next);
    }

    #[test]
    fn archive_then_truncate_preserves_archived(
        before in prop::collection::vec(payload_strategy(), 1..20),
        after in prop::collection::vec(payload_strategy(), 1..20),
        cut_fraction in 0u32..1000u32,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");

        let wal = Wal::open(&layout, None).expect("open wal");
        for (i, p) in before.iter().enumerate() {
            wal.append(p, u64::try_from(i).unwrap_or(0) * 10 + 100).expect("append");
        }
        let last_archived_seq = wal.next_seq().saturating_sub(1);
        let from_seq = 0;
        wal.archive(from_seq, last_archived_seq).expect("archive");
        prop_assert!(layout.wal_archived_path(from_seq, last_archived_seq).is_file());

        for (i, p) in after.iter().enumerate() {
            wal.append(p, u64::try_from(i).unwrap_or(0) * 10 + 1000)
                .expect("append");
        }
        drop(wal);

        let path = layout.wal_current_path();
        let total = std::fs::metadata(&path).expect("meta").len();
        let cut_at = total * u64::from(cut_fraction) / 1000;
        {
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open");
            f.set_len(cut_at).expect("set_len");
        }

        prop_assert!(layout.wal_archived_path(from_seq, last_archived_seq).is_file());
        let _wal2 = Wal::open(&layout, Some(last_archived_seq)).expect("reopen");
    }
}
