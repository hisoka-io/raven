//! Deferred appends under a simulated power loss: only the synced prefix of
//! `current.log` is guaranteed to reach the disk, so a loss is modelled as a cut
//! anywhere at or past `synced_len`, optionally with garbage where the unsynced
//! pages were.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use proptest::prelude::*;
use raven_storage::{
    decode_no_trailing, open_recovery, publish_snapshot, Manifest, SnapshotId, StoreLayout, Wal,
    MANIFEST_SCHEMA_VERSION,
};
use std::io::{Seek, SeekFrom, Write};

const MAGIC: [u8; 16] = *b"DEFERRED_SYNC_01";

#[derive(Clone, Debug)]
enum Op {
    Append(Vec<u8>),
    Sync,
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        9 => prop::collection::vec(any::<u8>(), 0..200).prop_map(Op::Append),
        1 => Just(Op::Sync),
    ]
}

fn file_len(layout: &StoreLayout) -> u64 {
    std::fs::metadata(layout.wal_current_path())
        .expect("metadata")
        .len()
}

fn garbage_bytes(len: usize, zeroes: bool, mut state: u64) -> Vec<u8> {
    if zeroes {
        return vec![0; len];
    }
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        ..ProptestConfig::default()
    })]

    #[test]
    fn a_power_loss_keeps_the_synced_prefix_and_leaves_no_gap(
        ops in prop::collection::vec(op_strategy(), 1..60),
        cut_permille in 0u64..=1000,
        garbage in prop::option::of((0u64..=1000, 1usize..=4096, any::<bool>(), 1u64..)),
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let wal = Wal::open(&layout, None).expect("open");

        // (payload, marker, end offset of its frame)
        let mut written: Vec<(Vec<u8>, u64, u64)> = Vec::new();
        for op in &ops {
            match op {
                Op::Append(payload) => {
                    let marker = 100 + written.len() as u64;
                    let seq = wal.append_deferred(payload, marker).expect("append_deferred");
                    prop_assert_eq!(seq, written.len() as u64);
                    written.push((payload.clone(), marker, file_len(&layout)));
                }
                Op::Sync => {
                    wal.sync().expect("sync");
                    prop_assert_eq!(
                        wal.synced_len(),
                        file_len(&layout),
                        "the tracked length must equal the file's length"
                    );
                }
            }
        }
        let synced = wal.synced_len();
        let total = file_len(&layout);
        prop_assert!(synced <= total);
        drop(wal);

        let cut = synced + (total - synced) * cut_permille / 1000;
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(layout.wal_current_path())
                .expect("open write");
            f.set_len(cut).expect("set_len");
            if let Some((at_permille, len, zeroes, seed)) = garbage {
                let at = synced + (cut - synced) * at_permille / 1000;
                f.seek(SeekFrom::Start(at)).expect("seek");
                f.write_all(&garbage_bytes(len, zeroes, seed)).expect("garbage");
            }
        }

        let durable = written.iter().filter(|w| w.2 <= synced).count();
        let below_cut = written.iter().filter(|w| w.2 <= cut).count();

        let reopened = Wal::open(&layout, None).expect("reopen after the loss");
        let replay = reopened.replay().expect("replay");
        let survivors = replay.entries.len();

        prop_assert!(
            survivors >= durable,
            "{} frames were synced but only {} replayed", durable, survivors
        );
        prop_assert!(survivors <= below_cut);
        if garbage.is_none() {
            prop_assert_eq!(survivors, below_cut, "every whole frame below the cut survives");
        }
        for (i, entry) in replay.entries.iter().enumerate() {
            let (payload, marker, _) = written.get(i).expect("survivor was written");
            prop_assert_eq!(entry.seq, i as u64, "survivors are gap-free from seq 0");
            prop_assert_eq!(entry.marker, *marker);
            let decoded: Vec<u8> = decode_no_trailing(&entry.payload).expect("decode");
            prop_assert_eq!(&decoded, payload);
        }
        prop_assert_eq!(replay.truncated_at, None, "open cut the torn tail");
        prop_assert_eq!(replay.next_seq, survivors as u64);
        prop_assert_eq!(reopened.next_seq(), survivors as u64);
        prop_assert_eq!(
            reopened.append_deferred(&vec![0xEEu8], u64::MAX).expect("appendable"),
            survivors as u64
        );
    }
}

fn fresh_manifest() -> Manifest {
    Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        scheme_tag: "test-scheme".to_owned(),
        instance_id: "test-instance".to_owned(),
        current_snapshot_id: SnapshotId(0),
        current_snapshot_seq: 0,
        current_marker: 0,
        encoder_label: "test-encoder".to_owned(),
        prev_encoder_label: None,
        entry_size_bytes: Some(32),
        rows_per_shard: Some(2048),
    }
}

fn point_at(m: &mut Manifest, id: SnapshotId, floor: u64) {
    m.current_snapshot_id = id;
    m.current_snapshot_seq = floor;
}

/// The manifest lands before the seal, so a power loss between the two leaves the
/// floor it recorded next to whatever of the log was durable. Unless the log was
/// synced first, that floor sits above the durable tail and the node refuses to boot.
#[test]
fn a_power_loss_after_the_manifest_lands_still_boots() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let wal = Wal::open(&layout, None).expect("open");
    for i in 0..2u64 {
        wal.append(&i, i).expect("synced append");
    }
    for i in 2..6u64 {
        wal.append_deferred(&i, i).expect("deferred append");
    }
    let floor = wal.next_seq();

    // An occupied archive slot refuses the seal after the manifest is saved, which
    // stops the publish at exactly the point a power loss would.
    let slot = layout.wal_archived_path(0, floor - 1);
    std::fs::create_dir_all(slot.parent().expect("archive dir")).expect("mkdir");
    std::fs::write(&slot, b"").expect("occupy the slot");
    let mut manifest = fresh_manifest();
    let err = publish_snapshot(
        &layout,
        &wal,
        &mut manifest,
        SnapshotId(1),
        b"state".to_vec(),
        MAGIC,
        point_at,
    )
    .expect_err("the occupied slot refuses the seal");
    assert!(format!("{err}").contains("already sealed"), "got {err}");
    assert_eq!(
        Manifest::load(&layout)
            .expect("load")
            .expect("the manifest landed")
            .current_snapshot_seq,
        floor
    );

    let durable = wal.synced_len();
    drop(wal);
    std::fs::OpenOptions::new()
        .write(true)
        .open(layout.wal_current_path())
        .expect("open")
        .set_len(durable)
        .expect("drop the unsynced suffix");

    let recovered = open_recovery(&layout, MAGIC, |_| Ok(()))
        .unwrap_or_else(|e| panic!("boot after the power loss: {e}"))
        .expect("a manifest was published");
    assert_eq!(recovered.manifest.current_snapshot_seq, floor);
    assert_eq!(recovered.wal.next_seq(), floor);
    assert!(
        recovered.replay.entries.is_empty(),
        "the snapshot covers them"
    );
}
