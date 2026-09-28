#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{
    apply_wal_entry, restore_inspire_state_v6, snapshot_inspire_state_v8, InspireServerState,
    LogicalLeafStore, SNAPSHOT_V8_MAGIC,
};
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_persistence::{StoreLayout, Wal, WalEntryPayload};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-wal-v6-recovery";
const TOY_ENTRY_SIZE: usize = 32;
const ENTRIES_PER_SHARD: u32 = 2048;

fn build_toy_state() -> InspireServerState {
    raven_railgun_testkit::toy_state(TOY_ENTRY_SIZE)
}

fn encoder_arc() -> Arc<dyn PirTableEncoder> {
    EncoderKind::PerLeafBc { tree_number: 0 }
        .build(TOY_ENTRY_SIZE, ENTRIES_PER_SHARD)
        .expect("build encoder")
}

use raven_railgun_testkit::canonical;

#[test]
fn bootstrap_then_kill_then_restart_serves_real_leaves() {
    let dir = tempfile::tempdir().expect("tempdir");

    {
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("v6-recovery-kill"),
            SnapshotPolicy::default(),
            encoder_arc(),
        )
        .expect("fresh open");

        let state = build_toy_state();
        let mut store = LogicalLeafStore::default();
        let encoder: Arc<dyn PirTableEncoder> = encoder_arc();

        for i in 0..4u32 {
            let payload = WalEntryPayload::AppendLeaf {
                tree_number: 0,
                leaf_index: i,
                commitment: canonical(u8::try_from(i).unwrap_or(0).saturating_add(1)),
            };
            apply_wal_entry(&mut store, &payload, 100 + u64::from(i), encoder.as_ref())
                .expect("apply to logical");
            opened
                .persistence
                .apply_event(&payload, 100 + u64::from(i))
                .expect("apply_event");
        }

        opened
            .persistence
            .commit_v6(&state, &store, 150)
            .expect("commit_v6 batch 1");

        for i in 4..6u32 {
            let payload = WalEntryPayload::AppendLeaf {
                tree_number: 0,
                leaf_index: i,
                commitment: canonical(u8::try_from(i).unwrap_or(0).saturating_add(1)),
            };
            apply_wal_entry(&mut store, &payload, 100 + u64::from(i), encoder.as_ref())
                .expect("apply to logical");
            opened
                .persistence
                .apply_event(&payload, 100 + u64::from(i))
                .expect("apply_event");
        }
    }

    let layout2 = StoreLayout::open(dir.path()).expect("layout reopen");
    let opened2 = InspirePersistence::open(
        layout2,
        SCHEME_TAG,
        InstanceId::new("v6-recovery-kill"),
        SnapshotPolicy::default(),
        encoder_arc(),
    )
    .expect("recovery open");

    assert_eq!(
        opened2.recovered_logical_store.imt_leaf_count_for(0),
        6,
        "V8 snapshot (4 leaves) + WAL replay (2 leaves) must combine to 6"
    );
    for i in 0..6u32 {
        let want = canonical(u8::try_from(i).unwrap_or(0).saturating_add(1));
        let got = opened2
            .recovered_logical_store
            .leaf(0, i)
            .copied()
            .expect("leaf present after recovery");
        assert_eq!(got, want, "leaf {i} must survive snapshot+WAL combine");
    }
}

#[test]
fn wal_replay_drops_entries_already_in_snapshot_at_v6() {
    let dir = tempfile::tempdir().expect("tempdir");

    {
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("v6-replay-floor"),
            SnapshotPolicy::default(),
            encoder_arc(),
        )
        .expect("fresh open");

        let state = build_toy_state();
        let mut store = LogicalLeafStore::default();
        let encoder: Arc<dyn PirTableEncoder> = encoder_arc();

        for cycle in 0..3u32 {
            let lo = cycle * 4;
            let hi = lo + 4;
            for i in lo..hi {
                let payload = WalEntryPayload::AppendLeaf {
                    tree_number: 0,
                    leaf_index: i,
                    commitment: canonical(u8::try_from(i).unwrap_or(0).saturating_add(1)),
                };
                apply_wal_entry(&mut store, &payload, 100 + u64::from(i), encoder.as_ref())
                    .expect("apply to logical");
                opened
                    .persistence
                    .apply_event(&payload, 100 + u64::from(i))
                    .expect("apply_event");
            }
            opened
                .persistence
                .commit_v6(&state, &store, 200 + u64::from(cycle))
                .expect("commit_v6");
        }
    }

    let layout2 = StoreLayout::open(dir.path()).expect("layout reopen");
    let opened2 = InspirePersistence::open(
        layout2,
        SCHEME_TAG,
        InstanceId::new("v6-replay-floor"),
        SnapshotPolicy::default(),
        encoder_arc(),
    )
    .expect("recovery open");

    assert_eq!(
        opened2.recovered_logical_store.imt_leaf_count_for(0),
        12,
        "post-multi-commit recovery must surface every leaf exactly once \
         (no double-apply across the WAL replay floor)"
    );
    // The floor decides WHICH entries replay; a count alone cannot tell a correct
    // floor from one that replayed the wrong cycle's bytes into the right slots.
    for i in 0..12u32 {
        let want = canonical(u8::try_from(i).unwrap_or(0).saturating_add(1));
        let got = opened2
            .recovered_logical_store
            .leaf(0, i)
            .copied()
            .expect("leaf present after multi-commit recovery");
        assert_eq!(got, want, "leaf {i} must byte-equal the commitment written");
    }
}

#[test]
fn snapshot_v8_envelope_roundtrips_in_isolation() {
    let state = build_toy_state();
    let mut store = LogicalLeafStore::default();
    let encoder: Arc<dyn PirTableEncoder> = encoder_arc();
    for i in 0..3u32 {
        let payload = WalEntryPayload::AppendLeaf {
            tree_number: 0,
            leaf_index: i,
            commitment: canonical(u8::try_from(i).unwrap_or(0).saturating_add(1)),
        };
        apply_wal_entry(&mut store, &payload, 100 + u64::from(i), encoder.as_ref())
            .expect("apply to logical");
    }
    let bytes = snapshot_inspire_state_v8(&state, &store).expect("v8 ser");
    let head = bytes
        .get(..SNAPSHOT_V8_MAGIC.len())
        .expect("v8 bytes long enough to hold magic");
    assert_eq!(
        head, SNAPSHOT_V8_MAGIC,
        "v8 envelope must lead with the magic prefix"
    );
    let (back_state, back_store) = restore_inspire_state_v6(&bytes).expect("v8 restore");
    assert_eq!(back_state.entry_size, state.entry_size);
    assert_eq!(back_store.imt_leaf_count_for(0), 3);
    for i in 0..3u32 {
        let want = canonical(u8::try_from(i).unwrap_or(0).saturating_add(1));
        let got = back_store.leaf(0, i).copied().expect("leaf present");
        assert_eq!(got, want);
    }
}

#[test]
fn drive_commit_truncates_wal_yet_v6_recovery_is_complete() {
    // commit_v6 archives the WAL, so reopen reads zero entries from current.log; the V8 snapshot must still recover every leaf
    let dir = tempfile::tempdir().expect("tempdir");

    let staged_root = {
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("v6-wal-truncate"),
            SnapshotPolicy::default(),
            encoder_arc(),
        )
        .expect("fresh open");
        assert!(
            opened.recovered_state.is_none(),
            "fresh bootstrap leaves no recovered state until the first commit"
        );

        let state = build_toy_state();
        let mut store = LogicalLeafStore::default();
        let encoder: Arc<dyn PirTableEncoder> = encoder_arc();
        for i in 0..5u32 {
            let payload = WalEntryPayload::AppendLeaf {
                tree_number: 0,
                leaf_index: i,
                commitment: canonical(u8::try_from(i).unwrap_or(0).saturating_add(1)),
            };
            apply_wal_entry(&mut store, &payload, 100 + u64::from(i), encoder.as_ref())
                .expect("apply to logical");
            opened
                .persistence
                .apply_event(&payload, 100 + u64::from(i))
                .expect("apply_event");
        }

        let staged_root = store.imt_root(0).expect("staged tree root");
        opened
            .persistence
            .commit_v6(&state, &store, 999)
            .expect("commit_v6");
        staged_root
    };

    let layout_probe = StoreLayout::open(dir.path()).expect("layout probe");
    let wal = Wal::open(&layout_probe, None).expect("wal probe open");
    let replay = wal.replay().expect("replay current.log");
    assert!(
        replay.entries.is_empty(),
        "after commit_v6 the current.log must be empty (archive succeeded); \
         got {} entries",
        replay.entries.len()
    );

    let layout2 = StoreLayout::open(dir.path()).expect("layout reopen");
    let opened2 = InspirePersistence::open(
        layout2,
        SCHEME_TAG,
        InstanceId::new("v6-wal-truncate"),
        SnapshotPolicy::default(),
        encoder_arc(),
    )
    .expect("recovery open");

    assert!(
        opened2.recovered_state.is_some(),
        "post-commit reopen must surface recovered_state"
    );
    assert_eq!(
        opened2.recovered_logical_store.imt_leaf_count_for(0),
        5,
        "Even with empty current.log post-archive, the V8 snapshot must \
         carry every applied leaf back into the recovered store"
    );
    // "carry every applied leaf" is a claim about bytes; the count above holds for a
    // snapshot that carried five leaves and lost their commitments.
    for i in 0..5u32 {
        let want = canonical(u8::try_from(i).unwrap_or(0).saturating_add(1));
        let got = opened2
            .recovered_logical_store
            .leaf(0, i)
            .copied()
            .expect("leaf present after post-archive recovery");
        assert_eq!(got, want, "leaf {i} must byte-equal the commitment written");
    }
    assert_eq!(
        opened2.recovered_logical_store.imt_root(0),
        Some(staged_root),
        "the recovered IMT root must equal the staged tree's root, so corruption that \
         never reaches a leaf slot is caught too"
    );
}

/// V8 holds every occurrence of a commitment, so a recurrence survives a snapshot rather than
/// collapsing to one index the reader can never widen again.
#[test]
fn a_v8_snapshot_keeps_every_occurrence_of_a_recurring_commitment() {
    const LIST_KEY: [u8; 32] = [0x71; 32];
    let state = build_toy_state();
    let encoder =
        raven_railgun_engine::pir_table::PerListPath10Encoder::new(ENTRIES_PER_SHARD, LIST_KEY)
            .expect("per-list-path10 encoder");
    let mut store = LogicalLeafStore::default();
    for list_index in 0..2u32 {
        apply_wal_entry(
            &mut store,
            &WalEntryPayload::PpoiListLeafAdded {
                list_key: LIST_KEY,
                list_index,
                blinded_commitment: canonical(9),
                status: 0,
                event_type: raven_railgun_persistence::PpoiEventType::Shield,
                signature: vec![0; 64],
                validated_merkleroot: [0; 32],
            },
            100 + u64::from(list_index),
            &encoder,
        )
        .expect("apply recurring commitment");
    }

    let bytes = snapshot_inspire_state_v8(&state, &store).expect("v8 ser");
    let (_, back) = restore_inspire_state_v6(&bytes).expect("v8 restore");
    assert_eq!(
        back.ppoi_indices_of(&LIST_KEY, &canonical(9))
            .collect::<Vec<_>>(),
        vec![0, 1],
        "both occurrences must come back from the snapshot"
    );
}

/// The WAL payload layout before the PPOI status row was retired, declared as it was: bincode is
/// positional, so this derive writes the bytes that build wrote.
#[derive(serde::Serialize)]
#[allow(dead_code)]
enum RetiredStatusLayoutPayload {
    AppendLeaf {
        tree_number: u32,
        leaf_index: u32,
        commitment: [u8; 32],
    },
    PpoiStatus {
        list_key: [u8; 32],
        blinded_commitment: [u8; 32],
        status: u8,
    },
    PpoiListLeafAdded {
        list_key: [u8; 32],
        list_index: u32,
        blinded_commitment: [u8; 32],
        status: u8,
        event_type: raven_railgun_persistence::PpoiEventType,
        signature: Vec<u8>,
        validated_merkleroot: [u8; 32],
    },
    Reorg {
        height: u64,
    },
    Heartbeat {
        wallclock_unix_ms: u64,
    },
}

/// Truncating a WAL of the retired layout drops its list rows, so the refusal must say which
/// layout it met and send the operator to a re-bootstrap instead.
#[test]
fn a_wal_only_data_dir_of_the_retired_status_layout_is_refused_toward_a_rebootstrap() {
    let dir = tempfile::tempdir().expect("tempdir");
    let open = || {
        InspirePersistence::open(
            StoreLayout::open(dir.path()).expect("layout"),
            SCHEME_TAG,
            InstanceId::new("retired-status-layout"),
            SnapshotPolicy::default(),
            encoder_arc(),
        )
    };
    drop(open().expect("fresh open"));
    {
        let wal = Wal::open(&StoreLayout::open(dir.path()).expect("layout"), None).expect("wal");
        wal.append(
            &RetiredStatusLayoutPayload::PpoiListLeafAdded {
                list_key: [0xDD; 32],
                list_index: 0,
                blinded_commitment: canonical(9),
                status: 2,
                event_type: raven_railgun_persistence::PpoiEventType::Shield,
                signature: vec![0xAB; 64],
                validated_merkleroot: [0xAC; 32],
            },
            100,
        )
        .expect("append a retired-layout list leaf");
    }

    let Err(error) = open() else {
        panic!("a retired-layout WAL must not open");
    };
    let message = error.to_string();
    assert!(
        message.contains("PPOI status") && message.contains("re-bootstrap"),
        "{message}"
    );
    assert!(!message.contains("truncate"), "{message}");
}
