#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{
    apply_wal_entry, restore_inspire_state_v6, setup_state, snapshot_inspire_state,
    snapshot_inspire_state_v6, InspireServerState, LogicalLeafStore, SNAPSHOT_V6_MAGIC,
};
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_persistence::{
    Manifest, Snapshot, SnapshotId, StoreLayout, Wal, WalEntryPayload, MANIFEST_SCHEMA_VERSION,
};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-wal-v6-recovery";
const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_SIZE: usize = 32;
const ENTRIES_PER_SHARD: u32 = 256;

fn build_toy_state() -> InspireServerState {
    let params = InspireParams::secure_128_d2048();
    let db: Vec<u8> = (0..TOY_ENTRIES)
        .flat_map(|i| (0..TOY_ENTRY_SIZE).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
        .collect();
    let (state, _sk) =
        setup_state(&params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking).expect("setup_state");
    state
}

fn encoder_arc() -> Arc<dyn PirTableEncoder> {
    EncoderKind::PerLeafBc
        .build(TOY_ENTRY_SIZE, ENTRIES_PER_SHARD)
        .expect("build encoder")
}

fn canonical(seed: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = seed.max(1);
    b
}

#[test]
fn bootstrap_then_drive_commit_then_restart_recovers_logical_store() {
    let dir = tempfile::tempdir().expect("tempdir");

    {
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("v6-recovery-1"),
            SnapshotPolicy::default(),
            encoder_arc(),
        )
        .expect("fresh open");

        let state = build_toy_state();
        let mut store = LogicalLeafStore::default();
        let encoder: Arc<dyn PirTableEncoder> = encoder_arc();

        for i in 0..8u32 {
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
            .commit_v6(&state, &store, 200)
            .expect("commit_v6");
    }

    let layout2 = StoreLayout::open(dir.path()).expect("layout reopen");
    let opened2 = InspirePersistence::open(
        layout2,
        SCHEME_TAG,
        InstanceId::new("v6-recovery-1"),
        SnapshotPolicy::default(),
        encoder_arc(),
    )
    .expect("recovery open");

    assert_eq!(
        opened2.recovered_logical_store.imt_leaf_count_for(0),
        8,
        "V6 snapshot must restore 8 leaves into the logical store after WAL archive"
    );
    for i in 0..8u32 {
        let want = canonical(u8::try_from(i).unwrap_or(0).saturating_add(1));
        let got = opened2
            .recovered_logical_store
            .leaf(0, i)
            .copied()
            .expect("leaf present after recovery");
        assert_eq!(got, want, "leaf {i} commitment hash must round-trip");
    }
}

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
        "V6 snapshot (4 leaves) + WAL replay (2 leaves) must combine to 6"
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
}

#[test]
fn manifest_v5_compatibility_on_open_existing_data() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");

    let state = build_toy_state();
    let v5_bytes = snapshot_inspire_state(&state).expect("snapshot v5");
    let v5_head = v5_bytes.get(..SNAPSHOT_V6_MAGIC.len()).unwrap_or(&v5_bytes);
    assert_ne!(
        v5_head, SNAPSHOT_V6_MAGIC,
        "V5 codec must not accidentally emit the V6 magic prefix"
    );

    let snap_id = SnapshotId(1);
    let snap = Snapshot::build(v5_bytes);
    snap.save(&layout, snap_id).expect("save v5 snapshot");

    let manifest = Manifest {
        schema_version: 5,
        scheme_tag: SCHEME_TAG.to_owned(),
        instance_id: "v5-compat".to_owned(),
        current_snapshot_id: snap_id,
        current_snapshot_seq: 0,
        current_block_height: 0,
        encoder_label: encoder_arc().label().to_owned(),
        prev_encoder_label: None,
    };
    manifest.save(&layout).expect("save v5 manifest");

    let layout2 = StoreLayout::open(dir.path()).expect("layout reopen");
    let opened = InspirePersistence::open(
        layout2,
        SCHEME_TAG,
        InstanceId::new("v5-compat"),
        SnapshotPolicy::default(),
        encoder_arc(),
    )
    .expect("V5 manifest must load under the V6-capable engine");

    assert_eq!(
        opened.recovered_logical_store.leaf_count(),
        0,
        "legacy V5 snapshot has no embedded LogicalLeafStore; recovery starts empty"
    );

    let state_after = opened.recovered_state.expect("recovered state present");
    let store = LogicalLeafStore::default();
    opened
        .persistence
        .commit_v6(&state_after, &store, 1)
        .expect("upgrade commit must succeed and bump manifest to V6");

    let m_after = Manifest::load(&layout)
        .expect("manifest reread")
        .expect("present");
    assert_eq!(
        m_after.schema_version, MANIFEST_SCHEMA_VERSION,
        "after a V6 commit the on-disk manifest must report the current schema"
    );
}

#[test]
fn snapshot_v6_envelope_roundtrips_in_isolation() {
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
    let bytes = snapshot_inspire_state_v6(&state, &store).expect("v6 ser");
    let head = bytes
        .get(..SNAPSHOT_V6_MAGIC.len())
        .expect("v6 bytes long enough to hold magic");
    assert_eq!(
        head, SNAPSHOT_V6_MAGIC,
        "v6 envelope must lead with the magic prefix"
    );
    let (back_state, back_store) = restore_inspire_state_v6(&bytes).expect("v6 restore");
    assert_eq!(back_state.entry_size, state.entry_size);
    assert_eq!(back_store.imt_leaf_count_for(0), 3);
    for i in 0..3u32 {
        let want = canonical(u8::try_from(i).unwrap_or(0).saturating_add(1));
        let got = back_store.leaf(0, i).copied().expect("leaf present");
        assert_eq!(got, want);
    }
}

#[test]
fn v5_bytes_decoded_by_v6_reader_yields_empty_store() {
    let state = build_toy_state();
    let v5_bytes = snapshot_inspire_state(&state).expect("v5 ser");
    let (back_state, back_store) =
        restore_inspire_state_v6(&v5_bytes).expect("v6 restore on v5 bytes");
    assert_eq!(back_state.entry_size, state.entry_size);
    assert_eq!(
        back_store.leaf_count(),
        0,
        "V5 fallback path must yield an empty store"
    );
}

#[test]
fn drive_commit_truncates_wal_yet_v6_recovery_is_complete() {
    // commit_v6 archives the WAL, so reopen reads zero entries from current.log; the V6 snapshot must still recover every leaf
    let dir = tempfile::tempdir().expect("tempdir");

    {
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("v6-wal-truncate"),
            SnapshotPolicy::default(),
            encoder_arc(),
        )
        .expect("fresh open");

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

        opened
            .persistence
            .commit_v6(&state, &store, 999)
            .expect("commit_v6");
    }

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

    assert_eq!(
        opened2.recovered_logical_store.imt_leaf_count_for(0),
        5,
        "Even with empty current.log post-archive, the V6 snapshot must \
         carry every applied leaf back into the recovered store"
    );
}
