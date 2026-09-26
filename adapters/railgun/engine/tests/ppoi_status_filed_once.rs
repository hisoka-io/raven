//! A list's statuses are stored once across its block instances, not once per block.
//!
//! A `PpoiStatus` carries a blinded commitment and no list index, so the router cannot
//! localize it and hands it to every block of the list. Each block must file it only for a
//! commitment it indexes: the sum of the blocks' status maps is then the list's, and a
//! block's map is the size of its own rows.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use raven_inspire::params::InspireParams;
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{apply_wal_entry, InspireServerState, LogicalLeafStore};
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine_multi, DataSourceFilter, InstanceConfig, VerificationMode,
    LEAVES_PER_PPOI_BLOCK,
};
use raven_railgun_engine::persistence::{ConsumerEvent, InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{EncoderKind, PerListStatusEncoder, PirTableEncoder};
use raven_railgun_engine::InstanceRole;
use raven_railgun_persistence::{PpoiEventType, StoreLayout, WalEntryPayload};
use raven_railgun_testkit::canonical;
use tokio::sync::mpsc;

const LIST_KEY: [u8; 32] = [0x6c; 32];
const ENTRY_SIZE: usize = 32;
const ENTRIES_PER_SHARD: u32 = 2048;
const ROWS_PER_BLOCK: u32 = 3;
const VALID: u8 = 0;
const SHIELD_BLOCKED: u8 = 1;

fn encoder() -> PerListStatusEncoder {
    PerListStatusEncoder::new(ENTRY_SIZE, ENTRIES_PER_SHARD, LIST_KEY).expect("encoder")
}

fn bc(global_index: u32) -> [u8; 32] {
    canonical(
        u8::try_from(global_index % 200)
            .unwrap_or(0)
            .saturating_add(0x20),
    )
}

fn leaf(list_index: u32, blinded_commitment: [u8; 32]) -> WalEntryPayload {
    WalEntryPayload::PpoiListLeafAdded {
        list_key: LIST_KEY,
        list_index,
        blinded_commitment,
        status: VALID,
        event_type: PpoiEventType::Shield,
        signature: vec![0; 64],
        validated_merkleroot: [0; 32],
    }
}

fn status(blinded_commitment: [u8; 32], status: u8) -> WalEntryPayload {
    WalEntryPayload::PpoiStatus {
        list_key: LIST_KEY,
        blinded_commitment,
        status,
    }
}

/// Global indices of the first `ROWS_PER_BLOCK` rows of blocks 0 and 1.
fn list_indices() -> Vec<u32> {
    (0..2u32)
        .flat_map(|block| {
            (0..ROWS_PER_BLOCK).map(move |local| block * LEAVES_PER_PPOI_BLOCK + local)
        })
        .collect()
}

fn host_config(root: &std::path::Path) -> InstanceConfig {
    let encoder = EncoderKind::PerListStatus { list_key: LIST_KEY };
    InstanceConfig {
        instance_id: InstanceId::new("ppoi-status-filed-once-host"),
        role: InstanceRole::Live,
        data_dir: root.join("host"),
        encoder,
        record_size: encoder.effective_record_size(ENTRY_SIZE),
        entries_per_shard: ENTRIES_PER_SHARD,
        verification_mode: VerificationMode::UpstreamAsserted,
        data_source: DataSourceFilter::PpoiList(LIST_KEY),
        use_flock: false,
        snapshot_policy: SnapshotPolicy::default(),
        scheme_tag: "raven-inspire-twopacking-inspiring-wp3-status-filed-once".to_owned(),
        channel_capacity: 256,
        max_concurrent_queries: None,
        verification_cadence_n: 0,
        chain_source: None,
    }
}

async fn drain(rx: &mut mpsc::Receiver<ConsumerEvent>, want: usize) -> Vec<WalEntryPayload> {
    let mut out = Vec::with_capacity(want);
    while out.len() < want {
        let event = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("block route received {} of {want} events", out.len()))
            .expect("block route channel open");
        match event {
            ConsumerEvent::Ppoi(payload, _) => out.push(payload),
            other => panic!("expected a PPOI event, got {other:?}"),
        }
    }
    out
}

/// Drives the REAL router with the mirror's own emission order (each leaf, then its status),
/// plus one later status update, and applies what each block route receives to its own store.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_blocks_together_hold_each_status_once() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let factory = |c: &InstanceConfig| -> raven_railgun_core::Result<InspireServerState> {
        raven_railgun_testkit::try_toy_state(c.record_size)
    };
    let mut handle = bootstrap_railgun_engine_multi(
        vec![host_config(tmp.path())],
        InspireParams::secure_128_d2048(),
        factory,
    )
    .expect("bootstrap");

    let (tx0, mut rx0) = mpsc::channel::<ConsumerEvent>(64);
    let (tx1, mut rx1) = mpsc::channel::<ConsumerEvent>(64);
    handle.ppoi_list_routes.store(Arc::new(vec![
        (
            DataSourceFilter::PpoiListBlock {
                list_key: LIST_KEY,
                block: 0,
            },
            tx0,
        ),
        (
            DataSourceFilter::PpoiListBlock {
                list_key: LIST_KEY,
                block: 1,
            },
            tx1,
        ),
    ]));

    let indices = list_indices();
    let updated = bc(LEAVES_PER_PPOI_BLOCK + 1);
    let mut sent = Vec::new();
    for &global in &indices {
        sent.push(leaf(global, bc(global)));
        sent.push(status(bc(global), VALID));
    }
    sent.push(status(updated, SHIELD_BLOCKED));
    for payload in sent {
        handle
            .channels
            .mirror_tx
            .send((payload, 0))
            .await
            .expect("router mirror inbound open");
    }

    // Each block: its own leaves, every status of the list, and the update.
    let rows = ROWS_PER_BLOCK as usize;
    let per_block = rows + indices.len() + 1;
    let mut blocks = Vec::new();
    for rx in [&mut rx0, &mut rx1] {
        let mut store = LogicalLeafStore::new();
        for payload in drain(rx, per_block).await {
            apply_wal_entry(&mut store, &payload, 0, &encoder()).expect("apply routed payload");
        }
        blocks.push(store);
    }

    for (block, store) in blocks.iter().enumerate() {
        assert_eq!(store.ppoi_list_leaves_iter(&LIST_KEY).count(), rows);
        assert_eq!(
            store.ppoi_count(),
            rows,
            "block {block} must hold the statuses of its own rows and no others"
        );
    }
    assert_eq!(
        blocks
            .iter()
            .map(LogicalLeafStore::ppoi_count)
            .sum::<usize>(),
        indices.len(),
        "across the blocks, the list's statuses are stored exactly once"
    );
    for &global in &indices {
        let holders = blocks
            .iter()
            .filter(|store| store.ppoi_status(&LIST_KEY, &bc(global)).is_some())
            .count();
        assert_eq!(holders, 1, "global index {global} is filed by one block");
    }
    let [block0, block1] = blocks.as_slice() else {
        panic!("two block routes");
    };
    assert_eq!(
        block1.ppoi_status_at(&LIST_KEY, 1),
        Some(SHIELD_BLOCKED),
        "a later status update still reaches the block that owns the row"
    );
    assert_eq!(block0.ppoi_status(&LIST_KEY, &updated), None);

    drop(handle.channels);
    for h in handle.instances.drain(..) {
        let _ = h.sender.send(ConsumerEvent::Shutdown).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), h.consumer).await;
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), handle.router).await;
}

/// A status that arrives with a height below its leaf's survives a rewind that takes the leaf,
/// unless the rewind retires it with the last occurrence.
#[test]
fn a_rewind_that_unindexes_a_commitment_retires_its_status() {
    let mut store = LogicalLeafStore::new();
    apply_wal_entry(&mut store, &leaf(0, bc(0)), 100, &encoder()).expect("leaf");
    apply_wal_entry(&mut store, &status(bc(0), SHIELD_BLOCKED), 50, &encoder()).expect("status");
    assert_eq!(store.ppoi_count(), 1);

    apply_wal_entry(
        &mut store,
        &WalEntryPayload::Reorg { height: 75 },
        75,
        &encoder(),
    )
    .expect("reorg");

    assert_eq!(
        store.ppoi_bc_at(&LIST_KEY, 0),
        None,
        "the leaf was above 75"
    );
    assert_eq!(store.ppoi_status(&LIST_KEY, &bc(0)), None);
    assert_eq!(store.ppoi_count(), 0);
}

/// A rewind that keeps one occurrence of a recurring commitment keeps its status.
#[test]
fn a_rewind_that_keeps_an_occurrence_keeps_its_status() {
    let mut store = LogicalLeafStore::new();
    apply_wal_entry(&mut store, &leaf(0, bc(0)), 0, &encoder()).expect("first occurrence");
    apply_wal_entry(&mut store, &leaf(1, bc(0)), 100, &encoder()).expect("second occurrence");
    apply_wal_entry(&mut store, &status(bc(0), SHIELD_BLOCKED), 50, &encoder()).expect("status");

    apply_wal_entry(
        &mut store,
        &WalEntryPayload::Reorg { height: 75 },
        75,
        &encoder(),
    )
    .expect("reorg");

    assert_eq!(store.ppoi_bc_at(&LIST_KEY, 1), None);
    assert_eq!(store.ppoi_status_at(&LIST_KEY, 0), Some(SHIELD_BLOCKED));
}

/// Replay files exactly what the live apply filed, across a snapshot and the WAL tail after it,
/// and the tail itself carries statuses for rows the block does not index.
#[test]
fn wal_replay_files_the_same_statuses_as_the_live_block() {
    let dir = tempfile::tempdir().expect("tempdir");
    let scheme_tag = "raven-inspire-twopacking-inspiring-wp3-status-replay";
    let instance = "ppoi-status-replay-block-1";
    let status_encoder = || -> Arc<dyn PirTableEncoder> {
        EncoderKind::PerListStatus { list_key: LIST_KEY }
            .build(ENTRY_SIZE, ENTRIES_PER_SHARD)
            .expect("encoder")
    };

    // What block 1's route delivers: each own row at its local index with its status, block 0's
    // statuses (their leaves go to block 0) interleaved, then an update to an own row. The commit
    // lands after the first triple, so block 0's statuses sit on both sides of it and replay must
    // drop the ones in the tail by itself.
    let own = |local: u32| bc(LEAVES_PER_PPOI_BLOCK + local);
    let mut routed = Vec::new();
    for local in 0..ROWS_PER_BLOCK {
        routed.push(leaf(local, own(local)));
        routed.push(status(own(local), VALID));
        routed.push(status(bc(local), VALID));
    }
    routed.push(status(own(0), SHIELD_BLOCKED));
    let split = 3;

    let mut live = LogicalLeafStore::new();
    {
        let opened = InspirePersistence::open(
            StoreLayout::open(dir.path()).expect("layout"),
            scheme_tag,
            InstanceId::new(instance),
            SnapshotPolicy::default(),
            status_encoder(),
        )
        .expect("fresh open");
        let state = raven_railgun_testkit::toy_state(ENTRY_SIZE);
        for (seq, payload) in routed.iter().enumerate() {
            apply_wal_entry(&mut live, payload, 0, &encoder()).expect("live apply");
            opened
                .persistence
                .apply_event(payload, 0)
                .expect("apply_event");
            if seq + 1 == split {
                opened
                    .persistence
                    .commit_v6(&state, &live, 0)
                    .expect("commit");
            }
        }
    }

    let reopened = InspirePersistence::open(
        StoreLayout::open(dir.path()).expect("layout reopen"),
        scheme_tag,
        InstanceId::new(instance),
        SnapshotPolicy::default(),
        status_encoder(),
    )
    .expect("recovery open");
    let recovered = &reopened.recovered_logical_store;

    assert_eq!(
        recovered.ppoi_count(),
        ROWS_PER_BLOCK as usize,
        "replay must file the block's own rows and drop the other block's statuses in the tail"
    );
    assert_eq!(live.ppoi_count(), recovered.ppoi_count());
    for global in (0..ROWS_PER_BLOCK).chain((0..ROWS_PER_BLOCK).map(|l| LEAVES_PER_PPOI_BLOCK + l))
    {
        assert_eq!(
            recovered.ppoi_status(&LIST_KEY, &bc(global)),
            live.ppoi_status(&LIST_KEY, &bc(global)),
            "global index {global}"
        );
    }
    assert_eq!(recovered.ppoi_status(&LIST_KEY, &bc(0)), None);
    assert_eq!(recovered.ppoi_status_at(&LIST_KEY, 0), Some(SHIELD_BLOCKED));
}
