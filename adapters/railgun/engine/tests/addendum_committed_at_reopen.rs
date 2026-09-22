//! An addendum served beside a row must be derived from the tree that row was encoded from.
//!
//! On reopen the logical store is WAL-replayed to the TIP, while `encoded_db` is still the last
//! COMMITTED tree. Deriving the addenda from the replayed store and recording the committed
//! `encoded_db` as their provenance produces a pair that passes every consistency check and folds
//! to a WRONG Merkle root at HTTP 200 -- no log, no counter, caught only by the client's pinned
//! root. `entries_per_shard == 1 << PATH10_LEVELS`, so a single append into shard `s^1` moves
//! shard `s`'s upper siblings; one uncommitted leaf is enough.
//!
//! Every case below asserts on a VALUE, not an absence. A test that only asserted `None` would
//! stay green under a "fix" that buys soundness by refusing to serve at all.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{
    apply_wal_entry, setup_state, LogicalLeafStore, RavenInspireScheme,
};
use raven_railgun_engine::persistence::{
    run_consumer_task, ConsumerEvent, ConsumerMetrics, InspirePersistence, OpenedInstance,
    SnapshotPolicy,
};
use raven_railgun_engine::pir_table::{PerListPath10Encoder, PirTableEncoder, PATH10_RECORD_BYTES};
use raven_railgun_engine::{InstanceRole, PirInstance};
use raven_railgun_persistence::{StoreLayout, WalEntryPayload};

const SCHEME_TAG: &str = "raven-inspire-twopacking-addendum-committed-at-reopen";
const INSTANCE: &str = "addendum-committed-at-reopen";
const LIST_KEY: [u8; 32] = [0xab; 32];
/// `1 << PATH10_LEVELS`: one shard is exactly one level-11 subtree.
const ENTRIES_PER_SHARD: u32 = 2_048;
const ADDENDUM_BYTES: usize = 5 * 32;
const COMMIT_HEIGHT: u64 = 500;

fn bc_for(index: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..20].copy_from_slice(&index.to_be_bytes());
    out[31] = 0x01;
    out
}

fn leaf_payload(index: u32) -> WalEntryPayload {
    WalEntryPayload::PpoiListLeafAdded {
        list_key: LIST_KEY,
        list_index: index,
        blinded_commitment: bc_for(index),
        status: 0,
        event_type: raven_railgun_persistence::PpoiEventType::Shield,
        signature: vec![0; 64],
        validated_merkleroot: [0; 32],
    }
}

/// Leaves in the per-list IMT. `leaf_count` counts the COMMITMENT tree, which a PPOI list
/// never touches.
fn list_leaf_count(store: &LogicalLeafStore) -> usize {
    store
        .ppoi_imt(&LIST_KEY)
        .map_or(0, raven_railgun_engine::imt::Imt::leaf_count)
}

/// Levels 11..15 of the path to a shard's first leaf, read from whatever tree `store` holds.
fn live_addendum(store: &LogicalLeafStore, shard_id: u32) -> Vec<u8> {
    let proof = store
        .ppoi_merkle_proof(&LIST_KEY, shard_id * ENTRIES_PER_SHARD)
        .expect("live proof");
    proof
        .elements
        .into_iter()
        .skip(11)
        .take(5)
        .flatten()
        .collect()
}

fn encoder() -> Arc<dyn PirTableEncoder> {
    Arc::new(PerListPath10Encoder::new(ENTRIES_PER_SHARD, LIST_KEY).expect("encoder"))
}

fn open_at(dir: &std::path::Path, enc: Arc<dyn PirTableEncoder>) -> OpenedInstance {
    InspirePersistence::open(
        StoreLayout::open(dir).expect("layout"),
        SCHEME_TAG,
        InstanceId::new(INSTANCE),
        SnapshotPolicy::default(),
        enc,
    )
    .expect("open")
}

fn toy_state_at_path10_width() -> raven_railgun_engine::inspire::InspireServerState {
    raven_railgun_testkit::toy_state(PATH10_RECORD_BYTES)
}

/// Fill shard 0 exactly, commit the pair, then optionally append one leaf to the WAL ONLY.
///
/// That trailing leaf is index `ENTRIES_PER_SHARD`, the first of shard 0's level-11 sibling
/// subtree, so replaying it necessarily moves shard 0's addendum. Dropping the handle without a
/// second commit is the unclean stop.
///
/// Returns the committed tree's shard-0 addendum: the only value the server may serve beside a
/// row encoded from that tree.
fn seed(dir: &std::path::Path, trailing_append: bool) -> Vec<u8> {
    let enc = encoder();
    let opened = open_at(dir, Arc::clone(&enc));
    let mut store = LogicalLeafStore::new();
    for index in 0..ENTRIES_PER_SHARD {
        let payload = leaf_payload(index);
        opened
            .persistence
            .apply_event(&payload, COMMIT_HEIGHT)
            .expect("wal append");
        apply_wal_entry(&mut store, &payload, COMMIT_HEIGHT, enc.as_ref()).expect("store append");
    }

    let params = InspireParams::secure_128_d2048();
    let db = enc.materialize_shard(0, &store);
    let (state, _sk) = setup_state(
        &params,
        &db,
        PATH10_RECORD_BYTES,
        InspireVariant::TwoPacking,
    )
    .expect("setup_state");
    opened
        .persistence
        .commit_v6(&state, &store, COMMIT_HEIGHT)
        .expect("commit_v6");

    let expected = live_addendum(&store, 0);
    assert_eq!(
        expected.len(),
        ADDENDUM_BYTES,
        "an addendum is five sibling hashes; a short one folds to a wrong root"
    );

    if trailing_append {
        opened
            .persistence
            .apply_event(&leaf_payload(ENTRIES_PER_SHARD), COMMIT_HEIGHT + 1)
            .expect("uncommitted wal append");
    }
    drop(opened);
    expected
}

/// CASE A: `open()` must hand back the COMMITTED addendum, not the replayed tip's.
#[test]
fn open_after_an_unclean_stop_restores_the_committed_addendum() {
    let dir = tempfile::tempdir().expect("tempdir");
    let expected = seed(dir.path(), true);

    let reopened = open_at(dir.path(), encoder());
    let store = &reopened.recovered_logical_store;

    // NEGATIVE CONTROL, FIRST. Without it every assertion below passes on a tree that never moved.
    assert_eq!(
        list_leaf_count(store),
        ENTRIES_PER_SHARD as usize + 1,
        "WAL replay must carry the store past the committed tree, or this test proves nothing"
    );
    assert_ne!(
        expected,
        live_addendum(store, 0),
        "the uncommitted leaf must actually move shard 0's upper siblings"
    );

    let recovered = reopened
        .recovered_state
        .as_ref()
        .expect("a committed snapshot must be recovered");
    assert_eq!(
        store.committed_addendum(&LIST_KEY, 0),
        Some(&expected[..]),
        "the addendum must belong to the tree `encoded_db` was encoded from"
    );
    assert!(
        store.committed_addenda_derived_from(&recovered.encoded_db),
        "provenance must name the recovered encoded database"
    );
}

/// CASE B -- THE GATE. The defect end to end, in the production wiring, by value.
///
/// The boot seed in `run_consumer_task` derives from the store it is handed, which recovery has
/// already advanced to the WAL tip, and records the COMMITTED `encoded_db` as provenance. The
/// resulting pair is what `inspire_batch_handler` folds into a Merkle root.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_consumer_boot_seed_must_not_replace_the_committed_addendum_with_the_tip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let expected = seed(dir.path(), true);

    let enc = encoder();
    let reopened = open_at(dir.path(), Arc::clone(&enc));
    let recovered_state = reopened
        .recovered_state
        .expect("a committed snapshot must be recovered");
    let instance: Arc<PirInstance<RavenInspireScheme>> = Arc::new(PirInstance::new(
        InstanceId::new(INSTANCE),
        InstanceRole::Live,
        recovered_state,
    ));
    let store = Arc::new(parking_lot::Mutex::new(reopened.recovered_logical_store));

    // Sender dropped up front: the task runs its boot seeding, then exits on channel close.
    let (tx, rx) = tokio::sync::mpsc::channel::<ConsumerEvent>(1);
    drop(tx);
    let task = tokio::spawn(run_consumer_task(
        Arc::clone(&instance),
        Arc::new(reopened.persistence),
        Arc::clone(&store),
        Arc::new(parking_lot::Mutex::new(ConsumerMetrics::default())),
        InspireParams::secure_128_d2048(),
        enc,
        rx,
        None,
    ));
    tokio::time::timeout(Duration::from_secs(60), task)
        .await
        .expect("consumer task must exit on channel close")
        .expect("consumer join")
        .expect("consumer exit");

    let guard = store.lock();
    let served_db = &instance.current_snapshot().state.encoded_db;

    // NEGATIVE CONTROL, FIRST.
    assert_ne!(
        expected,
        live_addendum(&guard, 0),
        "the consumer must be holding a store that is ahead of the committed tree"
    );

    assert!(
        guard.committed_addenda_derived_from(served_db),
        "the served state and the addenda must be a matched pair"
    );
    let served = guard
        .committed_addendum(&LIST_KEY, 0)
        .expect("shard 0 must carry an addendum");
    assert_eq!(
        served,
        &expected[..],
        "WRONG MERKLE ROOT AT HTTP 200: the addendum served beside a row from the committed \
         tree is the WAL tip's. Every path query for shard 0 folds to a root the client can \
         only reject as a pin mismatch"
    );
}

/// CASE C: the clean restart keeps the optimization. A fix that refuses here is an outage.
#[test]
fn a_clean_restart_serves_immediately_with_no_refusal_window() {
    let dir = tempfile::tempdir().expect("tempdir");
    let expected = seed(dir.path(), false);

    let reopened = open_at(dir.path(), encoder());
    let store = &reopened.recovered_logical_store;
    let recovered = reopened
        .recovered_state
        .as_ref()
        .expect("a committed snapshot must be recovered");

    assert_eq!(
        list_leaf_count(store),
        ENTRIES_PER_SHARD as usize,
        "a clean stop leaves the store exactly at the committed tree"
    );
    assert_eq!(
        store.committed_addendum(&LIST_KEY, 0),
        Some(&expected[..]),
        "a clean restart must serve from the first request, not after the first commit"
    );
    assert!(store.committed_addenda_derived_from(&recovered.encoded_db));
}

/// CASE D: an instance with a manifest but NO committed snapshot must refuse, not invent.
///
/// This is the `bootstrap_subsquid` shape. There is no committed tree at all, so no addendum can
/// be correct -- today the boot seed folds the WAL tip's upper siblings onto a synthetic
/// `(i + j) % 251` row and returns HTTP 200.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_instance_with_no_committed_snapshot_serves_no_addendum() {
    let dir = tempfile::tempdir().expect("tempdir");
    let enc = encoder();
    {
        let opened = open_at(dir.path(), Arc::clone(&enc));
        assert!(
            opened.recovered_state.is_none(),
            "fresh bootstrap must leave no recovered state"
        );
        for index in 0..4u32 {
            opened
                .persistence
                .apply_event(&leaf_payload(index), COMMIT_HEIGHT)
                .expect("wal append");
        }
    }

    let reopened = open_at(dir.path(), Arc::clone(&enc));
    assert!(
        reopened.recovered_state.is_none(),
        "snapshot id 0 means no committed tree"
    );
    // NEGATIVE CONTROL: replay really did populate a tree an over-eager seed could derive from.
    assert_eq!(
        list_leaf_count(&reopened.recovered_logical_store),
        4,
        "WAL replay must fill the store, or this test proves nothing"
    );

    let synthetic = toy_state_at_path10_width();
    let instance: Arc<PirInstance<RavenInspireScheme>> = Arc::new(PirInstance::new(
        InstanceId::new(INSTANCE),
        InstanceRole::Live,
        synthetic,
    ));
    let store = Arc::new(parking_lot::Mutex::new(reopened.recovered_logical_store));

    assert_eq!(
        store.lock().committed_addendum(&LIST_KEY, 0),
        None,
        "open() must not seed an addendum for a tree that was never committed"
    );

    let (tx, rx) = tokio::sync::mpsc::channel::<ConsumerEvent>(1);
    drop(tx);
    let task = tokio::spawn(run_consumer_task(
        Arc::clone(&instance),
        Arc::new(reopened.persistence),
        Arc::clone(&store),
        Arc::new(parking_lot::Mutex::new(ConsumerMetrics::default())),
        InspireParams::secure_128_d2048(),
        enc,
        rx,
        None,
    ));
    tokio::time::timeout(Duration::from_secs(60), task)
        .await
        .expect("consumer task must exit on channel close")
        .expect("consumer join")
        .expect("consumer exit");

    let guard = store.lock();
    assert_eq!(
        guard.committed_addendum(&LIST_KEY, 0),
        None,
        "SILENT WRONG ROOT: an addendum from the WAL tip served beside a synthetic row"
    );
    assert!(
        !guard.committed_addenda_derived_from(&instance.current_snapshot().state.encoded_db),
        "provenance must stay unset until a real commit establishes a tree"
    );
}

/// The function-level falsehood, in isolation: `refresh_committed_addenda` records whatever tree
/// `self` holds under whatever `Arc` it is handed, and cannot tell the two apart. Pins the
/// precondition its docstring now states. It does NOT gate the fix — the fix moved the call site.
#[test]
fn refresh_records_the_stores_current_tree_whatever_db_it_is_handed() {
    let enc = encoder();
    let mut store = LogicalLeafStore::new();
    for index in 0..ENTRIES_PER_SHARD {
        apply_wal_entry(
            &mut store,
            &leaf_payload(index),
            COMMIT_HEIGHT,
            enc.as_ref(),
        )
        .expect("store append");
    }
    let at_2048 = live_addendum(&store, 0);

    // The tree runs one append ahead of the database it is about to be paired with.
    apply_wal_entry(
        &mut store,
        &leaf_payload(ENTRIES_PER_SHARD),
        COMMIT_HEIGHT + 1,
        enc.as_ref(),
    )
    .expect("store append past the commit");
    assert_ne!(
        at_2048,
        live_addendum(&store, 0),
        "the append must move shard 0's upper siblings, or this test proves nothing"
    );

    let db_at_2048 = toy_state_at_path10_width().encoded_db;
    store.refresh_committed_addenda(&db_at_2048, ENTRIES_PER_SHARD);

    assert!(
        store.committed_addenda_derived_from(&db_at_2048),
        "the guard reports consistency for a pair that is not consistent -- which is why the \
         precondition has to be met at the CALL SITE"
    );
    assert_ne!(
        store.committed_addendum(&LIST_KEY, 0),
        Some(&at_2048[..]),
        "the recorded addendum is the 2,049-leaf tree's, not the database's"
    );
}
