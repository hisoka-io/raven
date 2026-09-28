//! A mirror-fed `role = "static"` PPOI block must serve the rows it applies, before any restart.
//!
//! The shim reads the logical store, so a block that applies rows without publishing them looks
//! healthy there while every PIR query answers from its boot-time table. What is decoded here is
//! the served state, through a real query, never the store.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use std::time::Duration;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::rlwe::RlweSecretKey;
use raven_railgun_core::{AdapterError, InstanceId, POIStatus};
use raven_railgun_engine::imt::Imt;
use raven_railgun_engine::inspire::{
    build_client_session, build_seeded_query, extract_response, register_client_session,
    setup_state, InspireServerState, RavenInspireScheme,
};
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine_multi, DataSourceFilter, InstanceConfig, MultiOrchestratorHandle,
};
use raven_railgun_engine::persistence::{ConsumerEvent, SnapshotPolicy};
use raven_railgun_engine::pir_table::list::PATH10_MAGIC;
use raven_railgun_engine::pir_table::{EncoderKind, PATH10_RECORD_BYTES};
use raven_railgun_engine::{InstanceRole, PirScheme};
use raven_railgun_persistence::{PpoiEventType, WalEntryPayload};

const LIST_KEY: [u8; 32] = [0x5c; 32];
const EPS: u32 = 2048;
const SHARDS: usize = 2;
const ROWS: u32 = 3;
const PATH10_STATUS: usize = 32;
const PATH10_MARKER: std::ops::Range<usize> = 34..38;
const BOUND_SECS: u64 = 2;
/// Far past [`BOUND_SECS`], so only a block that never applies or never publishes reaches it on
/// a loaded box.
const PUBLISH_DEADLINE: Duration = Duration::from_secs(45);

/// The static policy with its timer short enough to observe.
fn short_bound() -> SnapshotPolicy {
    SnapshotPolicy {
        max_seconds_between_snapshots: BOUND_SECS,
        ..SnapshotPolicy::static_default()
    }
}

fn bc_for(list_index: u32) -> [u8; 32] {
    let mut bc = [0u8; 32];
    bc[0] = 0x0b;
    bc[1..5].copy_from_slice(&list_index.to_be_bytes());
    bc[31] = 0x01;
    bc
}

fn fresh_state() -> (InspireServerState, RlweSecretKey) {
    let seed = vec![0u8; SHARDS * EPS as usize * PATH10_RECORD_BYTES];
    setup_state(
        &InspireParams::secure_128_d2048(),
        &seed,
        PATH10_RECORD_BYTES,
        InspireVariant::TwoPacking,
    )
    .expect("setup")
}

/// Boots the block over `dir`; `fresh` is `None` when the boot must recover what is there.
fn boot(
    dir: &std::path::Path,
    policy: SnapshotPolicy,
    fresh: Option<InspireServerState>,
) -> MultiOrchestratorHandle {
    let mut fresh = fresh;
    let config = InstanceConfig {
        instance_id: InstanceId::new("static-path10-block-0"),
        role: InstanceRole::Static,
        data_dir: dir.join("instance"),
        encoder: EncoderKind::PerListPath10 { list_key: LIST_KEY },
        record_size: PATH10_RECORD_BYTES,
        entries_per_shard: EPS,
        data_source: DataSourceFilter::PpoiListBlock {
            list_key: LIST_KEY,
            block: 0,
        },
        use_flock: false,
        snapshot_policy: policy,
        scheme_tag: "raven-inspire-twopacking-inspiring-wp3-static-block".to_owned(),
        channel_capacity: 64,
        max_concurrent_queries: None,
        verification_cadence_n: 0,
        chain_source: None,
    };
    bootstrap_railgun_engine_multi(vec![config], InspireParams::secure_128_d2048(), |_| {
        fresh.take().ok_or_else(|| {
            AdapterError::Internal("a recovering boot built a fresh state".to_owned())
        })
    })
    .expect("boot")
}

/// Stops without the Shutdown commit, the way a kill does.
fn stop_uncleanly(handle: MultiOrchestratorHandle) {
    for instance in &handle.instances {
        instance.consumer.abort();
    }
    handle.router.abort();
}

/// Waits for the store's dirty set to drain, up to [`PUBLISH_DEADLINE`], and returns how long it
/// waited. It does not assert: the served decode that follows is the proof, and the wait it
/// prints tells a slow box (short) from a block that never published (the full deadline).
async fn wait_published(handle: &MultiOrchestratorHandle) -> Duration {
    let booted = handle.instances.first().expect("one instance");
    let started = tokio::time::Instant::now();
    while !booted.logical_store.lock().dirty_shards().is_empty()
        && started.elapsed() < PUBLISH_DEADLINE
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    started.elapsed()
}

fn assert_serves(
    state: &InspireServerState,
    secret_key: RlweSecretKey,
    list_index: u32,
    why: &str,
) {
    let row = decrypt_row(state, secret_key, list_index);
    assert_eq!(
        &row[PATH10_MARKER],
        PATH10_MAGIC.as_slice(),
        "served row {list_index} carries no marker: {why}"
    );
    assert_eq!(&row[..32], &bc_for(list_index), "the served leaf");
    assert_eq!(row[PATH10_STATUS], POIStatus::Valid.wire_byte());
}

/// Sends rows the way the mirror does: list-wide indices, height 0, through the router.
async fn mirror_rows(
    handle: &MultiOrchestratorHandle,
    upstream: &mut Imt,
    list_indices: std::ops::Range<u32>,
) {
    for list_index in list_indices {
        upstream
            .insert_leaves(list_index as usize, &[bc_for(list_index)])
            .expect("reference insert");
        let row = WalEntryPayload::PpoiListLeafAdded {
            list_key: LIST_KEY,
            list_index,
            blinded_commitment: bc_for(list_index),
            event_type: PpoiEventType::Shield,
            validated_merkleroot: upstream.root(),
        };
        handle
            .channels
            .mirror_tx
            .send((row, 0))
            .await
            .expect("router open");
    }
}

async fn wait_applied(handle: &MultiOrchestratorHandle, rows: u32) {
    let booted = handle.instances.first().expect("one instance");
    let deadline = tokio::time::Instant::now() + PUBLISH_DEADLINE;
    loop {
        assert_eq!(
            booted.metrics.lock().consumer_errors,
            0,
            "every row carries its own root"
        );
        let applied = booted
            .logical_store
            .lock()
            .ppoi_imt(&LIST_KEY)
            .map_or(0, Imt::leaf_count);
        if applied == rows as usize {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the block applied {applied} of {rows} rows"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn decrypt_row(state: &InspireServerState, secret_key: RlweSecretKey, list_index: u32) -> Vec<u8> {
    let params = InspireParams::secure_128_d2048();
    let mut session =
        build_client_session((*state.crs).clone(), secret_key, &params).expect("client session");
    register_client_session(&mut session, state).expect("register session");
    let (client_state, query) = build_seeded_query(
        &session,
        state.shard_config(),
        u64::from(list_index),
        &params,
    )
    .expect("query");
    let response = <RavenInspireScheme as PirScheme>::respond(state, &query).expect("respond");
    extract_response(&state.crs, &client_state, &response, state.entry_size).expect("extract")
}

/// Rows applied and then a quiet feed: nothing else arrives, no chain signal, no shutdown.
///
/// The static policy's timer is shortened to [`BOUND_SECS`] so the bound is observable in a test;
/// the production static policy's own bound is pinned in the persistence unit tests. The feed is
/// row 0, a quiet spell past the timer, then rows 1 and 2 back to back, so an append-driven
/// trigger can fire on row 1 but not on row 2. Whatever published the last row did so with no
/// event after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_static_block_serves_mirrored_rows_once_the_feed_goes_quiet() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fresh, secret_key) = fresh_state();
    let handle = boot(dir.path(), short_bound(), Some(fresh));
    let mut upstream = Imt::new().expect("reference tree");

    mirror_rows(&handle, &mut upstream, 0..1).await;
    wait_applied(&handle, 1).await;
    tokio::time::sleep(Duration::from_millis(BOUND_SECS * 1000 + 500)).await;
    mirror_rows(&handle, &mut upstream, 1..ROWS).await;
    wait_applied(&handle, ROWS).await;

    let waited = wait_published(&handle).await;
    let booted = handle.instances.first().expect("one instance");
    assert_serves(
        &booted.instance.current_state(),
        secret_key,
        ROWS - 1,
        &format!("the block applied it and had not published it after {waited:?}"),
    );
    assert!(
        booted.logical_store.lock().dirty_shards().is_empty(),
        "nothing applied is left unpublished"
    );
    stop_uncleanly(handle);
}

/// A feed that never goes quiet must not hold off the publish: a row arrives every half second,
/// well inside the bound, for several bounds, and the first row is served before the feed stops.
///
/// The shortened timer would also fire the append trigger on every row and publish them whatever
/// the consumer does, so each row appends under the static policy, which has no trigger, as in
/// production. The bound is shortened again for a heartbeat sent after the row: it appends
/// nothing, and it is where the consumer next reads the bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_steady_feed_does_not_hold_off_the_publish() {
    const TICK: Duration = Duration::from_millis(500);
    let min_feed = Duration::from_secs(BOUND_SECS * 3);
    let dir = tempfile::tempdir().expect("tempdir");
    let (fresh, secret_key) = fresh_state();
    let handle = boot(dir.path(), SnapshotPolicy::static_default(), Some(fresh));
    let booted = handle.instances.first().expect("one instance");
    let mut upstream = Imt::new().expect("reference tree");
    let commits = booted.metrics.lock().commits_fired;

    let started = tokio::time::Instant::now();
    let mut rows = 0;
    let mut served = None;
    while served.is_none() || started.elapsed() < min_feed {
        assert!(
            started.elapsed() < PUBLISH_DEADLINE,
            "{rows} rows, one per {TICK:?}, and no publish at a {BOUND_SECS} s bound"
        );
        let next_tick = tokio::time::Instant::now() + TICK;
        booted
            .persistence
            .set_snapshot_policy(SnapshotPolicy::static_default());
        mirror_rows(&handle, &mut upstream, rows..rows + 1).await;
        rows += 1;
        wait_applied(&handle, rows).await;
        booted.persistence.set_snapshot_policy(short_bound());
        // Straight to the consumer: the router sends heartbeats to chain-tree instances only.
        booted
            .sender
            .send(ConsumerEvent::Heartbeat {
                chain_head: 0,
                scanned_through: 0,
            })
            .await
            .expect("consumer open");
        tokio::time::sleep_until(next_tick).await;
        // A publish swaps the served state before it counts the commit.
        if served.is_none() && booted.metrics.lock().commits_fired > commits {
            served = Some(booted.instance.current_state());
        }
    }

    let served = served.expect("the loop exits only once a publish is seen");
    assert_serves(
        &served,
        secret_key,
        0,
        "a commit landed during the feed and left it unserved",
    );
    stop_uncleanly(handle);
}

/// A kill leaves the rows in the WAL and out of the snapshot. Recovery replays them into the
/// logical store only, so the restarted block must still publish them on its own.
///
/// The first life runs the production static policy, whose bound is far past this test, so the
/// kill is sure to land before any publish.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restarted_static_block_serves_the_rows_its_wal_replayed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fresh, secret_key) = fresh_state();
    let first = boot(dir.path(), SnapshotPolicy::static_default(), Some(fresh));
    let mut upstream = Imt::new().expect("reference tree");
    mirror_rows(&first, &mut upstream, 0..ROWS).await;
    wait_applied(&first, ROWS).await;
    stop_uncleanly(first);

    let second = boot(dir.path(), short_bound(), None);
    let booted = second.instances.first().expect("one instance");
    assert_eq!(
        booted
            .logical_store
            .lock()
            .ppoi_imt(&LIST_KEY)
            .map_or(0, Imt::leaf_count),
        ROWS as usize,
        "precondition: replay restored every row to the logical store"
    );
    let waited = wait_published(&second).await;
    assert_serves(
        &booted.instance.current_state(),
        secret_key,
        ROWS - 1,
        &format!(
            "recovery replayed it into the store and the restarted block had not published it \
             after {waited:?}"
        ),
    );
    stop_uncleanly(second);
}

/// Once nothing is pending the block commits nothing while no event arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_static_block_takes_no_commit_while_idle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fresh, _secret_key) = fresh_state();
    let handle = boot(dir.path(), short_bound(), Some(fresh));
    let booted = handle.instances.first().expect("one instance");
    let mut upstream = Imt::new().expect("reference tree");
    mirror_rows(&handle, &mut upstream, 0..ROWS).await;
    wait_applied(&handle, ROWS).await;
    let waited = wait_published(&handle).await;
    assert!(
        booted.logical_store.lock().dirty_shards().is_empty(),
        "precondition: the rows were published, still pending after {waited:?}"
    );

    // The publish counts its commit just after draining the dirty set; let it land first.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let commits = booted.metrics.lock().commits_fired;
    tokio::time::sleep(Duration::from_secs(BOUND_SECS * 3)).await;
    assert_eq!(
        booted.metrics.lock().commits_fired,
        commits,
        "a block with nothing pending and no event must take no periodic commit"
    );
    stop_uncleanly(handle);
}
