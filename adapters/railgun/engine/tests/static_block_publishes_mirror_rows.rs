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

#[path = "support/progress.rs"]
mod progress;

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
use raven_railgun_engine::persistence::SnapshotPolicy;
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
/// The steady feed's pace: one row per tick, and a tick never shorter than this.
const TICK_MS: u64 = 500;
const TICK: Duration = Duration::from_millis(TICK_MS);
/// Rows by which the steady feed must see a publish. The timer starts before the second row is
/// sent, and row `k` reads the shortened bound more than `k - 2` ticks after that, so this row
/// publishes at the latest. Counted in rows: a slow box only stretches the ticks.
const MAX_ROWS_BEFORE_PUBLISH: u64 = BOUND_SECS * 1000 / TICK_MS + 2;

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
        scheme_tag: "raven-inspire-twopacking-inspiring-v1-static-block".to_owned(),
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

/// Stops without the Shutdown commit, the way a kill does, and returns once the consumer is gone
/// so a reboot never opens a data dir it is still writing.
async fn stop_uncleanly(handle: MultiOrchestratorHandle) {
    handle.router.abort();
    for mut instance in handle.instances {
        progress::abort_consumer(
            "aborted consumer exiting",
            &mut instance.consumer,
            &instance.metrics,
            &instance.persistence,
        )
        .await;
    }
}

/// Waits for the store's dirty set to drain and for the commit that drained it to land, and
/// returns how long that took. A block that never publishes stops moving and fails here.
async fn wait_published(handle: &MultiOrchestratorHandle) -> Duration {
    let booted = handle.instances.first().expect("one instance");
    let started = tokio::time::Instant::now();
    progress::until_done_or_stalled("the block publishing its applied rows", || {
        (
            progress::consumer_motion(&booted.metrics, &booted.persistence),
            booted
                .logical_store
                .lock()
                .dirty_shards()
                .is_empty()
                .then_some(()),
        )
    })
    .await;
    // The commit clears the dirty set before it counts itself.
    progress::drained(
        "the publish landing",
        &booted.sender,
        &booted.metrics,
        &booted.persistence,
    )
    .await;
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
    progress::until_done_or_stalled(&format!("the block applying {rows} rows"), || {
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
        (
            (
                applied,
                progress::consumer_motion(&booted.metrics, &booted.persistence),
            ),
            (applied == rows as usize).then_some(()),
        )
    })
    .await;
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
/// the production static policy's own bound is pinned in the persistence unit tests. Row 0 is
/// published first, so the later rows arm the timer after a commit rather than at boot. They
/// append under the static policy, which has no trigger, and the bound is shortened only after
/// their append checks ran: the one event after them is a heartbeat, which appends nothing, so
/// what publishes them is the timer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_static_block_serves_mirrored_rows_once_the_feed_goes_quiet() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fresh, secret_key) = fresh_state();
    let handle = boot(dir.path(), short_bound(), Some(fresh));
    let booted = handle.instances.first().expect("one instance");
    let mut upstream = Imt::new().expect("reference tree");

    mirror_rows(&handle, &mut upstream, 0..1).await;
    wait_applied(&handle, 1).await;
    wait_published(&handle).await;

    booted
        .persistence
        .set_snapshot_policy(SnapshotPolicy::static_default());
    mirror_rows(&handle, &mut upstream, 1..ROWS).await;
    wait_applied(&handle, ROWS).await;
    let (sender, metrics, persistence) = (&booted.sender, &booted.metrics, &booted.persistence);
    progress::drained("the rows' append checks", sender, metrics, persistence).await;
    booted.persistence.set_snapshot_policy(short_bound());
    // A policy change wakes nothing: the consumer reads the bound at its next loop top.
    progress::drained("a heartbeat after the bound", sender, metrics, persistence).await;

    let waited = wait_published(&handle).await;
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
    stop_uncleanly(handle).await;
}

/// A feed that never goes quiet must not hold off the publish: a row arrives every half second,
/// well inside the bound, for several bounds, and the first row is served before the feed stops.
///
/// The shortened timer would also fire the append trigger on every row and publish them whatever
/// the consumer does, so each row appends under the static policy, which has no trigger, as in
/// production, and the bound is shortened only after the row's append check ran. Two heartbeats
/// follow: they append nothing, and the second is taken only after the consumer has read the
/// shortened bound, where a due publish runs before the next receive.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_steady_feed_does_not_hold_off_the_publish() {
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
            served.is_some() || u64::from(rows) < MAX_ROWS_BEFORE_PUBLISH,
            "{rows} rows, one per {TICK:?}, and no publish at a {BOUND_SECS} s bound"
        );
        let next_tick = tokio::time::Instant::now() + TICK;
        booted
            .persistence
            .set_snapshot_policy(SnapshotPolicy::static_default());
        mirror_rows(&handle, &mut upstream, rows..rows + 1).await;
        rows += 1;
        wait_applied(&handle, rows).await;
        // The leaf count moves before the append check reads the bound.
        progress::drained(
            "the row's append check",
            &booted.sender,
            &booted.metrics,
            &booted.persistence,
        )
        .await;
        booted.persistence.set_snapshot_policy(short_bound());
        // Straight to the consumer: the router sends heartbeats to chain-tree instances only.
        for what in ["a heartbeat", "a heartbeat after the bound is read"] {
            progress::drained(what, &booted.sender, &booted.metrics, &booted.persistence).await;
        }
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
    stop_uncleanly(handle).await;
}

/// A kill leaves the rows in the WAL and out of the snapshot. Recovery replays them into the
/// logical store only, so the restarted block must still publish them on its own.
///
/// The first life runs the production static policy, whose bound is far past this test, and is
/// killed only once its append checks have run without a publish.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restarted_static_block_serves_the_rows_its_wal_replayed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fresh, secret_key) = fresh_state();
    let first = boot(dir.path(), SnapshotPolicy::static_default(), Some(fresh));
    let life = first.instances.first().expect("one instance");
    let commits = life.metrics.lock().commits_fired;
    let mut upstream = Imt::new().expect("reference tree");
    mirror_rows(&first, &mut upstream, 0..ROWS).await;
    wait_applied(&first, ROWS).await;
    progress::drained(
        "the first life's append checks",
        &life.sender,
        &life.metrics,
        &life.persistence,
    )
    .await;
    assert_eq!(
        life.metrics.lock().commits_fired,
        commits,
        "precondition: the first life published nothing, so the restart has the rows to publish"
    );
    stop_uncleanly(first).await;

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
    stop_uncleanly(second).await;
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

    let commits = booted.metrics.lock().commits_fired;
    tokio::time::sleep(Duration::from_secs(BOUND_SECS * 3)).await;
    assert_eq!(
        booted.metrics.lock().commits_fired,
        commits,
        "a block with nothing pending and no event must take no periodic commit"
    );
    stop_uncleanly(handle).await;
}
