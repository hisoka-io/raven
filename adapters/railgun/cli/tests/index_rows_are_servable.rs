//! Every row the list index advertises is served by the published PIR table.
//!
//! A wallet reads a note's row off the index and at once asks `/batch` for its path. The index is
//! read here through the shim registry the route answers from, and the row through a real query
//! against the served state, never the store.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

#[path = "support/progress.rs"]
mod progress;

use std::sync::Arc;
use std::time::Instant;

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
    PerInstanceHandles,
};
use raven_railgun_engine::persistence::SnapshotPolicy;
use raven_railgun_engine::pir_table::list::PATH10_MAGIC;
use raven_railgun_engine::pir_table::{EncoderKind, PATH10_RECORD_BYTES};
use raven_railgun_engine::{InstanceRole, PirScheme};
use raven_railgun_http::shim_store::{ShimStoreRegistry, UpstreamTip};
use raven_railgun_persistence::{PpoiEventType, WalEntryPayload};

const LIST_KEY: [u8; 32] = [0x3d; 32];
const EPS: u32 = 2048;
const SHARDS: usize = 2;
const CAUGHT_UP_ROWS: u32 = 3;
const PATH10_STATUS: usize = 32;
const PATH10_MARKER: std::ops::Range<usize> = 34..38;

fn bc_for(list_index: u32) -> [u8; 32] {
    let mut bc = [0u8; 32];
    bc[0] = 0x0c;
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

/// A live block under the shipped live policy, whose snapshot triggers are far past this test.
fn boot(dir: &std::path::Path, fresh: Option<InspireServerState>) -> MultiOrchestratorHandle {
    let mut fresh = fresh;
    let config = InstanceConfig {
        instance_id: InstanceId::new("live-path10-block-0"),
        role: InstanceRole::Live,
        data_dir: dir.join("instance"),
        encoder: EncoderKind::PerListPath10 { list_key: LIST_KEY },
        record_size: PATH10_RECORD_BYTES,
        entries_per_shard: EPS,
        data_source: DataSourceFilter::PpoiListBlock {
            list_key: LIST_KEY,
            block: 0,
        },
        use_flock: false,
        snapshot_policy: SnapshotPolicy::default(),
        scheme_tag: "raven-inspire-twopacking-inspiring-v1-live-block".to_owned(),
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

fn block(handle: &MultiOrchestratorHandle) -> &PerInstanceHandles {
    handle.instances.first().expect("one instance")
}

/// Rows the wallet-facing index advertises for the list, as the bc-prefixes route reads them.
fn advertised(handle: &MultiOrchestratorHandle) -> u32 {
    let store = Arc::clone(&block(handle).logical_store);
    let registry = ShimStoreRegistry::from_declarations([(
        DataSourceFilter::PpoiListBlock {
            list_key: LIST_KEY,
            block: 0,
        },
        store,
    )]);
    let upstream = UpstreamTip {
        rows: u64::try_from(held(handle)).expect("u64"),
        age_secs: 0,
    };
    registry
        .prove_list_coverage(&LIST_KEY, Some(upstream))
        .expect("the block covers upstream's count")
        .segment(0)
        .expect("the index answers")
        .next
}

fn held(handle: &MultiOrchestratorHandle) -> usize {
    block(handle)
        .logical_store
        .lock()
        .ppoi_imt(&LIST_KEY)
        .map_or(0, Imt::leaf_count)
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

/// What moves while the consumer works: its counters, the rows it holds and the table it serves.
fn motion(handle: &MultiOrchestratorHandle) -> (String, usize, u64) {
    let booted = block(handle);
    (
        format!("{:?}", *booted.metrics.lock()),
        held(handle),
        booted.instance.current_snapshot().epoch.0,
    )
}

/// Boots a block that has caught up with upstream: its backfill applied [`CAUGHT_UP_ROWS`] rows
/// and the publish that ends a backfill served them.
async fn caught_up(dir: &std::path::Path) -> (MultiOrchestratorHandle, RlweSecretKey, Imt) {
    let (fresh, secret_key) = fresh_state();
    let handle = boot(dir, Some(fresh));
    let booted = block(&handle);
    let mut upstream = Imt::new().expect("reference tree");
    booted.persistence.set_backfilling(true);
    let commits = booted.metrics.lock().commits_fired;
    mirror_rows(&handle, &mut upstream, 0..CAUGHT_UP_ROWS).await;
    progress::until_done_or_stalled("the backfill applied", async || {
        (
            motion(&handle),
            (held(&handle) == CAUGHT_UP_ROWS as usize).then_some(()),
        )
    })
    .await;
    booted.persistence.set_backfilling(false);
    progress::until_done_or_stalled("the catch-up publish", async || {
        (
            motion(&handle),
            (booted.metrics.lock().commits_fired > commits).then_some(()),
        )
    })
    .await;
    assert_eq!(advertised(&handle), CAUGHT_UP_ROWS, "fixture: caught up");
    (handle, secret_key, upstream)
}

async fn stop_uncleanly(handle: MultiOrchestratorHandle) {
    handle.router.abort();
    for instance in handle.instances {
        instance.consumer.abort();
        let _cancelled = instance.consumer.await;
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
        "served row {list_index} is unpopulated: {why}"
    );
    assert_eq!(&row[..32], &bc_for(list_index), "the served leaf");
    assert_eq!(row[PATH10_STATUS], POIStatus::Valid.wire_byte());
}

/// A caught-up block takes a new row. The moment the index advertises it, the table `/batch`
/// answers from must hold it: a wallet spending the note it just saw Valid asks for its path
/// right away.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_row_the_index_advertises_is_served_by_the_published_table() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (handle, secret_key, mut upstream) = caught_up(dir.path()).await;
    let booted = block(&handle);

    let new_row = CAUGHT_UP_ROWS;
    mirror_rows(&handle, &mut upstream, new_row..new_row + 1).await;
    // The served state is read in the same poll that first sees the row advertised, so a publish
    // landing after that cannot hide an index that ran ahead of it.
    let served = progress::until_done_or_stalled("the index advertising the new row", async || {
        let state = booted.instance.current_state();
        (
            motion(&handle),
            (advertised(&handle) > new_row).then_some(state),
        )
    })
    .await;
    assert_serves(
        &served,
        secret_key,
        new_row,
        "the index advertised it before the table held it",
    );
    stop_uncleanly(handle).await;
}

/// On a caught-up block a new row is advertised and served without waiting for a snapshot: the
/// shipped policy's snapshot triggers (1,000 appends, 300 s) are far past this test, and no
/// snapshot is taken on the way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::print_stderr)]
async fn a_caught_up_block_serves_a_new_row_ahead_of_its_snapshot() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (handle, secret_key, mut upstream) = caught_up(dir.path()).await;
    let booted = block(&handle);
    let commits = booted.metrics.lock().commits_fired;
    let snapshot = booted.persistence.current_snapshot_id();

    let new_row = CAUGHT_UP_ROWS;
    let sent = Instant::now();
    mirror_rows(&handle, &mut upstream, new_row..new_row + 1).await;
    let mut applied = None;
    progress::until_done_or_stalled("the new row advertised", async || {
        if applied.is_none() && held(&handle) > new_row as usize {
            applied = Some(sent.elapsed());
        }
        (
            motion(&handle),
            (advertised(&handle) > new_row).then_some(()),
        )
    })
    .await;
    let advertised_after = sent.elapsed();
    eprintln!(
        "index_rows_are_servable: applied after {applied:?}, advertised and served after \
         {advertised_after:?}"
    );
    assert_eq!(
        (
            booted.metrics.lock().commits_fired,
            booted.persistence.current_snapshot_id()
        ),
        (commits, snapshot),
        "the row waited for a snapshot"
    );
    assert!(
        booted.persistence.snapshot_pending(),
        "a row served ahead of its snapshot is left for the publish bound to snapshot"
    );
    assert_serves(
        &booted.instance.current_state(),
        secret_key,
        new_row,
        "advertised without being served",
    );
    stop_uncleanly(handle).await;
}

/// A kill after a row was served ahead of its snapshot. The restart replays it from the WAL into
/// the store while its recovered table lacks it, so the index must not advertise it until the
/// publish that ends the restart's backfill serves it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restart_advertises_only_the_rows_its_recovered_table_serves() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (first, secret_key, mut upstream) = caught_up(dir.path()).await;
    let new_row = CAUGHT_UP_ROWS;
    mirror_rows(&first, &mut upstream, new_row..new_row + 1).await;
    progress::until_done_or_stalled("the new row advertised", async || {
        (motion(&first), (advertised(&first) > new_row).then_some(()))
    })
    .await;
    assert!(
        block(&first).persistence.snapshot_pending(),
        "precondition: the row is in the WAL and not in a snapshot"
    );
    stop_uncleanly(first).await;

    let second = boot(dir.path(), None);
    let booted = block(&second);
    booted.persistence.set_backfilling(true);
    assert_eq!(
        held(&second),
        new_row as usize + 1,
        "precondition: recovery replayed the row into the store"
    );
    assert_eq!(
        advertised(&second),
        new_row,
        "the restart advertised a replayed row its recovered table lacks"
    );
    let recovered = booted.instance.current_state();
    for row in 0..new_row {
        assert_serves(
            &recovered,
            secret_key.clone(),
            row,
            "recovered and advertised",
        );
    }

    let commits = booted.metrics.lock().commits_fired;
    booted.persistence.set_backfilling(false);
    progress::until_done_or_stalled("the publish that ends the backfill", async || {
        (
            motion(&second),
            (booted.metrics.lock().commits_fired > commits).then_some(()),
        )
    })
    .await;
    assert_eq!(advertised(&second), new_row + 1);
    assert_serves(
        &booted.instance.current_state(),
        secret_key,
        new_row,
        "advertised after the backfill without being served",
    );
    stop_uncleanly(second).await;
}
