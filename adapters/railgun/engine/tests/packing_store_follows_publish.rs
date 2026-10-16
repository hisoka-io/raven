//! A shard's packing store is folded from its columns, so a publish that changes the columns
//! must change the store with them. A store left over the wrong columns would pack a plaintext
//! that belongs to neither. What is decoded here is the served state, through a real query.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

#[path = "support/progress.rs"]
mod progress;

use std::sync::Arc;

use raven_inspire::inspiring::ShardPackingStore;
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::{ClientSession, ClientState, EncodedDatabase, SeededClientQuery};
use raven_railgun_core::{AdapterError, InstanceId, POIStatus};
use raven_railgun_engine::imt::Imt;
use raven_railgun_engine::inspire::{
    build_client_session, build_seeded_query, extract_response, re_encode_shard,
    register_client_session, setup_state, setup_unfilled_state, InspireServerState,
    RavenInspireScheme,
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

fn bc_for(list_index: u32) -> [u8; 32] {
    let mut bc = [0u8; 32];
    bc[0] = 0x0b;
    bc[1..5].copy_from_slice(&list_index.to_be_bytes());
    bc[31] = 0x01;
    bc
}

fn fresh_state() -> InspireServerState {
    let seed = vec![0u8; SHARDS * EPS as usize * PATH10_RECORD_BYTES];
    setup_state(
        &InspireParams::secure_128_d2048(),
        &seed,
        PATH10_RECORD_BYTES,
        InspireVariant::TwoPacking,
    )
    .expect("setup")
    .0
}

/// Boots the block over `dir`; `fresh` is `None` when the boot must recover what is there.
fn boot(dir: &std::path::Path, fresh: Option<InspireServerState>) -> MultiOrchestratorHandle {
    let mut fresh = fresh;
    let config = InstanceConfig {
        instance_id: InstanceId::new("packing-store-block-0"),
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
        // A timer short enough to observe: it is what publishes rows on a static block.
        snapshot_policy: SnapshotPolicy {
            max_seconds_between_snapshots: 2,
            ..SnapshotPolicy::static_default()
        },
        scheme_tag: "raven-inspire-twopacking-inspiring-v1-packing-store".to_owned(),
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

/// The boot builds stores beside serving, not before it, and these tests read them.
async fn stores_built(handle: &MultiOrchestratorHandle) {
    let mut built = handle.packing_stores_built.clone();
    tokio::time::timeout(
        std::time::Duration::from_secs(120),
        built.wait_for(|done| *done),
    )
    .await
    .expect("the boot store build finished")
    .expect("the boot store build reported");
}

/// Returns once `rows` rows are applied, nothing is dirty and their snapshot has landed.
async fn wait_published(handle: &MultiOrchestratorHandle, rows: u32) {
    let booted = handle.instances.first().expect("one instance");
    progress::until_done_or_stalled("the block publishing its applied rows", || {
        assert_eq!(
            booted.metrics.lock().consumer_errors,
            0,
            "a row was refused"
        );
        let (applied, drained) = {
            let store = booted.logical_store.lock();
            (
                store.ppoi_imt(&LIST_KEY).map_or(0, Imt::leaf_count),
                store.dirty_shards().is_empty(),
            )
        };
        let done = applied == rows as usize && drained && !booted.persistence.snapshot_pending();
        (
            (
                applied,
                progress::consumer_motion(&booted.metrics, &booted.persistence),
            ),
            done.then_some(()),
        )
    })
    .await;
    progress::drained(
        "the publish landing",
        &booted.sender,
        &booted.metrics,
        &booted.persistence,
    )
    .await;
}

fn session_for(state: &InspireServerState) -> ClientSession {
    let mut session = build_client_session((*state.crs).clone()).expect("client session");
    register_client_session(&mut session, state).expect("register session");
    session
}

fn query_for(
    state: &InspireServerState,
    session: &ClientSession,
    row: u64,
) -> (ClientState, SeededClientQuery) {
    let params = InspireParams::secure_128_d2048();
    build_seeded_query(session, state.shard_config(), row, &params).expect("query")
}

fn served_row(
    state: &InspireServerState,
    client_state: &ClientState,
    query: &SeededClientQuery,
) -> Vec<u8> {
    let response = <RavenInspireScheme as PirScheme>::respond(state, query).expect("respond");
    extract_response(&state.crs, client_state, &response, state.entry_size).expect("extract")
}

fn store_of(state: &InspireServerState, shard: usize) -> &ShardPackingStore {
    state.encoded_db.shards[shard]
        .packing_store()
        .unwrap_or_else(|| panic!("shard {shard} is served without a packing store"))
}

/// `state` with every packing store dropped: the same rows, packed per query.
fn without_stores(state: &InspireServerState) -> InspireServerState {
    let mut encoded_db = EncodedDatabase::clone(&state.encoded_db);
    for shard in &mut encoded_db.shards {
        shard.drop_packing_store();
    }
    InspireServerState {
        crs: Arc::clone(&state.crs),
        encoded_db: Arc::new(encoded_db),
        cache: Arc::clone(&state.cache),
        session_store: Arc::clone(&state.session_store),
        variant: state.variant,
        entry_size: state.entry_size,
    }
}

/// Rows land in shard 0 only. After the publish the row is decoded through shard 0's store,
/// which must be a new one; shard 1 was not touched and keeps the store it booted with; the
/// state a query already holds still answers from its own columns; and a restart rebuilds
/// every store.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_published_row_is_served_through_the_store_of_its_new_columns() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fresh = fresh_state();
    let handle = boot(dir.path(), Some(fresh));
    let booted = handle.instances.first().expect("one instance");
    let last = u64::from(ROWS - 1);

    let before = booted.instance.current_state();
    assert_eq!(before.encoded_db.shards.len(), SHARDS);
    let (before_store_0, before_store_1) = (store_of(&before, 0), store_of(&before, 1));
    let before_session = session_for(&before);
    let (before_client, before_query) = query_for(&before, &before_session, last);
    assert_eq!(
        served_row(&before, &before_client, &before_query),
        vec![0u8; PATH10_RECORD_BYTES],
        "precondition: the row is empty before the publish"
    );

    let mut upstream = Imt::new().expect("reference tree");
    mirror_rows(&handle, &mut upstream, 0..ROWS).await;
    wait_published(&handle, ROWS).await;

    let after = booted.instance.current_state();
    assert!(
        !Arc::ptr_eq(&after.encoded_db, &before.encoded_db),
        "precondition: the publish swapped the served database"
    );

    // The decode comes first: it is the property, whatever the store bookkeeping below says.
    // Sessions carry across a publish, so the session registered before it still answers.
    let (client, query) = query_for(&after, &before_session, last);
    let row = served_row(&after, &client, &query);
    assert_eq!(&row[..32], &bc_for(ROWS - 1), "the served leaf");
    assert_eq!(&row[PATH10_MARKER], PATH10_MAGIC.as_slice());
    assert_eq!(row[PATH10_STATUS], POIStatus::Valid.wire_byte());

    let with_store =
        <RavenInspireScheme as PirScheme>::respond(&after, &query).expect("respond with a store");
    let per_query = <RavenInspireScheme as PirScheme>::respond(&without_stores(&after), &query)
        .expect("respond without a store");
    assert_eq!(
        bincode::serialize(&with_store).expect("response bytes"),
        bincode::serialize(&per_query).expect("response bytes"),
        "a store changes how a response is computed, never its bytes"
    );

    assert!(
        !std::ptr::eq(store_of(&after, 0), before_store_0),
        "shard 0 was re-encoded and still holds the store of its old columns"
    );
    assert!(
        std::ptr::eq(store_of(&after, 1), before_store_1),
        "shard 1 was not re-encoded, so its store is not rebuilt"
    );

    assert_eq!(
        served_row(&before, &before_client, &before_query),
        vec![0u8; PATH10_RECORD_BYTES],
        "the superseded state answers from its own columns and store"
    );

    stop_uncleanly(handle).await;
    let restarted = boot(dir.path(), None);
    let booted = restarted
        .instances
        .first()
        .expect("one instance")
        .instance
        .current_state();
    stores_built(&restarted).await;
    let recovered = restarted
        .instances
        .first()
        .expect("one instance")
        .instance
        .current_state();
    assert!(
        Arc::ptr_eq(&booted.encoded_db, &recovered.encoded_db),
        "the boot store build filled the served database, it did not publish a copy"
    );
    for shard in 0..SHARDS {
        assert!(std::ptr::eq(
            store_of(&booted, shard),
            store_of(&recovered, shard)
        ));
    }
    let session = session_for(&recovered);
    let (client, query) = query_for(&recovered, &session, last);
    assert_eq!(
        &served_row(&recovered, &client, &query)[..32],
        &bc_for(ROWS - 1),
        "the recovered block serves the row through its rebuilt store"
    );
    stop_uncleanly(restarted).await;
}

fn planted_rows(marker: u8) -> Vec<u8> {
    let mut rows = vec![0u8; SHARDS * EPS as usize * PATH10_RECORD_BYTES];
    for (index, row) in rows.chunks_mut(PATH10_RECORD_BYTES).enumerate() {
        row[0] = marker;
        row[1..5].copy_from_slice(&u32::try_from(index).expect("row index").to_be_bytes());
    }
    rows
}

/// The defect itself, built by hand: columns replaced under a store that is kept. The scheme
/// must refuse the shard, and the engine's own re-encode must serve the new rows.
#[test]
fn a_store_kept_over_replaced_columns_is_refused_and_a_re_encode_serves_them() {
    let params = InspireParams::secure_128_d2048();
    let shard_bytes = EPS as usize * PATH10_RECORD_BYTES;
    let (state, _) = setup_state(
        &params,
        &planted_rows(0xa1),
        PATH10_RECORD_BYTES,
        InspireVariant::TwoPacking,
    )
    .expect("setup");
    let (replacement, _) = setup_state(
        &params,
        &planted_rows(0xb2),
        PATH10_RECORD_BYTES,
        InspireVariant::TwoPacking,
    )
    .expect("replacement rows");
    let session = session_for(&state);
    let (client, query) = query_for(&state, &session, 5);
    assert_eq!(served_row(&state, &client, &query)[0], 0xa1);

    let serving = |encoded_db: EncodedDatabase| InspireServerState {
        crs: Arc::clone(&state.crs),
        encoded_db: Arc::new(encoded_db),
        cache: Arc::clone(&state.cache),
        session_store: Arc::clone(&state.session_store),
        variant: state.variant,
        entry_size: state.entry_size,
    };

    let mut stale = EncodedDatabase::clone(&state.encoded_db);
    stale.shards[0].polynomials = replacement.encoded_db.shards[0].polynomials.clone();
    assert!(
        stale.shards[0].packing_store().is_some(),
        "precondition: the store of the old columns is still attached"
    );
    let refusal = <RavenInspireScheme as PirScheme>::respond(&serving(stale), &query)
        .expect_err("a store over other columns must not answer");
    assert!(
        refusal.to_string().contains("packing store refused"),
        "the refusal must come from the store's own check: {refusal}"
    );

    let mut re_encoded = EncodedDatabase::clone(&state.encoded_db);
    re_encode_shard(
        &mut re_encoded,
        &params,
        0,
        &planted_rows(0xb2)[..shard_bytes],
        PATH10_RECORD_BYTES,
    )
    .expect("re-encode");
    assert!(
        re_encoded.shards[0].packing_store().is_none(),
        "a re-encode keeps no store over the columns it replaced"
    );
    assert!(
        re_encoded.shards[1].packing_store().is_some(),
        "the shard that was not re-encoded keeps its store"
    );
    let row = served_row(&serving(re_encoded), &client, &query);
    assert_eq!(row[0], 0xb2, "the re-encoded rows are served");
    assert_eq!(&row[1..5], &5u32.to_be_bytes());
}

/// A re-encode from the bytes a shard already serves replaces nothing, so the shard keeps its
/// columns and the store folded from them; one changed row still costs the store.
#[test]
fn a_re_encode_to_the_columns_already_held_keeps_the_store() {
    let params = InspireParams::secure_128_d2048();
    let shard_bytes = EPS as usize * PATH10_RECORD_BYTES;
    let rows = planted_rows(0xa1);
    let (state, _) = setup_state(
        &params,
        &rows,
        PATH10_RECORD_BYTES,
        InspireVariant::TwoPacking,
    )
    .expect("setup");
    let held = store_of(&state, 0);

    let mut same = EncodedDatabase::clone(&state.encoded_db);
    re_encode_shard(
        &mut same,
        &params,
        0,
        &rows[..shard_bytes],
        PATH10_RECORD_BYTES,
    )
    .expect("re-encode to the same rows");
    assert!(
        same.shards[0]
            .packing_store()
            .is_some_and(|store| std::ptr::eq(store, held)),
        "the same rows must keep the store they had"
    );
    assert_eq!(
        same.shards[0].polynomials,
        state.encoded_db.shards[0].polynomials
    );

    let mut one_row = rows[..shard_bytes].to_vec();
    one_row[7 * PATH10_RECORD_BYTES] ^= 1;
    let mut changed = EncodedDatabase::clone(&state.encoded_db);
    re_encode_shard(&mut changed, &params, 0, &one_row, PATH10_RECORD_BYTES)
        .expect("re-encode one changed row");
    assert!(
        changed.shards[0].packing_store().is_none(),
        "one changed row must drop the store of the old columns"
    );

    let kept = InspireServerState {
        crs: Arc::clone(&state.crs),
        encoded_db: Arc::new(same),
        cache: Arc::clone(&state.cache),
        session_store: Arc::clone(&state.session_store),
        variant: state.variant,
        entry_size: state.entry_size,
    };
    let session = session_for(&state);
    let (client, query) = query_for(&state, &session, 5);
    let row = served_row(&kept, &client, &query);
    assert_eq!(row[0], 0xa1);
    assert_eq!(&row[1..5], &5u32.to_be_bytes());
}

/// An unfilled cell holds one shard for all of them. Giving each its own copy must not give
/// each its own store: the copies are equal until one is re-encoded.
#[test]
fn the_shards_of_an_unfilled_cell_share_one_store_until_re_encoded() {
    let params = InspireParams::secure_128_d2048();
    let shard_bytes = EPS as usize * PATH10_RECORD_BYTES;
    let total = u64::from(EPS) * 4;
    let state = setup_unfilled_state(
        &params,
        &vec![0u8; shard_bytes],
        total,
        PATH10_RECORD_BYTES,
        InspireVariant::TwoPacking,
        None,
    )
    .expect("unfilled state");
    assert_eq!(state.encoded_db.shards.len(), 1);
    let template_store = store_of(&state, 0);

    let mut encoded_db = EncodedDatabase::clone(&state.encoded_db);
    re_encode_shard(
        &mut encoded_db,
        &params,
        2,
        &planted_rows(0xc3)[..shard_bytes],
        PATH10_RECORD_BYTES,
    )
    .expect("re-encode");
    assert_eq!(encoded_db.shards.len(), 4);
    for shard in [0, 1, 3] {
        let store = encoded_db.shards[shard]
            .packing_store()
            .unwrap_or_else(|| panic!("shard {shard} lost the template's store"));
        assert!(
            std::ptr::eq(store, template_store),
            "shard {shard} holds its own copy of the template's store"
        );
    }
    assert!(encoded_db.shards[2].packing_store().is_none());
}
