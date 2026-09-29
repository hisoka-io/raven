//! Every block of a list is served under one CRS, so the single client context a wallet derives
//! for the list decodes each block: across a restart that adds a block, a single block's wipe
//! and rebuild, and a fresh-state factory that sets up a CRS of its own for every block.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::rlwe::RlweSecretKey;
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{
    apply_wal_entry, build_client_session, build_seeded_query, extract_response, re_encode_shard,
    setup_unfilled_state, InspireServerState, LogicalLeafStore, RavenInspireScheme,
};
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine_multi_with_session_limits, DataSourceFilter, InstanceConfig,
    MultiOrchestratorHandle,
};
use raven_railgun_engine::persistence::{ConsumerEvent, InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{empty_store_shard, EncoderKind, PATH10_RECORD_BYTES};
use raven_railgun_engine::session_pool::{BoundedSessionStore, SessionStoreLimits};
use raven_railgun_engine::{InstanceRole, PirScheme};
use raven_railgun_persistence::{PpoiEventType, StoreLayout, WalEntryPayload};

const LIST: [u8; 32] = [0x5a; 32];
const OTHER_LIST: [u8; 32] = [0x6b; 32];
const ROWS: u64 = 65_536;
const ROWS_PER_SHARD: u32 = 2048;
const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-list-crs-test";

fn block(root: &std::path::Path, list_key: [u8; 32], number: u32) -> InstanceConfig {
    InstanceConfig {
        instance_id: InstanceId::new(format!("list-block-{number}")),
        role: InstanceRole::Static,
        data_dir: root.join(format!("block-{number}")),
        encoder: EncoderKind::PerListPath10 { list_key },
        record_size: PATH10_RECORD_BYTES,
        entries_per_shard: ROWS_PER_SHARD,
        data_source: DataSourceFilter::PpoiListBlock {
            list_key,
            block: number,
        },
        use_flock: false,
        snapshot_policy: SnapshotPolicy::static_default(),
        scheme_tag: SCHEME_TAG.to_owned(),
        channel_capacity: 16,
        max_concurrent_queries: None,
        verification_cadence_n: 0,
        chain_source: None,
    }
}

fn empty_rows(list_key: [u8; 32]) -> Vec<u8> {
    let encoder = EncoderKind::PerListPath10 { list_key }
        .build(PATH10_RECORD_BYTES, ROWS_PER_SHARD)
        .expect("encoder");
    empty_store_shard(encoder.as_ref(), 32).expect("uniform empty shard")
}

/// Sets up a CRS of its own for every block, ignoring the one the boot hands it: the property
/// must hold whatever the factory does.
fn own_crs_state(cfg: &InstanceConfig) -> raven_railgun_core::Result<InspireServerState> {
    let EncoderKind::PerListPath10 { list_key } = cfg.encoder else {
        panic!("list blocks only");
    };
    setup_unfilled_state(
        &InspireParams::secure_128_d2048(),
        &empty_rows(list_key),
        ROWS,
        PATH10_RECORD_BYTES,
        InspireVariant::TwoPacking,
        None,
    )
}

fn boot(configs: Vec<InstanceConfig>) -> raven_railgun_core::Result<MultiOrchestratorHandle> {
    bootstrap_railgun_engine_multi_with_session_limits(
        configs,
        InspireParams::secure_128_d2048(),
        SessionStoreLimits::default(),
        |cfg, _served_under| own_crs_state(cfg),
    )
}

async fn stop(handle: MultiOrchestratorHandle) {
    handle.router.abort();
    drop(handle.channels);
    for per in handle.instances {
        let _ = per.sender.send(ConsumerEvent::Shutdown).await;
        let _ = tokio::time::timeout(Duration::from_secs(30), per.consumer).await;
    }
}

fn state_of(handle: &MultiOrchestratorHandle, number: u32) -> Arc<InspireServerState> {
    handle
        .instances
        .iter()
        .find(|per| per.config.instance_id.as_str() == format!("list-block-{number}"))
        .map(|per| per.instance.current_state())
        .expect("block is served")
}

/// Decode `row` of `served` through a context derived from `context_crs` alone, as a wallet
/// derives one context per list.
fn decode_through(
    context_crs: &raven_inspire::ServerCrs,
    served: &InspireServerState,
    row: u64,
) -> Vec<u8> {
    let params = InspireParams::secure_128_d2048();
    let mut sampler = GaussianSampler::new(params.sigma);
    let secret = RlweSecretKey::generate(&params, &mut sampler);
    let session = build_client_session(context_crs.clone(), secret, &params).expect("session");
    let (client_state, query) =
        build_seeded_query(&session, served.shard_config(), row, &params).expect("query");
    let response = RavenInspireScheme::respond(served, &query).expect("respond");
    extract_response(context_crs, &client_state, &response, PATH10_RECORD_BYTES).expect("extract")
}

fn expected_row(row: u64) -> Vec<u8> {
    let rows = empty_rows(LIST);
    let at = usize::try_from(row % u64::from(ROWS_PER_SHARD)).expect("fits") * PATH10_RECORD_BYTES;
    rows.get(at..at + PATH10_RECORD_BYTES)
        .expect("row inside one shard")
        .to_vec()
}

/// `served` with shard `shard` re-encoded to rows no other shard or block holds, as a commit
/// re-encodes it, and the bytes of `row` within that shard.
fn with_distinct_shard(
    served: &InspireServerState,
    shard: u32,
    row: u64,
) -> (InspireServerState, Vec<u8>) {
    let rows: Vec<u8> = (0..ROWS_PER_SHARD as usize * PATH10_RECORD_BYTES)
        .map(|i| u8::try_from((i * 7 + shard as usize * 13 + 3) % 251).expect("below 251"))
        .collect();
    let mut encoded = (*served.encoded_db).clone();
    re_encode_shard(
        &mut encoded,
        &InspireParams::secure_128_d2048(),
        shard,
        &rows,
        PATH10_RECORD_BYTES,
    )
    .expect("re-encode one shard");
    let at = usize::try_from(row % u64::from(ROWS_PER_SHARD)).expect("fits") * PATH10_RECORD_BYTES;
    let expected = rows
        .get(at..at + PATH10_RECORD_BYTES)
        .expect("row inside one shard")
        .to_vec();
    let state = InspireServerState {
        encoded_db: Arc::new(encoded),
        crs: Arc::clone(&served.crs),
        cache: Arc::clone(&served.cache),
        session_store: Arc::clone(&served.session_store),
        variant: served.variant,
        entry_size: served.entry_size,
    };
    (state, expected)
}

/// Whether two blocks' packing-key caches are one file on disk.
#[cfg(unix)]
fn share_one_cache_file(root: &std::path::Path, a: u32, b: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let cache = |n: u32| {
        std::fs::metadata(
            root.join(format!("block-{n}"))
                .join(raven_railgun_engine::offline_packing_keys_cache::CACHE_RELATIVE_PATH),
        )
        .expect("cache file")
    };
    let (a, b) = (cache(a), cache(b));
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_client_context_decodes_a_block_added_by_restart_and_a_rebuilt_block() {
    let root = tempfile::tempdir().expect("tempdir");

    let first = boot(vec![
        block(root.path(), LIST, 0),
        block(root.path(), LIST, 1),
    ])
    .expect("first boot");
    let context_crs = (*state_of(&first, 0).crs).clone();
    stop(first).await;

    let added = boot((0..3).map(|n| block(root.path(), LIST, n)).collect())
        .expect("restart with block 2 added");
    let row = 3 * u64::from(ROWS_PER_SHARD) + 17;
    assert_eq!(
        decode_through(&context_crs, &state_of(&added, 2), row),
        expected_row(row),
        "block 0's client context must decode the block the restart added"
    );
    let (filled, expected) = with_distinct_shard(&state_of(&added, 2), 3, row);
    assert_eq!(
        decode_through(&context_crs, &filled, row),
        expected,
        "block 0's client context must decode rows written to the block the restart added"
    );
    stop(added).await;

    std::fs::remove_dir_all(root.path().join("block-1")).expect("wipe block 1");
    let rebuilt = boot((0..3).map(|n| block(root.path(), LIST, n)).collect())
        .expect("restart with block 1 rebuilt");
    let row = 29 * u64::from(ROWS_PER_SHARD) + 5;
    assert_eq!(
        decode_through(&context_crs, &state_of(&rebuilt, 1), row),
        expected_row(row),
        "block 0's client context must decode a wiped and rebuilt block"
    );
    let (filled, expected) = with_distinct_shard(&state_of(&rebuilt, 1), 29, row);
    assert_eq!(
        decode_through(&context_crs, &filled, row),
        expected,
        "block 0's client context must decode rows written to a wiped and rebuilt block"
    );
    stop(rebuilt).await;
    #[cfg(unix)]
    for number in 1..3 {
        assert!(
            share_one_cache_file(root.path(), 0, number),
            "block {number} holds its own copy of the list's packing keys"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocks_recovered_under_different_seeds_are_refused_by_name() {
    let root = tempfile::tempdir().expect("tempdir");
    stop(boot(vec![block(root.path(), LIST, 0)]).expect("block 0 alone")).await;
    stop(
        boot(vec![
            block(root.path(), LIST, 1),
            block(root.path(), LIST, 2),
        ])
        .expect("blocks 1 and 2 under one seed of their own"),
    )
    .await;
    let error = boot((0..3).map(|n| block(root.path(), LIST, n)).collect())
        .expect_err("blocks of one list under two seeds");
    let message = error.to_string();
    // Block 0 is the one to rebuild, although it comes first in config order.
    assert!(
        message.contains("held by list-block-0;")
            && message.contains("held by list-block-1, list-block-2 (kept)"),
        "{message}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_data_dir_built_under_other_parameters_is_refused() {
    let root = tempfile::tempdir().expect("tempdir");
    stop(boot(vec![block(root.path(), LIST, 0)]).expect("boot")).await;

    let mut other = InspireParams::secure_128_d2048();
    other.sigma += 0.5;
    let error = bootstrap_railgun_engine_multi_with_session_limits(
        vec![block(root.path(), LIST, 0)],
        other,
        SessionStoreLimits::default(),
        |cfg, _| own_crs_state(cfg),
    )
    .expect_err("other parameters");
    assert!(error.to_string().contains("InsPIRe parameters"), "{error}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_data_dir_holding_another_list_is_refused() {
    let root = tempfile::tempdir().expect("tempdir");
    let cfg = block(root.path(), OTHER_LIST, 0);
    let encoder = cfg
        .encoder
        .build(cfg.record_size, cfg.entries_per_shard)
        .expect("encoder");
    let layout = StoreLayout::open(&cfg.data_dir).expect("layout");
    BoundedSessionStore::open_with_limits(layout.root(), SessionStoreLimits::default())
        .expect("session store");
    let opened = InspirePersistence::open(
        layout,
        SCHEME_TAG,
        cfg.instance_id.clone(),
        cfg.snapshot_policy,
        Arc::clone(&encoder),
    )
    .expect("open");
    let mut store = LogicalLeafStore::new();
    let mut commitment = [0u8; 32];
    commitment[31] = 9;
    apply_wal_entry(
        &mut store,
        &WalEntryPayload::PpoiListLeafAdded {
            list_key: OTHER_LIST,
            list_index: 0,
            blinded_commitment: commitment,
            event_type: PpoiEventType::Shield,
            validated_merkleroot: [0; 32],
        },
        0,
        encoder.as_ref(),
    )
    .expect("row");
    let state = own_crs_state(&cfg).expect("state");
    opened
        .persistence
        .commit_v6(&state, &store, 0)
        .expect("commit a row of the other list");
    drop(opened);

    let error = boot(vec![block(root.path(), LIST, 0)]).expect_err("configured for LIST");
    assert!(
        error.to_string().contains("other than the configured list"),
        "{error}"
    );
}
