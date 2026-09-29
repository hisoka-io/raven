#![allow(clippy::expect_used)]

#[path = "support/progress.rs"]
mod progress;

use std::sync::Arc;
use std::time::Duration;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_engine::inspire::{
    build_client_session, build_seeded_query, extract_response, setup_state, InspireServerState,
    RavenInspireScheme,
};
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine, bootstrap_railgun_engine_multi, InstanceConfig, OrchestratorConfig,
};
use raven_railgun_engine::session_pool::{BoundedSessionStore, SessionStoreLimits};
use raven_railgun_engine::{InstanceRole, PirScheme};
use sha2::{Digest, Sha256};

const ENTRY_SIZE: usize = 32;
const FLOOR_FILE: &str = "session-handle-floor-v1.bin";
const CHILD_DATA_DIR: &str = "RAVEN_RESTART_HANDLE_CHILD_DATA_DIR";
const CHILD_OUTPUT: &str = "RAVEN_RESTART_HANDLE_CHILD_OUTPUT";

fn limits() -> SessionStoreLimits {
    SessionStoreLimits {
        max_sessions: 4,
        ttl: Duration::from_secs(3600),
    }
}

#[test]
fn reopening_one_data_dir_never_reissues_a_stale_handle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let params = InspireParams::secure_128_d2048();
    let database: Vec<u8> = (0..params.ring_dim * ENTRY_SIZE)
        .map(|offset| u8::try_from(offset % 251).expect("mod 251"))
        .collect();
    let (state, secret_key) =
        setup_state(&params, &database, ENTRY_SIZE, InspireVariant::TwoPacking).expect("setup");
    // The store issues the handle, so one client registered on both sides of the restart is
    // enough to show the restart never reissues.
    let mut client =
        build_client_session((*state.crs).clone(), secret_key, &params).expect("client");

    let first = BoundedSessionStore::open_with_limits(dir.path(), limits()).expect("first open");
    let stale = first
        .register_client_session_at(&mut client, std::time::Instant::now())
        .expect("first register")
        .expect("packing handle");
    drop(first);

    let second = Arc::new(
        BoundedSessionStore::open_with_limits(dir.path(), limits()).expect("restart open"),
    );
    let live = second
        .register_client_session_at(&mut client, std::time::Instant::now())
        .expect("second register")
        .expect("packing handle");

    assert_ne!(stale, live, "restart must not reissue the stale handle");
    let (inner_store, inner) = second
        .resolve(Some(live), std::time::Instant::now())
        .expect("live resolve");
    let inner = inner.expect("translated inner handle");
    assert_ne!(
        live, inner,
        "durable external handle must translate to the core handle"
    );
    assert!(
        second
            .resolve(Some(stale), std::time::Instant::now())
            .is_err(),
        "the stale handle must not resolve to the replacement client's keys"
    );

    let durable_state = InspireServerState {
        crs: Arc::clone(&state.crs),
        encoded_db: Arc::clone(&state.encoded_db),
        cache: Arc::clone(&state.cache),
        session_store: Arc::clone(&second),
        variant: state.variant,
        entry_size: state.entry_size,
    };
    let (client_state, query) =
        build_seeded_query(&client, durable_state.shard_config(), 3, &params)
            .expect("translated query");
    let response = <RavenInspireScheme as PirScheme>::respond(&durable_state, &query)
        .expect("translated response");
    let plaintext = extract_response(
        durable_state.crs.as_ref(),
        &client_state,
        &response,
        ENTRY_SIZE,
    )
    .expect("translated extraction");
    assert_eq!(
        plaintext,
        database
            .get(3 * ENTRY_SIZE..4 * ENTRY_SIZE)
            .expect("expected record"),
        "external-to-inner translation must preserve response bytes"
    );

    assert_durable_lifecycle(&second, &mut client, live, &inner_store, inner);
}

fn assert_durable_lifecycle(
    store: &BoundedSessionStore,
    client: &mut raven_inspire::ClientSession,
    live: raven_inspire::ServerSessionHandle,
    inner_store: &raven_inspire::ServerSessionStore,
    inner: raven_inspire::ServerSessionHandle,
) {
    assert!(
        store.remove(live),
        "external removal must find the translated entry"
    );
    assert!(inner_store
        .get(inner)
        .expect("removed inner lookup")
        .is_none());
    let registered_at = std::time::Instant::now();
    let expiring = store
        .register_client_session_at(client, registered_at)
        .expect("expiring register")
        .expect("expiring handle");
    let (expiring_store, expiring_inner) = store
        .resolve(Some(expiring), registered_at)
        .expect("expiring resolve");
    let expiring_inner = expiring_inner.expect("expiring inner");
    assert_eq!(store.sweep_expired(registered_at + limits().ttl), 1);
    assert!(expiring_store
        .get(expiring_inner)
        .expect("expired inner lookup")
        .is_none());
    let flush_time = registered_at + limits().ttl + Duration::from_secs(1);
    let flushed = store
        .register_client_session_at(client, flush_time)
        .expect("pre-flush register")
        .expect("pre-flush handle");
    let (flushed_store, flushed_inner) = store
        .resolve(Some(flushed), flush_time)
        .expect("pre-flush resolve");
    let flushed_inner = flushed_inner.expect("pre-flush inner");
    for _ in 0..limits().max_sessions {
        store
            .register_client_session_at(client, flush_time)
            .expect("fill registration")
            .expect("fill handle");
    }
    assert!(store.flushes_total() >= 1);
    assert!(store.resolve(Some(flushed), flush_time).is_err());
    assert!(flushed_store
        .get(flushed_inner)
        .expect("in-flight inner lookup")
        .is_some());
}

#[test]
fn a_present_truncated_floor_refuses_startup() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("session-handle-floor-v1.bin"), b"short")
        .expect("write truncated floor");

    let error = BoundedSessionStore::open_with_limits(dir.path(), limits())
        .expect_err("present corruption must fail closed");
    assert!(
        error.to_string().contains("session handle floor"),
        "{error}"
    );
}

#[test]
fn a_present_checksum_mismatch_refuses_startup() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = BoundedSessionStore::open_with_limits(dir.path(), limits()).expect("first open");
    drop(store);
    let floor_path = dir.path().join(FLOOR_FILE);
    let mut bytes = std::fs::read(&floor_path).expect("read floor");
    *bytes.get_mut(10).expect("floor byte") ^= 1;
    std::fs::write(&floor_path, bytes).expect("corrupt floor");

    let error = BoundedSessionStore::open_with_limits(dir.path(), limits())
        .expect_err("checksum corruption must fail closed");
    assert!(error.to_string().contains("checksum mismatch"), "{error}");
}

#[test]
fn a_published_but_unused_range_is_burned_after_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = BoundedSessionStore::open_with_limits(dir.path(), limits()).expect("first open");
    drop(first);
    let after_first = read_floor(&dir.path().join(FLOOR_FILE));
    let second = BoundedSessionStore::open_with_limits(dir.path(), limits()).expect("second open");
    drop(second);
    let after_second = read_floor(&dir.path().join(FLOOR_FILE));

    assert_eq!(after_first, 1024);
    assert_eq!(
        after_second, 2048,
        "restart must burn the unissued first range"
    );
}

#[test]
fn same_data_dir_stores_reserve_disjoint_ranges() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = BoundedSessionStore::open_with_limits(dir.path(), limits()).expect("first open");
    let second = BoundedSessionStore::open_with_limits(dir.path(), limits()).expect("second open");
    assert_eq!(read_floor(&dir.path().join(FLOOR_FILE)), 2048);
    drop((first, second));
}

#[test]
fn distinct_data_dirs_have_independent_handle_floors() {
    let first_dir = tempfile::tempdir().expect("first tempdir");
    let second_dir = tempfile::tempdir().expect("second tempdir");
    let first =
        BoundedSessionStore::open_with_limits(first_dir.path(), limits()).expect("first open");
    let second =
        BoundedSessionStore::open_with_limits(second_dir.path(), limits()).expect("second open");
    assert_eq!(read_floor(&first_dir.path().join(FLOOR_FILE)), 1024);
    assert_eq!(read_floor(&second_dir.path().join(FLOOR_FILE)), 1024);
    drop((first, second));
}

#[tokio::test]
async fn production_single_boot_opens_the_durable_allocator_and_refuses_corruption() {
    let dir = tempfile::tempdir().expect("tempdir");
    drop(BoundedSessionStore::open(dir.path()).expect("prime durable floor"));
    let mut config = OrchestratorConfig::demo(dir.path().to_path_buf(), "durable-single");
    config.record_size = 256;
    config.use_flock = false;
    config.role = InstanceRole::Live;
    let params = InspireParams::secure_128_d2048();
    // Non-constant rows, so the control below proves the client decoded its own record.
    let database: Vec<u8> = (0..params.ring_dim * 256)
        .map(|offset| u8::try_from(offset % 251).expect("mod 251"))
        .collect();
    let (fresh_state, secret_key) =
        setup_state(&params, &database, 256, InspireVariant::TwoPacking).expect("single setup");
    let mut handle = bootstrap_railgun_engine(config, params.clone(), || Ok(fresh_state))
        .expect("single production bootstrap");
    assert_eq!(read_floor(&dir.path().join(FLOOR_FILE)), 2048);
    let state = handle.instance.current_state();
    let mut client =
        build_client_session((*state.crs).clone(), secret_key, &params).expect("single client");
    let external = state
        .session_store
        .register_client_session_at(&mut client, std::time::Instant::now())
        .expect("single register")
        .expect("single handle");
    let (_, inner) = state
        .session_store
        .resolve(Some(external), std::time::Instant::now())
        .expect("single resolve");
    assert_ne!(external, inner.expect("single inner"));

    // NEGATIVE CONTROL: before the floor goes, this client's query is served. Without it the
    // refusals below could be a client that never worked.
    let (client_state, query) =
        build_seeded_query(&client, state.shard_config(), 3, &params).expect("single query");
    assert_eq!(query.session_handle, Some(external));
    let response =
        <RavenInspireScheme as PirScheme>::respond(&state, &query).expect("single response");
    let plaintext = extract_response(state.crs.as_ref(), &client_state, &response, 256)
        .expect("the registered client's query must serve before the floor is deleted");
    assert_eq!(
        plaintext,
        database.get(3 * 256..4 * 256).expect("expected record"),
        "the registered client's query must serve its own record before the floor is deleted"
    );
    handle.indexer_bridge.abort();
    handle.mirror_bridge.abort();
    // The restart below reopens this data dir, so the old consumer must be gone first.
    progress::abort_consumer(
        "aborted consumer exiting",
        &mut handle.consumer,
        &handle.metrics,
        &handle.persistence,
    )
    .await;
    drop(handle);

    assert!(dir.path().join("manifest.json").exists());
    std::fs::remove_file(dir.path().join(FLOOR_FILE)).expect("remove production floor");
    // The allocator decides before any responder runs, so a stale client's handle can never be
    // rebound to a replacement client's keys.
    let error = BoundedSessionStore::open_with_limits(dir.path(), limits())
        .expect_err("a deleted floor must refuse the allocator itself");
    assert!(
        matches!(error, raven_railgun_core::AdapterError::Internal(_)),
        "{error}"
    );
    assert!(error.to_string().contains("floor missing"), "{error}");
    let mut restart_config = OrchestratorConfig::demo(dir.path().to_path_buf(), "durable-single");
    restart_config.record_size = 256;
    restart_config.use_flock = false;
    restart_config.role = InstanceRole::Live;
    let error = bootstrap_railgun_engine(restart_config, params.clone(), || {
        raven_railgun_testkit::try_toy_state(256)
    })
    .expect_err("production restart must refuse a missing floor");
    assert!(error.to_string().contains("floor missing"), "{error}");

    let corrupt = tempfile::tempdir().expect("corrupt tempdir");
    std::fs::write(corrupt.path().join(FLOOR_FILE), b"short").expect("write corrupt floor");
    let mut config = OrchestratorConfig::demo(corrupt.path().to_path_buf(), "durable-corrupt");
    config.record_size = 256;
    config.use_flock = false;
    let error = bootstrap_railgun_engine(config, InspireParams::secure_128_d2048(), || {
        raven_railgun_testkit::try_toy_state(256)
    })
    .expect_err("production bootstrap must refuse a corrupt floor");
    assert!(
        error.to_string().contains("session handle floor"),
        "{error}"
    );
}

#[tokio::test]
async fn production_multi_boot_opens_each_data_dir_allocator() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("instance");
    std::fs::create_dir_all(&data_dir).expect("create instance dir");
    drop(BoundedSessionStore::open(&data_dir).expect("prime multi durable floor"));
    let mut config =
        InstanceConfig::commit_tree("durable-multi", data_dir.clone(), 0, InstanceRole::Live);
    config.use_flock = false;
    let params = InspireParams::secure_128_d2048();
    let database = vec![0u8; params.ring_dim * 512];
    let (fresh_state, secret_key) =
        setup_state(&params, &database, 512, InspireVariant::TwoPacking).expect("multi setup");
    let mut fresh_state = Some(fresh_state);
    let handle = bootstrap_railgun_engine_multi(vec![config], params.clone(), |_| {
        fresh_state
            .take()
            .ok_or_else(|| raven_railgun_core::AdapterError::Internal("factory reused".to_owned()))
    })
    .expect("multi production bootstrap");
    assert_eq!(read_floor(&data_dir.join(FLOOR_FILE)), 2048);
    let state = handle
        .instances
        .first()
        .expect("one multi instance")
        .instance
        .current_state();
    let mut client =
        build_client_session((*state.crs).clone(), secret_key, &params).expect("multi client");
    let external = state
        .session_store
        .register_client_session_at(&mut client, std::time::Instant::now())
        .expect("multi register")
        .expect("multi handle");
    let (_, inner) = state
        .session_store
        .resolve(Some(external), std::time::Instant::now())
        .expect("multi resolve");
    assert_ne!(external, inner.expect("multi inner"));
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

    assert!(data_dir.join("manifest.json").exists());
    std::fs::remove_file(data_dir.join(FLOOR_FILE)).expect("remove multi-instance floor");
    let mut restart_config =
        InstanceConfig::commit_tree("durable-multi", data_dir.clone(), 0, InstanceRole::Live);
    restart_config.use_flock = false;
    let error = bootstrap_railgun_engine_multi(vec![restart_config], params, |_| {
        raven_railgun_testkit::try_toy_state(512)
    })
    .expect_err("multi-instance restart must refuse a missing floor");
    assert!(error.to_string().contains("floor missing"), "{error}");
}

#[test]
fn checked_floor_overflow_refuses_startup() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_floor(&dir.path().join(FLOOR_FILE), u64::MAX - 100);
    let error = BoundedSessionStore::open_with_limits(dir.path(), limits())
        .expect_err("range overflow must fail closed");
    assert!(error.to_string().contains("exhausted"), "{error}");
}

#[test]
fn two_process_restarts_reserve_distinct_handle_ranges() {
    if let (Ok(data_dir), Ok(output)) = (std::env::var(CHILD_DATA_DIR), std::env::var(CHILD_OUTPUT))
    {
        write_one_child_handle(
            std::path::Path::new(&data_dir),
            std::path::Path::new(&output),
        );
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let first_output = dir.path().join("first-handle");
    let second_output = dir.path().join("second-handle");
    run_child(dir.path(), &first_output);
    run_child(dir.path(), &second_output);
    let stale = read_u64(&first_output);
    let live = read_u64(&second_output);
    assert_ne!(
        stale, live,
        "a process restart must not reissue the stale handle"
    );
    assert!(
        live > stale,
        "durable allocation must advance: {stale} -> {live}"
    );
}

fn run_child(data_dir: &std::path::Path, output: &std::path::Path) {
    let status = std::process::Command::new(std::env::current_exe().expect("current test binary"))
        .arg("--exact")
        .arg("two_process_restarts_reserve_distinct_handle_ranges")
        .env(CHILD_DATA_DIR, data_dir)
        .env(CHILD_OUTPUT, output)
        .status()
        .expect("spawn restart child");
    assert!(status.success(), "restart child exited {status}");
}

fn write_one_child_handle(data_dir: &std::path::Path, output: &std::path::Path) {
    let params = InspireParams::secure_128_d2048();
    let database = vec![0u8; params.ring_dim * ENTRY_SIZE];
    let (state, secret_key) =
        setup_state(&params, &database, ENTRY_SIZE, InspireVariant::TwoPacking).expect("setup");
    let mut client =
        build_client_session((*state.crs).clone(), secret_key, &params).expect("client session");
    let store = BoundedSessionStore::open_with_limits(data_dir, limits()).expect("durable open");
    let handle = store
        .register_client_session_at(&mut client, std::time::Instant::now())
        .expect("register")
        .expect("packing handle");
    std::fs::write(output, handle.0.to_be_bytes()).expect("write public handle");
}

fn read_u64(path: &std::path::Path) -> u64 {
    let bytes: [u8; 8] = std::fs::read(path)
        .expect("read u64")
        .try_into()
        .expect("u64 bytes");
    u64::from_be_bytes(bytes)
}

fn read_floor(path: &std::path::Path) -> u64 {
    let bytes = std::fs::read(path).expect("read floor");
    let floor: [u8; 8] = bytes
        .get(10..18)
        .expect("floor slice")
        .try_into()
        .expect("floor field");
    u64::from_be_bytes(floor)
}

fn write_floor(path: &std::path::Path, floor: u64) {
    let mut bytes = [0u8; 50];
    bytes[..8].copy_from_slice(b"RVNHNDL1");
    bytes[8..10].copy_from_slice(&1u16.to_be_bytes());
    bytes[10..18].copy_from_slice(&floor.to_be_bytes());
    let checksum = Sha256::digest(&bytes[..18]);
    bytes[18..].copy_from_slice(&checksum);
    std::fs::write(path, bytes).expect("write floor");
}
