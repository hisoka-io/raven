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

const ENTRY_SIZE: usize = 32;
/// Written by builds that kept a handle floor; a data dir may still hold one.
const FLOOR_FILE: &str = "session-handle-floor-v1.bin";
const CHILD_OUTPUT: &str = "RAVEN_RESTART_HANDLE_CHILD_OUTPUT";

fn limits() -> SessionStoreLimits {
    SessionStoreLimits {
        max_sessions: 4,
        ttl: Duration::from_secs(3600),
    }
}

#[test]
fn reopening_the_store_never_reissues_a_stale_handle() {
    let params = InspireParams::d2048();
    let database: Vec<u8> = (0..params.ring_dim * ENTRY_SIZE)
        .map(|offset| u8::try_from(offset % 251).expect("mod 251"))
        .collect();
    let (state, _) =
        setup_state(&params, &database, ENTRY_SIZE, InspireVariant::TwoPacking).expect("setup");
    // The store issues the handle, so one client registered on both sides of the restart is
    // enough to show the restart never reissues.
    let mut client = build_client_session((*state.crs).clone()).expect("client");

    let first = BoundedSessionStore::open_with_limits(limits()).expect("first open");
    let stale = first
        .register_client_session_at(&mut client, std::time::Instant::now())
        .expect("first register")
        .expect("packing handle");
    drop(first);

    let second = Arc::new(BoundedSessionStore::open_with_limits(limits()).expect("restart open"));
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
        "the random external handle must translate to the core handle"
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
        build_seeded_query(&client, durable_state.shard_config(), 3).expect("translated query");
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

    assert_lifecycle(&second, &mut client, live, &inner_store, inner);
}

fn assert_lifecycle(
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

#[tokio::test]
async fn production_single_boot_serves_random_handles_across_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = OrchestratorConfig::demo(dir.path().to_path_buf(), "durable-single");
    config.record_size = 256;
    config.use_flock = false;
    config.role = InstanceRole::Live;
    let params = InspireParams::d2048();
    // Non-constant rows, so the control below proves the client decoded its own record.
    let database: Vec<u8> = (0..params.ring_dim * 256)
        .map(|offset| u8::try_from(offset % 251).expect("mod 251"))
        .collect();
    let (fresh_state, _) =
        setup_state(&params, &database, 256, InspireVariant::TwoPacking).expect("single setup");
    let mut handle = bootstrap_railgun_engine(config, params.clone(), || Ok(fresh_state))
        .expect("single production bootstrap");
    assert!(!dir.path().join(FLOOR_FILE).exists());
    let state = handle.instance.current_state();
    let mut client = build_client_session((*state.crs).clone()).expect("single client");
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

    // The registered client is served under its random handle.
    let (client_state, query) =
        build_seeded_query(&client, state.shard_config(), 3).expect("single query");
    assert_eq!(query.session_handle, Some(external));
    let response =
        <RavenInspireScheme as PirScheme>::respond(&state, &query).expect("single response");
    let plaintext = extract_response(state.crs.as_ref(), &client_state, &response, 256)
        .expect("the registered client's query must serve");
    assert_eq!(
        plaintext,
        database.get(3 * 256..4 * 256).expect("expected record"),
        "the registered client's query must serve its own record"
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
    // An older build's floor beside the manifest neither blocks the restart nor is read.
    std::fs::write(dir.path().join(FLOOR_FILE), b"short").expect("old floor");
    let mut restart_config = OrchestratorConfig::demo(dir.path().to_path_buf(), "durable-single");
    restart_config.record_size = 256;
    restart_config.use_flock = false;
    restart_config.role = InstanceRole::Live;
    let mut restarted = bootstrap_railgun_engine(restart_config, params.clone(), || {
        raven_railgun_testkit::try_toy_state(256)
    })
    .expect("a restart needs no handle history");
    let state = restarted.instance.current_state();
    let mut client = build_client_session((*state.crs).clone()).expect("restart client");
    let after = state
        .session_store
        .register_client_session_at(&mut client, std::time::Instant::now())
        .expect("restart register")
        .expect("restart handle");
    assert_ne!(
        after, external,
        "a restart must not reissue the stale handle"
    );
    assert!(state
        .session_store
        .resolve(Some(external), std::time::Instant::now())
        .is_err());
    assert_eq!(
        std::fs::read(dir.path().join(FLOOR_FILE)).expect("old floor"),
        b"short"
    );
    restarted.indexer_bridge.abort();
    restarted.mirror_bridge.abort();
    progress::abort_consumer(
        "aborted consumer exiting",
        &mut restarted.consumer,
        &restarted.metrics,
        &restarted.persistence,
    )
    .await;
}

#[tokio::test]
async fn production_multi_boot_issues_random_handles() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("instance");
    std::fs::create_dir_all(&data_dir).expect("create instance dir");
    let mut config =
        InstanceConfig::commit_tree("durable-multi", data_dir.clone(), 0, InstanceRole::Live);
    config.use_flock = false;
    let params = InspireParams::d2048();
    let database = vec![0u8; params.ring_dim * 512];
    let (fresh_state, _) =
        setup_state(&params, &database, 512, InspireVariant::TwoPacking).expect("multi setup");
    let mut fresh_state = Some(fresh_state);
    let handle = bootstrap_railgun_engine_multi(vec![config], params.clone(), |_| {
        fresh_state
            .take()
            .ok_or_else(|| raven_railgun_core::AdapterError::Internal("factory reused".to_owned()))
    })
    .expect("multi production bootstrap");
    assert!(!data_dir.join(FLOOR_FILE).exists());
    let state = handle
        .instances
        .first()
        .expect("one multi instance")
        .instance
        .current_state();
    let mut client = build_client_session((*state.crs).clone()).expect("multi client");
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
}

#[test]
fn two_process_restarts_issue_unrelated_handles() {
    if let Ok(output) = std::env::var(CHILD_OUTPUT) {
        write_one_child_handle(std::path::Path::new(&output));
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let first_output = dir.path().join("first-handle");
    let second_output = dir.path().join("second-handle");
    run_child(&first_output);
    run_child(&second_output);
    let stale = read_u64(&first_output);
    let live = read_u64(&second_output);
    assert_ne!(
        stale, live,
        "a process restart must not reissue the stale handle"
    );
    assert!(
        stale.abs_diff(live) > 1 << 20,
        "restarted handles must not sit next to each other: {stale}, {live}"
    );
}

fn run_child(output: &std::path::Path) {
    let status = std::process::Command::new(std::env::current_exe().expect("current test binary"))
        .arg("--exact")
        .arg("two_process_restarts_issue_unrelated_handles")
        .env(CHILD_OUTPUT, output)
        .status()
        .expect("spawn restart child");
    assert!(status.success(), "restart child exited {status}");
}

fn write_one_child_handle(output: &std::path::Path) {
    let params = InspireParams::d2048();
    let database = vec![0u8; params.ring_dim * ENTRY_SIZE];
    let (state, _) =
        setup_state(&params, &database, ENTRY_SIZE, InspireVariant::TwoPacking).expect("setup");
    let mut client = build_client_session((*state.crs).clone()).expect("client session");
    let store = BoundedSessionStore::open_with_limits(limits()).expect("open");
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
