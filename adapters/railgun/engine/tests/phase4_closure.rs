//! Phase 4 closure E2E: chain-event -> consumer apply -> re-encode at
//! commit -> swap_state -> PIR response reflects new bytes.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::items_after_statements,
    clippy::print_stderr
)]

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::{CommitmentLeaf, RailgunEvent};
use raven_railgun_engine::inspire::{
    build_client_session, build_seeded_query, extract_response, register_client_session,
    setup_state, InspireServerState,
};
use raven_railgun_engine::orchestrator::{bootstrap_railgun_engine, OrchestratorConfig};
use raven_railgun_engine::persistence::ConsumerEvent;
use raven_railgun_engine::{InstanceRole, PirScheme};
use std::sync::Arc;
use std::time::Duration;

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-test";

// Toy DB: smallest cell (256x256) that exercises the production stack.
const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_SIZE: usize = 256;

// Locked production cell: T2/T3 PPOI / commit-tree path-table shape.
// ~17 s wall (3.7 s setup + 3.7 s ClientSession + ~5 ms re-encode
// + ~70 ms respond) so `#[ignore]`-gated.
const PROD_ENTRIES: usize = 65_536;
const PROD_ENTRY_SIZE: usize = 512;

fn build_initial_db_with_size(entries: usize, entry_size: usize) -> Vec<u8> {
    (0..entries)
        .flat_map(|i| (0..entry_size).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
        .collect()
}

fn build_initial_db() -> Vec<u8> {
    build_initial_db_with_size(TOY_ENTRIES, TOY_ENTRY_SIZE)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn phase4_chain_event_propagates_to_pir_response() {
    let dir = tempfile::tempdir().expect("tempdir");
    let params = InspireParams::secure_128_d2048();
    let db = build_initial_db();

    // Setup state OUTSIDE bootstrap so we keep the secret_key for
    // client session building.
    let (state, sk) =
        setup_state(&params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking).expect("setup");

    let mut state_holder = Some(state);
    let factory = move || {
        state_holder.take().ok_or_else(|| {
            raven_railgun_core::AdapterError::Internal("factory called twice".into())
        })
    };

    let mut config = OrchestratorConfig::demo(dir.path().to_path_buf(), "phase4-toy");
    config.use_flock = false;
    config.role = InstanceRole::Live;
    config.scheme_tag = SCHEME_TAG.to_owned();
    config.record_size = TOY_ENTRY_SIZE;
    config.entries_per_shard = u32::try_from(TOY_ENTRIES).expect("toy entries fits u32");

    let handle = bootstrap_railgun_engine(config, params.clone(), factory).expect("bootstrap");

    // Sessions are Arc-shared across re-encode-driven swaps so the
    // handle stays valid post-commit.
    let live_state: Arc<InspireServerState> = handle.instance.current_state();
    let crs_for_client = (*live_state.crs).clone();
    let mut client_session = build_client_session(crs_for_client, sk, &params).expect("client");
    register_client_session(&mut client_session, live_state.as_ref()).expect("register session");

    // The IMT requires contiguous-strict appends per tree (leaf_index 0
    // first, 1 next, ...). The planted commitment is BN254-Fr-canonical
    // (high byte = 0x07 < 0x30) so the IMT's Poseidon hash on insert
    // succeeds; a non-canonical pattern would surface as InvalidQuery
    // via the tolerant-replay path.
    const TARGET: u32 = 0;
    let planted: [u8; 32] = {
        let mut b = [0u8; 32];
        b[31] = 0x07;
        b[30] = 0xab;
        b
    };

    let chain_event = RailgunEvent::Transact {
        block_number: 100,
        tx_hash: [0u8; 32],
        tree_number: 0,
        start_position: TARGET,
        leaves: vec![CommitmentLeaf {
            tree_number: 0,
            leaf_index: TARGET,
            commitment_hash: planted,
            ciphertext: vec![],
        }],
    };
    handle
        .sender
        .send(ConsumerEvent::Chain(chain_event, 100))
        .await
        .expect("send chain event");

    // Register the commit notification BEFORE sending the trigger so
    // the wake isn't missed. Reorg to height 100 so the planted leaf
    // at block 100 SURVIVES.
    let commit_fut = handle.persistence.commit_notify().notified();
    tokio::pin!(commit_fut);
    commit_fut.as_mut().enable();
    handle
        .sender
        .send(ConsumerEvent::Reorg(100))
        .await
        .expect("send reorg");
    tokio::time::timeout(Duration::from_secs(60), commit_fut)
        .await
        .expect(
            "commit fired within 60s (re-encode latency at toy cell ~5ms; \
                 60s allows for slow CI)",
        );

    let surviving = {
        let store = handle.logical_store.lock();
        store.leaf(0, TARGET).copied()
    };
    assert_eq!(
        surviving,
        Some(planted),
        "leaf at block_height = reorg height should survive"
    );

    let live_state_after: Arc<InspireServerState> = handle.instance.current_state();
    let (client_state, query) = build_seeded_query(
        &client_session,
        live_state_after.shard_config(),
        u64::from(TARGET),
        &params,
    )
    .expect("build query");

    let response = <raven_railgun_engine::inspire::RavenInspireScheme as PirScheme>::respond(
        live_state_after.as_ref(),
        &query,
    )
    .expect("respond");

    let plaintext = extract_response(
        live_state_after.crs.as_ref(),
        &client_state,
        &response,
        TOY_ENTRY_SIZE,
    )
    .expect("extract");

    let recovered_first_32 = plaintext
        .get(..32)
        .expect("plaintext at least 32 bytes")
        .to_vec();
    assert_eq!(
        recovered_first_32, planted,
        "Phase 4 closure: PIR response's first 32 bytes must equal the \
         planted commitment_hash. If this fires, the chain-event → \
         apply_wal_entry → drive_commit → re_encode_shard → swap_state \
         → respond pipeline is broken."
    );

    let tail = plaintext.get(32..TOY_ENTRY_SIZE).expect("tail in range");
    assert!(
        tail.iter().all(|&b| b == 0),
        "rest of the row should be zero-filled"
    );

    handle
        .sender
        .send(ConsumerEvent::Shutdown)
        .await
        .expect("shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(5), handle.consumer).await;
}

// Gap A regression: a clean shutdown after the chain head has raced ahead of
// the last applied leaf must persist the LEAF block as the manifest resume
// floor, not the chain head. A head-based floor skips the lagged leaves on
// restart and wedges the tree on the next non-contiguous append.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_floor_is_last_leaf_block_not_chain_head() {
    let dir = tempfile::tempdir().expect("tempdir");
    let params = InspireParams::secure_128_d2048();
    let db = build_initial_db();
    let (state, _sk) =
        setup_state(&params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking).expect("setup");
    let mut state_holder = Some(state);
    let factory = move || {
        state_holder.take().ok_or_else(|| {
            raven_railgun_core::AdapterError::Internal("factory called twice".into())
        })
    };

    let mut config = OrchestratorConfig::demo(dir.path().to_path_buf(), "gap-a-toy");
    config.use_flock = false;
    config.role = InstanceRole::Live;
    config.scheme_tag = SCHEME_TAG.to_owned();
    config.record_size = TOY_ENTRY_SIZE;
    config.entries_per_shard = u32::try_from(TOY_ENTRIES).expect("toy entries fits u32");
    let handle = bootstrap_railgun_engine(config, params, factory).expect("bootstrap");

    const LEAF_BLOCK: u64 = 100;
    const CHAIN_HEAD: u64 = 5_000;
    let planted: [u8; 32] = {
        let mut b = [0u8; 32];
        b[31] = 0x07;
        b[30] = 0xab;
        b
    };
    let chain_event = RailgunEvent::Transact {
        block_number: LEAF_BLOCK,
        tx_hash: [0u8; 32],
        tree_number: 0,
        start_position: 0,
        leaves: vec![CommitmentLeaf {
            tree_number: 0,
            leaf_index: 0,
            commitment_hash: planted,
            ciphertext: vec![],
        }],
    };
    handle
        .sender
        .send(ConsumerEvent::Chain(chain_event, LEAF_BLOCK))
        .await
        .expect("send leaf");
    // Heartbeat: chain head races far past the last applied leaf (stall shape).
    handle
        .sender
        .send(ConsumerEvent::Heartbeat(CHAIN_HEAD))
        .await
        .expect("send heartbeat");
    handle
        .sender
        .send(ConsumerEvent::Shutdown)
        .await
        .expect("shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(30), handle.consumer)
        .await
        .expect("consumer joins");

    assert_eq!(
        handle.persistence.manifest_block_height(),
        LEAF_BLOCK,
        "manifest resume floor must equal the last applied-leaf block, not the \
         chain head ({CHAIN_HEAD}); a head-based floor wedges the tree on restart"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "production cell ~17s; runs alongside production_cell.rs"]
#[allow(clippy::too_many_lines)]
async fn phase4_chain_event_propagates_to_pir_response_at_production_cell() {
    let dir = tempfile::tempdir().expect("tempdir");
    let params = InspireParams::secure_128_d2048();
    let db = build_initial_db_with_size(PROD_ENTRIES, PROD_ENTRY_SIZE);

    let started = std::time::Instant::now();
    let (state, sk) =
        setup_state(&params, &db, PROD_ENTRY_SIZE, InspireVariant::TwoPacking).expect("setup");
    eprintln!(
        "phase4_closure prod: setup elapsed = {:?}",
        started.elapsed()
    );

    let mut state_holder = Some(state);
    let factory = move || {
        state_holder.take().ok_or_else(|| {
            raven_railgun_core::AdapterError::Internal("factory called twice".into())
        })
    };

    let mut config = OrchestratorConfig::demo(dir.path().to_path_buf(), "phase4-prod");
    config.use_flock = false;
    config.role = InstanceRole::Live;
    config.scheme_tag = SCHEME_TAG.to_owned();
    config.record_size = PROD_ENTRY_SIZE;
    config.entries_per_shard = 2048;

    let handle = bootstrap_railgun_engine(config, params.clone(), factory).expect("bootstrap");

    let live_state: Arc<InspireServerState> = handle.instance.current_state();
    let crs_for_client = (*live_state.crs).clone();
    let mut client_session = build_client_session(crs_for_client, sk, &params).expect("client");
    register_client_session(&mut client_session, live_state.as_ref()).expect("register session");

    // BN254-Fr-canonical commitment (high byte = 0x07 < 0x30) so the
    // IMT's Poseidon hash on insert succeeds.
    const TARGET: u32 = 0;
    let planted: [u8; 32] = {
        let mut b = [0u8; 32];
        b[31] = 0x07;
        b[30] = 0xcd;
        b
    };

    let chain_event = RailgunEvent::Transact {
        block_number: 100,
        tx_hash: [0u8; 32],
        tree_number: 0,
        start_position: TARGET,
        leaves: vec![CommitmentLeaf {
            tree_number: 0,
            leaf_index: TARGET,
            commitment_hash: planted,
            ciphertext: vec![],
        }],
    };
    handle
        .sender
        .send(ConsumerEvent::Chain(chain_event, 100))
        .await
        .expect("send chain event");

    let commit_fut = handle.persistence.commit_notify().notified();
    tokio::pin!(commit_fut);
    commit_fut.as_mut().enable();
    handle
        .sender
        .send(ConsumerEvent::Reorg(100))
        .await
        .expect("send reorg");
    tokio::time::timeout(Duration::from_secs(120), commit_fut)
        .await
        .expect("commit fired within 120s at production cell");

    let surviving = {
        let store = handle.logical_store.lock();
        store.leaf(0, TARGET).copied()
    };
    assert_eq!(
        surviving,
        Some(planted),
        "leaf at block_height = reorg height should survive"
    );

    let live_state_after: Arc<InspireServerState> = handle.instance.current_state();
    let (client_state, query) = build_seeded_query(
        &client_session,
        live_state_after.shard_config(),
        u64::from(TARGET),
        &params,
    )
    .expect("build query");

    let response = <raven_railgun_engine::inspire::RavenInspireScheme as PirScheme>::respond(
        live_state_after.as_ref(),
        &query,
    )
    .expect("respond");

    let plaintext = extract_response(
        live_state_after.crs.as_ref(),
        &client_state,
        &response,
        PROD_ENTRY_SIZE,
    )
    .expect("extract");

    let recovered_first_32 = plaintext
        .get(..32)
        .expect("plaintext at least 32 bytes")
        .to_vec();
    assert_eq!(
        recovered_first_32, planted,
        "Phase 4 closure at production cell: PIR response's first 32 bytes \
         must equal the planted commitment_hash. If this fires, the \
         closure-rule shape-dependent regressions sneaked in."
    );

    let tail = plaintext.get(32..PROD_ENTRY_SIZE).expect("tail in range");
    assert!(
        tail.iter().all(|&b| b == 0),
        "rest of the row should be zero-filled at production cell too"
    );

    eprintln!(
        "phase4_closure prod: full pipeline elapsed = {:?}",
        started.elapsed()
    );

    handle
        .sender
        .send(ConsumerEvent::Shutdown)
        .await
        .expect("shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(10), handle.consumer).await;
}
