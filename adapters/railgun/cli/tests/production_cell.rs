//! Production-cell integration test (`#[ignore]`-gated).
//! Exercises the full HTTP stack against the locked T2/T3 production
//! cell: 65,536 entries × 512 B records (16 × 32 B Merkle siblings).

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::print_stderr
)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::{ServerResponse, ServerSessionHandle};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{
    build_client_session, build_seeded_query, extract_response, register_client_session,
    setup_state, RavenInspireScheme,
};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
use raven_railgun_http::{inspire_router, AppState, HttpConfig};
use tokio::sync::oneshot;

const BEARER_TOKEN: &str = "production-cell-test-token";
const PRODUCTION_INSTANCE_ID: &str = "ppoi-paths-ofac";
const ENTRIES_LOG2: usize = 16;
/// T2/T3 cell: 16 siblings × 32 B = 512 B per Merkle path.
/// Locked by `INSPIRE_PRODUCTION_VARIANT_BENCH.md`: 71.9 ms total /
/// 69.3 ms server / 32.9 KB response.
const ENTRY_BYTES: usize = 512;

fn entries() -> usize {
    1usize << ENTRIES_LOG2
}

#[allow(clippy::cast_possible_truncation)]
fn build_synthetic_db(n_entries: usize, entry_bytes: usize) -> Vec<u8> {
    // Deterministic but non-trivial: byte (i, j) = (i * 31 + j * 17) mod 251.
    (0..n_entries)
        .flat_map(|i| (0..entry_bytes).map(move |j| ((i * 31 + j * 17) % 251) as u8))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "production-cell setup is heavy (~4-8s) and exercises the full stack"]
#[allow(clippy::too_many_lines)]
async fn production_cell_round_trip_and_batch_within_budget() {
    let setup_start = Instant::now();
    let params = InspireParams::secure_128_d2048();
    let db = build_synthetic_db(entries(), ENTRY_BYTES);
    let (server_state, secret_key) =
        setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("setup_state");
    let mut client_session =
        build_client_session((*server_state.crs).clone(), secret_key.clone(), &params)
            .expect("build_client_session");
    let session_handle: ServerSessionHandle = {
        register_client_session(&mut client_session, &server_state).expect("register session");
        client_session
            .session_handle()
            .expect("session_handle was set by register_client_session")
    };

    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    engine
        .add_instance(PirInstance::new(
            InstanceId::new(PRODUCTION_INSTANCE_ID),
            InstanceRole::Live,
            server_state,
        ))
        .expect("add instance");

    let mut http_config = HttpConfig::demo(BEARER_TOKEN.to_owned());
    http_config.max_concurrent_queries = 4;
    let app_state = AppState::new(engine, http_config).expect("AppState init");
    let setup_elapsed = setup_start.elapsed();
    eprintln!("production_cell: setup elapsed = {setup_elapsed:?}");

    // Snapshot the engine's live server state for in-process query
    // construction (same shard_config /v1/instance/{id}/params surfaces).
    let server_state_arc = app_state
        .engine
        .instance(&InstanceId::new(PRODUCTION_INSTANCE_ID))
        .expect("instance present")
        .current_state();

    let router = inspire_router(app_state.clone()).expect("router");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let (ready_tx, ready_rx) = oneshot::channel::<()>();
    let server_handle = tokio::spawn(async move {
        let _ = ready_tx.send(());
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    ready_rx.await.expect("server ready");

    let _ = session_handle; // session was registered in-process; HTTP queries use it via the session.

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("reqwest client");

    let target_index: u64 = 31_415;
    let (client_state, query) = build_seeded_query(
        &client_session,
        server_state_arc.shard_config(),
        target_index,
        &params,
    )
    .expect("build_seeded_query");
    let query_bytes =
        raven_railgun_http::write_versioned(&query).expect("serialize query (versioned)");

    let url = format!("http://{addr}/v1/instance/{PRODUCTION_INSTANCE_ID}/query");
    let single_start = Instant::now();
    let response = client
        .post(&url)
        .bearer_auth(BEARER_TOKEN)
        .body(query_bytes)
        .send()
        .await
        .expect("POST query");
    assert_eq!(response.status(), 200, "HTTP status");
    let single_total = single_start.elapsed();
    eprintln!("production_cell: single-query total = {single_total:?}");

    let body = response.bytes().await.expect("body bytes");
    let server_response: ServerResponse =
        raven_railgun_http::read_versioned(&body).expect("deserialize ServerResponse (versioned)");
    let plaintext = extract_response(
        &server_state_arc.crs,
        &client_state,
        &server_response,
        ENTRY_BYTES,
    )
    .expect("extract");

    let target_idx_usize = usize::try_from(target_index).expect("fits in usize");
    let expected = db
        .get(target_idx_usize * ENTRY_BYTES..(target_idx_usize + 1) * ENTRY_BYTES)
        .expect("planted slice in range");
    assert_eq!(
        plaintext.get(..ENTRY_BYTES),
        Some(expected),
        "single-query byte equality"
    );

    // Bench gate: locked production target is ~71.9 ms total /
    // 69.3 ms server (3-seed median, 0.6% spread) per
    // INSPIRE_PRODUCTION_VARIANT_BENCH.md. Test asserts < 300 ms
    // total RT to leave headroom for HTTP + serde + WSL2 noise +
    // single-test variance.
    assert!(
        single_total < Duration::from_millis(300),
        "single query total RT regressed: {single_total:?} (production floor 71.9 ms total)"
    );

    // BATCH of 16 queries — the 16-sibling Merkle-proof case.
    let mut batch_queries = Vec::with_capacity(16);
    let mut client_states = Vec::with_capacity(16);
    let mut targets = Vec::with_capacity(16);
    for k in 0..16u64 {
        let idx = target_index.wrapping_add(k * 911) % (entries() as u64);
        targets.push(idx);
        let (cs, q) = build_seeded_query(
            &client_session,
            server_state_arc.shard_config(),
            idx,
            &params,
        )
        .expect("build_seeded_query");
        client_states.push(cs);
        batch_queries.push(q);
    }
    let batch_bytes =
        raven_railgun_http::write_versioned(&batch_queries).expect("serialize batch (versioned)");

    let batch_url = format!("http://{addr}/v1/instance/{PRODUCTION_INSTANCE_ID}/batch");
    let batch_start = Instant::now();
    let batch_response = client
        .post(&batch_url)
        .bearer_auth(BEARER_TOKEN)
        .body(batch_bytes)
        .send()
        .await
        .expect("POST batch");
    assert_eq!(batch_response.status(), 200, "batch HTTP status");
    let batch_total = batch_start.elapsed();
    eprintln!("production_cell: batch (16 queries) total = {batch_total:?}");

    let batch_body = batch_response.bytes().await.expect("batch body");
    let responses: Vec<ServerResponse> = raven_railgun_http::read_batch_response_versioned(
        &batch_body,
    )
    .expect("deserialize batch (versioned)");
    assert_eq!(responses.len(), 16, "batch returned 16 responses");

    for (k, (cs, response)) in client_states.iter().zip(responses.iter()).enumerate() {
        let idx = *targets.get(k).expect("target idx in range");
        let plaintext =
            extract_response(&server_state_arc.crs, cs, response, ENTRY_BYTES).expect("extract");
        let expected = db
            .get(
                usize::try_from(idx).expect("fits in usize") * ENTRY_BYTES
                    ..(usize::try_from(idx).expect("fits in usize") + 1) * ENTRY_BYTES,
            )
            .expect("planted slice in range");
        assert_eq!(
            plaintext.get(..ENTRY_BYTES),
            Some(expected),
            "batch byte equality at k={k}, idx={idx}"
        );
    }

    // Batch wall-time gate. The /batch endpoint runs queries
    // sequentially inside spawn_blocking — each call already uses
    // rayon internally for the per-shard column loop, so wrapping
    // them in `par_iter` thrashes the global pool and makes the
    // batch slower than serial.
    //
    // Sequential floor: 16 × ~75 ms = ~1200 ms. Plus HTTP overhead +
    // WSL2 variance gives a realistic budget of ~3 s. Cross-query
    // K-style concurrency (memory 061, 3.97× at our cell) is
    // catalogued for an earlier cycle+ — that's where the <250 ms target
    // becomes reachable.
    assert!(
        batch_total < Duration::from_millis(3000),
        "batch total RT regressed: {batch_total:?} (sequential floor ~1.2 s)"
    );

    server_handle.abort();
    let _ = server_handle.await;
}
