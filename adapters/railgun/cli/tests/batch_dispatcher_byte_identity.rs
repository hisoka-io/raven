//! /batch dispatcher byte-identity test.
//!
//! Verifies that dispatching the same batch at K=1, K=4, and K=16 produces byte-identical
//! response vectors. Catches index-shuffling in the JoinSet drain loop and non-determinism
//! against a frozen server state.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use raven_inspire::ServerResponse;
use raven_railgun_cli::toy_server::{build_toy_pieces, ToyDbConfig, TOY_INSTANCE_ID};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{build_seeded_query, RavenInspireScheme};
use raven_railgun_engine::{Engine, PirInstance};
use raven_railgun_http::{inspire_router, AppState, HttpConfig};
use tokio::sync::oneshot;

const BEARER_TOKEN: &str = "batch-byte-identity-test-token";
const BATCH_SIZE: usize = 16;
const K_VALUES: &[usize] = &[1, 4, 16];

fn build_app_state_with_k(
    instance: Arc<PirInstance<RavenInspireScheme>>,
    k: usize,
) -> AppState<RavenInspireScheme> {
    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    engine
        .register_instance(instance)
        .expect("register shared instance");
    let mut http_config = HttpConfig::demo(BEARER_TOKEN.to_owned());
    http_config.max_concurrent_queries = k;
    AppState::new(engine, http_config).expect("AppState::new")
}

async fn spawn_server(
    app_state: AppState<RavenInspireScheme>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let router = inspire_router(app_state).expect("router");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let (ready_tx, ready_rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let _ = ready_tx.send(());
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    ready_rx.await.expect("server ready");
    (addr, handle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn batch_dispatcher_byte_identity_across_k_values() {
    let pieces = build_toy_pieces(BEARER_TOKEN.to_owned(), ToyDbConfig::default())
        .expect("toy stack builds");

    let shared_instance: Arc<PirInstance<RavenInspireScheme>> = pieces
        .app_state
        .engine
        .instance(&InstanceId::new(TOY_INSTANCE_ID))
        .expect("toy instance registered")
        .clone();
    let server_state_arc = shared_instance.current_state();

    let mut batch_queries = Vec::with_capacity(BATCH_SIZE);
    for k in 0..BATCH_SIZE as u64 {
        let idx = (37u64.wrapping_add(k * 11)) % (pieces.config.entries as u64);
        let (_cs, q) = build_seeded_query(
            &pieces.client_session,
            server_state_arc.shard_config(),
            idx,
            &pieces.params,
        )
        .expect("build_seeded_query");
        batch_queries.push(q);
    }
    let batch_bytes = raven_railgun_http::write_versioned(&batch_queries).expect("serialize batch");

    // generous deadline: K=16 debug batch wall-clocks past 30s on 2-vCPU CI
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .expect("reqwest client");

    let mut bodies_per_k: Vec<(usize, Vec<u8>)> = Vec::with_capacity(K_VALUES.len());

    for &k in K_VALUES {
        let app_state = build_app_state_with_k(Arc::clone(&shared_instance), k);
        let (addr, server_handle) = spawn_server(app_state).await;

        let url = format!("http://{addr}/v1/instance/{TOY_INSTANCE_ID}/batch");
        let resp = client
            .post(&url)
            .bearer_auth(BEARER_TOKEN)
            .body(batch_bytes.clone())
            .send()
            .await
            .expect("POST batch");
        assert_eq!(
            resp.status(),
            200,
            "K={k}: expected 200 OK, got {}",
            resp.status()
        );
        let body = resp.bytes().await.expect("body bytes").to_vec();

        let decoded: Vec<ServerResponse> = raven_railgun_http::read_batch_response_versioned(&body)
            .expect("decode batch responses");
        assert_eq!(
            decoded.len(),
            BATCH_SIZE,
            "K={k}: batch returned wrong count {}",
            decoded.len()
        );

        bodies_per_k.push((k, body));

        server_handle.abort();
        let _ = server_handle.await;
    }

    let (reference_k, reference) = bodies_per_k.first().expect("at least one K dispatched");
    for (k, body) in bodies_per_k.iter().skip(1) {
        assert_eq!(
            body.len(),
            reference.len(),
            "K={k}: response body length differs from K={reference_k} \
             (reference {} bytes, got {} bytes)",
            reference.len(),
            body.len()
        );
        assert_eq!(
            body, reference,
            "K={k}: response body bytes differ from K={reference_k}; \
             dispatcher is NOT byte-identical across concurrency levels"
        );
    }
}
