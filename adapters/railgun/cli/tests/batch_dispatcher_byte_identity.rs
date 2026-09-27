//! The same batch at K=1, K=4, K=16 must produce byte-identical response vectors,
//! catching index-shuffling in the JoinSet drain loop. The order is parameter-independent, so a
//! ring-256 cell stands in for the production one.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use raven_inspire::params::{InspireParams, InspireVariant, SecurityLevel};
use raven_inspire::{ClientSession, ServerResponse, ServerSessionHandle};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{
    build_client_session, build_seeded_query, register_client_session, setup_state,
    RavenInspireScheme,
};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
use raven_railgun_http::{inspire_router, AppState, HttpConfig};
use tokio::sync::oneshot;

const BEARER_TOKEN: &str = "batch-byte-identity-test-token";
const BATCH_SIZE: usize = 16;
const K_VALUES: &[usize] = &[1, 4, 16];
const CLIENT_ID: &str = "00112233445566778899aabbccddeeff";
const TOY_INSTANCE_ID: &str = "toy";
const ENTRIES: usize = 256;
const ENTRY_BYTES: usize = 32;

fn ring_256() -> InspireParams {
    InspireParams {
        ring_dim: 256,
        q: 1_152_921_504_606_830_593,
        crt_moduli: vec![1_152_921_504_606_830_593],
        p: 65_537,
        sigma: 6.4,
        gadget_base: 1 << 20,
        query_gadget_len: 3,
        packing_gadget_len: 3,
        security_level: SecurityLevel::Bits128,
    }
}

struct Fixture {
    instance: Arc<PirInstance<RavenInspireScheme>>,
    client_session: ClientSession,
    registration_body: Vec<u8>,
    params: InspireParams,
}

fn fixture() -> Fixture {
    let params = ring_256();
    let db = raven_railgun_testkit::toy_db(ENTRIES, ENTRY_BYTES);
    let (state, secret) =
        setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("setup_state");
    let mut client_session =
        build_client_session((*state.crs).clone(), secret, &params).expect("client session");
    let (_, registration) = build_seeded_query(&client_session, state.shard_config(), 0, &params)
        .expect("registration query");
    let registration_body = raven_railgun_http::write_versioned(
        &registration
            .inspiring_packing_keys
            .expect("a fresh session carries packing keys"),
    )
    .expect("registration wire");
    register_client_session(&mut client_session, &state).expect("register session");
    let instance = Arc::new(PirInstance::new(
        InstanceId::new(TOY_INSTANCE_ID),
        InstanceRole::Static,
        state,
    ));
    Fixture {
        instance,
        client_session,
        registration_body,
        params,
    }
}

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

async fn establish_http_session(
    client: &reqwest::Client,
    addr: SocketAddr,
    registration_body: &[u8],
) -> ServerSessionHandle {
    let url = format!("http://{addr}/v1/instance/{TOY_INSTANCE_ID}/session");
    let response = client
        .post(url)
        .bearer_auth(BEARER_TOKEN)
        .header("x-raven-client-id", CLIENT_ID)
        .body(registration_body.to_vec())
        .send()
        .await
        .expect("POST session");
    assert_eq!(response.status(), 200, "session establish must succeed");
    let raw = response
        .headers()
        .get("x-raven-session")
        .and_then(|value| value.to_str().ok())
        .expect("session response carries x-raven-session");
    ServerSessionHandle(raw.parse().expect("session handle is a decimal u64"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn batch_dispatcher_byte_identity_across_k_values() {
    let fixture = fixture();
    let shared_instance = Arc::clone(&fixture.instance);
    let server_state_arc = shared_instance.current_state();

    let mut batch_queries = Vec::with_capacity(BATCH_SIZE);
    for k in 0..BATCH_SIZE as u64 {
        let idx = (37u64.wrapping_add(k * 11)) % (ENTRIES as u64);
        let (_cs, q) = build_seeded_query(
            &fixture.client_session,
            server_state_arc.shard_config(),
            idx,
            &fixture.params,
        )
        .expect("build_seeded_query");
        batch_queries.push(q);
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest client");

    let mut bodies_per_k: Vec<(usize, Vec<u8>)> = Vec::with_capacity(K_VALUES.len());

    for &k in K_VALUES {
        let app_state = build_app_state_with_k(Arc::clone(&shared_instance), k);
        let (addr, server_handle) = spawn_server(app_state).await;
        let handle = establish_http_session(&client, addr, &fixture.registration_body).await;
        let bound_queries = batch_queries
            .iter()
            .cloned()
            .map(|mut query| {
                query.session_handle = Some(handle);
                query.inspiring_packing_keys = None;
                query
            })
            .collect::<Vec<_>>();
        let batch_bytes =
            raven_railgun_http::write_versioned(&bound_queries).expect("serialize batch");

        let url = format!("http://{addr}/v1/instance/{TOY_INSTANCE_ID}/batch");
        let resp = client
            .post(&url)
            .bearer_auth(BEARER_TOKEN)
            .header("x-raven-client-id", CLIENT_ID)
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
        let distinct: std::collections::BTreeSet<Vec<u8>> = decoded
            .iter()
            .map(|response| raven_railgun_http::write_versioned(response).expect("encode"))
            .collect();
        assert_eq!(
            distinct.len(),
            BATCH_SIZE,
            "K={k}: two queries drew one response, so a shuffle between them would go unseen"
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
