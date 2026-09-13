//! Shared fixture for the locked T2/T3 production cell: 65,536 entries x 512 B
//! records (16 x 32 B Merkle siblings), served over the real HTTP stack.
//!
//! Two consumers reach this through `#[path]`, and they exist as two consumers
//! on purpose:
//!
//! - `tests/production_cell.rs` asserts BYTE IDENTITY — the correctness half.
//!   It carries no wall-clock assertion, so it can run in a per-commit lane.
//! - `benches/production_cell_budget_bench.rs` asserts the LATENCY BUDGET — an
//!   SLO gate. A deadline reds on runner speed rather than on code, so it must
//!   never share a lane with the correctness half.
//!
//! Standing up the cell costs ~12 s of `setup_state`, which is why both halves
//! are `#[ignore]`d; the split is about which lane each belongs in, not about
//! making either cheap.

// `#[path]`-included by two targets; each uses a different subset, and `pub` is
// how the including crate root reaches any of it.
#![allow(dead_code, unreachable_pub)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::missing_panics_doc
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::{
    ClientSession, ClientState, SeededClientQuery, ServerResponse, ServerSessionHandle,
};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{
    build_client_session, build_seeded_query, extract_response, register_client_session,
    setup_state, InspireServerState, RavenInspireScheme,
};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
use raven_railgun_http::{inspire_router, AppState, HttpConfig};
use tokio::sync::oneshot;

pub const BEARER_TOKEN: &str = "production-cell-test-token";
pub const CLIENT_ID: &str = "00112233445566778899aabbccddeeff";
pub const PRODUCTION_INSTANCE_ID: &str = "ppoi-paths-ofac";
const ENTRIES_LOG2: usize = 16;
/// 16 siblings x 32 B per Merkle path.
pub const ENTRY_BYTES: usize = 512;
/// Batch width used by both halves; also the per-element byte-identity count.
pub const BATCH_WIDTH: usize = 16;

pub fn entries() -> usize {
    1usize << ENTRIES_LOG2
}

#[allow(clippy::cast_possible_truncation)]
pub fn build_synthetic_db(n_entries: usize, entry_bytes: usize) -> Vec<u8> {
    (0..n_entries)
        .flat_map(|i| (0..entry_bytes).map(move |j| ((i * 31 + j * 17) % 251) as u8))
        .collect()
}

/// A live server at the production cell plus everything a client needs to query it.
pub struct ProductionCell {
    pub addr: SocketAddr,
    pub db: Vec<u8>,
    pub params: InspireParams,
    pub client_session: ClientSession,
    pub server_state: Arc<InspireServerState>,
    pub setup_elapsed: Duration,
    pub max_body_bytes: usize,
    server_handle: tokio::task::JoinHandle<()>,
    /// Registered in-process; HTTP queries ride the same session.
    _session_handle: ServerSessionHandle,
}

impl ProductionCell {
    /// Stands up `setup_state` at the production cell and serves it over loopback.
    pub async fn spawn() -> Self {
        let setup_start = Instant::now();
        let params = InspireParams::secure_128_d2048();
        let db = build_synthetic_db(entries(), ENTRY_BYTES);
        let (server_state, secret_key) =
            setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking)
                .expect("setup_state");
        let mut client_session =
            build_client_session((*server_state.crs).clone(), secret_key.clone(), &params)
                .expect("build_client_session");
        let (_, registration_query) =
            build_seeded_query(&client_session, server_state.shard_config(), 0, &params)
                .expect("build registration query");
        let registration_keys = registration_query
            .inspiring_packing_keys
            .expect("unregistered query carries packing keys");
        let registration_body =
            raven_railgun_http::write_versioned(&registration_keys).expect("serialize keys");
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
        let max_body_bytes = http_config.max_body_bytes;
        let app_state = AppState::new(engine, http_config).expect("AppState init");
        let setup_elapsed = setup_start.elapsed();

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

        let session_response = Self::client()
            .post(format!(
                "http://{addr}/v1/instance/{PRODUCTION_INSTANCE_ID}/session"
            ))
            .bearer_auth(BEARER_TOKEN)
            .header("x-raven-client-id", CLIENT_ID)
            .body(registration_body)
            .send()
            .await
            .expect("POST session");
        assert_eq!(session_response.status(), 200, "session establish");
        let remote_handle = session_response
            .headers()
            .get("x-raven-session")
            .and_then(|value| value.to_str().ok())
            .expect("session response carries x-raven-session")
            .parse()
            .expect("session handle is a decimal u64");
        client_session
            .install_server_session_handle(ServerSessionHandle(remote_handle))
            .expect("install HTTP session handle");

        Self {
            addr,
            db,
            params,
            client_session,
            server_state: server_state_arc,
            setup_elapsed,
            max_body_bytes,
            server_handle,
            _session_handle: session_handle,
        }
    }

    pub fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client")
    }

    pub fn query_url(&self) -> String {
        let addr = self.addr;
        format!("http://{addr}/v1/instance/{PRODUCTION_INSTANCE_ID}/query")
    }

    pub fn batch_url(&self) -> String {
        let addr = self.addr;
        format!("http://{addr}/v1/instance/{PRODUCTION_INSTANCE_ID}/batch")
    }

    /// Serialized single query for `target_index`, plus the client state that decodes it.
    pub fn seeded_query(&self, target_index: u64) -> (ClientState, Vec<u8>) {
        let (client_state, query) = self.handled_query(target_index);
        let bytes = raven_railgun_http::write_versioned(&query).expect("serialize query");
        (client_state, bytes)
    }

    pub fn handled_query(&self, target_index: u64) -> (ClientState, SeededClientQuery) {
        build_seeded_query(
            &self.client_session,
            self.server_state.shard_config(),
            target_index,
            &self.params,
        )
        .expect("build_seeded_query")
    }

    /// The `BATCH_WIDTH` indices both halves use, with their serialized batch body.
    pub fn seeded_batch(&self, target_index: u64) -> (Vec<ClientState>, Vec<u64>, Vec<u8>) {
        let mut queries = Vec::with_capacity(BATCH_WIDTH);
        let mut client_states = Vec::with_capacity(BATCH_WIDTH);
        let mut targets = Vec::with_capacity(BATCH_WIDTH);
        let span = u64::try_from(entries()).expect("cell size fits u64");
        for k in 0..BATCH_WIDTH {
            let stride = u64::try_from(k).expect("batch index fits u64") * 911;
            let idx = target_index.wrapping_add(stride) % span;
            targets.push(idx);
            let (cs, q) = build_seeded_query(
                &self.client_session,
                self.server_state.shard_config(),
                idx,
                &self.params,
            )
            .expect("build_seeded_query");
            client_states.push(cs);
            queries.push(q);
        }
        let bytes = raven_railgun_http::write_versioned(&queries).expect("serialize batch");
        (client_states, targets, bytes)
    }

    /// The planted record at `idx` — the oracle a decoded response must equal.
    pub fn planted(&self, idx: u64) -> &[u8] {
        let i = usize::try_from(idx).expect("fits in usize");
        self.db
            .get(i * ENTRY_BYTES..(i + 1) * ENTRY_BYTES)
            .expect("planted slice in range")
    }

    pub fn decode(&self, client_state: &ClientState, response: &ServerResponse) -> Vec<u8> {
        extract_response(&self.server_state.crs, client_state, response, ENTRY_BYTES)
            .expect("extract")
    }

    pub async fn shutdown(self) {
        self.server_handle.abort();
        let _ = self.server_handle.await;
    }
}
