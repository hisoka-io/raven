//! `/v1/instance/{id}/fanout`: one uploaded query served against k shards.

#![allow(
    clippy::cast_possible_truncation,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use std::net::SocketAddr;

use raven_inspire::ServerResponse;
use raven_railgun_cli::toy_server::{build_toy_pieces, ToyDbConfig, TOY_INSTANCE_ID};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{build_seeded_query, extract_response, RavenInspireScheme};
use raven_railgun_engine::{DrainState, PirInstance};
use raven_railgun_http::{
    inspire_router, read_batch_response_versioned, read_versioned, write_versioned, FanoutRequest,
};
use std::sync::Arc;
use tokio::sync::oneshot;

const BEARER_TOKEN: &str = "fanout-multi-shard-test-token";
const SHARD_COUNT: usize = 3;
const ENTRY_BYTES: usize = 256;
/// Global index inside shard 0; every fanned-out shard reuses its local offset.
const TARGET_INDEX: u64 = 37;
/// Real entries in the tail shard of the partially filled fixture; below
/// [`TARGET_INDEX`], so the fanned-out tail slot lands on padding.
const TAIL_SHARD_FILL: usize = 10;

struct FanoutFixture {
    addr: SocketAddr,
    server: tokio::task::JoinHandle<()>,
    instance: Arc<PirInstance<RavenInspireScheme>>,
    pieces: raven_railgun_cli::toy_server::ToyPieces,
}

async fn spawn_multi_shard_server() -> FanoutFixture {
    let params = raven_inspire::params::InspireParams::secure_128_d2048();
    let fixture = spawn_fanout_server(params.ring_dim * SHARD_COUNT).await;
    assert_eq!(
        fixture.instance.current_state().encoded_db.shards.len(),
        SHARD_COUNT,
        "fixture must encode {SHARD_COUNT} shards for the fan-out to be meaningful"
    );
    fixture
}

/// Tail shard holds [`TAIL_SHARD_FILL`] real entries; the rest of it is padding.
async fn spawn_partially_filled_server() -> FanoutFixture {
    let params = raven_inspire::params::InspireParams::secure_128_d2048();
    let fixture = spawn_fanout_server(params.ring_dim * (SHARD_COUNT - 1) + TAIL_SHARD_FILL).await;
    assert_eq!(
        fixture.instance.current_state().encoded_db.shards.len(),
        SHARD_COUNT,
        "the partial entry count must still round up to {SHARD_COUNT} shards"
    );
    fixture
}

async fn spawn_fanout_server(entries: usize) -> FanoutFixture {
    let config = ToyDbConfig {
        entries,
        entry_bytes: ENTRY_BYTES,
        variant: raven_inspire::params::InspireVariant::TwoPacking,
    };
    let mut pieces = build_toy_pieces(BEARER_TOKEN.to_owned(), config).expect("toy stack");
    // the route is opt-in; this suite is what exercises it
    let mut http_config = (*pieces.app_state.config).clone();
    http_config.enable_fanout = true;
    pieces.app_state.config = std::sync::Arc::new(http_config);
    let instance = pieces
        .app_state
        .engine
        .instance(&InstanceId::new(TOY_INSTANCE_ID))
        .expect("toy instance registered")
        .clone();

    let router = inspire_router(pieces.app_state.clone()).expect("router");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let (ready_tx, ready_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let _ = ready_tx.send(());
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    ready_rx.await.expect("server ready");
    FanoutFixture {
        addr,
        server,
        instance,
        pieces,
    }
}

impl FanoutFixture {
    fn fanout_url(&self) -> String {
        format!("http://{}/v1/instance/{TOY_INSTANCE_ID}/fanout", self.addr)
    }

    fn query_url(&self) -> String {
        format!("http://{}/v1/instance/{TOY_INSTANCE_ID}/query", self.addr)
    }

    fn build_query(&self) -> (raven_inspire::ClientState, raven_inspire::SeededClientQuery) {
        let state = self.instance.current_state();
        build_seeded_query(
            &self.pieces.client_session,
            state.shard_config(),
            TARGET_INDEX,
            &self.pieces.params,
        )
        .expect("seeded query")
    }

    async fn shutdown(self) {
        self.server.abort();
        let _ = self.server.await;
    }
}

async fn post_fanout(
    client: &reqwest::Client,
    fixture: &FanoutFixture,
    query: &raven_inspire::SeededClientQuery,
    shard_ids: Vec<u32>,
) -> (reqwest::StatusCode, Vec<u8>, usize) {
    let body = write_versioned(&FanoutRequest {
        query: query.clone(),
        shard_ids,
    })
    .expect("encode fanout request");
    let uploaded = body.len();
    let resp = client
        .post(fixture.fanout_url())
        .bearer_auth(BEARER_TOKEN)
        .body(body)
        .send()
        .await
        .expect("send fanout");
    let status = resp.status();
    let bytes = resp.bytes().await.expect("fanout body").to_vec();
    (status, bytes, uploaded)
}

async fn post_single_shard(
    client: &reqwest::Client,
    fixture: &FanoutFixture,
    query: &raven_inspire::SeededClientQuery,
    shard_id: u32,
) -> (ServerResponse, usize) {
    let mut per_shard = query.clone();
    per_shard.shard_id = shard_id;
    let body = write_versioned(&per_shard).expect("encode query");
    let uploaded = body.len();
    let resp = client
        .post(fixture.query_url())
        .bearer_auth(BEARER_TOKEN)
        .body(body)
        .send()
        .await
        .expect("send query");
    assert_eq!(
        resp.status(),
        200,
        "single query on shard {shard_id} must succeed"
    );
    let bytes = resp.bytes().await.expect("query body").to_vec();
    (
        read_versioned(&bytes).expect("decode ServerResponse"),
        uploaded,
    )
}

fn response_bytes(response: &ServerResponse) -> Vec<u8> {
    bincode::serialize(response).expect("serialize ServerResponse")
}

fn expected_entry(db: &[u8], shard_id: u32, local_index: u64, entries_per_shard: u64) -> Vec<u8> {
    let global = u64::from(shard_id) * entries_per_shard + local_index;
    let start = usize::try_from(global).expect("fits usize") * ENTRY_BYTES;
    db[start..start + ENTRY_BYTES].to_vec()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fanout_slots_match_per_shard_single_queries_byte_exact() {
    let fixture = spawn_multi_shard_server().await;
    let client = reqwest::Client::new();
    let (client_state, query) = fixture.build_query();
    let shard_ids: Vec<u32> = (0..SHARD_COUNT as u32).collect();

    let (status, body, fanout_upload) =
        post_fanout(&client, &fixture, &query, shard_ids.clone()).await;
    assert_eq!(status, 200, "fan-out must succeed");
    let fanned: Vec<ServerResponse> =
        read_batch_response_versioned(&body).expect("decode fan-out body");
    assert_eq!(fanned.len(), SHARD_COUNT);

    let mut single_upload_total = 0usize;
    for (slot, shard_id) in shard_ids.iter().copied().enumerate() {
        let (single, uploaded) = post_single_shard(&client, &fixture, &query, shard_id).await;
        single_upload_total += uploaded;
        assert_eq!(
            response_bytes(&fanned[slot]),
            response_bytes(&single),
            "fan-out slot {slot} must be byte-identical to the shard-{shard_id} single query"
        );
    }

    // Upload is flat in k, not linear.
    let (status_k1, _, k1_upload) = post_fanout(&client, &fixture, &query, vec![0]).await;
    assert_eq!(status_k1, 200);
    assert!(
        fanout_upload.saturating_sub(k1_upload) <= 4 * SHARD_COUNT + 8,
        "fan-out upload must grow only by the shard-id list: k=1 {k1_upload} B -> \
         k={SHARD_COUNT} {fanout_upload} B"
    );
    assert!(
        fanout_upload < single_upload_total,
        "fan-out upload {fanout_upload} B must beat {SHARD_COUNT} single uploads \
         ({single_upload_total} B)"
    );

    let state = fixture.instance.current_state();
    let entries_per_shard = state.shard_config().entries_per_shard();
    for (slot, shard_id) in shard_ids.iter().copied().enumerate() {
        let plaintext = extract_response(
            &state.crs,
            &client_state,
            &fanned[slot],
            fixture.pieces.config.entry_bytes,
        )
        .expect("extract fan-out slot");
        assert_eq!(
            plaintext,
            expected_entry(
                &fixture.pieces.db,
                shard_id,
                client_state.local_index,
                entries_per_shard
            ),
            "fan-out slot {slot} must decrypt to the shard-{shard_id} entry at the shared local index"
        );
    }

    drop(state);
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fanout_returns_responses_in_request_order() {
    let fixture = spawn_multi_shard_server().await;
    let client = reqwest::Client::new();
    let (_client_state, query) = fixture.build_query();
    // Order follows the request, not the shard index.
    let shard_ids: Vec<u32> = vec![2, 0, 1, 0];

    let (status, body, _) = post_fanout(&client, &fixture, &query, shard_ids.clone()).await;
    assert_eq!(status, 200);
    let fanned: Vec<ServerResponse> =
        read_batch_response_versioned(&body).expect("decode fan-out body");
    assert_eq!(fanned.len(), shard_ids.len());

    for (slot, shard_id) in shard_ids.iter().copied().enumerate() {
        let (single, _) = post_single_shard(&client, &fixture, &query, shard_id).await;
        assert_eq!(
            response_bytes(&fanned[slot]),
            response_bytes(&single),
            "slot {slot} must carry shard {shard_id}, proving request order is preserved"
        );
    }

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fanout_rejects_out_of_range_shard_id() {
    let fixture = spawn_multi_shard_server().await;
    let client = reqwest::Client::new();
    let (_client_state, query) = fixture.build_query();

    let out_of_range = SHARD_COUNT as u32;
    let (status, body, _) = post_fanout(&client, &fixture, &query, vec![0, out_of_range]).await;
    assert_eq!(
        status, 400,
        "shard id {out_of_range} is past the {SHARD_COUNT}-shard instance and must be rejected"
    );
    let detail = String::from_utf8_lossy(&body).into_owned();
    assert!(
        detail.contains(&out_of_range.to_string())
            && detail.contains('1')
            && detail.contains(&SHARD_COUNT.to_string()),
        "the running server must name the offending shard id, its position and the \
         shard count, not just return an empty 400: {detail:?}"
    );

    let (status_far, _, _) = post_fanout(&client, &fixture, &query, vec![u32::MAX]).await;
    assert_eq!(status_far, 400, "u32::MAX shard id must be rejected");

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fanout_rejects_empty_shard_id_list() {
    let fixture = spawn_multi_shard_server().await;
    let client = reqwest::Client::new();
    let (_client_state, query) = fixture.build_query();

    let (status, _, _) = post_fanout(&client, &fixture, &query, Vec::new()).await;
    assert_eq!(status, 400, "empty shard_ids must be rejected");

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fanout_rejects_list_longer_than_cap() {
    let fixture = spawn_multi_shard_server().await;
    let client = reqwest::Client::new();
    let (_client_state, query) = fixture.build_query();

    let cap = fixture.pieces.app_state.config.max_fanout_shards;
    let over_cap: Vec<u32> = vec![0; cap + 1];
    let (status, body, _) = post_fanout(&client, &fixture, &query, over_cap).await;
    assert_eq!(
        status,
        400,
        "a {cap}-shard cap must reject a {}-id list before any respond runs",
        cap + 1
    );
    let detail = String::from_utf8_lossy(&body).into_owned();
    assert!(
        detail.contains(&(cap + 1).to_string()) && detail.contains(&cap.to_string()),
        "the running server must name the requested width and the cap: {detail:?}"
    );

    let at_cap: Vec<u32> = vec![0; cap];
    let (status_at_cap, _, _) = post_fanout(&client, &fixture, &query, at_cap).await;
    assert_eq!(
        status_at_cap, 200,
        "a list exactly at the cap must be served"
    );

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fanout_requires_a_valid_bearer_token() {
    let fixture = spawn_multi_shard_server().await;
    let client = reqwest::Client::new();
    let (_client_state, query) = fixture.build_query();
    let body = write_versioned(&FanoutRequest {
        query,
        shard_ids: vec![0, 1],
    })
    .expect("encode fanout request");

    let no_auth = client
        .post(fixture.fanout_url())
        .body(body.clone())
        .send()
        .await
        .expect("send unauthenticated fanout");
    assert_eq!(
        no_auth.status(),
        401,
        "fan-out must never be reachable without a bearer token"
    );

    let wrong_token = client
        .post(fixture.fanout_url())
        .bearer_auth("not-the-fanout-multi-shard-test-token")
        .body(body)
        .send()
        .await
        .expect("send wrong-token fanout");
    assert_eq!(wrong_token.status(), 401, "a wrong bearer must be rejected");

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fanout_refuses_a_draining_instance() {
    let fixture = spawn_multi_shard_server().await;
    let client = reqwest::Client::new();
    let (_client_state, query) = fixture.build_query();

    let (before, _, _) = post_fanout(&client, &fixture, &query, vec![0, 1]).await;
    assert_eq!(before, 200, "active instance must serve fan-out");

    fixture.instance.set_drain_state(DrainState::Draining);
    let (during, _, _) = post_fanout(&client, &fixture, &query, vec![0, 1]).await;
    assert_eq!(
        during, 503,
        "a draining instance must refuse fan-out like /query and /batch do"
    );

    fixture.instance.set_drain_state(DrainState::Active);
    let (after, _, _) = post_fanout(&client, &fixture, &query, vec![0, 1]).await;
    assert_eq!(after, 200, "undrain must restore fan-out");

    fixture.shutdown().await;
}

/// The padded tail of a partially filled shard decrypts to a well-formed
/// all-zeros record that no error distinguishes from a genuine zero entry, so
/// applications must carry their own presence tag in the record layout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fanout_tail_shard_padding_extracts_as_all_zeros() {
    let fixture = spawn_partially_filled_server().await;
    let client = reqwest::Client::new();
    let (client_state, query) = fixture.build_query();
    let tail_shard = (SHARD_COUNT - 1) as u32;
    assert!(
        client_state.local_index >= TAIL_SHARD_FILL as u64,
        "the shared local index must land past the tail shard's fill point"
    );

    let (status, body, _) = post_fanout(&client, &fixture, &query, vec![0, tail_shard]).await;
    assert_eq!(status, 200, "the padded tail slot must not error");
    let fanned: Vec<ServerResponse> =
        read_batch_response_versioned(&body).expect("decode fan-out body");

    let state = fixture.instance.current_state();
    let entries_per_shard = state.shard_config().entries_per_shard();
    let extract = |response: &ServerResponse| {
        extract_response(
            &state.crs,
            &client_state,
            response,
            fixture.pieces.config.entry_bytes,
        )
        .expect("extract fan-out slot")
    };

    let filled = extract(&fanned[0]);
    assert_eq!(
        filled,
        expected_entry(
            &fixture.pieces.db,
            0,
            client_state.local_index,
            entries_per_shard
        ),
        "the in-range slot must still decrypt to its real entry"
    );
    assert!(
        filled.iter().any(|b| *b != 0),
        "fixture entry must be non-zero for the contrast to mean anything"
    );

    let padded = extract(&fanned[1]);
    assert_eq!(
        padded,
        vec![0u8; fixture.pieces.config.entry_bytes],
        "the tail-shard slot decrypts to all zeros, indistinguishable from a \
         genuine zero entry: only a presence tag in the record layout separates them"
    );

    drop(state);
    fixture.shutdown().await;
}

/// Every other test here opts in, so only this one catches the default flipping.
#[tokio::test]
async fn fanout_is_not_mounted_by_default() {
    let params = raven_inspire::params::InspireParams::secure_128_d2048();
    let config = ToyDbConfig {
        entries: params.ring_dim * SHARD_COUNT,
        entry_bytes: ENTRY_BYTES,
        variant: raven_inspire::params::InspireVariant::TwoPacking,
    };
    let pieces = build_toy_pieces(BEARER_TOKEN.to_owned(), config).expect("toy stack");
    assert!(
        !pieces.app_state.config.enable_fanout,
        "enable_fanout must default to false"
    );

    let router = inspire_router(pieces.app_state.clone()).expect("router");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    let res = reqwest::Client::new()
        .post(format!(
            "http://{addr}/v1/instance/{TOY_INSTANCE_ID}/fanout"
        ))
        .bearer_auth(BEARER_TOKEN)
        .body(Vec::<u8>::new())
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), 404, "an unmounted route must 404, not serve");
}
