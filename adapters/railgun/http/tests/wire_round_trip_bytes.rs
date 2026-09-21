//! One run that produces the whole published wire figure: the uploaded query, the served
//! response and the sibling addendum, at the shape a PPOI block serves.
//!
//! Every earlier measurement took one half. The upload was a `const fn` model or a frozen hex
//! fixture, the response a hand-built `ServerResponse` or a lane nothing runs, and no test
//! carried an addendum at all -- so the published total was a sum of three numbers no single
//! run had ever produced together. Each figure below is derived from named constants AND
//! pinned as a literal, so a codec change reddens with a readable number rather than a diff.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::unwrap_used,
    reason = "HTTP integration fixture and byte-oracle diagnostics"
)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::{SeededClientQuery, ServerResponse, ServerSessionHandle};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::imt::TREE_DEPTH;
use raven_railgun_engine::inspire::{
    apply_wal_entry, build_client_session, build_seeded_query, extract_response, setup_state,
    InspireServerState, LogicalLeafStore, RavenInspireScheme, WIRE_RESPONSE_MODULUS,
};
use raven_railgun_engine::pir_table::list::{PATH10_LEVELS, PATH10_MAGIC};
use raven_railgun_engine::pir_table::{PerListPath10Encoder, PirTableEncoder, PATH10_RECORD_BYTES};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
use raven_railgun_http::{
    inspire_router, read_batch_response_versioned, write_versioned, AppState, HttpConfig,
    WIRE_SCHEMA_PREFIX_LEN, WIRE_SCHEMA_VERSION,
};
use raven_railgun_persistence::WalEntryPayload;
use tower::ServiceExt;

const TOKEN: &str = "wire-round-trip-bytes-token-padded-12";
const CLIENT_ID: &str = "00112233445566778899aabbccddeeff";
const INSTANCE: &str = "ppoi-paths-wire";
const LIST_KEY: [u8; 32] = [0x7e; 32];
/// The shipped block geometry: one shard per ring, one level-11 subtree per shard.
const ENTRIES_PER_SHARD: u32 = 2_048;
const LEAVES: u32 = 300;
/// Bits 0,1,2 set, so the path turns both ways before it reaches the zero chain.
const TARGET_INDEX: u32 = 7;
const NODE_BYTES: usize = 32;
/// Leaf, status, event type, format marker, then the retained siblings.
const ROW_SIBLINGS_OFFSET: usize = 38;

/// Levels 11..15, constant across a shard and served beside the row.
const ADDENDUM_BYTES: usize = (TREE_DEPTH - PATH10_LEVELS) * NODE_BYTES;
/// `[u16 BE version][u64 LE count]` then one `[u64 LE len]` per slot.
const BATCH_FRAME_BYTES: usize = WIRE_SCHEMA_PREFIX_LEN + 8 + 8;

/// bincode 1.3 fixint over a `Poly`: coefficients are bit-packed at the modulus width, so the
/// ring term is bits rather than 8 B per coefficient.
const fn poly_bytes(ring_dim: usize, crt_limbs: usize, coefficient_bits: usize) -> usize {
    (coefficient_bits * ring_dim * crt_limbs).div_ceil(8) + 8 * crt_limbs + 41
}

/// A registered client uploads one seeded fold row plus a session handle; the packing keys
/// went up once, at the handshake.
const fn query_bytes(ring_dim: usize, crt_limbs: usize, coefficient_bits: usize) -> usize {
    4 + (8 + 32 + poly_bytes(ring_dim, crt_limbs, coefficient_bits) + 24) + 4 + 1 + 9
}

/// Variant tag; `a`'s coefficient length, one-modulus vector, q, dim, CRT inverse and NTT flag;
/// the `b` prefix length; the retained count; the empty column vector; `Some(packing_mode)`.
const RESPONSE_HEADER_BYTES: usize = 4 + (8 + 16 + 8 + 8 + 8 + 1) + 8 + 4 + 8 + 5;

/// `a` in full and `b`'s retained prefix, both packed at the wire modulus's width.
const fn response_bytes(ring_dim: usize, retained: usize, coefficient_bits: usize) -> usize {
    RESPONSE_HEADER_BYTES + ((ring_dim + retained) * coefficient_bits).div_ceil(8)
}

fn packed_bits(modulus: u64) -> usize {
    usize::try_from(u64::BITS - (modulus - 1).leading_zeros()).expect("bit width fits usize")
}

fn served_response_bytes(params: &InspireParams) -> usize {
    response_bytes(
        params.ring_dim,
        PATH10_RECORD_BYTES.div_ceil(2),
        packed_bits(WIRE_RESPONSE_MODULUS),
    )
}

fn bc_for(index: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[28..32].copy_from_slice(&index.saturating_add(1).to_be_bytes());
    out
}

fn ppoi_leaf(index: u32) -> WalEntryPayload {
    WalEntryPayload::PpoiListLeafAdded {
        list_key: LIST_KEY,
        list_index: index,
        blinded_commitment: bc_for(index),
        status: 0,
        event_type: raven_railgun_persistence::PpoiEventType::Shield,
        signature: vec![0; 64],
        validated_merkleroot: [0; 32],
    }
}

fn request(route: &str, body: Vec<u8>) -> Request<Body> {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/instance/{INSTANCE}/{route}"))
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header("x-raven-client-id", CLIENT_ID)
        .body(Body::from(body))
        .expect("build request");
    request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        12_345,
    )));
    request
}

/// One PPOI block at the served cell: the path-10 store, the shard it materializes, and the
/// state encoded from that shard with its addenda refreshed against the published database.
fn served_block(params: &InspireParams) -> (InspireServerState, LogicalLeafStore, RlweSecretKey) {
    let encoder = PerListPath10Encoder::new(ENTRIES_PER_SHARD, LIST_KEY).expect("path-10 encoder");
    let mut store = LogicalLeafStore::new();
    for index in 0..LEAVES {
        apply_wal_entry(
            &mut store,
            &ppoi_leaf(index),
            100 + u64::from(index),
            &encoder,
        )
        .expect("append ppoi leaf");
    }
    let database = encoder.materialize_shard(0, &store);
    assert_eq!(
        database.len(),
        ENTRIES_PER_SHARD as usize * PATH10_RECORD_BYTES,
        "one shard of the served cell"
    );
    let (state, secret_key) = setup_state(
        params,
        &database,
        PATH10_RECORD_BYTES,
        InspireVariant::TwoPacking,
    )
    .expect("setup_state at the served cell");
    // Provenance is the published Arc, so the row and the upper siblings the client folds with
    // come from one tree; this is where the commit driver refreshes them.
    store.refresh_committed_addenda(&state.encoded_db, ENTRIES_PER_SHARD);
    assert!(store.committed_addenda_derived_from(&state.encoded_db));
    (state, store, secret_key)
}

/// The handshake a browser client runs once: keys up, handle back.
async fn establish_session(router: &axum::Router, packing_keys_body: Vec<u8>) -> u64 {
    let response = router
        .clone()
        .oneshot(request("session", packing_keys_body))
        .await
        .expect("session dispatch");
    assert_eq!(response.status(), StatusCode::OK, "session establish");
    response
        .headers()
        .get("x-raven-session")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .expect("session response carries a numeric x-raven-session")
}

fn assert_upload_bytes(params: &InspireParams, query: &SeededClientQuery, upload: &[u8]) -> usize {
    let payload = bincode::serialize(query).expect("serialize query").len();
    assert_eq!(
        payload,
        query_bytes(
            params.ring_dim,
            params.crt_moduli.len(),
            packed_bits(params.q)
        ),
        "the uploaded query must match the closed form over the served ring"
    );
    assert_eq!(payload, 15_491, "uploaded query bytes");
    assert_eq!(
        upload.len(),
        WIRE_SCHEMA_PREFIX_LEN + 8 + payload,
        "a batch of one adds the version prefix and bincode's vector length"
    );
    assert_eq!(upload.len(), 15_501, "batch-of-one upload bytes");
    payload
}

/// Split the framed body into the response and the addendum the server appended to its slot,
/// checking every length against the closed form on the way through.
fn split_served_slot<'a>(body: &'a [u8], params: &InspireParams) -> (&'a [u8], &'a [u8]) {
    assert_eq!(
        &body[..WIRE_SCHEMA_PREFIX_LEN],
        &WIRE_SCHEMA_VERSION.to_be_bytes(),
        "served under the current wire schema"
    );
    assert_eq!(
        u64::from_le_bytes(body[2..10].try_into().expect("batch count")),
        1,
        "one slot"
    );
    let slot_len = usize::try_from(u64::from_le_bytes(
        body[10..BATCH_FRAME_BYTES].try_into().expect("slot length"),
    ))
    .expect("slot length fits usize");
    assert_eq!(
        body.len(),
        BATCH_FRAME_BYTES + slot_len,
        "the framed length must account for every served byte"
    );
    assert_eq!(
        slot_len,
        served_response_bytes(params) + ADDENDUM_BYTES,
        "a slot is the served response plus its upper-sibling addendum"
    );
    assert_eq!(slot_len, 10_606, "response plus addendum in one slot");
    let (response_payload, addendum) =
        body[BATCH_FRAME_BYTES..].split_at(slot_len - ADDENDUM_BYTES);
    assert_eq!(response_payload.len(), 10_446, "served response bytes");
    assert_eq!(addendum.len(), ADDENDUM_BYTES, "addendum bytes");
    assert_eq!(addendum.len(), 160, "addendum bytes");
    (response_payload, addendum)
}

fn decode_slot(body: &[u8], response_payload: &[u8], retained: usize) -> ServerResponse {
    let responses: Vec<ServerResponse> =
        read_batch_response_versioned(body).expect("decode the reframed batch body");
    assert_eq!(responses.len(), 1);
    let response = responses.into_iter().next().expect("one response");
    assert_eq!(
        response.ciphertext.modulus(),
        WIRE_RESPONSE_MODULUS,
        "the served response must already be mod-switched"
    );
    assert_eq!(
        response.packed_coefficients,
        Some(u32::try_from(retained).expect("retained fits u32")),
        "the closed form must count the prefix the server actually retained"
    );
    assert_eq!(
        bincode::serialize(&response)
            .expect("re-serialize the decoded response")
            .len(),
        response_payload.len(),
        "the addendum must split off exactly at the codec boundary"
    );
    response
}

/// Levels 0..10 ride in the row and 11..15 in the addendum; together they must be the auth path
/// the tree holds, against the root that block publishes.
fn assert_row_and_addendum_reassemble_the_path(
    row: &[u8],
    addendum: &[u8],
    store: &LogicalLeafStore,
) {
    let leaf = store
        .ppoi_bc_at(&LIST_KEY, TARGET_INDEX)
        .expect("planted leaf");
    let proof = store
        .ppoi_merkle_proof(&LIST_KEY, TARGET_INDEX)
        .expect("oracle proof");
    let list_root = store.ppoi_imt_root(&LIST_KEY).expect("per-list IMT root");

    assert_eq!(&row[..NODE_BYTES], &leaf, "the row carries its own leaf");
    assert_eq!(&row[34..38], &PATH10_MAGIC, "format marker");
    // The row has no room for levels 11..15 and pads instead, which is what the 160 B buy.
    assert!(
        row[ROW_SIBLINGS_OFFSET + PATH10_LEVELS * NODE_BYTES..]
            .iter()
            .all(|byte| *byte == 0),
        "the row must carry no upper siblings, or the addendum is redundant"
    );

    let mut path = [[0u8; 32]; TREE_DEPTH];
    for (level, sibling) in path.iter_mut().enumerate().take(PATH10_LEVELS) {
        let start = ROW_SIBLINGS_OFFSET + level * NODE_BYTES;
        sibling.copy_from_slice(&row[start..start + NODE_BYTES]);
    }
    for (upper, sibling) in path.iter_mut().skip(PATH10_LEVELS).enumerate() {
        let start = upper * NODE_BYTES;
        sibling.copy_from_slice(&addendum[start..start + NODE_BYTES]);
    }
    assert_eq!(
        path, proof.elements,
        "the served row and its addendum must reassemble the auth path the tree holds"
    );
    assert_eq!(
        proof.root, list_root,
        "that path must belong to the list root the block publishes"
    );
    assert_eq!(
        usize::from(proof.indices),
        usize::try_from(TARGET_INDEX).expect("target index fits usize"),
        "the fold directions must be the queried leaf's"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_batch_round_trip_produces_the_published_wire_figure() {
    let started = Instant::now();
    let params = InspireParams::secure_128_d2048();
    let retained = PATH10_RECORD_BYTES.div_ceil(2);
    let (state, store, secret_key) = served_block(&params);
    let setup_elapsed = started.elapsed();

    let crs = Arc::clone(&state.crs);
    let instance_id = InstanceId::new(INSTANCE);
    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    engine
        .add_instance(PirInstance::new(
            instance_id.clone(),
            InstanceRole::Live,
            state,
        ))
        .expect("register instance");
    let served = engine
        .instance(&instance_id)
        .expect("instance just added")
        .current_state();

    let shared_store = Arc::new(parking_lot::Mutex::new(store));
    let mut logical_stores = HashMap::new();
    logical_stores.insert(instance_id, (LIST_KEY, Arc::clone(&shared_store)));
    let app = AppState::new(engine, HttpConfig::demo(TOKEN))
        .expect("app state")
        .with_instance_logical_stores(logical_stores);
    let router = inspire_router(app).expect("router");

    let mut client_session =
        build_client_session((*crs).clone(), secret_key, &params).expect("client session");
    let (_, unregistered) = build_seeded_query(&client_session, served.shard_config(), 0, &params)
        .expect("registration query");
    let packing_keys = unregistered
        .inspiring_packing_keys
        .expect("an unregistered query carries its packing keys");
    let handle = establish_session(
        &router,
        write_versioned(&packing_keys).expect("serialize packing keys"),
    )
    .await;
    client_session
        .install_server_session_handle(ServerSessionHandle(handle))
        .expect("install the server's handle");

    let (client_state, query) = build_seeded_query(
        &client_session,
        served.shard_config(),
        u64::from(TARGET_INDEX),
        &params,
    )
    .expect("target query");
    assert!(
        query.inspiring_packing_keys.is_none(),
        "a registered query must not re-upload its keys, or the UP half is not the served one"
    );
    assert_eq!(query.session_handle, Some(ServerSessionHandle(handle)));
    let upload = write_versioned(&vec![query.clone()]).expect("versioned batch upload");
    let query_payload = assert_upload_bytes(&params, &query, &upload);

    let batch_response = router
        .clone()
        .oneshot(request("batch", upload))
        .await
        .expect("batch dispatch");
    assert_eq!(batch_response.status(), StatusCode::OK, "batch HTTP status");
    let body = batch_response
        .into_body()
        .collect()
        .await
        .expect("batch body")
        .to_bytes()
        .to_vec();

    let (response_payload, addendum) = split_served_slot(&body, &params);
    let round_trip = query_payload + response_payload.len() + addendum.len();
    assert_eq!(
        round_trip,
        query_bytes(
            params.ring_dim,
            params.crt_moduli.len(),
            packed_bits(params.q)
        ) + served_response_bytes(&params)
            + ADDENDUM_BYTES,
        "the published total must be the sum of the three figures this run measured"
    );
    assert_eq!(round_trip, 26_097, "published warm round trip");

    let response = decode_slot(&body, response_payload, retained);
    let row = extract_response(&crs, &client_state, &response, PATH10_RECORD_BYTES)
        .expect("extract the served row");
    assert_eq!(row.len(), PATH10_RECORD_BYTES);
    assert_row_and_addendum_reassemble_the_path(&row, addendum, &shared_store.lock());

    eprintln!(
        "wire_round_trip_bytes: up={query_payload} down={} addendum={} total={round_trip} \
         body={} setup={setup_elapsed:?} wall={:?}",
        response_payload.len(),
        addendum.len(),
        body.len(),
        started.elapsed()
    );
}
