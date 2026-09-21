//! A shim route answers from a store that covers the whole question, or refuses.
//!
//! The routes answer questions whose domain is a whole list: `"Missing"`, an empty
//! blocked-set and a 404 are all claims about absence. A store holding one 65,536-row block
//! of a 358,320-row list can answer none of them, and every such answer is a well-formed
//! 200. These tests hold the refusal in place.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Method, Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::orchestrator::{DataSourceFilter, LEAVES_PER_PPOI_BLOCK};
use raven_railgun_engine::pir_table::PerLeafCommitmentEncoder;
use raven_railgun_engine::{Engine, PirScheme};
use raven_railgun_http::{AppState, HttpConfig};
use raven_railgun_persistence::WalEntryPayload;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use tower::ServiceExt;

const TOKEN: &str = "test-token-padded-long-enough-1234";
const LIST_KEY: [u8; 32] = [0x42; 32];

type SharedStore = Arc<parking_lot::Mutex<LogicalLeafStore>>;

// Serialises AppState::new against the global metrics recorder.
static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug, Default)]
struct StubScheme;

#[derive(Debug, Default)]
struct StubState;

#[derive(Serialize, Deserialize, Debug)]
struct StubQuery;

#[derive(Serialize, Deserialize, Debug)]
struct StubResponse;

impl PirScheme for StubScheme {
    type ServerState = StubState;
    type Query = StubQuery;
    type Response = StubResponse;

    fn respond(
        _state: &Self::ServerState,
        _query: &Self::Query,
    ) -> raven_railgun_core::Result<Self::Response> {
        Err(raven_railgun_core::AdapterError::Scheme(
            "stub respond invoked".to_owned(),
        ))
    }
    fn state_shape(_state: &Self::ServerState) -> raven_railgun_engine::StateShape {
        raven_railgun_engine::StateShape {
            entry_size_bytes: 1,
            rows_per_shard: u64::MAX,
        }
    }
}

/// Canonical BN254 Fr: the high bytes stay clear so the value is under the modulus.
fn fr(seed: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[20] = 0x01;
    out[28..].copy_from_slice(&seed.to_be_bytes());
    out
}

/// Distinct across blocks so a local index cannot be mistaken for a global one.
fn bc_for(global_index: u32) -> [u8; 32] {
    fr(global_index.wrapping_add(0x0100_0000))
}

fn seed_block(block: u32, rows: u32) -> SharedStore {
    let enc = PerLeafCommitmentEncoder::new(32, LEAVES_PER_PPOI_BLOCK, 0).expect("encoder");
    let mut store = LogicalLeafStore::new();
    let base = block * LEAVES_PER_PPOI_BLOCK;
    for local in 0..rows {
        apply_wal_entry(
            &mut store,
            &WalEntryPayload::PpoiListLeafAdded {
                list_key: LIST_KEY,
                list_index: local,
                blinded_commitment: bc_for(base + local),
                // ShieldBlocked on every third row, so the status-header sets are non-trivial.
                status: u8::from((base + local).is_multiple_of(3)),
                event_type: raven_railgun_persistence::PpoiEventType::Shield,
                signature: vec![0; 64],
                validated_merkleroot: [0; 32],
            },
            1_000 + u64::from(base + local),
            &enc,
        )
        .expect("seed ppoi leaf");
    }
    Arc::new(parking_lot::Mutex::new(store))
}

/// A sealed block costs 65,536 Poseidon IMT inserts (measured 32.8 s under `ci-test`), and
/// the coverage predicate cannot be satisfied without one. Paid once per test binary.
fn sealed_block_zero() -> SharedStore {
    static SEALED: OnceLock<SharedStore> = OnceLock::new();
    Arc::clone(SEALED.get_or_init(|| seed_block(0, LEAVES_PER_PPOI_BLOCK)))
}

fn app_state(build: impl FnOnce(AppState<StubScheme>) -> AppState<StubScheme>) -> Router {
    let engine: Engine<StubScheme> = Engine::new();
    let state = {
        let _g = APPSTATE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        AppState::new(engine, HttpConfig::demo(TOKEN)).expect("appstate")
    };
    raven_railgun_http::router(build(state)).expect("router")
}

fn declared(declarations: Vec<(DataSourceFilter, SharedStore)>) -> Router {
    app_state(move |state| state.with_shim_stores(declarations))
}

/// A sealed block 0 plus a live block 1: the smallest wiring the coverage predicate accepts
/// that still spans the 65,536 boundary.
fn two_covered_blocks() -> Router {
    declared(vec![
        (
            DataSourceFilter::PpoiListBlock {
                list_key: LIST_KEY,
                block: 0,
            },
            sealed_block_zero(),
        ),
        (
            DataSourceFilter::PpoiListBlock {
                list_key: LIST_KEY,
                block: 1,
            },
            seed_block(1, 3),
        ),
    ])
}

fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn authed(method: Method, uri: &str, body: Body) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .expect("request");
    // `PeerIpKeyExtractor` requires `ConnectInfo<SocketAddr>`; `oneshot` does not install it.
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    request
}

async fn send(router: &Router, request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let response = router.clone().oneshot(request).await.expect("dispatch");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec();
    (status, bytes)
}

/// The five routes a stock build registers. `bc-prefixes` is behind
/// `prefix-index-channel`, which declares no `default` key, so it is not one of them.
fn stock_requests(list_key_hex: &str, probe_bc: &str) -> Vec<(&'static str, Request<Body>)> {
    vec![
        (
            "pois-per-list",
            authed(
                Method::POST,
                "/v1/poi/pois-per-list",
                Body::from(
                    serde_json::json!({
                        "listKeys": [list_key_hex],
                        "blindedCommitmentDatas": [{ "blindedCommitment": probe_bc }],
                    })
                    .to_string(),
                ),
            ),
        ),
        (
            "merkle-proofs",
            authed(
                Method::POST,
                "/v1/poi/merkle-proofs",
                Body::from(
                    serde_json::json!({
                        "listKey": list_key_hex,
                        "blindedCommitments": [probe_bc],
                    })
                    .to_string(),
                ),
            ),
        ),
        (
            "commit-tree-merkle-proof",
            authed(
                Method::POST,
                "/v1/commit-tree/0/merkle-proof",
                Body::from(serde_json::json!({ "leafIndex": 0 }).to_string()),
            ),
        ),
        (
            "bc-to-idx-map",
            authed(
                Method::GET,
                &format!("/v1/poi/{list_key_hex}/bc-to-idx-map"),
                Body::empty(),
            ),
        ),
        (
            "status-header",
            authed(
                Method::GET,
                &format!("/v1/poi/{list_key_hex}/status-header"),
                Body::empty(),
            ),
        ),
    ]
}

/// The 503 nobody had ever seen: a live probe answers 401 from the auth layer before the
/// handler runs, so the finding had only ever been read out of the source. This carries a
/// valid bearer through the production router against the state the production bootstrap
/// actually produced, and observes it.
#[tokio::test]
async fn every_stock_route_refuses_when_no_store_is_wired() {
    let router = app_state(|state| state);
    let list_key_hex = hex32(&LIST_KEY);
    let probe = hex32(&bc_for(0));
    for (name, request) in stock_requests(&list_key_hex, &probe) {
        let (status, _) = send(&router, request).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{name} must refuse when no store is wired, not answer"
        );
    }
}

/// The trap the card says a builder falls into on the first try, pinned as a live fact:
/// the undeclared single-store setter carries no filter, so a block store's LOCAL indices
/// are served as if they were the list's. Block 2's rows are real; every index is wrong by
/// 131,072 and every BC outside the block reads `"Missing"` at HTTP 200.
#[tokio::test]
async fn an_undeclared_block_store_serves_local_indices_as_if_they_were_global() {
    let block_two = seed_block(2, 4);
    let router = app_state(move |state| state.with_logical_store(Arc::clone(&block_two)));
    let list_key_hex = hex32(&LIST_KEY);

    let (status, body) = send(
        &router,
        authed(
            Method::GET,
            &format!("/v1/poi/{list_key_hex}/bc-to-idx-map"),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("json");
    let entries = parsed["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 4);
    assert_eq!(
        entries[0]["idx"].as_u64(),
        Some(0),
        "the undeclared path serves the block-local index; the row's global index is 131,072"
    );
    assert_eq!(
        entries[0]["bc"].as_str().map(str::to_owned),
        Some(hex32(&bc_for(2 * LEAVES_PER_PPOI_BLOCK))),
        "the row itself is block 2's, so index 0 names a commitment at global index 131,072"
    );

    let (status, body) = send(
        &router,
        authed(
            Method::POST,
            "/v1/poi/pois-per-list",
            Body::from(
                serde_json::json!({
                    "listKeys": [list_key_hex],
                    "blindedCommitmentDatas": [{ "blindedCommitment": hex32(&bc_for(0)) }],
                })
                .to_string(),
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(
        parsed[hex32(&bc_for(0))][&list_key_hex].as_str(),
        Some("Missing"),
        "a block-0 commitment reads Missing off a block-2 store, at 200, with nothing logged"
    );
}

/// The same store, declared. Declaring it is what makes the answer provably wrong and the
/// route refuse: blocks 0 and 1 are held by nobody, so no absence claim over the list holds.
#[tokio::test]
async fn one_block_of_a_multi_block_list_refuses_on_every_stock_route() {
    let router = declared(vec![(
        DataSourceFilter::PpoiListBlock {
            list_key: LIST_KEY,
            block: 2,
        },
        seed_block(2, 4),
    )]);
    let list_key_hex = hex32(&LIST_KEY);
    let probe = hex32(&bc_for(2 * LEAVES_PER_PPOI_BLOCK));
    for (name, request) in stock_requests(&list_key_hex, &probe) {
        let (status, _) = send(&router, request).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{name} must refuse a list no wired store wholly covers, even for a row it holds"
        );
    }
}

/// A hole under a later block: block 0 is short while block 1 exists, so rows between them
/// are held by nobody and the list cannot be answered over.
#[tokio::test]
async fn a_short_block_under_a_later_one_refuses() {
    let router = declared(vec![
        (
            DataSourceFilter::PpoiListBlock {
                list_key: LIST_KEY,
                block: 0,
            },
            seed_block(0, 4),
        ),
        (
            DataSourceFilter::PpoiListBlock {
                list_key: LIST_KEY,
                block: 1,
            },
            seed_block(1, 4),
        ),
    ]);
    let list_key_hex = hex32(&LIST_KEY);
    let probe = hex32(&bc_for(0));
    for (name, request) in stock_requests(&list_key_hex, &probe) {
        let (status, _) = send(&router, request).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{name} must refuse a list with a hole under a later block"
        );
    }
}

/// A commit-tree proof may come only from the store declared for that tree. Without the
/// declaration the route used to serve whatever store it held, and a PPOI store holds no
/// commit tree at all, so the refusal arrived as a 404: "leaf not in the tree".
#[tokio::test]
async fn a_commit_tree_no_store_declares_refuses_rather_than_404s() {
    let router = declared(vec![(
        DataSourceFilter::PpoiListBlock {
            list_key: LIST_KEY,
            block: 0,
        },
        seed_block(0, 4),
    )]);
    let (status, _) = send(
        &router,
        authed(
            Method::POST,
            "/v1/commit-tree/3/merkle-proof",
            Body::from(serde_json::json!({ "leafIndex": 0 }).to_string()),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "an undeclared tree must refuse, not report the leaf absent"
    );
}

/// The frontier block sitting at capacity means a successor block may exist upstream and is
/// wired to nothing. Refused rather than guessed.
#[tokio::test]
async fn a_frontier_block_at_capacity_refuses() {
    let router = declared(vec![(
        DataSourceFilter::PpoiListBlock {
            list_key: LIST_KEY,
            block: 0,
        },
        sealed_block_zero(),
    )]);
    let list_key_hex = hex32(&LIST_KEY);
    let probe = hex32(&bc_for(0));
    for (name, request) in stock_requests(&list_key_hex, &probe) {
        let (status, _) = send(&router, request).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{name} must refuse while the last wired block is full"
        );
    }
}

/// The positive case, across a sealed block and a live one: every served index is the
/// GLOBAL index, and the row past 65,535 proves the composition rather than a coincidence
/// of a single block's numbering.
#[tokio::test]
async fn covered_blocks_serve_global_indices_past_the_block_boundary() {
    let router = two_covered_blocks();
    let list_key_hex = hex32(&LIST_KEY);

    let (status, body) = send(
        &router,
        authed(
            Method::GET,
            &format!("/v1/poi/{list_key_hex}/bc-to-idx-map"),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("json");
    let entries = parsed["entries"].as_array().expect("entries");
    assert_eq!(
        entries.len(),
        LEAVES_PER_PPOI_BLOCK as usize + 3,
        "the map must span every covered block"
    );

    for global in [
        0u32,
        LEAVES_PER_PPOI_BLOCK - 1,
        LEAVES_PER_PPOI_BLOCK,
        LEAVES_PER_PPOI_BLOCK + 2,
    ] {
        let entry = &entries[global as usize];
        assert_eq!(
            entry["idx"].as_u64(),
            Some(u64::from(global)),
            "row {global} must carry its global index"
        );
        assert_eq!(
            entry["bc"].as_str().map(str::to_owned),
            Some(hex32(&bc_for(global))),
            "row {global} must carry the commitment that lives at that global index"
        );
    }

    // The round trip: a commitment from the block past the boundary resolves to an index at
    // or above 65,536.
    let past_boundary = bc_for(LEAVES_PER_PPOI_BLOCK + 1);
    let resolved = entries
        .iter()
        .find(|entry| entry["bc"].as_str() == Some(&hex32(&past_boundary)))
        .and_then(|entry| entry["idx"].as_u64())
        .expect("commitment past the boundary must appear in the map");
    assert!(
        resolved >= u64::from(LEAVES_PER_PPOI_BLOCK),
        "expected a global index at or past the block boundary, got {resolved}"
    );
}

/// Over a covered list, `"Missing"` becomes a claim the coverage proof backs: it is served
/// for a commitment in no block and never for one the blocks hold.
#[tokio::test]
async fn missing_is_served_only_for_a_commitment_no_covered_block_holds() {
    let router = two_covered_blocks();
    let list_key_hex = hex32(&LIST_KEY);
    let past_boundary = bc_for(LEAVES_PER_PPOI_BLOCK + 1);
    let absent = fr(0xDEAD_BEEF);

    let (status, body) = send(
        &router,
        authed(
            Method::POST,
            "/v1/poi/pois-per-list",
            Body::from(
                serde_json::json!({
                    "listKeys": [list_key_hex],
                    "blindedCommitmentDatas": [
                        { "blindedCommitment": hex32(&bc_for(0)) },
                        { "blindedCommitment": hex32(&past_boundary) },
                        { "blindedCommitment": hex32(&absent) },
                    ],
                })
                .to_string(),
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("json");
    for bc in [bc_for(0), past_boundary] {
        assert_ne!(
            parsed[hex32(&bc)][&list_key_hex].as_str(),
            Some("Missing"),
            "a covered commitment must not read Missing"
        );
    }
    assert_eq!(
        parsed[hex32(&absent)][&list_key_hex].as_str(),
        Some("Missing"),
        "a commitment in no covered block is absent from the list"
    );
}

/// A merkle proof comes from the block that holds the row, and the block IMT is the tree
/// upstream takes `validatedMerkleroot` over, so the proof is against that block's root.
#[tokio::test]
async fn a_merkle_proof_past_the_boundary_comes_from_the_block_that_holds_the_row() {
    let block_one = seed_block(1, 3);
    let router = declared(vec![
        (
            DataSourceFilter::PpoiListBlock {
                list_key: LIST_KEY,
                block: 0,
            },
            sealed_block_zero(),
        ),
        (
            DataSourceFilter::PpoiListBlock {
                list_key: LIST_KEY,
                block: 1,
            },
            Arc::clone(&block_one),
        ),
    ]);
    let list_key_hex = hex32(&LIST_KEY);
    let past_boundary = bc_for(LEAVES_PER_PPOI_BLOCK + 1);

    let (status, body) = send(
        &router,
        authed(
            Method::POST,
            "/v1/poi/merkle-proofs",
            Body::from(
                serde_json::json!({
                    "listKey": list_key_hex,
                    "blindedCommitments": [hex32(&past_boundary)],
                })
                .to_string(),
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("json");
    let served = &parsed[0];
    assert_eq!(
        served["leaf"].as_str(),
        Some(hex32(&past_boundary).as_str())
    );

    let expected = block_one
        .lock()
        .ppoi_merkle_proof(&LIST_KEY, 1)
        .expect("block-local proof");
    assert_eq!(
        served["root"].as_str().map(str::to_owned),
        Some(hex32(&expected.root)),
        "the proof must fold to the holding block's root, not to another block's"
    );
    let elements = served["elements"].as_array().expect("elements");
    assert_eq!(elements.len(), 16);
    for (level, (got, want)) in elements.iter().zip(expected.elements.iter()).enumerate() {
        assert_eq!(
            got.as_str().map(str::to_owned),
            Some(hex32(want)),
            "sibling at level {level} must be the holding block's sibling"
        );
    }

    // A commitment the covered blocks do not hold is absent, not unavailable.
    let (status, _) = send(
        &router,
        authed(
            Method::POST,
            "/v1/poi/merkle-proofs",
            Body::from(
                serde_json::json!({
                    "listKey": list_key_hex,
                    "blindedCommitments": [hex32(&fr(0xDEAD_BEEF))],
                })
                .to_string(),
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The status-header sets are defined over the whole list, so they must span every covered
/// block rather than stopping at the first.
#[tokio::test]
async fn status_header_sets_span_every_covered_block() {
    let router = two_covered_blocks();
    let list_key_hex = hex32(&LIST_KEY);
    let (status, body) = send(
        &router,
        authed(
            Method::GET,
            &format!("/v1/poi/{list_key_hex}/status-header"),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("json");
    let blocked: Vec<String> = parsed["blockedBcs"]
        .as_array()
        .expect("blockedBcs")
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    // Seeded ShieldBlocked on every third global index; 65,538 is the first past the boundary.
    assert!(
        blocked.contains(&hex32(&bc_for(0))),
        "a blocked row in the sealed block must be in the set"
    );
    assert!(
        blocked.contains(&hex32(&bc_for(65_538))),
        "a blocked row past the block boundary must be in the set too"
    );
}

/// The card's gate names six blocks. Five of them must be sealed to satisfy the coverage
/// predicate, and a sealed block costs 65,536 Poseidon IMT inserts: 32.8 s each under
/// `ci-test`, measured, so ~2.8 minutes of pure seeding. The two-block tests above carry
/// the same properties including an index past 65,536.
///
/// Trigger: run this by hand before the wallet PR is handed to Railgun, and whenever
/// `LEAVES_PER_PPOI_BLOCK`, the router localization or the coverage predicate changes.
#[tokio::test]
#[ignore = "seeds five sealed blocks: 5 x 65,536 Poseidon IMT inserts, ~165 s measured under \
            ci-test. Trigger: before the wallet PR is handed to Railgun, and whenever \
            LEAVES_PER_PPOI_BLOCK, the router localization or the coverage predicate changes."]
async fn six_covered_blocks_round_trip_one_commitment_from_each() {
    let mut declarations: Vec<(DataSourceFilter, SharedStore)> = Vec::with_capacity(6);
    for block in 0..6u32 {
        let rows = if block == 5 {
            17
        } else {
            LEAVES_PER_PPOI_BLOCK
        };
        declarations.push((
            DataSourceFilter::PpoiListBlock {
                list_key: LIST_KEY,
                block,
            },
            seed_block(block, rows),
        ));
    }
    let router = declared(declarations);
    let list_key_hex = hex32(&LIST_KEY);

    let (status, body) = send(
        &router,
        authed(
            Method::GET,
            &format!("/v1/poi/{list_key_hex}/bc-to-idx-map"),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("json");
    let entries = parsed["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 5 * LEAVES_PER_PPOI_BLOCK as usize + 17);

    for block in 0..6u32 {
        let global = block * LEAVES_PER_PPOI_BLOCK + 3;
        let entry = entries
            .iter()
            .find(|entry| entry["bc"].as_str() == Some(&hex32(&bc_for(global))))
            .expect("one commitment from each block must appear");
        assert_eq!(
            entry["idx"].as_u64(),
            Some(u64::from(global)),
            "block {block}'s commitment must carry its global index"
        );
    }
}
