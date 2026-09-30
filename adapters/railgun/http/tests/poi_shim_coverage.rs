//! A shim route answers from a store that covers the whole question, or refuses.
//!
//! The index route answers a question whose domain is a whole list: the end of the index is a
//! claim about absence, which a client reads as "Missing". A store holding one 65,536-row block
//! of a 358,320-row list cannot make it, and its answer would be a well-formed 200. These tests
//! hold the refusal in place.
//!
//! A gap-free prefix is not enough on its own: the frontier block has to be CURRENT, which only
//! upstream's own recent row count can say. A cold sync or a restart leaves the frontier short
//! of upstream with every block below it sealed.

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
use raven_railgun_http::poi_shim::BC_INDEX_PREFIX_BYTES;
use raven_railgun_http::shim_store::UPSTREAM_TIP_MAX_AGE_SECS;
use raven_railgun_http::status::{MirrorFeedState, MirrorFeedView};
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

/// Distinct across blocks so a local index cannot be mistaken for a global one, and in the
/// first six bytes too: the prefix channel publishes only those, and identical prefixes would
/// let a segment serve the wrong rows and still match.
fn bc_for(global_index: u32) -> [u8; 32] {
    let mut bc = fr(global_index.wrapping_add(0x0100_0000));
    bc[2..6].copy_from_slice(&global_index.to_be_bytes());
    bc
}

fn seed_block(block: u32, rows: u32) -> SharedStore {
    seed_list_block(LIST_KEY, block, rows)
}

/// One seeded run: each tree node is hashed once, not once per row, so a sealed block costs
/// about 65,536 Poseidon hashes instead of the 1,048,576 a row-by-row apply pays.
fn seed_list_block(list_key: [u8; 32], block: u32, rows: u32) -> SharedStore {
    let enc = PerLeafCommitmentEncoder::new(32, LEAVES_PER_PPOI_BLOCK, 0).expect("encoder");
    let base = block * LEAVES_PER_PPOI_BLOCK;
    let run: Vec<(WalEntryPayload, u64)> = (0..rows)
        .map(|local| {
            (
                WalEntryPayload::PpoiListLeafAdded {
                    list_key,
                    list_index: local,
                    blinded_commitment: bc_for(base + local),
                    event_type: raven_railgun_persistence::PpoiEventType::Shield,
                    validated_merkleroot: [0; 32],
                },
                1_000 + u64::from(base + local),
            )
        })
        .collect();
    let mut store = LogicalLeafStore::new();
    store.seed_leaf_run(&run, &enc).expect("seed ppoi rows");
    mark_published(&mut store);
    Arc::new(parking_lot::Mutex::new(store))
}

/// Record every row `store` holds as served, as the commit driver does once it publishes.
fn mark_published(store: &mut LogicalLeafStore) {
    let table = Arc::new(raven_inspire::EncodedDatabase {
        shards: Vec::new(),
        config: raven_inspire::params::ShardConfig {
            shard_size_bytes: 0,
            entry_size_bytes: 0,
            total_entries: 0,
        },
    });
    store.refresh_committed_addenda(&table, 0);
}

/// The coverage predicate cannot be satisfied past one block without a sealed one. Shared by
/// the tests of one process; nextest runs each test in its own, so each pays it once.
fn sealed_block_zero() -> SharedStore {
    static SEALED: OnceLock<SharedStore> = OnceLock::new();
    Arc::clone(SEALED.get_or_init(|| seed_block(0, LEAVES_PER_PPOI_BLOCK)))
}

fn app_state(build: impl FnOnce(AppState<StubScheme>) -> AppState<StubScheme>) -> Router {
    app_state_with(HttpConfig::demo(TOKEN), build)
}

fn app_state_with(
    config: HttpConfig,
    build: impl FnOnce(AppState<StubScheme>) -> AppState<StubScheme>,
) -> Router {
    let engine: Engine<StubScheme> = Engine::new();
    let state = {
        let _g = APPSTATE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        AppState::new(engine, config).expect("appstate")
    };
    raven_railgun_http::router(build(state)).expect("router")
}

/// The list's mirror feed as readiness reports it: `upstream_rows` is what upstream's last
/// answer counted, and `None` when that answer was a full page.
fn feed(upstream_rows: Option<u64>, seconds_since_answer: u64) -> MirrorFeedView {
    feed_for(&LIST_KEY, upstream_rows, seconds_since_answer)
}

fn feed_for(
    list_key: &[u8; 32],
    upstream_rows: Option<u64>,
    seconds_since_answer: u64,
) -> MirrorFeedView {
    MirrorFeedView {
        list_key: hex32(list_key),
        state: MirrorFeedState::Syncing,
        rows_held: 0,
        upstream_rows,
        upstream_rows_seen: upstream_rows,
        next_index: upstream_rows.unwrap_or(0),
        consecutive_failures: 0,
        last_failure: None,
        seconds_since_answer: Some(seconds_since_answer),
    }
}

/// Upstream counted `rows` for the list just now.
fn counted(rows: u64) -> MirrorFeedView {
    feed(Some(rows), 0)
}

fn declared_with(
    declarations: Vec<(DataSourceFilter, SharedStore)>,
    upstream: Option<MirrorFeedView>,
) -> Router {
    app_state(move |state| {
        let state = state.with_shim_stores(declarations);
        match upstream {
            Some(view) => state.with_mirror_feeds(Arc::new(move || vec![view.clone()])),
            None => state,
        }
    })
}

/// Upstream counts zero rows, so the currency rule can never be the one that refuses: a 503
/// here is the structural rule under test.
fn declared(declarations: Vec<(DataSourceFilter, SharedStore)>) -> Router {
    declared_with(declarations, Some(counted(0)))
}

/// A sealed block 0 plus `frontier` as block 1.
fn two_block_declarations(frontier: SharedStore) -> Vec<(DataSourceFilter, SharedStore)> {
    vec![
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
            frontier,
        ),
    ]
}

/// A sealed block 0 plus a live block 1, at upstream's count: the smallest wiring the coverage
/// predicate accepts that still spans the 65,536 boundary. Block 1 is handed back so a test can
/// grow the frontier under a sealed block and watch the sealed bytes not move.
fn two_covered_blocks_with_frontier() -> (Router, SharedStore) {
    let frontier = seed_block(1, 3);
    let router = declared_with(
        two_block_declarations(Arc::clone(&frontier)),
        Some(counted(u64::from(LEAVES_PER_PPOI_BLOCK) + 3)),
    );
    (router, frontier)
}

/// Append one row to a frontier block, so a test can move it while a sealed block below
/// stays put.
fn append_frontier_row(store: &SharedStore, local: u32) {
    let enc = PerLeafCommitmentEncoder::new(32, LEAVES_PER_PPOI_BLOCK, 0).expect("encoder");
    let global = LEAVES_PER_PPOI_BLOCK + local;
    let mut store = store.lock();
    apply_wal_entry(
        &mut store,
        &WalEntryPayload::PpoiListLeafAdded {
            list_key: LIST_KEY,
            list_index: local,
            blinded_commitment: bc_for(global),
            event_type: raven_railgun_persistence::PpoiEventType::Shield,
            validated_merkleroot: [0; 32],
        },
        1_000 + u64::from(global),
        &enc,
    )
    .expect("append frontier row");
    mark_published(&mut store);
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

/// Every route a build registers.
fn stock_requests(list_key_hex: &str) -> Vec<(&'static str, Request<Body>)> {
    vec![
        (
            "commit-tree-merkle-proof",
            authed(
                Method::POST,
                "/v1/commit-tree/0/merkle-proof",
                Body::from(serde_json::json!({ "leafIndex": 0 }).to_string()),
            ),
        ),
        (
            "bc-prefixes",
            authed(
                Method::GET,
                &format!("/v1/poi/{list_key_hex}/bc-prefixes"),
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
    for (name, request) in stock_requests(&list_key_hex) {
        let (status, _) = send(&router, request).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{name} must refuse when no store is wired, not answer"
        );
    }
}

/// One block of a list, declared as what it is: blocks 0 and 1 are held by nobody, so no
/// absence claim over the list holds.
#[tokio::test]
async fn one_block_of_a_multi_block_list_refuses_on_every_stock_route() {
    let router = declared(vec![(
        DataSourceFilter::PpoiListBlock {
            list_key: LIST_KEY,
            block: 2,
        },
        seed_block(2, 4),
    )]);
    for (name, request) in stock_requests(&hex32(&LIST_KEY)) {
        let (status, _) = send(&router, request).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{name} must refuse a list no wired store wholly covers"
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
    for (name, request) in stock_requests(&list_key_hex) {
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
    for (name, request) in stock_requests(&list_key_hex) {
        let (status, _) = send(&router, request).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{name} must refuse while the last wired block is full"
        );
    }
}

/// Every stock list route over `router`, in order. The commit-tree route is left out: no list
/// coverage decides it.
async fn list_route_statuses(router: &Router) -> Vec<(&'static str, StatusCode)> {
    list_route_statuses_for(router, &LIST_KEY).await
}

async fn list_route_statuses_for(
    router: &Router,
    list_key: &[u8; 32],
) -> Vec<(&'static str, StatusCode)> {
    let mut out = Vec::new();
    for (name, request) in stock_requests(&hex32(list_key)) {
        if name == "commit-tree-merkle-proof" {
            continue;
        }
        out.push((name, send(router, request).await.0));
    }
    out
}

/// A contiguous prefix whose frontier is short of full is still no proof the list ends there:
/// a cold sync holds exactly this shape while upstream holds thousands more rows. Only
/// upstream's own count, recent and no larger than what is held, lets a route answer.
#[tokio::test]
async fn a_short_frontier_is_answered_only_while_upstream_recently_counted_no_more_rows() {
    let declarations = two_block_declarations(seed_block(1, 3));
    let held = u64::from(LEAVES_PER_PPOI_BLOCK) + 3;

    for (case, upstream) in [
        ("no mirror feed at all", None),
        ("a last answer that was a full page", Some(feed(None, 0))),
        ("upstream counting one row more", Some(counted(held + 1))),
        (
            "a count older than the bound",
            Some(feed(Some(held), UPSTREAM_TIP_MAX_AGE_SECS + 1)),
        ),
    ] {
        let router = declared_with(declarations.clone(), upstream);
        for (route, status) in list_route_statuses(&router).await {
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "{route} answered {status} with {case}"
            );
        }
    }

    for (case, upstream) in [
        ("upstream counting what is held", Some(counted(held))),
        (
            "a count exactly at the bound",
            Some(feed(Some(held), UPSTREAM_TIP_MAX_AGE_SECS)),
        ),
        (
            "rows applied since upstream counted",
            Some(counted(held - 1)),
        ),
    ] {
        let router = declared_with(declarations.clone(), upstream);
        for (route, status) in list_route_statuses(&router).await {
            assert_eq!(status, StatusCode::OK, "{route} refused with {case}");
        }
    }
}

/// The zero-row hole, one block up: every block below the frontier sealed and the frontier
/// itself empty, which is what a cold sync looks like the moment a block seals.
#[tokio::test]
async fn an_empty_frontier_over_sealed_blocks_is_refused_until_upstream_counts_it() {
    let declarations = two_block_declarations(seed_block(1, 0));

    let unanchored = declared_with(declarations.clone(), None);
    for (route, status) in list_route_statuses(&unanchored).await {
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{route}");
    }

    // An index that ended at the local rows would read as "Missing" for every row upstream
    // holds past them.
    let counted_behind = declared_with(
        declarations.clone(),
        Some(counted(u64::from(LEAVES_PER_PPOI_BLOCK) + 33_000)),
    );
    for (route, status) in list_route_statuses(&counted_behind).await {
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{route} answered while upstream holds more rows than the local ones"
        );
    }

    let at_tip = declared_with(
        declarations,
        Some(counted(u64::from(LEAVES_PER_PPOI_BLOCK))),
    );
    for (route, status) in list_route_statuses(&at_tip).await {
        assert_eq!(status, StatusCode::OK, "{route}");
    }
}

/// The next block declared before the current one fills sits empty past upstream's count, so it
/// holds nothing the list has and the routes answer over it. A row in a block past an empty one
/// is a hole, and still refuses.
#[tokio::test]
async fn a_block_declared_ahead_of_the_list_is_answered_over_and_a_row_past_it_is_not() {
    let blocks = |rows: [u32; 3]| -> Vec<(DataSourceFilter, SharedStore)> {
        (0u32..)
            .zip(rows)
            .map(|(block, rows)| {
                (
                    DataSourceFilter::PpoiListBlock {
                        list_key: LIST_KEY,
                        block,
                    },
                    seed_block(block, rows),
                )
            })
            .collect()
    };
    let ahead = blocks([4, 0, 0]);

    let at_tip = declared_with(ahead.clone(), Some(counted(4)));
    for (route, status) in list_route_statuses(&at_tip).await {
        assert_eq!(
            status,
            StatusCode::OK,
            "{route} refused over a block declared ahead of the list"
        );
    }
    // The index ends at row 4, which is what a client reads as "Missing" for the next row.
    let (status, body) = send(
        &at_tip,
        authed(
            Method::GET,
            &format!("/v1/poi/{}/bc-prefixes", hex32(&LIST_KEY)),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.len(), 4 * BC_INDEX_PREFIX_BYTES);

    let behind = declared_with(ahead, Some(counted(5)));
    for (route, status) in list_route_statuses(&behind).await {
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{route} answered with upstream a row past the frontier"
        );
    }

    let holed = declared(blocks([4, 0, 1]));
    for (route, status) in list_route_statuses(&holed).await {
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{route} answered over an empty block under one holding a row"
        );
    }
}

/// Each list is answered on its own upstream count: a count taken for one list says nothing about
/// where another ends, so a list with no current count of its own refuses beside one that has.
#[tokio::test]
async fn each_list_is_answered_only_on_its_own_upstream_count() {
    const OTHER_LIST: [u8; 32] = [0x43; 32];
    let declarations: Vec<(DataSourceFilter, SharedStore)> = [LIST_KEY, OTHER_LIST]
        .into_iter()
        .map(|list_key| {
            (
                DataSourceFilter::PpoiListBlock { list_key, block: 0 },
                seed_list_block(list_key, 0, 4),
            )
        })
        .collect();
    for (case, feeds) in [
        (
            "only the first list fed",
            vec![feed_for(&LIST_KEY, Some(4), 0)],
        ),
        (
            "the other list listed first, a row ahead of its store",
            vec![
                feed_for(&OTHER_LIST, Some(5), 0),
                feed_for(&LIST_KEY, Some(4), 0),
            ],
        ),
    ] {
        let declared = declarations.clone();
        let router = app_state(move |state| {
            state
                .with_shim_stores(declared)
                .with_mirror_feeds(Arc::new(move || feeds.clone()))
        });
        for (route, status) in list_route_statuses_for(&router, &LIST_KEY).await {
            assert_eq!(
                status,
                StatusCode::OK,
                "{route} on the counted list, {case}"
            );
        }
        for (route, status) in list_route_statuses_for(&router, &OTHER_LIST).await {
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "{route} on the other list answered on a count not its own, {case}"
            );
        }
    }
}

mod index_channel {
    use super::{
        authed, bc_for, counted, declared_with, hex32, seed_block,
        two_covered_blocks_with_frontier, Body, BodyExt, DataSourceFilter, HttpConfig, Method,
        ServiceExt, SharedStore, StatusCode, LEAVES_PER_PPOI_BLOCK, LIST_KEY, TOKEN,
    };
    use raven_railgun_http::poi_shim::{BC_INDEX_PREFIX_BYTES, BC_INDEX_SEGMENT_MAX_BYTES};
    use std::collections::BTreeMap;

    const SEALED_ROWS: u32 = LEAVES_PER_PPOI_BLOCK;
    const FRONTIER_ROWS: u32 = 3;
    const TOTAL_ROWS: u32 = SEALED_ROWS + FRONTIER_ROWS;

    type Headers = BTreeMap<String, String>;

    /// Every response header, so a test can assert what a segment does NOT carry.
    async fn segment(router: &axum::Router, query: &str) -> (StatusCode, Vec<u8>, Headers) {
        let uri = format!("/v1/poi/{}/bc-prefixes{query}", hex32(&LIST_KEY));
        let response = router
            .clone()
            .oneshot(authed(Method::GET, &uri, Body::empty()))
            .await
            .expect("dispatch");
        let status = response.status();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    value.to_str().expect("ascii header").to_owned(),
                )
            })
            .collect();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes()
            .to_vec();
        (status, bytes, headers)
    }

    fn cursor(headers: &Headers, name: &str) -> u32 {
        headers
            .get(name)
            .unwrap_or_else(|| panic!("segment is missing {name}: {headers:?}"))
            .parse()
            .expect("cursor is an integer")
    }

    /// A client's walk: a segment that ends on its block boundary is sealed, and the first
    /// one that does not is the frontier, which is the only one naming the list's total.
    async fn walk(router: &axum::Router) -> Vec<(Vec<u8>, Headers)> {
        let mut since = 0u32;
        let mut segments = Vec::new();
        loop {
            let (status, body, headers) = segment(router, &format!("?since={since}")).await;
            assert_eq!(status, StatusCode::OK);
            let next = cursor(&headers, "x-raven-index-next");
            let block_end = (since / LEAVES_PER_PPOI_BLOCK + 1) * LEAVES_PER_PPOI_BLOCK;
            let sealed = next == block_end;
            segments.push((body, headers));
            if !sealed {
                return segments;
            }
            since = next;
        }
    }

    fn prefix_of(global_index: u32) -> Vec<u8> {
        bc_for(global_index)
            .into_iter()
            .take(BC_INDEX_PREFIX_BYTES)
            .collect()
    }

    fn row(body: &[u8], position: usize) -> Vec<u8> {
        body[position * BC_INDEX_PREFIX_BYTES..(position + 1) * BC_INDEX_PREFIX_BYTES].to_vec()
    }

    /// One response never spans more than one block, and `?since` walks the rest. Both
    /// halves are asserted on content, not only on length: a body of the right size whose
    /// rows are renumbered is the failure that matters, because ordinal position in this
    /// channel IS the global index a client then queries with.
    #[tokio::test]
    async fn a_response_stops_at_the_block_boundary_and_since_resumes_past_it() {
        let (router, _frontier) = two_covered_blocks_with_frontier();

        let (status, head, headers) = segment(&router, "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            head.len(),
            SEALED_ROWS as usize * BC_INDEX_PREFIX_BYTES,
            "a headless request must stop at the first block boundary, not serve the list"
        );
        assert_eq!(head.len(), BC_INDEX_SEGMENT_MAX_BYTES);
        assert_eq!(headers["x-raven-index-base"], "0");
        assert_eq!(headers["x-raven-index-next"], SEALED_ROWS.to_string());
        assert_eq!(row(&head, 0), prefix_of(0));
        assert_eq!(
            row(&head, SEALED_ROWS as usize - 1),
            prefix_of(SEALED_ROWS - 1)
        );

        let (status, tail, headers) = segment(&router, &format!("?since={SEALED_ROWS}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(tail.len(), FRONTIER_ROWS as usize * BC_INDEX_PREFIX_BYTES);
        assert_eq!(headers["x-raven-index-base"], SEALED_ROWS.to_string());
        assert_eq!(headers["x-raven-index-next"], TOTAL_ROWS.to_string());
        assert_eq!(headers["x-raven-index-total"], TOTAL_ROWS.to_string());
        assert_eq!(
            row(&tail, 0),
            prefix_of(SEALED_ROWS),
            "the tail must start at the global index the caller asked for"
        );
        assert_eq!(row(&tail, 2), prefix_of(SEALED_ROWS + 2));

        assert_eq!(
            head.len() + tail.len(),
            TOTAL_ROWS as usize * BC_INDEX_PREFIX_BYTES,
            "the walk must reconstruct the whole channel"
        );
        assert_eq!(
            walk(&router).await.len(),
            2,
            "65,539 rows is two blocks, so two responses"
        );
    }

    /// A sealed segment is served `immutable`, so any cache may replay it, headers and all,
    /// for a year. Everything it carries therefore has to survive the frontier growing: the
    /// body, and every header too. A list-wide total on it would be replayed stale against
    /// a fresh frontier, and a client comparing the two would refuse every later walk.
    #[tokio::test]
    async fn a_sealed_segment_is_identical_after_the_frontier_grows() {
        let (router, frontier) = two_covered_blocks_with_frontier();
        let (_, sealed_before, headers_before) = segment(&router, "").await;
        assert!(
            headers_before["cache-control"].contains("immutable"),
            "a sealed segment must not be marked revalidate-on-use: {}",
            headers_before["cache-control"]
        );
        for list_wide in [
            "x-raven-index-total",
            "x-raven-index-epoch",
            "last-modified",
        ] {
            assert!(
                !headers_before.contains_key(list_wide),
                "an immutable segment must not carry the list-wide {list_wide}: {headers_before:?}"
            );
        }

        let (_, _, tail_before) = segment(&router, &format!("?since={SEALED_ROWS}")).await;
        assert!(
            !tail_before["cache-control"].contains("immutable"),
            "the frontier block still grows, so its segment is never immutable"
        );

        super::append_frontier_row(&frontier, FRONTIER_ROWS);

        let (_, sealed_after, headers_after) = segment(&router, "").await;
        assert_eq!(
            sealed_before, sealed_after,
            "a sealed segment's bytes must not move when a later block grows"
        );
        assert_eq!(
            headers_before, headers_after,
            "nor may any header a cache would replay with those bytes"
        );

        let (_, _, tail_after) = segment(&router, &format!("?since={SEALED_ROWS}")).await;
        assert_eq!(
            tail_after["x-raven-index-total"],
            (TOTAL_ROWS + 1).to_string(),
            "the growth has to be visible somewhere, or this test proves nothing"
        );
        assert_ne!(
            tail_before["etag"], tail_after["etag"],
            "the frontier segment did change and must not serve a stale digest"
        );
    }

    /// A single short block 0 at upstream's count, with its store handed back so a test can
    /// grow it. Cheap: no sealed block.
    fn one_short_block(rows: u32) -> (axum::Router, SharedStore) {
        let block_zero = seed_block(0, rows);
        let router = declared_with(
            vec![(
                DataSourceFilter::PpoiListBlock {
                    list_key: LIST_KEY,
                    block: 0,
                },
                std::sync::Arc::clone(&block_zero),
            )],
            Some(counted(u64::from(rows))),
        );
        (router, block_zero)
    }

    /// `since` at the frontier is a caught-up poll. Past it the caller holds rows this epoch
    /// does not, which is a rollback to report rather than an empty body to absorb, and the
    /// refusal still carries the cursor headers that say where this node's list ends.
    #[tokio::test]
    async fn a_refusal_past_the_frontier_still_names_where_the_list_ends() {
        let (router, _block_zero) = one_short_block(4);
        let (status, body, frontier) = segment(&router, "?since=4").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.is_empty());
        assert_eq!(cursor(&frontier, "x-raven-index-next"), 4);
        assert_eq!(cursor(&frontier, "x-raven-index-total"), 4);

        let (status, _, refused) = segment(&router, "?since=5").await;
        assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
        for name in ["x-raven-index-total", "x-raven-index-epoch"] {
            assert_eq!(
                refused.get(name),
                frontier.get(name),
                "a refusal past the frontier must carry the frontier's {name}: {refused:?}"
            );
        }
        assert_eq!(cursor(&refused, "x-raven-index-total"), 4);
    }

    /// A browser hands a cross-origin script `null` for any response header CORS does not
    /// expose, and the SDK's walk refuses a segment without its cursor. Checked on the
    /// frontier, the one segment carrying every cursor header, through the production router.
    #[tokio::test]
    async fn a_cross_origin_reader_can_see_every_cursor_header() {
        const ORIGIN: &str = "https://wallet.example.com";
        let mut config = HttpConfig::demo(TOKEN);
        config.cors_allowed_origins = vec![ORIGIN.to_owned()];
        let block_zero = seed_block(0, 4);
        let upstream = super::feed(Some(4), 0);
        let router = super::app_state_with(config, move |state| {
            state
                .with_shim_stores(vec![(
                    DataSourceFilter::PpoiListBlock {
                        list_key: LIST_KEY,
                        block: 0,
                    },
                    block_zero,
                )])
                .with_mirror_feeds(std::sync::Arc::new(move || vec![upstream.clone()]))
        });

        let mut request = authed(
            Method::GET,
            &format!("/v1/poi/{}/bc-prefixes", hex32(&LIST_KEY)),
            Body::empty(),
        );
        request
            .headers_mut()
            .insert("origin", ORIGIN.parse().expect("origin"));
        let response = router.oneshot(request).await.expect("dispatch");
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(
            headers
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some(ORIGIN)
        );
        let exposed: Vec<String> = headers
            .get_all("access-control-expose-headers")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(|name| name.trim().to_ascii_lowercase())
            .collect();
        let served: Vec<&str> = headers
            .keys()
            .map(axum::http::HeaderName::as_str)
            .filter(|name| name.starts_with("x-raven-"))
            .collect();
        for cursor_header in [
            "x-raven-index-base",
            "x-raven-index-next",
            "x-raven-index-total",
            "x-raven-index-epoch",
        ] {
            assert!(
                served.contains(&cursor_header),
                "the frontier must carry {cursor_header}, or this test proves nothing"
            );
        }
        for name in served {
            assert!(
                exposed.iter().any(|e| e == name),
                "{name} is served but not exposed, so a browser reads it as null: {exposed:?}"
            );
        }
    }

    /// Six blocks: five sealed under a short sixth, the shape of the list itself. The two-block
    /// tests carry the same properties per push, including an index past 65,536.
    ///
    /// Trigger: run this by hand before the wallet PR is handed to Railgun, and whenever
    /// `LEAVES_PER_PPOI_BLOCK`, the router localization or the coverage predicate changes.
    #[tokio::test]
    #[ignore = "seeds five sealed blocks, 8.3 s measured under ci-test. Trigger: before the wallet \
                PR is handed to Railgun, and whenever LEAVES_PER_PPOI_BLOCK, the router \
                localization or the coverage predicate changes."]
    async fn six_covered_blocks_round_trip_one_commitment_from_each() {
        let declarations: Vec<(DataSourceFilter, SharedStore)> = (0..6u32)
            .map(|block| {
                let rows = if block == 5 {
                    17
                } else {
                    LEAVES_PER_PPOI_BLOCK
                };
                (
                    DataSourceFilter::PpoiListBlock {
                        list_key: LIST_KEY,
                        block,
                    },
                    seed_block(block, rows),
                )
            })
            .collect();
        let held = 5 * LEAVES_PER_PPOI_BLOCK + 17;

        // Five sealed blocks under a short sixth is the shape a cold sync passes through; without
        // upstream's count it is no evidence the list ends there.
        let unanchored = declared_with(declarations.clone(), None);
        let (status, _, _) = segment(&unanchored, "").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

        let router = declared_with(declarations, Some(counted(u64::from(held))));
        let segments = walk(&router).await;
        assert_eq!(segments.len(), 6);
        let index: Vec<u8> = segments
            .iter()
            .flat_map(|(body, _)| body.iter().copied())
            .collect();
        assert_eq!(index.len(), held as usize * BC_INDEX_PREFIX_BYTES);
        for block in 0..6u32 {
            let global = block * LEAVES_PER_PPOI_BLOCK + 3;
            assert_eq!(
                row(&index, global as usize),
                prefix_of(global),
                "block {block}'s commitment must sit at its global index"
            );
        }
    }
}
