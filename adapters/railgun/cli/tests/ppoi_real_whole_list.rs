//! Whole-list root oracle: replay an upstream PPOI list end to end through the list bootstrap,
//! which holds every rebuilt root to the `validatedMerkleroot` upstream published with its event.
//!
//! The live run is by hand only, and it reads its aggregator from the environment:
//! `RAVEN_PPOI_UPSTREAM_BASE=https://ppoi.fdi.network cargo test --manifest-path
//! adapters/railgun/Cargo.toml -p raven-railgun-cli --profile ci-test --test ppoi_real_whole_list
//! -- --ignored --nocapture`. `cargo test`, because the replay outlasts nextest's slow-timeout.
//! The same harness runs on every push against a local feed shaped the way upstream publishes.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    reason = "network oracle fixture; the receipt is the printed run"
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use axum::routing::post;
use axum::{Json, Router};
use parking_lot::Mutex;
use raven_railgun_cli::bootstrap_subsquid::{
    bootstrap_one_list_with_mode, BootstrapError, PpoiBootstrapMode, PpoiEventRow,
    PpoiEventsSource, RailwayPpoiClient,
};
use raven_railgun_poseidon::{merkle_node, railgun_merkle_zero_value};
use serde_json::{json, Value};

const UPSTREAM_BASE_ENV: &str = "RAVEN_PPOI_UPSTREAM_BASE";
const OFAC_LIST_KEY_HEX: &str = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";
const STUB_LIST_KEY: [u8; 32] = [0xab; 32];
const UPSTREAM_TREE_DEPTH: usize = 16;
// Upstream's tree size, pinned here so a drift in Raven's own block constant cannot move the
// oracle along with the code it grades.
const UPSTREAM_TREE_LEAVES: usize = 1 << UPSTREAM_TREE_DEPTH;
const UPSTREAM_PAGE_ROWS: usize = 501;
const EVENT_TYPES: [&str; 4] = ["Shield", "Transact", "Unshield", "LegacyTransact"];

/// The list as the aggregator served it, kept so the run can say where it stopped and check
/// each sealed tree. The per-event comparison stays in the bootstrap; this adds no second one.
struct Recording {
    client: RailwayPpoiClient,
    published: Mutex<Vec<(u64, [u8; 32])>>,
}

#[async_trait]
impl PpoiEventsSource for Recording {
    async fn fetch_all_events(
        &self,
        list_key: [u8; 32],
    ) -> Result<Vec<PpoiEventRow>, BootstrapError> {
        let rows = self.client.fetch_all_events(list_key).await?;
        *self.published.lock() = rows
            .iter()
            .map(|row| (row.index, row.validated_merkleroot))
            .collect();
        Ok(rows)
    }
}

struct WholeListRun {
    events: usize,
    last_index: u64,
    trees: usize,
    receipt: String,
}

async fn replay_whole_list(base: &str, list_key: [u8; 32]) -> WholeListRun {
    let source = Recording {
        client: RailwayPpoiClient::new(base, 0, 1).expect("aggregator client"),
        published: Mutex::new(Vec::new()),
    };
    let started = Instant::now();
    let report = bootstrap_one_list_with_mode(list_key, &source, PpoiBootstrapMode::Strict, &[])
        .await
        .unwrap_or_else(|error| panic!("replay of the list served at {base} refused: {error}"));
    let wall = started.elapsed();
    let published = source.published.into_inner();

    assert_eq!(report.list_key, list_key);
    assert_eq!(report.events, published.len());
    assert!(
        published
            .iter()
            .enumerate()
            .all(|(position, (index, _))| u64::try_from(position).ok() == Some(*index)),
        "the feed must be the list from index 0 with no gap"
    );
    let trees = report.events.div_ceil(UPSTREAM_TREE_LEAVES);
    assert!(
        trees > 1,
        "{} events never reach a seal, so the run proves nothing a one-tree run did not",
        report.events
    );
    assert_eq!(
        report.block_roots.len(),
        trees,
        "one root per upstream tree over {} events",
        report.events
    );
    for (tree, sealed) in report.block_roots.iter().enumerate() {
        let last_row = ((tree + 1) * UPSTREAM_TREE_LEAVES).min(published.len()) - 1;
        assert_eq!(
            *sealed, published[last_row].1,
            "tree {tree} must end on the root upstream published with row {last_row}"
        );
    }
    assert_eq!(report.block_roots.last(), Some(&report.local_root));

    let last_index = published.last().map_or(0, |(index, _)| *index);
    // The client refuses a scan whose length differs from the count node status advertised,
    // so `events` is that count and the run stops one row below it.
    let receipt = format!(
        "list {} events={} (the node-status count read when the run began) \
         stopped_at_index={last_index} trees={trees}",
        hex::encode(list_key),
        report.events,
    );
    eprintln!(
        "whole-list root oracle: {receipt} wall={wall:?}; every event's rebuilt root \
         byte-equals its validatedMerkleroot"
    );
    for (tree, sealed) in report.block_roots.iter().enumerate() {
        eprintln!("  tree {tree} root {}", hex::encode(sealed));
    }
    WholeListRun {
        events: report.events,
        last_index,
        trees,
        receipt,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "trigger: run by hand with RAVEN_PPOI_UPSTREAM_BASE set to a live PPOI aggregator \
            base URL; pages the whole list, about 720 JSON-RPC requests at 501 rows each"]
async fn every_root_of_the_live_list_matches_the_aggregator() {
    let base = std::env::var(UPSTREAM_BASE_ENV)
        .unwrap_or_else(|_| panic!("{UPSTREAM_BASE_ENV} is unset; name the aggregator to read"));
    let list_key: [u8; 32] = hex::decode(OFAC_LIST_KEY_HEX)
        .expect("list key hex")
        .try_into()
        .expect("32-byte list key");
    replay_whole_list(&base, list_key).await;
}

/// Two trees and a partial last page: the list crosses a seal, the seal falls inside a page, and
/// the scan ends short of a full page.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn whole_list_harness_holds_on_a_local_forest_feed() {
    let events = UPSTREAM_TREE_LEAVES + 43;
    let feed = Arc::new(StubFeed {
        list_key_hex: hex::encode(STUB_LIST_KEY),
        rows: forest_feed(events),
        pages: AtomicUsize::new(0),
        highest_end: AtomicUsize::new(0),
    });
    let base = serve(Arc::clone(&feed)).await;

    let run = replay_whole_list(&base, STUB_LIST_KEY).await;

    assert_eq!(run.events, events);
    assert_eq!(run.last_index, u64::try_from(events - 1).expect("fits"));
    assert_eq!(run.trees, 2);
    assert_eq!(
        feed.pages.load(Ordering::SeqCst),
        events.div_ceil(UPSTREAM_PAGE_ROWS)
    );
    assert_eq!(
        feed.highest_end.load(Ordering::SeqCst),
        events - 1,
        "the scan must stop at the advertised count, not probe past it"
    );
    assert_eq!(
        run.receipt,
        format!(
            "list {} events={events} (the node-status count read when the run began) \
             stopped_at_index={} trees=2",
            hex::encode(STUB_LIST_KEY),
            events - 1
        ),
        "the receipt must state the advertised count and the last index below it"
    );
}

struct StubRow {
    leaf: [u8; 32],
    root: [u8; 32],
}

/// What upstream publishes beside each event: the root of the depth-16 tree it landed in. A
/// frontier accumulator, not the engine's tree, so the stub does not grade the code under test
/// with its own arithmetic.
fn forest_feed(events: usize) -> Vec<StubRow> {
    let mut zeros = [[0u8; 32]; UPSTREAM_TREE_DEPTH];
    let mut zero = railgun_merkle_zero_value();
    for slot in &mut zeros {
        *slot = zero;
        zero = merkle_node(zero, zero).expect("zero subtree");
    }
    let mut frontier = [[0u8; 32]; UPSTREAM_TREE_DEPTH];
    (0..events)
        .map(|index| {
            let mut leaf = [0u8; 32];
            leaf[1] = 0x5a;
            leaf[24..].copy_from_slice(&u64::try_from(index).expect("fits").to_be_bytes());
            let mut node = leaf;
            let mut position = index % UPSTREAM_TREE_LEAVES;
            for (filled, zero) in frontier.iter_mut().zip(&zeros) {
                node = if position.is_multiple_of(2) {
                    *filled = node;
                    merkle_node(node, *zero)
                } else {
                    merkle_node(*filled, node)
                }
                .expect("canonical node");
                position /= 2;
            }
            StubRow { leaf, root: node }
        })
        .collect()
}

struct StubFeed {
    list_key_hex: String,
    rows: Vec<StubRow>,
    pages: AtomicUsize,
    highest_end: AtomicUsize,
}

impl StubFeed {
    fn answer(&self, request: &Value) -> Value {
        let result = match request["method"].as_str() {
            Some("ppoi_node_status") => Ok(self.node_status()),
            Some("ppoi_poi_events") => self.events_page(&request["params"]),
            other => Err(format!("no such method {other:?}")),
        };
        match result {
            Ok(result) => json!({"jsonrpc": "2.0", "id": request["id"], "result": result}),
            Err(data) => json!({
                "jsonrpc": "2.0",
                "id": request["id"],
                "error": {"code": -32602, "message": "Invalid params", "data": data},
            }),
        }
    }

    fn node_status(&self) -> Value {
        let mut lengths = serde_json::Map::new();
        for (slot, name) in EVENT_TYPES.iter().enumerate() {
            let count = (0..self.rows.len())
                .filter(|index| index % EVENT_TYPES.len() == slot)
                .count();
            lengths.insert((*name).to_owned(), json!(count));
        }
        let mut lists = serde_json::Map::new();
        lists.insert(
            self.list_key_hex.clone(),
            json!({"poiEventLengths": lengths, "historicalMerklerootsLength": self.rows.len()}),
        );
        json!({"forNetwork": {"Ethereum": {"listStatuses": lists}}})
    }

    fn events_page(&self, params: &Value) -> Result<Value, String> {
        let scoped = params["chainType"] == "0"
            && params["chainID"] == "1"
            && params["txidVersion"] == "V2_PoseidonMerkle"
            && params["listKey"] == self.list_key_hex.as_str();
        let as_index = |key: &str| params[key].as_u64().and_then(|v| usize::try_from(v).ok());
        let (Some(start), Some(end)) = (as_index("startIndex"), as_index("endIndex")) else {
            return Err("startIndex and endIndex must be integers".to_owned());
        };
        if !scoped || end < start || end - start >= UPSTREAM_PAGE_ROWS {
            return Err(format!("refused page {params}"));
        }
        self.pages.fetch_add(1, Ordering::SeqCst);
        self.highest_end.fetch_max(end, Ordering::SeqCst);
        let end = end.min(self.rows.len() - 1);
        let rows = (start..=end)
            .map(|index| {
                let row = &self.rows[index];
                json!({
                    "signedPOIEvent": {
                        "index": index,
                        "blindedCommitment": format!("0x{}", hex::encode(row.leaf)),
                        "signature": hex::encode([0x11u8; 64]),
                        "type": EVENT_TYPES[index % EVENT_TYPES.len()],
                    },
                    "validatedMerkleroot": hex::encode(row.root),
                })
            })
            .collect();
        Ok(Value::Array(rows))
    }
}

async fn serve(feed: Arc<StubFeed>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let app = Router::new().route(
        "/",
        post(move |Json(request): Json<Value>| {
            let feed = Arc::clone(&feed);
            async move { Json(feed.answer(&request)) }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    format!("http://{addr}")
}
