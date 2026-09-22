//! The addendum refusal counters must exist at zero before any refusal, and each refusal must
//! land on its own `reason`.
//!
//! An assertion that only watches a counter rise cannot see the hole this closes: until the
//! first refusal the series does not exist at all, so a rate alert reads "no data" and cannot
//! tell a silent server from an unscraped one. Every case here reads the zero series first,
//! through `/metrics`, and pins the untouched siblings to 0 so an inverted or shared `reason`
//! is not hidden by the one counter that did move.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "HTTP integration fixture diagnostics"
)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, InspireVariant, SecurityLevel};
use raven_inspire::query_seeded;
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{setup_state, LogicalLeafStore, RavenInspireScheme};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
use raven_railgun_http::{inspire_router, write_versioned, AppState, HttpConfig};
use tower::ServiceExt;

const TOKEN: &str = "addendum-refusal-metrics-token-123456";
const LIST_KEY: [u8; 32] = [0x5c; 32];
const RING_DIM: usize = 256;
const ENTRY_BYTES: usize = 32;
const ROWS: usize = 32;
/// Shard width the commit driver derives addenda at; any positive width reaches the table.
const ENTRIES_PER_SHARD: u32 = 2_048;

const SKEW: &str = "raven_railgun_addendum_provenance_skew_total";
const MISSING: &str = "raven_railgun_addendum_missing_total";
/// Spelled out rather than imported: an oracle that reads the crate's own list agrees with it
/// by construction, including when the list is wrong.
const REASONS: [&str; 3] = ["unseeded", "stale_provenance", "swapped_mid_request"];

/// What the instance's committed-addenda table holds when the batch lands.
enum Provenance {
    /// Never committed a tree: no table and no recorded database.
    Never,
    /// Recorded against a database the instance no longer serves.
    Superseded,
    /// Recorded against the served database, but holding no addendum for the queried shard.
    ServedButEmpty,
}

fn params() -> InspireParams {
    InspireParams {
        ring_dim: RING_DIM,
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

fn fixture(instance: &str, provenance: &Provenance) -> (axum::Router, Vec<u8>) {
    let params = params();
    let db = raven_railgun_testkit::toy_db(ROWS, ENTRY_BYTES);
    let (state, secret_key) =
        setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("toy state");

    let mut sampler = GaussianSampler::with_seed(params.sigma, 0x5c);
    let (_, query) = query_seeded(
        &state.crs,
        0,
        state.shard_config(),
        &secret_key,
        &mut sampler,
    )
    .expect("seeded query for shard 0");
    let upload = write_versioned(&vec![query]).expect("versioned batch upload");

    let mut store = LogicalLeafStore::new();
    match *provenance {
        Provenance::Never => {}
        Provenance::Superseded => {
            let superseded = Arc::new((*state.encoded_db).clone());
            store.refresh_committed_addenda(&superseded, ENTRIES_PER_SHARD);
        }
        Provenance::ServedButEmpty => {
            store.refresh_committed_addenda(&state.encoded_db, ENTRIES_PER_SHARD);
        }
    }

    let instance_id = InstanceId::new(instance);
    let engine: Engine<RavenInspireScheme> = Engine::new();
    engine
        .add_live(Arc::new(PirInstance::new(
            instance_id.clone(),
            InstanceRole::Live,
            state,
        )))
        .expect("register instance");

    let mut stores = HashMap::new();
    stores.insert(
        instance_id,
        (LIST_KEY, Arc::new(parking_lot::Mutex::new(store))),
    );

    let mut config = HttpConfig::demo(TOKEN);
    config.metrics_public = true;
    let app = AppState::new(engine, config)
        .expect("app state")
        .with_instance_logical_stores(stores);
    (inspire_router(app).expect("router"), upload)
}

fn request(method: Method, uri: String, body: Vec<u8>) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(body))
        .expect("build request");
    request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        12_345,
    )));
    request
}

async fn scrape(router: &axum::Router) -> String {
    let response = router
        .clone()
        .oneshot(request(Method::GET, "/metrics".to_owned(), Vec::new()))
        .await
        .expect("metrics dispatch");
    assert_eq!(response.status(), StatusCode::OK, "metrics scrape");
    let body = response
        .into_body()
        .collect()
        .await
        .expect("metrics body")
        .to_bytes();
    String::from_utf8(body.to_vec()).expect("metrics body is utf8")
}

async fn post_batch(router: &axum::Router, instance: &str, upload: Vec<u8>) -> StatusCode {
    router
        .clone()
        .oneshot(request(
            Method::POST,
            format!("/v1/instance/{instance}/batch"),
            upload,
        ))
        .await
        .expect("batch dispatch")
        .status()
}

/// Select a rendered series by NAME and its full label set together. Two `contains` over the
/// whole scrape do not compose into this: the label half is satisfied by any other row.
fn row(text: &str, name: &str, instance: &str, labels: &[&str]) -> String {
    let want = format!("instance=\"{instance}\"");
    text.lines()
        .find(|line| {
            line.starts_with(&format!("{name}{{"))
                && line.contains(&want)
                && labels.iter().all(|label| line.contains(label))
        })
        .unwrap_or_else(|| panic!("scrape has no {name} row for {want} {labels:?}:\n{text}"))
        .to_owned()
}

fn sample(text: &str, name: &str, instance: &str, labels: &[&str]) -> u64 {
    let rendered = row(text, name, instance, labels);
    rendered
        .rsplit(' ')
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("row carries no integer sample: {rendered}"))
}

fn skew(text: &str, instance: &str, reason: &str) -> u64 {
    sample(text, SKEW, instance, &[&format!("reason=\"{reason}\"")])
}

fn missing(text: &str, instance: &str) -> u64 {
    sample(text, MISSING, instance, &[])
}

fn assert_all_series_are_zero(text: &str, instance: &str) {
    for reason in REASONS {
        assert_eq!(
            skew(text, instance, reason),
            0,
            "{SKEW} must scrape as zero for reason {reason} before any refusal:\n{text}"
        );
    }
    assert_eq!(
        missing(text, instance),
        0,
        "{MISSING} must scrape as zero before any refusal:\n{text}"
    );
}

/// The whole point of the change: a registered instance publishes every refusal series at zero
/// before it has anything to report, so an alert can tell "never fired" from "not scraped".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refusal_series_scrape_zero_for_a_registered_instance_before_any_refusal() {
    const INSTANCE: &str = "addendum-zero-before-refusal";
    let (router, _) = fixture(INSTANCE, &Provenance::Never);
    let text = scrape(&router).await;

    assert!(
        text.contains(&format!("# HELP {SKEW}")),
        "the skew counter must register HELP text:\n{text}"
    );
    assert!(
        text.contains(&format!("# HELP {MISSING}")),
        "the missing counter must register HELP text:\n{text}"
    );
    assert_all_series_are_zero(&text, INSTANCE);

    // The label domain is closed, so the instance publishes exactly three skew series. A
    // fourth would be a reason no zero-init covers; a value outside the set is a cardinality
    // leak into an unbounded label.
    let published: Vec<&str> = text
        .lines()
        .filter(|line| {
            line.starts_with(&format!("{SKEW}{{"))
                && line.contains(&format!("instance=\"{INSTANCE}\""))
        })
        .collect();
    assert_eq!(
        published.len(),
        REASONS.len(),
        "the reason label must stay bounded to its closed set; got {published:?}"
    );
}

/// An instance that has never committed a tree. This is a correct transient, and it must not
/// read as the superseded-database case an operator would chase as a commit-cadence skew.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_never_committed_instance_refuses_under_the_unseeded_reason() {
    const INSTANCE: &str = "addendum-unseeded-refusal";
    let (router, upload) = fixture(INSTANCE, &Provenance::Never);
    assert_all_series_are_zero(&scrape(&router).await, INSTANCE);

    assert_eq!(
        post_batch(&router, INSTANCE, upload).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "a batch served without provenance folds to a wrong root and must be refused"
    );

    let text = scrape(&router).await;
    assert_eq!(skew(&text, INSTANCE, "unseeded"), 1, "{text}");
    assert_eq!(skew(&text, INSTANCE, "stale_provenance"), 0, "{text}");
    assert_eq!(skew(&text, INSTANCE, "swapped_mid_request"), 0, "{text}");
    assert_eq!(missing(&text, INSTANCE), 0, "{text}");
}

/// The narrow `publish_recommitted_state` -> `refresh_committed_addenda` window: a table that
/// was seeded, against a database this instance no longer serves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_superseded_addenda_table_refuses_under_the_stale_provenance_reason() {
    const INSTANCE: &str = "addendum-stale-provenance-refusal";
    let (router, upload) = fixture(INSTANCE, &Provenance::Superseded);
    assert_all_series_are_zero(&scrape(&router).await, INSTANCE);

    assert_eq!(
        post_batch(&router, INSTANCE, upload).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "addenda from a superseded database must be refused"
    );

    let text = scrape(&router).await;
    assert_eq!(skew(&text, INSTANCE, "stale_provenance"), 1, "{text}");
    assert_eq!(skew(&text, INSTANCE, "unseeded"), 0, "{text}");
    assert_eq!(skew(&text, INSTANCE, "swapped_mid_request"), 0, "{text}");
    assert_eq!(missing(&text, INSTANCE), 0, "{text}");
}

/// Provenance holds, but the queried shard has no committed addendum. That is its own counter,
/// and the skew series must stay at zero or the two refusals are indistinguishable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shard_without_a_committed_addendum_refuses_on_the_missing_counter() {
    const INSTANCE: &str = "addendum-missing-refusal";
    let (router, upload) = fixture(INSTANCE, &Provenance::ServedButEmpty);
    assert_all_series_are_zero(&scrape(&router).await, INSTANCE);

    assert_eq!(
        post_batch(&router, INSTANCE, upload).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "an absent addendum must be refused, never served as an empty one"
    );

    let text = scrape(&router).await;
    assert_eq!(missing(&text, INSTANCE), 1, "{text}");
    for reason in REASONS {
        assert_eq!(
            skew(&text, INSTANCE, reason),
            0,
            "provenance held, so no skew reason may fire:\n{text}"
        );
    }
}
