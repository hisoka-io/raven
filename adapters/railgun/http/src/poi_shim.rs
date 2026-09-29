//! Wallet-facing routes outside the PIR query path: the list index channel and the commit-tree
//! proof.
//!
//! These routes are NOT private; wallet privacy needs `/v1/instance/:id/query`.
//!
//! `bc-prefixes` publishes the list's index in per-block segments a client resumes with
//! `?since=`. No route takes a blinded commitment: the client derives its status from the
//! index and fetches its proof by PIR.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{header::HeaderName, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use raven_railgun_core::hex::decode_hex;
use raven_railgun_core::MerkleProof as CoreMerkleProof;
use raven_railgun_engine::orchestrator::LEAVES_PER_PPOI_BLOCK;
use raven_railgun_engine::PirScheme;
use serde::{Deserialize, Serialize};

use crate::shim_store::{
    CoverageRefusal, ListCoverage, SegmentRefusal, SharedLogicalStore as CoveredStore, UpstreamTip,
};
use crate::status::MirrorFeedView;
use crate::AppState;

const ETAG_HEADER: HeaderName = HeaderName::from_static("etag");
const IF_NONE_MATCH_HEADER: HeaderName = HeaderName::from_static("if-none-match");
const CACHE_CONTROL_HEADER: HeaderName = HeaderName::from_static("cache-control");
const LAST_MODIFIED_HEADER: HeaderName = HeaderName::from_static("last-modified");

// `bc-prefixes` cursor. TOTAL and EPOCH describe the whole list, so only the frontier carries them.
pub(crate) const X_RAVEN_INDEX_BASE: HeaderName = HeaderName::from_static("x-raven-index-base");
pub(crate) const X_RAVEN_INDEX_NEXT: HeaderName = HeaderName::from_static("x-raven-index-next");
pub(crate) const X_RAVEN_INDEX_TOTAL: HeaderName = HeaderName::from_static("x-raven-index-total");
pub(crate) const X_RAVEN_INDEX_EPOCH: HeaderName = HeaderName::from_static("x-raven-index-epoch");

/// Hex-encoded 32-byte blob. No `0x` prefix (matches Railgun upstream).
type HexHash = String;

/// Body for `POST /v1/commit-tree/:tree_number/merkle-proof`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitTreeProofRequest {
    /// 0-based leaf index within the tree.
    pub leaf_index: u32,
}

/// Railgun-shaped Merkle proof JSON (`shared-models/src/models/proof-of-innocence.ts`).
#[derive(Debug, Clone, Serialize)]
pub struct MerkleProofJson {
    /// Commitment hex at the proven leaf; empty when the tree holds none there.
    pub leaf: HexHash,
    /// Sibling-hash chain, leaf-to-root, 16 entries.
    pub elements: Vec<HexHash>,
    /// Leaf index as 32-byte big-endian hex (matches upstream `BigInt` -> `nToHex(., 32)`).
    pub indices: HexHash,
    /// Merkle root hex.
    pub root: HexHash,
}

impl MerkleProofJson {
    fn from_core(core: &CoreMerkleProof, leaf_hex: HexHash) -> Self {
        Self {
            leaf: leaf_hex,
            elements: core.elements.iter().map(hex_encode).collect(),
            indices: indices_to_hex(core.indices),
            root: hex_encode(&core.root),
        }
    }
}

fn hex_encode(bytes: &[u8; 32]) -> HexHash {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn indices_to_hex(idx: u16) -> HexHash {
    let mut buf = [0u8; 32];
    buf[30] = ((idx >> 8) & 0xff) as u8;
    buf[31] = (idx & 0xff) as u8;
    hex_encode(&buf)
}

const COMMIT_TREE_PROOF_ROUTE: &str = "commit-tree-merkle-proof";
const BC_PREFIXES_ROUTE: &str = "bc-prefixes";

/// Refuse loudly and name what is not covered: a bare 503 reads the same as a crashed process.
fn refuse_uncovered(route: &'static str, refusal: &CoverageRefusal) -> StatusCode {
    tracing::warn!(
        route,
        reason = %refusal,
        "poi shim refused: no wired store covers the whole question"
    );
    metrics::counter!(
        "raven_railgun_shim_coverage_refusals_total",
        "route" => route
    )
    .increment(1);
    StatusCode::SERVICE_UNAVAILABLE
}

/// Every mirror feed as readiness reads it. Taken once per request, because the probe locks
/// every store on every list.
fn read_mirror_feeds<S: PirScheme>(app: &AppState<S>) -> Vec<MirrorFeedView> {
    app.mirror_feeds
        .as_ref()
        .map(|probe| probe())
        .unwrap_or_default()
}

/// Upstream's latest row count for `list_key`. No feed, or one whose last answer was a full
/// page, gives none.
fn upstream_tip(feeds: &[MirrorFeedView], list_key: &[u8; 32]) -> Option<UpstreamTip> {
    let wanted = hex_encode(list_key);
    let feed = feeds.iter().find(|feed| feed.list_key == wanted)?;
    Some(UpstreamTip {
        rows: feed.upstream_rows?,
        age_secs: feed.seconds_since_answer?,
    })
}

fn cover_list<'a, S: PirScheme>(
    app: &'a AppState<S>,
    list_key: [u8; 32],
    route: &'static str,
    feeds: &[MirrorFeedView],
) -> Result<ListCoverage<'a>, StatusCode> {
    app.shim_stores
        .as_ref()
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
        .prove_list_coverage(&list_key, upstream_tip(feeds, &list_key))
        .map_err(|refusal| refuse_uncovered(route, &refusal))
}

fn cover_tree<'a, S: PirScheme>(
    app: &'a AppState<S>,
    tree_number: u32,
    route: &'static str,
) -> Result<&'a CoveredStore, StatusCode> {
    app.shim_stores
        .as_ref()
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
        .prove_tree(tree_number)
        .map_err(|refusal| refuse_uncovered(route, &refusal))
}

pub(crate) async fn commit_tree_proof_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
    Path(tree_number): Path<u32>,
    Json(req): Json<CommitTreeProofRequest>,
) -> Result<Json<MerkleProofJson>, StatusCode> {
    let store = cover_tree(&app, tree_number, COMMIT_TREE_PROOF_ROUTE)?;
    let store = store.lock();
    let proof = store
        .merkle_proof(tree_number, req.leaf_index)
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let leaf_hex = store
        .leaf(tree_number, req.leaf_index)
        .map(hex_encode)
        .unwrap_or_default();
    Ok(Json(MerkleProofJson::from_core(&proof, leaf_hex)))
}

/// Prefix width for the binary index channel.
pub const BC_INDEX_PREFIX_BYTES: usize = 6;

/// Largest body the index channel can emit: the list's size decides how many segments a
/// cold client walks, never how large one of them is.
pub const BC_INDEX_SEGMENT_MAX_BYTES: usize =
    BC_INDEX_PREFIX_BYTES * LEAVES_PER_PPOI_BLOCK as usize;

/// Query string of `GET /v1/poi/:list_key_hex/bc-prefixes`.
#[derive(Debug, Clone, Deserialize)]
pub struct IndexSegmentQuery {
    /// Global index to resume from. Absent means the head of the list.
    #[serde(default)]
    pub since: Option<u32>,
}

pub(crate) async fn bc_prefix_segment_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
    Path(list_key_hex): Path<String>,
    Query(segment): Query<IndexSegmentQuery>,
    headers_in: HeaderMap,
) -> Result<axum::response::Response, StatusCode> {
    let list_key = decode_hex(&list_key_hex).ok_or(StatusCode::BAD_REQUEST)?;
    let since = segment.since.unwrap_or(0);
    // Waited for here, off the blocking pool, so a queued read holds no thread.
    let permit = {
        let registry = app
            .shim_stores
            .as_ref()
            .as_ref()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        Arc::clone(registry.segment_reads())
    }
    .acquire_owned()
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        #[cfg(test)]
        let _reading = app
            .shim_stores
            .as_ref()
            .as_ref()
            .map(crate::shim_store::ShimStoreRegistry::segment_read_probe);
        serve_prefix_segment(&app, list_key, since, &headers_in)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// Runs under block locks the ingest path also takes, so only ever on the blocking pool.
fn serve_prefix_segment<S: PirScheme>(
    app: &AppState<S>,
    list_key: [u8; 32],
    since: u32,
    headers_in: &HeaderMap,
) -> Result<axum::response::Response, StatusCode> {
    let coverage = cover_list(app, list_key, BC_PREFIXES_ROUTE, &read_mirror_feeds(app))?;
    // Epoch before rows, so it never names a height whose rows are missing from the body.
    let epoch = coverage.epoch();
    let segment = coverage.segment(since);
    coverage
        .recheck_frontier()
        .map_err(|refusal| refuse_uncovered(BC_PREFIXES_ROUTE, &refusal))?;
    let segment = match segment {
        Ok(segment) => segment,
        // Past the frontier the caller holds rows this epoch does not, which is a rollback to
        // report rather than an empty body to absorb. The refusal still says where this node's
        // list ends, so the caller can resume from there.
        Err(SegmentRefusal::PastFrontier { total }) => {
            let mut hdrs = HeaderMap::new();
            hdrs.insert(X_RAVEN_INDEX_TOTAL, HeaderValue::from(total));
            hdrs.insert(X_RAVEN_INDEX_EPOCH, HeaderValue::from(epoch));
            return Ok((StatusCode::RANGE_NOT_SATISFIABLE, hdrs).into_response());
        }
        Err(SegmentRefusal::Uncovered(refusal)) => {
            return Err(refuse_uncovered(BC_PREFIXES_ROUTE, &refusal));
        }
    };
    let next = segment.next;

    let mut extra = vec![
        (X_RAVEN_INDEX_BASE, HeaderValue::from(since)),
        (X_RAVEN_INDEX_NEXT, HeaderValue::from(next)),
    ];
    // A sealed block can never change again, which is what makes its segment cacheable forever.
    // An immutable response may carry only what is immutable: a cache holds it for a year, and
    // a list-wide total or epoch read off it then contradicts the frontier's.
    let last_modified = if segment.sealed {
        extra.push((
            CACHE_CONTROL_HEADER,
            HeaderValue::from_static("public, max-age=31536000, immutable"),
        ));
        None
    } else {
        // An unsealed segment is the frontier, so the list ends where it does.
        extra.push((X_RAVEN_INDEX_TOTAL, HeaderValue::from(next)));
        extra.push((X_RAVEN_INDEX_EPOCH, HeaderValue::from(epoch)));
        extra.push((
            CACHE_CONTROL_HEADER,
            HeaderValue::from_static("public, max-age=15, must-revalidate"),
        ));
        Some(epoch)
    };

    Ok(serve_publishing_bytes(
        segment.prefixes,
        &segment.etag,
        last_modified,
        headers_in,
        &extra,
    ))
}

fn if_none_match(headers_in: &HeaderMap) -> Option<&str> {
    headers_in
        .get(&IF_NONE_MATCH_HEADER)
        .and_then(|v| v.to_str().ok())
}

/// `extra` lands on the 304 as well, so a resuming client learns where to continue from a
/// response whose body it already holds.
fn not_modified(etag: &str, extra: &[(HeaderName, HeaderValue)]) -> axum::response::Response {
    let mut hdrs = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(etag) {
        hdrs.insert(ETAG_HEADER, v);
    }
    for (name, value) in extra {
        hdrs.insert(name.clone(), value.clone());
    }
    (StatusCode::NOT_MODIFIED, hdrs).into_response()
}

fn serve_publishing_bytes(
    body: bytes::Bytes,
    etag: &str,
    last_modified: Option<u64>,
    headers_in: &HeaderMap,
    extra: &[(HeaderName, HeaderValue)],
) -> axum::response::Response {
    if if_none_match(headers_in) == Some(etag) {
        return not_modified(etag, extra);
    }

    let mut hdrs = HeaderMap::new();
    hdrs.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(v) = HeaderValue::from_str(etag) {
        hdrs.insert(ETAG_HEADER, v);
    }
    if let Some(epoch) = last_modified {
        hdrs.insert(LAST_MODIFIED_HEADER, HeaderValue::from(epoch));
    }
    hdrs.insert(
        CACHE_CONTROL_HEADER,
        HeaderValue::from_static("public, max-age=15, must-revalidate"),
    );
    for (name, value) in extra {
        hdrs.insert(name.clone(), value.clone());
    }
    (StatusCode::OK, hdrs, body).into_response()
}

/// Build the wallet-shim + index-channel router.
pub fn poi_shim_routes<S: PirScheme>(state: AppState<S>) -> axum::Router {
    use axum::routing::{get, post};
    axum::Router::new()
        .route(
            "/v1/commit-tree/:tree_number/merkle-proof",
            post(commit_tree_proof_handler::<S>),
        )
        .route(
            "/v1/poi/:list_key_hex/bc-prefixes",
            get(bc_prefix_segment_handler::<S>),
        )
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_round_trips() {
        let bytes = [0xab; 32];
        let s = hex_encode(&bytes);
        assert_eq!(s.len(), 64);
        assert_eq!(decode_hex(&s), Some(bytes));
    }

    #[test]
    fn indices_hex_zero_pads_to_32_bytes() {
        let s = indices_to_hex(0x0102);
        assert_eq!(s.len(), 64);
        assert!(s.starts_with("0000"));
        assert!(s.ends_with("0102"));
    }

    mod index_channel_reads {
        use super::super::*;
        use crate::shim_store::{ShimStoreRegistry, SEGMENT_READS_AT_ONCE};
        use crate::status::{MirrorFeedState, MirrorFeedView};
        use crate::HttpConfig;
        use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
        use raven_railgun_engine::orchestrator::DataSourceFilter;
        use raven_railgun_engine::pir_table::PerLeafCommitmentEncoder;
        use raven_railgun_engine::Engine;
        use raven_railgun_persistence::WalEntryPayload;

        const LIST_KEY: [u8; 32] = [0x42; 32];

        #[derive(Debug, Default)]
        struct StubScheme;

        #[derive(Debug, Default)]
        struct StubState;

        impl PirScheme for StubScheme {
            type ServerState = StubState;
            type Query = ();
            type Response = ();

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

        /// Canonical BN254 Fr, with the seed inside the published six-byte prefix too.
        fn fr(seed: u32) -> [u8; 32] {
            let mut out = [0u8; 32];
            out[1..5].copy_from_slice(&seed.to_be_bytes());
            out[20] = 0x01;
            out[28..].copy_from_slice(&seed.to_be_bytes());
            out
        }

        fn leaf(local: u32, seed: u32) -> (WalEntryPayload, u64) {
            (
                WalEntryPayload::PpoiListLeafAdded {
                    list_key: LIST_KEY,
                    list_index: local,
                    blinded_commitment: fr(seed),
                    event_type: raven_railgun_persistence::PpoiEventType::Shield,
                    validated_merkleroot: [0; 32],
                },
                1_000 + u64::from(local),
            )
        }

        fn encoder() -> PerLeafCommitmentEncoder {
            PerLeafCommitmentEncoder::new(32, LEAVES_PER_PPOI_BLOCK, 0).expect("encoder")
        }

        /// Block `block` holding `rows` rows, each seeded with its global index.
        fn block_store(block: u32, rows: u32) -> CoveredStore {
            let base = block * LEAVES_PER_PPOI_BLOCK;
            let run: Vec<_> = (0..rows).map(|local| leaf(local, base + local)).collect();
            let mut store = LogicalLeafStore::new();
            store.seed_leaf_run(&run, &encoder()).expect("seed rows");
            Arc::new(parking_lot::Mutex::new(store))
        }

        /// Blocks `0..` in order, with upstream counting exactly the rows they hold.
        fn covered_app(blocks: &[CoveredStore], rows: u64) -> AppState<StubScheme> {
            let view = MirrorFeedView {
                list_key: hex_encode(&LIST_KEY),
                state: MirrorFeedState::Syncing,
                rows_held: rows,
                upstream_rows: Some(rows),
                upstream_rows_seen: Some(rows),
                next_index: rows,
                consecutive_failures: 0,
                last_failure: None,
                seconds_since_answer: Some(0),
            };
            let declarations: Vec<_> = (0u32..)
                .zip(blocks)
                .map(|(block, store)| {
                    (
                        DataSourceFilter::PpoiListBlock {
                            list_key: LIST_KEY,
                            block,
                        },
                        Arc::clone(store),
                    )
                })
                .collect();
            AppState::new(
                Engine::<StubScheme>::new(),
                HttpConfig::demo("shim-unit-test-token"),
            )
            .expect("appstate")
            .with_shim_stores(declarations)
            .with_mirror_feeds(Arc::new(move || vec![view.clone()]))
        }

        fn registry(app: &AppState<StubScheme>) -> &ShimStoreRegistry {
            app.shim_stores.as_ref().as_ref().expect("registry")
        }

        async fn body_of(response: axum::response::Response) -> bytes::Bytes {
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body")
        }

        fn etag_of(response: &axum::response::Response) -> String {
            response
                .headers()
                .get(ETAG_HEADER)
                .and_then(|v| v.to_str().ok())
                .expect("etag")
                .to_owned()
        }

        /// Poll `done` for up to ten seconds; the interleavings below are staged, not timed.
        async fn until(mut done: impl FnMut() -> bool) {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !done() {
                assert!(std::time::Instant::now() < deadline, "stage never reached");
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        }

        /// A sealed block's rows are read on the first request only, and its body is answered
        /// again, a mid-block `since` included, while the frontier is read on every request. The
        /// body is kept by the store's rows stamp, so rows that change under a full block are
        /// read again.
        #[tokio::test]
        async fn a_sealed_repeat_rebuilds_nothing_until_the_block_changes() {
            let sealed = block_store(0, LEAVES_PER_PPOI_BLOCK);
            let frontier = block_store(1, 3);
            let app = covered_app(
                &[Arc::clone(&sealed), frontier],
                u64::from(LEAVES_PER_PPOI_BLOCK) + 3,
            );
            // Blocks walked, and index rows read by any means, a count included.
            let get = |since: u32| {
                let walked = registry(&app).blocks_walked();
                let rows = registry(&app).rows_read();
                let response =
                    serve_prefix_segment(&app, LIST_KEY, since, &HeaderMap::new()).expect("served");
                assert_eq!(response.status(), StatusCode::OK, "since={since}");
                (
                    response,
                    registry(&app).blocks_walked() - walked,
                    registry(&app).rows_read() - rows,
                )
            };

            let (first, walked, rows) = get(0);
            assert_eq!(walked, 1);
            assert_eq!(rows, LEAVES_PER_PPOI_BLOCK as usize);
            let etag = etag_of(&first);
            let body = body_of(first).await;
            assert_eq!(body.len(), BC_INDEX_SEGMENT_MAX_BYTES);

            let (repeat, walked, rows) = get(0);
            assert_eq!((walked, rows), (0, 0), "a sealed repeat must read no row");
            assert_eq!(etag_of(&repeat), etag);
            assert_eq!(body_of(repeat).await, body);

            let (mid, walked, rows) = get(10);
            assert_eq!(
                (walked, rows),
                (0, 0),
                "a resume inside a sealed block must read no row"
            );
            assert_eq!(
                body_of(mid).await,
                body.slice(10 * BC_INDEX_PREFIX_BYTES..),
                "position i must still be the row at global index since + i"
            );

            for _ in 0..2 {
                let (_, walked, _) = get(LEAVES_PER_PPOI_BLOCK);
                assert_eq!(
                    walked, 1,
                    "the frontier still grows, so it is read every time"
                );
            }

            // A rewind past the block's tail, refilled with other rows: full again, new root.
            let refill_from = LEAVES_PER_PPOI_BLOCK - 500;
            let enc = encoder();
            {
                let mut store = sealed.lock();
                apply_wal_entry(
                    &mut store,
                    &WalEntryPayload::Reorg {
                        height: 1_000 + u64::from(refill_from) - 1,
                    },
                    1_000 + u64::from(refill_from) - 1,
                    &enc,
                )
                .expect("rewind");
                for local in refill_from..LEAVES_PER_PPOI_BLOCK {
                    let (payload, height) = leaf(local, 0x00ff_0000 + local);
                    apply_wal_entry(&mut store, &payload, height, &enc).expect("refill");
                }
            }
            let (changed, walked, _) = get(0);
            assert_eq!(
                walked, 1,
                "a sealed block whose rows changed must be read again"
            );
            assert_ne!(etag_of(&changed), etag);
            let changed = body_of(changed).await;
            let tail = usize::try_from(refill_from).expect("usize") * BC_INDEX_PREFIX_BYTES;
            assert_eq!(changed.slice(..tail), body.slice(..tail));
            assert_eq!(
                changed.slice(tail..tail + BC_INDEX_PREFIX_BYTES).to_vec(),
                fr(0x00ff_0000 + refill_from)
                    .into_iter()
                    .take(BC_INDEX_PREFIX_BYTES)
                    .collect::<Vec<_>>()
            );
            let (_, walked, rows) = get(0);
            assert_eq!((walked, rows), (0, 0));
        }

        /// A reorg that drops a middle row of a sealed block leaves its count and root unchanged.
        /// A process that kept the block's body must refuse it exactly as a fresh process does,
        /// not answer the pre-reorg bytes as immutable.
        #[tokio::test]
        async fn a_kept_sealed_body_is_refused_once_a_reorg_tears_the_block() {
            const DROPPED: u32 = 30_000;
            const DROPPED_AT: u64 = 5_000_000;
            let run: Vec<_> = (0..LEAVES_PER_PPOI_BLOCK)
                .map(|local| {
                    let (payload, height) = leaf(local, local);
                    (payload, if local == DROPPED { DROPPED_AT } else { height })
                })
                .collect();
            let mut seeded = LogicalLeafStore::new();
            seeded.seed_leaf_run(&run, &encoder()).expect("seed rows");
            let sealed = Arc::new(parking_lot::Mutex::new(seeded));
            let frontier = block_store(1, 3);
            let rows = u64::from(LEAVES_PER_PPOI_BLOCK) + 3;
            let stores = [Arc::clone(&sealed), Arc::clone(&frontier)];
            let kept = covered_app(&stores, rows);

            let first =
                serve_prefix_segment(&kept, LIST_KEY, 0, &HeaderMap::new()).expect("served");
            assert_eq!(first.status(), StatusCode::OK);

            let state = |store: &CoveredStore| {
                let guard = store.lock();
                let imt = guard.ppoi_imt(&LIST_KEY).expect("imt");
                (imt.leaf_count(), imt.root())
            };
            let before = state(&sealed);
            apply_wal_entry(
                &mut sealed.lock(),
                &WalEntryPayload::Reorg {
                    height: DROPPED_AT - 1,
                },
                DROPPED_AT - 1,
                &encoder(),
            )
            .expect("reorg");
            assert_eq!(
                state(&sealed),
                before,
                "the tear leaves count and root alone"
            );
            assert!(sealed.lock().ppoi_bc_at(&LIST_KEY, DROPPED).is_none());

            let fresh =
                serve_prefix_segment(&covered_app(&stores, rows), LIST_KEY, 0, &HeaderMap::new())
                    .map(|response| response.status());
            assert_eq!(fresh, Err(StatusCode::SERVICE_UNAVAILABLE));
            let repeat = serve_prefix_segment(&kept, LIST_KEY, 0, &HeaderMap::new())
                .map(|response| response.status());
            assert_eq!(repeat, fresh, "a kept body outlived the tear");
            let mid = serve_prefix_segment(&kept, LIST_KEY, 10, &HeaderMap::new())
                .map(|response| response.status());
            assert_eq!(mid, fresh);
        }

        /// A segment read holds a blocking-pool thread `/batch` also responds on, so past the
        /// pool's permits a request waits without starting a read.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn segment_reads_past_the_pool_wait_for_a_permit() {
            let store = block_store(0, 4);
            let app = covered_app(&[Arc::clone(&store)], 4);

            // Held on its own thread so every read that starts blocks on it.
            let (locked_tx, locked) = std::sync::mpsc::channel::<()>();
            let (release, released) = std::sync::mpsc::channel::<()>();
            let holder = {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    let _guard = store.lock();
                    let _ = locked_tx.send(());
                    let _ = released.recv();
                })
            };
            locked.recv().expect("store locked");

            let requests: Vec<_> = (0..=SEGMENT_READS_AT_ONCE)
                .map(|_| {
                    tokio::spawn(bc_prefix_segment_handler(
                        State(app.clone()),
                        Path(hex_encode(&LIST_KEY)),
                        Query(IndexSegmentQuery { since: None }),
                        HeaderMap::new(),
                    ))
                })
                .collect();
            until(|| registry(&app).segment_reads_now_and_peak().0 >= SEGMENT_READS_AT_ONCE).await;
            // Time for the request past the pool to start a read, if it could.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            assert_eq!(
                registry(&app).segment_reads_now_and_peak(),
                (SEGMENT_READS_AT_ONCE, SEGMENT_READS_AT_ONCE),
                "a read ran past the pool's permits"
            );

            release.send(()).expect("release");
            holder.join().expect("holder");
            for request in requests {
                let response = request.await.expect("joined").expect("served");
                assert_eq!(response.status(), StatusCode::OK);
            }
            assert_eq!(
                registry(&app).segment_reads_now_and_peak(),
                (0, SEGMENT_READS_AT_ONCE)
            );
        }
    }
}
