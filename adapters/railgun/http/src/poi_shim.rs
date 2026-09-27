//! Wallet-facing PPOI passthrough routes mirroring upstream
//! `private-proof-of-innocence/packages/node/src/api/api.ts`.
//!
//! These routes are NOT private; wallet privacy needs `/v1/instance/:id/query`.
//!
//! Two features publish the same index: `bc-prefixes` in per-block segments a client
//! resumes with `?since=`, `bc-to-idx-map` as 64-hex rows in one unbounded body.

use std::sync::Arc;

#[cfg(feature = "prefix-index-channel")]
use axum::extract::Query;
use axum::{
    extract::{Path, State},
    http::{header::HeaderName, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use bytes::Bytes;
use raven_railgun_core::{MerkleProof as CoreMerkleProof, POIStatus};
use raven_railgun_engine::inspire::LogicalLeafStore;
#[cfg(feature = "prefix-index-channel")]
use raven_railgun_engine::orchestrator::LEAVES_PER_PPOI_BLOCK;
use raven_railgun_engine::PirScheme;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(feature = "json-index-channel")]
use crate::shim_store::PublishedBody;
#[cfg(feature = "prefix-index-channel")]
use crate::shim_store::SegmentRefusal;
use crate::shim_store::{
    CoverageRefusal, ListCoverage, SharedLogicalStore as CoveredStore, ShimStoreRegistry,
    UpstreamTip,
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

/// Body for `POST /v1/poi/pois-per-list`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoisPerListRequest {
    /// Echoes `txidVersion`; accepted but not dispatched on.
    #[serde(default)]
    pub txid_version: Option<String>,
    /// List keys to query (hex-encoded 32-byte, no `0x`).
    pub list_keys: Vec<HexHash>,
    /// Blinded commitments to look up.
    pub blinded_commitment_datas: Vec<BlindedCommitmentData>,
}

/// One entry in [`PoisPerListRequest`], mirroring upstream `BlindedCommitmentData`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlindedCommitmentData {
    /// Hex-encoded 32-byte blinded commitment.
    pub blinded_commitment: HexHash,
    /// `Shield` / `Transact` / `Unshield`; carried for parity only.
    #[serde(default)]
    pub r#type: Option<String>,
}

/// Body for `POST /v1/poi/merkle-proofs`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MerkleProofsRequest {
    /// Optional txid version string (ignored server-side, present for upstream parity).
    #[serde(default)]
    pub txid_version: Option<String>,
    /// Hex-encoded 32-byte list key.
    pub list_key: HexHash,
    /// Hex-encoded blinded commitments to look up.
    pub blinded_commitments: Vec<HexHash>,
}

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
    /// Blinded commitment hex for PPOI proofs; empty for commit-tree proofs.
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

fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let pair = s.get(i * 2..i * 2 + 2)?;
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

fn poi_status_to_str(byte: u8) -> &'static str {
    match byte {
        0 => "Valid",
        1 => "ShieldBlocked",
        2 => "ProofSubmitted",
        _ => "Missing",
    }
}

type PoisPerListMap =
    std::collections::BTreeMap<HexHash, std::collections::BTreeMap<HexHash, String>>;

/// Element caps on the shim request vectors. These handlers hold the global
/// [`LogicalLeafStore`] mutex that block-commit also takes, so an oversized body
/// stalls the indexer; `pois-per-list` caps the vector product, not just each side.
const MAX_SHIM_LIST_KEYS: usize = 64;
const MAX_SHIM_BLINDED_COMMITMENTS: usize = 1024;
const MAX_SHIM_LOOKUP_PAIRS: usize = 16_384;

const POIS_PER_LIST_ROUTE: &str = "pois-per-list";
const MERKLE_PROOFS_ROUTE: &str = "merkle-proofs";
const COMMIT_TREE_PROOF_ROUTE: &str = "commit-tree-merkle-proof";
#[cfg(feature = "json-index-channel")]
const BC_TO_IDX_MAP_ROUTE: &str = "bc-to-idx-map";
const STATUS_HEADER_ROUTE: &str = "status-header";
#[cfg(feature = "prefix-index-channel")]
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
    if let Some(registry) = app.shim_stores.as_ref().as_ref() {
        return registry
            .prove_list_coverage(&list_key, upstream_tip(feeds, &list_key))
            .map_err(|refusal| refuse_uncovered(route, &refusal));
    }
    app.logical_store
        .as_ref()
        .as_ref()
        .map(|store| ListCoverage::undeclared(list_key, store))
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)
}

fn cover_tree<'a, S: PirScheme>(
    app: &'a AppState<S>,
    tree_number: u32,
    route: &'static str,
) -> Result<&'a CoveredStore, StatusCode> {
    if let Some(registry) = app.shim_stores.as_ref().as_ref() {
        return registry
            .prove_tree(tree_number)
            .map_err(|refusal| refuse_uncovered(route, &refusal));
    }
    app.logical_store
        .as_ref()
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)
}

pub(crate) async fn pois_per_list_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
    Json(req): Json<PoisPerListRequest>,
) -> Result<Json<PoisPerListMap>, StatusCode> {
    if req.list_keys.len() > MAX_SHIM_LIST_KEYS
        || req.blinded_commitment_datas.len() > MAX_SHIM_BLINDED_COMMITMENTS
        || req
            .list_keys
            .len()
            .saturating_mul(req.blinded_commitment_datas.len())
            > MAX_SHIM_LOOKUP_PAIRS
    {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let list_keys: Vec<[u8; 32]> = req
        .list_keys
        .iter()
        .filter_map(|s| hex_decode_32(s))
        .collect();
    if list_keys.len() != req.list_keys.len() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let blinded_commitments: Vec<[u8; 32]> = req
        .blinded_commitment_datas
        .iter()
        .filter_map(|d| hex_decode_32(&d.blinded_commitment))
        .collect();
    if blinded_commitments.len() != req.blinded_commitment_datas.len() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // "Missing" is a claim about the WHOLE list, so every requested list key has to be
    // covered before any of them is answered - a per-key partial answer is the same defect
    // spread across fewer rows.
    let mut out: PoisPerListMap = PoisPerListMap::new();
    let mut per_key_statuses: Vec<Vec<Option<u8>>> = Vec::with_capacity(list_keys.len());
    let feeds = read_mirror_feeds(&app);
    for list_key in &list_keys {
        let coverage = cover_list(&app, *list_key, POIS_PER_LIST_ROUTE, &feeds)?;
        per_key_statuses.push(coverage.statuses_of(&blinded_commitments));
        coverage
            .recheck_frontier()
            .map_err(|refusal| refuse_uncovered(POIS_PER_LIST_ROUTE, &refusal))?;
    }

    // Upstream echoes the caller's blindedCommitment verbatim (private-proof-of-innocence
    // poi-merkletree-manager.ts:216-219), and the engine indexes the reply with its own
    // `0x`-prefixed string where a miss is an unlogged `continue`. Re-keying here drops every row.
    for (position, data) in req.blinded_commitment_datas.iter().enumerate() {
        let bc_hex = data.blinded_commitment.clone();
        let mut per_list: std::collections::BTreeMap<HexHash, String> =
            std::collections::BTreeMap::new();
        for (list_key_hex, statuses) in req.list_keys.iter().zip(per_key_statuses.iter()) {
            let status_str = match statuses.get(position).copied().flatten() {
                Some(byte) => poi_status_to_str(byte),
                None => "Missing",
            };
            per_list.insert(list_key_hex.clone(), status_str.to_owned());
        }
        out.insert(bc_hex, per_list);
    }
    Ok(Json(out))
}

pub(crate) async fn merkle_proofs_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
    Json(req): Json<MerkleProofsRequest>,
) -> Result<Json<Vec<MerkleProofJson>>, StatusCode> {
    if req.blinded_commitments.len() > MAX_SHIM_BLINDED_COMMITMENTS {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let list_key = hex_decode_32(&req.list_key).ok_or(StatusCode::BAD_REQUEST)?;
    let blinded_commitments: Vec<[u8; 32]> = req
        .blinded_commitments
        .iter()
        .filter_map(|s| hex_decode_32(s))
        .collect();
    if blinded_commitments.len() != req.blinded_commitments.len() {
        return Err(StatusCode::BAD_REQUEST);
    }
    // The 404 below is an absence claim, so it needs the same whole-list proof the status
    // routes need: without it, "not in my block" is served as "not in the list".
    let coverage = cover_list(
        &app,
        list_key,
        MERKLE_PROOFS_ROUTE,
        &read_mirror_feeds(&app),
    )?;
    let mut proofs = Vec::with_capacity(blinded_commitments.len());
    for bc in &blinded_commitments {
        // The proof itself comes from the block that HOLDS the row: a block IMT is exactly
        // the tree upstream's `validatedMerkleroot` is taken over.
        let (store, local_index) = coverage.owner_of(bc).ok_or(StatusCode::NOT_FOUND)?;
        let proof = store
            .lock()
            .ppoi_merkle_proof(&list_key, local_index)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        proofs.push(MerkleProofJson::from_core(&proof, hex_encode(bc)));
    }
    coverage
        .recheck_frontier()
        .map_err(|refusal| refuse_uncovered(MERKLE_PROOFS_ROUTE, &refusal))?;
    Ok(Json(proofs))
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

/// JSON shape returned by `GET /v1/poi/:list_key_hex/bc-to-idx-map`.
#[cfg(feature = "json-index-channel")]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BcToIdxMapResponse {
    /// Lowest block height any covering store has applied; 0 for a mirrored PPOI list.
    pub epoch: u64,
    /// Hex-encoded 32-byte list key.
    pub list_key: HexHash,
    /// `(blinded_commitment_hex, list_index)` rows in ascending index order.
    pub entries: Vec<BcIdxEntry>,
}

/// One row of the bc-to-idx publishing channel.
#[cfg(feature = "json-index-channel")]
#[derive(Debug, Clone, Serialize)]
pub struct BcIdxEntry {
    /// Hex-encoded blinded commitment.
    pub bc: HexHash,
    /// List index.
    pub idx: u32,
}

/// Prefix width for the binary index channel.
pub const BC_INDEX_PREFIX_BYTES: usize = 6;

/// Largest body the index channel can emit: the list's size decides how many segments a
/// cold client walks, never how large one of them is.
#[cfg(feature = "prefix-index-channel")]
pub const BC_INDEX_SEGMENT_MAX_BYTES: usize =
    BC_INDEX_PREFIX_BYTES * LEAVES_PER_PPOI_BLOCK as usize;

/// Query string of `GET /v1/poi/:list_key_hex/bc-prefixes`.
#[cfg(feature = "prefix-index-channel")]
#[derive(Debug, Clone, Deserialize)]
pub struct IndexSegmentQuery {
    /// Global index to resume from. Absent means the head of the list.
    #[serde(default)]
    pub since: Option<u32>,
}

#[cfg(feature = "prefix-index-channel")]
pub(crate) async fn bc_prefix_segment_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
    Path(list_key_hex): Path<String>,
    Query(segment): Query<IndexSegmentQuery>,
    headers_in: HeaderMap,
) -> Result<axum::response::Response, StatusCode> {
    let list_key = hex_decode_32(&list_key_hex).ok_or(StatusCode::BAD_REQUEST)?;
    let since = segment.since.unwrap_or(0);
    off_executor(move || serve_prefix_segment(&app, list_key, since, &headers_in)).await
}

#[cfg(feature = "prefix-index-channel")]
fn serve_prefix_segment<S: PirScheme>(
    app: &AppState<S>,
    list_key: [u8; 32],
    since: u32,
    headers_in: &HeaderMap,
) -> Result<axum::response::Response, StatusCode> {
    let coverage = cover_list(app, list_key, BC_PREFIXES_ROUTE, &read_mirror_feeds(app))?;
    // Epoch before rows, so it never names a height whose rows are missing from the body.
    let epoch = coverage.epoch();
    let mut body = Vec::new();
    let segment = coverage.segment(since, |bc| {
        body.extend(bc.iter().copied().take(BC_INDEX_PREFIX_BYTES));
    });
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

    let etag = body_etag(&body);
    Ok(serve_publishing_bytes(
        Bytes::from(body),
        &etag,
        last_modified,
        headers_in,
        HeaderValue::from_static("application/octet-stream"),
        &extra,
    ))
}

/// JSON shape returned by `GET /v1/poi/:list_key_hex/status-header`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusHeaderResponse {
    /// Lowest block height any covering store has applied; 0 for a mirrored PPOI list.
    pub epoch: u64,
    /// Hex-encoded 32-byte list key.
    pub list_key: HexHash,
    /// Shield-blocked blinded commitments.
    pub blocked_bcs: Vec<HexHash>,
    /// Proof-submitted (pending) blinded commitments.
    pub pending_bcs: Vec<HexHash>,
}

#[cfg(feature = "json-index-channel")]
pub(crate) async fn bc_to_idx_map_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
    Path(list_key_hex): Path<String>,
    headers_in: HeaderMap,
) -> Result<axum::response::Response, StatusCode> {
    let list_key = hex_decode_32(&list_key_hex).ok_or(StatusCode::BAD_REQUEST)?;
    let (kept_app, kept_headers) = (app.clone(), headers_in.clone());
    if let Some(response) =
        off_executor(move || serve_index_map(&kept_app, list_key, &kept_headers, false)).await?
    {
        return Ok(response);
    }
    // The requests queued here are answered from the body the read ahead of them kept, unless
    // the list moved again in between.
    let permit = read_permit(&app, ShimStoreRegistry::index_map_reads).await?;
    off_executor(move || {
        let _permit = permit;
        serve_index_map(&app, list_key, &headers_in, true)
    })
    .await?
    .ok_or(StatusCode::INTERNAL_SERVER_ERROR)
}

/// `None` when the list moved since its body was kept and `may_read` is false.
#[cfg(feature = "json-index-channel")]
fn serve_index_map<S: PirScheme>(
    app: &AppState<S>,
    list_key: [u8; 32],
    headers_in: &HeaderMap,
    may_read: bool,
) -> Result<Option<axum::response::Response>, StatusCode> {
    let refuse = |refusal: CoverageRefusal| refuse_uncovered(BC_TO_IDX_MAP_ROUTE, &refusal);
    let coverage = cover_list(app, list_key, BC_TO_IDX_MAP_ROUTE, &read_mirror_feeds(app))?;
    // Uncredentialed, pollable and sized by the list, so an unchanged list is answered from the
    // body its last read kept, a matching revalidation included; only a moved list is read again.
    let fingerprint = coverage.fingerprint().map_err(refuse)?;
    if let Some(kept) = coverage.published_index_map(&fingerprint) {
        coverage.recheck_frontier().map_err(refuse)?;
        return Ok(Some(serve_publishing_bytes(
            kept.body,
            &kept.etag,
            Some(fingerprint.epoch()),
            headers_in,
            HeaderValue::from_static("application/json"),
            &[],
        )));
    }
    if !may_read {
        return Ok(None);
    }
    let mut rows: Vec<(u32, [u8; 32])> = Vec::new();
    let read = coverage
        .read_list(false, |leaf| {
            rows.push((leaf.global_index, leaf.blinded_commitment));
        })
        .map_err(refuse)?;
    coverage.recheck_frontier().map_err(refuse)?;
    let body = BcToIdxMapResponse {
        epoch: read.epoch(),
        list_key: hex_encode(&list_key),
        // GLOBAL index: the client resolves a PIR row from it, and the router localizes with
        // `% 65_536` on the way in, so a block-local index here would collide six ways.
        entries: rows
            .iter()
            .map(|(idx, bc)| BcIdxEntry {
                bc: hex_encode(bc),
                idx: *idx,
            })
            .collect(),
    };
    drop(rows);
    let json =
        Bytes::from(serde_json::to_vec(&body).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?);
    drop(body);
    let etag = body_etag(&json);
    let epoch = read.epoch();
    coverage.publish_index_map(
        read,
        PublishedBody {
            etag: etag.clone(),
            body: json.clone(),
        },
    );
    Ok(Some(serve_publishing_bytes(
        json,
        &etag,
        Some(epoch),
        headers_in,
        HeaderValue::from_static("application/json"),
        &[],
    )))
}

pub(crate) async fn status_header_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
    Path(list_key_hex): Path<String>,
    headers_in: HeaderMap,
) -> Result<axum::response::Response, StatusCode> {
    let list_key = hex_decode_32(&list_key_hex).ok_or(StatusCode::BAD_REQUEST)?;
    // No fingerprint covers statuses, so every answer, a 304 included, reads the whole list.
    let permit = read_permit(&app, ShimStoreRegistry::status_header_reads).await?;
    off_executor(move || {
        let _permit = permit;
        serve_status_header(&app, list_key, &headers_in)
    })
    .await
}

fn serve_status_header<S: PirScheme>(
    app: &AppState<S>,
    list_key: [u8; 32],
    headers_in: &HeaderMap,
) -> Result<axum::response::Response, StatusCode> {
    // Both fields are SETS over the list; a partial store silently shrinks the blocked set,
    // which reads as "nothing is blocked".
    let coverage = cover_list(app, list_key, STATUS_HEADER_ROUTE, &read_mirror_feeds(app))?;
    let blocked_byte = poi_status_byte(POIStatus::ShieldBlocked);
    let pending_bytes = [
        poi_status_byte(POIStatus::ProofSubmitted),
        poi_status_byte(POIStatus::Missing),
    ];
    let mut blocked: Vec<[u8; 32]> = Vec::new();
    let mut pending: Vec<[u8; 32]> = Vec::new();
    let read = coverage
        .read_list(true, |leaf| match leaf.status {
            Some(b) if b == blocked_byte => blocked.push(leaf.blinded_commitment),
            Some(b) if pending_bytes.contains(&b) => pending.push(leaf.blinded_commitment),
            _ => {}
        })
        .map_err(|refusal| refuse_uncovered(STATUS_HEADER_ROUTE, &refusal))?;
    coverage
        .recheck_frontier()
        .map_err(|refusal| refuse_uncovered(STATUS_HEADER_ROUTE, &refusal))?;
    let body = StatusHeaderResponse {
        epoch: read.epoch(),
        list_key: hex_encode(&list_key),
        blocked_bcs: blocked.iter().map(hex_encode).collect(),
        pending_bcs: pending.iter().map(hex_encode).collect(),
    };
    serve_publishing_channel(&body, read.epoch(), headers_in)
}

fn poi_status_byte(s: POIStatus) -> u8 {
    s.wire_byte()
}

/// The publishing channels read up to a whole list under store locks the ingest path also takes,
/// so they run on the blocking pool rather than stall the executor every other route shares.
async fn off_executor<T, F>(work: F) -> Result<T, StatusCode>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, StatusCode> + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// A permit from the registry pool `pick` names, held for the whole read. The undeclared
/// single-store path has no registry and no production caller, so it takes none.
async fn read_permit<S: PirScheme>(
    app: &AppState<S>,
    pick: fn(&ShimStoreRegistry) -> &Arc<tokio::sync::Semaphore>,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, StatusCode> {
    let Some(registry) = app.shim_stores.as_ref().as_ref() else {
        return Ok(None);
    };
    let pool = Arc::clone(pick(registry));
    pool.acquire_owned()
        .await
        .map(Some)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

/// ETag + 304 short-circuit for publishing channels; ETag = SHA-256(body)[..16] hex.
fn serve_publishing_channel<T: Serialize>(
    body: &T,
    epoch: u64,
    headers_in: &HeaderMap,
) -> Result<axum::response::Response, StatusCode> {
    let json = serde_json::to_vec(body).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let etag = body_etag(&json);
    Ok(serve_publishing_bytes(
        Bytes::from(json),
        &etag,
        Some(epoch),
        headers_in,
        HeaderValue::from_static("application/json"),
        &[],
    ))
}

/// Quoted SHA-256(body)[..16] hex.
fn body_etag(body: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(body);
    let mut etag = String::with_capacity(2 + 32);
    etag.push('"');
    for b in digest.iter().take(16) {
        let _ = write!(etag, "{b:02x}");
    }
    etag.push('"');
    etag
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
    body: Bytes,
    etag: &str,
    last_modified: Option<u64>,
    headers_in: &HeaderMap,
    content_type: HeaderValue,
    extra: &[(HeaderName, HeaderValue)],
) -> axum::response::Response {
    if if_none_match(headers_in) == Some(etag) {
        return not_modified(etag, extra);
    }

    let mut hdrs = HeaderMap::new();
    hdrs.insert(axum::http::header::CONTENT_TYPE, content_type);
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

/// Build the wallet-shim + publishing-channel router.
pub fn poi_shim_routes<S: PirScheme>(state: AppState<S>) -> axum::Router {
    use axum::routing::{get, post};
    let router = axum::Router::new()
        .route("/v1/poi/pois-per-list", post(pois_per_list_handler::<S>))
        .route("/v1/poi/merkle-proofs", post(merkle_proofs_handler::<S>))
        .route(
            "/v1/commit-tree/:tree_number/merkle-proof",
            post(commit_tree_proof_handler::<S>),
        )
        .route(
            "/v1/poi/:list_key_hex/status-header",
            get(status_header_handler::<S>),
        );
    #[cfg(feature = "json-index-channel")]
    let router = router.route(
        "/v1/poi/:list_key_hex/bc-to-idx-map",
        get(bc_to_idx_map_handler::<S>),
    );
    #[cfg(feature = "prefix-index-channel")]
    let router = router.route(
        "/v1/poi/:list_key_hex/bc-prefixes",
        get(bc_prefix_segment_handler::<S>),
    );
    router.with_state(state)
}

/// Re-exported so fixtures can seed a [`LogicalLeafStore`].
pub use raven_railgun_engine::inspire::apply_wal_entry as apply_wal_entry_for_test;

/// `Arc<Mutex<LogicalLeafStore>>` alias for passing to [`AppState`].
pub type SharedLogicalStore = Arc<parking_lot::Mutex<LogicalLeafStore>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_round_trips() {
        let bytes = [0xab; 32];
        let s = hex_encode(&bytes);
        assert_eq!(s.len(), 64);
        assert_eq!(hex_decode_32(&s), Some(bytes));
    }

    #[test]
    fn hex_decode_rejects_short_input() {
        assert!(hex_decode_32("ab").is_none());
    }

    #[test]
    fn hex_decode_accepts_optional_0x_prefix() {
        let bytes = [0x12; 32];
        let with_prefix = format!("0x{}", hex_encode(&bytes));
        assert_eq!(hex_decode_32(&with_prefix), Some(bytes));
    }

    #[test]
    fn indices_hex_zero_pads_to_32_bytes() {
        let s = indices_to_hex(0x0102);
        assert_eq!(s.len(), 64);
        assert!(s.starts_with("0000"));
        assert!(s.ends_with("0102"));
    }

    #[test]
    fn poi_status_byte_round_trips_each_variant() {
        assert_eq!(poi_status_byte(POIStatus::Valid), 0);
        assert_eq!(poi_status_byte(POIStatus::ShieldBlocked), 1);
        assert_eq!(poi_status_byte(POIStatus::ProofSubmitted), 2);
        assert_eq!(poi_status_byte(POIStatus::Missing), 3);
    }

    mod publishing_reads {
        use super::super::*;
        use crate::shim_store::STATUS_HEADER_READS_AT_ONCE;
        use crate::status::{MirrorFeedState, MirrorFeedView};
        use crate::HttpConfig;
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

        fn fr(seed: u32) -> [u8; 32] {
            let mut out = [0u8; 32];
            out[20] = 0x01;
            out[28..].copy_from_slice(&seed.to_be_bytes());
            out
        }

        fn append(store: &SharedLogicalStore, local_indices: std::ops::Range<u32>) {
            let enc = PerLeafCommitmentEncoder::new(32, 65_536, 0).expect("encoder");
            let mut guard = store.lock();
            for local in local_indices {
                apply_wal_entry_for_test(
                    &mut guard,
                    &WalEntryPayload::PpoiListLeafAdded {
                        list_key: LIST_KEY,
                        list_index: local,
                        blinded_commitment: fr(local),
                        status: 0,
                        event_type: raven_railgun_persistence::PpoiEventType::Shield,
                        signature: vec![0; 64],
                        validated_merkleroot: [0; 32],
                    },
                    1_000 + u64::from(local),
                    &enc,
                )
                .expect("seed ppoi leaf");
            }
        }

        fn store_with(rows: u32) -> SharedLogicalStore {
            let store: SharedLogicalStore =
                Arc::new(parking_lot::Mutex::new(LogicalLeafStore::new()));
            append(&store, 0..rows);
            store
        }

        /// One declared block holding `rows` rows, with upstream counting exactly that many.
        fn covered_app(store: &SharedLogicalStore, rows: u64) -> AppState<StubScheme> {
            // The recorder install loses a race to a concurrent winner until the winner has
            // published its handle, so wait a bounded while for one before building state on it.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while crate::global_prometheus_handle().is_err() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "no metrics recorder handle within 10 s"
                );
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let view = MirrorFeedView {
                list_key: hex_encode(&LIST_KEY),
                state: MirrorFeedState::Syncing,
                rows_held: rows,
                upstream_rows: Some(rows),
                next_index: rows,
                consecutive_failures: 0,
                last_failure: None,
                seconds_since_answer: Some(0),
            };
            AppState::new(
                Engine::<StubScheme>::new(),
                HttpConfig::demo("shim-unit-test-token"),
            )
            .expect("appstate")
            .with_shim_stores([(
                DataSourceFilter::PpoiListBlock {
                    list_key: LIST_KEY,
                    block: 0,
                },
                Arc::clone(store),
            )])
            .with_mirror_feeds(Arc::new(move || vec![view.clone()]))
        }

        fn registry(app: &AppState<StubScheme>) -> &ShimStoreRegistry {
            app.shim_stores.as_ref().as_ref().expect("registry")
        }

        #[cfg(feature = "json-index-channel")]
        fn revalidating(etag: &str) -> HeaderMap {
            let mut headers = HeaderMap::new();
            headers.insert(
                IF_NONE_MATCH_HEADER,
                HeaderValue::from_str(etag).expect("etag"),
            );
            headers
        }

        #[cfg(feature = "json-index-channel")]
        fn etag_of(response: &axum::response::Response) -> String {
            response
                .headers()
                .get(ETAG_HEADER)
                .and_then(|v| v.to_str().ok())
                .expect("etag")
                .to_owned()
        }

        #[cfg(feature = "json-index-channel")]
        async fn body_of(response: axum::response::Response) -> Bytes {
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body")
        }

        /// Poll `done` for up to ten seconds; the interleavings below are staged, not timed.
        #[cfg(feature = "json-index-channel")]
        async fn until(mut done: impl FnMut() -> bool) {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !done() {
                assert!(std::time::Instant::now() < deadline, "stage never reached");
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        }

        /// The channel is uncredentialed and pollable, so an unchanged list is answered from the
        /// body its last read kept, a matching revalidation and a repeat 200 alike; a list that
        /// moved since is read again.
        #[cfg(feature = "json-index-channel")]
        #[tokio::test]
        async fn an_unchanged_list_is_answered_without_a_read_and_a_moved_list_is_read_again() {
            let store = store_with(4);
            let app = covered_app(&store, 4);
            let serve = |headers: &HeaderMap, may_read| {
                serve_index_map(&app, LIST_KEY, headers, may_read)
                    .expect("served")
                    .expect("answered")
            };

            let first = serve(&HeaderMap::new(), true);
            assert_eq!(first.status(), StatusCode::OK);
            let etag = etag_of(&first);
            let first_body = body_of(first).await;
            assert_eq!(registry(&app).list_reads(), 1);

            for _ in 0..3 {
                let again = serve(&revalidating(&etag), false);
                assert_eq!(again.status(), StatusCode::NOT_MODIFIED);
                assert_eq!(etag_of(&again), etag);
            }
            let repeat = serve(&revalidating("\"not-it\""), false);
            assert_eq!(repeat.status(), StatusCode::OK);
            assert_eq!(etag_of(&repeat), etag);
            assert_eq!(body_of(repeat).await, first_body);
            assert_eq!(
                registry(&app).list_reads(),
                1,
                "an unchanged list must be answered before it is read"
            );

            append(&store, 4..5);
            assert!(
                serve_index_map(&app, LIST_KEY, &revalidating(&etag), false)
                    .expect("served")
                    .is_none(),
                "a list that grew must not revalidate against its old body"
            );
            let moved = serve(&revalidating(&etag), true);
            assert_eq!(moved.status(), StatusCode::OK);
            assert_ne!(etag_of(&moved), etag);
            assert_eq!(registry(&app).list_reads(), 2);
        }

        /// A 200 costs a whole-list read and a body sized by the list, so requests that find no
        /// kept body queue for one read at a time and the ones behind it are answered from what
        /// it kept. Every request below misses before the first read is let through.
        #[cfg(feature = "json-index-channel")]
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn requests_queued_behind_a_read_are_answered_from_its_body() {
            const REQUESTS: usize = 8;
            let store = store_with(4);
            let app = covered_app(&store, 4);
            let held = Arc::clone(registry(&app).index_map_reads())
                .acquire_owned()
                .await
                .expect("permit");

            let walked_before = registry(&app).blocks_walked();
            let requests: Vec<_> = (0..REQUESTS)
                .map(|_| {
                    tokio::spawn(bc_to_idx_map_handler(
                        State(app.clone()),
                        Path(hex_encode(&LIST_KEY)),
                        HeaderMap::new(),
                    ))
                })
                .collect();
            // One block walked per request is each request's fingerprint missing the empty cache.
            until(|| registry(&app).blocks_walked() - walked_before >= REQUESTS).await;
            assert_eq!(registry(&app).list_reads(), 0);
            drop(held);

            let mut etags = std::collections::BTreeSet::new();
            for request in requests {
                let response = request.await.expect("joined").expect("served");
                assert_eq!(response.status(), StatusCode::OK);
                etags.insert(etag_of(&response));
            }
            assert_eq!(etags.len(), 1);
            assert_eq!(
                registry(&app).list_reads(),
                1,
                "requests queued behind a read must be answered from its body"
            );
        }

        /// No fingerprint covers statuses, so each status answer reads the whole list; past the
        /// pool's permits a request waits rather than start another read.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_status_read_past_the_pool_waits_for_a_permit() {
            let store = store_with(4);
            let app = covered_app(&store, 4);
            let pool = Arc::clone(registry(&app).status_header_reads());
            let held = pool
                .acquire_many_owned(
                    u32::try_from(STATUS_HEADER_READS_AT_ONCE).expect("permit count"),
                )
                .await
                .expect("permits");

            let request = tokio::spawn(status_header_handler(
                State(app.clone()),
                Path(hex_encode(&LIST_KEY)),
                HeaderMap::new(),
            ));
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            assert!(!request.is_finished(), "a read ran with every permit held");
            assert_eq!(registry(&app).list_reads(), 0);

            drop(held);
            let response = request.await.expect("joined").expect("served");
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(registry(&app).list_reads(), 1);
        }
    }
}
