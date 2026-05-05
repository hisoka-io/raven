//! Wallet-facing PPOI passthrough routes (Railgun JSON shapes).
//!
//! Mirrors `getPOIsPerList` / `getPOIMerkleProofs` from upstream
//! `private-proof-of-innocence/packages/node/src/api/api.ts`.
//! Wallet privacy still requires client-side PIR via `/v1/instance/:id/query`.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{header::HeaderName, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use raven_railgun_core::{MerkleProof as CoreMerkleProof, POIStatus};
use raven_railgun_engine::inspire::LogicalLeafStore;
use raven_railgun_engine::PirScheme;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::AppState;

const ETAG_HEADER: HeaderName = HeaderName::from_static("etag");
const IF_NONE_MATCH_HEADER: HeaderName = HeaderName::from_static("if-none-match");
const CACHE_CONTROL_HEADER: HeaderName = HeaderName::from_static("cache-control");
const LAST_MODIFIED_HEADER: HeaderName = HeaderName::from_static("last-modified");

/// Hex-encoded 32-byte blob. No `0x` prefix (matches Railgun upstream).
type HexHash = String;

// Wallet-facing routes

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

/// Railgun-shaped Merkle proof JSON (`shared-models/proof-of-innocence.ts:28-33`).
#[derive(Debug, Clone, Serialize)]
pub struct MerkleProofJson {
    /// Blinded commitment hex for PPOI proofs; empty for commit-tree proofs.
    pub leaf: HexHash,
    /// Sibling-hash chain, leaf-to-root, 16 entries.
    pub elements: Vec<HexHash>,
    /// Leaf index as 32-byte big-endian hex (matches upstream `BigInt` → `nToHex(., 32)`).
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

pub(crate) async fn pois_per_list_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
    Json(req): Json<PoisPerListRequest>,
) -> Result<Json<PoisPerListMap>, StatusCode> {
    let store = app
        .logical_store
        .as_ref()
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let mut out: PoisPerListMap = PoisPerListMap::new();
    let store = store.lock();

    let list_keys: Vec<[u8; 32]> = req
        .list_keys
        .iter()
        .filter_map(|s| hex_decode_32(s))
        .collect();
    if list_keys.len() != req.list_keys.len() {
        return Err(StatusCode::BAD_REQUEST);
    }

    for bc_data in &req.blinded_commitment_datas {
        let bc = hex_decode_32(&bc_data.blinded_commitment).ok_or(StatusCode::BAD_REQUEST)?;
        let bc_hex = hex_encode(&bc);
        let mut per_list: std::collections::BTreeMap<HexHash, String> =
            std::collections::BTreeMap::new();
        for (list_key_hex, list_key) in req.list_keys.iter().zip(list_keys.iter()) {
            let status_str = match store.ppoi_status(list_key, &bc) {
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
    let store = app
        .logical_store
        .as_ref()
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let list_key = hex_decode_32(&req.list_key).ok_or(StatusCode::BAD_REQUEST)?;
    let store = store.lock();
    let mut proofs = Vec::with_capacity(req.blinded_commitments.len());
    for bc_hex in &req.blinded_commitments {
        let bc = hex_decode_32(bc_hex).ok_or(StatusCode::BAD_REQUEST)?;
        let idx = store
            .ppoi_index_of(&list_key, &bc)
            .ok_or(StatusCode::NOT_FOUND)?;
        let proof = store
            .ppoi_merkle_proof(&list_key, idx)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        proofs.push(MerkleProofJson::from_core(&proof, hex_encode(&bc)));
    }
    Ok(Json(proofs))
}

pub(crate) async fn commit_tree_proof_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
    Path(tree_number): Path<u32>,
    Json(req): Json<CommitTreeProofRequest>,
) -> Result<Json<MerkleProofJson>, StatusCode> {
    let store = app
        .logical_store
        .as_ref()
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
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

// Publishing channels

/// JSON shape returned by `GET /v1/poi/:list_key_hex/bc-to-idx-map`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BcToIdxMapResponse {
    /// Block height at time of snapshot.
    pub epoch: u64,
    /// Hex-encoded 32-byte list key.
    pub list_key: HexHash,
    /// `(blinded_commitment_hex, list_index)` rows in ascending index order.
    pub entries: Vec<BcIdxEntry>,
}

/// One row of the bc-to-idx publishing channel.
#[derive(Debug, Clone, Serialize)]
pub struct BcIdxEntry {
    /// Hex-encoded blinded commitment.
    pub bc: HexHash,
    /// List index.
    pub idx: u32,
}

/// JSON shape returned by `GET /v1/poi/:list_key_hex/status-header`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusHeaderResponse {
    /// Block height at time of snapshot.
    pub epoch: u64,
    /// Hex-encoded 32-byte list key.
    pub list_key: HexHash,
    /// Shield-blocked blinded commitments.
    pub blocked_bcs: Vec<HexHash>,
    /// Proof-submitted (pending) blinded commitments.
    pub pending_bcs: Vec<HexHash>,
}

pub(crate) async fn bc_to_idx_map_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
    Path(list_key_hex): Path<String>,
    headers_in: HeaderMap,
) -> Result<axum::response::Response, StatusCode> {
    let store = app
        .logical_store
        .as_ref()
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let list_key = hex_decode_32(&list_key_hex).ok_or(StatusCode::BAD_REQUEST)?;
    let (body, epoch) = {
        let store = store.lock();
        let entries: Vec<BcIdxEntry> = store
            .ppoi_list_leaves_iter(&list_key)
            .map(|(idx, bc)| BcIdxEntry {
                bc: hex_encode(bc),
                idx,
            })
            .collect();
        let resp = BcToIdxMapResponse {
            epoch: store.last_block_height(),
            list_key: hex_encode(&list_key),
            entries,
        };
        (resp, store.last_block_height())
    };
    serve_publishing_channel(&body, epoch, &headers_in)
}

pub(crate) async fn status_header_handler<S: PirScheme>(
    State(app): State<AppState<S>>,
    Path(list_key_hex): Path<String>,
    headers_in: HeaderMap,
) -> Result<axum::response::Response, StatusCode> {
    let store = app
        .logical_store
        .as_ref()
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let list_key = hex_decode_32(&list_key_hex).ok_or(StatusCode::BAD_REQUEST)?;
    let (body, epoch) = {
        let store = store.lock();
        let mut blocked: Vec<HexHash> = Vec::new();
        let mut pending: Vec<HexHash> = Vec::new();
        for (idx, bc) in store.ppoi_list_leaves_iter(&list_key) {
            match store.ppoi_status_at(&list_key, idx) {
                Some(b) if b == poi_status_byte(POIStatus::ShieldBlocked) => {
                    blocked.push(hex_encode(bc));
                }
                Some(b)
                    if b == poi_status_byte(POIStatus::ProofSubmitted)
                        || b == poi_status_byte(POIStatus::Missing) =>
                {
                    pending.push(hex_encode(bc));
                }
                _ => {}
            }
        }
        let resp = StatusHeaderResponse {
            epoch: store.last_block_height(),
            list_key: hex_encode(&list_key),
            blocked_bcs: blocked,
            pending_bcs: pending,
        };
        (resp, store.last_block_height())
    };
    serve_publishing_channel(&body, epoch, &headers_in)
}

fn poi_status_byte(s: POIStatus) -> u8 {
    match s {
        POIStatus::Valid => 0,
        POIStatus::ShieldBlocked => 1,
        POIStatus::ProofSubmitted => 2,
        POIStatus::Missing => 3,
    }
}

/// ETag + 304 short-circuit for publishing channels; ETag = SHA-256(body)[..16] hex.
fn serve_publishing_channel<T: Serialize>(
    body: &T,
    epoch: u64,
    headers_in: &HeaderMap,
) -> Result<axum::response::Response, StatusCode> {
    let json = serde_json::to_vec(body).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut hasher = Sha256::new();
    hasher.update(&json);
    let digest = hasher.finalize();
    let etag = {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(2 + 32);
        s.push('"');
        for b in digest.iter().take(16) {
            let _ = write!(s, "{b:02x}");
        }
        s.push('"');
        s
    };

    let if_none_match = headers_in
        .get(&IF_NONE_MATCH_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    if if_none_match == etag {
        let mut hdrs = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(&etag) {
            hdrs.insert(ETAG_HEADER, v);
        }
        return Ok((StatusCode::NOT_MODIFIED, hdrs).into_response());
    }

    let mut hdrs = HeaderMap::new();
    hdrs.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Ok(v) = HeaderValue::from_str(&etag) {
        hdrs.insert(ETAG_HEADER, v);
    }
    if let Ok(v) = HeaderValue::from_str(&epoch.to_string()) {
        hdrs.insert(LAST_MODIFIED_HEADER, v);
    }
    hdrs.insert(
        CACHE_CONTROL_HEADER,
        HeaderValue::from_static("public, max-age=15, must-revalidate"),
    );
    Ok((StatusCode::OK, hdrs, json).into_response())
}

/// Build the wallet-shim + publishing-channel router.
pub fn poi_shim_routes<S: PirScheme>(state: AppState<S>) -> axum::Router {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/v1/poi/pois-per-list", post(pois_per_list_handler::<S>))
        .route("/v1/poi/merkle-proofs", post(merkle_proofs_handler::<S>))
        .route(
            "/v1/commit-tree/:tree_number/merkle-proof",
            post(commit_tree_proof_handler::<S>),
        )
        .route(
            "/v1/poi/:list_key_hex/bc-to-idx-map",
            get(bc_to_idx_map_handler::<S>),
        )
        .route(
            "/v1/poi/:list_key_hex/status-header",
            get(status_header_handler::<S>),
        )
        .with_state(state)
}

/// Re-export for test fixtures that need to seed a [`LogicalLeafStore`].
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
}
