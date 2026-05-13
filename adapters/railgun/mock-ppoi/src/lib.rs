//! SYNTHETIC PPOI surface impersonator.
//!
//! Stands in for the upstream Railway PPOI service so the adapter's
//! mirror worker can populate empty PPOI instances during the public
//! demo. The corpus is generated deterministically from a seed and
//! tagged as Valid by default; an optional CSV file lets the operator
//! flip specific blinded commitments to ShieldBlocked for the
//! leak-vs-no-leak demo contrast.
//!
//! NEVER deploy this crate to production. The data is synthetic. The
//! signing key is freshly generated at startup. There is no list
//! authority. The adapter does not verify upstream signatures, which
//! is what makes this stand-in functionally adequate for the demo
//! pipeline; treating its output as authoritative would conflate
//! real-OFAC data with a synthetic corpus.
//!
//! The wire shape mirrors the upstream contract verified at
//! `clones/railgun-research/repo-cache/private-proof-of-innocence/packages/node/src/api/schemas.ts`
//! and `models/poi-types.ts` — `POST /poi-events/{chainType}/{chainID}`
//! returns `Vec<POISyncedListEvent>` and
//! `POST /pois-per-blinded-commitment/{chainType}/{chainID}` returns a
//! `{[bc]: POIStatus}` map.

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]
#![deny(missing_docs)]

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use parking_lot::RwLock;
use raven_railgun_core::{ListKey, POIStatus};
use raven_railgun_engine::imt::Imt;
use raven_railgun_poseidon::hash_n;
use serde::{Deserialize, Serialize};

/// Default corpus size when the operator does not pass `--corpus-size`.
pub const DEFAULT_CORPUS_SIZE: u32 = 1_000;

/// Default deterministic corpus seed (32 bytes hex, no `0x` prefix).
pub const DEFAULT_CORPUS_SEED_HEX: &str =
    "deadbeefcafebabefacefeed0123456789abcdef0123456789abcdef00112233";

/// Production OFAC list key matching the canonical Railgun mainnet PPOI list.
pub const DEFAULT_LIST_KEY_HEX: &str =
    "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";

/// Distinct startup banner. Tests assert this fires so stale binaries
/// without the synthetic-tag log can never silently pass for real
/// upstream feeds.
pub const SYNTHETIC_BANNER: &str =
    "raven-railgun-mock-ppoi: SYNTHETIC corpus, do not pass off as real OFAC";

/// Error surface for the mock PPOI service.
#[derive(thiserror::Error, Debug)]
pub enum MockError {
    /// Hex-decode of operator-supplied input failed.
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    /// Filesystem-level CSV read failed.
    #[error("csv read: {0}")]
    CsvRead(String),
    /// Underlying engine error from the per-list IMT.
    #[error("imt: {0}")]
    Imt(String),
    /// Poseidon hash construction failed (should be impossible for
    /// canonical 32-byte inputs).
    #[error("poseidon: {0}")]
    Poseidon(String),
    /// TCP bind / accept failed.
    #[error("bind: {0}")]
    Bind(String),
}

/// Convenience type alias for fallible operations within this crate.
pub type Result<T> = core::result::Result<T, MockError>;

/// Synthetic PPOI corpus state, materialised once at startup.
///
/// The corpus is `(blinded_commitment, status, validatedMerkleroot)`
/// triples ordered by their list-index, plus a lookup map
/// `bc -> (index, status)` for the per-bc query endpoint.
#[derive(Debug)]
pub struct Corpus {
    list_key_bytes: [u8; 32],
    list_key_hex: String,
    events: Vec<SyntheticEvent>,
    by_bc: HashMap<[u8; 32], (u32, POIStatus)>,
}

/// Public accessor row for an entry in the synthetic corpus. Tests
/// and integrations consume this via [`Corpus::events_view`] without
/// needing to reach into private fields.
#[derive(Clone, Copy, Debug)]
pub struct SyntheticEvent {
    /// List-index assigned by the corpus generator (monotone from 0).
    pub index: u32,
    /// 32-byte blinded commitment (Poseidon-derived).
    pub blinded_commitment: [u8; 32],
    /// Status as the corpus reports it (`Valid` by default; CSV
    /// overrides flip selected BCs to `ShieldBlocked`).
    pub status: POIStatus,
    /// Per-list IMT root after this event was inserted.
    pub validated_merkleroot: [u8; 32],
}

/// Configuration for [`Corpus::generate`].
#[derive(Clone, Debug)]
pub struct CorpusConfig {
    /// 32-byte list identifier embedded in deterministic BC hashing.
    pub list_key: [u8; 32],
    /// 32-byte deterministic seed for the corpus generator.
    pub seed: [u8; 32],
    /// Number of synthetic blinded commitments to emit.
    pub size: u32,
    /// Optional override-set: BCs that should report `ShieldBlocked`
    /// instead of the default `Valid`.
    pub blocked: Vec<[u8; 32]>,
}

impl Corpus {
    /// Deterministically construct a synthetic corpus.
    ///
    /// Each blinded commitment is `Poseidon(seed, i, list_key)` with
    /// inputs encoded as 32-byte big-endian field elements (the same
    /// circomlibjs convention the rest of the adapter uses). The
    /// `validatedMerkleroot` for event `i` is the post-insert root of
    /// a per-list IMT built incrementally; the spec requires roots to
    /// strictly advance as events accrue.
    ///
    /// # Errors
    ///
    /// Returns [`MockError::Poseidon`] if a deterministic input falls
    /// outside the BN254 scalar field (in practice never; we mask the
    /// high bits of each input below `Fr::MODULUS`). Returns
    /// [`MockError::Imt`] if leaf insertion ever fails (also unreachable
    /// for canonical inputs but surfaced as a typed error rather than
    /// a panic).
    pub fn generate(config: CorpusConfig) -> Result<Self> {
        let CorpusConfig {
            list_key,
            seed,
            size,
            blocked,
        } = config;

        let blocked_set: std::collections::HashSet<[u8; 32]> = blocked.into_iter().collect();
        let mut imt = Imt::new().map_err(|e| MockError::Imt(format!("imt new: {e}")))?;
        let size_us = usize::try_from(size).unwrap_or(usize::MAX);
        let mut events = Vec::with_capacity(size_us);
        let mut by_bc = HashMap::with_capacity(size_us);

        for i in 0..size {
            let bc = derive_blinded_commitment(&seed, i, &list_key)?;
            let leaf_idx = usize::try_from(i).unwrap_or(usize::MAX);
            imt.insert_leaves(leaf_idx, &[bc])
                .map_err(|e| MockError::Imt(format!("insert {i}: {e}")))?;
            let validated_merkleroot = imt.root();
            let status = if blocked_set.contains(&bc) {
                POIStatus::ShieldBlocked
            } else {
                POIStatus::Valid
            };
            by_bc.insert(bc, (i, status));
            events.push(SyntheticEvent {
                index: i,
                blinded_commitment: bc,
                status,
                validated_merkleroot,
            });
        }

        Ok(Self {
            list_key_bytes: list_key,
            list_key_hex: hex_lower(&list_key),
            events,
            by_bc,
        })
    }

    /// Return the events in `[start, end)` clamped to the corpus span.
    fn events_range(&self, start: u32, end: u32) -> &[SyntheticEvent] {
        let len = self.events.len();
        let start_us = usize::try_from(start).unwrap_or(usize::MAX).min(len);
        let end_us = usize::try_from(end).unwrap_or(usize::MAX).min(len);
        if end_us <= start_us {
            return &[];
        }
        self.events.get(start_us..end_us).unwrap_or(&[])
    }

    /// Look up the status of a single blinded commitment. Returns
    /// `Missing` if the BC is not in the synthetic corpus.
    fn status_for(&self, bc: &[u8; 32]) -> POIStatus {
        self.by_bc
            .get(bc)
            .map_or(POIStatus::Missing, |(_, status)| *status)
    }

    /// Borrow the configured list key as raw bytes.
    #[must_use]
    pub fn list_key_bytes(&self) -> [u8; 32] {
        self.list_key_bytes
    }

    /// Number of events currently in the corpus.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the corpus is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Borrow the full event log in deterministic order.
    #[must_use]
    pub fn events_view(&self) -> &[SyntheticEvent] {
        &self.events
    }
}

/// Derive `Poseidon(seed, i_be, list_key)` for a single corpus row.
fn derive_blinded_commitment(seed: &[u8; 32], index: u32, list_key: &[u8; 32]) -> Result<[u8; 32]> {
    let mut index_be = [0u8; 32];
    index_be[28..].copy_from_slice(&index.to_be_bytes());
    // light-poseidon enforces canonical Fr inputs. Mask the most
    // significant 4 bits of seed and list_key copies so any operator-
    // supplied seed reduces deterministically below the BN254 modulus
    // without surfacing as an error.
    let seed_masked = mask_to_fr(seed);
    let list_key_masked = mask_to_fr(list_key);
    hash_n(&[seed_masked, index_be, list_key_masked])
        .map_err(|e| MockError::Poseidon(format!("hash_n: {e}")))
}

/// Clear the top 4 bits so the resulting big-endian buffer is always
/// below the BN254 scalar modulus (`p` has its top byte = 0x30, so
/// masking to 0x0F leaves headroom).
fn mask_to_fr(input: &[u8; 32]) -> [u8; 32] {
    let mut out = *input;
    if let Some(byte) = out.first_mut() {
        *byte &= 0x0F;
    }
    out
}

/// Application state shared across axum handlers.
#[derive(Clone, Debug)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

#[derive(Debug)]
struct AppStateInner {
    corpus: RwLock<Arc<Corpus>>,
    list_key_hex: String,
}

impl AppState {
    /// Build the application state from a pre-generated corpus.
    #[must_use]
    pub fn new(corpus: Corpus) -> Self {
        let list_key_hex = corpus.list_key_hex.clone();
        Self {
            inner: Arc::new(AppStateInner {
                corpus: RwLock::new(Arc::new(corpus)),
                list_key_hex,
            }),
        }
    }

    /// Borrow the underlying corpus for tests / assertions.
    #[must_use]
    pub fn corpus(&self) -> Arc<Corpus> {
        self.inner.corpus.read().clone()
    }
}

/// Build the axum router serving the upstream PPOI surface.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/poi-events/:chain_type/:chain_id", post(handle_poi_events))
        .route(
            "/pois-per-blinded-commitment/:chain_type/:chain_id",
            post(handle_pois_per_blinded_commitment),
        )
        .route("/node-status-v2", get(handle_node_status_root))
        .route("/node-status-v2/:list_key", get(handle_node_status_list))
        .with_state(state)
}

/// Bind to `addr` and serve the router until the future is dropped.
///
/// # Errors
///
/// Returns [`MockError::Bind`] if the TCP bind fails or if `axum::serve`
/// errors during the accept loop.
pub async fn serve(addr: SocketAddr, state: AppState) -> Result<()> {
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| MockError::Bind(format!("bind {addr}: {e}")))?;
    tracing::info!(%addr, "{SYNTHETIC_BANNER}");
    axum::serve(listener, app)
        .await
        .map_err(|e| MockError::Bind(format!("serve: {e}")))
}

/// Bind to `addr` (resolving port-zero to an OS-chosen port) and return
/// the listener alongside the bound `SocketAddr`. Used by integration
/// tests so they can spawn the service on a dynamic port without
/// racing on a hard-coded one.
///
/// # Errors
///
/// Returns [`MockError::Bind`] if the TCP bind fails or the resulting
/// local-address read fails.
pub async fn bind_listener(addr: SocketAddr) -> Result<(tokio::net::TcpListener, SocketAddr)> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| MockError::Bind(format!("bind {addr}: {e}")))?;
    let local = listener
        .local_addr()
        .map_err(|e| MockError::Bind(format!("local_addr: {e}")))?;
    Ok((listener, local))
}

/// Serve `state` on a pre-bound listener. Pairs with [`bind_listener`].
///
/// # Errors
///
/// Returns [`MockError::Bind`] if the axum accept loop errors.
pub async fn serve_on(listener: tokio::net::TcpListener, state: AppState) -> Result<()> {
    let app = build_router(state);
    tracing::info!("{SYNTHETIC_BANNER}");
    axum::serve(listener, app)
        .await
        .map_err(|e| MockError::Bind(format!("serve: {e}")))
}

#[derive(Debug, Deserialize)]
struct PoiEventsRequestBody {
    #[serde(rename = "txidVersion")]
    _txid_version: String,
    #[serde(rename = "listKey")]
    list_key: String,
    #[serde(rename = "startIndex")]
    start_index: u32,
    #[serde(rename = "endIndex")]
    end_index: u32,
}

#[derive(Debug, Serialize)]
struct WireSignedPoiEvent {
    index: u32,
    #[serde(rename = "blindedCommitment")]
    blinded_commitment: String,
    signature: String,
    #[serde(rename = "type")]
    event_type: &'static str,
}

#[derive(Debug, Serialize)]
struct WirePoiSyncedListEvent {
    #[serde(rename = "signedPOIEvent")]
    signed_event: WireSignedPoiEvent,
    #[serde(rename = "validatedMerkleroot")]
    validated_merkleroot: String,
}

async fn handle_poi_events(
    AxumPath((_chain_type, _chain_id)): AxumPath<(String, String)>,
    State(state): State<AppState>,
    Json(body): Json<PoiEventsRequestBody>,
) -> impl IntoResponse {
    let corpus = state.inner.corpus.read().clone();
    let list_matches = body.list_key.eq_ignore_ascii_case(&corpus.list_key_hex)
        || body
            .list_key
            .strip_prefix("0x")
            .is_some_and(|rest| rest.eq_ignore_ascii_case(&corpus.list_key_hex));
    if !list_matches {
        tracing::debug!(
            request_list = %body.list_key,
            corpus_list = %corpus.list_key_hex,
            "poi-events list_key mismatch; returning empty event vector"
        );
        return Json(Vec::<WirePoiSyncedListEvent>::new()).into_response();
    }
    let events = corpus.events_range(body.start_index, body.end_index);
    let wire: Vec<WirePoiSyncedListEvent> = events
        .iter()
        .map(|event| WirePoiSyncedListEvent {
            signed_event: WireSignedPoiEvent {
                index: event.index,
                blinded_commitment: hex_lower(&event.blinded_commitment),
                signature: synthetic_signature_hex(&event.blinded_commitment, event.index),
                event_type: "Shield",
            },
            validated_merkleroot: hex_lower(&event.validated_merkleroot),
        })
        .collect();
    Json(wire).into_response()
}

#[derive(Debug, Deserialize)]
struct WireBlindedCommitmentData {
    #[serde(rename = "blindedCommitment")]
    blinded_commitment: String,
    #[serde(rename = "type")]
    _bc_type: String,
}

#[derive(Debug, Deserialize)]
struct PoisPerBlindedCommitmentBody {
    #[serde(rename = "txidVersion")]
    _txid_version: String,
    #[serde(rename = "listKey")]
    list_key: String,
    #[serde(rename = "blindedCommitmentDatas")]
    blinded_commitment_datas: Vec<WireBlindedCommitmentData>,
}

async fn handle_pois_per_blinded_commitment(
    AxumPath((_chain_type, _chain_id)): AxumPath<(String, String)>,
    State(state): State<AppState>,
    Json(body): Json<PoisPerBlindedCommitmentBody>,
) -> impl IntoResponse {
    let corpus = state.inner.corpus.read().clone();
    let list_matches = body.list_key.eq_ignore_ascii_case(&corpus.list_key_hex)
        || body
            .list_key
            .strip_prefix("0x")
            .is_some_and(|rest| rest.eq_ignore_ascii_case(&corpus.list_key_hex));
    if !list_matches {
        let map: BTreeMap<String, POIStatus> = body
            .blinded_commitment_datas
            .into_iter()
            .map(|item| (item.blinded_commitment, POIStatus::Missing))
            .collect();
        return Json(map).into_response();
    }
    let mut map: BTreeMap<String, POIStatus> = BTreeMap::new();
    for item in body.blinded_commitment_datas {
        let bc_hex = item
            .blinded_commitment
            .strip_prefix("0x")
            .unwrap_or(&item.blinded_commitment)
            .to_owned();
        let status =
            decode_hex32(&bc_hex).map_or(POIStatus::Missing, |bytes| corpus.status_for(&bytes));
        map.insert(item.blinded_commitment, status);
    }
    Json(map).into_response()
}

#[derive(Debug, Serialize)]
struct WireNodeStatusList {
    #[serde(rename = "listKey")]
    list_key: String,
    synced: bool,
    #[serde(rename = "eventListLength")]
    event_list_length: u32,
    synthetic: bool,
}

async fn handle_node_status_list(
    AxumPath(list_key): AxumPath<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let corpus = state.inner.corpus.read().clone();
    let event_list_length = u32::try_from(corpus.events.len()).unwrap_or(u32::MAX);
    Json(WireNodeStatusList {
        list_key,
        synced: true,
        event_list_length,
        synthetic: true,
    })
}

#[derive(Debug, Serialize)]
struct WireNodeStatusRoot {
    #[serde(rename = "listKeys")]
    list_keys: Vec<String>,
    synthetic: bool,
}

async fn handle_node_status_root(State(state): State<AppState>) -> impl IntoResponse {
    let list_keys = vec![state.inner.list_key_hex.clone()];
    Json(WireNodeStatusRoot {
        list_keys,
        synthetic: true,
    })
}

/// Read newline-delimited blinded-commitment hex strings from `path`.
/// Empty lines and lines starting with `#` are ignored. Each entry
/// must be exactly 64 hex chars (with an optional `0x` prefix).
///
/// # Errors
///
/// - [`MockError::CsvRead`] if the file cannot be opened or read.
/// - [`MockError::InvalidHex`] if any non-comment line fails to decode.
pub fn load_blocked_csv(path: &Path) -> Result<Vec<[u8; 32]>> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| MockError::CsvRead(format!("{}: {e}", path.display())))?;
    let mut out = Vec::new();
    for (line_no, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let entry = decode_hex32(trimmed.strip_prefix("0x").unwrap_or(trimmed))
            .ok_or_else(|| MockError::InvalidHex(format!("line {}: {trimmed}", line_no + 1)))?;
        out.push(entry);
    }
    Ok(out)
}

/// Decode a 64-char (or `0x`-prefixed 66-char) hex string into 32 bytes.
fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    if trimmed.len() != 64 {
        return None;
    }
    let bytes = trimmed.as_bytes();
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = bytes.get(i * 2).copied()?;
        let lo = bytes.get(i * 2 + 1).copied()?;
        *byte = (hex_nibble(hi)? << 4) | hex_nibble(lo)?;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Lowercase hex-encode, no `0x` prefix.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let hi = HEX.get(usize::from(byte >> 4)).copied().unwrap_or(b'0');
        let lo = HEX.get(usize::from(byte & 0x0F)).copied().unwrap_or(b'0');
        s.push(hi as char);
        s.push(lo as char);
    }
    s
}

/// Synthesize a deterministic 64-byte signature hex placeholder.
///
/// The adapter does not verify upstream signatures, so the wire shape
/// only needs a non-empty hex string of plausible length. We expand a
/// `Poseidon(bc, index)` digest into 64 bytes by hashing twice with
/// distinct domain bytes; the value is reproducible across runs but
/// cryptographically meaningless.
fn synthetic_signature_hex(bc: &[u8; 32], index: u32) -> String {
    let mut idx_buf = [0u8; 32];
    idx_buf[28..].copy_from_slice(&index.to_be_bytes());
    let mut domain_a = [0u8; 32];
    domain_a[31] = 0x01;
    let mut domain_b = [0u8; 32];
    domain_b[31] = 0x02;
    let bc_masked = mask_to_fr(bc);
    let part_a = hash_n(&[domain_a, bc_masked, idx_buf]).unwrap_or([0u8; 32]);
    let part_b = hash_n(&[domain_b, bc_masked, idx_buf]).unwrap_or([0u8; 32]);
    let mut out = String::with_capacity(128);
    out.push_str(&hex_lower(&part_a));
    out.push_str(&hex_lower(&part_b));
    out
}

/// Decode a hex-encoded list-key parameter into a [`ListKey`].
///
/// # Errors
///
/// Returns [`MockError::InvalidHex`] if the string is not 64 hex chars.
pub fn list_key_from_hex(hex: &str) -> Result<ListKey> {
    let bytes = decode_hex32(hex)
        .ok_or_else(|| MockError::InvalidHex(format!("expected 64 hex chars, got: {hex}")))?;
    Ok(ListKey::from_bytes(bytes))
}

/// Decode a hex-encoded 32-byte seed.
///
/// # Errors
///
/// Returns [`MockError::InvalidHex`] if the string is not 64 hex chars.
pub fn seed_from_hex(hex: &str) -> Result<[u8; 32]> {
    decode_hex32(hex).ok_or_else(|| MockError::InvalidHex(format!("seed must be 64 hex: {hex}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_corpus(size: u32) -> Corpus {
        let list_key = decode_hex32(DEFAULT_LIST_KEY_HEX).expect("default list key");
        let seed = decode_hex32(DEFAULT_CORPUS_SEED_HEX).expect("default seed");
        Corpus::generate(CorpusConfig {
            list_key,
            seed,
            size,
            blocked: Vec::new(),
        })
        .expect("generate")
    }

    #[test]
    fn corpus_generation_is_deterministic() {
        let a = fixture_corpus(8);
        let b = fixture_corpus(8);
        assert_eq!(a.len(), 8);
        for i in 0..8usize {
            let ev_a = a.events.get(i).expect("i in range");
            let ev_b = b.events.get(i).expect("i in range");
            assert_eq!(ev_a.blinded_commitment, ev_b.blinded_commitment);
            assert_eq!(ev_a.validated_merkleroot, ev_b.validated_merkleroot);
        }
    }

    #[test]
    fn validated_merkleroot_advances_with_event_count() {
        let corpus = fixture_corpus(16);
        for i in 1..16usize {
            let prev = corpus.events.get(i - 1).expect("prev").validated_merkleroot;
            let curr = corpus.events.get(i).expect("curr").validated_merkleroot;
            assert_ne!(
                prev, curr,
                "validatedMerkleroot must advance after each insert (idx {i})"
            );
        }
    }

    #[test]
    fn status_for_seeded_bc_is_valid() {
        let corpus = fixture_corpus(4);
        let bc = corpus
            .events
            .first()
            .expect("first event")
            .blinded_commitment;
        assert_eq!(corpus.status_for(&bc), POIStatus::Valid);
    }

    #[test]
    fn status_for_unknown_bc_is_missing() {
        let corpus = fixture_corpus(4);
        let unknown = [0xffu8; 32];
        assert_eq!(corpus.status_for(&unknown), POIStatus::Missing);
    }

    #[test]
    fn blocked_override_marks_specific_bc_as_shield_blocked() {
        let list_key = decode_hex32(DEFAULT_LIST_KEY_HEX).expect("list key");
        let seed = decode_hex32(DEFAULT_CORPUS_SEED_HEX).expect("seed");
        let baseline = Corpus::generate(CorpusConfig {
            list_key,
            seed,
            size: 4,
            blocked: Vec::new(),
        })
        .expect("baseline");
        let target_bc = baseline
            .events
            .get(2)
            .expect("third event")
            .blinded_commitment;
        let blocked = Corpus::generate(CorpusConfig {
            list_key,
            seed,
            size: 4,
            blocked: vec![target_bc],
        })
        .expect("blocked");
        assert_eq!(blocked.status_for(&target_bc), POIStatus::ShieldBlocked);
        let other_bc = blocked.events.first().expect("first").blinded_commitment;
        assert_eq!(blocked.status_for(&other_bc), POIStatus::Valid);
    }

    #[test]
    fn events_range_is_clamped_to_corpus() {
        let corpus = fixture_corpus(4);
        let view = corpus.events_range(2, 100);
        assert_eq!(view.len(), 2);
        let empty = corpus.events_range(10, 12);
        assert!(empty.is_empty());
    }

    #[test]
    fn hex_round_trip_helpers() {
        let buf = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
        ];
        let s = hex_lower(&buf);
        assert_eq!(s.len(), 64);
        let back = decode_hex32(&s).expect("decode");
        assert_eq!(back, buf);
        let prefixed = format!("0x{s}");
        let back2 = decode_hex32(&prefixed).expect("decode 0x");
        assert_eq!(back2, buf);
    }
}
