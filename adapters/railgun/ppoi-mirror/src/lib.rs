//! Upstream PPOI mirror for the Raven Railgun PIR adapter.
//!
//! All upstream endpoints use **POST** with JSON body (not GET).
//! Routes consumed: `/poi-events` (event feed) and
//! `/pois-per-blinded-commitment` (canonical status query).

#![allow(missing_docs, clippy::items_after_statements)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use async_trait::async_trait;
use raven_railgun_core::{
    BlindedCommitment, BlindedCommitmentType, ListKey, POIStatus, PoiStatusRow,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Production V2 mainnet `txidVersion` value.
pub const DEFAULT_TXID_VERSION: &str = "V2_PoseidonMerkle";

/// Errors from upstream mirror interactions.
#[derive(thiserror::Error, Debug)]
pub enum MirrorError {
    /// Upstream HTTP / network failure.
    #[error("upstream error: {0}")]
    Upstream(String),
    /// JSON decode or type-shape mismatch.
    #[error("decode error: {0}")]
    Decode(String),
    /// Mirror source has been shut down.
    #[error("source closed")]
    Closed,
}

pub type Result<T, E = MirrorError> = core::result::Result<T, E>;

/// Default polling cadence between upstream pulls (seconds).
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 30;

/// Default upstream PPOI endpoint.
pub const DEFAULT_PPOI_ENDPOINT: &str = "https://poi.us.proxy.railwayapi.xyz";

/// Default chain type in PPOI URLs.
pub const DEFAULT_CHAIN_TYPE: &str = "0";

/// Default Ethereum mainnet chain id.
pub const DEFAULT_CHAIN_ID: u64 = 1;

/// Mirrors upstream PPOI service state into the engine.
#[async_trait]
pub trait MirrorSource: Send + Sync + 'static {
    /// Fetch rows in `[start_index, end_index)` from `/poi-events`; all returned rows have `Valid` status.
    async fn fetch_status_range(
        &self,
        list: &ListKey,
        start_index: u64,
        end_index: u64,
    ) -> Result<Vec<PoiStatusRow>>;

    /// Fetch the canonical status for a single blinded commitment via `/pois-per-blinded-commitment`.
    async fn fetch_status_typed(
        &self,
        list: &ListKey,
        bc: &BlindedCommitment,
        bc_type: BlindedCommitmentType,
    ) -> Result<POIStatus>;
}

/// Configuration for [`UpstreamPpoiMirror`].
#[derive(Clone, Debug)]
pub struct MirrorConfig {
    /// Upstream PPOI service endpoint (no trailing slash).
    pub endpoint: String,
    /// Chain type identifier embedded in URL paths.
    pub chain_type: String,
    /// Chain id embedded in URL paths.
    pub chain_id: u64,
    /// Polling cadence in seconds.
    pub poll_interval_secs: u64,
    /// Maximum row span per `fetch_status_range` call (upstream limit: 1000).
    pub max_rows_per_fetch: u64,
    /// `txidVersion` field in every PPOI request body.
    pub txid_version: String,
}

impl Default for MirrorConfig {
    fn default() -> Self {
        Self {
            endpoint: DEFAULT_PPOI_ENDPOINT.to_owned(),
            chain_type: DEFAULT_CHAIN_TYPE.to_owned(),
            chain_id: DEFAULT_CHAIN_ID,
            poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
            max_rows_per_fetch: 1000,
            txid_version: DEFAULT_TXID_VERSION.to_owned(),
        }
    }
}

/// Per-(list_key, kind) cursor identifier. The mirror keeps the status
/// feed and the path-projection feed on separate sidecars because they
/// advance independently across restart boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MirrorKind {
    /// Drives `PpoiStatus` consumers (T1 status PIR encoder).
    Status,
    /// Drives `PpoiListLeafAdded` consumers used by path-projection
    /// encoders (T2 path / per-list-node).
    Path,
}

impl MirrorKind {
    /// Stable filename suffix for the per-(list_key, kind) cursor
    /// sidecar. Two distinct files so status and path advance
    /// independently after a restart.
    #[must_use]
    pub const fn sidecar_filename(self) -> &'static str {
        match self {
            Self::Status => "ppoi_cursor_status.bin",
            Self::Path => "ppoi_cursor_path.bin",
        }
    }
}

/// Sidecar cursor wired into [`UpstreamPpoiMirror::run_worker_with_cursor`].
///
/// Atomic-rename semantics: the on-disk write is
/// `fs::write(tmp); fsync; fs::rename(tmp, final)` so a torn cursor is
/// never observable. On a crash between `tmp` write and rename the next
/// worker start observes the prior valid sidecar (or the configured
/// `fallback` when that too is absent).
#[derive(Clone, Debug)]
pub struct MirrorCursor {
    /// Directory the sidecar lives in. Full path is
    /// `data_dir / kind.sidecar_filename()`.
    pub data_dir: PathBuf,
    /// Cursor kind: status or path; determines the sidecar filename.
    pub kind: MirrorKind,
    /// Fallback cursor used when the sidecar is missing or torn. Caller
    /// derives this from `LogicalLeafStore::ppoi_imt(&list_key)
    /// .map_or(0, |i| i.leaf_count() as u64)` so a fresh-bootstrap with
    /// already-replayed WAL state never re-pulls from index 0.
    pub fallback: u64,
}

impl MirrorCursor {
    /// Construct a new cursor binding.
    #[must_use]
    pub fn new(data_dir: PathBuf, kind: MirrorKind, fallback: u64) -> Self {
        Self {
            data_dir,
            kind,
            fallback,
        }
    }

    /// Absolute path to the sidecar file.
    #[must_use]
    pub fn sidecar_path(&self) -> PathBuf {
        self.data_dir.join(self.kind.sidecar_filename())
    }

    /// Resolve the worker's starting cursor: prefer the sidecar value
    /// when present and decodable; fall back to `self.fallback`
    /// otherwise. Tracing is loud on each branch so an operator
    /// auditing a restart sees exactly which path fired.
    #[must_use]
    pub fn resolve_start(&self) -> u64 {
        let path = self.sidecar_path();
        if let Some(v) = read_cursor_sidecar(&path) {
            tracing::info!(
                sidecar = %path.display(),
                cursor = v,
                "ppoi mirror cursor: resumed from sidecar"
            );
            v
        } else {
            tracing::info!(
                sidecar = %path.display(),
                fallback = self.fallback,
                "ppoi mirror cursor: sidecar absent or torn; falling back"
            );
            self.fallback
        }
    }

    /// Atomically persist the new cursor to disk. Errors are surfaced
    /// as `std::io::Error` so callers can log + continue; the worker
    /// uses `tracing::warn` and proceeds (the next successful batch
    /// will re-attempt the write).
    ///
    /// # Errors
    ///
    /// Returns the underlying [`std::io::Error`] if creating the parent
    /// directory, writing the temp file, fsync'ing, or renaming fails.
    pub fn persist(&self, cursor: u64) -> std::io::Result<()> {
        write_cursor_sidecar_atomic(&self.sidecar_path(), cursor)
    }
}

/// Wire size of a serialized cursor sidecar: u64 little-endian = 8
/// bytes. Promoted to a const so callers (tests, forensics) can reason
/// about on-disk layout without re-encoding the magic number.
pub const MIRROR_CURSOR_SIDECAR_BYTES: usize = 8;

/// Atomically write `cursor` to `path` as 8 little-endian bytes. Uses
/// `<path>.tmp` + fsync + rename so a torn cursor is never observable
/// across a crash.
fn write_cursor_sidecar_atomic(path: &Path, cursor: u64) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp = PathBuf::from(tmp_name);
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(&cursor.to_le_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Read the sidecar at `path`. Returns `None` on any failure (absent,
/// short, torn, IO error) so the worker falls back cleanly.
fn read_cursor_sidecar(path: &Path) -> Option<u64> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() != MIRROR_CURSOR_SIDECAR_BYTES {
        return None;
    }
    let mut arr = [0u8; MIRROR_CURSOR_SIDECAR_BYTES];
    arr.copy_from_slice(&bytes);
    Some(u64::from_le_bytes(arr))
}

/// HTTP pull from the configured upstream PPOI service.
pub struct UpstreamPpoiMirror {
    config: MirrorConfig,
    client: reqwest::Client,
}

impl std::fmt::Debug for UpstreamPpoiMirror {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamPpoiMirror")
            .field("endpoint", &self.config.endpoint)
            .field("chain_type", &self.config.chain_type)
            .field("chain_id", &self.config.chain_id)
            .finish_non_exhaustive()
    }
}

impl UpstreamPpoiMirror {
    /// Build from config with a default `reqwest::Client` (10s timeout).
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError::Upstream`] if `reqwest::Client::builder().build()`
    /// fails (typically TLS root-store initialisation). On that path no
    /// functional client exists, so we escalate rather than silently
    /// fall back to a timeout-less client.
    pub fn new(config: MirrorConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| MirrorError::Upstream(format!("reqwest builder: {e}")))?;
        Ok(Self { config, client })
    }

    /// Build with the default OFAC-list config.
    ///
    /// # Errors
    ///
    /// Same conditions as [`Self::new`].
    pub fn ofac_default() -> Result<Self> {
        Self::new(MirrorConfig::default())
    }

    /// Return the configured upstream endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.config.endpoint
    }

    /// Periodic polling worker: fetches new PPOI rows and emits them as
    /// WAL payloads. Exits when the channel closes or the task is
    /// cancelled. Legacy no-cursor entry point; delegates to
    /// [`Self::run_worker_with_cursor`] with `None`.
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError`] only for non-recoverable failures; the
    /// per-batch fetch path logs + retries on the next tick.
    pub async fn run_worker(
        self: std::sync::Arc<Self>,
        list: ListKey,
        starting_cursor: u64,
        sender: tokio::sync::mpsc::Sender<(raven_railgun_persistence::WalEntryPayload, u64)>,
    ) -> Result<()> {
        self.run_worker_with_cursor(list, starting_cursor, None, sender)
            .await
    }

    /// Cursor-aware worker entry point. When `persistent_cursor` is
    /// `Some`, the worker resolves its starting position from the
    /// sidecar (falling back to the operator-supplied
    /// [`MirrorCursor::fallback`] when absent / torn) and atomically
    /// writes the advanced cursor after every successful upstream
    /// batch. `starting_cursor` is honoured only when
    /// `persistent_cursor` is `None`; it is preserved as the no-cursor
    /// fast path for the legacy callers and tests.
    ///
    /// # Load-bearing emission order
    ///
    /// For every `/poi-events` row consumed from upstream the worker
    /// emits [`raven_railgun_persistence::WalEntryPayload::PpoiListLeafAdded`]
    /// FIRST, then [`raven_railgun_persistence::WalEntryPayload::PpoiStatus`].
    /// The engine apply path's `(blinded_commitment -> list_index)`
    /// ordering oracle MUST be allocated before the status-only update
    /// touches its key. Flipping the order leaves the per-list IMT
    /// stale and silently breaks T2 path PIR.
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError`] only for non-recoverable failures.
    pub async fn run_worker_with_cursor(
        self: std::sync::Arc<Self>,
        list: ListKey,
        starting_cursor: u64,
        persistent_cursor: Option<MirrorCursor>,
        sender: tokio::sync::mpsc::Sender<(raven_railgun_persistence::WalEntryPayload, u64)>,
    ) -> Result<()> {
        use tokio::time::{interval, Duration, MissedTickBehavior};
        let mut tick = interval(Duration::from_secs(self.config.poll_interval_secs.max(1)));
        // Delay: schedule next tick relative to actual completion time, not the missed tick.
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut cursor = match persistent_cursor.as_ref() {
            Some(pc) => pc.resolve_start(),
            None => starting_cursor,
        };
        loop {
            tick.tick().await;
            if sender.is_closed() {
                tracing::info!(cursor, "ppoi mirror worker exiting; channel closed");
                return Ok(());
            }
            let end = cursor.saturating_add(self.config.max_rows_per_fetch);
            let events = match self.fetch_indexed_events(&list, cursor, end).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "fetch_indexed_events failed; retrying next tick");
                    continue;
                }
            };
            if events.is_empty() {
                continue;
            }
            for ev in &events {
                let status_byte = poi_status_to_byte(ev.status);
                // PpoiListLeafAdded must precede PpoiStatus; see the emission-order doc above.
                let leaf_added = raven_railgun_persistence::WalEntryPayload::PpoiListLeafAdded {
                    list_key: list.0,
                    list_index: ev.list_index,
                    blinded_commitment: ev.blinded_commitment.0,
                    status: status_byte,
                };
                if sender.send((leaf_added, 0)).await.is_err() {
                    tracing::info!("ppoi mirror engine consumer dropped channel; exiting");
                    return Ok(());
                }
                let status_payload = raven_railgun_persistence::WalEntryPayload::PpoiStatus {
                    list_key: list.0,
                    blinded_commitment: ev.blinded_commitment.0,
                    status: status_byte,
                };
                if sender.send((status_payload, 0)).await.is_err() {
                    tracing::info!("ppoi mirror engine consumer dropped channel; exiting");
                    return Ok(());
                }
            }
            #[allow(clippy::cast_possible_truncation)]
            let advanced = events.len() as u64;
            cursor = cursor.saturating_add(advanced);
            if let Some(pc) = persistent_cursor.as_ref() {
                if let Err(e) = pc.persist(cursor) {
                    tracing::warn!(
                        error = %e,
                        sidecar = %pc.sidecar_path().display(),
                        cursor,
                        "ppoi mirror cursor: atomic write failed; will retry on next batch"
                    );
                }
            }
        }
    }

    /// Internal indexed-fetch path used by [`Self::run_worker_with_cursor`].
    ///
    /// Pulls upstream `/poi-events` and surfaces each row's full
    /// `(list_index, blinded_commitment, status)` tuple. The
    /// trait-level [`MirrorSource::fetch_status_range`] strips the
    /// index because its consumers (status PIR / external callers)
    /// don't need it; the worker does, because it must drive per-list
    /// IMT growth via `PpoiListLeafAdded`.
    async fn fetch_indexed_events(
        &self,
        list: &ListKey,
        start_index: u64,
        end_index: u64,
    ) -> Result<Vec<IndexedPoiEvent>> {
        if end_index <= start_index {
            return Ok(Vec::new());
        }
        let url = format!(
            "{}/poi-events/{}/{}",
            self.config.endpoint, self.config.chain_type, self.config.chain_id
        );
        let body = PoiEventsRequestBody {
            txid_version: &self.config.txid_version,
            list_key: hex_lower(&list.0),
            start_index,
            end_index,
        };
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| MirrorError::Upstream(format!("POST {url}: {e}")))?;
        if !resp.status().is_success() {
            return Err(MirrorError::Upstream(format!(
                "POST {url} returned {}",
                resp.status()
            )));
        }
        let events: Vec<WirePOISyncedListEvent> = resp
            .json()
            .await
            .map_err(|e| MirrorError::Decode(format!("/poi-events JSON: {e}")))?;
        let mut out = Vec::with_capacity(events.len());
        for e in events {
            let bc_str = e.signed_event.blinded_commitment;
            let bc_bytes = decode_hex32(&bc_str)
                .ok_or_else(|| MirrorError::Decode(format!("invalid bc hex: {bc_str}")))?;
            let list_index = u32::try_from(e.signed_event.index).map_err(|_| {
                MirrorError::Decode(format!(
                    "list_index {} exceeds u32 IMT capacity",
                    e.signed_event.index
                ))
            })?;
            out.push(IndexedPoiEvent {
                list_index,
                blinded_commitment: BlindedCommitment::from_bytes(bc_bytes),
                status: POIStatus::Valid,
            });
        }
        Ok(out)
    }
}

/// Internal indexed-event row carried from `fetch_indexed_events` into
/// `run_worker_with_cursor`. Pairs the `list_index` (for IMT growth)
/// with the bc + status (for the status map).
#[derive(Clone, Debug)]
struct IndexedPoiEvent {
    list_index: u32,
    blinded_commitment: BlindedCommitment,
    status: POIStatus,
}

/// Encode [`POIStatus`] as a WAL byte (Valid=0, ShieldBlocked=1, ProofSubmitted=2, Missing=3).
#[must_use]
pub fn poi_status_to_byte(s: POIStatus) -> u8 {
    match s {
        POIStatus::Valid => 0,
        POIStatus::ShieldBlocked => 1,
        POIStatus::ProofSubmitted => 2,
        POIStatus::Missing => 3,
    }
}

/// Decode a WAL byte back to [`POIStatus`]; returns `None` for unknown values.
#[must_use]
pub fn poi_status_from_byte(b: u8) -> Option<POIStatus> {
    match b {
        0 => Some(POIStatus::Valid),
        1 => Some(POIStatus::ShieldBlocked),
        2 => Some(POIStatus::ProofSubmitted),
        3 => Some(POIStatus::Missing),
        _ => None,
    }
}

/// Wire JSON shape for `POISyncedListEvent` from `POST /poi-events`.
#[derive(Debug, Deserialize)]
struct WirePOISyncedListEvent {
    #[serde(rename = "signedPOIEvent")]
    signed_event: WireSignedPOIEvent,
}

#[derive(Debug, Deserialize)]
struct WireSignedPOIEvent {
    /// Upstream-issued contiguous position of this entry within the
    /// list. Wire shape is JSON `number`; decoded as `u64` and narrowed
    /// to `u32` at the WAL-payload boundary because
    /// [`raven_railgun_persistence::WalEntryPayload::PpoiListLeafAdded`]
    /// uses `u32`. Indices > `u32::MAX` would exceed per-list IMT
    /// capacity and are rejected with a typed [`MirrorError::Decode`].
    index: u64,
    #[serde(rename = "blindedCommitment")]
    blinded_commitment: String,
}

/// Request body for `POST /poi-events/:chainType/:chainID`.
#[derive(Debug, Serialize)]
struct PoiEventsRequestBody<'a> {
    #[serde(rename = "txidVersion")]
    txid_version: &'a str,
    #[serde(rename = "listKey")]
    list_key: String,
    #[serde(rename = "startIndex")]
    start_index: u64,
    #[serde(rename = "endIndex")]
    end_index: u64,
}

/// Single entry in `blindedCommitmentDatas[]` for status queries.
#[derive(Debug, Serialize)]
struct WireBlindedCommitmentData {
    #[serde(rename = "blindedCommitment")]
    blinded_commitment: String,
    #[serde(rename = "type")]
    bc_type: BlindedCommitmentType,
}

/// Request body for `POST /pois-per-blinded-commitment/:chainType/:chainID`.
#[derive(Debug, Serialize)]
struct PoisPerBlindedCommitmentRequestBody<'a> {
    #[serde(rename = "txidVersion")]
    txid_version: &'a str,
    #[serde(rename = "listKey")]
    list_key: String,
    #[serde(rename = "blindedCommitmentDatas")]
    blinded_commitment_datas: Vec<WireBlindedCommitmentData>,
}

#[async_trait]
impl MirrorSource for UpstreamPpoiMirror {
    async fn fetch_status_range(
        &self,
        list: &ListKey,
        start_index: u64,
        end_index: u64,
    ) -> Result<Vec<PoiStatusRow>> {
        if end_index <= start_index {
            return Ok(Vec::new());
        }
        let url = format!(
            "{}/poi-events/{}/{}",
            self.config.endpoint, self.config.chain_type, self.config.chain_id
        );
        let body = PoiEventsRequestBody {
            txid_version: &self.config.txid_version,
            list_key: hex_lower(&list.0),
            start_index,
            end_index,
        };
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| MirrorError::Upstream(format!("POST {url}: {e}")))?;
        if !resp.status().is_success() {
            return Err(MirrorError::Upstream(format!(
                "POST {url} returned {}",
                resp.status()
            )));
        }
        let events: Vec<WirePOISyncedListEvent> = resp
            .json()
            .await
            .map_err(|e| MirrorError::Decode(format!("/poi-events JSON: {e}")))?;
        let mut rows = Vec::with_capacity(events.len());
        for e in events {
            let bc_str = e.signed_event.blinded_commitment;
            let bc_bytes = decode_hex32(&bc_str)
                .ok_or_else(|| MirrorError::Decode(format!("invalid bc hex: {bc_str}")))?;
            rows.push(PoiStatusRow {
                blinded_commitment: BlindedCommitment::from_bytes(bc_bytes),
                status: POIStatus::Valid,
            });
        }
        Ok(rows)
    }

    async fn fetch_status_typed(
        &self,
        list: &ListKey,
        bc: &BlindedCommitment,
        bc_type: BlindedCommitmentType,
    ) -> Result<POIStatus> {
        let url = format!(
            "{}/pois-per-blinded-commitment/{}/{}",
            self.config.endpoint, self.config.chain_type, self.config.chain_id
        );
        let bc_hex = hex_lower(bc.as_bytes());
        let body = PoisPerBlindedCommitmentRequestBody {
            txid_version: &self.config.txid_version,
            list_key: hex_lower(&list.0),
            blinded_commitment_datas: vec![WireBlindedCommitmentData {
                blinded_commitment: bc_hex.clone(),
                bc_type,
            }],
        };
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| MirrorError::Upstream(format!("POST {url}: {e}")))?;
        if !resp.status().is_success() {
            return Err(MirrorError::Upstream(format!(
                "POST {url} returned {}",
                resp.status()
            )));
        }
        let map: std::collections::HashMap<String, POIStatus> = resp
            .json()
            .await
            .map_err(|e| MirrorError::Decode(format!("/pois-per-blinded-commitment JSON: {e}")))?;
        // Upstream may key by `bc_hex` with or without `0x` prefix.
        let prefixed = format!("0x{bc_hex}");
        map.get(&bc_hex)
            .or_else(|| map.get(&prefixed))
            .copied()
            .ok_or_else(|| {
                MirrorError::Decode(format!(
                    "/pois-per-blinded-commitment response missing key {bc_hex}"
                ))
            })
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let hi = HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0');
        let lo = HEX.get(usize::from(b & 0x0F)).copied().unwrap_or(b'0');
        s.push(hi as char);
        s.push(lo as char);
    }
    s
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    if trimmed.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = trimmed.as_bytes().get(i * 2).copied()?;
        let lo = trimmed.as_bytes().get(i * 2 + 1).copied()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poi_status_byte_round_trip() {
        for s in [
            POIStatus::Valid,
            POIStatus::ShieldBlocked,
            POIStatus::ProofSubmitted,
            POIStatus::Missing,
        ] {
            let b = poi_status_to_byte(s);
            assert_eq!(poi_status_from_byte(b), Some(s));
        }
    }

    #[test]
    fn decode_hex32_accepts_0x_prefix() {
        let bytes = [1u8; 32];
        let s = format!("0x{}", hex_lower(&bytes));
        let back = decode_hex32(&s).expect("decode 0x");
        assert_eq!(back, bytes);
    }

    #[test]
    fn decode_hex32_rejects_short() {
        assert!(decode_hex32("0xdeadbeef").is_none());
    }

    #[test]
    fn poi_status_pascal_case_serde_round_trip() {
        for s in ["Valid", "ShieldBlocked", "ProofSubmitted", "Missing"] {
            let parsed: POIStatus = serde_json::from_str(&format!("\"{s}\""))
                .expect("PascalCase status decodes via serde");
            let reser = serde_json::to_string(&parsed).expect("serialize");
            assert_eq!(reser, format!("\"{s}\""));
        }
        let bad: serde_json::Result<POIStatus> = serde_json::from_str("\"nonsense\"");
        assert!(bad.is_err(), "unknown status must reject");
    }

    #[test]
    fn mirror_kind_sidecar_filenames_are_distinct() {
        assert_ne!(
            MirrorKind::Status.sidecar_filename(),
            MirrorKind::Path.sidecar_filename(),
            "status and path sidecars must use distinct filenames"
        );
    }

    #[test]
    fn upstream_ppoi_mirror_constructor_round_trips() {
        let m = UpstreamPpoiMirror::ofac_default().expect("ofac_default builds");
        assert_eq!(m.endpoint(), "https://poi.us.proxy.railwayapi.xyz");
    }
}
