//! Upstream PPOI mirror over the aggregator's JSON-RPC endpoint.

#![allow(missing_docs, clippy::items_after_statements)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use async_trait::async_trait;
use raven_railgun_core::{
    BlindedCommitment, BlindedCommitmentType, ListKey, POIStatus, PoiStatusRow,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Production V2 mainnet `txidVersion` value.
pub const DEFAULT_TXID_VERSION: &str = "V2_PoseidonMerkle";

/// Errors from upstream mirror interactions.
#[derive(thiserror::Error, Debug)]
pub enum MirrorError {
    /// Mirror configuration is invalid.
    #[error("invalid mirror configuration: {0}")]
    InvalidConfig(String),
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
pub const DEFAULT_PPOI_ENDPOINT: &str = "https://ppoi.fdi.network";

const JSON_RPC_VERSION: &str = "2.0";
const POI_EVENTS_METHOD: &str = "ppoi_poi_events";
const POIS_PER_BLINDED_COMMITMENT_METHOD: &str = "ppoi_pois_per_blinded_commitment";

/// Default chain type in PPOI URLs.
pub const DEFAULT_CHAIN_TYPE: &str = "0";

/// Default Ethereum mainnet chain id.
pub const DEFAULT_CHAIN_ID: u64 = 1;

/// Mirrors upstream PPOI service state into the engine.
#[async_trait]
pub trait MirrorSource: Send + Sync + 'static {
    /// Fetch rows in the inclusive range `[start_index, end_index]`; all returned rows have `Valid` status.
    async fn fetch_status_range(
        &self,
        list: &ListKey,
        start_index: u64,
        end_index: u64,
    ) -> Result<Vec<PoiStatusRow>>;

    /// Fetch the canonical status for one blinded commitment via JSON-RPC.
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
    /// Chain type identifier sent in JSON-RPC parameters.
    pub chain_type: String,
    /// Chain id sent in JSON-RPC parameters.
    pub chain_id: u64,
    /// Polling cadence in seconds.
    pub poll_interval_secs: u64,
    /// Maximum rows per inclusive event-page request (upstream limit: 501).
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
            max_rows_per_fetch: 501,
            txid_version: DEFAULT_TXID_VERSION.to_owned(),
        }
    }
}

/// Cursor kind. Status and path-projection feeds get separate sidecars
/// because they advance independently across restarts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MirrorKind {
    /// Drives `PpoiStatus` consumers.
    Status,
    /// Drives `PpoiListLeafAdded` consumers used by path-projection encoders.
    Path,
}

impl MirrorKind {
    /// Sidecar filename suffix; distinct per kind so the two feeds advance
    /// independently after a restart.
    #[must_use]
    pub const fn sidecar_filename(self) -> &'static str {
        match self {
            Self::Status => "ppoi_cursor_status.bin",
            Self::Path => "ppoi_cursor_path.bin",
        }
    }
}

/// Sidecar cursor for [`UpstreamPpoiMirror::run_worker_with_cursor`]. Written
/// write-tmp + fsync + rename, so a torn cursor is never observable; a crash
/// mid-write leaves the prior sidecar, or the `fallback` when absent.
#[derive(Clone, Debug)]
pub struct MirrorCursor {
    /// Directory holding `kind.sidecar_filename()`.
    pub data_dir: PathBuf,
    /// Cursor kind; selects the sidecar filename.
    pub kind: MirrorKind,
    /// Used when the sidecar is missing or torn. Derive it from the replayed
    /// per-list leaf count so a fresh bootstrap never re-pulls from index 0.
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

    /// Starting cursor: the sidecar when decodable, else `self.fallback`.
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

    /// Atomically persist the cursor. The worker logs and continues on error;
    /// the next successful batch retries the write.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] from mkdir, temp write, fsync, or rename.
    pub fn persist(&self, cursor: u64) -> std::io::Result<()> {
        write_cursor_sidecar_atomic(&self.sidecar_path(), cursor)
    }
}

/// Cursor sidecar wire size: one little-endian u64.
pub const MIRROR_CURSOR_SIDECAR_BYTES: usize = 8;

/// Write `cursor` as little-endian bytes via tmp + fsync + rename, so a torn
/// cursor is never observable across a crash.
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

/// Read the sidecar; `None` on any failure so the worker falls back cleanly.
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
    /// Build from config with a default 10s-timeout `reqwest::Client`.
    ///
    /// # Errors
    ///
    /// [`MirrorError::Upstream`] if client construction fails; escalated rather
    /// than falling back to a timeout-less client.
    pub fn new(config: MirrorConfig) -> Result<Self> {
        if config.max_rows_per_fetch == 0 || config.max_rows_per_fetch > 501 {
            return Err(MirrorError::InvalidConfig(format!(
                "max_rows_per_fetch {} is outside 1..=501",
                config.max_rows_per_fetch
            )));
        }
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

    /// No-cursor polling worker; delegates to
    /// [`Self::run_worker_with_cursor`] with `None`.
    ///
    /// # Errors
    ///
    /// [`MirrorError`] only for non-recoverable failures; per-batch fetch
    /// failures log and retry on the next tick.
    pub async fn run_worker(
        self: std::sync::Arc<Self>,
        list: ListKey,
        starting_cursor: u64,
        sender: tokio::sync::mpsc::Sender<(raven_railgun_persistence::WalEntryPayload, u64)>,
    ) -> Result<()> {
        self.run_worker_with_cursor(list, starting_cursor, None, sender)
            .await
    }

    /// Cursor-aware polling worker. With `persistent_cursor` set, the start
    /// position comes from the sidecar and the advanced cursor is persisted
    /// after every successful batch; `starting_cursor` applies only when it is
    /// `None`.
    ///
    /// # Load-bearing emission order
    ///
    /// Per upstream row, `PpoiListLeafAdded` MUST be emitted before
    /// `PpoiStatus`: the apply path allocates the
    /// `(blinded_commitment -> list_index)` mapping from the former, and the
    /// reverse order leaves the per-list IMT silently stale.
    ///
    /// # Errors
    ///
    /// [`MirrorError`] only for non-recoverable failures.
    pub async fn run_worker_with_cursor(
        self: std::sync::Arc<Self>,
        list: ListKey,
        starting_cursor: u64,
        persistent_cursor: Option<MirrorCursor>,
        sender: tokio::sync::mpsc::Sender<(raven_railgun_persistence::WalEntryPayload, u64)>,
    ) -> Result<()> {
        use tokio::time::{interval, Duration, MissedTickBehavior};
        let mut tick = interval(Duration::from_secs(self.config.poll_interval_secs.max(1)));
        // Next tick is relative to completion, not to the missed tick.
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
            let end = cursor
                .checked_add(self.config.max_rows_per_fetch - 1)
                .ok_or_else(|| {
                    MirrorError::Decode(format!(
                        "PPOI page starting at {cursor} overflows u64 for {} rows",
                        self.config.max_rows_per_fetch
                    ))
                })?;
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
                // Emission order is load-bearing; see the worker doc.
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
            let last_index = events
                .last()
                .map(|event| u64::from(event.list_index))
                .ok_or_else(|| {
                    MirrorError::Decode("nonempty PPOI page lost its final index".to_owned())
                })?;
            cursor = last_index.checked_add(1).ok_or_else(|| {
                MirrorError::Decode(format!(
                    "PPOI cursor cannot advance past consumed index {last_index}"
                ))
            })?;
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

    /// `ppoi_poi_events` pull retaining each row's `list_index`, which the worker
    /// needs to drive per-list IMT growth and
    /// [`MirrorSource::fetch_status_range`] therefore strips.
    async fn fetch_indexed_events(
        &self,
        list: &ListKey,
        start_index: u64,
        end_index: u64,
    ) -> Result<Vec<IndexedPoiEvent>> {
        if end_index < start_index {
            return Ok(Vec::new());
        }
        let params = PoiEventsRequestBody {
            chain_type: &self.config.chain_type,
            chain_id: self.config.chain_id.to_string(),
            txid_version: &self.config.txid_version,
            list_key: hex_lower(&list.0),
            start_index,
            end_index,
        };
        let events: Vec<WirePOISyncedListEvent> =
            self.post_json_rpc(POI_EVENTS_METHOD, params).await?;
        decode_indexed_events(events, start_index, end_index)
    }

    async fn post_json_rpc<P, T>(&self, method: &'static str, params: P) -> Result<T>
    where
        P: Serialize,
        T: DeserializeOwned,
    {
        let request = JsonRpcRequest {
            jsonrpc: JSON_RPC_VERSION,
            method,
            params,
            id: 1,
        };
        let response = self
            .client
            .post(&self.config.endpoint)
            .json(&request)
            .send()
            .await
            .map_err(|error| {
                MirrorError::Upstream(format!(
                    "JSON-RPC {method} POST {}: {error}",
                    self.config.endpoint
                ))
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(MirrorError::Upstream(format!(
                "JSON-RPC {method} POST {} returned {status}",
                self.config.endpoint
            )));
        }
        let response: JsonRpcResponse<T> = response
            .json()
            .await
            .map_err(|error| MirrorError::Decode(format!("JSON-RPC {method} response: {error}")))?;
        if response.jsonrpc != JSON_RPC_VERSION || response.id != 1 {
            return Err(MirrorError::Decode(format!(
                "JSON-RPC {method} response envelope mismatch: version {}, id {}",
                response.jsonrpc, response.id
            )));
        }
        match (response.result, response.error) {
            (Some(result), None) => Ok(result),
            (None, Some(error)) => Err(MirrorError::Upstream(format!(
                "JSON-RPC {method} error {}: {}",
                error.code, error.message
            ))),
            (Some(_), Some(_)) => Err(MirrorError::Decode(format!(
                "JSON-RPC {method} response contains both result and error"
            ))),
            (None, None) => Err(MirrorError::Decode(format!(
                "JSON-RPC {method} response contains neither result nor error"
            ))),
        }
    }
}

/// Indexed event row: `list_index` for IMT growth, bc + status for the map.
#[derive(Clone, Debug)]
struct IndexedPoiEvent {
    list_index: u32,
    blinded_commitment: BlindedCommitment,
    status: POIStatus,
}

fn decode_indexed_events(
    events: Vec<WirePOISyncedListEvent>,
    start_index: u64,
    end_index: u64,
) -> Result<Vec<IndexedPoiEvent>> {
    let requested = end_index
        .checked_sub(start_index)
        .and_then(|span| span.checked_add(1))
        .ok_or_else(|| {
            MirrorError::Decode(format!(
                "invalid inclusive PPOI range {start_index}..={end_index}"
            ))
        })?;
    if u64::try_from(events.len()).unwrap_or(u64::MAX) > requested {
        return Err(MirrorError::Decode(format!(
            "PPOI response has {} rows for requested inclusive range {start_index}..={end_index}",
            events.len()
        )));
    }
    let mut out = Vec::with_capacity(events.len());
    let mut previous = None;
    for event in events {
        let index = event.signed_event.index;
        if !(start_index..=end_index).contains(&index)
            || previous.is_some_and(|prior| index <= prior)
        {
            return Err(MirrorError::Decode(format!(
                "PPOI response index {index} is outside or non-monotone for {start_index}..={end_index}"
            )));
        }
        previous = Some(index);
        decode_hex64(&event.signed_event.signature).ok_or_else(|| {
            MirrorError::Decode(format!("invalid signature hex at index {index}"))
        })?;
        if !matches!(
            event.signed_event.event_type.as_str(),
            "Shield" | "Transact" | "Unshield" | "LegacyTransact"
        ) {
            return Err(MirrorError::Decode(format!(
                "unknown PPOI event type {} at index {index}",
                event.signed_event.event_type
            )));
        }
        decode_hex32(&event.validated_merkleroot).ok_or_else(|| {
            MirrorError::Decode(format!("invalid validatedMerkleroot hex at index {index}"))
        })?;
        let bc_str = event.signed_event.blinded_commitment;
        let bc_bytes = decode_hex32(&bc_str).ok_or_else(|| {
            MirrorError::Decode(format!("invalid bc hex at index {index}: {bc_str}"))
        })?;
        let list_index = u32::try_from(index).map_err(|_| {
            MirrorError::Decode(format!("list_index {index} exceeds u32 IMT capacity"))
        })?;
        out.push(IndexedPoiEvent {
            list_index,
            blinded_commitment: BlindedCommitment::from_bytes(bc_bytes),
            status: POIStatus::Valid,
        });
    }
    Ok(out)
}

/// Encode [`POIStatus`] as a WAL byte (Valid=0, ShieldBlocked=1, ProofSubmitted=2, Missing=3).
#[must_use]
pub fn poi_status_to_byte(s: POIStatus) -> u8 {
    s.wire_byte()
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

/// Wire JSON shape for a `ppoi_poi_events` result row.
#[derive(Debug, Deserialize)]
struct WirePOISyncedListEvent {
    #[serde(rename = "signedPOIEvent")]
    signed_event: WireSignedPOIEvent,
    #[serde(rename = "validatedMerkleroot")]
    validated_merkleroot: String,
}

#[derive(Debug, Deserialize)]
struct WireSignedPOIEvent {
    /// Contiguous position within the list. Narrowed to `u32` at the WAL
    /// boundary; anything wider exceeds per-list IMT capacity and is rejected.
    index: u64,
    #[serde(rename = "blindedCommitment")]
    blinded_commitment: String,
    signature: String,
    #[serde(rename = "type")]
    event_type: String,
}

#[derive(Debug, Serialize)]
struct JsonRpcRequest<P> {
    jsonrpc: &'static str,
    method: &'static str,
    params: P,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
    jsonrpc: String,
    id: u64,
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

/// Parameters for `ppoi_poi_events`.
#[derive(Debug, Serialize)]
struct PoiEventsRequestBody<'a> {
    #[serde(rename = "chainType")]
    chain_type: &'a str,
    #[serde(rename = "chainID")]
    chain_id: String,
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

/// Parameters for `ppoi_pois_per_blinded_commitment`.
#[derive(Debug, Serialize)]
struct PoisPerBlindedCommitmentRequestBody<'a> {
    #[serde(rename = "chainType")]
    chain_type: &'a str,
    #[serde(rename = "chainID")]
    chain_id: String,
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
        if end_index < start_index {
            return Ok(Vec::new());
        }
        let params = PoiEventsRequestBody {
            chain_type: &self.config.chain_type,
            chain_id: self.config.chain_id.to_string(),
            txid_version: &self.config.txid_version,
            list_key: hex_lower(&list.0),
            start_index,
            end_index,
        };
        let events: Vec<WirePOISyncedListEvent> =
            self.post_json_rpc(POI_EVENTS_METHOD, params).await?;
        decode_indexed_events(events, start_index, end_index).map(|events| {
            events
                .into_iter()
                .map(|event| PoiStatusRow {
                    blinded_commitment: event.blinded_commitment,
                    status: event.status,
                })
                .collect()
        })
    }

    async fn fetch_status_typed(
        &self,
        list: &ListKey,
        bc: &BlindedCommitment,
        bc_type: BlindedCommitmentType,
    ) -> Result<POIStatus> {
        let bc_hex = hex_lower(bc.as_bytes());
        let prefixed = format!("0x{bc_hex}");
        let params = PoisPerBlindedCommitmentRequestBody {
            chain_type: &self.config.chain_type,
            chain_id: self.config.chain_id.to_string(),
            txid_version: &self.config.txid_version,
            list_key: hex_lower(&list.0),
            blinded_commitment_datas: vec![WireBlindedCommitmentData {
                blinded_commitment: prefixed.clone(),
                bc_type,
            }],
        };
        let map: std::collections::HashMap<String, POIStatus> = self
            .post_json_rpc(POIS_PER_BLINDED_COMMITMENT_METHOD, params)
            .await?;
        // Upstream keys by `bc_hex` with or without the `0x` prefix.
        map.get(&bc_hex)
            .or_else(|| map.get(&prefixed))
            .copied()
            .ok_or_else(|| {
                MirrorError::Decode(format!(
                    "ppoi_pois_per_blinded_commitment response missing key {bc_hex}"
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

fn decode_hex64(s: &str) -> Option<[u8; 64]> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    if trimmed.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
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
        assert_eq!(m.endpoint(), "https://ppoi.fdi.network");
    }
}
