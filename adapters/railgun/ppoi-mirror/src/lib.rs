//! Upstream PPOI mirror over the aggregator's JSON-RPC endpoint.
//!
//! # Trust
//!
//! Each `signedPOIEvent` carries the list provider's ed25519 signature over the UTF-8 of
//! `JSON.stringify({index, blindedCommitment, type})`, built from the strings exactly as upstream
//! serves them. A Railgun list key is the provider's public key. The feed checks every row
//! against the list key it is given, and nothing turns that check off. A row whose signature
//! fails, or is not 64 bytes of hex, is refused by index, counted in
//! [`FeedProgress::signatures_refused`], and never delivered: the feed stops in front of it and
//! asks for it again.
//!
//! That authenticates each row's index, blinded commitment and type. It does not stop the
//! endpoint from withholding or delaying rows, it does not cover `validatedMerkleroot` (the
//! engine holds each row to that root against the tree it builds), and the list key itself is
//! trusted as configured. The signed message names no chain and no txid version, and an
//! upstream node signs for all of them with one key, so the endpoint can serve rows the same key
//! signed for another chain or txid version. [`TRUST_STATEMENT`] says the same for an operator's
//! log. The signature is dropped once checked: a delivered row does not carry it.
//!
//! # What a mirrored row says
//!
//! `ppoi_poi_events` carries membership, not a verdict. Upstream's `Valid` for a list is presence
//! in that list's POI merkletree, whose leaf is the event's blinded commitment, inserted at the
//! event's index. So a row this mirror delivers carries no status: it says its commitment sits in
//! the list at its index, and that is the whole of what the data says. A commitment upstream
//! would call `ShieldBlocked` was never given a list index, so no row here can express it.

#![allow(missing_docs, clippy::items_after_statements)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use raven_railgun_core::hex::decode_hex;
use raven_railgun_core::{BlindedCommitment, ListKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

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
    /// No consumer can hold the row at `list_index`, so the feed stopped in front of it.
    #[error("no consumer holds list index {list_index}; the feed stopped in front of it")]
    Unheld { list_index: u64 },
}

pub type Result<T, E = MirrorError> = core::result::Result<T, E>;

/// Class of a failed exchange with the upstream: a refused [`UpstreamPpoiMirror::preflight`], or
/// a feed request recorded in [`FeedProgress::last_failure`]. It names no endpoint and quotes no
/// body, so an uncredentialed surface can carry it.
#[derive(thiserror::Error, Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreflightFailure {
    /// The endpoint's host did not resolve.
    #[error("host did not resolve")]
    Dns,
    /// The host resolved but no connection was established.
    #[error("connection failed")]
    Connect,
    /// No complete answer inside the caller's bound.
    #[error("no answer within {0:?}")]
    Timeout(std::time::Duration),
    /// The request failed in transit for a reason no other class covers.
    #[error("request failed in transit")]
    Transport,
    /// Answered with a non-success HTTP status.
    #[error("answered HTTP {0}")]
    HttpStatus(u16),
    /// Answered a body that is not a JSON-RPC 2.0 reply to the request.
    #[error("answered a body that is not a JSON-RPC 2.0 reply")]
    MalformedEnvelope,
    /// Answered a JSON-RPC error object carrying this code.
    #[error("answered JSON-RPC error {0}")]
    Rpc(i64),
    /// Answered rows the worker's decoder refuses.
    #[error("answered rows the mirror cannot ingest")]
    UndecodableRows,
    /// Answered a page missing the row at `.0`; the rows below it were taken and it is asked
    /// for again.
    #[error("answered a page without row {0}")]
    MissingRow(u64),
    /// Answered row `.0` with a signature the list key does not verify; the rows below it were
    /// taken and it is asked for again.
    #[error("answered row {0} with a signature the list key does not verify")]
    BadSignature(u64),
}

/// A refused [`UpstreamPpoiMirror::preflight`].
#[derive(thiserror::Error, Clone, Debug, Eq, PartialEq)]
#[error(
    "ppoi mirror preflight: {} POST {endpoint}: {failure} ({detail})",
    POI_EVENTS_METHOD
)]
pub struct PreflightError {
    /// The endpoint exactly as configured.
    pub endpoint: String,
    /// Failure class.
    pub failure: PreflightFailure,
    /// The underlying error, with its causes.
    pub detail: String,
}

/// What vouches for a mirrored row, worded for an operator. Logged once per feed.
pub const TRUST_STATEMENT: &str = "each row's index, blinded commitment and type are \
    authenticated by its signedPOIEvent ed25519 signature under the configured list key; the \
    endpoint can still withhold or delay rows, validatedMerkleroot is not signed, the signature \
    binds neither chain nor txid version so rows the same key signed for another chain or txid \
    version pass, and the list key is trusted as configured";

/// Default polling cadence between upstream pulls (seconds).
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 30;

/// Default bound on one upstream request, connect to last body byte.
pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Default upstream PPOI endpoint.
pub const DEFAULT_PPOI_ENDPOINT: &str = "https://ppoi.fdi.network";

#[cfg(feature = "test-signer")]
pub mod test_signer;

const JSON_RPC_VERSION: &str = "2.0";
const POI_EVENTS_METHOD: &str = "ppoi_poi_events";

/// Default chain type in PPOI URLs.
pub const DEFAULT_CHAIN_TYPE: &str = "0";

/// Default Ethereum mainnet chain id.
pub const DEFAULT_CHAIN_ID: u64 = 1;

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
    /// Bound on one feed request, connect to last body byte.
    pub request_timeout: std::time::Duration,
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
            request_timeout: REQUEST_TIMEOUT,
        }
    }
}

/// What one list's feed has seen of upstream, as of its last request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeedProgress {
    /// List-wide index of the next row the feed asks for. The rows below it were handed
    /// downstream, and may still be queued there: nothing here says they are durable.
    pub next_index: u64,
    /// Upstream's row count, known only when its last answer came back shorter than the page
    /// asked for. `None` while pages come back full, and before the first answer.
    pub upstream_rows: Option<u64>,
    /// Rows handed downstream since the feed started.
    pub rows_delivered: u64,
    /// Requests that failed since upstream last answered.
    pub consecutive_failures: u64,
    /// Class of the latest failure; cleared by an answer.
    pub last_failure: Option<PreflightFailure>,
    /// When upstream last answered.
    pub last_answer: Option<std::time::Instant>,
    /// Why the feed stopped for good; `None` while it runs.
    pub stopped: Option<String>,
    /// Rows refused because the list key does not verify their signature, since the feed
    /// started. A row refused again when it is asked for again counts again.
    pub signatures_refused: u64,
    /// A row the feed delivered that no consumer took, which it is asking for again. Cleared
    /// once the span starts past it, so while this is set the list cannot complete.
    pub untaken_row: Option<u64>,
}

/// Shared handle on one feed's [`FeedProgress`]: the feed writes it, an operator surface reads
/// it. Every lock is taken and released inside one call, never across an await.
#[derive(Clone, Debug, Default)]
pub struct FeedStatus(std::sync::Arc<std::sync::Mutex<FeedProgress>>);

impl FeedStatus {
    /// The feed as of its last request.
    #[must_use]
    pub fn snapshot(&self) -> FeedProgress {
        self.progress().clone()
    }

    // A poisoned lock still holds the last whole write, which is the best report there is.
    fn progress(&self) -> std::sync::MutexGuard<'_, FeedProgress> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn at(&self, next_index: u64) {
        self.progress().next_index = next_index;
    }

    fn failed(&self, class: PreflightFailure) {
        let mut progress = self.progress();
        progress.consecutive_failures = progress.consecutive_failures.saturating_add(1);
        progress.last_failure = Some(class);
    }

    fn answered(&self, next_index: u64, delivered: usize, upstream_rows: Option<u64>) {
        let mut progress = self.progress();
        progress.next_index = next_index;
        progress.rows_delivered = progress
            .rows_delivered
            .saturating_add(u64::try_from(delivered).unwrap_or(u64::MAX));
        progress.upstream_rows = upstream_rows;
        progress.consecutive_failures = 0;
        progress.last_failure = None;
        progress.last_answer = Some(std::time::Instant::now());
    }

    /// Upstream answered, but the page stops short at a row the feed cannot take: the rows below
    /// it were delivered, and the page says nothing of upstream's size.
    fn answered_short_of(&self, next_index: u64, delivered: usize, refusal: PreflightFailure) {
        tracing::warn!(
            %refusal,
            "ppoi mirror: took the rows below the refused one and will ask for it again"
        );
        let mut progress = self.progress();
        progress.next_index = next_index;
        progress.rows_delivered = progress
            .rows_delivered
            .saturating_add(u64::try_from(delivered).unwrap_or(u64::MAX));
        progress.upstream_rows = None;
        progress.consecutive_failures = progress.consecutive_failures.saturating_add(1);
        progress.last_failure = Some(refusal);
        progress.last_answer = Some(std::time::Instant::now());
        if matches!(refusal, PreflightFailure::BadSignature(_)) {
            progress.signatures_refused = progress.signatures_refused.saturating_add(1);
        }
    }

    fn untaken(&self, row: Option<u64>) {
        self.progress().untaken_row = row;
    }

    fn stopped(&self, reason: String) {
        self.progress().stopped = Some(reason);
    }
}

/// HTTP pull from the configured upstream PPOI service.
pub struct UpstreamPpoiMirror {
    config: MirrorConfig,
    client: reqwest::Client,
    backfill_interval: Option<std::time::Duration>,
}

impl std::fmt::Debug for UpstreamPpoiMirror {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamPpoiMirror")
            .field("endpoint", &self.config.endpoint)
            .field("chain_type", &self.config.chain_type)
            .field("chain_id", &self.config.chain_id)
            .field("backfill_interval", &self.backfill_interval)
            .finish_non_exhaustive()
    }
}

impl UpstreamPpoiMirror {
    /// Build from config, with a client bounded by `config.request_timeout`.
    ///
    /// # Errors
    ///
    /// [`MirrorError::InvalidConfig`] for a page size outside `1..=501` or a zero timeout;
    /// [`MirrorError::Upstream`] if client construction fails, escalated rather than falling
    /// back to a timeout-less client.
    pub fn new(config: MirrorConfig) -> Result<Self> {
        if config.max_rows_per_fetch == 0 || config.max_rows_per_fetch > 501 {
            return Err(MirrorError::InvalidConfig(format!(
                "max_rows_per_fetch {} is outside 1..=501",
                config.max_rows_per_fetch
            )));
        }
        if config.request_timeout.is_zero() {
            return Err(MirrorError::InvalidConfig(
                "request_timeout must be above zero".to_owned(),
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()
            .map_err(|e| MirrorError::Upstream(format!("reqwest builder: {e}")))?;
        Ok(Self {
            config,
            client,
            backfill_interval: None,
        })
    }

    /// Wait `interval` after a page that came back as long as it asked for, and the poll interval
    /// after any other. Only a cold sync sees full pages, so a caught-up worker is back at the
    /// poll cadence one page later. Unset, a full page is followed at once: a cold sync then runs
    /// as fast as the engine applies, which the feed channel paces, and asks upstream for a page
    /// per `max_rows_per_fetch` rows applied. While a row the feed delivered stands untaken, every
    /// page waits the poll.
    #[must_use]
    pub fn with_backfill_interval(mut self, interval: std::time::Duration) -> Self {
        self.backfill_interval = Some(interval);
        self
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

    /// One bounded `ppoi_poi_events` request for index 0 of `list`, over the client, envelope
    /// check, row decoder and signature check the feed itself uses, so `Ok` means the feed's
    /// first page can succeed. The feed retries a dead endpoint forever and only warns; this is
    /// the call that lets a boot path refuse one instead.
    ///
    /// ```no_run
    /// # async fn boot() -> Result<(), Box<dyn std::error::Error>> {
    /// use raven_railgun_ppoi_mirror::UpstreamPpoiMirror;
    /// let mirror = UpstreamPpoiMirror::ofac_default()?;
    /// let list = raven_railgun_core::ListKey([0u8; 32]);
    /// mirror.preflight(&list, std::time::Duration::from_secs(5)).await?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// [`PreflightError`] naming the endpoint and the [`PreflightFailure`] class.
    pub async fn preflight(
        &self,
        list: &ListKey,
        timeout: std::time::Duration,
    ) -> core::result::Result<(), PreflightError> {
        let refuse = |failure, detail| PreflightError {
            endpoint: self.config.endpoint.clone(),
            failure,
            detail,
        };
        let page = self
            .fetch_page(list, 0, 0, Some(timeout), &RowVerifier::for_list(list))
            .await
            .map_err(|(class, detail)| refuse(class, detail))?;
        match page.forged {
            Some(row) => Err(refuse(
                PreflightFailure::BadSignature(row),
                format!(
                    "list key {} does not verify the row's signature",
                    hex_lower(&list.0)
                ),
            )),
            None => Ok(()),
        }
    }

    fn poi_events_params(
        &self,
        list: &ListKey,
        start_index: u64,
        end_index: u64,
    ) -> PoiEventsRequestBody<'_> {
        PoiEventsRequestBody {
            chain_type: &self.config.chain_type,
            chain_id: self.config.chain_id.to_string(),
            txid_version: &self.config.txid_version,
            list_key: hex_lower(&list.0),
            start_index,
            end_index,
        }
    }

    /// Feed `list` from `starting_cursor`, asking only for the rows `span(cursor)` names, and
    /// record what it sees of upstream in `status`.
    ///
    /// `span(cursor)` starts at the lowest list-wide index that some consumer still has to
    /// append, and ends in front of the first index past that which no consumer needs or can
    /// hold. A start above the cursor steps over rows every consumer that can hold them already
    /// holds. A start below it is a row the feed delivered and no consumer took; once it has
    /// stood there for a poll interval, the feed moves back, asks for it again and names it in
    /// [`FeedProgress::untaken_row`] until a consumer takes it, pacing every page at the poll
    /// meanwhile. That recovers a refused row without a restart only if `span` reads what each
    /// consumer holds at the call: a span that never starts below the cursor never sends the
    /// feed back. An empty span stops the feed.
    ///
    /// # Errors
    ///
    /// [`MirrorError::Unheld`] at an empty span, naming the span's start, which can lie below
    /// the cursor; otherwise only non-recoverable failures. A failed request is counted in
    /// `status` and retried at the poll interval, and so is a page that leaves out a row or
    /// carries one whose signature fails, once the rows below that row are delivered.
    pub async fn run_feed<F>(
        self: std::sync::Arc<Self>,
        list: ListKey,
        starting_cursor: u64,
        span: F,
        status: FeedStatus,
        sender: tokio::sync::mpsc::Sender<(raven_railgun_persistence::WalEntryPayload, u64)>,
    ) -> Result<()>
    where
        F: Fn(u64) -> std::ops::Range<u64> + Send,
    {
        let outcome = self
            .feed(list, starting_cursor, span, &status, sender)
            .await;
        status.stopped(match &outcome {
            Ok(()) => "the engine closed the feed channel".to_owned(),
            Err(error) => error.to_string(),
        });
        outcome
    }

    async fn feed<F>(
        &self,
        list: ListKey,
        mut cursor: u64,
        span: F,
        status: &FeedStatus,
        sender: tokio::sync::mpsc::Sender<(raven_railgun_persistence::WalEntryPayload, u64)>,
    ) -> Result<()>
    where
        F: Fn(u64) -> std::ops::Range<u64> + Send,
    {
        use tokio::time::{sleep, Duration, Instant};
        let poll = Duration::from_secs(self.config.poll_interval_secs.max(1));
        let backfill = self.backfill_interval.unwrap_or(Duration::ZERO);
        let verifier = RowVerifier::for_list(&list);
        status.at(cursor);
        tracing::info!(endpoint = %self.config.endpoint, "ppoi mirror: {TRUST_STATEMENT}");
        let mut pause = Duration::ZERO;
        let mut asked_at = Instant::now();
        let mut untaken = UntakenRow::default();
        loop {
            // Measured from the previous request, so the setting bounds the request rate. A closed
            // channel ends the wait, so shutdown is not held for a poll interval.
            tokio::select! {
                biased;
                () = sender.closed() => {
                    tracing::info!(cursor, "ppoi mirror worker exiting; channel closed");
                    return Ok(());
                }
                () = sleep(pause.saturating_sub(asked_at.elapsed())) => {}
            }
            asked_at = Instant::now();
            pause = poll;
            let wanted = span(cursor);
            if let Some(row) = untaken.observe(&wanted, cursor, poll, status) {
                cursor = row;
                status.at(cursor);
            }
            if wanted.start > cursor {
                cursor = wanted.start;
                status.at(cursor);
            }
            if wanted.end <= cursor {
                if untaken.waiting() {
                    continue;
                }
                return Err(MirrorError::Unheld {
                    list_index: wanted.start,
                });
            }
            let end = cursor
                .checked_add(self.config.max_rows_per_fetch - 1)
                .ok_or_else(|| {
                    MirrorError::Decode(format!(
                        "PPOI page starting at {cursor} overflows u64 for {} rows",
                        self.config.max_rows_per_fetch
                    ))
                })?
                .min(wanted.end - 1);
            let Page { mut events, forged } =
                match self.fetch_page(&list, cursor, end, None, &verifier).await {
                    Ok(page) => page,
                    Err((class, detail)) => {
                        tracing::warn!(
                            endpoint = %self.config.endpoint,
                            method = POI_EVENTS_METHOD,
                            failure = %class,
                            %detail,
                            "ppoi mirror: page request failed; asking again at the poll interval"
                        );
                        status.failed(class);
                        continue;
                    }
                };
            let missing = truncate_at_first_missing(&mut events, cursor);
            let taken = u64::try_from(events.len()).unwrap_or(u64::MAX);
            let next = cursor.saturating_add(taken);
            let refusal = page_refusal(missing, forged, next);
            let full = taken == end - cursor + 1;
            // While a row below the cursor is untaken, every page past it may be refused again,
            // so the feed holds to the poll rather than re-download the rest of the span back
            // to back each time it comes back for the row.
            if full && !untaken.pending() {
                pause = backfill;
            }
            for ev in events {
                // Upstream rows have no block, and 0 keeps them out of every reorg unwind
                // (`h > height` is never true). A real height here makes reorgs drop PPOI rows.
                let leaf_added = raven_railgun_persistence::WalEntryPayload::PpoiListLeafAdded {
                    list_key: list.0,
                    list_index: ev.list_index,
                    blinded_commitment: ev.blinded_commitment.0,
                    event_type: ev.event_type,
                    validated_merkleroot: ev.validated_merkleroot,
                };
                if sender.send((leaf_added, 0)).await.is_err() {
                    tracing::info!("ppoi mirror engine consumer dropped channel; exiting");
                    return Ok(());
                }
            }
            cursor = next;
            let delivered = usize::try_from(taken).unwrap_or(usize::MAX);
            match refusal {
                Some(refusal) => status.answered_short_of(cursor, delivered, refusal),
                // A short answer is the whole of upstream's list: no row past its last exists yet.
                None => status.answered(cursor, delivered, (!full).then_some(cursor)),
            }
        }
    }

    /// One `ppoi_poi_events` page, decoded and checked by `verifier`. `timeout` overrides the
    /// client-wide bound. A failure carries its class beside its worded detail.
    async fn fetch_page(
        &self,
        list: &ListKey,
        start_index: u64,
        end_index: u64,
        timeout: Option<std::time::Duration>,
        verifier: &RowVerifier,
    ) -> core::result::Result<Page, (PreflightFailure, String)> {
        let bound = timeout.unwrap_or(self.config.request_timeout);
        let events: Vec<WirePOISyncedListEvent> = self
            .exchange_json_rpc(
                POI_EVENTS_METHOD,
                self.poi_events_params(list, start_index, end_index),
                timeout,
            )
            .await
            .map_err(|failure| failure.classify(bound))?;
        decode_indexed_events(events, start_index, end_index, verifier)
            .map_err(|error| (PreflightFailure::UndecodableRows, error.to_string()))
    }

    async fn exchange_json_rpc<P, T>(
        &self,
        method: &'static str,
        params: P,
        timeout: Option<std::time::Duration>,
    ) -> core::result::Result<T, RpcFailure>
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
        let mut post = self.client.post(&self.config.endpoint).json(&request);
        if let Some(timeout) = timeout {
            post = post.timeout(timeout);
        }
        let response = post.send().await.map_err(RpcFailure::Send)?;
        let status = response.status();
        if !status.is_success() {
            return Err(RpcFailure::Status(status));
        }
        let response: JsonRpcResponse<T> = response.json().await.map_err(RpcFailure::Body)?;
        if response.jsonrpc != JSON_RPC_VERSION || response.id != 1 {
            return Err(RpcFailure::Envelope(format!(
                "response envelope mismatch: version {}, id {}",
                response.jsonrpc, response.id
            )));
        }
        match (response.result, response.error) {
            (Some(result), None) => Ok(result),
            (None, Some(error)) => Err(RpcFailure::Rpc {
                code: error.code,
                message: error.message,
            }),
            (Some(_), Some(_)) => Err(RpcFailure::Envelope(
                "response contains both result and error".to_owned(),
            )),
            (None, None) => Err(RpcFailure::Envelope(
                "response contains neither result nor error".to_owned(),
            )),
        }
    }
}

/// A span start below the cursor: a row the feed delivered that no consumer took.
#[derive(Debug, Default)]
struct UntakenRow {
    /// The row the span starts on below the cursor, and since when.
    standing: Option<(u64, tokio::time::Instant)>,
    /// The row last asked for again, until the span starts past it.
    asked_again: Option<u64>,
}

impl UntakenRow {
    /// The row to ask for again, once the span has started on it, below `cursor`, for
    /// `patience`. Rows still in flight downstream look the same until applied, so a row is only
    /// asked for again once it stops moving: a duplicate is refused downstream, a skipped row is
    /// never recovered. `status` names the row from then until the span starts past it.
    fn observe(
        &mut self,
        wanted: &std::ops::Range<u64>,
        cursor: u64,
        patience: std::time::Duration,
        status: &FeedStatus,
    ) -> Option<u64> {
        if self.asked_again.is_some_and(|row| wanted.start > row) {
            self.asked_again = None;
            status.untaken(None);
        }
        if wanted.start >= cursor || wanted.is_empty() {
            self.standing = None;
            return None;
        }
        match self.standing {
            Some((row, since)) if row == wanted.start => {
                if since.elapsed() < patience {
                    return None;
                }
                tracing::warn!(
                    row,
                    "ppoi mirror: no consumer took the row; asking for it again"
                );
                self.standing = None;
                self.asked_again = Some(row);
                status.untaken(self.asked_again);
                Some(row)
            }
            _ => {
                self.standing = Some((wanted.start, tokio::time::Instant::now()));
                None
            }
        }
    }

    fn waiting(&self) -> bool {
        self.standing.is_some()
    }

    /// A row stands below the cursor, or was asked for again and not yet passed.
    fn pending(&self) -> bool {
        self.standing.is_some() || self.asked_again.is_some()
    }
}

/// Why a page stops short of what it holds: the first row missing from it, or the first whose
/// signature failed when no row below it is missing. `next` is the first index not taken.
fn page_refusal(missing: Option<u64>, forged: Option<u64>, next: u64) -> Option<PreflightFailure> {
    match (missing, forged) {
        (Some(row), _) => Some(PreflightFailure::MissingRow(row)),
        (None, Some(row)) if row == next => Some(PreflightFailure::BadSignature(row)),
        (None, Some(_)) => Some(PreflightFailure::MissingRow(next)),
        (None, None) => None,
    }
}

/// One failed JSON-RPC exchange, kept classified until a caller words it.
#[derive(Debug)]
enum RpcFailure {
    Send(reqwest::Error),
    Status(reqwest::StatusCode),
    Body(reqwest::Error),
    Envelope(String),
    Rpc { code: i64, message: String },
}

impl RpcFailure {
    fn classify(self, timeout: std::time::Duration) -> (PreflightFailure, String) {
        let class = match &self {
            Self::Send(error) => classify_send_error(error, timeout),
            Self::Status(status) => PreflightFailure::HttpStatus(status.as_u16()),
            // A body that stalls is a timeout, not a malformed reply.
            Self::Body(error) if error.is_timeout() => PreflightFailure::Timeout(timeout),
            Self::Body(_) | Self::Envelope(_) => PreflightFailure::MalformedEnvelope,
            Self::Rpc { code, .. } => PreflightFailure::Rpc(*code),
        };
        let detail = match self {
            Self::Send(error) | Self::Body(error) => error_chain(&error),
            Self::Status(status) => status.to_string(),
            Self::Envelope(detail) => detail,
            Self::Rpc { message, .. } => message,
        };
        (class, detail)
    }
}

/// Timeout is tested first: a connect that the OS itself times out is also a connect error.
fn classify_send_error(error: &reqwest::Error, timeout: std::time::Duration) -> PreflightFailure {
    if error.is_timeout() {
        return PreflightFailure::Timeout(timeout);
    }
    if !error.is_connect() {
        return PreflightFailure::Transport;
    }
    // The connector's error type is private; its message is the only handle on a DNS failure.
    let mut cause = std::error::Error::source(error);
    while let Some(inner) = cause {
        if inner.to_string() == "dns error" {
            return PreflightFailure::Dns;
        }
        cause = inner.source();
    }
    PreflightFailure::Connect
}

/// `reqwest` words only the outermost layer; the causes carry the actionable part.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut cause = error.source();
    while let Some(inner) = cause {
        text.push_str(": ");
        text.push_str(&inner.to_string());
        cause = inner.source();
    }
    text
}

/// The list key as a signature verifier.
struct RowVerifier {
    /// `None` when the key is not a curve point: it then verifies no row, so every row is
    /// refused rather than the list being taken unchecked.
    key: Option<ed25519_dalek::VerifyingKey>,
}

impl RowVerifier {
    fn for_list(list: &ListKey) -> Self {
        let key = ed25519_dalek::VerifyingKey::from_bytes(&list.0).ok();
        if key.is_none() {
            tracing::warn!(
                list_key = %hex_lower(&list.0),
                "ppoi mirror: the list key is not an ed25519 public key, so no row can verify"
            );
        }
        Self { key }
    }

    /// Upstream signs `JSON.stringify({index, blindedCommitment, type})` over the wire strings.
    /// Five mainnet rows serve their commitment without `0x` and are signed that way, so the
    /// strings are never normalised first.
    fn accepts(
        &self,
        index: u64,
        blinded_commitment: &str,
        event_type: &str,
        signature: &[u8; 64],
    ) -> bool {
        let Some(key) = &self.key else {
            return false;
        };
        let Ok(message) = signed_message(index, blinded_commitment, event_type) else {
            return false;
        };
        // Stricter than upstream's verify: small-order keys and R are refused. Only the key
        // holder could craft a signature that passes there and fails here, and it fails closed.
        key.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(signature))
            .is_ok()
    }
}

/// The bytes a list provider signs for one event.
fn signed_message(
    index: u64,
    blinded_commitment: &str,
    event_type: &str,
) -> serde_json::Result<Vec<u8>> {
    #[derive(Serialize)]
    struct SignedPoiEvent<'a> {
        index: u64,
        #[serde(rename = "blindedCommitment")]
        blinded_commitment: &'a str,
        #[serde(rename = "type")]
        event_type: &'a str,
    }
    serde_json::to_vec(&SignedPoiEvent {
        index,
        blinded_commitment,
        event_type,
    })
}

/// A decoded page: the rows below `forged`, and the index of the first row whose signature
/// failed, if one did.
struct Page {
    events: Vec<IndexedPoiEvent>,
    forged: Option<u64>,
}

#[derive(Clone, Debug)]
struct IndexedPoiEvent {
    list_index: u32,
    blinded_commitment: BlindedCommitment,
    event_type: raven_railgun_persistence::PpoiEventType,
    validated_merkleroot: [u8; 32],
}

/// Cut `events`, a decoded page asked for from `from`, at its first missing row, and name that
/// row. The cursor may only pass rows that were delivered, so the missing row is asked for again.
fn truncate_at_first_missing(events: &mut Vec<IndexedPoiEvent>, from: u64) -> Option<u64> {
    let contiguous = events
        .iter()
        .zip(from..)
        .take_while(|(ev, at)| u64::from(ev.list_index) == *at)
        .count();
    let missing = (contiguous < events.len())
        .then(|| from.saturating_add(u64::try_from(contiguous).unwrap_or(u64::MAX)));
    events.truncate(contiguous);
    missing
}

fn decode_indexed_events(
    events: Vec<WirePOISyncedListEvent>,
    start_index: u64,
    end_index: u64,
    verifier: &RowVerifier,
) -> Result<Page> {
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
        let event_type = match event.signed_event.event_type.as_str() {
            "Shield" => raven_railgun_persistence::PpoiEventType::Shield,
            "Transact" => raven_railgun_persistence::PpoiEventType::Transact,
            "Unshield" => raven_railgun_persistence::PpoiEventType::Unshield,
            "LegacyTransact" => raven_railgun_persistence::PpoiEventType::LegacyTransact,
            event_type => {
                return Err(MirrorError::Decode(format!(
                    "unknown PPOI event type {event_type} at index {index}"
                )));
            }
        };
        let validated_merkleroot = decode_hex(&event.validated_merkleroot).ok_or_else(|| {
            MirrorError::Decode(format!("invalid validatedMerkleroot hex at index {index}"))
        })?;
        // Upstream serves a stored tree root or omits the row; the engine applies an all-zero
        // root uncompared, so one arriving here would skip the only check on these bytes.
        if validated_merkleroot == [0u8; 32] {
            return Err(MirrorError::Decode(format!(
                "all-zero validatedMerkleroot at index {index}: not a root upstream can publish"
            )));
        }
        let bc_str = &event.signed_event.blinded_commitment;
        let bc_bytes = decode_hex(bc_str).ok_or_else(|| {
            MirrorError::Decode(format!("invalid bc hex at index {index}: {bc_str}"))
        })?;
        let list_index = u32::try_from(index).map_err(|_| {
            MirrorError::Decode(format!("list_index {index} exceeds u32 IMT capacity"))
        })?;
        let verified = decode_hex(&event.signed_event.signature).is_some_and(|signature| {
            verifier.accepts(index, bc_str, &event.signed_event.event_type, &signature)
        });
        if !verified {
            // Rows past a refused one cannot be applied before it, so they are not decoded.
            return Ok(Page {
                events: out,
                forged: Some(index),
            });
        }
        out.push(IndexedPoiEvent {
            list_index,
            blinded_commitment: BlindedCommitment::from_bytes(bc_bytes),
            event_type,
            validated_merkleroot,
        });
    }
    Ok(Page {
        events: out,
        forged: None,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte for byte what `JSON.stringify({index, blindedCommitment, type})` produces: that key
    /// order, no whitespace, the number bare and the strings quoted as given.
    #[test]
    fn the_signed_message_is_upstreams_json_stringify() {
        let message = signed_message(301_593, "0141bf", "Unshield").expect("serializes");
        assert_eq!(
            message,
            br#"{"index":301593,"blindedCommitment":"0141bf","type":"Unshield"}"#
        );
    }

    #[test]
    fn upstream_ppoi_mirror_constructor_round_trips() {
        let m = UpstreamPpoiMirror::ofac_default().expect("ofac_default builds");
        assert_eq!(m.endpoint(), "https://ppoi.fdi.network");
    }
}
