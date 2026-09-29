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
//!
//! # Load on upstream
//!
//! One request to upstream is in flight at a time, whatever the number of feeds, and two start
//! no less than [`DEFAULT_REQUEST_SPACING`] apart unless the caller lowers that for a local
//! replay. Each carries [`USER_AGENT`]. Failures in a row lengthen the wait before the next
//! request, up to [`MirrorConfig::failure_backoff_cap`], and an answer resets it. A mirror given
//! [`UpstreamPpoiMirror::with_node_status`] also asks upstream's node status for a list's row
//! count, at most once a poll per feed and only after a page that does not show where the list
//! ends.

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

/// Least time between the starts of two upstream requests, unless the caller lowers it.
pub const DEFAULT_REQUEST_SPACING: std::time::Duration = std::time::Duration::from_secs(1);

/// Default longest wait after failures in a row.
pub const DEFAULT_FAILURE_BACKOFF_CAP: std::time::Duration = std::time::Duration::from_secs(300);

/// `User-Agent` on every upstream request: the operator of an endpoint can tell who is asking.
pub const USER_AGENT: &str = concat!(
    "raven-railgun/",
    env!("CARGO_PKG_VERSION"),
    " (ppoi-mirror; +https://github.com/hisoka-io/raven)"
);

/// Default upstream PPOI endpoint.
pub const DEFAULT_PPOI_ENDPOINT: &str = "https://ppoi.fdi.network";

#[cfg(feature = "test-signer")]
pub mod test_signer;

const JSON_RPC_VERSION: &str = "2.0";
const POI_EVENTS_METHOD: &str = "ppoi_poi_events";
const NODE_STATUS_METHOD: &str = "ppoi_node_status";

/// Upstream's network name for an EVM chain, the key its node status files each list's counts
/// under; `None` for a pair not listed here. A wrong name would read another chain's count.
#[must_use]
pub fn ppoi_network_name(chain_type: &str, chain_id: u64) -> Option<&'static str> {
    match (chain_type, chain_id) {
        ("0", 1) => Some("Ethereum"),
        ("0", 56) => Some("BNB_Chain"),
        ("0", 137) => Some("Polygon"),
        ("0", 42_161) => Some("Arbitrum"),
        ("0", 11_155_111) => Some("Ethereum_Sepolia"),
        ("0", 80_002) => Some("Polygon_Amoy"),
        _ => None,
    }
}

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
    /// Longest wait after failures in a row; below the poll interval, the poll interval.
    pub failure_backoff_cap: std::time::Duration,
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
            failure_backoff_cap: DEFAULT_FAILURE_BACKOFF_CAP,
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
    /// Upstream's row count as its latest answers give it, whether or not the node took the
    /// rows: one past the last row the latest page served, or the index it asked from when it
    /// served none. After a page that served a row at the end of what it asked for, and so does
    /// not show where the list ends, the larger of that and the count upstream's node status
    /// last stated (see [`UpstreamPpoiMirror::with_node_status`]). The status is unsigned, so
    /// this moves no readiness state. `None` before the first answer; a failed request leaves
    /// it as it was.
    pub upstream_rows_seen: Option<u64>,
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

    fn answered(&self, next_index: u64, delivered: usize, upstream_rows: Option<u64>, seen: u64) {
        let mut progress = self.progress();
        progress.next_index = next_index;
        progress.rows_delivered = progress
            .rows_delivered
            .saturating_add(u64::try_from(delivered).unwrap_or(u64::MAX));
        progress.upstream_rows = upstream_rows;
        progress.upstream_rows_seen = Some(seen);
        progress.consecutive_failures = 0;
        progress.last_failure = None;
        progress.last_answer = Some(std::time::Instant::now());
    }

    /// Upstream answered, but the page stops short at a row the feed cannot take: the rows below
    /// it were delivered, and the list is not known to end at the last of them.
    fn answered_short_of(
        &self,
        next_index: u64,
        delivered: usize,
        refusal: PreflightFailure,
        seen: u64,
    ) {
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
        progress.upstream_rows_seen = Some(seen);
        progress.consecutive_failures = progress.consecutive_failures.saturating_add(1);
        progress.last_failure = Some(refusal);
        progress.last_answer = Some(std::time::Instant::now());
        if matches!(refusal, PreflightFailure::BadSignature(_)) {
            progress.signatures_refused = progress.signatures_refused.saturating_add(1);
        }
    }

    fn seen(&self, rows: u64) {
        self.progress().upstream_rows_seen = Some(rows);
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
    request_spacing: std::time::Duration,
    /// Upstream's network name for this chain, when the feeds ask its node status for counts.
    status_network: Option<String>,
    /// When the last request started. Held across each request, so only one is ever in flight.
    last_request: tokio::sync::Mutex<Option<tokio::time::Instant>>,
}

impl std::fmt::Debug for UpstreamPpoiMirror {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamPpoiMirror")
            .field("endpoint", &self.config.endpoint)
            .field("chain_type", &self.config.chain_type)
            .field("chain_id", &self.config.chain_id)
            .field("request_spacing", &self.request_spacing)
            .field("status_network", &self.status_network)
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
        let client = client_builder(&config)
            .build()
            .map_err(|e| MirrorError::Upstream(format!("reqwest builder: {e}")))?;
        Ok(Self::with_client(config, client))
    }

    fn with_client(config: MirrorConfig, client: reqwest::Client) -> Self {
        Self {
            config,
            client,
            request_spacing: DEFAULT_REQUEST_SPACING,
            status_network: None,
            last_request: tokio::sync::Mutex::new(None),
        }
    }

    /// Have each feed ask upstream's node status for its list's row count, filed under
    /// `network` (see [`ppoi_network_name`]), after a page that served a row at the end of what
    /// it asked for, and so does not show where the list ends; at most once a poll per feed.
    /// [`FeedProgress::upstream_rows_seen`] then reads upstream's count during a cold sync and
    /// past a refused row. Upstream keeps these counts for its `V2_PoseidonMerkle` lists only,
    /// so a mirror on another txid version asks nothing.
    #[must_use]
    pub fn with_node_status(mut self, network: impl Into<String>) -> Self {
        self.status_network = Some(network.into());
        self
    }

    /// Least time between the starts of two requests to upstream, from every feed and preflight
    /// of this mirror together; [`DEFAULT_REQUEST_SPACING`] unless set. A page that came back as
    /// long as it asked for is followed as soon as this allows, so it also paces a cold sync;
    /// any other page waits the poll interval, and so does every page while a row the feed
    /// delivered stands untaken. Only a caught-up worker sees short pages, so it is back at the
    /// poll one page after a cold sync ends. Lower it only for a local replay of a capture.
    #[must_use]
    pub fn with_backfill_interval(mut self, interval: std::time::Duration) -> Self {
        self.request_spacing = interval;
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
    /// `status` and retried after the poll interval, longer while failures run on, and so is a
    /// page that leaves out a row or carries one whose signature fails, once the rows below
    /// that row are delivered.
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
        let verifier = RowVerifier::for_list(&list);
        status.at(cursor);
        tracing::info!(endpoint = %self.config.endpoint, "ppoi mirror: {TRUST_STATEMENT}");
        let mut pause = Duration::ZERO;
        let mut asked_at = Instant::now();
        let mut untaken = UntakenRow::default();
        let mut failures = 0u32;
        let mut count = UpstreamCount::default();
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
            let Page {
                mut events,
                forged,
                last_served,
            } = match self.fetch_page(&list, cursor, end, None, &verifier).await {
                Ok(page) => page,
                Err((class, detail)) => {
                    failures = failures.saturating_add(1);
                    pause = failure_wait(poll, failures, self.config.failure_backoff_cap);
                    tracing::warn!(
                        endpoint = %self.config.endpoint,
                        method = POI_EVENTS_METHOD,
                        failure = %class,
                        %detail,
                        retry_in = ?pause,
                        "ppoi mirror: page request failed; asking again after the wait"
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
            // to back each time it comes back for the row. Otherwise the request spacing alone
            // paces a full page.
            if full && !untaken.pending() {
                pause = Duration::ZERO;
            }
            if !deliver(&list, events, &sender).await {
                tracing::info!("ppoi mirror engine consumer dropped channel; exiting");
                return Ok(());
            }
            let (seen, ends) = count.page(last_served, cursor, end);
            cursor = next;
            let delivered = usize::try_from(taken).unwrap_or(usize::MAX);
            if let Some(refusal) = refusal {
                status.answered_short_of(cursor, delivered, refusal, seen);
                failures = failures.saturating_add(1);
                pause = failure_wait(poll, failures, self.config.failure_backoff_cap);
            } else {
                // A short answer is the whole of upstream's list: no row past its last exists yet.
                status.answered(cursor, delivered, (!full).then_some(cursor), seen);
                failures = 0;
            }
            self.renew_stated_count(&list, &mut count, ends, poll, status)
                .await;
        }
    }

    /// After a page that does not show where the list ends, asks upstream's node status for
    /// `list`'s count, at most once a poll, and records it. A failure is only logged: the
    /// pages, not the status, are the feed's health.
    async fn renew_stated_count(
        &self,
        list: &ListKey,
        count: &mut UpstreamCount,
        page_ends: bool,
        poll: std::time::Duration,
        status: &FeedStatus,
    ) {
        let Some(network) = self
            .status_network
            .as_deref()
            .filter(|_| self.config.txid_version == DEFAULT_TXID_VERSION)
        else {
            return;
        };
        if page_ends || count.asked.is_some_and(|at| at.elapsed() < poll) {
            return;
        }
        count.asked = Some(tokio::time::Instant::now());
        match self.stated_rows(list, network).await {
            Ok(rows) => {
                count.stated = Some(rows);
                status.seen(rows.max(count.shown));
            }
            Err((class, detail)) => tracing::warn!(
                endpoint = %self.config.endpoint,
                method = NODE_STATUS_METHOD,
                failure = %class,
                %detail,
                "ppoi mirror: node status gave no row count; the feed goes on without it"
            ),
        }
    }

    /// The row count upstream's node status states for `list` on `network`: the sum of its
    /// per-type event counts, which is how upstream's own nodes size a list.
    async fn stated_rows(
        &self,
        list: &ListKey,
        network: &str,
    ) -> core::result::Result<u64, (PreflightFailure, String)> {
        let status: serde_json::Value = self
            .exchange_json_rpc(NODE_STATUS_METHOD, serde_json::Map::new(), None)
            .await
            .map_err(|failure| failure.classify(self.config.request_timeout))?;
        let list_key = hex_lower(&list.0);
        status
            .get("forNetwork")
            .and_then(|networks| networks.get(network))
            .and_then(|lists| lists.get("listStatuses"))
            .and_then(|lists| lists.get(&list_key))
            .and_then(|list| list.get("poiEventLengths"))
            .and_then(serde_json::Value::as_object)
            .and_then(|lengths| {
                lengths.values().try_fold(0u64, |sum, count| {
                    count.as_u64().and_then(|count| sum.checked_add(count))
                })
            })
            .ok_or_else(|| {
                (
                    PreflightFailure::MalformedEnvelope,
                    format!("no poiEventLengths for list {list_key} on {network}"),
                )
            })
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
        // Held until the body is read, so feeds sharing this mirror queue behind each other.
        let mut last_request = self.last_request.lock().await;
        if let Some(at) = *last_request {
            tokio::time::sleep_until(at + self.request_spacing).await;
        }
        *last_request = Some(tokio::time::Instant::now());
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

/// Hands each row downstream; `false` once the consumer has dropped the channel.
async fn deliver(
    list: &ListKey,
    events: Vec<IndexedPoiEvent>,
    sender: &tokio::sync::mpsc::Sender<(raven_railgun_persistence::WalEntryPayload, u64)>,
) -> bool {
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
            return false;
        }
    }
    true
}

fn client_builder(config: &MirrorConfig) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .timeout(config.request_timeout)
        .user_agent(USER_AGENT)
}

/// What a feed knows of upstream's row count beyond the rows it took.
#[derive(Debug, Default)]
struct UpstreamCount {
    /// One past the last row the latest page served, or where it was asked from if none.
    shown: u64,
    /// The count upstream's node status last stated, until a page shows where the list ends.
    stated: Option<u64>,
    /// When the node status was last asked for.
    asked: Option<tokio::time::Instant>,
}

impl UpstreamCount {
    /// Takes a page asked for from `from` to `end` whose highest served index is `last_served`.
    /// Returns upstream's count as now known, and whether the page shows where the list ends:
    /// one that served nothing at `end` does, whether or not its rows were taken.
    fn page(&mut self, last_served: Option<u64>, from: u64, end: u64) -> (u64, bool) {
        self.shown = last_served.map_or(from, |last| last.saturating_add(1));
        let ends = last_served.is_none_or(|last| last < end);
        if ends {
            self.stated = None;
        }
        (
            self.stated.map_or(self.shown, |rows| rows.max(self.shown)),
            ends,
        )
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

/// Wait before the next request after `failures` in a row. Two in a row still wait the poll, as a
/// caught-up feed is held to renewing upstream's row count within three polls; each one past
/// that doubles the wait, up to `cap`.
fn failure_wait(
    poll: std::time::Duration,
    failures: u32,
    cap: std::time::Duration,
) -> std::time::Duration {
    let doublings = failures.saturating_sub(2).min(16);
    poll.saturating_mul(1 << doublings).min(cap.max(poll))
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
    /// Some rows serve their commitment without `0x`, or without its leading zero digits, and
    /// are signed that way, so the strings are never normalised first.
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

/// A decoded page: the rows below `forged`, the index of the first row whose signature
/// failed, if one did, and the highest index the answer served inside the range asked for,
/// whether or not its row was taken.
struct Page {
    events: Vec<IndexedPoiEvent>,
    forged: Option<u64>,
    last_served: Option<u64>,
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
    let last_served = events
        .iter()
        .map(|event| event.signed_event.index)
        .filter(|index| (start_index..=end_index).contains(index))
        .max();
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
        let bc_bytes = decode_commitment(bc_str).ok_or_else(|| {
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
                last_served,
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
        last_served,
    })
}

/// A served `blindedCommitment`: 1 to 64 hex digits, optionally after `0x`, as the 32-byte
/// big-endian number they spell. Upstream's tree inserts the number, and some Sepolia rows are
/// served with their leading zero digits dropped.
fn decode_commitment(text: &str) -> Option<[u8; 32]> {
    let digits = text.strip_prefix("0x").unwrap_or(text).as_bytes();
    let pad = 64usize.checked_sub(digits.len()).filter(|pad| *pad < 64)?;
    let mut padded = [b'0'; 64];
    padded.get_mut(pad..)?.copy_from_slice(digits);
    decode_hex(std::str::from_utf8(&padded).ok()?)
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
    fn a_commitment_of_1_to_64_hex_digits_is_the_number_it_spells() {
        let full = "0123456789abcdef".repeat(4);
        let mut expected = [0u8; 32];
        for (at, byte) in expected.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&full[2 * at..2 * at + 2], 16).unwrap();
        }
        assert_eq!(decode_commitment(&full), Some(expected));
        assert_eq!(decode_commitment(&format!("0x{full}")), Some(expected));
        assert_eq!(
            decode_commitment(&format!("0x{}", &full[1..])),
            Some(expected)
        );
        assert_eq!(decode_commitment("0x1"), Some(one_at_the_end()));
        assert_eq!(decode_commitment("01"), Some(one_at_the_end()));
        assert_eq!(decode_commitment("0x0"), Some([0u8; 32]));
        assert_eq!(
            decode_commitment("0xABC").map(|b| [b[30], b[31]]),
            Some([0x0a, 0xbc])
        );
    }

    fn one_at_the_end() -> [u8; 32] {
        let mut one = [0u8; 32];
        one[31] = 1;
        one
    }

    #[test]
    fn a_commitment_past_64_digits_empty_or_not_hex_is_refused() {
        let full = "ab".repeat(32);
        for text in [
            String::new(),
            "0x".to_owned(),
            format!("{full}0"),
            format!("0x0{full}"),
            "0x12g4".to_owned(),
            "0X12".to_owned(),
            "0x0x12".to_owned(),
            " 12".to_owned(),
            "+12".to_owned(),
            format!("\u{e9}{}", &full[2..]),
        ] {
            assert_eq!(decode_commitment(&text), None, "{text:?}");
        }
    }

    #[test]
    fn failures_in_a_row_wait_the_poll_twice_then_double_up_to_the_cap() {
        let poll = std::time::Duration::from_secs(30);
        let cap = std::time::Duration::from_secs(300);
        let waits: Vec<u64> = (1..=8)
            .map(|failures| failure_wait(poll, failures, cap).as_secs())
            .collect();
        assert_eq!(waits, [30, 30, 60, 120, 240, 300, 300, 300]);
        assert_eq!(failure_wait(poll, u32::MAX, cap), cap);
        assert_eq!(
            failure_wait(poll, 5, std::time::Duration::from_secs(1)),
            poll,
            "a cap below the poll never shortens the poll"
        );
    }

    /// Refuses every name at once, so the verdict never waits on a real resolver.
    struct NoSuchHost;

    impl reqwest::dns::Resolve for NoSuchHost {
        fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
            let refusal = format!("{}: no such host", name.as_str());
            Box::pin(async move { Err(refusal.into()) })
        }
    }

    #[tokio::test]
    async fn unresolvable_host_is_classed_dns() {
        let config = MirrorConfig {
            endpoint: "http://raven-preflight.invalid".to_owned(),
            ..MirrorConfig::default()
        };
        let client = client_builder(&config)
            .dns_resolver(std::sync::Arc::new(NoSuchHost))
            .build()
            .expect("client builds");
        let error = UpstreamPpoiMirror::with_client(config, client)
            .preflight(&ListKey([0u8; 32]), std::time::Duration::from_secs(60))
            .await
            .expect_err("a host that does not resolve must be refused");
        assert_eq!(error.failure, PreflightFailure::Dns, "{error}");
        assert_eq!(error.endpoint, "http://raven-preflight.invalid");
    }

    #[test]
    fn upstream_ppoi_mirror_constructor_round_trips() {
        let m = UpstreamPpoiMirror::ofac_default().expect("ofac_default builds");
        assert_eq!(m.endpoint(), "https://ppoi.fdi.network");
    }
}
