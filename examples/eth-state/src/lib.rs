//! Generic Ethereum-state private-balance PIR demo (flat state, no trie).
//!
//! Serves a flat `address -> 32-byte big-endian balance` corpus through the
//! InsPIRe respond path. One changed account is one row plus one shard re-encode:
//! no trie, no state root, no ancestor churn. Generic Ethereum-state vocabulary
//! only; depends on the framework crates, never on an application adapter.
//!
//! The address -> leaf-index map follows the flat single-keyspace shape of
//! EIP-7864 (Unified Binary Tree, draft): a plain dense `u64` leaf assigned per
//! address, `shard = flat_index / ENTRIES_PER_SHARD`. It does NOT build a live
//! unified binary tree and uses no per-tree key schedule.

#[cfg(feature = "anvil-e2e")]
pub mod anvil;
pub mod fold;
pub mod harness;
pub mod ingest;

use bytes::Bytes;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use raven_core::server_error::Result as SchemeResult;
use raven_core::ServerError;
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, ShardConfig};
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::{
    setup_with_rng, ClientSession, EncodedDatabase, SeededClientQuery, ServerCrs, ServerResponse,
};
#[cfg(feature = "cached-respond")]
use raven_inspire::{respond_seeded_inspiring_cached, ServerInspiringCache};
#[cfg(not(feature = "cached-respond"))]
use raven_inspire::respond_seeded_inspiring;
#[cfg(feature = "cached-respond")]
use std::sync::Arc;
use raven_server::{PirInstance, PirScheme};

use raven_client::{build_seeded_query_rust, extract_response_rust};

/// Fixed record width: byte 0 is the presence tag, bytes 1..32 the big-endian balance. Even,
/// so the encoder's 16-bit-chunk reader is well-defined; `num_polys = (32*8)/16 = 16`.
pub const ENTRY_SIZE: usize = 32;

/// Presence tag at record byte 0 on every constructed record (including a zero balance), so a
/// changed-to-zero balance is distinguishable from an absent (all-zero) slot.
pub const PRESENT_TAG: u8 = 0x01;

/// Entries per shard, equal to the ring dimension; `shard = flat_index / 2048`.
pub const ENTRIES_PER_SHARD: usize = 2048;

/// Errors from the flat-state demo glue. Every variant names the failing operation.
#[derive(Debug, thiserror::Error)]
pub enum EthStateError {
    /// A record exceeds the fixed 32-byte entry width.
    #[error("record too large: {got} bytes exceeds the 31-byte balance field (byte 0 is the presence tag)")]
    RecordTooLarge {
        /// Observed record length.
        got: usize,
    },
    /// InsPIRe setup/encode failed.
    #[error("flat-state setup failed: {0}")]
    Setup(String),
    /// Client query construction failed.
    #[error("client query build failed: {0}")]
    Query(String),
    /// Response extraction/decode failed.
    #[error("response decode failed: {0}")]
    Decode(String),
    /// Server respond failed.
    #[error("respond failed: {0}")]
    Respond(String),
}

/// Construct the fixed [`ENTRY_SIZE`]-byte record: byte 0 is the [`PRESENT_TAG`], the value is
/// big-endian right-aligned in bytes `1..ENTRY_SIZE`. A value wider than `ENTRY_SIZE - 1` is
/// rejected, since byte 0 is reserved for the tag.
///
/// ```
/// let r = eth_state::pad_record(&[7u8; 8]).expect("fits");
/// assert_eq!(r.len(), eth_state::ENTRY_SIZE);
/// assert_eq!(r[0], eth_state::PRESENT_TAG);
/// ```
pub fn pad_record(value: &[u8]) -> Result<Bytes, EthStateError> {
    if value.len() >= ENTRY_SIZE {
        return Err(EthStateError::RecordTooLarge { got: value.len() });
    }
    let mut buf = vec![0u8; ENTRY_SIZE];
    buf[0] = PRESENT_TAG;
    buf[ENTRY_SIZE - value.len()..].copy_from_slice(value);
    Ok(Bytes::from(buf))
}

/// Decoded record bytes, verbatim. The byte-0 tag MUST survive here: [`record_present`] runs on
/// these bytes downstream in the fan-out, so stripping the tag would make a present-zero record
/// read as absent. The comparison against a normalized expected stays symmetric (both tagged).
///
/// ```
/// let r = eth_state::pad_record(&[7u8; 8]).expect("fits");
/// assert_eq!(eth_state::unpad_record(&r), r);
/// ```
pub fn unpad_record(record: &[u8]) -> Bytes {
    Bytes::copy_from_slice(record)
}

/// Server-side state for one flat-balance engine.
pub struct FlatServerState {
    /// Public common reference string.
    pub crs: ServerCrs,
    /// Encoded shard corpus (its `config` is the client's [`ShardConfig`]).
    pub encoded_db: EncodedDatabase,
    /// Per-database server-compute cache (CRS-static `pack_params`/`offline_keys`, zero
    /// per-client data). Built once per engine and Arc-cloned through every fold, never
    /// rebuilt: `num_columns` is fixed for a fixed `entry_size`.
    #[cfg(feature = "cached-respond")]
    pub cache: Arc<ServerInspiringCache>,
}

/// Generic flat-state balance PIR scheme. Serves a fixed-width record corpus via
/// the handshake-free InsPIRe respond path: each query carries inline packing keys
/// with `session_handle: None` and the respond call is given no server session
/// store, so the engine is both client-stateless and server-stateless.
pub struct FlatBalanceScheme;

impl PirScheme for FlatBalanceScheme {
    type ServerState = FlatServerState;
    type Query = SeededClientQuery;
    type Response = ServerResponse;

    fn respond(state: &Self::ServerState, query: &Self::Query) -> SchemeResult<Self::Response> {
        #[cfg(feature = "cached-respond")]
        let result = {
            // The cache was built for this engine's `num_columns = ceil(entry_size/2)`; a fold
            // that diverged the corpus shape from the cache would silently corrupt the response.
            // Make the doc-only invariant a debug guard.
            debug_assert!(
                state
                    .encoded_db
                    .shards
                    .first()
                    .is_none_or(|s| s.polynomials.len() == ENTRY_SIZE / 2),
                "cached respond: shard column count must equal the cache's num_columns"
            );
            respond_seeded_inspiring_cached(&state.crs, &state.encoded_db, query, &state.cache)
        };
        #[cfg(not(feature = "cached-respond"))]
        let result = respond_seeded_inspiring(&state.crs, &state.encoded_db, query);
        result.map_err(|e| ServerError::Scheme(format!("flat-state respond failed: {e}")))
    }
}

/// Build one flat-balance engine state from a flat record buffer (`entry_size`
/// bytes per record).
///
/// Uses a seeded [`ChaCha20Rng`] (never `thread_rng`) so the CRS is reproducible.
/// `setup_with_rng` derives the correct flat shard config
/// (`shard_size_bytes = ring_dim * entry_size`), so the 1 GiB `for_flat_db` default
/// trap is never hit and one shard holds exactly `ring_dim` entries.
pub fn build_flat_state(
    params: &InspireParams,
    database: &[u8],
    entry_size: usize,
    seed: u64,
) -> Result<(FlatServerState, RlweSecretKey), EthStateError> {
    let mut sampler = GaussianSampler::with_seed(params.sigma, seed);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (crs, encoded_db, rlwe_sk) =
        setup_with_rng(params, database, entry_size, &mut sampler, &mut rng)
            .map_err(|e| EthStateError::Setup(e.to_string()))?;
    #[cfg(feature = "cached-respond")]
    let cache = Arc::new(
        ServerInspiringCache::new(&crs, &encoded_db)
            .map_err(|e| EthStateError::Setup(format!("inspiring cache build failed: {e}")))?,
    );
    Ok((
        FlatServerState {
            crs,
            encoded_db,
            #[cfg(feature = "cached-respond")]
            cache,
        },
        rlwe_sk,
    ))
}

/// Build a [`ClientSession`] bound to one engine's CRS, seeded for reproducibility.
pub fn build_session(
    crs: &ServerCrs,
    rlwe_sk: RlweSecretKey,
    sigma: f64,
    seed: u64,
) -> Result<ClientSession, EthStateError> {
    let mut sampler = GaussianSampler::with_seed(sigma, seed);
    ClientSession::new(crs.clone(), rlwe_sk, &mut sampler)
        .map_err(|e| EthStateError::Setup(e.to_string()))
}

/// Which engine's value a fan-out read selected: `Sidecar` when it held a fresher record,
/// else `Main`. Both legs are always extracted regardless (timing-leak safety).
///
/// ```
/// use eth_state::AnsweringEngine;
/// assert_ne!(AnsweringEngine::Main, AnsweringEngine::Sidecar);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnsweringEngine {
    /// The main (Live) engine's value was used.
    Main,
    /// The sidecar's fresher value was used.
    Sidecar,
}

/// Presence predicate over a decoded record: the sidecar holds an account iff the structural
/// [`PRESENT_TAG`] at byte 0 is set. Structural, not content-derived, so a freshly-changed-to-zero
/// balance (tag set, balance bytes zero) is present, while an untouched all-zero slot is absent.
/// One constant-position byte read, no secret-dependent short-circuit over the balance content;
/// the check is client-local, after both legs have emitted.
fn record_present(bytes: &[u8]) -> bool {
    bytes.first() == Some(&PRESENT_TAG)
}

/// Client-side handle for one engine in a main+sidecar pair.
pub struct EngineHandle<'a> {
    /// The registered instance answering queries.
    pub instance: &'a PirInstance<FlatBalanceScheme>,
    /// The client session bound to this engine's CRS.
    pub session: &'a ClientSession,
    /// This engine's public CRS, for response extraction.
    pub crs: &'a ServerCrs,
    /// Scheme params for query construction.
    pub params: &'a InspireParams,
    /// Shard config for query construction.
    pub shard_config: &'a ShardConfig,
}

/// One read leg: build a seeded query, query the instance, extract the response.
/// The extract always runs; it is never gated behind a cross-leg selection.
async fn read_leg(h: &EngineHandle<'_>, leaf: u64) -> Result<Bytes, EthStateError> {
    let (state, query) = build_seeded_query_rust(h.session, h.params, h.shard_config, leaf)
        .map_err(EthStateError::Query)?;
    let (_epoch, response) = h
        .instance
        .query(&query)
        .map_err(|e| EthStateError::Respond(e.to_string()))?;
    let bytes = extract_response_rust(h.crs, &state, &response, ENTRY_SIZE)
        .map_err(EthStateError::Decode)?;
    // The counter travels with the extract it certifies (not read_leg entry): a lazy regression
    // that skips the losing leg's extract reads 1, not 2. Test-only, off the production/WASM path.
    #[cfg(test)]
    EXTRACT_LEG_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(unpad_record(&bytes))
}

/// Per-leg extract counter for the C3 both-legs-extracted gate. Test-only so the production read
/// path carries no per-query cross-leg observable.
#[cfg(test)]
pub(crate) static EXTRACT_LEG_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Privacy-critical fan-out: fire a query at BOTH the main and the sidecar engine
/// for the SAME leaf, await BOTH, extract BOTH (the extract is never gated behind
/// the selection), then select the answer on decrypted CONTENT via a presence
/// predicate. Both legs always run to completion, so the server cannot learn which
/// engine held the record from timing or request shape. The two legs use distinct
/// sessions/CRSes and are never crossed.
pub async fn read_balance_consume_both(
    main: &EngineHandle<'_>,
    sidecar: &EngineHandle<'_>,
    leaf: u64,
) -> Result<(Bytes, AnsweringEngine), EthStateError> {
    let (main_res, side_res) = futures::join!(read_leg(main, leaf), read_leg(sidecar, leaf));
    // Both legs (and both extracts) have already run; select only after both resolve.
    let main_bytes = main_res?;
    let side_bytes = side_res?;
    if record_present(&side_bytes) {
        Ok((side_bytes, AnsweringEngine::Sidecar))
    } else {
        Ok((main_bytes, AnsweringEngine::Main))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use crate::harness::Demo;
    use crate::ingest::normalize_balance_be;
    use crate::{record_present, EXTRACT_LEG_COUNT, ENTRY_SIZE, PRESENT_TAG};
    use serial_test::serial;
    use std::sync::atomic::Ordering;

    /// The structural tag distinguishes a present-zero balance from an absent slot.
    #[test]
    fn record_present_tags_zero_vs_absent() {
        let zero = normalize_balance_be(&0u128.to_be_bytes()).expect("fits");
        assert_eq!(zero[0], PRESENT_TAG);
        assert!(record_present(&zero), "a present (changed-to-zero) record is present");
        assert!(!record_present(&[0u8; ENTRY_SIZE]), "an all-zero slot is absent");
        let nonzero = normalize_balance_be(&5u128.to_be_bytes()).expect("fits");
        assert!(record_present(&nonzero), "a non-zero balance is present");
    }

    /// A single fan-out read extracts BOTH legs (count == 2) regardless of which the content
    /// predicate selects. A lazy-extract-only-the-selected-leg regression would read 1 and fail.
    #[test]
    #[serial]
    fn both_legs_extracted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut demo = Demo::new(3000, 1_000_000, dir.path(), 0x0000_C3C3).expect("demo");
        let changed = demo.accounts[42];
        demo.apply_block(1, &[(changed, 777_777)]).expect("apply");

        EXTRACT_LEG_COUNT.store(0, Ordering::Relaxed);
        demo.read_verify(&changed).expect("read changed");
        assert_eq!(
            EXTRACT_LEG_COUNT.load(Ordering::Relaxed),
            2,
            "both legs extracted on a sidecar-wins read"
        );

        let untouched = demo.accounts[100];
        EXTRACT_LEG_COUNT.store(0, Ordering::Relaxed);
        demo.read_verify(&untouched).expect("read untouched");
        assert_eq!(
            EXTRACT_LEG_COUNT.load(Ordering::Relaxed),
            2,
            "both legs extracted on a main-fallback read"
        );
    }
}
