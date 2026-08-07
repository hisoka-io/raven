//! Flat `address -> 32-byte big-endian balance` PIR demo over the InsPIRe respond path:
//! one changed account is one row plus one shard re-encode, no trie and no root churn.
//!
//! Leaf assignment is a dense `u64` per address with `shard = flat_index / ENTRIES_PER_SHARD`,
//! the flat single-keyspace shape of EIP-7864 (draft). No live tree is built.

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
#[cfg(not(feature = "cached-respond"))]
use raven_inspire::respond_seeded_inspiring;
use raven_inspire::rlwe::RlweSecretKey;
#[cfg(feature = "cached-respond")]
use raven_inspire::{respond_seeded_inspiring_cached, ServerInspiringCache};
use raven_inspire::{
    setup_with_rng, ClientSession, EncodedDatabase, SeededClientQuery, ServerCrs, ServerResponse,
};
use raven_server::{PirInstance, PirScheme};
#[cfg(feature = "cached-respond")]
use std::sync::Arc;

use raven_client::{build_seeded_query_rust, extract_response_rust};

/// Record width; byte 0 is the presence tag. MUST stay even: the encoder reads 16-bit chunks.
pub const ENTRY_SIZE: usize = 32;

/// Byte-0 tag set on every constructed record, so a changed-to-zero balance is
/// distinguishable from an absent (all-zero) slot.
pub const PRESENT_TAG: u8 = 0x01;

/// Entries per shard, equal to the ring dimension.
pub const ENTRIES_PER_SHARD: usize = 2048;

/// Errors from the flat-state demo glue.
#[derive(Debug, thiserror::Error)]
pub enum EthStateError {
    /// Record wider than the balance field.
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

/// Fixed-width record: [`PRESENT_TAG`] at byte 0, `value` big-endian right-aligned after it.
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

/// Decoded record bytes verbatim; the byte-0 tag MUST survive for [`record_present`].
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
    /// Encoded shard corpus.
    pub encoded_db: EncodedDatabase,
    /// CRS-static server-compute cache, no per-client data. Arc-cloned through every fold,
    /// never rebuilt: `num_columns` is fixed for a fixed `entry_size`.
    #[cfg(feature = "cached-respond")]
    pub cache: Arc<ServerInspiringCache>,
}

/// Flat-balance PIR scheme over the handshake-free InsPIRe respond path: queries carry inline
/// packing keys with no `session_handle`, so the engine is client- and server-stateless.
pub struct FlatBalanceScheme;

impl PirScheme for FlatBalanceScheme {
    type ServerState = FlatServerState;
    type Query = SeededClientQuery;
    type Response = ServerResponse;

    fn respond(state: &Self::ServerState, query: &Self::Query) -> SchemeResult<Self::Response> {
        #[cfg(feature = "cached-respond")]
        let result = {
            // Cache is bound to num_columns = entry_size/2; a fold that diverged the corpus
            // shape from it would silently corrupt the response.
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
    fn state_shape(state: &Self::ServerState) -> raven_server::StateShape {
        let cfg = &state.encoded_db.config;
        raven_server::StateShape {
            entry_size_bytes: cfg.entry_size_bytes,
            rows_per_shard: cfg.entries_per_shard(),
        }
    }
}

/// Build one engine from a flat record buffer. Seeded [`ChaCha20Rng`], never `thread_rng`, so
/// the CRS is reproducible; `setup_with_rng` derives `shard_size_bytes = ring_dim * entry_size`
/// rather than the 1 GiB `for_flat_db` default.
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

/// Which engine's value a fan-out read selected. Both legs are extracted regardless.
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

/// Structural, not content-derived: a changed-to-zero balance is present, an untouched all-zero
/// slot is absent. One constant-position read, no short-circuit over the balance bytes.
fn record_present(bytes: &[u8]) -> bool {
    bytes.first() == Some(&PRESENT_TAG)
}

/// Client-side handle for one engine in a main+sidecar pair.
pub struct EngineHandle<'a> {
    /// Registered instance answering queries.
    pub instance: &'a PirInstance<FlatBalanceScheme>,
    /// Session bound to this engine's CRS.
    pub session: &'a ClientSession,
    /// This engine's public CRS.
    pub crs: &'a ServerCrs,
    /// Scheme params.
    pub params: &'a InspireParams,
    /// Shard config.
    pub shard_config: &'a ShardConfig,
}

/// Build, query, extract. The extract always runs; never gated behind a cross-leg selection.
async fn read_leg(h: &EngineHandle<'_>, leaf: u64) -> Result<Bytes, EthStateError> {
    let (state, query) = build_seeded_query_rust(h.session, h.params, h.shard_config, leaf)
        .map_err(EthStateError::Query)?;
    let (_epoch, response) = h
        .instance
        .query(&query)
        .map_err(|e| EthStateError::Respond(e.to_string()))?;
    let bytes = extract_response_rust(h.crs, &state, &response, ENTRY_SIZE)
        .map_err(EthStateError::Decode)?;
    // Counts the extract, not leg entry, so a lazy skip of the losing leg reads 1 not 2.
    #[cfg(test)]
    EXTRACT_LEG_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(unpad_record(&bytes))
}

/// Test-only, so the production read path carries no cross-leg observable.
#[cfg(test)]
pub(crate) static EXTRACT_LEG_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Fan out the same leaf at both engines, await and extract BOTH, then select on decrypted
/// content. Unconditional completion of both legs is what keeps the server from learning
/// which engine held the record. The legs use distinct sessions/CRSes and are never crossed.
pub async fn read_balance_consume_both(
    main: &EngineHandle<'_>,
    sidecar: &EngineHandle<'_>,
    leaf: u64,
) -> Result<(Bytes, AnsweringEngine), EthStateError> {
    let (main_res, side_res) = futures::join!(read_leg(main, leaf), read_leg(sidecar, leaf));
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
    use crate::{record_present, ENTRY_SIZE, EXTRACT_LEG_COUNT, PRESENT_TAG};
    use serial_test::serial;
    use std::sync::atomic::Ordering;

    #[test]
    fn record_present_tags_zero_vs_absent() {
        let zero = normalize_balance_be(&0u128.to_be_bytes()).expect("fits");
        assert_eq!(zero[0], PRESENT_TAG);
        assert!(
            record_present(&zero),
            "a present (changed-to-zero) record is present"
        );
        assert!(
            !record_present(&[0u8; ENTRY_SIZE]),
            "an all-zero slot is absent"
        );
        let nonzero = normalize_balance_be(&5u128.to_be_bytes()).expect("fits");
        assert!(record_present(&nonzero), "a non-zero balance is present");
    }

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
