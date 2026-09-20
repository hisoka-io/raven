//! Production adapter implementing [`PirScheme`] for raven-inspire.

use super::{PirScheme, Result};
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, InspireVariant, ShardConfig};
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::{
    extract_two_packing, respond_seeded_inspiring_cached_with_session, setup as inspire_setup,
    ClientSession, ClientState, EncodedDatabase, SeededClientQuery, ServerCrs,
    ServerInspiringCache, ServerResponse,
};
use raven_railgun_core::{batch_ladder, AdapterError};
use std::sync::Arc;
use std::time::Instant;

use super::session_pool::BoundedSessionStore;

/// Server state for one InsPIRe instance. `Arc` fields carry across re-encode
/// swaps so re-preprocess skips the O(d^3) cache rebuild.
pub struct InspireServerState {
    /// Public CRS.
    pub crs: Arc<ServerCrs>,
    /// Encoded shard polynomials.
    pub encoded_db: Arc<EncodedDatabase>,
    /// Pre-warmed packing keys, rebuilt only on cell-shape change.
    pub cache: Arc<ServerInspiringCache>,
    /// Per-instance session store; survives re-encode swaps.
    pub session_store: Arc<BoundedSessionStore>,
    /// InsPIRe variant.
    pub variant: InspireVariant,
    /// Entry size in bytes.
    pub entry_size: usize,
}

impl std::fmt::Debug for InspireServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InspireServerState")
            .field("variant", &self.variant)
            .field("entry_size", &self.entry_size)
            .field("ring_dim", &self.crs.ring_dim())
            .field("modulus", &self.crs.modulus())
            .field("session_count", &self.session_store.len())
            .finish_non_exhaustive()
    }
}

impl InspireServerState {
    /// Shard config needed by clients to build queries.
    pub fn shard_config(&self) -> &ShardConfig {
        &self.encoded_db.config
    }

    /// Borrow the encoded database as a concrete `&EncodedDatabase`.
    #[must_use]
    pub fn encoded_db(&self) -> &EncodedDatabase {
        &self.encoded_db
    }
}

/// Marker type implementing [`PirScheme`] for the production stack.
#[derive(Debug, Default)]
pub struct RavenInspireScheme;

impl PirScheme for RavenInspireScheme {
    type ServerState = InspireServerState;
    type Query = SeededClientQuery;
    type Response = ServerResponse;

    fn respond(state: &Self::ServerState, query: &Self::Query) -> Result<Self::Response> {
        // Resolve before expansion so stale handles never reach scheme evaluation.
        let (store, inner) = state
            .session_store
            .resolve(query.session_handle, Instant::now())?;
        let mut resolved = query.clone();
        resolved.session_handle = inner;
        respond_seeded_inspiring_cached_with_session(
            state.crs.as_ref(),
            &state.encoded_db,
            &resolved,
            state.cache.as_ref(),
            Some(store.as_ref()),
        )
        .map_err(|e| AdapterError::Scheme(format!("inspire respond: {e}")))
    }
    fn state_shape(state: &Self::ServerState) -> raven_server::StateShape {
        let cfg = &state.encoded_db.config;
        raven_server::StateShape {
            entry_size_bytes: cfg.entry_size_bytes,
            rows_per_shard: cfg.entries_per_shard(),
        }
    }
}

/// Build a fresh server state. Returns the secret key alongside state (not server-side material).
pub fn setup_state(
    params: &InspireParams,
    database: &[u8],
    entry_size: usize,
    variant: InspireVariant,
) -> Result<(InspireServerState, RlweSecretKey)> {
    setup_state_with_inspiring_seed(params, database, entry_size, variant, None)
}

/// Build a fresh state while optionally reusing the public packing seed.
pub fn setup_state_with_inspiring_seed(
    params: &InspireParams,
    database: &[u8],
    entry_size: usize,
    variant: InspireVariant,
    inspiring_w_seed: Option<[u8; 32]>,
) -> Result<(InspireServerState, RlweSecretKey)> {
    let mut sampler = GaussianSampler::new(params.sigma);
    let (mut crs, encoded_db, sk) = inspire_setup(params, database, entry_size, &mut sampler)
        .map_err(|e| AdapterError::Scheme(format!("inspire setup: {e}")))?;
    let cache = if let Some(seed) = inspiring_w_seed {
        crs.inspiring_w_seed = seed;
        let cache = ServerInspiringCache::new(&crs, &encoded_db)
            .map_err(|e| AdapterError::Scheme(format!("inspire setup cache: {e}")))?;
        crs.inspiring_pack_params = None;
        crs.inspiring_packing_key = None;
        cache
    } else {
        ServerInspiringCache::from_setup(&mut crs, &encoded_db)
            .map_err(|e| AdapterError::Scheme(format!("inspire setup cache: {e}")))?
    };
    Ok((
        InspireServerState {
            crs: Arc::new(crs),
            encoded_db: Arc::new(encoded_db),
            cache: Arc::new(cache),
            session_store: Arc::new(BoundedSessionStore::new()),
            variant,
            entry_size,
        },
        sk,
    ))
}

/// Cache-affecting fingerprint: the cache is a pure function of
/// `(params, num_columns, inspiring_w_seed)`. `num_columns == 0` never matches,
/// forcing a rebuild.
#[derive(Clone, Debug, PartialEq)]
pub struct CacheFingerprint {
    params: InspireParams,
    num_columns: usize,
    inspiring_w_seed: [u8; 32],
}

impl InspireServerState {
    /// Cache-affecting fingerprint of this state.
    #[must_use]
    pub fn cache_fingerprint(&self) -> CacheFingerprint {
        let num_columns = self
            .encoded_db
            .shards
            .first()
            .map_or(0, |s| s.polynomials.len());
        CacheFingerprint {
            params: self.crs.params.clone(),
            num_columns,
            inspiring_w_seed: self.crs.inspiring_w_seed,
        }
    }
}

/// Atomically swap in a new state, carrying the donor cache on fingerprint
/// match and installing a fresh empty session store.
///
/// # Errors
/// [`AdapterError::Scheme`] if the cache rebuild fires and fails.
pub fn swap_state(
    instance: &super::PirInstance<RavenInspireScheme>,
    crs: ServerCrs,
    encoded_db: EncodedDatabase,
    variant: InspireVariant,
    entry_size: usize,
    new_epoch: super::Epoch,
) -> Result<()> {
    let crs = Arc::new(crs);
    let new_num_columns = encoded_db.shards.first().map_or(0, |s| s.polynomials.len());
    let new_fingerprint = CacheFingerprint {
        params: crs.params.clone(),
        num_columns: new_num_columns,
        inspiring_w_seed: crs.inspiring_w_seed,
    };
    let donor = instance.current_state();
    let cache: Arc<ServerInspiringCache> =
        if new_num_columns != 0 && donor.cache_fingerprint() == new_fingerprint {
            Arc::clone(&donor.cache)
        } else {
            let built = ServerInspiringCache::new(crs.as_ref(), &encoded_db)
                .map_err(|e| AdapterError::Scheme(format!("inspire cache build: {e}")))?;
            Arc::new(built)
        };
    let new_state = InspireServerState {
        crs,
        encoded_db: Arc::new(encoded_db),
        cache,
        session_store: Arc::new(donor.session_store.empty_successor()),
        variant,
        entry_size,
    };
    instance.swap_state(new_state, new_epoch)?;
    Ok(())
}

/// Operator-scheduled session flush: same-shape swap with an empty session
/// store, on top of the occupancy and TTL bounds [`BoundedSessionStore`]
/// enforces. In-flight queries keep running on the donor store.
///
/// # Errors
/// [`ServerError::StateShapeMismatch`] if the donor geometry ever diverges.
pub fn heartbeat_session_eviction(instance: &super::PirInstance<RavenInspireScheme>) -> Result<()> {
    // State and epoch must come from ONE load. Reading the epoch separately lets a
    // commit land in between: the donor is then pre-re-encode while the epoch is
    // post-commit, so the proposed epoch clears `swap_state`'s monotonicity guard and
    // republishes the shard the commit just replaced.
    let snapshot = instance.current_snapshot();
    let donor = &snapshot.state;
    let new_state = InspireServerState {
        crs: Arc::clone(&donor.crs),
        encoded_db: Arc::clone(&donor.encoded_db),
        cache: Arc::clone(&donor.cache),
        session_store: Arc::new(donor.session_store.empty_successor()),
        variant: donor.variant,
        entry_size: donor.entry_size,
    };
    instance.swap_state(new_state, snapshot.epoch.next())?;
    Ok(())
}

/// Build a [`ClientSession`] from a CRS + RLWE secret key.
pub fn build_client_session(
    crs: ServerCrs,
    sk: RlweSecretKey,
    params: &InspireParams,
) -> Result<ClientSession> {
    let mut sampler = GaussianSampler::new(params.sigma);
    ClientSession::new(crs, sk, &mut sampler)
        .map_err(|e| AdapterError::Scheme(format!("client session: {e}")))
}

/// Register a [`ClientSession`] on the server's session store via server-side derivation.
///
/// # Errors
/// Returns [`AdapterError::Scheme`] if the store rejects the derived keys.
pub fn register_client_session(
    client_session: &mut ClientSession,
    state: &InspireServerState,
) -> Result<()> {
    state
        .session_store
        .register_client_session_at(client_session, Instant::now())?;
    Ok(())
}

/// Build a [`SeededClientQuery`] for the given index, in whatever packing mode
/// the session derived from the CRS.
pub fn build_seeded_query(
    client_session: &ClientSession,
    shard_config: &ShardConfig,
    global_index: u64,
    params: &InspireParams,
) -> Result<(ClientState, SeededClientQuery)> {
    let mut sampler = GaussianSampler::new(params.sigma);
    let (state, query) = client_session
        .query_seeded(global_index, shard_config, &mut sampler)
        .map_err(|e| AdapterError::Scheme(format!("query_seeded: {e}")))?;
    Ok((state, query))
}

/// Largest multiple of `bound` representable in `u64`. Draws at or above it are rejected,
/// which is what makes the remainder uniform.
const fn rejection_limit(bound: u64) -> u64 {
    (u64::MAX / bound) * bound
}

/// Uniform draw below `bound`, rejection-sampled to match the SDK's `randomBelow`.
///
/// The two implementations of one privacy mechanism should not disagree on their draw: a
/// reader comparing them has to decide which is right. The bias a bare remainder would leave
/// is about `bound / 2^64`, unobservable at any batch length this ladder admits, so this is
/// parity rather than a live leak. The attempt bound exists because an unbounded retry in a
/// request path is a worse failure than a refusal.
fn uniform_below(bound: u64) -> Result<u64> {
    if bound == 0 {
        return Err(AdapterError::Scheme(
            "pad draw bound is zero; an empty batch has nothing to draw from".to_owned(),
        ));
    }
    let limit = rejection_limit(bound);
    for _ in 0..64 {
        let seed = raven_inspire::math::gaussian::os_seed("batch_pad_index")
            .map_err(|e| AdapterError::Scheme(format!("pad index entropy: {e}")))?;
        let draw = u64::from_le_bytes([
            seed[0], seed[1], seed[2], seed[3], seed[4], seed[5], seed[6], seed[7],
        ]);
        if draw < limit {
            return Ok(draw % bound);
        }
    }
    Err(AdapterError::Scheme(
        "pad index rejection sampling did not converge in 64 attempts; entropy source is \
         degenerate and a cycling pad would publish the real query count"
            .to_owned(),
    ))
}

/// Build a batch padded up to the next [`batch_ladder`] step. Slots stay in
/// `global_indices` order, so `states[i]` decodes `responses[i]`.
///
/// Padding is client-side because the server is the adversary the ladder hides
/// the count from: a pad the server generates is a pad the server knows about.
/// Each pad re-queries an in-batch index with fresh randomness and costs a full
/// database pass, so it is indistinguishable from a real slot.
///
/// # Errors
/// [`AdapterError::InvalidQuery`] when `global_indices` is empty or exceeds
/// [`batch_ladder::max_batch_size`]; [`AdapterError::Scheme`] on query build.
pub fn build_padded_batch(
    client_session: &ClientSession,
    shard_config: &ShardConfig,
    params: &InspireParams,
    global_indices: &[u64],
) -> Result<(Vec<ClientState>, Vec<SeededClientQuery>)> {
    let padded = batch_ladder::padded_len(global_indices.len()).ok_or_else(|| {
        AdapterError::InvalidQuery(format!(
            "batch of {} exceeds the fixed-size ladder maximum {}; split into \
             several batches and pad each",
            global_indices.len(),
            batch_ladder::max_batch_size()
        ))
    })?;
    if global_indices.is_empty() {
        return Err(AdapterError::InvalidQuery(
            "batch must carry at least one real query; an empty batch has nothing to pad"
                .to_owned(),
        ));
    }

    let mut states = Vec::with_capacity(padded);
    let mut queries = Vec::with_capacity(padded);
    for slot in 0..padded {
        // Pads draw uniformly from the real set: same cleartext shard distribution as
        // cycling, without the period-`global_indices.len()` repeat that published the
        // real count. Residual: reals hold slots 0..len in order, so with distinct
        // reals the first repeated shard still bounds the count. Closing that needs a
        // whole-batch shuffle plus a permutation map, which changes this contract.
        let index = if let Some(real) = global_indices.get(slot) {
            *real
        } else {
            let len = u64::try_from(global_indices.len())
                .map_err(|_| AdapterError::Scheme("batch length exceeds u64".to_owned()))?;
            let pick = usize::try_from(uniform_below(len)?)
                .map_err(|_| AdapterError::Scheme("pad index exceeds usize".to_owned()))?;
            global_indices
                .get(pick)
                .copied()
                .ok_or_else(|| AdapterError::Scheme("pad index out of range".to_owned()))?
        };
        let (state, query) = build_seeded_query(client_session, shard_config, index, params)?;
        states.push(state);
        queries.push(query);
    }
    Ok((states, queries))
}

/// Decode a server response into the original plaintext bytes.
pub fn extract_response(
    crs: &ServerCrs,
    client_state: &ClientState,
    response: &ServerResponse,
    entry_size: usize,
) -> Result<Vec<u8>> {
    extract_two_packing(crs, client_state, response, entry_size)
        .map_err(|e| AdapterError::Scheme(format!("inspire extract: {e}")))
}

/// Pad a raw record to [`MIN_SAFE_RECORD_BYTES`]. Returns `None` if already over the floor.
#[must_use]
pub fn pad_record(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() > MIN_SAFE_RECORD_BYTES {
        return None;
    }
    let mut padded = vec![0u8; MIN_SAFE_RECORD_BYTES];
    let dst = padded.get_mut(..payload.len())?;
    dst.copy_from_slice(payload);
    Some(padded)
}

/// Recover the raw payload from a padded record. Inverse of [`pad_record`].
#[must_use]
pub fn unpad_record(padded: &[u8], payload_len: usize) -> Option<&[u8]> {
    if padded.len() != MIN_SAFE_RECORD_BYTES || payload_len > MIN_SAFE_RECORD_BYTES {
        return None;
    }
    padded.get(..payload_len)
}

/// Minimum InsPIRe-safe record size in bytes. 33 B causes decryption garbage.
pub const MIN_SAFE_RECORD_BYTES: usize = 32;

/// Snapshot bundle; cache and session store are derived or empty on restore.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PersistedInspireState {
    crs: ServerCrs,
    encoded_db: EncodedDatabase,
    variant: InspireVariant,
    entry_size: usize,
}

impl std::fmt::Debug for PersistedInspireState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistedInspireState")
            .field("variant", &self.variant)
            .field("entry_size", &self.entry_size)
            .finish_non_exhaustive()
    }
}

/// Serialize an [`InspireServerState`] to legacy V5 bincode bytes. Prefer
/// [`snapshot_inspire_state_v6`], which also embeds the [`LogicalLeafStore`].
pub fn snapshot_inspire_state(state: &InspireServerState) -> Result<Vec<u8>> {
    let bundle = PersistedInspireState {
        crs: (*state.crs).clone(),
        encoded_db: (*state.encoded_db).clone(),
        variant: state.variant,
        entry_size: state.entry_size,
    };
    bincode::serialize(&bundle)
        .map_err(|e| AdapterError::Serialization(format!("snapshot serialize: {e}")))
}

/// V6 magic header; V5 raw bincode never starts with these bytes, so restore
/// dispatches on the prefix.
pub const SNAPSHOT_V6_MAGIC: [u8; 4] = *b"RV6\0";

/// V7 magic header; V7 retains upstream PPOI event metadata in the logical store.
pub const SNAPSHOT_V7_MAGIC: [u8; 4] = *b"RV7\0";

/// V6 envelope; bundling the store lets a commit archive the WAL without
/// losing logical state on restart.
///
/// `store` is the FROZEN [`LogicalLeafStoreV6`], never the live one. Every V6 snapshot on
/// disk was written by a build predating `ppoi_event_metadata`, and bincode is positional.
#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedInspireStateV6 {
    state: PersistedInspireState,
    store: LogicalLeafStoreV6,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedInspireStateV7 {
    state: PersistedInspireState,
    store: LogicalLeafStore,
}

/// Serialize `(state, store)` with retained PPOI metadata.
pub fn snapshot_inspire_state_v7(
    state: &InspireServerState,
    store: &LogicalLeafStore,
) -> Result<Vec<u8>> {
    let bundle = PersistedInspireStateV7 {
        state: PersistedInspireState {
            crs: (*state.crs).clone(),
            encoded_db: (*state.encoded_db).clone(),
            variant: state.variant,
            entry_size: state.entry_size,
        },
        store: store.clone(),
    };
    let mut out = Vec::with_capacity(SNAPSHOT_V7_MAGIC.len() + 1024);
    out.extend_from_slice(&SNAPSHOT_V7_MAGIC);
    let body = bincode::serialize(&bundle)
        .map_err(|e| AdapterError::Serialization(format!("v7 snapshot serialize: {e}")))?;
    out.extend_from_slice(&body);
    Ok(out)
}

/// Serialize `(state, store)` as `SNAPSHOT_V6_MAGIC || bincode(envelope)`.
pub fn snapshot_inspire_state_v6(
    state: &InspireServerState,
    store: &LogicalLeafStore,
) -> Result<Vec<u8>> {
    let bundle = PersistedInspireStateV6 {
        state: PersistedInspireState {
            crs: (*state.crs).clone(),
            encoded_db: (*state.encoded_db).clone(),
            variant: state.variant,
            entry_size: state.entry_size,
        },
        store: LogicalLeafStoreV6::try_from_current(store)?,
    };
    let mut out = Vec::with_capacity(SNAPSHOT_V6_MAGIC.len() + 1024);
    out.extend_from_slice(&SNAPSHOT_V6_MAGIC);
    let body = bincode::serialize(&bundle)
        .map_err(|e| AdapterError::Serialization(format!("v6 snapshot serialize: {e}")))?;
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode a snapshot body, REFUSING surplus bytes.
///
/// `bincode::deserialize` is `…with_fixint_encoding().allow_trailing_bytes()`, which bincode's own
/// docs flag as the opposite of the `DefaultOptions` struct's default. Surplus after a snapshot
/// means the writer and the reader disagree about the shape; discarding it silently is how a
/// V7-shaped store read through the V6 reader returns `Ok` with a list key assembled from
/// signature bytes. `inspire-cache`, `pir/respond.rs` and `crates/client` already reject trailing
/// bytes -- the snapshot path was the outlier.
fn decode_snapshot_body<'a, T: serde::de::Deserialize<'a>>(
    body: &'a [u8],
) -> std::result::Result<T, bincode::Error> {
    raven_railgun_persistence::decode_no_trailing(body)
}

/// Shared tail for every snapshot-decode refusal.
///
/// `PersistedInspireState` is the first field of every envelope and reaches into the InsPIRe
/// submodule's types, so a field moved anywhere in that reach surfaces as an arbitrary error on
/// whichever arm happened to run. The arm is not a diagnosis and the message must not read as
/// one. The command below is exact: this is a DETACHED workspace, so `-p` alone resolves to
/// nothing from the repo root.
const SNAPSHOT_LAYOUT_HELP: &str = "Either these bytes are damaged, or they were written by a \
     build whose serialized layout differs from this one: bincode is positional, so a field \
     added or moved anywhere inside the snapshot -- including inside the embedded InsPIRe \
     types -- shifts every byte after it, and no in-place migration exists. Operator: probe a \
     data_dir before deploying, with RAVEN_PROBE_DATA_DIR=<dir> cargo test --manifest-path \
     adapters/railgun/Cargo.toml -p raven-railgun-engine --test data_dir_reopen_probe -- \
     --ignored; then either ship a build whose layout matches, or re-bootstrap this instance.";

/// Reconstruct an [`InspireServerState`] from bincode bytes. Rebuilds cache; session store starts empty.
pub fn restore_inspire_state(bytes: &[u8]) -> Result<InspireServerState> {
    let bundle: PersistedInspireState = decode_snapshot_body(bytes).map_err(|e| {
        AdapterError::Serialization(format!(
            "v5 snapshot deserialize: {e}. {SNAPSHOT_LAYOUT_HELP}"
        ))
    })?;
    bundle_to_state(bundle)
}

fn bundle_to_state(bundle: PersistedInspireState) -> Result<InspireServerState> {
    let cache = ServerInspiringCache::new(&bundle.crs, &bundle.encoded_db)
        .map_err(|e| AdapterError::Scheme(format!("restore cache build: {e}")))?;
    Ok(InspireServerState {
        crs: Arc::new(bundle.crs),
        encoded_db: Arc::new(bundle.encoded_db),
        cache: Arc::new(cache),
        session_store: Arc::new(BoundedSessionStore::new()),
        variant: bundle.variant,
        entry_size: bundle.entry_size,
    })
}

fn cache_identity(
    crs: &ServerCrs,
    encoded_db: &EncodedDatabase,
) -> super::offline_packing_keys_cache::CellShape {
    let num_columns = encoded_db
        .shards
        .first()
        .map_or(0, |shard| shard.polynomials.len());
    super::offline_packing_keys_cache::CellShape::for_inspiring(
        &crs.params,
        num_columns,
        crs.inspiring_w_seed,
    )
}

fn cache_for_recovery(
    data_dir: &std::path::Path,
    crs: &ServerCrs,
    encoded_db: &EncodedDatabase,
) -> Result<(ServerInspiringCache, bool, bool)> {
    use super::offline_packing_keys_cache::{CacheLoad, OfflinePackingKeysCache};

    let identity = cache_identity(crs, encoded_db);
    let disk = OfflinePackingKeysCache::new(data_dir);
    if let CacheLoad::Hit(parts) = disk.load(&identity) {
        let cache = ServerInspiringCache::from_parts(parts.pack_params, parts.offline_keys);
        match cache.validate_for(crs, encoded_db) {
            Ok(()) => return Ok((cache, true, true)),
            Err(error) => {
                tracing::warn!(%error, "offline packing cache failed validation; rebuilding");
            }
        }
    }

    let cache = ServerInspiringCache::new(crs, encoded_db)
        .map_err(|e| AdapterError::Scheme(format!("restore cache build: {e}")))?;
    let persisted = match disk.store(&identity, cache.pack_params(), cache.offline_keys()) {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(error = %error, "offline packing cache store failed; recovery remains correct");
            false
        }
    };
    Ok((cache, false, persisted))
}

pub(crate) fn persist_inspiring_cache(
    data_dir: &std::path::Path,
    state: &InspireServerState,
) -> Result<()> {
    let identity = cache_identity(&state.crs, &state.encoded_db);
    super::offline_packing_keys_cache::OfflinePackingKeysCache::new(data_dir)
        .store(
            &identity,
            state.cache.pack_params(),
            state.cache.offline_keys(),
        )
        .map_err(|e| AdapterError::Internal(format!("offline packing cache store: {e}")))
}

/// A V6 body that will not parse as the frozen V6 layout is either damaged or was written by
/// a build with a different one; these bytes cannot tell you which, and the message says so.
/// What it can say is that bincode carries no field names, so nothing migrates in place.
fn decode_v6_body(body: &[u8]) -> Result<PersistedInspireStateV6> {
    decode_snapshot_body(body).map_err(|e| {
        AdapterError::Serialization(format!(
            "v6 snapshot deserialize: {e}. These bytes do not match the frozen V6 layout. \
             {SNAPSHOT_LAYOUT_HELP}"
        ))
    })
}

/// V7 carries the LIVE store, so unlike V6 there is no frozen shape to name -- but the
/// operator's options are identical and so is the message.
fn decode_v7_body(body: &[u8]) -> Result<PersistedInspireStateV7> {
    decode_snapshot_body(body).map_err(|e| {
        AdapterError::Serialization(format!(
            "v7 snapshot deserialize: {e}. {SNAPSHOT_LAYOUT_HELP}"
        ))
    })
}

/// Reconstruct `(InspireServerState, LogicalLeafStore)`, dispatching on
/// [`SNAPSHOT_V6_MAGIC`]. V5 yields an empty store that WAL replay refills.
pub fn restore_inspire_state_v6(bytes: &[u8]) -> Result<(InspireServerState, LogicalLeafStore)> {
    if let Some(body) = bytes.strip_prefix(SNAPSHOT_V7_MAGIC.as_slice()) {
        let bundle = decode_v7_body(body)?;
        let state = bundle_to_state(bundle.state)?;
        Ok((state, bundle.store))
    } else if let Some(body) = bytes.strip_prefix(SNAPSHOT_V6_MAGIC.as_slice()) {
        let bundle = decode_v6_body(body)?;
        let state = bundle_to_state(bundle.state)?;
        Ok((state, bundle.store.into_current()))
    } else {
        tracing::warn!(
            target = "raven::engine::snapshot",
            "legacy V5 snapshot (no V6 magic prefix); LogicalLeafStore starts empty and will \
             be repopulated from WAL replay if WAL bytes are still present"
        );
        let state = restore_inspire_state(bytes)?;
        Ok((state, LogicalLeafStore::default()))
    }
}

pub(crate) fn restore_inspire_state_v6_cached(
    bytes: &[u8],
    data_dir: &std::path::Path,
) -> Result<(InspireServerState, LogicalLeafStore, bool, bool)> {
    if let Some(body) = bytes.strip_prefix(SNAPSHOT_V7_MAGIC.as_slice()) {
        let bundle = decode_v7_body(body)?;
        let (cache, hit, persisted) =
            cache_for_recovery(data_dir, &bundle.state.crs, &bundle.state.encoded_db)?;
        let state = InspireServerState {
            crs: Arc::new(bundle.state.crs),
            encoded_db: Arc::new(bundle.state.encoded_db),
            cache: Arc::new(cache),
            session_store: Arc::new(BoundedSessionStore::new()),
            variant: bundle.state.variant,
            entry_size: bundle.state.entry_size,
        };
        Ok((state, bundle.store, hit, persisted))
    } else if let Some(body) = bytes.strip_prefix(SNAPSHOT_V6_MAGIC.as_slice()) {
        let bundle = decode_v6_body(body)?;
        let (cache, hit, persisted) =
            cache_for_recovery(data_dir, &bundle.state.crs, &bundle.state.encoded_db)?;
        let state = InspireServerState {
            crs: Arc::new(bundle.state.crs),
            encoded_db: Arc::new(bundle.state.encoded_db),
            cache: Arc::new(cache),
            session_store: Arc::new(BoundedSessionStore::new()),
            variant: bundle.state.variant,
            entry_size: bundle.state.entry_size,
        };
        Ok((state, bundle.store.into_current(), hit, persisted))
    } else {
        tracing::warn!(
            target = "raven::engine::snapshot",
            "legacy V5 snapshot (no V6 magic prefix); LogicalLeafStore starts empty and will \
             be repopulated from WAL replay if WAL bytes are still present"
        );
        // The boot path (`persistence.rs`) comes through HERE, not through the uncached
        // twin -- so this is the arm a production reopen failure surfaces on, and it was the
        // one still emitting a bare bincode error the operator could not act on.
        let bundle: PersistedInspireState = decode_snapshot_body(bytes).map_err(|e| {
            AdapterError::Serialization(format!(
                "v5 snapshot deserialize: {e}. {SNAPSHOT_LAYOUT_HELP}"
            ))
        })?;
        let (cache, hit, persisted) =
            cache_for_recovery(data_dir, &bundle.crs, &bundle.encoded_db)?;
        let state = InspireServerState {
            crs: Arc::new(bundle.crs),
            encoded_db: Arc::new(bundle.encoded_db),
            cache: Arc::new(cache),
            session_store: Arc::new(BoundedSessionStore::new()),
            variant: bundle.variant,
            entry_size: bundle.entry_size,
        };
        Ok((state, LogicalLeafStore::default(), hit, persisted))
    }
}

/// Re-encode a single shard from a raw byte buffer in place.
///
/// # Errors
/// [`AdapterError::Scheme`] if the shape is rejected or `shard_bytes` re-shards
/// into more than one shard; [`AdapterError::ShardOutOfRange`] if `shard_id` is
/// absent, which the commit driver treats as terminal.
pub fn re_encode_shard(
    encoded_db: &mut EncodedDatabase,
    params: &InspireParams,
    shard_id: u32,
    shard_bytes: &[u8],
    entry_size: usize,
) -> Result<()> {
    let total_shards = encoded_db.shards.len();
    let existing = encoded_db
        .shards
        .iter_mut()
        .find(|s| s.id == shard_id)
        .ok_or(AdapterError::ShardOutOfRange {
            shard_id,
            db_shard_count: total_shards,
        })?;

    let entries = shard_bytes.len() / entry_size.max(1);
    let single_shard_config = ShardConfig {
        shard_size_bytes: encoded_db.config.shard_size_bytes,
        entry_size_bytes: entry_size,
        total_entries: entries as u64,
    };
    let mut rebuilt =
        raven_inspire::encode_database(shard_bytes, entry_size, params, &single_shard_config)
            .map_err(|e| AdapterError::Scheme(format!("re_encode_shard: {e}")))?;

    // >1 rebuilt shard means the buffer was sized off the cell's total row count,
    // and installing one of them would give the slot the wrong row window.
    if rebuilt.len() != 1 {
        let per_shard = single_shard_config.entries_per_shard();
        return Err(AdapterError::Scheme(format!(
            "re_encode_shard: shard {shard_id} was handed {entries} rows \
             ({buf_len} bytes at entry_size {entry_size}) and re-sharded into \
             {rebuilt_count} shards; one shard holds exactly {per_shard} rows \
             (shard_size_bytes {shard_size_bytes} / entry_size {entry_size}), so the caller \
             must materialize {per_shard} rows per shard - not the cell's total row count",
            buf_len = shard_bytes.len(),
            rebuilt_count = rebuilt.len(),
            shard_size_bytes = single_shard_config.shard_size_bytes,
        )));
    }

    // `encode_database` re-numbers from id=0; keep the in-place slot's id.
    let new_shard = rebuilt
        .pop()
        .ok_or_else(|| AdapterError::Scheme("re_encode_shard: encoder produced no shard".into()))?;
    existing.polynomials = new_shard.polynomials;
    Ok(())
}

mod logical_store;

pub(crate) use logical_store::{appends_to_a_tree, LogicalLeafStoreV6};
pub use logical_store::{
    apply_wal_entry, ensure_canonical_leaf, materialize_shard_bytes, validate_apply,
    LogicalLeafStore,
};

#[cfg(test)]
mod frozen_v6_shape_tests {
    //! Every V6 snapshot on disk was written before `ppoi_event_metadata` existed.
    //! bincode is positional, so reading those bytes with the LIVE struct reinterprets
    //! `ppoi_list_leaf_block_height` as the new field. These tests pin the V6 read path to
    //! frozen BYTES, because a round trip through today's codec cannot see a shape change --
    //! it writes and reads the same wrong layout and passes.
    //!
    //! LIMIT, stated so a green run is not over-read: the store holds `HashMap`s, so minting
    //! is NOT byte-reproducible. Decoding is order-independent, so the fixtures are sound to
    //! read -- but a fixture diff is not evidence of a shape change, and a test that passes
    //! after a re-mint proves only that the fixture matches the struct that minted it. The
    //! control is that both generators are `#[ignore]`d and re-minting is a deliberate act.

    use super::{
        apply_wal_entry, restore_inspire_state_v6, setup_state, InspireVariant, LogicalLeafStore,
        LogicalLeafStoreV6, PersistedInspireState, SNAPSHOT_V6_MAGIC, SNAPSHOT_V7_MAGIC,
    };
    use crate::pir_table::PerLeafCommitmentEncoder;
    use raven_inspire::params::InspireParams;
    use raven_railgun_persistence::{PpoiEventType, WalEntryPayload};

    /// The bytes a pre-`ppoi_event_metadata` build WOULD have written for the store
    /// `sample_store()` builds -- minted here, not recovered from one; that build could not have
    /// constructed this store at all, since three of the payload fields postdate it.
    /// Store-only: `PersistedInspireStateV6` is positionally `state ++ store`.
    const FROZEN_V6_STORE: &[u8] = include_bytes!("../tests/fixtures/logical_store_v6.bin");

    /// The CURRENT layout, frozen at the shape that ships. V7 carries the live struct, which
    /// is the position V6 was in when it broke: the next field inserted mid-struct silently
    /// reinterprets the bytes on every deployed data_dir. This fixture fires here rather than
    /// on the box.
    ///
    /// What it catches: a field added, removed or moved, and a width change -- the decode
    /// underruns or leaves surplus, and surplus is now refused. What it does NOT catch: a
    /// same-width type substitution (`u64` for `i64`), which decodes cleanly and passes every
    /// assertion below.
    const FROZEN_V7_STORE: &[u8] = include_bytes!("../tests/fixtures/logical_store_v7.bin");

    const LIST_KEY: [u8; 32] = [0xab; 32];

    /// One commitment leaf and two PPOI list leaves. The PPOI leaves are what matters: they
    /// are the only writers of `ppoi_list_leaf_block_height`, the map the inserted field
    /// steals the bytes of. Height 0 mirrors production, where the mirror sends 0.
    fn sample_store() -> LogicalLeafStore {
        let enc = PerLeafCommitmentEncoder::new(32, 65_536, 0).expect("test encoder");
        let mut store = LogicalLeafStore::new();
        apply_wal_entry(
            &mut store,
            &WalEntryPayload::AppendLeaf {
                tree_number: 0,
                leaf_index: 0,
                commitment: [7u8; 32],
            },
            0,
            &enc,
        )
        .expect("append leaf");
        for index in 0..2u32 {
            let mut bc = [0u8; 32];
            bc[31] = u8::try_from(index).unwrap_or(0).saturating_add(1);
            apply_wal_entry(
                &mut store,
                &WalEntryPayload::PpoiListLeafAdded {
                    list_key: LIST_KEY,
                    list_index: index,
                    blinded_commitment: bc,
                    status: 0,
                    event_type: PpoiEventType::Shield,
                    signature: vec![0x5a; 64],
                    validated_merkleroot: [0x11; 32],
                },
                0,
                &enc,
            )
            .expect("append ppoi list leaf");
        }
        store
    }

    /// One InsPIRe setup shared by every test here; it dominates this module's runtime.
    fn toy_state() -> &'static super::InspireServerState {
        static STATE: std::sync::OnceLock<super::InspireServerState> = std::sync::OnceLock::new();
        STATE.get_or_init(|| {
            let params = InspireParams::secure_128_d2048();
            let db = raven_railgun_testkit::toy_db(256, 32);
            let (state, _sk) =
                setup_state(&params, &db, 32, InspireVariant::TwoPacking).expect("setup");
            state
        })
    }

    fn state_bytes() -> Vec<u8> {
        let state = toy_state();
        bincode::serialize(&PersistedInspireState {
            crs: (*state.crs).clone(),
            encoded_db: (*state.encoded_db).clone(),
            variant: state.variant,
            entry_size: state.entry_size,
        })
        .expect("serialize state")
    }

    /// `PersistedInspireStateV6` is `{ state, store }` and bincode writes fields in order, so
    /// this is today's state bytes followed by the frozen store bytes.
    ///
    /// **Legacy in the STORE half only.** The state half is serialized by today's code and
    /// therefore carries today's `InspireParams`. A real V6 snapshot on a box carries the older
    /// one, and that half is not frozen here -- so nothing built on this function is evidence
    /// that a production data_dir reopens. `data_dir_reopen_probe` is what answers that.
    fn legacy_v6_snapshot(magic: [u8; 4]) -> Vec<u8> {
        let mut out = magic.to_vec();
        out.extend_from_slice(&state_bytes());
        out.extend_from_slice(FROZEN_V6_STORE);
        out
    }

    #[test]
    #[ignore = "trigger: a deliberate re-mint only; this WRITES the fixture it pins, so running \
                it in a lane would erase the evidence. Run with --ignored by hand."]
    fn mint_frozen_v6_store_fixture() {
        let frozen = LogicalLeafStoreV6::from_current_dropping_metadata(&sample_store());
        let bytes = bincode::serialize(&frozen).expect("serialize frozen v6 store");
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/logical_store_v6.bin");
        std::fs::write(&path, &bytes).expect("write fixture");
    }

    #[test]
    #[ignore = "trigger: a change to LogicalLeafStore's layout, and then only in the same \
                change as a new snapshot magic. Run with --ignored by hand."]
    fn mint_frozen_v7_store_fixture() {
        let bytes = bincode::serialize(&sample_store()).expect("serialize v7 store");
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/logical_store_v7.bin");
        std::fs::write(&path, &bytes).expect("write fixture");
    }

    // The same trap, one version forward. Changing `LogicalLeafStore`'s layout without a magic
    // reddens HERE, at desk speed, instead of at boot on a data_dir nobody can re-read.
    #[test]
    fn the_live_store_still_reads_the_shipped_v7_layout() {
        let store: LogicalLeafStore =
            super::decode_snapshot_body(FROZEN_V7_STORE).unwrap_or_else(|e| {
                panic!(
                "LogicalLeafStore no longer reads the V7 bytes it ships with ({e}). bincode is \
                 positional: a field added or moved breaks every deployed data_dir. Add a new \
                 SNAPSHOT_V8_MAGIC, freeze the V7 shape the way LogicalLeafStoreV6 is frozen, \
                 and re-mint this fixture in the SAME change."
                )
            });
        assert_eq!(store.leaf(0, 0), Some(&[7u8; 32]));
        assert_eq!(store.ppoi_list_leaves_iter(&LIST_KEY).count(), 2);
        assert_eq!(store.ppoi_list_leaf_block_height_len(), 2);
        let meta = store
            .ppoi_event_metadata(&LIST_KEY, 0)
            .expect("V7 retains upstream metadata; that is what V7 is for");
        assert_eq!(meta.validated_merkleroot, [0x11; 32]);
        assert_eq!(meta.signature.len(), 64);
    }

    // THE DEFECT, pinned. Deserializing the frozen bytes with the LIVE struct is exactly what
    // the V6 arm did before this fix. If someone later "simplifies" `LogicalLeafStoreV6` back
    // to `LogicalLeafStore`, this test is what tells them the box cannot reopen.
    #[test]
    fn frozen_v6_store_bytes_do_not_decode_as_the_live_store() {
        let Err(err) = super::decode_snapshot_body::<LogicalLeafStore>(FROZEN_V6_STORE) else {
            panic!("the live struct must NOT be able to read frozen V6 bytes");
        };
        assert!(
            err.to_string().contains("end of file"),
            "expected the reader to outrun the buffer; got {err}"
        );
    }

    #[test]
    fn frozen_v6_store_bytes_decode_as_the_frozen_shape() {
        let frozen: LogicalLeafStoreV6 = super::decode_snapshot_body(FROZEN_V6_STORE)
            .expect("frozen shape must read its own bytes");
        let store = frozen.into_current();
        assert_eq!(
            store.leaf(0, 0),
            Some(&[7u8; 32]),
            "commitment leaf survived"
        );
        assert_eq!(store.ppoi_list_count(), 1, "one list key");
        assert_eq!(
            store.ppoi_list_leaves_iter(&LIST_KEY).count(),
            2,
            "both PPOI list leaves survived"
        );
        // The map the inserted field steals the bytes of. Asserted directly, because a
        // clean decode of the fields BEFORE it would not have noticed.
        assert_eq!(store.ppoi_list_leaf_block_height_len(), 2);
        let mut bc = [0u8; 32];
        bc[31] = 1;
        assert_eq!(store.ppoi_index_of(&LIST_KEY, &bc), Some(0));
        assert_eq!(
            store.ppoi_event_metadata(&LIST_KEY, 0),
            None,
            "V6 never carried retained metadata; absence is a fact about the snapshot"
        );
    }

    // Store half only -- see `legacy_v6_snapshot`. A green here does NOT mean a deployed
    // data_dir reopens; it means the frozen V6 store shape is read correctly.
    #[test]
    fn a_legacy_v6_snapshot_reopens() {
        let (state, store) =
            restore_inspire_state_v6(&legacy_v6_snapshot(SNAPSHOT_V6_MAGIC)).expect("v6 reopen");
        assert_eq!(state.entry_size, 32);
        assert_eq!(store.ppoi_list_leaves_iter(&LIST_KEY).count(), 2);
        assert_eq!(store.ppoi_list_leaf_block_height_len(), 2);
        assert_eq!(store.leaf(0, 0), Some(&[7u8; 32]));
    }

    // The V7 arm still reads the live struct -- correctly, since V7 wrote it. Feeding it a
    // legacy body exercises the same deserialization target the V6 arm had before it was
    // frozen. (The error path around it is new; the struct being decoded into is not.)
    #[test]
    fn the_same_legacy_body_under_v7_magic_is_refused() {
        let Err(err) = restore_inspire_state_v6(&legacy_v6_snapshot(SNAPSHOT_V7_MAGIC)) else {
            panic!("legacy bytes must not be readable as V7");
        };
        assert!(
            err.to_string().contains("v7 snapshot deserialize"),
            "got {err}"
        );
    }

    // A V7-shaped store under V6 magic. The frozen V6 reader stops after its eleventh field,
    // and while surplus bytes were tolerated it returned `Ok` with a list key assembled from
    // the tail of a signature -- wrong bytes, `Ok`, nothing logged, on this repo's own fixtures.
    #[test]
    fn a_v7_shaped_store_under_v6_magic_is_refused_rather_than_truncated() {
        let mut snapshot = SNAPSHOT_V6_MAGIC.to_vec();
        snapshot.extend_from_slice(&state_bytes());
        snapshot.extend_from_slice(FROZEN_V7_STORE);
        let Err(err) = restore_inspire_state_v6(&snapshot) else {
            panic!("a V7-shaped store must not decode as V6 with the surplus discarded");
        };
        assert!(
            err.to_string().contains("v6 snapshot deserialize"),
            "got {err}"
        );
    }

    #[test]
    fn an_unreadable_v6_body_names_the_migration_not_bincode_alone() {
        let mut truncated = legacy_v6_snapshot(SNAPSHOT_V6_MAGIC);
        truncated.truncate(truncated.len() - 16);
        let Err(err) = restore_inspire_state_v6(&truncated) else {
            panic!("a truncated body must refuse");
        };
        let msg = err.to_string();
        // The last needle is the one that matters: this is a detached workspace, and the
        // advice shipped without `--manifest-path` resolves to no package from the repo root.
        // Asserting the message merely SAYS "Operator" would pin the letter of the gate.
        for needle in [
            "frozen V6 layout",
            "re-bootstrap",
            "Operator",
            "--manifest-path adapters/railgun/Cargo.toml",
        ] {
            assert!(
                msg.contains(needle),
                "refusal must tell the operator what to do; {needle:?} missing from {msg:?}"
            );
        }
    }

    // V6 has no field for retained metadata, so writing one from a store that carries it would
    // drop data silently -- the defect class this whole card is about, in the other direction.
    #[test]
    fn writing_v6_from_a_store_carrying_metadata_is_refused() {
        let Err(err) = super::snapshot_inspire_state_v6(toy_state(), &sample_store()) else {
            panic!("V6 cannot represent retained metadata");
        };
        assert!(err.to_string().contains("Write V7"), "got {err}");
    }
}

#[cfg(test)]
mod snapshot_v6_tests {
    use super::{
        restore_inspire_state, restore_inspire_state_v6, setup_state, snapshot_inspire_state,
        snapshot_inspire_state_v6, snapshot_inspire_state_v7, InspireVariant, LogicalLeafStore,
        SNAPSHOT_V6_MAGIC, SNAPSHOT_V7_MAGIC,
    };
    use raven_inspire::params::InspireParams;

    fn toy_state_and_db() -> (super::InspireServerState, Vec<u8>) {
        let params = InspireParams::secure_128_d2048();
        let entries = 256usize;
        let entry_size = 32usize;
        let db = raven_railgun_testkit::toy_db(entries, entry_size);
        let (state, _sk) =
            setup_state(&params, &db, entry_size, InspireVariant::TwoPacking).expect("setup");
        (state, db)
    }

    #[test]
    fn v6_snapshot_carries_magic_prefix() {
        let (state, _) = toy_state_and_db();
        let store = LogicalLeafStore::new();
        let bytes = snapshot_inspire_state_v6(&state, &store).expect("v6 serialize");
        assert!(
            bytes.starts_with(&SNAPSHOT_V6_MAGIC),
            "V6 snapshot must start with RV6\\0 magic; got {:?}",
            bytes.get(..SNAPSHOT_V6_MAGIC.len())
        );
    }

    #[test]
    fn v7_snapshot_carries_distinct_magic_prefix() {
        let (state, _) = toy_state_and_db();
        let store = LogicalLeafStore::new();
        let bytes = snapshot_inspire_state_v7(&state, &store).expect("v7 serialize");
        assert!(bytes.starts_with(&SNAPSHOT_V7_MAGIC));
        assert!(!bytes.starts_with(&SNAPSHOT_V6_MAGIC));
        restore_inspire_state_v6(&bytes).expect("v7 restore through current reader");
    }

    #[test]
    fn explicit_inspiring_seed_is_reused_across_fresh_instances() {
        let params = InspireParams::secure_128_d2048();
        let database = raven_railgun_testkit::toy_db(256, 32);
        let (first, _) = super::setup_state_with_inspiring_seed(
            &params,
            &database,
            32,
            InspireVariant::TwoPacking,
            None,
        )
        .expect("first setup");
        let (second, _) = super::setup_state_with_inspiring_seed(
            &params,
            &database,
            32,
            InspireVariant::TwoPacking,
            Some(first.crs.inspiring_w_seed),
        )
        .expect("second setup");
        assert_eq!(first.crs.inspiring_w_seed, second.crs.inspiring_w_seed);
        assert_eq!(first.cache_fingerprint(), second.cache_fingerprint());
    }

    #[test]
    fn v6_round_trip_restores_state_and_empty_store() {
        let (state, _) = toy_state_and_db();
        let store = LogicalLeafStore::new();
        let bytes = snapshot_inspire_state_v6(&state, &store).expect("v6 serialize");
        let (restored, store_back) = restore_inspire_state_v6(&bytes).expect("v6 restore");
        assert_eq!(restored.entry_size, state.entry_size);
        assert_eq!(store_back.ppoi_count(), 0);
        assert_eq!(store_back.leaf_count(), 0);
    }

    #[test]
    fn legacy_v5_snapshot_decodes_with_empty_store_via_v6_restore() {
        let (state, _) = toy_state_and_db();
        let v5_bytes = snapshot_inspire_state(&state).expect("v5 serialize");
        assert!(
            !v5_bytes.starts_with(&SNAPSHOT_V6_MAGIC),
            "V5 raw bincode must NOT collide with V6 magic"
        );
        let (restored, store_back) = restore_inspire_state_v6(&v5_bytes).expect("v5 via v6");
        assert_eq!(restored.entry_size, state.entry_size);
        assert_eq!(store_back.ppoi_count(), 0);
        let _ = restore_inspire_state(&v5_bytes).expect("v5 directly via legacy path");
    }
}

#[cfg(test)]
mod logical_store_tests {
    use super::{apply_wal_entry, LogicalLeafStore};
    use crate::pir_table::PerLeafCommitmentEncoder;
    use raven_railgun_persistence::WalEntryPayload;

    const ENTRIES_PER_SHARD: u32 = 65_536;

    fn enc() -> PerLeafCommitmentEncoder {
        PerLeafCommitmentEncoder::new(32, ENTRIES_PER_SHARD, 0).expect("test encoder")
    }

    fn append(tree: u32, leaf: u32, _height: u64) -> WalEntryPayload {
        WalEntryPayload::AppendLeaf {
            tree_number: tree,
            leaf_index: leaf,
            commitment: [(leaf & 0xff) as u8; 32],
        }
    }

    #[test]
    fn append_inserts_leaf_and_marks_shard_dirty() {
        let mut s = LogicalLeafStore::new();
        apply_wal_entry(&mut s, &append(0, 0, 100), 100, &enc()).expect("apply");
        assert_eq!(s.leaf_count(), 1);
        assert_eq!(s.last_block_height(), 100);
        assert!(s.dirty_shards().contains(&0));
        assert_eq!(s.leaf(0, 0), Some(&[0u8; 32]));
    }

    #[test]
    fn encoder_shard_layout_is_tree_local() {
        use crate::pir_table::PirTableEncoder;
        let e = enc();
        assert!(e.affected_shards_for_leaf(0, 0).contains(&0));
        assert!(e.affected_shards_for_leaf(0, 65_535).contains(&0));

        // The row INDEX is tree-local: encoders pinned to different trees map the same
        // leaf index to the same shard. The tree is a filter, not part of the index.
        for tree in [1u32, 2, 7] {
            let pinned =
                super::super::pir_table::PerLeafCommitmentEncoder::new(32, ENTRIES_PER_SHARD, tree)
                    .expect("encoder");
            assert_eq!(
                pinned.affected_shards_for_leaf(tree, 0),
                e.affected_shards_for_leaf(0, 0),
                "tree {tree} leaf 0 must map to the same shard as tree 0 leaf 0"
            );
            // ...and a leaf from outside the pin dirties nothing, or it would overwrite
            // this tree's row: the store can hold two trees on the single-instance path.
            assert!(
                e.affected_shards_for_leaf(tree, 0).is_empty(),
                "an encoder pinned to tree 0 must ignore tree {tree}"
            );
        }
        assert!(
            e.affected_shards_for_leaf(0, 65_536).is_empty(),
            "a leaf past one tree's row space has no row"
        );
    }

    #[test]
    fn ppoi_status_round_trips() {
        let mut s = LogicalLeafStore::new();
        let lk = [1u8; 32];
        let bc = [2u8; 32];
        let payload = WalEntryPayload::PpoiStatus {
            list_key: lk,
            blinded_commitment: bc,
            status: 3,
        };
        apply_wal_entry(&mut s, &payload, 200, &enc()).expect("apply");
        assert_eq!(s.ppoi_count(), 1);
        assert_eq!(s.ppoi_status(&lk, &bc), Some(3));
    }

    #[test]
    fn reorg_truncates_leaves_and_ppoi_past_height() {
        let mut s = LogicalLeafStore::new();
        for i in 0..5u32 {
            let payload = append(0, i, 100 + u64::from(i));
            apply_wal_entry(&mut s, &payload, 100 + u64::from(i), &enc()).expect("apply");
        }
        for i in 0..3u8 {
            let mut bc = [0u8; 32];
            bc[0] = i;
            let payload = WalEntryPayload::PpoiStatus {
                list_key: [0u8; 32],
                blinded_commitment: bc,
                status: 0,
            };
            apply_wal_entry(&mut s, &payload, 200 + u64::from(i), &enc()).expect("apply");
        }
        assert_eq!(s.leaf_count(), 5);
        assert_eq!(s.ppoi_count(), 3);
        let reorg = WalEntryPayload::Reorg { height: 102 };
        apply_wal_entry(&mut s, &reorg, 102, &enc()).expect("apply reorg");
        assert_eq!(s.leaf_count(), 3, "leaves at 100, 101, 102 survive");
        assert_eq!(s.ppoi_count(), 0, "all PPOI past 102 dropped");
        assert!(s.leaf(0, 0).is_some());
        assert!(s.leaf(0, 1).is_some());
        assert!(s.leaf(0, 2).is_some());
        assert!(s.leaf(0, 3).is_none());
        assert!(s.leaf(0, 4).is_none());
        assert!(s.dirty_shards().contains(&0));
    }

    #[test]
    fn heartbeat_is_no_op_but_advances_block_height() {
        let mut s = LogicalLeafStore::new();
        let hb = WalEntryPayload::Heartbeat {
            wallclock_unix_ms: 1_000_000,
        };
        apply_wal_entry(&mut s, &hb, 500, &enc()).expect("apply");
        assert_eq!(s.leaf_count(), 0);
        assert_eq!(s.ppoi_count(), 0);
        assert_eq!(s.last_block_height(), 500);
    }

    #[test]
    fn clear_dirty_shards_drains_set() {
        let mut s = LogicalLeafStore::new();
        apply_wal_entry(&mut s, &append(0, 0, 100), 100, &enc()).expect("apply");
        // the tree-1 append enters the store but dirties nothing: a one-tree cell
        // holds no row for it
        apply_wal_entry(&mut s, &append(1, 0, 101), 101, &enc()).expect("apply");
        assert_eq!(s.dirty_shards().len(), 1);
        s.clear_dirty_shards();
        assert_eq!(s.dirty_shards().len(), 0);
        apply_wal_entry(&mut s, &append(0, 1, 102), 102, &enc()).expect("apply");
        assert_eq!(s.dirty_shards().len(), 1);
    }

    #[test]
    fn replay_idempotent_for_same_input() {
        let payloads: Vec<_> = (0..10u32)
            .map(|i| (append(0, i, 100 + u64::from(i)), 100 + u64::from(i)))
            .collect();
        let mut a = LogicalLeafStore::new();
        let mut b = LogicalLeafStore::new();
        for (p, h) in &payloads {
            apply_wal_entry(&mut a, p, *h, &enc()).expect("apply a");
            apply_wal_entry(&mut b, p, *h, &enc()).expect("apply b");
        }
        assert_eq!(a.leaf_count(), b.leaf_count());
        assert_eq!(a.last_block_height(), b.last_block_height());
        assert_eq!(a.dirty_shards(), b.dirty_shards());
        for i in 0..10u32 {
            assert_eq!(a.leaf(0, i), b.leaf(0, i));
        }
    }

    #[test]
    fn append_maintains_per_tree_imt_root_changes_on_each_leaf() {
        let mut s = LogicalLeafStore::new();
        assert!(s.imt_root(0).is_none(), "no leaves -> no IMT");

        apply_wal_entry(&mut s, &append(0, 0, 100), 100, &enc()).expect("seed 0");
        let r0 = s.imt_root(0).expect("IMT for tree 0");
        apply_wal_entry(&mut s, &append(0, 1, 101), 101, &enc()).expect("seed 1");
        let r1 = s.imt_root(0).expect("IMT for tree 0");
        apply_wal_entry(&mut s, &append(0, 2, 102), 102, &enc()).expect("seed 2");
        let r2 = s.imt_root(0).expect("IMT for tree 0");

        assert_ne!(r0, r1, "root must change after first leaf insert");
        assert_ne!(r1, r2, "root must change after second leaf insert");
        assert_eq!(s.imt_tree_count(), 1);
    }

    /// Reconstruct the root from a leaf and its auth path.
    #[allow(clippy::indexing_slicing)]
    fn reconstruct_root_from_proof(
        leaf: [u8; 32],
        leaf_index: u32,
        proof: &raven_railgun_core::MerkleProof,
    ) -> [u8; 32] {
        use raven_railgun_poseidon::merkle_node;
        let mut current = leaf;
        for level in 0..16usize {
            let bit = (leaf_index >> level) & 1;
            let sibling = proof.elements[level];
            current = if bit == 1 {
                merkle_node(sibling, current).expect("hash")
            } else {
                merkle_node(current, sibling).expect("hash")
            };
        }
        current
    }

    #[test]
    fn merkle_proof_reconstructs_to_local_root() {
        let mut s = LogicalLeafStore::new();
        for i in 0u32..6 {
            apply_wal_entry(
                &mut s,
                &append(0, i, 100 + u64::from(i)),
                100 + u64::from(i),
                &enc(),
            )
            .expect("seed");
        }
        let local_root = s.imt_root(0).expect("IMT root");

        for i in 0u32..6 {
            let proof = s.merkle_proof(0, i).expect("proof");
            assert_eq!(proof.root, local_root, "proof carries the local root");
            let leaf = *s.leaf(0, i).expect("leaf");
            let reconstructed = reconstruct_root_from_proof(leaf, i, &proof);
            assert_eq!(
                reconstructed, local_root,
                "auth path for leaf {i} must reconstruct to local root"
            );
        }
    }

    #[test]
    fn reorg_truncates_imt_in_lockstep_with_leaf_map() {
        let mut s = LogicalLeafStore::new();
        for i in 0u32..5 {
            apply_wal_entry(
                &mut s,
                &append(0, i, 100 + u64::from(i)),
                100 + u64::from(i),
                &enc(),
            )
            .expect("seed");
        }
        let pre_root = s.imt_root(0).expect("pre-reorg root");

        apply_wal_entry(&mut s, &WalEntryPayload::Reorg { height: 102 }, 102, &enc())
            .expect("reorg");

        assert_eq!(s.leaf_count(), 3, "reorg drops 2 leaves");
        let post_root = s.imt_root(0).expect("post-reorg root");
        assert_ne!(pre_root, post_root, "IMT root must change post-reorg");

        let mut fresh = LogicalLeafStore::new();
        for i in 0u32..3 {
            apply_wal_entry(
                &mut fresh,
                &append(0, i, 100 + u64::from(i)),
                100 + u64::from(i),
                &enc(),
            )
            .expect("fresh seed");
        }
        let fresh_root = fresh.imt_root(0).expect("fresh root");
        assert_eq!(
            post_root, fresh_root,
            "post-reorg root must equal fresh-insert-of-survivors root"
        );

        for i in 0u32..3 {
            let proof = s.merkle_proof(0, i).expect("proof");
            assert_eq!(proof.root, post_root);
        }
        assert!(s.merkle_proof(0, 3).is_err());
        assert!(s.merkle_proof(0, 4).is_err());
    }

    #[test]
    fn per_tree_imts_are_independent() {
        let mut s = LogicalLeafStore::new();
        apply_wal_entry(&mut s, &append(0, 0, 100), 100, &enc()).expect("t0 l0");
        let t0_after_first = s.imt_root(0).expect("tree 0 root");
        apply_wal_entry(&mut s, &append(1, 0, 101), 101, &enc()).expect("t1 l0");
        let t0_after_t1 = s.imt_root(0).expect("tree 0 unchanged");
        assert_eq!(
            t0_after_first, t0_after_t1,
            "inserting into tree 1 must NOT mutate tree 0's IMT"
        );
        assert_eq!(s.imt_tree_count(), 2);
    }

    #[test]
    fn merkle_proof_for_unknown_tree_errors() {
        let s = LogicalLeafStore::new();
        let err = s.merkle_proof(99, 0).expect_err("no IMT for tree 99");
        assert!(matches!(
            err,
            raven_railgun_core::AdapterError::InvalidQuery(_)
        ));
    }

    #[test]
    fn non_contiguous_leaf_index_surfaces_invalid_query() {
        let mut s = LogicalLeafStore::new();
        apply_wal_entry(&mut s, &append(0, 0, 100), 100, &enc()).expect("seed 0");
        let err = apply_wal_entry(&mut s, &append(0, 5, 101), 101, &enc())
            .expect_err("sparse insert must fail");
        assert!(matches!(
            err,
            raven_railgun_core::AdapterError::InvalidQuery(_)
        ));
    }

    /// Rejected non-contiguous `AppendLeaf` leaves no torn state.
    #[test]
    fn rejected_append_leaves_no_torn_state() {
        let mut s = LogicalLeafStore::new();
        apply_wal_entry(&mut s, &append(0, 0, 100), 100, &enc()).expect("seed 0");

        let pre_leaf_count = s.leaf_count();
        let pre_root = s.imt_root(0);
        let pre_dirty: std::collections::BTreeSet<u32> = s.dirty_shards().clone();
        let pre_last_block = s.last_block_height();

        let _err =
            apply_wal_entry(&mut s, &append(0, 5, 101), 101, &enc()).expect_err("sparse must fail");

        assert_eq!(s.leaf_count(), pre_leaf_count, "leaf_count unchanged");
        assert_eq!(s.imt_root(0), pre_root, "IMT root unchanged");
        assert_eq!(
            s.dirty_shards().clone(),
            pre_dirty,
            "dirty_shards unchanged"
        );
        assert_eq!(
            s.last_block_height(),
            pre_last_block,
            "last_block_height unchanged"
        );
        assert!(s.leaf(0, 5).is_none(), "rejected leaf must NOT be in map");
    }

    /// Pre-check rejects non-contiguous `AppendLeaf` without mutating.
    #[test]
    fn validate_apply_rejects_non_contiguous_without_mutating() {
        let mut s = LogicalLeafStore::new();
        apply_wal_entry(&mut s, &append(0, 0, 100), 100, &enc()).expect("seed 0");

        let sparse = append(0, 5, 101);
        let pre_root = s.imt_root(0);
        let err = super::validate_apply(&s, &sparse).expect_err("sparse must fail validate");
        assert!(matches!(
            err,
            raven_railgun_core::AdapterError::InvalidQuery(_)
        ));
        assert_eq!(s.imt_root(0), pre_root);
        assert_eq!(s.leaf_count(), 1);
    }

    /// Validate accepts a contiguous leaf for empty and non-empty trees.
    #[test]
    fn validate_apply_accepts_contiguous() {
        let s = LogicalLeafStore::new();
        super::validate_apply(&s, &append(0, 0, 100)).expect("first leaf at 0 must validate");

        let mut s2 = LogicalLeafStore::new();
        apply_wal_entry(&mut s2, &append(0, 0, 100), 100, &enc()).expect("seed");
        super::validate_apply(&s2, &append(0, 1, 101))
            .expect("next leaf at leaf_count must validate");
    }

    /// Rejected first `AppendLeaf` must not lazy-create the per-tree IMT.
    #[test]
    fn rejected_first_append_does_not_lazy_create_imt() {
        let mut s = LogicalLeafStore::new();
        let err = apply_wal_entry(&mut s, &append(99, 7, 100), 100, &enc())
            .expect_err("sparse first must fail");
        assert!(matches!(
            err,
            raven_railgun_core::AdapterError::InvalidQuery(_)
        ));
        assert!(s.imt_root(99).is_none(), "no IMT must exist for tree 99");
        assert_eq!(s.imt_tree_count(), 0, "no trees should be tracked");
    }
}

#[cfg(test)]
mod re_encode_tests {
    use super::{re_encode_shard, setup_state, InspireVariant};
    use raven_inspire::params::InspireParams;
    use std::sync::Arc;

    #[test]
    fn re_encode_matches_fresh_encode() {
        let params = InspireParams::secure_128_d2048();
        let entries = 256usize;
        let entry_size = 256usize;
        let db = raven_railgun_testkit::toy_db(entries, entry_size);
        let (mut state, _sk) =
            setup_state(&params, &db, entry_size, InspireVariant::TwoPacking).expect("setup_state");

        let original_polys: Vec<_> = state
            .encoded_db
            .shards
            .iter()
            .find(|s| s.id == 0)
            .expect("shard 0 present")
            .polynomials
            .clone();

        let entries_per_shard = usize::try_from(state.encoded_db.config.entries_per_shard())
            .expect("entries_per_shard fits usize");
        let shard_bytes_len = entries_per_shard.min(entries) * entry_size;
        let shard_bytes = db
            .get(..shard_bytes_len)
            .expect("db slice for shard 0")
            .to_vec();
        re_encode_shard(
            Arc::make_mut(&mut state.encoded_db),
            &params,
            0,
            &shard_bytes,
            entry_size,
        )
        .expect("re_encode_shard");

        let new_polys = &state
            .encoded_db
            .shards
            .iter()
            .find(|s| s.id == 0)
            .expect("shard 0 still present")
            .polynomials;

        assert_eq!(new_polys.len(), original_polys.len());
        for (i, (a, b)) in new_polys.iter().zip(original_polys.iter()).enumerate() {
            assert_eq!(
                a.coeffs(),
                b.coeffs(),
                "polynomial {i} differs after re-encode of identical bytes"
            );
        }
    }

    /// Mutated bytes must produce different polynomials, proving the rebuild is real.
    #[test]
    fn re_encode_mutates_polys_for_changed_bytes() {
        let params = InspireParams::secure_128_d2048();
        let entries = 256usize;
        let entry_size = 256usize;
        let db = raven_railgun_testkit::toy_db(entries, entry_size);
        let (mut state, _sk) =
            setup_state(&params, &db, entry_size, InspireVariant::TwoPacking).expect("setup_state");

        let original_polys: Vec<_> = state
            .encoded_db
            .shards
            .iter()
            .find(|s| s.id == 0)
            .expect("shard 0 present")
            .polynomials
            .clone();

        let entries_per_shard = usize::try_from(state.encoded_db.config.entries_per_shard())
            .expect("entries_per_shard fits usize");
        let shard_bytes_len = entries_per_shard.min(entries) * entry_size;
        let mut shard_bytes = db.get(..shard_bytes_len).expect("db slice").to_vec();
        if let Some(b) = shard_bytes.get_mut(7) {
            *b ^= 0xff;
        }
        re_encode_shard(
            Arc::make_mut(&mut state.encoded_db),
            &params,
            0,
            &shard_bytes,
            entry_size,
        )
        .expect("re_encode_shard");

        let new_polys = &state
            .encoded_db
            .shards
            .iter()
            .find(|s| s.id == 0)
            .expect("shard 0")
            .polynomials;
        let any_diff = new_polys
            .iter()
            .zip(original_polys.iter())
            .any(|(a, b)| a.coeffs() != b.coeffs());
        assert!(
            any_diff,
            "byte mutation must change at least one polynomial"
        );
    }

    /// Re-encoding shard 1 must be byte-identical to setup, ruling out shard-0 specialization.
    #[test]
    fn re_encode_shard_k1_byte_identity() {
        let params = InspireParams::secure_128_d2048();
        let entries = 4096usize; // 2 x ring_dim => 2 shards.
        let entry_size = 32usize;
        let db = raven_railgun_testkit::toy_db(entries, entry_size);
        let (mut state, _sk) =
            setup_state(&params, &db, entry_size, InspireVariant::TwoPacking).expect("setup_state");

        assert!(
            state.encoded_db.shards.len() >= 2,
            "test requires multi-shard cell; got {} shards",
            state.encoded_db.shards.len()
        );

        let original_shard1: Vec<_> = state
            .encoded_db
            .shards
            .iter()
            .find(|s| s.id == 1)
            .expect("shard 1 present")
            .polynomials
            .clone();

        let entries_per_shard =
            usize::try_from(state.encoded_db.config.entries_per_shard()).expect("eps fits usize");
        let shard_bytes_len = entries_per_shard * entry_size;
        let shard_bytes = db
            .get(shard_bytes_len..2 * shard_bytes_len)
            .expect("shard 1 byte range")
            .to_vec();
        re_encode_shard(
            Arc::make_mut(&mut state.encoded_db),
            &params,
            1,
            &shard_bytes,
            entry_size,
        )
        .expect("re_encode_shard k=1");

        let new_shard1 = &state
            .encoded_db
            .shards
            .iter()
            .find(|s| s.id == 1)
            .expect("shard 1 still present")
            .polynomials;
        assert_eq!(new_shard1.len(), original_shard1.len());
        for (i, (a, b)) in new_shard1.iter().zip(original_shard1.iter()).enumerate() {
            assert_eq!(
                a.coeffs(),
                b.coeffs(),
                "polynomial {i} of shard 1 differs after re-encode of identical bytes"
            );
        }
    }

    #[test]
    fn re_encode_unknown_shard_returns_internal_error() {
        let params = InspireParams::secure_128_d2048();
        let entries = 256usize;
        let entry_size = 256usize;
        let db = raven_railgun_testkit::toy_db(entries, entry_size);
        let (mut state, _sk) =
            setup_state(&params, &db, entry_size, InspireVariant::TwoPacking).expect("setup_state");
        let err = re_encode_shard(
            Arc::make_mut(&mut state.encoded_db),
            &params,
            999,
            &[],
            entry_size,
        )
        .expect_err("unknown shard id");
        let msg = format!("{err}");
        assert!(
            msg.contains("999"),
            "error should name the missing shard id: {msg}"
        );
    }
}

#[cfg(test)]
mod pad_draw_tests {
    use super::{rejection_limit, uniform_below};

    /// `SeededClientQuery.shard_id` travels in cleartext, so a favoured residue is a bias in
    /// what an operator sees. The bound is the observable: the bias a bare remainder leaves at
    /// these batch lengths is about `bound / 2^64`, which no statistical test on the draw could
    /// distinguish, so asserting on samples would prove nothing either way.
    #[test]
    fn the_rejection_bound_is_a_whole_number_of_buckets() {
        for bound in [1_u64, 2, 3, 5, 8, 32, 84, 128, 1000, u64::MAX / 2] {
            let limit = rejection_limit(bound);
            assert_eq!(
                limit % bound,
                0,
                "bound {bound}: {limit} is not a multiple, so the remainder is not uniform"
            );
        }
    }

    #[test]
    fn the_rejection_bound_discards_at_most_one_bucket() {
        for bound in [3_u64, 7, 32, 84, 1000, 65_537] {
            let discarded = u64::MAX - rejection_limit(bound) + 1;
            assert!(
                discarded <= bound,
                "bound {bound}: discards {discarded}, more than one bucket"
            );
        }
    }

    /// The excess a bare remainder would leave, stated as arithmetic rather than sampled.
    #[test]
    fn the_bound_removes_the_excess_a_bare_remainder_would_leave() {
        for bound in [3_u64, 7, 84, 1000] {
            let excess = ((u64::MAX % bound) + 1) % bound;
            assert_ne!(
                excess, 0,
                "bound {bound} divides 2^64; pick one that does not"
            );
            assert_eq!(rejection_limit(bound) % bound, 0);
        }
    }

    #[test]
    fn a_zero_bound_is_refused_rather_than_dividing_by_zero() {
        let err = uniform_below(0).expect_err("a zero bound must not reach the remainder");
        assert!(
            format!("{err}").contains("bound is zero"),
            "the refusal must name the cause; got: {err}"
        );
    }

    #[test]
    fn a_real_draw_lands_in_range_and_is_not_pinned_to_one_value() {
        // Not a uniformity test - it cannot be one at this bias. It checks the loop returns,
        // stays in range, and is not stuck, which is what a broken entropy path would show.
        let draws: Vec<u64> = (0..64)
            .map(|_| uniform_below(8).expect("entropy available in test"))
            .collect();
        assert!(draws.iter().all(|&d| d < 8), "draw out of range: {draws:?}");
        let distinct = draws
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        assert!(
            distinct > 1,
            "every draw returned the same value: {draws:?}"
        );
    }
}
