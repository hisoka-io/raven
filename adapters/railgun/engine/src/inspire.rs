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
        // Resolve first: an evicted handle must surface as a typed 400, not a scheme error.
        let store = state
            .session_store
            .resolve(query.session_handle, Instant::now())?;
        respond_seeded_inspiring_cached_with_session(
            state.crs.as_ref(),
            &state.encoded_db,
            query,
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
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) = inspire_setup(params, database, entry_size, &mut sampler)
        .map_err(|e| AdapterError::Scheme(format!("inspire setup: {e}")))?;
    let cache = ServerInspiringCache::new(&crs, &encoded_db)
        .map_err(|e| AdapterError::Scheme(format!("inspire cache build: {e}")))?;
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
        session_store: Arc::new(BoundedSessionStore::new()),
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
        session_store: Arc::new(BoundedSessionStore::new()),
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
            let draw = raven_inspire::math::gaussian::os_seed("batch_pad_index")
                .map_err(|e| AdapterError::Scheme(format!("pad index entropy: {e}")))?;
            let draw64 = u64::from_le_bytes([
                draw[0], draw[1], draw[2], draw[3], draw[4], draw[5], draw[6], draw[7],
            ]);
            let len = u64::try_from(global_indices.len())
                .map_err(|_| AdapterError::Scheme("batch length exceeds u64".to_owned()))?;
            let pick = usize::try_from(draw64 % len)
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

/// V6 envelope; bundling the store lets a commit archive the WAL without
/// losing logical state on restart.
#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedInspireStateV6 {
    state: PersistedInspireState,
    store: LogicalLeafStore,
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
        store: store.clone(),
    };
    let mut out = Vec::with_capacity(SNAPSHOT_V6_MAGIC.len() + 1024);
    out.extend_from_slice(&SNAPSHOT_V6_MAGIC);
    let body = bincode::serialize(&bundle)
        .map_err(|e| AdapterError::Serialization(format!("v6 snapshot serialize: {e}")))?;
    out.extend_from_slice(&body);
    Ok(out)
}

/// Reconstruct an [`InspireServerState`] from bincode bytes. Rebuilds cache; session store starts empty.
pub fn restore_inspire_state(bytes: &[u8]) -> Result<InspireServerState> {
    let bundle: PersistedInspireState = bincode::deserialize(bytes)
        .map_err(|e| AdapterError::Serialization(format!("snapshot deserialize: {e}")))?;
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

/// Reconstruct `(InspireServerState, LogicalLeafStore)`, dispatching on
/// [`SNAPSHOT_V6_MAGIC`]. V5 yields an empty store that WAL replay refills.
pub fn restore_inspire_state_v6(bytes: &[u8]) -> Result<(InspireServerState, LogicalLeafStore)> {
    if let Some(body) = bytes.strip_prefix(SNAPSHOT_V6_MAGIC.as_slice()) {
        let bundle: PersistedInspireStateV6 = bincode::deserialize(body)
            .map_err(|e| AdapterError::Serialization(format!("v6 snapshot deserialize: {e}")))?;
        let state = bundle_to_state(bundle.state)?;
        Ok((state, bundle.store))
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

/// Materialize a shard buffer: row-major `entries_per_shard x entry_size`,
/// each row `commitment_hash` (32 B) then zero fill.
#[must_use]
pub fn materialize_shard_bytes(
    store: &LogicalLeafStore,
    shard_id: u32,
    entries_per_shard: u32,
    entry_size: usize,
    tree_number: u32,
) -> Vec<u8> {
    let eps = entries_per_shard as usize;
    let total_bytes = eps.saturating_mul(entry_size);
    let mut buf = vec![0u8; total_bytes];
    let shard_start_global = u64::from(shard_id) * u64::from(entries_per_shard);
    let shard_end_global = shard_start_global + u64::from(entries_per_shard);

    // Row index is the leaf index alone, and the tree is a FILTER rather than part of the
    // index. The invariant lives in the encoder's `tree_number` pin, NOT in the router:
    // the multi-instance path scopes by route table but `indexer_to_consumer_bridge` on
    // the single-instance path forwards every tree, so a store can hold more than one.
    // Folding the tree into the index instead would shift an already-tree-local leaf out
    // of its own cell; ignoring it entirely would let a foreign tree overwrite this row.
    for ((tree, leaf), commitment) in store.leaves_iter() {
        if *tree != tree_number {
            continue;
        }
        let global = u64::from(*leaf);
        if global < shard_start_global || global >= shard_end_global {
            continue;
        }
        let in_shard_idx = usize::try_from(global - shard_start_global).unwrap_or(usize::MAX);
        let row_start = in_shard_idx.saturating_mul(entry_size);
        let copy_len = commitment.len().min(entry_size);
        if let (Some(dst), Some(src)) = (
            buf.get_mut(row_start..row_start.saturating_add(copy_len)),
            commitment.get(..copy_len),
        ) {
            dst.copy_from_slice(src);
        }
    }
    buf
}

/// BN254 scalar field modulus, big-endian. IMT leaves are Poseidon field
/// elements, so bytes at or above this never hash.
const BN254_FR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

#[derive(Clone, Copy)]
enum ImtSlot {
    CommitmentTree(u32),
    PpoiList,
}

impl ImtSlot {
    const fn index_field(self) -> &'static str {
        match self {
            Self::CommitmentTree(_) => "leaf_index",
            Self::PpoiList => "list_index",
        }
    }

    fn non_canonical_leaf(self, index: u32, leaf: &[u8; 32]) -> AdapterError {
        let field = self.index_field();
        AdapterError::InvalidQuery(format!(
            "non-canonical Fr leaf at {field} {index}: {leaf:02x?} is at or above \
             the BN254 scalar modulus"
        ))
    }

    fn non_contiguous(self, expected: usize, got: u32) -> AdapterError {
        AdapterError::InvalidQuery(match self {
            Self::CommitmentTree(tree_number) => format!(
                "non-contiguous AppendLeaf: tree {tree_number} expected leaf_index \
                 {expected}, got {got}"
            ),
            Self::PpoiList => format!(
                "non-contiguous PpoiListLeafAdded: list expected list_index \
                 {expected}, got {got}"
            ),
        })
    }
}

/// Everything the IMT would refuse, refused before the WAL write. Capacity is
/// judged on the index alone so the refusal does not depend on store state.
fn checked_imt_append(
    slot: ImtSlot,
    index: u32,
    expected: usize,
    leaf: &[u8; 32],
) -> Result<usize> {
    let field = slot.index_field();
    let index_usize = usize::try_from(index)
        .map_err(|_| AdapterError::InvalidQuery(format!("{field} {index} out of usize range")))?;
    if index_usize >= super::imt::TREE_MAX_ITEMS {
        return Err(AdapterError::InvalidQuery(format!(
            "{field} {index} is at or past IMT capacity {}",
            super::imt::TREE_MAX_ITEMS
        )));
    }
    if index_usize != expected {
        return Err(slot.non_contiguous(expected, index));
    }
    if leaf >= &BN254_FR_MODULUS_BE {
        return Err(slot.non_canonical_leaf(index, leaf));
    }
    Ok(index_usize)
}

/// Refuse a payload carrying an IMT leaf that is not a canonical BN254 Fr
/// element. WAL replay runs this before [`apply_wal_entry`]: the value can never
/// hash, so skipping the entry would leave the tree permanently short a leaf and
/// fail the contiguity screen for every later entry on that tree.
///
/// # Errors
/// [`AdapterError::InvalidQuery`] if the payload's leaf is at or above the BN254
/// scalar modulus.
///
/// ```
/// # use raven_railgun_engine::inspire::ensure_canonical_leaf;
/// # use raven_railgun_persistence::WalEntryPayload;
/// let heartbeat = WalEntryPayload::Heartbeat { wallclock_unix_ms: 0 };
/// assert!(ensure_canonical_leaf(&heartbeat).is_ok());
/// ```
pub fn ensure_canonical_leaf(payload: &raven_railgun_persistence::WalEntryPayload) -> Result<()> {
    use raven_railgun_persistence::WalEntryPayload as P;
    let (slot, index, leaf) = match payload {
        P::AppendLeaf {
            tree_number,
            leaf_index,
            commitment,
        } => (
            ImtSlot::CommitmentTree(*tree_number),
            *leaf_index,
            commitment,
        ),
        P::PpoiListLeafAdded {
            list_index,
            blinded_commitment,
            ..
        } => (ImtSlot::PpoiList, *list_index, blinded_commitment),
        P::PpoiStatus { .. } | P::Reorg { .. } | P::Heartbeat { .. } => return Ok(()),
    };
    if leaf >= &BN254_FR_MODULUS_BE {
        return Err(slot.non_canonical_leaf(index, leaf));
    }
    Ok(())
}

/// Sidecar logical-state store; accumulates chain rows and marks shards dirty
/// so commit re-encodes only those. Rebuilt from WAL replay on bootstrap.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogicalLeafStore {
    leaves: std::collections::BTreeMap<(u32, u32), [u8; 32]>,
    ppoi_status: std::collections::BTreeMap<([u8; 32], [u8; 32]), u8>,
    dirty_shards: std::collections::BTreeSet<u32>,
    last_block_height: u64,
    leaf_block_height: std::collections::BTreeMap<(u32, u32), u64>,
    ppoi_block_height: std::collections::BTreeMap<([u8; 32], [u8; 32]), u64>,
    imts: std::collections::HashMap<u32, super::imt::Imt>,
    ppoi_imts: std::collections::HashMap<[u8; 32], super::imt::Imt>,
    ppoi_bc_index: std::collections::BTreeMap<([u8; 32], [u8; 32]), u32>,
    ppoi_index_bc: std::collections::BTreeMap<([u8; 32], u32), [u8; 32]>,
    ppoi_list_leaf_block_height: std::collections::BTreeMap<([u8; 32], u32), u64>,
}

impl LogicalLeafStore {
    /// Build an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one WAL payload. Logical mutation only; does not touch `encoded_db`.
    #[allow(clippy::too_many_lines)]
    pub fn apply(
        &mut self,
        payload: &raven_railgun_persistence::WalEntryPayload,
        block_height: u64,
        encoder: &dyn super::pir_table::PirTableEncoder,
    ) -> Result<()> {
        use raven_railgun_persistence::WalEntryPayload as P;
        match payload {
            P::AppendLeaf {
                tree_number,
                leaf_index,
                commitment,
            } => {
                let expected_idx = self
                    .imts
                    .get(tree_number)
                    .map_or(0, super::imt::Imt::leaf_count);
                let leaf_idx_usize = checked_imt_append(
                    ImtSlot::CommitmentTree(*tree_number),
                    *leaf_index,
                    expected_idx,
                    commitment,
                )?;

                let imt = match self.imts.entry(*tree_number) {
                    std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
                    std::collections::hash_map::Entry::Vacant(v) => {
                        v.insert(super::imt::Imt::new()?)
                    }
                };
                imt.insert_leaves(leaf_idx_usize, &[*commitment])?;
                let key = (*tree_number, *leaf_index);
                self.leaves.insert(key, *commitment);
                self.leaf_block_height.insert(key, block_height);
                self.dirty_shards
                    .extend(encoder.affected_shards_for_leaf(*tree_number, *leaf_index));
            }
            P::PpoiStatus {
                list_key,
                blinded_commitment,
                status,
            } => {
                let key = (*list_key, *blinded_commitment);
                self.ppoi_status.insert(key, *status);
                self.ppoi_block_height.insert(key, block_height);
                self.dirty_shards
                    .extend(encoder.affected_shards_for_ppoi_status(list_key, blinded_commitment));
                if let Some(list_index) = self.ppoi_bc_index.get(&key).copied() {
                    self.dirty_shards
                        .extend(encoder.affected_shards_for_ppoi_leaf(list_key, list_index));
                }
            }
            P::PpoiListLeafAdded {
                list_key,
                list_index,
                blinded_commitment,
                status,
            } => {
                let expected_idx = self
                    .ppoi_imts
                    .get(list_key)
                    .map_or(0, super::imt::Imt::leaf_count);
                let leaf_idx_usize = checked_imt_append(
                    ImtSlot::PpoiList,
                    *list_index,
                    expected_idx,
                    blinded_commitment,
                )?;
                let imt = match self.ppoi_imts.entry(*list_key) {
                    std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
                    std::collections::hash_map::Entry::Vacant(v) => {
                        v.insert(super::imt::Imt::new()?)
                    }
                };
                imt.insert_leaves(leaf_idx_usize, &[*blinded_commitment])?;
                let bc_key = (*list_key, *blinded_commitment);
                let idx_key = (*list_key, *list_index);
                self.ppoi_bc_index.insert(bc_key, *list_index);
                self.ppoi_index_bc.insert(idx_key, *blinded_commitment);
                self.ppoi_status.insert(bc_key, *status);
                self.ppoi_block_height.insert(bc_key, block_height);
                self.ppoi_list_leaf_block_height
                    .insert(idx_key, block_height);
                self.dirty_shards
                    .extend(encoder.affected_shards_for_ppoi_leaf(list_key, *list_index));
            }
            P::Reorg { height } => {
                let stale_leaves: Vec<(u32, u32)> = self
                    .leaf_block_height
                    .iter()
                    .filter(|(_, &h)| h > *height)
                    .map(|(k, _)| *k)
                    .collect();
                let mut affected_trees: std::collections::BTreeSet<u32> =
                    std::collections::BTreeSet::new();
                for key in stale_leaves {
                    let (tree_number, leaf_index) = key;
                    self.leaves.remove(&key);
                    self.leaf_block_height.remove(&key);
                    self.dirty_shards
                        .extend(encoder.affected_shards_for_leaf(tree_number, leaf_index));
                    affected_trees.insert(tree_number);
                }
                // Surviving count = max remaining leaf_index + 1, scoped to one tree.
                for tree in &affected_trees {
                    let new_count: usize = match self
                        .leaves
                        .range((*tree, 0u32)..(tree.saturating_add(1), 0u32))
                        .next_back()
                    {
                        Some(((_, last_idx), _)) => {
                            usize::try_from(last_idx.saturating_add(1)).unwrap_or(usize::MAX)
                        }
                        None => 0,
                    };
                    if let Some(imt) = self.imts.get_mut(tree) {
                        imt.truncate_to(new_count);
                    }
                }
                let stale_ppoi: Vec<([u8; 32], [u8; 32])> = self
                    .ppoi_block_height
                    .iter()
                    .filter(|(_, &h)| h > *height)
                    .map(|(k, _)| *k)
                    .collect();
                for key in stale_ppoi {
                    self.ppoi_status.remove(&key);
                    self.ppoi_block_height.remove(&key);
                }

                let stale_list_leaves: Vec<([u8; 32], u32)> = self
                    .ppoi_list_leaf_block_height
                    .iter()
                    .filter(|(_, &h)| h > *height)
                    .map(|(k, _)| *k)
                    .collect();
                let mut affected_lists: std::collections::BTreeSet<[u8; 32]> =
                    std::collections::BTreeSet::new();
                for key in stale_list_leaves {
                    let (list_key, list_index) = key;
                    self.ppoi_list_leaf_block_height.remove(&key);
                    if let Some(bc) = self.ppoi_index_bc.remove(&key) {
                        self.ppoi_bc_index.remove(&(list_key, bc));
                    }
                    self.dirty_shards
                        .extend(encoder.affected_shards_for_ppoi_leaf(&list_key, list_index));
                    affected_lists.insert(list_key);
                }
                for list_key in &affected_lists {
                    let new_count: usize = match self
                        .ppoi_index_bc
                        .range((*list_key, 0u32)..)
                        .take_while(|((lk, _), _)| lk == list_key)
                        .last()
                    {
                        Some(((_, last_idx), _)) => {
                            usize::try_from(last_idx.saturating_add(1)).unwrap_or(usize::MAX)
                        }
                        None => 0,
                    };
                    if let Some(imt) = self.ppoi_imts.get_mut(list_key) {
                        imt.truncate_to(new_count);
                    }
                }
            }
            P::Heartbeat { .. } => {}
        }
        self.last_block_height = self.last_block_height.max(block_height);
        Ok(())
    }

    /// Number of leaves currently tracked.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Iterator over all leaves in deterministic `BTreeMap` order.
    pub fn leaves_iter(&self) -> impl Iterator<Item = (&(u32, u32), &[u8; 32])> {
        self.leaves.iter()
    }

    /// Number of PPOI rows currently tracked.
    #[must_use]
    pub fn ppoi_count(&self) -> usize {
        self.ppoi_status.len()
    }

    /// Set of shard ids with pending re-encode work.
    #[must_use]
    pub fn dirty_shards(&self) -> &std::collections::BTreeSet<u32> {
        &self.dirty_shards
    }

    /// Highest block_height seen by `apply`.
    #[must_use]
    pub fn last_block_height(&self) -> u64 {
        self.last_block_height
    }

    /// Look up a leaf by (tree, leaf_index).
    #[must_use]
    pub fn leaf(&self, tree_number: u32, leaf_index: u32) -> Option<&[u8; 32]> {
        self.leaves.get(&(tree_number, leaf_index))
    }

    /// Look up a PPOI status row.
    #[must_use]
    pub fn ppoi_status(&self, list_key: &[u8; 32], blinded_commitment: &[u8; 32]) -> Option<u8> {
        self.ppoi_status
            .get(&(*list_key, *blinded_commitment))
            .copied()
    }

    /// Per-list IMT for `list_key`, or `None` if no leaves applied yet.
    #[must_use]
    pub fn ppoi_imt(&self, list_key: &[u8; 32]) -> Option<&super::imt::Imt> {
        self.ppoi_imts.get(list_key)
    }

    /// Current root of the per-list IMT, or `None` if no leaves yet.
    #[must_use]
    pub fn ppoi_imt_root(&self, list_key: &[u8; 32]) -> Option<[u8; 32]> {
        self.ppoi_imts.get(list_key).map(super::imt::Imt::root)
    }

    /// Number of distinct PPOI lists with at least one applied leaf.
    #[must_use]
    pub fn ppoi_list_count(&self) -> usize {
        self.ppoi_imts.len()
    }

    /// Per-list `(blinded_commitment -> list_index)` lookup.
    #[must_use]
    pub fn ppoi_index_of(&self, list_key: &[u8; 32], blinded_commitment: &[u8; 32]) -> Option<u32> {
        self.ppoi_bc_index
            .get(&(*list_key, *blinded_commitment))
            .copied()
    }

    /// Per-list `(list_index -> blinded_commitment)` lookup.
    #[must_use]
    pub fn ppoi_bc_at(&self, list_key: &[u8; 32], list_index: u32) -> Option<[u8; 32]> {
        self.ppoi_index_bc.get(&(*list_key, list_index)).copied()
    }

    /// Per-list `(list_index -> status_byte)` derived view.
    #[must_use]
    pub fn ppoi_status_at(&self, list_key: &[u8; 32], list_index: u32) -> Option<u8> {
        let bc = self.ppoi_bc_at(list_key, list_index)?;
        self.ppoi_status(list_key, &bc)
    }

    /// Iterator over per-list leaves in ascending `list_index` order.
    pub fn ppoi_list_leaves_iter(
        &self,
        list_key: &[u8; 32],
    ) -> impl Iterator<Item = (u32, &[u8; 32])> {
        let lk = *list_key;
        self.ppoi_index_bc
            .range((lk, 0u32)..)
            .take_while(move |((k, _), _)| *k == lk)
            .map(|((_, idx), bc)| (*idx, bc))
    }

    /// Merkle auth path for `(list_key, list_index)`.
    ///
    /// # Errors
    /// [`AdapterError::InvalidQuery`] if no IMT exists or the index is out of range.
    pub fn ppoi_merkle_proof(
        &self,
        list_key: &[u8; 32],
        list_index: u32,
    ) -> Result<raven_railgun_core::MerkleProof> {
        let imt = self.ppoi_imts.get(list_key).ok_or_else(|| {
            AdapterError::InvalidQuery(format!(
                "no per-list IMT for list_key {list_key:?}; no leaves applied yet"
            ))
        })?;
        let idx = usize::try_from(list_index).map_err(|_| {
            AdapterError::InvalidQuery(format!("list_index {list_index} out of usize range"))
        })?;
        imt.merkle_proof(idx)
    }

    /// Drain the dirty-shards set after re-encoding.
    pub fn clear_dirty_shards(&mut self) {
        self.dirty_shards.clear();
    }

    /// Discard a shard id from the dirty set so the commit driver stops
    /// retrying a structurally-unencodable shard; transient errors leave it.
    pub fn drop_dirty_shard(&mut self, shard_id: u32) -> bool {
        self.dirty_shards.remove(&shard_id)
    }

    /// Test-only mutable access to the dirty-shards set for seeding out-of-range ids.
    #[cfg(test)]
    pub fn dirty_shards_mut_for_test(&mut self) -> &mut std::collections::BTreeSet<u32> {
        &mut self.dirty_shards
    }

    /// Merkle auth path for `(tree_number, leaf_index)`.
    ///
    /// # Errors
    /// [`AdapterError::InvalidQuery`] if no IMT exists or the index is out of range.
    pub fn merkle_proof(
        &self,
        tree_number: u32,
        leaf_index: u32,
    ) -> Result<raven_railgun_core::MerkleProof> {
        let imt = self.imts.get(&tree_number).ok_or_else(|| {
            AdapterError::InvalidQuery(format!(
                "no IMT for tree {tree_number}; no leaves applied yet"
            ))
        })?;
        let idx = usize::try_from(leaf_index).map_err(|_| {
            AdapterError::InvalidQuery(format!("leaf_index {leaf_index} out of usize range"))
        })?;
        imt.merkle_proof(idx)
    }

    /// Current root of the per-tree IMT, or `None` if no leaves applied yet.
    #[must_use]
    pub fn imt_root(&self, tree_number: u32) -> Option<[u8; 32]> {
        self.imts.get(&tree_number).map(super::imt::Imt::root)
    }

    /// Number of trees with at least one applied leaf.
    #[must_use]
    pub fn imt_tree_count(&self) -> usize {
        self.imts.len()
    }

    /// Current leaf count for `tree_number`'s IMT, or 0 if no leaves applied yet.
    #[must_use]
    pub fn imt_leaf_count_for(&self, tree_number: u32) -> usize {
        self.imts
            .get(&tree_number)
            .map_or(0, super::imt::Imt::leaf_count)
    }

    /// Per-tree IMT, or `None` if no leaves applied yet.
    #[must_use]
    pub fn imt(&self, tree_number: u32) -> Option<&super::imt::Imt> {
        self.imts.get(&tree_number)
    }
}

/// Apply a WAL payload to a [`LogicalLeafStore`]. Does not touch `encoded_db`.
pub fn apply_wal_entry(
    store: &mut LogicalLeafStore,
    payload: &raven_railgun_persistence::WalEntryPayload,
    block_height: u64,
    encoder: &dyn super::pir_table::PirTableEncoder,
) -> Result<()> {
    store.apply(payload, block_height, encoder)
}

/// Non-mutating pre-check run before the WAL write. Screens the two IMT-backed
/// variants on index contiguity, tree capacity and leaf Fr-canonicity; the
/// other variants are unconditionally accepted. Runs the same screen
/// [`LogicalLeafStore::apply`] does, so a payload that passes here and is then
/// applied against the same store cannot be refused for one of those reasons.
///
/// # Errors
/// [`AdapterError::InvalidQuery`] on a non-contiguous index, an index at or
/// past IMT capacity, or a leaf at or above the BN254 scalar modulus.
pub fn validate_apply(
    store: &LogicalLeafStore,
    payload: &raven_railgun_persistence::WalEntryPayload,
) -> Result<()> {
    use raven_railgun_persistence::WalEntryPayload as P;
    match payload {
        P::AppendLeaf {
            tree_number,
            leaf_index,
            commitment,
        } => {
            checked_imt_append(
                ImtSlot::CommitmentTree(*tree_number),
                *leaf_index,
                store.imt_leaf_count_for(*tree_number),
                commitment,
            )?;
        }
        P::PpoiListLeafAdded {
            list_key,
            list_index,
            blinded_commitment,
            ..
        } => {
            let expected = store
                .ppoi_imt(list_key)
                .map_or(0, super::imt::Imt::leaf_count);
            checked_imt_append(ImtSlot::PpoiList, *list_index, expected, blinded_commitment)?;
        }
        P::PpoiStatus { .. } | P::Reorg { .. } | P::Heartbeat { .. } => {}
    }
    Ok(())
}

#[cfg(test)]
mod snapshot_v6_tests {
    use super::{
        restore_inspire_state, restore_inspire_state_v6, setup_state, snapshot_inspire_state,
        snapshot_inspire_state_v6, InspireVariant, LogicalLeafStore, SNAPSHOT_V6_MAGIC,
    };
    use raven_inspire::params::InspireParams;

    fn toy_state_and_db() -> (super::InspireServerState, Vec<u8>) {
        let params = InspireParams::secure_128_d2048();
        let entries = 256usize;
        let entry_size = 32usize;
        let db: Vec<u8> = (0..entries)
            .flat_map(|i| (0..entry_size).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
            .collect();
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
        let db: Vec<u8> = (0..entries)
            .flat_map(|i| (0..entry_size).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
            .collect();
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
        let db: Vec<u8> = (0..entries)
            .flat_map(|i| (0..entry_size).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
            .collect();
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
        let db: Vec<u8> = (0..entries)
            .flat_map(|i| (0..entry_size).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
            .collect();
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
        let db: Vec<u8> = (0..entries)
            .flat_map(|i| (0..entry_size).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
            .collect();
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
