//! Production adapter implementing [`PirScheme`] for raven-inspire.

use super::{PirScheme, Result};
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, InspireVariant, ShardConfig};
use raven_inspire::pir::mod_switch::{
    check_mod_switch_noise_budget, extract_inspiring_mod_switched, mod_switch_response_checked,
    MOD_SWITCH_TARGET_36BIT,
};
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::{
    respond_seeded_inspiring_cached_with_session, setup as inspire_setup, ClientSession,
    ClientState, EncodedDatabase, SeededClientQuery, ServerCrs, ServerInspiringCache,
    ServerResponse,
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

/// Every served response is mod-switched to this modulus before it leaves `respond`, so
/// the switch cannot be skipped by a route. The serializer packs at the modulus's tight
/// width: 36 bits puts a 512 B row at 10,446 wire bytes against 17,358 unswitched.
pub const WIRE_RESPONSE_MODULUS: u64 = MOD_SWITCH_TARGET_36BIT;

/// The rung is fixed and the parameters are not. Checked wherever a state is built from
/// parameters: a set the rung cannot carry would otherwise boot healthy and fail every query.
fn require_wire_rung(params: &InspireParams) -> Result<()> {
    check_mod_switch_noise_budget(params, WIRE_RESPONSE_MODULUS)
        .map_err(|e| AdapterError::Scheme(format!("served response modulus: {e}")))
}

/// A snapshot's parameters and shard geometry are data, so a restored state is held to what
/// setup accepts before anything is built from it.
fn validate_persisted_state(bundle: &PersistedInspireState) -> Result<()> {
    let params = &bundle.crs.params;
    params
        .validate()
        .map_err(|e| AdapterError::Scheme(format!("snapshot parameters: {e}")))?;
    require_wire_rung(params)?;
    bundle
        .encoded_db
        .config
        .validate_for_params(params)
        .map_err(|e| AdapterError::Scheme(format!("snapshot shard geometry: {e}")))
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
        if holds_one_shard_for_all(&state.encoded_db)
            && u64::from(resolved.shard_id) < state.encoded_db.config.num_shards()
        {
            resolved.shard_id = 0;
        }
        let response = respond_seeded_inspiring_cached_with_session(
            state.crs.as_ref(),
            &state.encoded_db,
            &resolved,
            state.cache.as_ref(),
            Some(store.as_ref()),
        )
        .map_err(|e| AdapterError::Scheme(format!("inspire respond: {e}")))?;
        mod_switch_response_checked(&state.crs.params, &response, WIRE_RESPONSE_MODULUS)
            .map_err(|e| AdapterError::Scheme(format!("inspire mod-switch: {e}")))
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
    require_wire_rung(params)?;
    let mut sampler = GaussianSampler::new(params.sigma);
    let (mut crs, encoded_db, sk) = inspire_setup(params, database, entry_size, &mut sampler)
        .map_err(|e| AdapterError::Scheme(format!("inspire setup: {e}")))?;
    let cache = if let Some(seed) = inspiring_w_seed {
        crs.inspiring_w_seed = seed;
        crs.inspiring_pack_params = None;
        crs.inspiring_packing_key = None;
        shared_packing_cache(&crs, &encoded_db)?
    } else {
        let built = ServerInspiringCache::from_setup(&mut crs, &encoded_db)
            .map_err(|e| AdapterError::Scheme(format!("inspire setup cache: {e}")))?;
        register_packing_cache(&crs, &encoded_db, built)
    };
    Ok((
        InspireServerState {
            crs: Arc::new(crs),
            encoded_db: Arc::new(encoded_db),
            cache,
            session_store: Arc::new(BoundedSessionStore::new()),
            variant,
            entry_size,
        },
        sk,
    ))
}

/// A fresh state for a cell that holds no rows yet, in which every shard encodes the same
/// `shard_rows`. One encoded shard stands in for all of them until the first re-encode, which
/// gives each shard its own copy: an empty block costs one shard, not the whole cell.
///
/// Served under `crs` when given, so every block of a list shares one client context; a new
/// CRS is set up otherwise.
///
/// # Errors
/// [`AdapterError::Scheme`] if `shard_rows` is not exactly one shard of `entry_size` rows, if
/// `crs` was set up for other parameters or another row width, or if encoding fails.
pub fn setup_unfilled_state(
    params: &InspireParams,
    shard_rows: &[u8],
    total_entries: u64,
    entry_size: usize,
    variant: InspireVariant,
    crs: Option<&Arc<ServerCrs>>,
) -> Result<InspireServerState> {
    require_wire_rung(params)?;
    let config = ShardConfig::for_ring_dim(params.ring_dim, entry_size, total_entries)
        .map_err(|e| AdapterError::Scheme(format!("unfilled cell geometry: {e}")))?;
    let shard_len = usize::try_from(config.entries_per_shard())
        .ok()
        .and_then(|rows| rows.checked_mul(entry_size));
    if shard_len != Some(shard_rows.len()) {
        return Err(AdapterError::Scheme(format!(
            "unfilled cell: one shard is {} rows of {entry_size} bytes, but {} bytes were given",
            config.entries_per_shard(),
            shard_rows.len()
        )));
    }
    let (crs, one_shard, minted_cache) = if let Some(crs) = crs {
        require_crs_fits(crs, params, entry_size)?;
        let shard_config = ShardConfig {
            total_entries: config.entries_per_shard(),
            ..config.clone()
        };
        let shards = raven_inspire::encode_database(shard_rows, entry_size, params, &shard_config)
            .map_err(|e| AdapterError::Scheme(format!("unfilled cell encode: {e}")))?;
        (Arc::clone(crs), shards, None)
    } else {
        let mut sampler = GaussianSampler::new(params.sigma);
        let (mut minted, one_shard, _sk) =
            inspire_setup(params, shard_rows, entry_size, &mut sampler)
                .map_err(|e| AdapterError::Scheme(format!("inspire setup: {e}")))?;
        let cache = ServerInspiringCache::from_setup(&mut minted, &one_shard)
            .map_err(|e| AdapterError::Scheme(format!("inspire setup cache: {e}")))?;
        (Arc::new(minted), one_shard.shards, Some(cache))
    };
    let [first] = <[raven_inspire::ShardData; 1]>::try_from(one_shard).map_err(|shards| {
        AdapterError::Scheme(format!(
            "unfilled cell: one shard of rows encoded to {} shards",
            shards.len()
        ))
    })?;
    let encoded_db = EncodedDatabase {
        shards: vec![raven_inspire::ShardData {
            id: 0,
            polynomials: first.polynomials,
        }],
        config,
    };
    let cache = match minted_cache {
        Some(built) => register_packing_cache(&crs, &encoded_db, built),
        None => shared_packing_cache(&crs, &encoded_db)?,
    };
    Ok(InspireServerState {
        crs,
        encoded_db: Arc::new(encoded_db),
        cache,
        session_store: Arc::new(BoundedSessionStore::new()),
        variant,
        entry_size,
    })
}

fn require_crs_fits(crs: &ServerCrs, params: &InspireParams, entry_size: usize) -> Result<()> {
    let columns = crate::pir_table::pir_cell_columns(entry_size);
    if crs.params != *params || crs.inspiring_num_columns != columns {
        return Err(AdapterError::Scheme(format!(
            "the CRS was set up for {} packing columns under other parameters than this cell's \
             {columns} columns; one client context cannot decode both",
            crs.inspiring_num_columns
        )));
    }
    Ok(())
}

/// Serve `state` under `crs`, which its encoded rows do not depend on, so one client context
/// decodes it alongside every other state served under `crs`.
///
/// # Errors
/// [`AdapterError::Scheme`] if `crs` was set up for other parameters or another row width.
pub fn serve_under_crs(
    state: InspireServerState,
    crs: &Arc<ServerCrs>,
) -> Result<InspireServerState> {
    if Arc::ptr_eq(&state.crs, crs) {
        return Ok(state);
    }
    require_crs_fits(crs, &state.crs.params, state.entry_size)?;
    let cache = shared_packing_cache(crs, &state.encoded_db)?;
    Ok(InspireServerState {
        crs: Arc::clone(crs),
        cache,
        ..state
    })
}

/// A cell whose one encoded shard stands in for every shard: see [`setup_unfilled_state`].
fn holds_one_shard_for_all(encoded_db: &EncodedDatabase) -> bool {
    encoded_db.config.num_shards() > 1
        && encoded_db.shards.len() == 1
        && encoded_db.shards.first().is_some_and(|shard| shard.id == 0)
}

/// Give every shard of an unfilled cell its own copy before any one is re-encoded.
fn allocate_every_shard(encoded_db: &mut EncodedDatabase) -> Result<()> {
    if !holds_one_shard_for_all(encoded_db) {
        return Ok(());
    }
    let declared = u32::try_from(encoded_db.config.num_shards()).map_err(|_| {
        AdapterError::Scheme(format!(
            "unfilled cell declares {} shards, past a u32 shard id",
            encoded_db.config.num_shards()
        ))
    })?;
    let template = encoded_db
        .shards
        .first()
        .map(|shard| shard.polynomials.clone())
        .ok_or_else(|| AdapterError::Scheme("unfilled cell lost its shard".into()))?;
    encoded_db.shards.reserve(declared as usize);
    for id in 1..declared {
        encoded_db.shards.push(raven_inspire::ShardData {
            id,
            polynomials: template.clone(),
        });
    }
    Ok(())
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
        fingerprint_for(&self.crs, &self.encoded_db)
    }
}

fn fingerprint_for(crs: &ServerCrs, encoded_db: &EncodedDatabase) -> CacheFingerprint {
    CacheFingerprint {
        params: crs.params.clone(),
        num_columns: encoded_db.shards.first().map_or(0, |s| s.polynomials.len()),
        inspiring_w_seed: crs.inspiring_w_seed,
    }
}

/// One packing cache per fingerprint per process. The cache is a pure function of its
/// fingerprint, so instances that agree on one hold the same keys once rather than a copy each.
struct PackingCacheEntry {
    fingerprint: CacheFingerprint,
    cache: std::sync::Weak<ServerInspiringCache>,
    /// A validated copy on disk that other data dirs link to instead of writing their own.
    file: Option<std::path::PathBuf>,
}

static PACKING_CACHES: parking_lot::Mutex<Vec<PackingCacheEntry>> =
    parking_lot::Mutex::new(Vec::new());

fn live_packing_cache(
    registry: &mut Vec<PackingCacheEntry>,
    fingerprint: &CacheFingerprint,
) -> Option<(Arc<ServerInspiringCache>, Option<std::path::PathBuf>)> {
    registry.retain(|entry| entry.cache.strong_count() > 0);
    registry
        .iter()
        .find(|entry| entry.fingerprint == *fingerprint)
        .and_then(|entry| Some((entry.cache.upgrade()?, entry.file.clone())))
}

fn record_packing_cache(
    registry: &mut Vec<PackingCacheEntry>,
    fingerprint: CacheFingerprint,
    cache: &Arc<ServerInspiringCache>,
    file: Option<std::path::PathBuf>,
) {
    if let Some(path) = file.as_ref() {
        // A path now holds this fingerprint's keys, so no other entry may link to it.
        for entry in registry.iter_mut() {
            if entry.file.as_ref() == Some(path) {
                entry.file = None;
            }
        }
    }
    if let Some(entry) = registry
        .iter_mut()
        .find(|entry| entry.fingerprint == fingerprint)
    {
        if entry.cache.strong_count() == 0 {
            entry.cache = Arc::downgrade(cache);
        }
        if file.is_some() {
            entry.file = file;
        }
    } else {
        registry.push(PackingCacheEntry {
            fingerprint,
            cache: Arc::downgrade(cache),
            file,
        });
    }
}

/// The live cache for `(crs, encoded_db)`, built and registered if no instance holds one.
fn shared_packing_cache(
    crs: &ServerCrs,
    encoded_db: &EncodedDatabase,
) -> Result<Arc<ServerInspiringCache>> {
    let fingerprint = fingerprint_for(crs, encoded_db);
    let mut registry = PACKING_CACHES.lock();
    if let Some((cache, _)) = live_packing_cache(&mut registry, &fingerprint) {
        cache
            .validate_for(crs, encoded_db)
            .map_err(|e| AdapterError::Scheme(format!("shared packing cache: {e}")))?;
        return Ok(cache);
    }
    let built = Arc::new(
        ServerInspiringCache::new(crs, encoded_db)
            .map_err(|e| AdapterError::Scheme(format!("inspire cache build: {e}")))?,
    );
    record_packing_cache(&mut registry, fingerprint, &built, None);
    Ok(built)
}

/// Register a cache built elsewhere, unless an instance already holds one for its fingerprint.
fn register_packing_cache(
    crs: &ServerCrs,
    encoded_db: &EncodedDatabase,
    built: ServerInspiringCache,
) -> Arc<ServerInspiringCache> {
    let fingerprint = fingerprint_for(crs, encoded_db);
    let mut registry = PACKING_CACHES.lock();
    if let Some((cache, _)) = live_packing_cache(&mut registry, &fingerprint) {
        return cache;
    }
    let built = Arc::new(built);
    record_packing_cache(&mut registry, fingerprint, &built, None);
    built
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
            shared_packing_cache(crs.as_ref(), &encoded_db)?
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
/// [`AdapterError::StateShapeMismatch`] if the donor geometry ever diverges.
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
/// The two implementations should not disagree on their draw: a reader comparing them has to
/// decide which is right. A bare remainder would leave a bias of about `bound / 2^64`; the
/// rejection sampling here is for parity. The attempt bound exists because an unbounded retry in a
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

/// Global rows for one padded batch: `global_indices` in order, then `padded - len` covers.
///
/// Covers go to shards no real index occupies, up to min(padded, shard count) distinct shards;
/// a cover that fits no free shard goes to a uniform shard. Covers address rows below
/// `total_entries`.
fn padded_targets(
    shard_config: &ShardConfig,
    global_indices: &[u64],
    padded: usize,
) -> Result<Vec<u64>> {
    let per_shard = shard_config.entries_per_shard();
    if per_shard == 0 {
        return Err(AdapterError::InvalidQuery(
            "shard config holds no entries per shard, so no cover shard can be named".to_owned(),
        ));
    }
    let overflow = || AdapterError::Scheme("cover target arithmetic overflowed".to_owned());
    let mut rows = shard_config.total_entries.max(1);
    let mut taken: Vec<u64> = Vec::with_capacity(padded);
    for &index in global_indices {
        // A real index past the stated table proves the row exists, so the bound was stale.
        rows = rows.max(index.checked_add(1).ok_or_else(overflow)?);
        let shard = index / per_shard;
        if let Err(at) = taken.binary_search(&shard) {
            taken.insert(at, shard);
        }
    }
    let shards = rows.div_ceil(per_shard);
    let padded_u64 = u64::try_from(padded).map_err(|_| overflow())?;
    let cover_slots = padded
        .checked_sub(global_indices.len())
        .ok_or_else(overflow)?;
    let free = padded_u64
        .min(shards)
        .saturating_sub(u64::try_from(taken.len()).map_err(|_| overflow())?);
    let distinct = cover_slots.min(usize::try_from(free).map_err(|_| overflow())?);

    let cover_row = |shard: u64| -> Result<u64> {
        let first = shard.checked_mul(per_shard).ok_or_else(overflow)?;
        let span = per_shard.min(rows.checked_sub(first).ok_or_else(overflow)?);
        first.checked_add(uniform_below(span)?).ok_or_else(overflow)
    };
    let mut targets = global_indices.to_vec();
    for _ in 0..distinct {
        let open = shards
            .checked_sub(u64::try_from(taken.len()).map_err(|_| overflow())?)
            .ok_or_else(overflow)?;
        let mut shard = uniform_below(open)?;
        for &held in &taken {
            if held > shard {
                break;
            }
            shard = shard.checked_add(1).ok_or_else(overflow)?;
        }
        if let Err(at) = taken.binary_search(&shard) {
            taken.insert(at, shard);
        }
        targets.push(cover_row(shard)?);
    }
    while targets.len() < padded {
        targets.push(cover_row(uniform_below(shards)?)?);
    }
    Ok(targets)
}

/// Build a batch padded up to the next [`batch_ladder`] step. Slots stay in
/// `global_indices` order, so `states[i]` decodes `responses[i]`.
///
/// Pads are built on the client. Each pad is a fresh query of the same size and work as
/// a real slot. Pads go first to shards no real index occupies, then to uniform shards.
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

    let targets = padded_targets(shard_config, global_indices, padded)?;
    let mut states = Vec::with_capacity(padded);
    let mut queries = Vec::with_capacity(padded);
    for index in targets {
        let (state, query) = build_seeded_query(client_session, shard_config, index, params)?;
        states.push(state);
        queries.push(query);
    }
    Ok((states, queries))
}

/// Decode a served response into the original plaintext bytes. The response carries its
/// own modulus; an unswitched one is the identity switch, so there is one extract path.
pub fn extract_response(
    crs: &ServerCrs,
    client_state: &ClientState,
    response: &ServerResponse,
    entry_size: usize,
) -> Result<Vec<u8>> {
    extract_inspiring_mod_switched(crs, client_state, response, entry_size)
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
/// [`snapshot_inspire_state_v8`], which also embeds the [`LogicalLeafStore`].
pub fn snapshot_inspire_state(state: &InspireServerState) -> Result<Vec<u8>> {
    serialize_after(&[], &PersistedInspireStateRef::of(state))
        .map_err(|e| AdapterError::Serialization(format!("snapshot serialize: {e}")))
}

/// Borrowing twin of [`PersistedInspireState`]. bincode writes a reference as the value behind
/// it, so the bytes are the owned bundle's and a commit serializes the served state in place
/// instead of cloning its encoded rows first.
#[derive(serde::Serialize)]
struct PersistedInspireStateRef<'a> {
    crs: &'a ServerCrs,
    encoded_db: &'a EncodedDatabase,
    variant: InspireVariant,
    entry_size: usize,
}

impl<'a> PersistedInspireStateRef<'a> {
    fn of(state: &'a InspireServerState) -> Self {
        Self {
            crs: &state.crs,
            encoded_db: &state.encoded_db,
            variant: state.variant,
            entry_size: state.entry_size,
        }
    }
}

#[derive(serde::Serialize)]
struct PersistedInspireStateV8Ref<'a> {
    state: PersistedInspireStateRef<'a>,
    store: &'a LogicalLeafStore,
}

/// `prefix` then the bincode body, in one buffer sized up front.
fn serialize_after<T: serde::Serialize>(
    prefix: &[u8],
    body: &T,
) -> std::result::Result<Vec<u8>, bincode::Error> {
    let body_len = usize::try_from(bincode::serialized_size(body)?).map_err(|_| {
        bincode::Error::from(bincode::ErrorKind::Custom(
            "snapshot body is larger than this platform can address".to_owned(),
        ))
    })?;
    let mut out = Vec::with_capacity(prefix.len().saturating_add(body_len));
    out.extend_from_slice(prefix);
    bincode::serialize_into(&mut out, body)?;
    Ok(out)
}

/// V6 magic header, recognised only so a V6 body is refused by name; V5 raw bincode never
/// starts with these bytes.
pub const SNAPSHOT_V6_MAGIC: [u8; 4] = *b"RV6\0";

/// V7 magic header, recognised only so a V7 body is refused by name. V7 stored a status byte
/// per list commitment and each row's upstream signature.
pub const SNAPSHOT_V7_MAGIC: [u8; 4] = *b"RV7\0";

/// V8 magic header; V8 retains each list row's event type and upstream root, and no status or
/// signature.
pub const SNAPSHOT_V8_MAGIC: [u8; 4] = *b"RV8\0";

/// V8 envelope; bundling the store lets a commit archive the WAL without
/// losing logical state on restart.
#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedInspireStateV8 {
    state: PersistedInspireState,
    store: LogicalLeafStore,
}

/// Serialize `(state, store)` under [`SNAPSHOT_V8_MAGIC`].
pub fn snapshot_inspire_state_v8(
    state: &InspireServerState,
    store: &LogicalLeafStore,
) -> Result<Vec<u8>> {
    let bundle = PersistedInspireStateV8Ref {
        state: PersistedInspireStateRef::of(state),
        store,
    };
    serialize_after(&SNAPSHOT_V8_MAGIC, &bundle)
        .map_err(|e| AdapterError::Serialization(format!("v8 snapshot serialize: {e}")))
}

/// Decode a snapshot body, REFUSING surplus bytes.
///
/// `bincode::deserialize` is `…with_fixint_encoding().allow_trailing_bytes()`, which bincode's own
/// docs flag as the opposite of the `DefaultOptions` struct's default. Surplus after a snapshot
/// means the writer and the reader disagree about the shape; discarding it silently is how a
/// V7-shaped store read through the former V6 reader returned `Ok` with a list key assembled
/// from signature bytes. `inspire-cache`, `pir/respond.rs` and `crates/client` already reject
/// trailing bytes -- the snapshot path was the outlier.
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
    validate_persisted_state(&bundle)?;
    let cache = shared_packing_cache(&bundle.crs, &bundle.encoded_db)?;
    Ok(InspireServerState {
        crs: Arc::new(bundle.crs),
        encoded_db: Arc::new(bundle.encoded_db),
        cache,
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

/// The recovered state's cache, and whether this data dir now holds a validated copy of it on
/// disk without a rebuild. A cache another instance of this process already holds is shared, and
/// its validated file is linked into this data dir; otherwise the dir's own file is read.
fn cache_for_recovery(
    data_dir: &std::path::Path,
    crs: &ServerCrs,
    encoded_db: &EncodedDatabase,
) -> Result<(Arc<ServerInspiringCache>, bool, bool)> {
    use super::offline_packing_keys_cache::{CacheLoad, OfflinePackingKeysCache};

    let identity = cache_identity(crs, encoded_db);
    let fingerprint = fingerprint_for(crs, encoded_db);
    let disk = OfflinePackingKeysCache::new(data_dir);
    let mut registry = PACKING_CACHES.lock();
    let shared = live_packing_cache(&mut registry, &fingerprint);
    if let Some((cache, canonical)) = shared.as_ref() {
        cache
            .validate_for(crs, encoded_db)
            .map_err(|e| AdapterError::Scheme(format!("shared packing cache: {e}")))?;
        if let Some(canonical) = canonical.as_deref().filter(|path| *path != disk.path()) {
            match disk.link_from(canonical) {
                Ok(()) => {
                    let linked = Some(disk.path().to_path_buf());
                    record_packing_cache(&mut registry, fingerprint, cache, linked);
                    return Ok((Arc::clone(cache), true, true));
                }
                Err(error) => tracing::warn!(
                    %error,
                    "offline packing cache link failed; checking this data dir's own copy"
                ),
            }
        }
    }
    let loaded = match disk.load(&identity) {
        CacheLoad::Hit(parts) => {
            let cache = ServerInspiringCache::from_parts(parts.pack_params, parts.offline_keys);
            match cache.validate_for(crs, encoded_db) {
                Ok(()) => Some(cache),
                Err(error) => {
                    tracing::warn!(%error, "offline packing cache failed validation; rebuilding");
                    None
                }
            }
        }
        CacheLoad::Miss(_) => None,
    };
    let hit = loaded.is_some();
    let cache = match (shared, loaded) {
        (Some((cache, _)), _) => cache,
        (None, Some(loaded)) => Arc::new(loaded),
        (None, None) => Arc::new(
            ServerInspiringCache::new(crs, encoded_db)
                .map_err(|e| AdapterError::Scheme(format!("restore cache build: {e}")))?,
        ),
    };
    let persisted = hit
        || match disk.store(&identity, cache.pack_params(), cache.offline_keys()) {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(error = %error, "offline packing cache store failed; recovery remains correct");
                false
            }
        };
    let file = persisted.then(|| disk.path().to_path_buf());
    record_packing_cache(&mut registry, fingerprint, &cache, file);
    Ok((cache, hit, persisted))
}

pub(crate) fn persist_inspiring_cache(
    data_dir: &std::path::Path,
    state: &InspireServerState,
) -> Result<()> {
    use super::offline_packing_keys_cache::OfflinePackingKeysCache;

    let disk = OfflinePackingKeysCache::new(data_dir);
    let fingerprint = state.cache_fingerprint();
    let mut registry = PACKING_CACHES.lock();
    let canonical = live_packing_cache(&mut registry, &fingerprint)
        .and_then(|(_, file)| file)
        .filter(|path| path != disk.path());
    if let Some(canonical) = canonical {
        match disk.link_from(&canonical) {
            Ok(()) => {
                let linked = Some(disk.path().to_path_buf());
                record_packing_cache(&mut registry, fingerprint, &state.cache, linked);
                return Ok(());
            }
            Err(error) => tracing::warn!(
                %error,
                "offline packing cache link failed; writing this data dir's own copy"
            ),
        }
    }
    disk.store(
        &cache_identity(&state.crs, &state.encoded_db),
        state.cache.pack_params(),
        state.cache.offline_keys(),
    )
    .map_err(|e| AdapterError::Internal(format!("offline packing cache store: {e}")))?;
    record_packing_cache(
        &mut registry,
        fingerprint,
        &state.cache,
        Some(disk.path().to_path_buf()),
    );
    Ok(())
}

/// Refused before a byte of the body is read. No V6 or V7 writer survives, so a decoder for
/// either has nothing to read correctly and could not tell a same-width reinterpretation from a
/// value. The layout help is left off: its probe and matching-build advice cannot succeed on a
/// body this build never reads.
fn refuse_retired_body(epoch: &str) -> AdapterError {
    AdapterError::Serialization(format!(
        "{epoch} snapshot refused: this build reads the V8 snapshot epoch and refuses a \
         {epoch} body unread, whatever it contains; no in-place migration exists. Operator: \
         re-bootstrap this instance."
    ))
}

/// The magic of a snapshot epoch this build refuses by name, if `bytes` carries one.
fn retired_epoch(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(SNAPSHOT_V7_MAGIC.as_slice()) {
        Some("v7")
    } else if bytes.starts_with(SNAPSHOT_V6_MAGIC.as_slice()) {
        Some("v6")
    } else {
        None
    }
}

/// V8 carries the LIVE store, so there is no frozen shape to name; the operator's options are
/// those of every other arm, and so is the message.
fn decode_v8_body(body: &[u8]) -> Result<PersistedInspireStateV8> {
    decode_snapshot_body(body).map_err(|e| {
        AdapterError::Serialization(format!(
            "v8 snapshot deserialize: {e}. {SNAPSHOT_LAYOUT_HELP}"
        ))
    })
}

/// Reconstruct `(InspireServerState, LogicalLeafStore)`, dispatching on the snapshot magic.
/// V8 carries the store, V7 and V6 are refused unread, and V5 yields an empty store that WAL
/// replay refills.
pub fn restore_inspire_state_v6(bytes: &[u8]) -> Result<(InspireServerState, LogicalLeafStore)> {
    if let Some(body) = bytes.strip_prefix(SNAPSHOT_V8_MAGIC.as_slice()) {
        let bundle = decode_v8_body(body)?;
        let state = bundle_to_state(bundle.state)?;
        Ok((state, bundle.store))
    } else if let Some(epoch) = retired_epoch(bytes) {
        Err(refuse_retired_body(epoch))
    } else {
        tracing::warn!(
            target = "raven::engine::snapshot",
            "legacy V5 snapshot (no snapshot magic prefix); LogicalLeafStore starts empty and \
             will be repopulated from WAL replay if WAL bytes are still present"
        );
        let state = restore_inspire_state(bytes)?;
        Ok((state, LogicalLeafStore::default()))
    }
}

pub(crate) fn restore_inspire_state_v6_cached(
    bytes: &[u8],
    data_dir: &std::path::Path,
) -> Result<(InspireServerState, LogicalLeafStore, bool, bool)> {
    if let Some(body) = bytes.strip_prefix(SNAPSHOT_V8_MAGIC.as_slice()) {
        let bundle = decode_v8_body(body)?;
        validate_persisted_state(&bundle.state)?;
        let (cache, hit, persisted) =
            cache_for_recovery(data_dir, &bundle.state.crs, &bundle.state.encoded_db)?;
        let state = InspireServerState {
            crs: Arc::new(bundle.state.crs),
            encoded_db: Arc::new(bundle.state.encoded_db),
            cache,
            session_store: Arc::new(BoundedSessionStore::new()),
            variant: bundle.state.variant,
            entry_size: bundle.state.entry_size,
        };
        Ok((state, bundle.store, hit, persisted))
    } else if let Some(epoch) = retired_epoch(bytes) {
        Err(refuse_retired_body(epoch))
    } else {
        tracing::warn!(
            target = "raven::engine::snapshot",
            "legacy V5 snapshot (no snapshot magic prefix); LogicalLeafStore starts empty and \
             will be repopulated from WAL replay if WAL bytes are still present"
        );
        // The boot path (`persistence.rs`) comes through HERE, not through the uncached
        // twin -- so this is the arm a production reopen failure surfaces on, and it was the
        // one still emitting a bare bincode error the operator could not act on.
        let bundle: PersistedInspireState = decode_snapshot_body(bytes).map_err(|e| {
            AdapterError::Serialization(format!(
                "v5 snapshot deserialize: {e}. {SNAPSHOT_LAYOUT_HELP}"
            ))
        })?;
        validate_persisted_state(&bundle)?;
        let (cache, hit, persisted) =
            cache_for_recovery(data_dir, &bundle.crs, &bundle.encoded_db)?;
        let state = InspireServerState {
            crs: Arc::new(bundle.crs),
            encoded_db: Arc::new(bundle.encoded_db),
            cache,
            session_store: Arc::new(BoundedSessionStore::new()),
            variant: bundle.variant,
            entry_size: bundle.entry_size,
        };
        Ok((state, LogicalLeafStore::default(), hit, persisted))
    }
}

/// Re-encode a single shard from a raw byte buffer in place. An unfilled cell first gives
/// every shard its own copy of the one it holds.
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
    allocate_every_shard(encoded_db)?;
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

pub(crate) use logical_store::appends_to_a_tree;
pub use logical_store::{
    apply_wal_entry, ensure_canonical_leaf, materialize_shard_bytes, validate_apply,
    LogicalLeafStore,
};

#[cfg(test)]
mod frozen_v8_shape_tests {
    //! V8 carries the LIVE `LogicalLeafStore`, the position V6 was in when a field inserted
    //! mid-struct reinterpreted the bytes of every snapshot written before it. These tests pin
    //! the V8 read path to frozen BYTES, because a round trip through today's codec cannot see
    //! a shape change -- it writes and reads the same wrong layout and passes.
    //!
    //! LIMIT, stated so a green run is not over-read: the store holds `HashMap`s, so minting
    //! is NOT byte-reproducible. Decoding is order-independent, so the fixture is sound to
    //! read -- but a fixture diff is not evidence of a shape change, and a test that passes
    //! after a re-mint proves only that the fixture matches the struct that minted it. The
    //! control is that the generator is `#[ignore]`d and re-minting is a deliberate act.

    use super::{apply_wal_entry, LogicalLeafStore};
    use crate::pir_table::PerLeafCommitmentEncoder;
    use raven_railgun_persistence::{PpoiEventType, WalEntryPayload};

    /// The CURRENT layout, frozen at the shape that ships: the next field inserted mid-struct
    /// fires here rather than on the box.
    ///
    /// What it catches: a field added, removed or moved, and a width change -- the decode
    /// underruns or leaves surplus, and surplus is refused. What it does NOT catch: a
    /// same-width type substitution (`u64` for `i64`), which decodes cleanly and passes every
    /// assertion below.
    const FROZEN_V8_STORE: &[u8] = include_bytes!("../tests/fixtures/logical_store_v8.bin");

    /// The store the V7 epoch wrote, minted by the last build that wrote it. It is kept to prove
    /// that the V8 layout really differs, so a V7 body read as V8 could only fail or misread,
    /// which is why the V7 magic is refused unread.
    const FROZEN_V7_STORE: &[u8] = include_bytes!("../tests/fixtures/logical_store_v7.bin");

    const LIST_KEY: [u8; 32] = [0xab; 32];

    /// One commitment leaf and two PPOI list leaves. The PPOI leaves are the only writers of
    /// `ppoi_list_leaf_block_height`, the map a mid-struct insertion steals the bytes of.
    /// Height 0 mirrors production, where the mirror sends 0.
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
                    event_type: PpoiEventType::Shield,
                    validated_merkleroot: [0x11; 32],
                },
                0,
                &enc,
            )
            .expect("append ppoi list leaf");
        }
        store
    }

    #[test]
    #[ignore = "trigger: a change to LogicalLeafStore's layout, and then only in the same \
                change as a new snapshot magic. Run with --ignored by hand."]
    fn mint_frozen_v8_store_fixture() {
        let bytes = bincode::serialize(&sample_store()).expect("serialize v8 store");
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/logical_store_v8.bin");
        std::fs::write(&path, &bytes).expect("write fixture");
    }

    // Changing `LogicalLeafStore`'s layout without a magic reddens HERE, at desk speed,
    // instead of at boot on a data_dir nobody can re-read.
    #[test]
    fn the_live_store_still_reads_the_shipped_v8_layout() {
        let store: LogicalLeafStore =
            super::decode_snapshot_body(FROZEN_V8_STORE).unwrap_or_else(|e| {
                panic!(
                "LogicalLeafStore no longer reads the V8 bytes it ships with ({e}). bincode is \
                 positional: a field added or moved breaks every existing data_dir. Add a new \
                 SNAPSHOT_V9_MAGIC, refuse a V8 body by name, and re-mint this fixture in the \
                 SAME change."
                )
            });
        assert_eq!(store.leaf(0, 0), Some(&[7u8; 32]));
        assert_eq!(store.ppoi_list_leaves_iter(&LIST_KEY).count(), 2);
        assert_eq!(store.ppoi_list_leaf_block_height_len(), 2);
        let meta = store
            .ppoi_event_metadata(&LIST_KEY, 0)
            .expect("V8 retains each row's upstream metadata");
        assert_eq!(meta.validated_merkleroot, [0x11; 32]);
        assert_eq!(meta.event_type, PpoiEventType::Shield);
    }

    #[test]
    fn a_v7_store_does_not_read_as_the_v8_layout() {
        let decoded = super::decode_snapshot_body::<LogicalLeafStore>(FROZEN_V7_STORE);
        assert!(
            decoded.is_err(),
            "the V7 store decodes under the V8 layout, so the epochs are not distinct layouts \
             and the V7 refusal would be refusing a readable body"
        );
    }
}

#[cfg(test)]
mod snapshot_v6_tests {
    use super::{
        restore_inspire_state, restore_inspire_state_v6, setup_state, snapshot_inspire_state,
        snapshot_inspire_state_v8, InspireVariant, LogicalLeafStore, SNAPSHOT_V6_MAGIC,
        SNAPSHOT_V7_MAGIC, SNAPSHOT_V8_MAGIC,
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

    // The borrowed writer must emit the owned bundle's exact bytes, or every snapshot it writes
    // is one the reader cannot decode.
    #[test]
    fn a_borrowed_snapshot_is_byte_identical_to_the_owned_bundle() {
        let (state, _) = toy_state_and_db();
        let mut store = LogicalLeafStore::new();
        let encoder =
            crate::pir_table::PerLeafCommitmentEncoder::new(32, 2048, 0).expect("encoder");
        super::apply_wal_entry(
            &mut store,
            &raven_railgun_persistence::WalEntryPayload::AppendLeaf {
                tree_number: 0,
                leaf_index: 0,
                commitment: [3; 32],
            },
            7,
            &encoder,
        )
        .expect("leaf");
        let owned = super::PersistedInspireState {
            crs: (*state.crs).clone(),
            encoded_db: (*state.encoded_db).clone(),
            variant: state.variant,
            entry_size: state.entry_size,
        };
        assert_eq!(
            snapshot_inspire_state(&state).expect("v5"),
            bincode::serialize(&owned).expect("owned v5")
        );
        let mut owned_v8 = SNAPSHOT_V8_MAGIC.to_vec();
        owned_v8.extend(
            bincode::serialize(&super::PersistedInspireStateV8 {
                state: owned,
                store: store.clone(),
            })
            .expect("owned v8"),
        );
        assert_eq!(
            snapshot_inspire_state_v8(&state, &store).expect("v8"),
            owned_v8
        );
    }

    #[test]
    fn v8_snapshot_carries_distinct_magic_prefix() {
        let (state, _) = toy_state_and_db();
        let store = LogicalLeafStore::new();
        let bytes = snapshot_inspire_state_v8(&state, &store).expect("v8 serialize");
        assert!(bytes.starts_with(&SNAPSHOT_V8_MAGIC));
        assert!(!bytes.starts_with(&SNAPSHOT_V7_MAGIC));
        assert!(!bytes.starts_with(&SNAPSHOT_V6_MAGIC));
        restore_inspire_state_v6(&bytes).expect("v8 restore through current reader");
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
    fn v8_round_trip_restores_state_and_empty_store() {
        let (state, _) = toy_state_and_db();
        let store = LogicalLeafStore::new();
        let bytes = snapshot_inspire_state_v8(&state, &store).expect("v8 serialize");
        let (restored, store_back) = restore_inspire_state_v6(&bytes).expect("v8 restore");
        assert_eq!(restored.entry_size, state.entry_size);
        assert_eq!(store_back.ppoi_list_count(), 0);
        assert_eq!(store_back.leaf_count(), 0);
    }

    /// A snapshot's parameters are data read off disk, so the boot path holds them to what setup
    /// accepts. Here `q` no longer equals its CRT moduli's product.
    #[test]
    fn a_snapshot_whose_parameters_setup_would_refuse_is_refused_on_both_paths() {
        let (state, _) = toy_state_and_db();
        let mut crs = (*state.crs).clone();
        crs.params.q = crs.params.q.wrapping_add(2);
        let tampered = super::InspireServerState {
            crs: std::sync::Arc::new(crs),
            ..state
        };
        let bytes =
            snapshot_inspire_state_v8(&tampered, &LogicalLeafStore::new()).expect("v8 serialize");
        let dir = tempfile::tempdir().expect("tempdir");
        for (path, outcome) in [
            ("uncached", restore_inspire_state_v6(&bytes).map(|_| ())),
            (
                "boot",
                super::restore_inspire_state_v6_cached(&bytes, dir.path()).map(|_| ()),
            ),
        ] {
            let error = outcome.expect_err("tampered parameters must not restore");
            assert!(
                error.to_string().contains("snapshot parameters"),
                "{path}: {error}"
            );
        }
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
        assert_eq!(store_back.ppoi_list_count(), 0);
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
            // this tree's row: the store accepts any tree regardless of what ingest scoped.
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

    fn list_leaf(list_key: [u8; 32], list_index: u32, bc: [u8; 32]) -> WalEntryPayload {
        WalEntryPayload::PpoiListLeafAdded {
            list_key,
            list_index,
            blinded_commitment: bc,
            event_type: raven_railgun_persistence::PpoiEventType::Shield,
            validated_merkleroot: [0; 32],
        }
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
            let leaf = list_leaf([0u8; 32], u32::from(i), bc);
            apply_wal_entry(&mut s, &leaf, 200 + u64::from(i), &enc()).expect("apply leaf");
        }
        assert_eq!(s.leaf_count(), 5);
        assert_eq!(s.ppoi_list_leaves_iter(&[0u8; 32]).count(), 3);
        let reorg = WalEntryPayload::Reorg { height: 102 };
        apply_wal_entry(&mut s, &reorg, 102, &enc()).expect("apply reorg");
        assert_eq!(s.leaf_count(), 3, "leaves at 100, 101, 102 survive");
        assert_eq!(
            s.ppoi_list_leaves_iter(&[0u8; 32]).count(),
            0,
            "all PPOI past 102 dropped"
        );
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
        assert_eq!(s.ppoi_list_count(), 0);
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
mod unfilled_cell_tests {
    use super::{
        build_client_session, build_seeded_query, extract_response, re_encode_shard,
        restore_inspire_state_v6, setup_unfilled_state, snapshot_inspire_state_v8,
        InspireServerState, LogicalLeafStore, RavenInspireScheme,
    };
    use crate::PirScheme;
    use raven_inspire::math::GaussianSampler;
    use raven_inspire::params::{InspireParams, InspireVariant};
    use raven_inspire::rlwe::RlweSecretKey;
    use std::sync::Arc;

    const ENTRY: usize = 32;
    const ROWS_PER_SHARD: usize = 2048;

    fn unfilled() -> InspireServerState {
        setup_unfilled_state(
            &InspireParams::secure_128_d2048(),
            &vec![0x11; ROWS_PER_SHARD * ENTRY],
            65_536,
            ENTRY,
            InspireVariant::TwoPacking,
            None,
        )
        .expect("unfilled cell")
    }

    fn decode(state: &InspireServerState, row: usize) -> Vec<u8> {
        let params = InspireParams::secure_128_d2048();
        let mut sampler = GaussianSampler::new(params.sigma);
        let secret = RlweSecretKey::generate(&params, &mut sampler);
        let session = build_client_session((*state.crs).clone(), secret, &params).expect("session");
        let (client_state, query) =
            build_seeded_query(&session, state.shard_config(), row as u64, &params).expect("query");
        let response = RavenInspireScheme::respond(state, &query).expect("respond");
        extract_response(&state.crs, &client_state, &response, ENTRY).expect("extract")
    }

    #[test]
    fn an_unfilled_cell_serves_every_shard_from_its_one_encoding_across_a_restart() {
        let state = unfilled();
        assert_eq!(state.encoded_db.shards.len(), 1);
        assert_eq!(decode(&state, 7 * ROWS_PER_SHARD + 5), vec![0x11; ENTRY]);

        let bytes = snapshot_inspire_state_v8(&state, &LogicalLeafStore::new()).expect("snapshot");
        let (restored, _) = restore_inspire_state_v6(&bytes).expect("restore");
        assert_eq!(restored.encoded_db.shards.len(), 1);
        assert_eq!(decode(&restored, 31 * ROWS_PER_SHARD), vec![0x11; ENTRY]);
    }

    #[test]
    fn the_first_re_encode_gives_every_shard_its_own_copy() {
        let state = unfilled();
        let mut encoded = (*state.encoded_db).clone();
        re_encode_shard(
            &mut encoded,
            &InspireParams::secure_128_d2048(),
            3,
            &vec![0x22; ROWS_PER_SHARD * ENTRY],
            ENTRY,
        )
        .expect("re-encode one shard of an unfilled cell");
        assert_eq!(encoded.shards.len(), 32);
        let state = InspireServerState {
            encoded_db: Arc::new(encoded),
            ..state
        };
        assert_eq!(decode(&state, 3 * ROWS_PER_SHARD + 9), vec![0x22; ENTRY]);
        assert_eq!(decode(&state, 5 * ROWS_PER_SHARD + 9), vec![0x11; ENTRY]);
        assert_eq!(decode(&state, 9), vec![0x11; ENTRY]);
    }
}

#[cfg(test)]
mod packing_cache_registry_tests {
    use super::{
        cache_for_recovery, cache_identity, persist_inspiring_cache, setup_unfilled_state,
        InspireServerState,
    };
    use crate::offline_packing_keys_cache::{CacheLoad, OfflinePackingKeysCache};
    use raven_inspire::params::{InspireParams, InspireVariant};
    use std::path::Path;

    const ENTRY: usize = 32;

    /// Each call sets up a CRS of its own, so each state has its own packing keys.
    fn own_keys() -> InspireServerState {
        setup_unfilled_state(
            &InspireParams::secure_128_d2048(),
            &vec![0x11; 2048 * ENTRY],
            65_536,
            ENTRY,
            InspireVariant::TwoPacking,
            None,
        )
        .expect("unfilled cell")
    }

    fn holds_keys_of(dir: &Path, state: &InspireServerState) -> bool {
        let identity = cache_identity(&state.crs, &state.encoded_db);
        matches!(
            OfflinePackingKeysCache::new(dir).load(&identity),
            CacheLoad::Hit(_)
        )
    }

    /// Dir `a` holds the first keys, then is linked to the second's; a third dir that later
    /// asks for the first keys must not be linked to `a`.
    fn relinked_dir_is_not_offered_as_its_old_keys(relink: impl Fn(&Path, &InspireServerState)) {
        let root = tempfile::tempdir().expect("tempdir");
        let (a, b, c) = (
            root.path().join("a"),
            root.path().join("b"),
            root.path().join("c"),
        );
        let (first, second) = (own_keys(), own_keys());
        cache_for_recovery(&a, &first.crs, &first.encoded_db).expect("a holds the first keys");
        cache_for_recovery(&b, &second.crs, &second.encoded_db).expect("b holds the second");
        relink(&a, &second);
        assert!(holds_keys_of(&a, &second), "a is linked to the second keys");

        cache_for_recovery(&c, &first.crs, &first.encoded_db).expect("c asks for the first keys");
        assert!(
            holds_keys_of(&c, &first),
            "c was linked to a file that no longer holds the keys it was recorded for"
        );
    }

    #[test]
    fn a_dir_relinked_on_recovery_is_not_offered_as_its_old_keys() {
        relinked_dir_is_not_offered_as_its_old_keys(|dir, state| {
            cache_for_recovery(dir, &state.crs, &state.encoded_db).expect("relink on recovery");
        });
    }

    #[test]
    fn a_dir_relinked_on_persist_is_not_offered_as_its_old_keys() {
        relinked_dir_is_not_offered_as_its_old_keys(|dir, state| {
            persist_inspiring_cache(dir, state).expect("relink on persist");
        });
    }
}

#[cfg(test)]
mod pad_draw_tests {
    use super::{padded_targets, rejection_limit, uniform_below};
    use raven_inspire::params::ShardConfig;
    use raven_railgun_core::batch_ladder;
    use std::collections::BTreeSet;

    const PER_SHARD: u64 = 2048;

    fn table(shards: u64) -> ShardConfig {
        ShardConfig {
            shard_size_bytes: PER_SHARD * 32,
            entry_size_bytes: 32,
            total_entries: shards * PER_SHARD,
        }
    }

    fn distinct_shards(targets: &[u64]) -> usize {
        targets
            .iter()
            .map(|t| t / PER_SHARD)
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// Covers fill free shards first, so reals in distinct shards plus their covers touch
    /// exactly `padded` shards.
    #[test]
    fn distinct_shards_depend_on_the_ladder_step_alone() {
        let config = table(64);
        for real in 1..=32_usize {
            let padded = batch_ladder::padded_len(real).expect("in ladder range");
            let reals: Vec<u64> = (0..real as u64).map(|s| s * PER_SHARD + 3).collect();
            for _ in 0..4 {
                let targets = padded_targets(&config, &reals, padded).expect("targets");
                assert_eq!(targets.len(), padded);
                assert_eq!(
                    targets.get(..real),
                    Some(reals.as_slice()),
                    "reals lead in order"
                );
                assert_eq!(
                    distinct_shards(&targets),
                    padded,
                    "{real} reals in {real} shards must touch {padded} shards"
                );
            }
        }
    }

    #[test]
    fn a_small_table_is_covered_whole_and_no_row_past_it_is_named() {
        let config = ShardConfig {
            total_entries: 3 * PER_SHARD - 100,
            ..table(3)
        };
        for real in 1..=32_usize {
            let padded = batch_ladder::padded_len(real).expect("in ladder range");
            let reals: Vec<u64> = (0..real as u64)
                .map(|i| (i % 3) * PER_SHARD + i / 3)
                .collect();
            let targets = padded_targets(&config, &reals, padded).expect("targets");
            assert_eq!(distinct_shards(&targets), padded.min(3), "real={real}");
            assert!(
                targets.iter().all(|t| *t < config.total_entries),
                "{targets:?}"
            );
        }
    }

    /// A favoured residue would bias which cover shards are drawn. The bias a bare remainder
    /// leaves at these batch lengths is about `bound / 2^64`, which no statistical test on the
    /// draw could distinguish, so the bound is asserted rather than samples.
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
