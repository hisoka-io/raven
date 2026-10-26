//! The served state: one immutable [`View`] of the table, swapped whole after each change.
//!
//! A view holds everything an answer reads - the feed, the tree's leaves, the upper nodes
//! and the encoded shards the private reads run over - at one leaf count. A new view is
//! published only once its shards are encoded, so a row the feed shows is a row a private
//! read returns, and an answer read from one view agrees with itself.
//!
//! Each shard is encoded on its own, with its packing store beside it, and shared between
//! views. An append re-encodes the shards whose cells changed - with leaves arriving at the
//! end, the newest one - and every other shard is the same allocation as before. A shard is
//! re-encoded exactly when its cells' digest changes, so a store always answers for the
//! cells it was built from.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use howl_store::{NoteStore, StoreError, ROWS_PER_SHARD, SHARD_BYTES};
use howl_wire::tree::{Node, BLOCK_LEAVES};
use howl_wire::{
    Answer, Body, LeafBlock, P16Batch, PrefixSegment, UpperNodes, CELL_BYTES, LADDER,
    MAX_UPPER_NODES, NODE_BYTES, P16_KEY_BYTES, PARAM_SET_D2048_CELL256,
    PARAM_SET_D2048_CELL256_P16, PREFIX_BYTES,
};
use raven_inspire::inspiring::ClientPackingKeys;
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, ShardConfig};
use raven_inspire::pir::mod_switch::{mod_switch_response_checked, MOD_SWITCH_TARGET_36BIT};
use raven_inspire::special_modulus::{KeySeat, ShardTable};
use raven_inspire::{
    encode_database, resolve_packing_seat, respond_seeded_with_seat, setup_with_rng,
    EncodedDatabase, PackingKeySource, SeededQueryBatch, ServerCrs, ServerInspiringCache,
    ServerSessionHandle,
};
use raven_inspire_session::{BoundedSessionStore, SessionStoreLimits};

use crate::single::Single;

/// Rows of one feed segment, as the feed crate cuts them.
const SEGMENT_ROWS: u64 = howl_prefix_feed::SEGMENT_ROWS;

/// Why the engine could not build or serve.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// The table refused a read.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The private-read scheme refused.
    #[error("private read: {0}")]
    Scheme(String),
    /// A file of the node's own state could not be read or written.
    #[error("node state: {0}")]
    Io(#[from] std::io::Error),
}

/// Why a private read was refused.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    /// The batch is not a ladder step.
    #[error("a batch of {0} is not a ladder step (1, 2, 4, 8 or 16)")]
    NotALadderStep(usize),
    /// A query names a shard past the view's table.
    #[error("shard {shard} is past the {shards} shards served")]
    Stale {
        /// Shard named.
        shard: u32,
        /// Shards in the view.
        shards: usize,
    },
    /// The session handle is expired or unknown.
    #[error("{0}")]
    Session(String),
    /// Every seat is taken.
    #[error("{0}")]
    Full(String),
    /// The key or a query does not fit the parameters.
    #[error("{0}")]
    Malformed(String),
}

/// Parameter set 1's fixed parts: parameters, public key material, packing cache, sessions.
struct Gadget {
    params: InspireParams,
    crs: ServerCrs,
    crs_bytes: Vec<u8>,
    cache: ServerInspiringCache,
    shard_config: ShardConfig,
    sessions: BoundedSessionStore,
}

impl std::fmt::Debug for Gadget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gadget")
            .field("ring_dim", &self.params.ring_dim)
            .field("sessions", &self.sessions.len())
            .finish_non_exhaustive()
    }
}

fn scheme(e: impl std::fmt::Display) -> EngineError {
    EngineError::Scheme(e.to_string())
}

const CRS_FILE: &str = "crs.bin";
const SESSIONS_DIR: &str = "sessions";

/// The wire CRS: everything a client needs and nothing only another packing mode reads.
fn wire_crs(crs: &ServerCrs) -> ServerCrs {
    ServerCrs {
        params: crs.params.clone(),
        galois_keys: Vec::new(),
        rgsw_gadget: crs.rgsw_gadget.clone(),
        inspiring_pack_params: None,
        inspiring_packing_key: None,
        inspiring_w_seed: crs.inspiring_w_seed,
        inspiring_v_seed: crs.inspiring_v_seed,
        inspiring_num_columns: crs.inspiring_num_columns,
    }
}

impl Gadget {
    fn open(
        dir: &Path,
        limits: SessionStoreLimits,
        seed: Option<[u8; 32]>,
    ) -> Result<Self, EngineError> {
        use rand_chacha::rand_core::SeedableRng;
        let params = InspireParams::d2048();
        let shard_config =
            ShardConfig::for_ring_dim(params.ring_dim, CELL_BYTES, ROWS_PER_SHARD as u64)
                .map_err(scheme)?;
        let path = dir.join(CRS_FILE);
        let crs = match std::fs::read(&path) {
            Ok(bytes) => ServerCrs::from_versioned_bytes(&bytes).map_err(scheme)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut rng = match seed {
                    Some(seed) => rand_chacha::ChaCha20Rng::from_seed(seed),
                    None => rand_chacha::ChaCha20Rng::from_entropy(),
                };
                let mut sampler = GaussianSampler::new(params.sigma);
                let zero = vec![0u8; SHARD_BYTES];
                let (crs, _, _) =
                    setup_with_rng(&params, &zero, CELL_BYTES, &mut sampler, &mut rng)
                        .map_err(scheme)?;
                let crs = wire_crs(&crs);
                let bytes = crs.to_versioned_bytes().map_err(scheme)?;
                std::fs::create_dir_all(dir)?;
                let staged = dir.join(format!("{CRS_FILE}.new"));
                std::fs::write(&staged, &bytes)?;
                std::fs::File::open(&staged)?.sync_all()?;
                std::fs::rename(&staged, &path)?;
                crs
            }
            Err(e) => return Err(e.into()),
        };
        if crs.params != params
            || crs.inspiring_num_columns != raven_inspire::num_columns(CELL_BYTES)
        {
            return Err(EngineError::Scheme(
                "the stored key material was made for other parameters".to_owned(),
            ));
        }
        let crs_bytes = crs.to_versioned_bytes().map_err(scheme)?;
        let zero = encode_one(&params, &shard_config, &vec![0u8; SHARD_BYTES])?;
        let cache = ServerInspiringCache::new(&crs, &zero).map_err(scheme)?;
        std::fs::create_dir_all(dir.join(SESSIONS_DIR))?;
        let sessions = BoundedSessionStore::open_with_limits(&dir.join(SESSIONS_DIR), limits)
            .map_err(scheme)?;
        Ok(Self {
            params,
            crs,
            crs_bytes,
            cache,
            shard_config,
            sessions,
        })
    }

    fn key_upload_limit(&self) -> usize {
        2usize
            .saturating_mul(self.params.packing_key_rows())
            .saturating_mul(self.params.ring_dim)
            .saturating_mul(self.params.crt_moduli.len().max(1))
            .saturating_mul(8)
            .saturating_add(4096)
    }

    fn register(&self, keys: ClientPackingKeys) -> Result<ServerSessionHandle, Refusal> {
        let (outcome, _, _) = self
            .sessions
            .register_server_side(keys, self.cache.pack_params(), &self.params.ntt_context())
            .into_parts();
        outcome.map_err(|e| match e {
            raven_inspire_session::SessionStoreError::AtCapacity { .. } => {
                Refusal::Full(e.to_string())
            }
            _ => Refusal::Malformed(e.to_string()),
        })
    }

    fn sweep(&self) -> usize {
        self.sessions
            .sweep_expired(Instant::now())
            .into_parts()
            .0
            .unwrap_or(0)
    }

    fn encode(&self, cells: &[u8]) -> Result<EncodedDatabase, EngineError> {
        let mut db = encode_one(&self.params, &self.shard_config, cells)?;
        let context = self.params.ntt_context();
        for shard in &mut db.shards {
            shard
                .precompute_packing(self.cache.pack_params(), &context)
                .map_err(scheme)?;
        }
        Ok(db)
    }

    fn respond(&self, view: &View, batch: &SeededQueryBatch) -> Result<Vec<Vec<u8>>, Refusal> {
        let queries = batch.queries();
        if !LADDER.contains(&queries.len()) {
            return Err(Refusal::NotALadderStep(queries.len()));
        }
        let mut shards = Vec::with_capacity(queries.len());
        for query in queries {
            let shard = view
                .shards
                .get(query.shard_id as usize)
                .and_then(|s| match &s.db {
                    Encoded::Gadget(db) => Some(db),
                    Encoded::Single(_) => None,
                })
                .ok_or(Refusal::Stale {
                    shard: query.shard_id,
                    shards: view.shards.len(),
                })?;
            shards.push(shard);
        }
        let seat = match batch.packing_key() {
            PackingKeySource::Registered(handle) => {
                let (store, inner) = self
                    .sessions
                    .resolve_renewing(*handle, Instant::now())
                    .map_err(|e| Refusal::Session(e.to_string()))?;
                resolve_packing_seat(
                    &self.crs,
                    &self.cache,
                    &PackingKeySource::Registered(inner),
                    Some(&store),
                )
            }
            inline @ PackingKeySource::Inline(_) => {
                resolve_packing_seat(&self.crs, &self.cache, inline, None)
            }
        }
        .map_err(|e| Refusal::Malformed(e.to_string()))?;
        queries
            .iter()
            .zip(shards)
            .map(|(query, shard)| {
                // Each shard is its own one-shard database.
                let mut local = query.clone();
                local.shard_id = 0;
                let response =
                    respond_seeded_with_seat(&self.crs, shard, &local, &self.cache, &seat)
                        .map_err(|e| Refusal::Malformed(e.to_string()))?;
                let switched =
                    mod_switch_response_checked(&self.params, &response, MOD_SWITCH_TARGET_36BIT)
                        .map_err(|e| Refusal::Malformed(e.to_string()))?;
                bincode::serialize(&switched).map_err(|e| Refusal::Malformed(e.to_string()))
            })
            .collect()
    }
}

/// A key upload, decoded for the set the node serves.
#[derive(Debug)]
pub enum Key {
    /// Set 1.
    Gadget(Box<ClientPackingKeys>),
    /// Set 2, already seated.
    Single(Box<KeySeat>),
}

/// A batch body, decoded for the set the node serves.
#[derive(Debug)]
pub enum Batch {
    /// Set 1.
    Gadget(SeededQueryBatch),
    /// Set 2.
    Single(P16Batch),
}

enum Scheme {
    Gadget(Box<Gadget>),
    Single(Box<Single>),
}

/// The private-read scheme of the one parameter set a node serves.
pub struct Pir {
    set: u16,
    scheme: Scheme,
}

impl std::fmt::Debug for Pir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("Pir");
        d.field("param_set", &self.set);
        match &self.scheme {
            Scheme::Gadget(g) => d.field("scheme", g),
            Scheme::Single(s) => d.field("scheme", s),
        };
        d.finish()
    }
}

fn bincode_decode<T: serde::de::DeserializeOwned>(bytes: &[u8], limit: usize) -> Result<T, String> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_limit(limit as u64)
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| format!("body does not decode: {e}"))
}

impl Pir {
    /// The scheme of parameter set `set`. Set 1 loads its key material from `dir`, creating it
    /// on first start; `seed` fixes the material a new directory gets, for tests that pin
    /// bytes, and a node passes `None`. Set 2's public material is fixed in code, and its
    /// queries are answered by `respond_threads` threads shared by every batch.
    ///
    /// # Errors
    /// [`EngineError`] for a set this node does not serve, or material that cannot be made,
    /// read or written.
    pub fn open(
        dir: &Path,
        set: u16,
        limits: SessionStoreLimits,
        seed: Option<[u8; 32]>,
        respond_threads: usize,
    ) -> Result<Self, EngineError> {
        let scheme = match set {
            PARAM_SET_D2048_CELL256 => Scheme::Gadget(Box::new(Gadget::open(dir, limits, seed)?)),
            PARAM_SET_D2048_CELL256_P16 => {
                Scheme::Single(Box::new(Single::new(limits, respond_threads)?))
            }
            other => {
                return Err(EngineError::Scheme(format!(
                    "parameter set {other} is not one this node serves (1 or 2)"
                )))
            }
        };
        Ok(Self { set, scheme })
    }

    /// The parameter set served.
    #[must_use]
    pub const fn param_set(&self) -> u16 {
        self.set
    }

    /// The key material clients build under: set 1's versioned CRS, set 2's key-mask version.
    #[must_use]
    pub fn crs_bytes(&self) -> &[u8] {
        match &self.scheme {
            Scheme::Gadget(g) => &g.crs_bytes,
            Scheme::Single(s) => s.crs(),
        }
    }

    /// Seconds a session lives after its last use.
    #[must_use]
    pub fn session_ttl(&self) -> Duration {
        match &self.scheme {
            Scheme::Gadget(g) => g.sessions.limits().ttl,
            Scheme::Single(s) => s.limits().ttl,
        }
    }

    /// Sessions resident.
    #[must_use]
    pub fn session_count(&self) -> usize {
        match &self.scheme {
            Scheme::Gadget(g) => g.sessions.len(),
            Scheme::Single(s) => s.sessions(),
        }
    }

    /// The largest key upload an honest client sends.
    #[must_use]
    pub fn key_upload_limit(&self) -> usize {
        match &self.scheme {
            Scheme::Gadget(g) => g.key_upload_limit(),
            Scheme::Single(_) => P16_KEY_BYTES,
        }
    }

    /// Decode a session payload.
    ///
    /// # Errors
    /// A message for a payload that is not a key of the set served.
    pub fn decode_key(&self, payload: &[u8]) -> Result<Key, String> {
        match &self.scheme {
            Scheme::Gadget(g) => {
                bincode_decode(payload, g.key_upload_limit()).map(|k| Key::Gadget(Box::new(k)))
            }
            Scheme::Single(s) => s.seat(payload).map(|k| Key::Single(Box::new(k))),
        }
    }

    /// Decode a batch payload.
    ///
    /// # Errors
    /// A message for a payload that is not a batch of the set served.
    pub fn decode_batch(&self, payload: &[u8], query_limit: usize) -> Result<Batch, String> {
        match &self.scheme {
            Scheme::Gadget(g) => {
                bincode_decode(payload, g.key_upload_limit() + query_limit).map(Batch::Gadget)
            }
            Scheme::Single(_) => P16Batch::decode(payload)
                .map(Batch::Single)
                .map_err(|e| format!("body does not decode: {e}")),
        }
    }

    /// Seat a session's packing key.
    ///
    /// # Errors
    /// [`Refusal::Full`] when every seat is taken, [`Refusal::Malformed`] for a key of
    /// another shape or set.
    pub fn register(&self, key: Key) -> Result<ServerSessionHandle, Refusal> {
        match (&self.scheme, key) {
            (Scheme::Gadget(g), Key::Gadget(keys)) => g.register(*keys),
            (Scheme::Single(s), Key::Single(seat)) => s.register(*seat).map(ServerSessionHandle),
            _ => Err(Refusal::Malformed(
                "a key of another parameter set".to_owned(),
            )),
        }
    }

    /// Drop sessions idle past their lifetime.
    pub fn sweep(&self) -> usize {
        match &self.scheme {
            Scheme::Gadget(g) => g.sweep(),
            Scheme::Single(s) => s.sweep(),
        }
    }

    fn encode(&self, cells: &[u8]) -> Result<Encoded, EngineError> {
        Ok(match &self.scheme {
            Scheme::Gadget(g) => Encoded::Gadget(g.encode(cells)?),
            Scheme::Single(s) => Encoded::Single(Arc::new(s.encode(cells)?)),
        })
    }

    /// Answer every query of `batch` from `view`, in order, each response serialized for
    /// the wire (under set 1 switched to the wire modulus first).
    ///
    /// # Errors
    /// See [`Refusal`]. Nothing is answered when any query is refused.
    pub fn respond(&self, view: &View, batch: &Batch) -> Result<Vec<Vec<u8>>, Refusal> {
        match (&self.scheme, batch) {
            (Scheme::Gadget(g), Batch::Gadget(batch)) => g.respond(view, batch),
            (Scheme::Single(s), Batch::Single(batch)) => {
                let tables: Vec<&Arc<ShardTable>> = view
                    .shards
                    .iter()
                    .map_while(|shard| match &shard.db {
                        Encoded::Single(table) => Some(table),
                        Encoded::Gadget(_) => None,
                    })
                    .collect();
                s.respond(&tables, view.shards.len(), batch)
            }
            _ => Err(Refusal::Malformed(
                "a batch of another parameter set".to_owned(),
            )),
        }
    }
}

fn encode_one(
    params: &InspireParams,
    config: &ShardConfig,
    cells: &[u8],
) -> Result<EncodedDatabase, EngineError> {
    let shards = encode_database(cells, CELL_BYTES, params, config).map_err(scheme)?;
    if shards.len() != 1 {
        return Err(EngineError::Scheme(format!(
            "one shard of cells encoded to {} shards",
            shards.len()
        )));
    }
    Ok(EncodedDatabase {
        shards,
        config: config.clone(),
    })
}

enum Encoded {
    Gadget(EncodedDatabase),
    Single(Arc<ShardTable>),
}

/// One encoded shard and the digest of the cells it was encoded from.
pub struct ShardServe {
    /// SHA-256 of the cells.
    pub digest: [u8; 32],
    db: Encoded,
}

impl std::fmt::Debug for ShardServe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShardServe")
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

/// Everything served, at one leaf count.
#[derive(Debug, Default)]
pub struct View {
    /// The parameter set of the private reads, stated in every answer's header.
    pub param_set: u16,
    /// Leaves in the tree.
    pub leaf_count: u64,
    /// The chain block the table is the state after; zero before any.
    pub block: u64,
    /// The pool's root at `leaf_count`.
    pub root: [u8; 32],
    segments: Vec<Arc<[u8]>>,
    blocks: Vec<Arc<[u8]>>,
    upper: Arc<[Node]>,
    /// The encoded shards, in order.
    pub shards: Vec<Arc<ShardServe>>,
}

impl View {
    /// An answer read from this view.
    #[must_use]
    pub const fn answer(&self, body: Body) -> Answer {
        Answer {
            param_set: self.param_set,
            leaf_count: self.leaf_count,
            block: self.block,
            root: self.root,
            body,
        }
    }

    /// Feed rows from `since` to the next segment boundary or the end; `None` past the end.
    #[must_use]
    pub fn prefixes(&self, since: u64) -> Option<PrefixSegment> {
        if since > self.leaf_count {
            return None;
        }
        let next = ((since / SEGMENT_ROWS + 1) * SEGMENT_ROWS).min(self.leaf_count);
        let segment = self
            .segments
            .get(usize::try_from(since / SEGMENT_ROWS).ok()?);
        let from = usize::try_from(since % SEGMENT_ROWS).ok()? * PREFIX_BYTES;
        let to = from + usize::try_from(next - since).ok()? * PREFIX_BYTES;
        let rows = segment
            .and_then(|rows| rows.get(from..to))
            .unwrap_or_default()
            .to_vec();
        Some(PrefixSegment {
            base: since,
            next,
            rows,
        })
    }

    /// Block `index`'s leaves present at this view; `None` past the newest block.
    #[must_use]
    pub fn block(&self, index: u32) -> Option<LeafBlock> {
        Some(LeafBlock {
            block_index: index,
            leaves: self.blocks.get(index as usize)?.to_vec(),
        })
    }

    /// Full blocks in the tree.
    #[must_use]
    pub fn full_blocks(&self) -> u64 {
        self.leaf_count / BLOCK_LEAVES
    }

    /// Upper nodes from block `since`; `None` past the full blocks.
    #[must_use]
    pub fn upper(&self, since: u64) -> Option<UpperNodes> {
        let full = self.full_blocks();
        if since > full {
            return None;
        }
        let next = full.min(since.saturating_add(MAX_UPPER_NODES));
        let nodes = self
            .upper
            .get(usize::try_from(since).ok()?..usize::try_from(next).ok()?)
            .unwrap_or_default()
            .iter()
            .flatten()
            .copied()
            .collect();
        Some(UpperNodes {
            base: since,
            next,
            nodes,
        })
    }

    /// The leaves at or after leaf `held` of the block holding the newest leaf; `None` when
    /// `held` is past the tree. Empty for an empty tree.
    #[must_use]
    pub fn newest(&self, held: u64) -> Option<LeafBlock> {
        if held > self.leaf_count {
            return None;
        }
        let index = self.leaf_count.saturating_sub(1) / BLOCK_LEAVES;
        let start = index * BLOCK_LEAVES;
        let skip = usize::try_from(held.saturating_sub(start)).ok()? * NODE_BYTES;
        let block = u32::try_from(index).ok()?;
        let leaves = self
            .blocks
            .get(block as usize)
            .and_then(|leaves| leaves.get(skip..))
            .unwrap_or_default()
            .to_vec();
        Some(LeafBlock {
            block_index: block,
            leaves,
        })
    }
}

/// The served view and what replaces it.
pub struct Engine {
    pir: Pir,
    view: ArcSwap<View>,
    encodes: AtomicU64,
    // The lowest leaf a refused refresh was asked to read again: the table changed from
    // there and the served view does not show it yet.
    unpublished: AtomicU64,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("leaf_count", &self.view.load().leaf_count)
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// An engine serving an empty view until the first [`Engine::refresh`].
    #[must_use]
    pub fn new(pir: Pir) -> Self {
        let empty = View {
            param_set: pir.param_set(),
            ..View::default()
        };
        Self {
            pir,
            view: ArcSwap::from_pointee(empty),
            encodes: AtomicU64::new(0),
            unpublished: AtomicU64::new(u64::MAX),
        }
    }

    /// The scheme half.
    #[must_use]
    pub const fn pir(&self) -> &Pir {
        &self.pir
    }

    /// The view now served. Read every part of one answer from one call.
    #[must_use]
    pub fn view(&self) -> Arc<View> {
        self.view.load_full()
    }

    /// Shards encoded since start.
    #[must_use]
    pub fn encodes(&self) -> u64 {
        self.encodes.load(Ordering::Relaxed)
    }

    /// Whether a refresh failed since the last one that succeeded.
    #[must_use]
    pub fn unpublished(&self) -> bool {
        self.unpublished.load(Ordering::Relaxed) != u64::MAX
    }

    /// Publish the table as it now stands. Everything at or after leaf `from`, or after the
    /// lowest `from` of a refresh that failed since the last one that succeeded, is read
    /// again; what lies wholly before it is carried over from the current view.
    ///
    /// # Errors
    /// [`EngineError`] when a shard cannot be read or encoded; the current view stays.
    pub fn refresh(&self, store: &NoteStore, upper: &[Node], from: u64) -> Result<(), EngineError> {
        let from = from.min(self.unpublished.fetch_min(from, Ordering::Relaxed));
        self.rebuild(store, upper, from)?;
        self.unpublished.store(u64::MAX, Ordering::Relaxed);
        Ok(())
    }

    fn rebuild(&self, store: &NoteStore, upper: &[Node], from: u64) -> Result<(), EngineError> {
        let old = self.view.load_full();
        let n = store.leaf_count();
        let from = from.min(old.leaf_count).min(n);
        let resume = store.resume_point();

        let segment_count = n.div_ceil(SEGMENT_ROWS);
        let mut segments: Vec<Arc<[u8]>> = old
            .segments
            .iter()
            .take(usize::try_from((from / SEGMENT_ROWS).min(segment_count)).unwrap_or(0))
            .cloned()
            .collect();
        for index in segments.len() as u64..segment_count {
            let segment = store
                .prefix_segment(index * SEGMENT_ROWS)
                .map_err(|e| EngineError::Scheme(e.to_string()))?;
            segments.push(Arc::from(segment.rows));
        }

        let block_count = n.div_ceil(BLOCK_LEAVES);
        let mut blocks: Vec<Arc<[u8]>> = old
            .blocks
            .iter()
            .take(usize::try_from((from / BLOCK_LEAVES).min(block_count)).unwrap_or(0))
            .cloned()
            .collect();
        for index in blocks.len() as u64..block_count {
            let block = store.leaf_block(u32::try_from(index).unwrap_or(u32::MAX));
            blocks.push(Arc::from(block.leaves));
        }

        let shard_count = store.shard_count() as usize;
        let mut shards: Vec<Arc<ShardServe>> = old
            .shards
            .iter()
            .take(
                usize::try_from(from / ROWS_PER_SHARD as u64)
                    .unwrap_or(0)
                    .min(shard_count),
            )
            .cloned()
            .collect();
        for index in shards.len()..shard_count {
            let shard = store.shard(u32::try_from(index).unwrap_or(u32::MAX))?;
            let reuse = old
                .shards
                .get(index)
                .filter(|served| served.digest == shard.digest)
                .cloned();
            let served = match reuse {
                Some(served) => served,
                None => {
                    self.encodes.fetch_add(1, Ordering::Relaxed);
                    Arc::new(ShardServe {
                        digest: shard.digest,
                        db: self.pir.encode(&shard.cells)?,
                    })
                }
            };
            shards.push(served);
        }

        let full = usize::try_from(n / BLOCK_LEAVES).unwrap_or(usize::MAX);
        let upper = upper.get(..full).ok_or_else(|| {
            EngineError::Scheme(format!(
                "{} upper nodes for {full} full blocks",
                upper.len()
            ))
        })?;
        self.view.store(Arc::new(View {
            param_set: self.pir.param_set(),
            leaf_count: n,
            block: resume.final_block.unwrap_or(0),
            root: resume.root,
            segments,
            blocks,
            upper: Arc::from(upper),
            shards,
        }));
        Ok(())
    }
}

// The wire's widths are the store's.
const _: () = assert!(NODE_BYTES == 32 && PREFIX_BYTES == howl_prefix_feed::PREFIX_BYTES);
const _: () = assert!(CELL_BYTES == howl_record::CELL_BYTES);
const _: () = assert!(ROWS_PER_SHARD as u64 == howl_wire::ROWS_PER_SHARD);
const _: () = assert!(BLOCK_LEAVES == howl_store::LEAF_BLOCK_ROWS as u64);
