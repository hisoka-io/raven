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
    Answer, Body, LeafBlock, PrefixSegment, UpperNodes, CELL_BYTES, LADDER, MAX_UPPER_NODES,
    NODE_BYTES, PARAM_SET_D2048_CELL256, PREFIX_BYTES,
};
use raven_inspire::inspiring::ClientPackingKeys;
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, ShardConfig};
use raven_inspire::pir::mod_switch::{mod_switch_response_checked, MOD_SWITCH_TARGET_36BIT};
use raven_inspire::{
    encode_database, resolve_packing_seat, respond_seeded_with_seat, setup_with_rng,
    EncodedDatabase, PackingKeySource, SeededQueryBatch, ServerCrs, ServerInspiringCache,
    ServerSessionHandle,
};
use raven_inspire_session::{BoundedSessionStore, SessionStoreLimits};

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

/// The scheme's fixed parts: parameters, public key material, packing cache, sessions.
pub struct Pir {
    params: InspireParams,
    crs: ServerCrs,
    crs_bytes: Vec<u8>,
    cache: ServerInspiringCache,
    shard_config: ShardConfig,
    sessions: BoundedSessionStore,
}

impl std::fmt::Debug for Pir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pir")
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

impl Pir {
    /// Load the node's key material from `dir`, creating it on first start. `seed` fixes
    /// the material a new directory gets, for tests that pin bytes; a node passes `None`.
    ///
    /// # Errors
    /// [`EngineError`] when the material cannot be made, read or written.
    pub fn open(
        dir: &Path,
        limits: SessionStoreLimits,
        seed: Option<[u8; 32]>,
    ) -> Result<Self, EngineError> {
        use rand_chacha::rand_core::SeedableRng;
        let params = InspireParams::secure_128_d2048();
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

    /// The versioned key material clients build under.
    #[must_use]
    pub fn crs_bytes(&self) -> &[u8] {
        &self.crs_bytes
    }

    /// Seconds a session lives after its last use.
    #[must_use]
    pub fn session_ttl(&self) -> Duration {
        self.sessions.limits().ttl
    }

    /// Sessions resident.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// The largest key upload an honest client sends.
    #[must_use]
    pub fn key_upload_limit(&self) -> usize {
        2usize
            .saturating_mul(self.params.packing_key_rows())
            .saturating_mul(self.params.ring_dim)
            .saturating_mul(self.params.crt_moduli.len().max(1))
            .saturating_mul(8)
            .saturating_add(4096)
    }

    /// Seat a session's packing key.
    ///
    /// # Errors
    /// [`Refusal::Full`] when every seat is taken, [`Refusal::Malformed`] for a key of
    /// another shape.
    pub fn register(&self, keys: ClientPackingKeys) -> Result<ServerSessionHandle, Refusal> {
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

    /// Drop sessions idle past their lifetime.
    pub fn sweep(&self) -> usize {
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

    /// Answer every query of `batch` from `view`, in order, each response switched to the
    /// wire modulus and serialized.
    ///
    /// # Errors
    /// See [`Refusal`]. Nothing is answered when any query is refused.
    pub fn respond(&self, view: &View, batch: &SeededQueryBatch) -> Result<Vec<Vec<u8>>, Refusal> {
        let queries = batch.queries();
        if !LADDER.contains(&queries.len()) {
            return Err(Refusal::NotALadderStep(queries.len()));
        }
        let mut shards = Vec::with_capacity(queries.len());
        for query in queries {
            let shard = view
                .shards
                .get(query.shard_id as usize)
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
                    respond_seeded_with_seat(&self.crs, &shard.db, &local, &self.cache, &seat)
                        .map_err(|e| Refusal::Malformed(e.to_string()))?;
                let switched =
                    mod_switch_response_checked(&self.params, &response, MOD_SWITCH_TARGET_36BIT)
                        .map_err(|e| Refusal::Malformed(e.to_string()))?;
                bincode::serialize(&switched).map_err(|e| Refusal::Malformed(e.to_string()))
            })
            .collect()
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

/// One encoded shard and the digest of the cells it was encoded from.
pub struct ShardServe {
    /// SHA-256 of the cells.
    pub digest: [u8; 32],
    db: EncodedDatabase,
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
            param_set: PARAM_SET_D2048_CELL256,
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
        Self {
            pir,
            view: ArcSwap::from_pointee(View::default()),
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
