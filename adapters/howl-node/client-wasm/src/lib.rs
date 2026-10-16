//! WebAssembly client for a Howl node.
//!
//! - [`decode_answer`] reads any plain answer (feed segment, block, upper nodes, sync, params,
//!   stale) and checks that its parts agree with the leaf count in its header.
//! - [`HowlClient`] holds one freshly drawn secret and the one packing key built under it. It
//!   builds padded batches of private cell reads and opens their answers.
//! - [`HowlTree`] keeps the tree a wallet verified level by level: a sync hashes only what is
//!   new, and a root or a path at any count it covers walks one right edge.
//! - [`merkle_path`], [`tree_root`], [`block_node`] and [`fold_path`] are the same arithmetic over
//!   inputs given whole, and [`fold_path`] checks a path by the circuit's rule.
//!
//! Every byte layout is `howl_wire`'s; this crate adds no wire of its own.

#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use howl_wire::tree::{self, Node, TreeView, TREE_DEPTH};
use howl_wire::{
    Answer, Body, RequestPrefix, CELL_BYTES, LADDER_CAP, NODE_BYTES, PARAM_SET_D2048_CELL256,
    ROWS_PER_SHARD,
};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::ShardConfig;
use raven_inspire::{ClientSession, ClientState, ServerCrs, ServerResponse, ServerSessionHandle};
use wasm_bindgen::prelude::*;

mod lean;

/// Ring dimension of the one parameter set this client speaks.
const RING_DIM: usize = 2048;

/// Largest leaf count of the pool's depth-32 tree.
const MAX_LEAVES: u64 = 1 << TREE_DEPTH;

/// Largest answer this client decodes: a full feed segment plus the newest block and a full
/// upper run, with room to spare.
const MAX_ANSWER_BYTES: usize = 8 << 20;

/// Largest single PIR response this client decodes.
const MAX_RESPONSE_BYTES: usize = 1 << 20;

fn err(message: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&message.to_string())
}

/// A count or position that crossed the JS boundary as a number.
fn whole(value: f64, what: &str, max: u64) -> Result<u64, String> {
    if value.is_finite() && value >= 0.0 && value.fract() == 0.0 && value <= max as f64 {
        // in range and integral, so the cast is exact
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Ok(value as u64)
    } else {
        Err(format!(
            "{what} {value} is not a whole number in [0, {max}]"
        ))
    }
}

fn nodes(bytes: &[u8], what: &str) -> Result<Vec<Node>, String> {
    let (chunks, rest) = bytes.as_chunks::<NODE_BYTES>();
    if !rest.is_empty() {
        return Err(format!(
            "{what}: {} bytes is not a whole number of 32-byte nodes",
            bytes.len()
        ));
    }
    Ok(chunks.to_vec())
}

fn node(bytes: &[u8], what: &str) -> Result<Node, String> {
    <Node>::try_from(bytes).map_err(|_| format!("{what} is {} bytes, not 32", bytes.len()))
}

/// Route a Rust panic to a JS exception with its message. Idempotent.
#[wasm_bindgen(js_name = initPanicHook)]
pub fn init_panic_hook() {
    raven_client::init_panic_hook();
}

/// A decoded plain answer. Fields that the answer's route does not carry read as zero or
/// empty.
#[wasm_bindgen]
#[derive(Debug, Clone, Default)]
pub struct HowlAnswer {
    kind: u8,
    leaf_count: u64,
    block: u64,
    root: Vec<u8>,
    base: u64,
    next: u64,
    rows: Vec<u8>,
    upper_base: u64,
    upper_next: u64,
    upper_nodes: Vec<u8>,
    block_index: u32,
    block_leaves: Vec<u8>,
    ladder_cap: u16,
    session_ttl_secs: u32,
}

// Counts on the wire are below 2^53 (leaf counts at most 2^32, chain blocks far below), so they
// cross as JS numbers.
#[allow(clippy::cast_precision_loss)]
#[wasm_bindgen]
impl HowlAnswer {
    /// Route id: 1 params, 2 prefixes, 3 block, 4 upper, 5 sync, 6 session, 7 notes, 8 stale.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> u8 {
        self.kind
    }
    /// Leaves in the tree every part of this answer was read at.
    #[wasm_bindgen(getter, js_name = leafCount)]
    pub fn leaf_count(&self) -> f64 {
        self.leaf_count as f64
    }
    /// The chain block that tree is the state after.
    #[wasm_bindgen(getter)]
    pub fn block(&self) -> f64 {
        self.block as f64
    }
    /// The pool's root at `leafCount`, 32 bytes big-endian.
    #[wasm_bindgen(getter)]
    pub fn root(&self) -> Vec<u8> {
        self.root.clone()
    }
    /// First feed position carried.
    #[wasm_bindgen(getter)]
    pub fn base(&self) -> f64 {
        self.base as f64
    }
    /// Feed position after the last row carried: the next read's `since`.
    #[wasm_bindgen(getter)]
    pub fn next(&self) -> f64 {
        self.next as f64
    }
    /// Feed rows `[base, next)`, six bytes each.
    #[wasm_bindgen(getter)]
    pub fn rows(&self) -> Vec<u8> {
        self.rows.clone()
    }
    /// First block whose upper node is carried.
    #[wasm_bindgen(getter, js_name = upperBase)]
    pub fn upper_base(&self) -> f64 {
        self.upper_base as f64
    }
    /// Block after the last upper node carried.
    #[wasm_bindgen(getter, js_name = upperNext)]
    pub fn upper_next(&self) -> f64 {
        self.upper_next as f64
    }
    /// Level-10 nodes of full blocks `[upperBase, upperNext)`, 32 bytes each.
    #[wasm_bindgen(getter, js_name = upperNodes)]
    pub fn upper_nodes(&self) -> Vec<u8> {
        self.upper_nodes.clone()
    }
    /// Index of the block carried (a block read, or the newest block of a sync).
    #[wasm_bindgen(getter, js_name = blockIndex)]
    pub fn block_index(&self) -> u32 {
        self.block_index
    }
    /// That block's leaves present at `leafCount`, 32 bytes each.
    #[wasm_bindgen(getter, js_name = blockLeaves)]
    pub fn block_leaves(&self) -> Vec<u8> {
        self.block_leaves.clone()
    }
    /// The largest batch the node takes (params answers).
    #[wasm_bindgen(getter, js_name = ladderCap)]
    pub fn ladder_cap(&self) -> u16 {
        self.ladder_cap
    }
    /// Seconds a session lives after its last use (params and session answers).
    #[wasm_bindgen(getter, js_name = sessionTtlSecs)]
    pub fn session_ttl_secs(&self) -> u32 {
        self.session_ttl_secs
    }
}

/// Leaves of block `index` present at `leaf_count`.
fn leaves_present(index: u32, leaf_count: u64) -> u64 {
    leaf_count
        .saturating_sub(u64::from(index) * tree::BLOCK_LEAVES)
        .min(tree::BLOCK_LEAVES)
}

fn check_block(block: &howl_wire::LeafBlock, leaf_count: u64) -> Result<(), String> {
    let carried = (block.leaves.len() / NODE_BYTES) as u64;
    let present = leaves_present(block.block_index, leaf_count);
    if carried == present {
        Ok(())
    } else {
        Err(format!(
            "block {} carries {carried} leaves where a tree of {leaf_count} holds {present}",
            block.block_index
        ))
    }
}

fn check_segment(segment: &howl_wire::PrefixSegment, leaf_count: u64) -> Result<(), String> {
    if segment.next > leaf_count {
        return Err(format!(
            "feed segment ends at {} past the {leaf_count} rows the answer was read at",
            segment.next
        ));
    }
    Ok(())
}

fn check_upper(upper: &howl_wire::UpperNodes, leaf_count: u64) -> Result<(), String> {
    let full = leaf_count / tree::BLOCK_LEAVES;
    if upper.next > full {
        return Err(format!(
            "upper run ends at block {} past the {full} full blocks of a tree of {leaf_count}",
            upper.next
        ));
    }
    Ok(())
}

/// Decode an answer and check its parts against its own header. Only the parameter set this
/// client speaks is accepted.
pub fn decode_answer_rust(bytes: &[u8]) -> Result<Answer, String> {
    if bytes.len() > MAX_ANSWER_BYTES {
        return Err(format!(
            "answer of {} bytes exceeds the {MAX_ANSWER_BYTES}-byte cap",
            bytes.len()
        ));
    }
    let answer = Answer::decode(bytes).map_err(|e| e.to_string())?;
    if answer.param_set != PARAM_SET_D2048_CELL256 {
        return Err(format!(
            "answer is for parameter set {}, this client speaks {PARAM_SET_D2048_CELL256}",
            answer.param_set
        ));
    }
    if answer.leaf_count > MAX_LEAVES {
        return Err(format!(
            "leaf count {} exceeds the tree's capacity",
            answer.leaf_count
        ));
    }
    let n = answer.leaf_count;
    match &answer.body {
        Body::Prefixes(segment) => check_segment(segment, n)?,
        Body::Block(block) => check_block(block, n)?,
        Body::Upper(upper) => check_upper(upper, n)?,
        Body::Sync {
            prefixes,
            upper,
            newest,
        } => {
            check_segment(prefixes, n)?;
            check_upper(upper, n)?;
            check_block(newest, n)?;
            let expected = u32::try_from(n.saturating_sub(1) / tree::BLOCK_LEAVES)
                .map_err(|e| e.to_string())?;
            if newest.block_index != expected {
                return Err(format!(
                    "sync carries block {} as the newest of a tree of {n}",
                    newest.block_index
                ));
            }
        }
        Body::Params(params) => {
            let shape = (
                params.entry_bytes as usize,
                u64::from(params.rows_per_shard),
            );
            if shape != (CELL_BYTES, ROWS_PER_SHARD) {
                return Err(format!(
                    "node serves {}-byte cells in shards of {} rows; this client reads {CELL_BYTES} in {ROWS_PER_SHARD}",
                    params.entry_bytes, params.rows_per_shard
                ));
            }
            if params.ladder_cap == 0 || usize::from(params.ladder_cap) > LADDER_CAP {
                return Err(format!(
                    "ladder cap {} is outside 1..={LADDER_CAP}",
                    params.ladder_cap
                ));
            }
        }
        Body::Session(_) | Body::Notes(_) | Body::Stale => {}
    }
    Ok(answer)
}

/// Decode any answer of the node.
///
/// # Errors
/// A malformed answer, another wire version or parameter set, or parts that disagree with the
/// header's leaf count.
#[wasm_bindgen(js_name = decodeAnswer)]
pub fn decode_answer(bytes: &[u8]) -> Result<HowlAnswer, JsValue> {
    let answer = decode_answer_rust(bytes).map_err(err)?;
    let mut out = HowlAnswer {
        kind: answer.body.kind() as u8,
        leaf_count: answer.leaf_count,
        block: answer.block,
        root: answer.root.to_vec(),
        ..HowlAnswer::default()
    };
    let segment = |s: howl_wire::PrefixSegment, out: &mut HowlAnswer| {
        out.base = s.base;
        out.next = s.next;
        out.rows = s.rows;
    };
    match answer.body {
        Body::Prefixes(s) => segment(s, &mut out),
        Body::Block(b) => {
            out.block_index = b.block_index;
            out.block_leaves = b.leaves;
        }
        Body::Upper(u) => {
            out.upper_base = u.base;
            out.upper_next = u.next;
            out.upper_nodes = u.nodes;
        }
        Body::Sync {
            prefixes,
            upper,
            newest,
        } => {
            segment(prefixes, &mut out);
            out.upper_base = upper.base;
            out.upper_next = upper.next;
            out.upper_nodes = upper.nodes;
            out.block_index = newest.block_index;
            out.block_leaves = newest.leaves;
        }
        Body::Params(p) => {
            out.ladder_cap = p.ladder_cap;
            out.session_ttl_secs = p.session_ttl_secs;
        }
        Body::Session(s) => out.session_ttl_secs = s.ttl_secs,
        Body::Notes(_) | Body::Stale => {}
    }
    Ok(out)
}

/// A sampler over a fresh OS seed. A failed draw is an error: any fallback would hand clients
/// a shared secret or shared query noise.
fn os_sampler(sigma: f64) -> Result<GaussianSampler, String> {
    let mut seed = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut seed)
        .map_err(|e| format!("OS entropy unavailable: {e}"))?;
    Ok(GaussianSampler::from_seed(sigma, seed))
}

fn check_leaf_count(leaf_count: u64) -> Result<(), String> {
    if leaf_count == 0 || leaf_count > MAX_LEAVES {
        return Err(format!(
            "leaf count {leaf_count} is outside 1..={MAX_LEAVES}"
        ));
    }
    Ok(())
}

fn request(payload: &[u8]) -> Vec<u8> {
    let mut body = RequestPrefix {
        param_set: PARAM_SET_D2048_CELL256,
    }
    .encode()
    .to_vec();
    body.extend_from_slice(payload);
    body
}

/// One private-read client: a secret drawn from OS entropy when it is built, and the one
/// packing key built under it.
///
/// No entry point takes a secret or builds a second key. The key goes up once per session
/// ([`Self::session_body`]) or inside one batch when no handle is installed, and it is the
/// same bytes every time. A new secret means a new client, and so does each request sent
/// without a session.
#[wasm_bindgen]
pub struct HowlClient {
    session: ClientSession,
    crs: ServerCrs,
    ladder_cap: usize,
    session_body: Vec<u8>,
    sent_inline: std::cell::Cell<bool>,
}

impl std::fmt::Debug for HowlClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HowlClient")
            .field("ladder_cap", &self.ladder_cap)
            .field("has_session", &self.session.session_handle().is_some())
            .finish_non_exhaustive()
    }
}

impl HowlClient {
    /// [`Self::new`] for native callers.
    pub fn from_params(params_answer: &[u8]) -> Result<Self, String> {
        let answer = decode_answer_rust(params_answer)?;
        let Body::Params(params) = answer.body else {
            return Err(format!(
                "expected a params answer, got route {}",
                answer.body.kind() as u8
            ));
        };
        let crs = ServerCrs::from_versioned_bytes(&params.crs).map_err(|e| e.to_string())?;
        raven_client::check_parameter_floor(&crs.params)
            .map_err(|e| format!("parameter floor refused the node's key material: {e}"))?;
        if crs.params.ring_dim != RING_DIM
            || crs.inspiring_num_columns != raven_inspire::num_columns(CELL_BYTES)
        {
            return Err(format!(
                "key material is for ring {} and {} columns; this client reads {CELL_BYTES}-byte cells at ring {RING_DIM}",
                crs.params.ring_dim, crs.inspiring_num_columns
            ));
        }
        let session = ClientSession::with_fresh_secret(crs.clone()).map_err(|e| e.to_string())?;
        let keys = session
            .packing_keys()
            .ok_or("the node's key material has no packing columns")?;
        let session_body = request(&bincode::serialize(keys).map_err(|e| e.to_string())?);
        Ok(Self {
            session,
            crs,
            ladder_cap: usize::from(params.ladder_cap),
            session_body,
            sent_inline: std::cell::Cell::new(false),
        })
    }

    /// [`Self::install_session`] for native callers.
    pub fn install_session_rust(&mut self, answer: &[u8]) -> Result<u32, String> {
        if self.session.session_handle().is_some() {
            return Err(
                "this client already holds a session; build a new client for another".into(),
            );
        }
        if self.sent_inline.get() {
            return Err(
                "this client's key already went out inline; build a new client for a session"
                    .into(),
            );
        }
        let answer = decode_answer_rust(answer)?;
        let Body::Session(session) = answer.body else {
            return Err(format!(
                "expected a session answer, got route {}",
                answer.body.kind() as u8
            ));
        };
        self.session
            .install_server_session_handle(ServerSessionHandle(session.handle))
            .map_err(|e| e.to_string())?;
        Ok(session.ttl_secs)
    }

    /// [`Self::build_batch`] for native callers.
    pub fn build_batch_rust(
        &self,
        positions: &[u32],
        leaf_count: u64,
    ) -> Result<HowlBatch, String> {
        let Some(padded) = howl_wire::padded_len(positions.len()) else {
            return Err(format!(
                "a batch takes 1 to {LADDER_CAP} positions, got {}",
                positions.len()
            ));
        };
        check_leaf_count(leaf_count)?;
        if let Some(bad) = positions.iter().find(|p| u64::from(**p) >= leaf_count) {
            return Err(format!(
                "position {bad} is not below the leaf count {leaf_count}"
            ));
        }
        // Real positions take random slots among uniform pads, so slot order carries nothing
        // about the request.
        let mut slots: Vec<usize> = (0..padded).collect();
        for i in (1..padded).rev() {
            slots.swap(i, OsRng.gen_range(0..=i));
        }
        let mut targets: Vec<u32> = (0..padded)
            .map(|_| {
                // below leaf_count, which is at most 2^32
                #[allow(clippy::cast_possible_truncation)]
                let pad = OsRng.gen_range(0..leaf_count) as u32;
                pad
            })
            .collect();
        for (position, slot) in positions.iter().zip(&slots) {
            if let Some(target) = targets.get_mut(*slot) {
                *target = *position;
            }
        }
        slots.truncate(positions.len());
        self.build_batch_at_rust(&targets, &slots, leaf_count)
    }

    /// [`Self::build_batch_at`] for native callers.
    pub fn build_batch_at_rust(
        &self,
        targets: &[u32],
        slots: &[usize],
        leaf_count: u64,
    ) -> Result<HowlBatch, String> {
        if howl_wire::padded_len(targets.len()) != Some(targets.len()) {
            return Err(format!(
                "{} targets is not a ladder step up to {LADDER_CAP}",
                targets.len()
            ));
        }
        if targets.len() > self.ladder_cap {
            return Err(format!(
                "{} targets is above the node's cap of {}",
                targets.len(),
                self.ladder_cap
            ));
        }
        check_leaf_count(leaf_count)?;
        if let Some(bad) = targets.iter().find(|t| u64::from(**t) >= leaf_count) {
            return Err(format!(
                "target {bad} is not below the leaf count {leaf_count}"
            ));
        }
        if slots.is_empty() || slots.len() > targets.len() {
            return Err(format!(
                "{} real slots for {} targets",
                slots.len(),
                targets.len()
            ));
        }
        let mut seen = vec![false; targets.len()];
        let mut positions = Vec::with_capacity(slots.len());
        for slot in slots {
            match (seen.get_mut(*slot), targets.get(*slot)) {
                (Some(taken), Some(target)) if !*taken => {
                    *taken = true;
                    positions.push(*target);
                }
                _ => return Err(format!("slot {slot} is repeated or outside the batch")),
            }
        }
        let inline = self.session.session_handle().is_none();
        if inline && self.sent_inline.get() {
            return Err(
                "this client's key already went out inline; build a new client per request".into(),
            );
        }
        let config = ShardConfig::for_ring_dim(RING_DIM, CELL_BYTES, leaf_count)
            .map_err(|e| e.to_string())?;
        let mut sampler = os_sampler(self.crs.params.sigma)?;
        let queries: Vec<u64> = targets.iter().map(|t| u64::from(*t)).collect();
        let (states, batch) = self
            .session
            .query_batch(&queries, &config, &mut sampler)
            .map_err(|e| e.to_string())?;
        let body = request(&bincode::serialize(&batch).map_err(|e| e.to_string())?);
        if inline {
            self.sent_inline.set(true);
        }
        Ok(HowlBatch {
            states,
            targets: targets.to_vec(),
            slots: slots.to_vec(),
            positions,
            body,
        })
    }

    /// [`Self::open_notes`] for native callers.
    pub fn open_notes_rust(&self, batch: &HowlBatch, answer: &[u8]) -> Result<HowlCells, String> {
        let answer = decode_answer_rust(answer)?;
        let Body::Notes(notes) = &answer.body else {
            return Err(match answer.body {
                Body::Stale => format!(
                    "the node holds {} leaves, behind the rows asked for",
                    answer.leaf_count
                ),
                other => format!("expected a notes answer, got route {}", other.kind() as u8),
            });
        };
        if notes.responses.len() != batch.states.len() {
            return Err(format!(
                "{} responses for a batch of {}",
                notes.responses.len(),
                batch.states.len()
            ));
        }
        if let Some(bad) = batch
            .positions
            .iter()
            .find(|p| u64::from(**p) >= answer.leaf_count)
        {
            return Err(format!(
                "answer was read at {} leaves, which does not hold position {bad}",
                answer.leaf_count
            ));
        }
        let mut cells = Vec::with_capacity(batch.slots.len() * CELL_BYTES);
        for slot in &batch.slots {
            let (Some(bytes), Some(state)) = (notes.responses.get(*slot), batch.states.get(*slot))
            else {
                return Err(format!("slot {slot} is outside the batch"));
            };
            let response = decode_response(bytes)?;
            let cell =
                raven_client::extract_response_rust(&self.crs, state, &response, CELL_BYTES)?;
            if cell.len() != CELL_BYTES {
                return Err(format!("a cell decoded to {} bytes", cell.len()));
            }
            cells.extend_from_slice(&cell);
        }
        Ok(HowlCells {
            cells,
            leaf_count: answer.leaf_count,
            block: answer.block,
            root: answer.root.to_vec(),
        })
    }

    /// The batch's packing key source bytes would carry, for tests that pin key identity.
    #[doc(hidden)]
    pub fn session_body_rust(&self) -> &[u8] {
        &self.session_body
    }
}

fn decode_response(bytes: &[u8]) -> Result<ServerResponse, String> {
    use bincode::Options;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(format!(
            "response of {} bytes exceeds the {MAX_RESPONSE_BYTES}-byte cap",
            bytes.len()
        ));
    }
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| format!("response does not decode: {e}"))
}

#[wasm_bindgen]
impl HowlClient {
    /// A client for the node whose params answer this is. Draws a fresh secret and builds its
    /// packing key.
    ///
    /// # Errors
    /// An answer that is not a params answer, key material outside the parameter floors or for
    /// another cell size, or no OS entropy.
    #[wasm_bindgen(constructor)]
    pub fn new(params_answer: &[u8]) -> Result<HowlClient, JsValue> {
        Self::from_params(params_answer).map_err(err)
    }

    /// The body of `POST /howl/v1/session`: this client's one packing key. The same bytes on
    /// every call, so a retry resends exactly what was sent.
    #[wasm_bindgen(js_name = sessionBody)]
    pub fn session_body(&self) -> Vec<u8> {
        self.session_body.clone()
    }

    /// Install the handle from the session answer; later batches go by handle. Returns the
    /// session lifetime in seconds.
    ///
    /// # Errors
    /// Not a session answer, or a handle already installed.
    #[wasm_bindgen(js_name = installSession)]
    pub fn install_session(&mut self, answer: &[u8]) -> Result<u32, JsValue> {
        self.install_session_rust(answer).map_err(err)
    }

    /// Whether batches go by session handle (otherwise the key rides in each batch).
    #[wasm_bindgen(getter, js_name = hasSession)]
    pub fn has_session(&self) -> bool {
        self.session.session_handle().is_some()
    }

    /// The largest batch the node takes.
    #[wasm_bindgen(getter, js_name = ladderCap)]
    pub fn ladder_cap(&self) -> usize {
        self.ladder_cap
    }

    /// A batch reading the cells at `positions` from a table of `leaf_count` rows, padded to
    /// the next ladder step with uniform positions and shuffled.
    ///
    /// # Errors
    /// No positions, more than the ladder cap, a position at or past `leaf_count`, or no OS
    /// entropy.
    #[wasm_bindgen(js_name = buildBatch)]
    pub fn build_batch(&self, positions: &[u32], leaf_count: f64) -> Result<HowlBatch, JsValue> {
        let leaf_count = whole(leaf_count, "leaf count", MAX_LEAVES).map_err(err)?;
        self.build_batch_rust(positions, leaf_count).map_err(err)
    }

    /// A batch with the targets and slot order of an earlier one (its `targets` and
    /// `realSlots`), under this client's key, for a read sent again after the node dropped
    /// its session.
    ///
    /// # Errors
    /// Targets that are not a ladder step within the node's cap, a target at or past
    /// `leaf_count`, a repeated or outside slot, or no OS entropy.
    #[wasm_bindgen(js_name = buildBatchAt)]
    pub fn build_batch_at(
        &self,
        targets: &[u32],
        real_slots: &[u32],
        leaf_count: f64,
    ) -> Result<HowlBatch, JsValue> {
        let leaf_count = whole(leaf_count, "leaf count", MAX_LEAVES).map_err(err)?;
        let slots: Vec<usize> = real_slots.iter().map(|s| *s as usize).collect();
        self.build_batch_at_rust(targets, &slots, leaf_count)
            .map_err(err)
    }

    /// The cells the batch asked for, in request order, from the node's notes answer.
    ///
    /// # Errors
    /// A stale or malformed answer, a response count other than the batch's, an answer read at
    /// a leaf count that does not hold a requested row, or a response that does not decrypt
    /// to a cell.
    #[wasm_bindgen(js_name = openNotes)]
    pub fn open_notes(&self, batch: &HowlBatch, answer: &[u8]) -> Result<HowlCells, JsValue> {
        self.open_notes_rust(batch, answer).map_err(err)
    }
}

/// A built batch: its request body, and the per-slot state that opens its answer. The state
/// never leaves this module.
#[wasm_bindgen]
pub struct HowlBatch {
    states: Vec<ClientState>,
    /// The row each slot reads, pads included.
    targets: Vec<u32>,
    /// Slot of each requested position, in request order.
    slots: Vec<usize>,
    positions: Vec<u32>,
    body: Vec<u8>,
}

impl std::fmt::Debug for HowlBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HowlBatch")
            .field("slots", &self.states.len())
            .field("real", &self.positions.len())
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl HowlBatch {
    /// The body of `POST /howl/v1/notes`.
    #[wasm_bindgen(getter)]
    pub fn body(&self) -> Vec<u8> {
        self.body.clone()
    }
    /// Queries in the batch, after padding.
    #[wasm_bindgen(getter)]
    pub fn slots(&self) -> usize {
        self.states.len()
    }
    /// The row each slot reads, pads included; with `realSlots`, what `buildBatchAt` takes
    /// to ask for the same rows again.
    #[wasm_bindgen(getter)]
    pub fn targets(&self) -> Vec<u32> {
        self.targets.clone()
    }
    /// Slot of each requested position, in request order.
    #[wasm_bindgen(getter, js_name = realSlots)]
    pub fn real_slots(&self) -> Vec<u32> {
        // slots index a batch of at most the ladder cap
        #[allow(clippy::cast_possible_truncation)]
        self.slots.iter().map(|s| *s as u32).collect()
    }
}

impl HowlBatch {
    /// The body, borrowed.
    pub fn body_rust(&self) -> &[u8] {
        &self.body
    }
    /// Slot of each requested position.
    #[doc(hidden)]
    pub fn slot_order(&self) -> &[usize] {
        &self.slots
    }
}

/// Cells read privately, in request order, with the state they were read at.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct HowlCells {
    cells: Vec<u8>,
    leaf_count: u64,
    block: u64,
    root: Vec<u8>,
}

#[allow(clippy::cast_precision_loss)]
#[wasm_bindgen]
impl HowlCells {
    /// 256 bytes per requested position, in request order.
    #[wasm_bindgen(getter)]
    pub fn cells(&self) -> Vec<u8> {
        self.cells.clone()
    }
    /// Leaves in the table the cells were read from.
    #[wasm_bindgen(getter, js_name = leafCount)]
    pub fn leaf_count(&self) -> f64 {
        self.leaf_count as f64
    }
    /// The chain block that table is the state after.
    #[wasm_bindgen(getter)]
    pub fn block(&self) -> f64 {
        self.block as f64
    }
    /// The pool's root at `leafCount`.
    #[wasm_bindgen(getter)]
    pub fn root(&self) -> Vec<u8> {
        self.root.clone()
    }
}

impl HowlCells {
    /// The cells, borrowed.
    pub fn cells_rust(&self) -> &[u8] {
        &self.cells
    }
}

/// Path of leaf `index` in the tree of the first `n` leaves: 32 siblings from level 0 up, then
/// the root at `n`, 33 × 32 bytes. `upper` holds the level-10 nodes of full blocks from block 0
/// (at least `n / 1024`), `tail` the leaves of the block holding leaf `n - 1`, and
/// `note_block` the leaves of the note's block.
///
/// # Errors
/// `index` not below `n`, inputs that do not cover `n`, or a value that is not a field element.
#[wasm_bindgen(js_name = merklePath)]
pub fn merkle_path(
    index: f64,
    n: f64,
    upper: &[u8],
    tail: &[u8],
    note_block: &[u8],
) -> Result<Vec<u8>, JsValue> {
    merkle_path_rust(index, n, upper, tail, note_block).map_err(err)
}

/// [`merkle_path`] for native callers.
pub fn merkle_path_rust(
    index: f64,
    n: f64,
    upper: &[u8],
    tail: &[u8],
    note_block: &[u8],
) -> Result<Vec<u8>, String> {
    let n = whole(n, "leaf count", MAX_LEAVES)?;
    let index = whole(index, "leaf index", MAX_LEAVES)?;
    let upper = nodes(upper, "upper nodes")?;
    let tail = nodes(tail, "tail leaves")?;
    let note_block = nodes(note_block, "note block leaves")?;
    let view = TreeView {
        n,
        upper: &upper,
        tail: &tail,
    };
    let path = view.path(index, &note_block).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity((TREE_DEPTH + 1) * NODE_BYTES);
    for sibling in &path.siblings {
        out.extend_from_slice(sibling);
    }
    out.extend_from_slice(&path.root);
    Ok(out)
}

/// Root of the first `n` leaves, from the upper nodes and the newest block's leaves; zero for
/// an empty tree.
///
/// # Errors
/// Inputs that do not cover `n`, or a value that is not a field element.
#[wasm_bindgen(js_name = treeRoot)]
pub fn tree_root(n: f64, upper: &[u8], tail: &[u8]) -> Result<Vec<u8>, JsValue> {
    tree_root_rust(n, upper, tail).map_err(err)
}

/// [`tree_root`] for native callers.
pub fn tree_root_rust(n: f64, upper: &[u8], tail: &[u8]) -> Result<Vec<u8>, String> {
    let n = whole(n, "leaf count", MAX_LEAVES)?;
    let upper = nodes(upper, "upper nodes")?;
    let tail = nodes(tail, "tail leaves")?;
    let view = TreeView {
        n,
        upper: &upper,
        tail: &tail,
    };
    Ok(view.root().map_err(|e| e.to_string())?.to_vec())
}

/// The root a path proves for `leaf` at `index`, by the circuit's rule (a zero sibling carries
/// the node up, and is refused where the index makes it a right child).
///
/// # Errors
/// Malformed inputs, a right child at an empty level, or a value that is not a field element.
#[wasm_bindgen(js_name = foldPath)]
pub fn fold_path(leaf: &[u8], index: f64, siblings: &[u8]) -> Result<Vec<u8>, JsValue> {
    fold_path_rust(leaf, index, siblings).map_err(err)
}

/// [`fold_path`] for native callers.
pub fn fold_path_rust(leaf: &[u8], index: f64, siblings: &[u8]) -> Result<Vec<u8>, String> {
    let leaf = node(leaf, "leaf")?;
    let index = whole(index, "leaf index", MAX_LEAVES)?;
    let list = nodes(siblings, "siblings")?;
    let siblings: [Node; TREE_DEPTH] = list
        .try_into()
        .map_err(|v: Vec<Node>| format!("{} siblings, {TREE_DEPTH} needed", v.len()))?;
    Ok(tree::fold(&leaf, index, &siblings)
        .map_err(|e| e.to_string())?
        .to_vec())
}

/// The tree a wallet verified, kept level by level: the level-10 nodes of the full blocks,
/// the newest block's leaves and any full block a path needed. Appending hashes only what is
/// new; a root or a path at any count the held blocks cover walks one right edge.
#[wasm_bindgen]
#[derive(Debug, Clone, Default)]
pub struct HowlTree {
    inner: lean::Tree,
}

#[allow(clippy::cast_precision_loss)]
#[wasm_bindgen]
impl HowlTree {
    /// An empty tree.
    #[wasm_bindgen(constructor)]
    pub fn new() -> HowlTree {
        Self::default()
    }

    /// Full blocks held.
    #[wasm_bindgen(getter, js_name = fullBlocks)]
    pub fn full_blocks(&self) -> f64 {
        self.inner.full_blocks() as f64
    }

    /// Index of the newest block held.
    #[wasm_bindgen(getter, js_name = newestIndex)]
    pub fn newest_index(&self) -> f64 {
        self.inner.newest_index() as f64
    }

    /// The level-10 nodes held, 32 bytes each.
    #[wasm_bindgen(js_name = upperNodes)]
    pub fn upper_nodes(&self) -> Vec<u8> {
        self.inner.upper_nodes().concat()
    }

    /// The newest block's leaves held, 32 bytes each.
    #[wasm_bindgen(js_name = newestLeaves)]
    pub fn newest_leaves(&self) -> Vec<u8> {
        self.inner.newest_leaves().concat()
    }

    /// Append level-10 nodes of the next full blocks.
    ///
    /// # Errors
    /// Ragged bytes or a value that is not a field element.
    #[wasm_bindgen(js_name = appendUpper)]
    pub fn append_upper(&mut self, nodes: &[u8]) -> Result<(), JsValue> {
        let list = self::nodes(nodes, "upper nodes").map_err(err)?;
        self.inner.append_upper(&list).map_err(err)
    }

    /// Hold `leaves` as the leaves of block `index`, the newest block.
    ///
    /// # Errors
    /// Ragged bytes, more than one block, or a value that is not a field element.
    #[wasm_bindgen(js_name = setNewest)]
    pub fn set_newest(&mut self, index: f64, leaves: &[u8]) -> Result<(), JsValue> {
        let index = whole(index, "block index", MAX_LEAVES / tree::BLOCK_LEAVES).map_err(err)?;
        let list = nodes(leaves, "block leaves").map_err(err)?;
        self.inner.set_newest(index, &list).map_err(err)
    }

    /// Hold full block `index` for paths, after checking it hashes to its upper node.
    ///
    /// # Errors
    /// Not a full block, no upper node held for it, or leaves that hash to another node.
    #[wasm_bindgen(js_name = addBlock)]
    pub fn add_block(&mut self, index: f64, leaves: &[u8]) -> Result<(), JsValue> {
        let index = whole(index, "block index", MAX_LEAVES / tree::BLOCK_LEAVES).map_err(err)?;
        let list = nodes(leaves, "block leaves").map_err(err)?;
        self.inner
            .add_block(index, &list)
            .map_err(|e| err(format!("block {index}: {e}")))
    }

    /// Leaf `index`, when its block is held.
    ///
    /// # Errors
    /// A block not held.
    pub fn leaf(&self, index: f64) -> Result<Vec<u8>, JsValue> {
        let index = whole(index, "leaf index", MAX_LEAVES).map_err(err)?;
        self.inner
            .leaf(index)
            .map(|leaf| leaf.to_vec())
            .ok_or_else(|| err(format!("the block of leaf {index} is not held")))
    }

    /// Whether block `index`'s leaves are held.
    #[wasm_bindgen(js_name = holdsBlock)]
    pub fn holds_block(&self, index: f64) -> bool {
        whole(index, "block index", MAX_LEAVES).is_ok_and(|b| self.inner.holds(b))
    }

    /// Drop every leaf from `n` on.
    ///
    /// # Errors
    /// `n` not a whole number in range.
    pub fn truncate(&mut self, n: f64) -> Result<(), JsValue> {
        self.inner
            .truncate(whole(n, "leaf count", MAX_LEAVES).map_err(err)?);
        Ok(())
    }

    /// Root of the first `n` leaves; zero for an empty tree.
    ///
    /// # Errors
    /// A count whose blocks are not held.
    pub fn root(&self, n: f64) -> Result<Vec<u8>, JsValue> {
        let n = whole(n, "leaf count", MAX_LEAVES).map_err(err)?;
        Ok(self.inner.root(n).map_err(err)?.to_vec())
    }

    /// Siblings of leaf `index` from level 0 up, then the root, at count `n` (33 × 32 bytes).
    ///
    /// # Errors
    /// `index` not below `n`, or blocks the path needs that are not held.
    pub fn path(&self, index: f64, n: f64) -> Result<Vec<u8>, JsValue> {
        let n = whole(n, "leaf count", MAX_LEAVES).map_err(err)?;
        let index = whole(index, "leaf index", MAX_LEAVES).map_err(err)?;
        let (siblings, root) = self.inner.path(index, n).map_err(err)?;
        let mut out = siblings.concat();
        out.extend_from_slice(&root);
        Ok(out)
    }
}

/// The level-10 node of a run of at most 1,024 leaves that starts at a block boundary: the
/// subtree root of a full block, the node a wallet holds in its upper list.
///
/// # Errors
/// No leaves, more than one block, or a value that is not a field element.
#[wasm_bindgen(js_name = blockNode)]
pub fn block_node(leaves: &[u8]) -> Result<Vec<u8>, JsValue> {
    block_node_rust(leaves).map_err(err)
}

/// [`block_node`] for native callers.
pub fn block_node_rust(leaves: &[u8]) -> Result<Vec<u8>, String> {
    let leaves = nodes(leaves, "block leaves")?;
    Ok(tree::block_node(&leaves)
        .map_err(|e| e.to_string())?
        .to_vec())
}

/// Wire constants a caller sizes its buffers and batches by.
#[wasm_bindgen(js_name = wireConstants)]
pub fn wire_constants() -> Vec<u32> {
    [
        u32::from(howl_wire::WIRE_VERSION),
        u32::from(PARAM_SET_D2048_CELL256),
        CELL_BYTES as u32,
        howl_wire::PREFIX_BYTES as u32,
        LADDER_CAP as u32,
        tree::BLOCK_LEAVES as u32,
        TREE_DEPTH as u32,
    ]
    .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_refuses_fractions_negatives_and_overflow() {
        assert!(whole(3.0, "x", 10).is_ok());
        for bad in [-1.0, 1.5, 11.0, f64::NAN, f64::INFINITY] {
            assert!(whole(bad, "x", 10).is_err(), "{bad}");
        }
    }

    #[test]
    fn leaves_present_per_block() {
        assert_eq!(leaves_present(0, 0), 0);
        assert_eq!(leaves_present(0, 160), 160);
        assert_eq!(leaves_present(0, 5000), 1024);
        assert_eq!(leaves_present(4, 5000), 904);
        assert_eq!(leaves_present(5, 5000), 0);
    }
}
