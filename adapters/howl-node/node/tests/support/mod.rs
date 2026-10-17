//! A chain the node can follow in-process, a reference tree, and a wallet that speaks the
//! wire through the router.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use axum::body::Body as HttpBody;
use axum::http::{Request, StatusCode};
use axum::Router;
use howl_indexer::{RawLog, TOPIC_LEAF_INSERTED, TOPIC_NEW_NOTE, TOPIC_NEW_PRIVATE_MEMO};
use howl_node::chain::{BlockLog, Chain, ChainError, Header};
use howl_wire::{Answer, Body, RequestPrefix, PARAM_SET_D2048_CELL256};
use http_body_util::BodyExt;
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::ShardConfig;
use raven_inspire::pir::mod_switch::extract_inspiring_mod_switched;
use raven_inspire::{ClientSession, ServerCrs, ServerResponse, ServerSessionHandle};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use crate::chain::{Fixture, Rng};

pub fn scalar(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

pub fn bytes(value: Fr) -> [u8; 32] {
    let be = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// A port of the wallet's `LeanIMT`: every level kept, a lone node carried, a zero
/// sibling meaning absent. Written apart from the node's tree code to check it.
#[derive(Default, Clone)]
pub struct LeanTree {
    levels: Vec<Vec<Fr>>,
}

impl LeanTree {
    pub fn len(&self) -> u64 {
        self.levels.first().map_or(0, |l| l.len() as u64)
    }

    pub fn insert(&mut self, leaf: Fr) -> [u8; 32] {
        if self.levels.is_empty() {
            self.levels = vec![Vec::new(); 32];
        }
        let index = self.levels[0].len();
        self.levels[0].push(leaf);
        let mut node = leaf;
        let mut at = index;
        for level in 0..32 {
            let sibling = at ^ 1;
            let sibling = self.levels[level].get(sibling).copied();
            node = match (at & 1, sibling) {
                (0, None) => node,
                (0, Some(right)) => howl_poseidon2::hash(&[node, right, Fr::from(level as u64)]),
                (_, Some(left)) => howl_poseidon2::hash(&[left, node, Fr::from(level as u64)]),
                (_, None) => unreachable!("a right child has a left sibling"),
            };
            at /= 2;
            if level < 31 {
                if at < self.levels[level + 1].len() {
                    self.levels[level + 1][at] = node;
                } else {
                    self.levels[level + 1].push(node);
                }
            }
        }
        bytes(node)
    }
}

/// The root of the first `n` of `leaves`, folded pairwise from scratch.
pub fn root_of(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut nodes: Vec<Fr> = leaves.iter().map(scalar).collect();
    let mut level = 0u64;
    while nodes.len() > 1 {
        nodes = nodes
            .chunks(2)
            .map(|pair| match pair {
                [left, right] => howl_poseidon2::hash(&[*left, *right, Fr::from(level)]),
                _ => pair[0],
            })
            .collect();
        level += 1;
    }
    bytes(nodes[0])
}

struct Inner {
    pool: [u8; 20],
    logs: Vec<RawLog>,
    head: u64,
    /// `(first block, fork id)`: blocks from the first one on belong to that fork.
    forks: Vec<(u64, u32)>,
    first: u64,
    /// A fork applied at the next head read: `(first block, logs, new head)`.
    on_head: Option<(u64, Vec<RawLog>, u64)>,
    /// Hashes a stale backend keeps answering.
    frozen: HashMap<u64, [u8; 32]>,
    /// The next logs read answers from another fork from this block on: `(first block, logs)`.
    logs_from_fork: Option<(u64, Vec<RawLog>)>,
    /// The next header read of a block answers from that fork: `(block, first block)`.
    header_from_fork: Option<(u64, u64)>,
    /// A fork applied when a block's header is next read: `(block, first block, logs)`.
    on_header: Option<(u64, u64, Vec<RawLog>)>,
}

impl Inner {
    fn fork_of(&self, block: u64) -> u32 {
        self.forks
            .iter()
            .rev()
            .find(|(from, _)| *from <= block)
            .map_or(0, |(_, id)| *id)
    }
}

/// An in-process chain: blocks up to a movable head, each with a hash that changes when
/// the block is replaced by a fork.
#[derive(Clone)]
pub struct FakeChain(Arc<Mutex<Inner>>);

impl FakeChain {
    pub fn new(pool: [u8; 20], first: u64, logs: Vec<RawLog>, head: u64) -> Self {
        Self(Arc::new(Mutex::new(Inner {
            pool,
            logs,
            head,
            forks: vec![(0, 0)],
            first,
            on_head: None,
            frozen: HashMap::new(),
            logs_from_fork: None,
            header_from_fork: None,
            on_header: None,
        })))
    }

    pub fn set_head(&self, head: u64) {
        self.0.lock().expect("lock").head = head;
    }

    pub fn head_now(&self) -> u64 {
        self.0.lock().expect("lock").head
    }

    pub fn tip(&self) -> u64 {
        let inner = self.0.lock().expect("lock");
        inner
            .logs
            .iter()
            .map(|l| l.block_number)
            .max()
            .unwrap_or(inner.first)
    }

    /// Replace every block from `from` on with `logs`, under a new fork id.
    pub fn fork(&self, from: u64, logs: Vec<RawLog>) {
        let mut inner = self.0.lock().expect("lock");
        inner.logs.retain(|log| log.block_number < from);
        inner.logs.extend(logs);
        let id = inner.forks.len() as u32;
        inner.forks.push((from, id));
    }

    /// Fork as [`Self::fork`] and move the head, at the next head read: inside a step, after
    /// its first check of the newest mark.
    pub fn fork_on_next_head(&self, from: u64, logs: Vec<RawLog>, head: u64) {
        self.0.lock().expect("lock").on_head = Some((from, logs, head));
    }

    /// Keep answering block `number`'s current hash, whatever the chain does.
    pub fn freeze_hash(&self, number: u64) {
        let mut inner = self.0.lock().expect("lock");
        let hash = Self::hash(&inner, number);
        inner.frozen.insert(number, hash);
    }

    /// Answer the next logs read from a fork that replaces every block from `from` with
    /// `logs`, and every other read from the chain as it is: a chain that reorganised and
    /// reorganised back while one step read it.
    pub fn fork_for_next_logs(&self, from: u64, logs: Vec<RawLog>) {
        self.0.lock().expect("lock").logs_from_fork = Some((from, logs));
    }

    /// Answer the next header read of block `number` from the fork of
    /// [`Self::fork_for_next_logs`] that starts at `from`.
    pub fn fork_for_next_header(&self, number: u64, from: u64) {
        self.0.lock().expect("lock").header_from_fork = Some((number, from));
    }

    /// Fork as [`Self::fork`] when block `number`'s header is next read: inside a step, after
    /// its logs read.
    pub fn fork_on_header_of(&self, number: u64, from: u64, logs: Vec<RawLog>) {
        self.0.lock().expect("lock").on_header = Some((number, from, logs));
    }

    pub fn thaw(&self) {
        self.0.lock().expect("lock").frozen.clear();
    }

    pub fn logs_now(&self) -> Vec<RawLog> {
        self.0.lock().expect("lock").logs.clone()
    }

    fn hash(inner: &Inner, block: u64) -> [u8; 32] {
        Self::hash_on(inner.fork_of(block), block)
    }

    fn hash_on(fork: u32, block: u64) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(fork.to_be_bytes());
        h.update(block.to_be_bytes());
        h.finalize().into()
    }

    /// Block `number`'s hash as this backend answers it.
    fn answered(inner: &Inner, number: u64) -> [u8; 32] {
        inner
            .frozen
            .get(&number)
            .copied()
            .unwrap_or_else(|| Self::hash(inner, number))
    }
}

impl Chain for FakeChain {
    async fn head(&self) -> Result<u64, ChainError> {
        let pending = self.0.lock().expect("lock").on_head.take();
        if let Some((from, logs, head)) = pending {
            self.fork(from, logs);
            self.set_head(head);
        }
        Ok(self.0.lock().expect("lock").head)
    }

    async fn header(&self, number: u64) -> Result<Option<Header>, ChainError> {
        let armed = {
            let mut inner = self.0.lock().expect("lock");
            match inner.on_header.take() {
                Some((block, from, logs)) if block == number => Some((from, logs)),
                other => {
                    inner.on_header = other;
                    None
                }
            }
        };
        if let Some((from, logs)) = armed {
            self.fork(from, logs);
        }
        let mut inner = self.0.lock().expect("lock");
        if number > inner.head && !inner.frozen.contains_key(&number) {
            return Ok(None);
        }
        let cut = match inner.header_from_fork {
            Some((block, from)) if block == number => {
                inner.header_from_fork = None;
                from
            }
            _ => u64::MAX,
        };
        let other = inner.forks.len() as u32 + 1_000;
        let at = |block: u64| {
            if block >= cut {
                Self::hash_on(other, block)
            } else {
                Self::answered(&inner, block)
            }
        };
        Ok(Some(Header {
            hash: at(number),
            parent: at(number.wrapping_sub(1)),
        }))
    }

    async fn logs(&self, from: u64, to: u64) -> Result<Vec<BlockLog>, ChainError> {
        let mut inner = self.0.lock().expect("lock");
        let to = to.min(inner.head);
        let fork = inner.logs_from_fork.take();
        let other = inner.forks.len() as u32 + 1_000;
        let (cut, extra) = fork.unwrap_or((u64::MAX, Vec::new()));
        let place = |log: &RawLog| BlockLog {
            log: log.clone(),
            block_hash: if log.block_number >= cut {
                Self::hash_on(other, log.block_number)
            } else {
                Self::answered(&inner, log.block_number)
            },
        };
        Ok(inner
            .logs
            .iter()
            .filter(|log| log.block_number < cut)
            .chain(&extra)
            .filter(|log| (from..=to).contains(&log.block_number))
            .map(place)
            .collect())
    }

    async fn leaf_count(&self, block: [u8; 32]) -> Result<Option<u64>, ChainError> {
        let inner = self.0.lock().expect("lock");
        // A block this chain no longer has is unknown to it, as to an endpoint that keeps
        // no other fork.
        let top = inner
            .head
            .max(inner.frozen.keys().copied().max().unwrap_or(0));
        let Some(number) = (0..=top).find(|n| Self::answered(&inner, *n) == block) else {
            return Err(ChainError::Rpc {
                method: "eth_call",
                message: "unknown block".to_owned(),
            });
        };
        Ok(Some(
            inner
                .logs
                .iter()
                .filter(|log| {
                    log.address == inner.pool
                        && log.block_number <= number
                        && log.topics.first() == Some(&TOPIC_LEAF_INSERTED)
                })
                .count() as u64,
        ))
    }
}

fn random_scalar(rng: &mut Rng) -> [u8; 32] {
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        chunk.copy_from_slice(&rng.next().to_be_bytes());
    }
    out[0] &= 0x1f;
    out[31] |= 1;
    out
}

fn word(n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&n.to_be_bytes());
    out
}

/// Notes appended to a chain, with the leaves they insert.
pub struct Extension {
    pub logs: Vec<RawLog>,
    pub leaves: Vec<[u8; 32]>,
    pub last_block: u64,
}

/// `blocks` blocks of `per_block` notes each, from `first_block`, continuing `tree`.
/// Every other note is an incoming one.
pub fn extend(
    pool: [u8; 20],
    tree: &mut LeanTree,
    first_block: u64,
    blocks: u64,
    per_block: u64,
    seed: u64,
) -> Extension {
    let mut rng = Rng(seed);
    let mut logs = Vec::new();
    let mut leaves = Vec::new();
    for block in first_block..first_block + blocks {
        for k in 0..per_block {
            let index = tree.len();
            let commitment = random_scalar(&mut rng);
            let root = tree.insert(scalar(&commitment));
            leaves.push(commitment);
            let mut inserted = commitment.to_vec();
            inserted.extend_from_slice(&root);
            logs.push(RawLog {
                block_number: block,
                log_index: 2 * k,
                address: pool,
                topics: vec![TOPIC_LEAF_INSERTED, word(index)],
                data: inserted,
            });
            let tag = random_scalar(&mut rng);
            let mut data = Vec::new();
            let topics = if index.is_multiple_of(2) {
                data.extend_from_slice(&tag);
                vec![TOPIC_NEW_NOTE, word(index), commitment]
            } else {
                data.extend_from_slice(&random_scalar(&mut rng));
                data.extend_from_slice(&random_scalar(&mut rng));
                vec![TOPIC_NEW_PRIVATE_MEMO, word(index), commitment, tag]
            };
            for _ in 0..7 {
                data.extend_from_slice(&random_scalar(&mut rng));
            }
            logs.push(RawLog {
                block_number: block,
                log_index: 2 * k + 1,
                address: pool,
                topics,
                data,
            });
        }
    }
    Extension {
        logs,
        leaves,
        last_block: first_block + blocks - 1,
    }
}

/// The fixture's leaves in a reference tree.
pub fn fixture_tree(fixture: &Fixture) -> (LeanTree, Vec<[u8; 32]>) {
    let mut tree = LeanTree::default();
    let leaves: Vec<[u8; 32]> = fixture.leaves.iter().map(|l| l.commitment).collect();
    for leaf in &leaves {
        tree.insert(scalar(leaf));
    }
    (tree, leaves)
}

/// The router, called in-process.
pub struct Http(pub Router);

impl Http {
    pub async fn send(&self, request: Request<HttpBody>) -> (StatusCode, Vec<u8>) {
        let response = self.0.clone().oneshot(request).await.expect("infallible");
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes()
            .to_vec();
        (status, body)
    }

    pub async fn get(&self, path: &str) -> (StatusCode, Vec<u8>) {
        self.send(Request::get(path).body(HttpBody::empty()).expect("request"))
            .await
    }

    pub async fn post(&self, path: &str, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
        self.send(
            Request::post(path)
                .body(HttpBody::from(body))
                .expect("request"),
        )
        .await
    }

    pub async fn answer(&self, path: &str) -> Answer {
        let (status, body) = self.get(path).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{path}: {}",
            String::from_utf8_lossy(&body)
        );
        Answer::decode(&body).expect("answer decodes")
    }
}

pub fn request(payload: &[u8]) -> Vec<u8> {
    let mut body = RequestPrefix {
        param_set: PARAM_SET_D2048_CELL256,
    }
    .encode()
    .to_vec();
    body.extend_from_slice(payload);
    body
}

/// A wallet's private-read half: its own secret, a session when it registered one.
pub struct Reader {
    pub session: ClientSession,
    pub crs: ServerCrs,
    pub sampler: GaussianSampler,
    pub rng: Rng,
}

impl Reader {
    pub async fn new(http: &Http, seed: u64) -> Self {
        let answer = http.answer("/howl/v1/params").await;
        let Body::Params(params) = answer.body else {
            panic!("params body");
        };
        let crs = ServerCrs::from_versioned_bytes(&params.crs).expect("crs");
        let sampler = GaussianSampler::with_seed(crs.params.sigma, seed);
        let session = ClientSession::with_fresh_secret(crs.clone()).expect("session");
        Self {
            session,
            crs,
            sampler,
            rng: Rng(seed ^ 0x5eed),
        }
    }

    pub fn key_upload(&self) -> Vec<u8> {
        request(
            &bincode::serialize(self.session.packing_keys().expect("keys")).expect("keys encode"),
        )
    }

    pub async fn register(&mut self, http: &Http) -> u64 {
        let (status, body) = http.post("/howl/v1/session", self.key_upload()).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let Body::Session(session) = Answer::decode(&body).expect("answer").body else {
            panic!("session body");
        };
        self.session
            .install_server_session_handle(ServerSessionHandle(session.handle))
            .expect("handle");
        session.handle
    }

    /// The padded batch for `positions` in a table of `leaf_count` rows, and its body.
    pub fn batch(
        &mut self,
        positions: &[u64],
        leaf_count: u64,
    ) -> (Vec<raven_inspire::ClientState>, Vec<u8>) {
        let padded = howl_wire::padded_len(positions.len()).expect("ladder");
        let mut targets = positions.to_vec();
        while targets.len() < padded {
            targets.push(self.rng.below(leaf_count));
        }
        let config = ShardConfig::for_ring_dim(2048, 256, leaf_count).expect("config");
        let (states, batch) = self
            .session
            .query_batch_fresh(&targets, &config)
            .expect("batch");
        (
            states,
            request(&bincode::serialize(&batch).expect("batch encodes")),
        )
    }

    /// Cells at `positions`, read privately; the answer's leaf count with them.
    pub async fn fetch(
        &mut self,
        http: &Http,
        positions: &[u64],
        leaf_count: u64,
    ) -> (Answer, Vec<Vec<u8>>) {
        let (states, body) = self.batch(positions, leaf_count);
        let (status, bytes) = http.post("/howl/v1/notes", body).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
        let answer = Answer::decode(&bytes).expect("answer");
        let Body::Notes(notes) = &answer.body else {
            panic!("notes body");
        };
        assert_eq!(notes.responses.len(), states.len());
        let cells = notes
            .responses
            .iter()
            .zip(&states)
            .take(positions.len())
            .map(|(bytes, state)| {
                let response: ServerResponse = bincode::deserialize(bytes).expect("response");
                extract_inspiring_mod_switched(&self.crs, state, &response, 256).expect("extract")
            })
            .collect();
        (answer, cells)
    }
}
