//! The client against a node driven in-process: private reads by handle and inline, slot
//! order, key identity, sizes, refusals, paths at chosen counts, and the answer files the
//! package's offline tests read.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

#[path = "../../../howl/indexer/tests/support/mod.rs"]
mod chain;
#[path = "../../node/tests/support/mod.rs"]
mod support;
#[path = "../../../howl/indexer/tests/support/wallet.rs"]
mod wallet;

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use chain::Fixture;
use howl_client_wasm::{
    decode_answer_rust, fold_path_rust, merkle_path_rust, tree_root_rust, HowlBatch, HowlClient,
};
use howl_indexer::{RawLog, TOPIC_LEAF_INSERTED};
use howl_node::engine::Engine;
use howl_node::follow::{Follower, Step};
use howl_node::http::{router, Served};
use howl_node::NodeConfig;
use howl_prefix_feed::{PrefixIndex, Segment};
use howl_wire::tree::BLOCK_LEAVES;
use howl_wire::{Answer, Body, Notes, LADDER};
use raven_inspire::{PackingKeySource, SeededQueryBatch};
use raven_inspire_session::SessionStoreLimits;
use sha2::{Digest, Sha256};
use support::{extend, fixture_tree, FakeChain, Http};

struct TestNode {
    follower: Follower<FakeChain>,
    engine: Arc<Engine>,
    http: Http,
}

impl TestNode {
    fn start(dir: &std::path::Path, fixture: &Fixture, chain: FakeChain) -> Self {
        let config = NodeConfig {
            data_dir: dir.to_path_buf(),
            chain_id: fixture.chain_id,
            pool: fixture.pool,
            deployment_block: fixture.first_block,
            max_range: 40,
            sessions: SessionStoreLimits {
                max_sessions: 64,
                ttl: Duration::from_secs(3_600),
            },
            seed: Some([7; 32]),
        };
        let (follower, engine) = howl_node::open(&config, chain).expect("open");
        let http = Http(router(Served::new(Arc::clone(&engine), 4)));
        Self {
            follower,
            engine,
            http,
        }
    }

    async fn catch_up(&mut self) {
        for _ in 0..5_000 {
            let step = self.follower.step().await.expect("step");
            howl_node::publish(&self.follower, &self.engine, &step).expect("publish");
            if matches!(step, Step::Idle { .. }) {
                return;
            }
        }
        panic!("the follower never settled");
    }

    async fn raw(&self, path: &str) -> Vec<u8> {
        let (status, body) = self.http.get(path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        body
    }
}

async fn fixture_node(dir: &std::path::Path) -> (Fixture, TestNode) {
    let fixture = Fixture::load();
    let chain = FakeChain::new(
        fixture.pool,
        fixture.first_block,
        fixture.logs.clone(),
        fixture.head,
    );
    let mut node = TestNode::start(dir, &fixture, chain);
    node.catch_up().await;
    (fixture, node)
}

async fn client(node: &TestNode) -> HowlClient {
    HowlClient::from_params(&node.raw("/howl/v1/params").await).expect("client")
}

async fn register(node: &TestNode, client: &mut HowlClient) {
    let (status, body) = node
        .http
        .post("/howl/v1/session", client.session_body_rust().to_vec())
        .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    client.install_session_rust(&body).expect("install");
}

/// Cells at `positions`, read in batches of at most 16 through `client`, or without one through
/// a new client per batch with the key inline.
async fn read(
    node: &TestNode,
    client: Option<&HowlClient>,
    positions: &[u32],
    n: u64,
) -> Vec<Vec<u8>> {
    let mut cells = Vec::new();
    for chunk in positions.chunks(16) {
        let fresh;
        let client = match client {
            Some(client) => client,
            None => {
                fresh = self::client(node).await;
                &fresh
            }
        };
        let batch = client.build_batch_rust(chunk, n).expect("batch");
        let (status, body) = node
            .http
            .post("/howl/v1/notes", batch.body_rust().to_vec())
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let opened = client.open_notes_rust(&batch, &body).expect("open");
        cells.extend(opened.cells_rust().chunks(256).map(<[u8]>::to_vec));
    }
    cells
}

/// Each fixture wallet's positions, found the way a wallet finds them: its tags from its
/// view key, matched against the served feed.
fn wallet_positions(fixture: &Fixture, feed: &Answer) -> Vec<Vec<u32>> {
    let Body::Prefixes(segment) = &feed.body else {
        panic!("feed");
    };
    let mut index = PrefixIndex::new();
    index
        .absorb(&Segment {
            base: segment.base,
            next: segment.next,
            rows: &segment.rows,
        })
        .expect("absorb");
    fixture
        .wallets
        .iter()
        .map(|w| {
            let tags = wallet::candidate_tags(
                &w.sk_view,
                w.self_keys.len() as u64,
                w.incoming_keys.len() as u64,
            );
            let found: BTreeSet<u32> = index
                .matches(&tags, 0)
                .iter()
                .map(|m| u32::try_from(m.position).expect("u32"))
                .collect();
            found.into_iter().collect()
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn wallets_read_their_cells_by_handle_and_inline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, node) = fixture_node(dir.path()).await;
    let feed = Answer::decode(&node.raw("/howl/v1/prefixes?since=0").await).expect("feed");
    let n = feed.leaf_count;
    let positions = wallet_positions(&fixture, &feed);
    let mut total = 0;
    for (wallet, owned) in fixture.wallets.iter().zip(&positions) {
        let mut expected = wallet.owned_leaves.clone();
        expected.sort_unstable();
        assert_eq!(
            *owned, expected,
            "{}: feed scan finds its notes",
            wallet.label
        );
        let want: Vec<Vec<u8>> = owned
            .iter()
            .map(|p| {
                fixture.leaves[*p as usize]
                    .cell
                    .clone()
                    .expect("a note leaf has a cell")
            })
            .collect();

        let mut by_handle = client(&node).await;
        register(&node, &mut by_handle).await;
        assert!(by_handle.has_session());
        assert_eq!(
            read(&node, Some(&by_handle), owned, n).await,
            want,
            "by handle"
        );
        assert_eq!(read(&node, None, owned, n).await, want, "inline");
        total += owned.len();
    }
    assert!(total >= 30, "the fixture's wallets own {total} notes");
}

#[tokio::test(flavor = "multi_thread")]
async fn every_ladder_step_reads_every_slot_count() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, node) = fixture_node(dir.path()).await;
    let n = fixture.leaf_count;
    let mut reader = client(&node).await;
    register(&node, &mut reader).await;
    for real in 1..=16u32 {
        // the newest rows and the first note: both ends of the table
        let positions: Vec<u32> = (0..real)
            .map(|i| if i == 0 { 1 } else { 160 - i })
            .collect();
        let cells = read(&node, Some(&reader), &positions, n).await;
        for (p, cell) in positions.iter().zip(&cells) {
            assert_eq!(
                Some(cell),
                fixture.leaves[*p as usize].cell.as_ref(),
                "{real}: {p}"
            );
        }
    }
}

fn batch_of(body: &[u8]) -> SeededQueryBatch {
    bincode::deserialize(&body[4..]).expect("batch decodes")
}

#[tokio::test(flavor = "multi_thread")]
async fn real_positions_sit_in_random_slots_among_pads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_fixture, node) = fixture_node(dir.path()).await;
    let mut reader = client(&node).await;
    register(&node, &mut reader).await;
    let trials = 480;
    let mut hits = [0u32; 16];
    let mut shards = HashMap::new();
    for _ in 0..trials {
        let batch = reader.build_batch_rust(&[42], 5_000).expect("batch");
        assert_eq!(batch.slot_order().len(), 1);
        hits[batch.slot_order()[0]] += 1;
        let decoded = batch_of(batch.body_rust());
        assert_eq!(decoded.queries().len(), 1);
        let batch = reader
            .build_batch_rust(&[42, 43, 44, 45, 46, 47, 48, 49, 50], 5_000)
            .expect("batch");
        let decoded = batch_of(batch.body_rust());
        assert_eq!(decoded.queries().len(), 16);
        for query in decoded.queries() {
            assert!(query.shard_id <= 2, "pads stay inside the table");
            *shards.entry(query.shard_id).or_insert(0u32) += 1;
        }
    }
    // pads are drawn over the whole table
    assert_eq!(hits[0], trials);
    assert_eq!(shards.len(), 3, "{shards:?}");

    // One real position among 16: every slot must carry it at times, and none most of them.
    let mut slots = [0u32; 16];
    for _ in 0..trials {
        let batch = reader
            .build_batch_rust(&[7, 8, 9, 10, 11, 12, 13, 14, 15], 160)
            .expect("batch");
        slots[batch.slot_order()[0]] += 1;
    }
    let expected = trials / 16;
    for (slot, count) in slots.iter().enumerate() {
        assert!(
            *count > expected / 3 && *count < expected * 3,
            "slot {slot}: {count} of {trials}: {slots:?}"
        );
    }
}

fn inline_key(body: &[u8]) -> Vec<u8> {
    match batch_of(body).packing_key() {
        PackingKeySource::Inline(keys) => bincode::serialize(keys).expect("keys"),
        PackingKeySource::Registered(_) => panic!("expected the key inline"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn one_client_holds_one_secret_and_one_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_fixture, node) = fixture_node(dir.path()).await;
    let mut a = client(&node).await;
    let b = client(&node).await;
    let key = a.session_body_rust().to_vec();
    assert_eq!(key, a.session_body_rust(), "a retry resends the same bytes");
    assert_ne!(
        key,
        b.session_body_rust(),
        "a new client draws a new secret"
    );
    // An inline batch carries exactly the key the session would upload, and a client sends
    // it inline once, with no second request and no session after it.
    let mut c = client(&node).await;
    let c_key = c.session_body_rust().to_vec();
    let batch = c.build_batch_rust(&[1, 2, 3], 160).expect("batch");
    assert_eq!(inline_key(batch.body_rust()), c_key[4..]);
    assert!(
        c.build_batch_rust(&[1], 160).is_err(),
        "a second inline batch"
    );
    let (_, session) = node.http.post("/howl/v1/session", c_key.clone()).await;
    assert!(
        c.install_session_rust(&session).is_err(),
        "a session after an inline batch"
    );
    register(&node, &mut a).await;
    let batch = a.build_batch_rust(&[1], 160).expect("batch");
    assert!(matches!(
        batch_of(batch.body_rust()).packing_key(),
        PackingKeySource::Registered(_)
    ));
    let (_, session) = node.http.post("/howl/v1/session", key.clone()).await;
    assert!(
        a.install_session_rust(&session).is_err(),
        "a client takes one session"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_batch_sent_again_asks_for_the_same_rows_in_the_same_slots() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, node) = fixture_node(dir.path()).await;
    let mut first = client(&node).await;
    register(&node, &mut first).await;
    let positions = [9u32, 120, 33];
    let batch = first.build_batch_rust(&positions, 160).expect("batch");
    let targets = batch.targets();
    let slots: Vec<usize> = batch.real_slots().iter().map(|s| *s as usize).collect();
    assert_eq!(targets.len(), 4);
    let shards = |b: &HowlBatch| -> Vec<_> {
        batch_of(b.body_rust())
            .queries()
            .iter()
            .map(|q| q.shard_id)
            .collect()
    };

    // a new session, as after the node dropped the first one
    let mut second = client(&node).await;
    register(&node, &mut second).await;
    let again = second
        .build_batch_at_rust(&targets, &slots, 160)
        .expect("same plan");
    assert_eq!(again.targets(), targets);
    assert_eq!(again.real_slots(), batch.real_slots());
    assert_eq!(shards(&again), shards(&batch));
    let (status, body) = node
        .http
        .post("/howl/v1/notes", again.body_rust().to_vec())
        .await;
    assert_eq!(status, StatusCode::OK);
    let cells = second.open_notes_rust(&again, &body).expect("open");
    for (p, cell) in positions.iter().zip(cells.cells_rust().chunks(256)) {
        assert_eq!(Some(cell.to_vec()), fixture.leaves[*p as usize].cell, "{p}");
    }
    // control: a fresh build draws its own pads and order
    let differs = (0..32).any(|_| {
        let fresh = second.build_batch_rust(&positions, 160).expect("batch");
        fresh.targets() != targets || fresh.real_slots() != batch.real_slots()
    });
    assert!(differs, "fresh batches never moved");

    for (bad_targets, bad_slots, why) in [
        (&targets[..3], &slots[..], "not a ladder step"),
        (&targets[..], &[0, 0, 1][..], "repeated slot"),
        (&targets[..], &[0, 1, 4][..], "slot outside"),
        (&targets[..], &[][..], "no real slot"),
    ] {
        assert!(
            second
                .build_batch_at_rust(bad_targets, bad_slots, 160)
                .is_err(),
            "{why}"
        );
    }
    assert!(
        second.build_batch_at_rust(&targets, &slots, 100).is_err(),
        "a target past the table"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sizes_on_the_wire() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_fixture, node) = fixture_node(dir.path()).await;
    let mut reader = client(&node).await;
    assert_eq!(reader.session_body_rust().len(), 46_256);
    register(&node, &mut reader).await;
    let mut sizes = Vec::new();
    for step in LADDER {
        let positions = vec![3u32; step];
        let handle = reader.build_batch_rust(&positions, 160).expect("batch");
        let carried = client(&node)
            .await
            .build_batch_rust(&positions, 160)
            .expect("batch");
        let (status, answer) = node
            .http
            .post("/howl/v1/notes", handle.body_rust().to_vec())
            .await;
        assert_eq!(status, StatusCode::OK);
        sizes.push((
            step,
            handle.body_rust().len(),
            carried.body_rust().len(),
            answer.len(),
        ));
    }
    // per slot 15,477 B up and 9,874 B down; 24 B of batch framing up, 58 B of header and
    // count down; inline adds the 46,244 B key
    let expected: Vec<(usize, usize, usize, usize)> = LADDER
        .iter()
        .map(|&s| {
            (
                s,
                24 + 15_477 * s,
                24 + 46_244 + 15_477 * s,
                56 + 2 + (4 + 9_870) * s,
            )
        })
        .collect();
    assert_eq!(sizes, expected);
}

#[tokio::test(flavor = "multi_thread")]
async fn refusals() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_fixture, node) = fixture_node(dir.path()).await;
    let reader = client(&node).await;
    assert!(reader.build_batch_rust(&[], 160).is_err(), "empty");
    assert!(
        reader.build_batch_rust(&[1; 17], 160).is_err(),
        "past the cap"
    );
    assert!(
        reader.build_batch_rust(&[160], 160).is_err(),
        "past the table"
    );
    assert!(reader.build_batch_rust(&[0], 0).is_err(), "empty table");

    let batch = reader.build_batch_rust(&[1, 2, 3], 160).expect("batch");
    let (_, good) = node
        .http
        .post("/howl/v1/notes", batch.body_rust().to_vec())
        .await;
    let answer = Answer::decode(&good).expect("answer");
    assert!(reader.open_notes_rust(&batch, &good).is_ok(), "control");

    let Body::Notes(notes) = &answer.body else {
        panic!("notes");
    };
    let short = Answer {
        body: Body::Notes(Notes {
            responses: notes.responses[..3].to_vec(),
        }),
        ..answer.clone()
    };
    assert!(
        reader.open_notes_rust(&batch, &short.encode()).is_err(),
        "count"
    );
    let behind = Answer {
        leaf_count: 3,
        ..answer.clone()
    };
    assert!(
        reader.open_notes_rust(&batch, &behind.encode()).is_err(),
        "behind"
    );
    let stale = Answer {
        body: Body::Stale,
        ..answer.clone()
    };
    let refused = reader
        .open_notes_rust(&batch, &stale.encode())
        .expect_err("stale");
    assert!(refused.contains("behind"), "{refused}");
    let other_set = Answer {
        param_set: 2,
        ..answer.clone()
    };
    assert!(
        reader.open_notes_rust(&batch, &other_set.encode()).is_err(),
        "set"
    );
    // every slot, since only the slots of the positions asked for are opened
    let mut tampered = notes.responses.clone();
    for response in &mut tampered {
        response.push(0);
    }
    let trailing = Answer {
        body: Body::Notes(Notes {
            responses: tampered,
        }),
        ..answer
    };
    assert!(
        reader.open_notes_rust(&batch, &trailing.encode()).is_err(),
        "trailing byte"
    );

    let params = node.raw("/howl/v1/params").await;
    let mut decoded = Answer::decode(&params).expect("params");
    let Body::Params(p) = &mut decoded.body else {
        panic!("params");
    };
    p.entry_bytes = 512;
    assert!(
        HowlClient::from_params(&decoded.encode()).is_err(),
        "cell size"
    );
    let Body::Params(p) = &mut decoded.body else {
        panic!("params");
    };
    p.entry_bytes = 256;
    p.ladder_cap = 32;
    assert!(
        HowlClient::from_params(&decoded.encode()).is_err(),
        "ladder cap"
    );
    let Body::Params(p) = &mut decoded.body else {
        panic!("params");
    };
    p.ladder_cap = 4;
    let capped = HowlClient::from_params(&decoded.encode()).expect("a smaller cap is fine");
    assert!(
        capped.build_batch_rust(&[1; 5], 160).is_err(),
        "pads past the node's cap"
    );
    assert!(HowlClient::from_params(&node.raw("/howl/v1/sync?since=0&upper=0").await).is_err());

    // A plain answer whose parts disagree with its header is refused.
    let block = Answer::decode(&node.raw("/howl/v1/block/0").await).expect("block");
    assert!(decode_answer_rust(&block.encode()).is_ok(), "control");
    let shrunk = Answer {
        leaf_count: 100,
        ..block
    };
    assert!(
        decode_answer_rust(&shrunk.encode()).is_err(),
        "block vs count"
    );
    let feed = Answer::decode(&node.raw("/howl/v1/prefixes?since=0").await).expect("feed");
    let short = Answer {
        leaf_count: 10,
        ..feed
    };
    assert!(
        decode_answer_rust(&short.encode()).is_err(),
        "feed vs count"
    );
}

/// `root at count i + 1` for every `LeafInserted`.
fn chain_roots(pool: [u8; 20], logs: &[RawLog]) -> HashMap<u64, [u8; 32]> {
    logs.iter()
        .filter(|log| log.address == pool && log.topics.first() == Some(&TOPIC_LEAF_INSERTED))
        .map(|log| {
            let index = u64::from_be_bytes(log.topics[1][24..].try_into().expect("8"));
            (index + 1, log.data[32..64].try_into().expect("32"))
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn paths_from_the_routes_fold_to_the_chain_root_at_chosen_counts() {
    let fixture = Fixture::load();
    let (mut tree, mut leaves) = fixture_tree(&fixture);
    let ext = extend(fixture.pool, &mut tree, fixture.head + 1, 300, 17, 0x0c11);
    let mut logs = fixture.logs.clone();
    logs.extend(ext.logs);
    leaves.extend(ext.leaves);
    let roots = chain_roots(fixture.pool, &logs);
    let total = leaves.len() as u64;
    assert!(total > 5 * BLOCK_LEAVES);

    let dir = tempfile::tempdir().expect("tempdir");
    let chain = FakeChain::new(fixture.pool, fixture.first_block, logs, ext.last_block);
    let mut node = TestNode::start(dir.path(), &fixture, chain);
    node.catch_up().await;

    let upper_answer =
        decode_answer_rust(&node.raw("/howl/v1/upper?since=0").await).expect("upper");
    let Body::Upper(upper) = upper_answer.body else {
        panic!("upper");
    };
    let mut blocks = HashMap::new();
    for b in 0..=(total - 1) / BLOCK_LEAVES {
        let answer =
            decode_answer_rust(&node.raw(&format!("/howl/v1/block/{b}")).await).expect("block");
        let Body::Block(block) = answer.body else {
            panic!("block");
        };
        blocks.insert(b, block.leaves);
    }
    let mut folds = 0;
    let indices = [
        1,
        2,
        159,
        1_023,
        1_024,
        1_025,
        2_047,
        2_048,
        3_000,
        total - 1,
    ];
    for index in indices {
        for n in [
            index + 1,
            index + 2,
            (index / BLOCK_LEAVES + 1) * BLOCK_LEAVES,
            index + 777,
            total,
        ] {
            if n > total {
                continue;
            }
            let tail = &blocks[&((n - 1) / BLOCK_LEAVES)];
            let path = merkle_path_rust(
                index as f64,
                n as f64,
                &upper.nodes,
                tail,
                &blocks[&(index / BLOCK_LEAVES)],
            )
            .expect("path");
            let (siblings, root) = path.split_at(32 * 32);
            assert_eq!(root, roots[&n], "root at {n}");
            let leaf = leaves[index as usize];
            let folded = fold_path_rust(&leaf, index as f64, siblings).expect("fold");
            assert_eq!(folded, roots[&n], "leaf {index} at {n}");
            assert_eq!(
                tree_root_rust(n as f64, &upper.nodes, tail).expect("root"),
                roots[&n]
            );
            // a path for another leaf does not fold this one
            let other = leaves[(index as usize + 1) % leaves.len()];
            assert_ne!(
                fold_path_rust(&other, index as f64, siblings).ok(),
                Some(roots[&n].to_vec())
            );
            folds += 1;
        }
    }
    assert!(folds >= 40, "{folds} folds");
    assert!(merkle_path_rust(5.0, 5.0, &upper.nodes, &blocks[&0], &blocks[&0]).is_err());
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../sdk/tests/fixtures")
}

/// The answers the package's offline tests decode, as the fixture node serves them. With
/// `HOWL_CLIENT_WRITE_FIXTURES=1` the files are written; otherwise they must match.
#[tokio::test(flavor = "multi_thread")]
async fn the_package_fixture_answers_are_what_the_node_serves() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_fixture, node) = fixture_node(dir.path()).await;
    let routes = [
        ("params.bin", "/howl/v1/params", StatusCode::OK),
        (
            "prefixes-0.bin",
            "/howl/v1/prefixes?since=0",
            StatusCode::OK,
        ),
        (
            "prefixes-150.bin",
            "/howl/v1/prefixes?since=150",
            StatusCode::OK,
        ),
        ("block-0.bin", "/howl/v1/block/0", StatusCode::OK),
        ("upper-0.bin", "/howl/v1/upper?since=0", StatusCode::OK),
        (
            "sync-100-0.bin",
            "/howl/v1/sync?since=100&upper=0",
            StatusCode::OK,
        ),
        (
            "stale-161.bin",
            "/howl/v1/prefixes?since=161",
            StatusCode::CONFLICT,
        ),
    ];
    let write = std::env::var("HOWL_CLIENT_WRITE_FIXTURES").is_ok_and(|v| v == "1");
    let mut digests = String::new();
    for (file, route, status) in routes {
        let (got, body) = node.http.get(route).await;
        assert_eq!(got, status, "{route}");
        let path = fixtures_dir().join(file);
        if write {
            std::fs::create_dir_all(fixtures_dir()).expect("mkdir");
            std::fs::write(&path, &body).expect("write");
        } else {
            let held = std::fs::read(&path)
                .expect("fixture file; regenerate with HOWL_CLIENT_WRITE_FIXTURES=1");
            assert_eq!(held, body, "{file}");
        }
        let digest: String = Sha256::digest(&body)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        digests.push_str(&format!("{digest}  {file}\n"));
    }
    let sums = fixtures_dir().join("SHA256SUMS");
    if write {
        std::fs::write(&sums, &digests).expect("write");
    } else {
        assert_eq!(std::fs::read_to_string(&sums).expect("sums"), digests);
    }
}
