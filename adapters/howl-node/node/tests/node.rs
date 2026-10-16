//! The node end to end: a chain followed in-process, read back through the routes.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

#[path = "../../../howl/indexer/tests/support/mod.rs"]
mod chain;
mod support;
#[path = "../../../howl/indexer/tests/support/wallet.rs"]
mod wallet;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use chain::{Fixture, Rng};
use howl_indexer::{RawLog, TOPIC_LEAF_INSERTED};
use howl_node::engine::Engine;
use howl_node::follow::{Follower, Step};
use howl_node::http::{router, Served};
use howl_node::NodeConfig;
use howl_prefix_feed::{PrefixIndex, Segment};
use howl_record::{decode, CELL_BYTES};
use howl_store::ROWS_PER_SHARD;
use howl_wire::tree::{fold, Node, TreeView, BLOCK_LEAVES};
use howl_wire::{Answer, Body, Kind};
use raven_inspire_session::SessionStoreLimits;
use support::{extend, fixture_tree, root_of, FakeChain, Http, Reader};

struct TestNode {
    follower: Follower<FakeChain>,
    engine: Arc<Engine>,
    http: Http,
}

fn config(dir: &std::path::Path, fixture: &Fixture, ttl: Duration) -> NodeConfig {
    NodeConfig {
        data_dir: dir.to_path_buf(),
        chain_id: fixture.chain_id,
        pool: fixture.pool,
        deployment_block: fixture.first_block,
        max_range: 40,
        sessions: SessionStoreLimits {
            max_sessions: 64,
            ttl,
        },
        seed: Some([7; 32]),
    }
}

impl TestNode {
    fn start(dir: &std::path::Path, fixture: &Fixture, chain: FakeChain) -> Self {
        Self::start_with(config(dir, fixture, Duration::from_secs(3_600)), chain)
    }

    fn start_with(config: NodeConfig, chain: FakeChain) -> Self {
        let (follower, engine) = howl_node::open(&config, chain).expect("open");
        let http = Http(router(Served::new(Arc::clone(&engine), 4)));
        Self {
            follower,
            engine,
            http,
        }
    }

    async fn step(&mut self) -> Step {
        let step = self.follower.step().await.expect("step");
        howl_node::publish(&self.follower, &self.engine, &step).expect("publish");
        step
    }

    /// Step until the table is at the head; the steps taken.
    async fn catch_up(&mut self) -> Vec<Step> {
        let mut steps = Vec::new();
        loop {
            // A follower that never settles is a defect, not a slow test.
            assert!(
                steps.len() < 5_000,
                "no idle step after {} steps",
                steps.len()
            );
            let step = self.step().await;
            let idle = matches!(step, Step::Idle { .. });
            steps.push(step);
            if idle {
                return steps;
            }
        }
    }

    async fn sync(&self) -> Answer {
        self.http.answer("/howl/v1/sync?since=0&upper=0").await
    }
}

/// `root after leaf i` for every `LeafInserted` in `logs`: the root at count `i + 1`.
fn chain_roots(pool: [u8; 20], logs: &[RawLog]) -> HashMap<u64, [u8; 32]> {
    logs.iter()
        .filter(|log| log.address == pool && log.topics.first() == Some(&TOPIC_LEAF_INSERTED))
        .map(|log| {
            let index = u64::from_be_bytes(log.topics[1][24..].try_into().expect("8"));
            (index + 1, log.data[32..64].try_into().expect("32"))
        })
        .collect()
}

/// The path of leaf `index` at count `n`, built only from what the routes return.
async fn path_from_routes(http: &Http, index: u64, n: u64) -> (Node, howl_wire::tree::Path) {
    let block = |b: u64| format!("/howl/v1/block/{b}");
    let Body::Block(own) = http.answer(&block(index / BLOCK_LEAVES)).await.body else {
        panic!("block");
    };
    let Body::Block(tail) = http
        .answer(&block(n.saturating_sub(1) / BLOCK_LEAVES))
        .await
        .body
    else {
        panic!("block");
    };
    let Body::Upper(upper) = http.answer("/howl/v1/upper?since=0").await.body else {
        panic!("upper");
    };
    let own = own.nodes();
    let view = TreeView {
        n,
        upper: &upper.list(),
        tail: &tail.nodes(),
    };
    let path = view.path(index, &own).expect("path");
    (own[(index % BLOCK_LEAVES) as usize], path)
}

fn wallet_positions(
    fixture: &Fixture,
    segment: &howl_wire::PrefixSegment,
) -> Vec<(usize, Vec<u64>)> {
    fixture
        .wallets
        .iter()
        .enumerate()
        .map(|(w, owner)| {
            let mut index = PrefixIndex::new();
            index
                .absorb(&Segment {
                    base: segment.base,
                    next: segment.next,
                    rows: &segment.rows,
                })
                .expect("absorb");
            let tags = wallet::candidate_tags(
                &owner.sk_view,
                owner.self_keys.len() as u64,
                owner.incoming_keys.len() as u64,
            );
            (
                w,
                index.matches(&tags, 0).iter().map(|m| m.position).collect(),
            )
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn wallets_find_open_and_prove_their_notes_on_the_fixture_chain() {
    let fixture = Fixture::load();
    let dir = tempfile::tempdir().expect("tempdir");
    let chain = FakeChain::new(
        fixture.pool,
        fixture.first_block,
        fixture.logs.clone(),
        fixture.first_block,
    );
    let mut node = TestNode::start(dir.path(), &fixture, chain.clone());
    let mut head = fixture.first_block;
    while head < fixture.head {
        head = (head + 5).min(fixture.head);
        chain.set_head(head);
        node.catch_up().await;
        // Every answer's reads agree: the feed holds the header's leaf count.
        let sync = node.sync().await;
        let Body::Sync {
            prefixes,
            newest,
            upper,
        } = &sync.body
        else {
            panic!("sync");
        };
        assert_eq!(prefixes.next, sync.leaf_count);
        assert_eq!(upper.next, sync.leaf_count / BLOCK_LEAVES);
        assert_eq!(
            newest.nodes().len() as u64,
            (sync.leaf_count + BLOCK_LEAVES - 1) % BLOCK_LEAVES + 1
        );
        assert_eq!(sync.block, head);
        let view = TreeView {
            n: sync.leaf_count,
            upper: &upper.list(),
            tail: &newest.nodes(),
        };
        assert_eq!(
            view.root().expect("root"),
            sync.root,
            "the header's root is its leaves'"
        );
    }

    let sync = node.sync().await;
    assert_eq!(sync.leaf_count, fixture.leaf_count);
    assert_eq!(sync.root, fixture.root);
    let Body::Sync {
        prefixes, newest, ..
    } = &sync.body
    else {
        panic!("sync");
    };
    assert_eq!(
        prefixes.rows,
        fixture.prefix_feed(),
        "the feed is the fixture's, row for row"
    );
    let commitments: Vec<u8> = fixture.leaves.iter().flat_map(|l| l.commitment).collect();
    assert_eq!(newest.leaves, commitments);

    let roots = chain_roots(fixture.pool, &fixture.logs);
    let mut session = Reader::new(&node.http, 1).await;
    session.register(&node.http).await;
    let mut inline = Reader::new(&node.http, 2).await;
    let mut found = 0;
    for (w, positions) in wallet_positions(&fixture, prefixes) {
        let mut owned: Vec<u64> = fixture.wallets[w]
            .owned_leaves
            .iter()
            .map(|&l| u64::from(l))
            .collect();
        owned.sort_unstable();
        assert_eq!(positions, owned, "{}", fixture.wallets[w].label);
        for chunk in positions.chunks(howl_wire::LADDER_CAP) {
            let (answer, by_handle) = session.fetch(&node.http, chunk, sync.leaf_count).await;
            assert_eq!(answer.leaf_count, sync.leaf_count);
            let (_, by_key) = inline.fetch(&node.http, chunk, sync.leaf_count).await;
            assert_eq!(by_handle, by_key, "both key modes read the same cells");
            for (&position, cell) in chunk.iter().zip(&by_handle) {
                let expected = fixture.leaves[position as usize]
                    .cell
                    .as_ref()
                    .expect("a note");
                assert_eq!(cell, expected, "cell {position}");
                assert_eq!(
                    u64::from(decode(cell).expect("decodes").leaf_index),
                    position
                );
                found += 1;
            }
        }
        let mut rng = Rng(w as u64 + 11);
        for &index in &positions {
            let mut counts = vec![index + 1, fixture.leaf_count];
            counts.push(index + 1 + rng.below(fixture.leaf_count - index));
            for n in counts {
                let (leaf, path) = path_from_routes(&node.http, index, n).await;
                assert_eq!(path.root, roots[&n], "root at {n}");
                assert_eq!(
                    fold(&leaf, index, &path.siblings).expect("fold"),
                    roots[&n],
                    "leaf {index} at {n}"
                );
            }
        }
    }
    assert!(found >= 10, "the fixture's wallets own notes");
}

/// The fixture, then synthetic notes past several blocks and shards.
fn long_chain(
    fixture: &Fixture,
    blocks: u64,
    per_block: u64,
    seed: u64,
) -> (Vec<RawLog>, Vec<Node>, u64) {
    let (mut tree, mut leaves) = fixture_tree(fixture);
    let ext = extend(
        fixture.pool,
        &mut tree,
        fixture.head + 1,
        blocks,
        per_block,
        seed,
    );
    let mut logs = fixture.logs.clone();
    logs.extend(ext.logs);
    leaves.extend(ext.leaves);
    (logs, leaves, ext.last_block)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_path_folds_to_the_pool_root_at_any_count_across_blocks() {
    let fixture = Fixture::load();
    let (logs, leaves, last) = long_chain(&fixture, 300, 17, 0xb10c);
    let total = leaves.len() as u64;
    assert!(total > 5 * BLOCK_LEAVES && total > 2 * ROWS_PER_SHARD as u64);
    let dir = tempfile::tempdir().expect("tempdir");
    let chain = FakeChain::new(fixture.pool, fixture.first_block, logs.clone(), last);
    let mut node = TestNode::start(dir.path(), &fixture, chain);
    node.catch_up().await;
    let sync = node.sync().await;
    assert_eq!(sync.leaf_count, total);
    assert_eq!(
        sync.root,
        root_of(&leaves),
        "the chain's root, folded from scratch"
    );

    let roots = chain_roots(fixture.pool, &logs);
    let mut rng = Rng(0x9a7);
    let mut checked = 0;
    let boundaries = [1_024, 2_048, 3_072, 4_096, 5_120, total];
    for _ in 0..30 {
        let index = 1 + rng.below(total - 1);
        let mut counts: Vec<u64> = boundaries.iter().copied().filter(|&n| n > index).collect();
        counts.push(index + 1);
        counts.push(index + 1 + rng.below(total - index));
        for n in counts {
            let (leaf, path) = path_from_routes(&node.http, index, n).await;
            assert_eq!(leaf, leaves[index as usize]);
            assert_eq!(path.root, roots[&n], "root at {n}");
            assert_eq!(
                fold(&leaf, index, &path.siblings).expect("fold"),
                roots[&n],
                "leaf {index} at {n}"
            );
            checked += 1;
        }
    }
    // Two counts checked against a root folded from scratch, not the chain's.
    for n in [3_000, total - 1] {
        let (_, path) = path_from_routes(&node.http, 7, n).await;
        assert_eq!(path.root, root_of(&leaves[..n as usize]));
    }
    // A path proves nothing for another leaf, index or count.
    let (leaf, path) = path_from_routes(&node.http, 2_500, 4_000).await;
    assert_ne!(
        fold(&leaves[2_501], 2_500, &path.siblings).expect("fold"),
        roots[&4_000]
    );
    assert_ne!(fold(&leaf, 2_501, &path.siblings).ok(), Some(roots[&4_000]));
    assert_ne!(path.root, roots[&4_001]);
    assert!(checked > 150);

    // Private reads across the shards, against the table's own cells.
    let mut reader = Reader::new(&node.http, 3).await;
    reader.register(&node.http).await;
    let positions = [0, 1, 2_047, 2_048, 2_049, 4_095, 4_096, total - 1];
    let (_, cells) = reader.fetch(&node.http, &positions, total).await;
    for (&position, cell) in positions.iter().zip(&cells) {
        let shard = node
            .follower
            .store()
            .shard((position / 2_048) as u32)
            .expect("shard");
        let row = (position % 2_048) as usize;
        assert_eq!(
            cell.as_slice(),
            &shard.cells[row * CELL_BYTES..(row + 1) * CELL_BYTES],
            "row {position}"
        );
    }
    assert!(
        cells[0].iter().all(|b| *b == 0),
        "row 0 is the genesis filler"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_append_re_encodes_the_newest_shard_alone_and_is_served_at_once() {
    let fixture = Fixture::load();
    let (logs, leaves, last) = long_chain(&fixture, 150, 17, 0xa99);
    let dir = tempfile::tempdir().expect("tempdir");
    let chain = FakeChain::new(fixture.pool, fixture.first_block, logs, fixture.head);
    let mut node = TestNode::start(dir.path(), &fixture, chain.clone());
    node.catch_up().await;
    let mut reader = Reader::new(&node.http, 4).await;
    reader.register(&node.http).await;
    let mut block = fixture.head;
    let mut reads = 0;
    while block < last {
        block += 1;
        chain.set_head(block);
        let before = node.engine.view();
        let encodes = node.engine.encodes();
        let Step::Read { leaves: added, .. } = node.step().await else {
            panic!("a block was read");
        };
        let after = node.engine.view();
        let first = added.start / ROWS_PER_SHARD as u64;
        let touched = (added.end - 1) / ROWS_PER_SHARD as u64 - first + 1;
        assert_eq!(node.engine.encodes() - encodes, touched, "block {block}");
        for (old, new) in before.shards.iter().zip(&after.shards).take(first as usize) {
            assert!(Arc::ptr_eq(old, new), "a full shard is the same allocation");
        }
        // A row the feed shows is a row a private read returns.
        if block.is_multiple_of(25) || added.end / 2_048 != added.start / 2_048 {
            let sync = node.sync().await;
            assert_eq!(sync.leaf_count, added.end);
            let newest = added.end - 1;
            let (answer, cells) = reader.fetch(&node.http, &[newest], sync.leaf_count).await;
            assert_eq!(answer.leaf_count, added.end);
            let record = decode(&cells[0]).expect("decodes");
            assert_eq!(u64::from(record.leaf_index), newest);
            assert_eq!(record.commitment_prefix, leaves[newest as usize][..16]);
            reads += 1;
        }
    }
    assert!(reads >= 6);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restart_resumes_where_the_table_stopped() {
    let fixture = Fixture::load();
    let (logs, _, last) = long_chain(&fixture, 150, 17, 0x7e57);
    let straight_dir = tempfile::tempdir().expect("tempdir");
    let mut straight = TestNode::start(
        straight_dir.path(),
        &fixture,
        FakeChain::new(fixture.pool, fixture.first_block, logs.clone(), last),
    );
    straight.catch_up().await;

    let dir = tempfile::tempdir().expect("tempdir");
    let chain = FakeChain::new(fixture.pool, fixture.first_block, logs, fixture.head + 70);
    let mut node = TestNode::start(dir.path(), &fixture, chain.clone());
    node.catch_up().await;
    let before = node.sync().await.encode();
    drop(node);
    let mut node = TestNode::start(dir.path(), &fixture, chain.clone());
    assert_eq!(
        node.sync().await.encode(),
        before,
        "the reopened node serves what it served"
    );
    chain.set_head(last);
    node.catch_up().await;
    for path in [
        "/howl/v1/sync?since=0&upper=0",
        "/howl/v1/upper?since=2",
        "/howl/v1/block/3",
        "/howl/v1/prefixes?since=1000",
    ] {
        assert_eq!(
            node.http.get(path).await,
            straight.http.get(path).await,
            "{path}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reorganisation_below_the_tip_rewinds_and_serves_the_new_chain() {
    let fixture = Fixture::load();
    let (tree, base) = fixture_tree(&fixture);
    let mut tree_a = tree.clone();
    let a = extend(fixture.pool, &mut tree_a, fixture.head + 1, 300, 17, 0xaaaa);
    // The fork keeps the first 60 blocks of A and replaces the rest: it crosses back over a
    // sealed shard.
    let fork_block = fixture.head + 1 + 60;
    let kept_logs: Vec<RawLog> = a
        .logs
        .iter()
        .filter(|l| l.block_number < fork_block)
        .cloned()
        .collect();
    let kept = (60 * 17) as usize;
    let mut tree_b = tree;
    let mut leaves_b = base.clone();
    for leaf in &a.leaves[..kept] {
        tree_b.insert(support::scalar(leaf));
        leaves_b.push(*leaf);
    }
    let b = extend(fixture.pool, &mut tree_b, fork_block, 120, 9, 0xbbbb);
    leaves_b.extend(&b.leaves);

    let dir = tempfile::tempdir().expect("tempdir");
    let mut logs_a = fixture.logs.clone();
    logs_a.extend(a.logs.clone());
    let chain = FakeChain::new(fixture.pool, fixture.first_block, logs_a, a.last_block);
    let mut node = TestNode::start(dir.path(), &fixture, chain.clone());
    node.catch_up().await;
    let before = node.sync().await;
    assert!(before.leaf_count > 2 * ROWS_PER_SHARD as u64);

    chain.fork(fork_block, b.logs.clone());
    chain.set_head(b.last_block);
    let Step::Rewound {
        leaves: dropped,
        block,
    } = node.step().await
    else {
        panic!("the node notices the reorganisation first");
    };
    // Back to the newest batch end the new chain still has, at or before the fork.
    let at_fork = base.len() as u64 + kept as u64;
    assert!(dropped.start <= at_fork && dropped.end == before.leaf_count);
    assert!(block < Some(fork_block));
    assert!(
        dropped.start < ROWS_PER_SHARD as u64,
        "the cut reopens a sealed shard"
    );
    let rewound = node.sync().await;
    assert_eq!(rewound.leaf_count, dropped.start);
    assert_eq!(rewound.root, root_of(&leaves_b[..dropped.start as usize]));
    node.catch_up().await;
    let after = node.sync().await;
    assert_eq!(after.leaf_count, leaves_b.len() as u64);
    assert_eq!(after.root, root_of(&leaves_b));

    // The same bytes as a node that only ever saw the new chain.
    let mut logs_b = fixture.logs.clone();
    logs_b.extend(kept_logs);
    logs_b.extend(b.logs);
    let fresh_dir = tempfile::tempdir().expect("tempdir");
    let mut fresh = TestNode::start(
        fresh_dir.path(),
        &fixture,
        FakeChain::new(fixture.pool, fixture.first_block, logs_b, b.last_block),
    );
    fresh.catch_up().await;
    for path in [
        "/howl/v1/sync?since=0&upper=0",
        "/howl/v1/block/1",
        "/howl/v1/block/2",
        "/howl/v1/upper?since=0",
    ] {
        assert_eq!(
            node.http.get(path).await,
            fresh.http.get(path).await,
            "{path}"
        );
    }
    for index in 0..node.follower.store().shard_count() {
        assert_eq!(
            node.follower.store().shard(index).expect("shard"),
            fresh.follower.store().shard(index).expect("shard")
        );
    }
    // The rewritten rows are read privately from the new chain.
    let mut reader = Reader::new(&node.http, 5).await;
    let rewritten = [at_fork, at_fork + 1, after.leaf_count - 1];
    let (_, cells) = reader.fetch(&node.http, &rewritten, after.leaf_count).await;
    for (&position, cell) in rewritten.iter().zip(&cells) {
        assert_eq!(
            decode(cell).expect("decodes").commitment_prefix,
            leaves_b[position as usize][..16]
        );
    }

    // A reorganisation that keeps every leaf only moves the table's block back.
    let same: Vec<RawLog> = chain
        .logs_now()
        .into_iter()
        .filter(|l| l.block_number >= b.last_block - 3)
        .collect();
    chain.fork(b.last_block - 3, same);
    let Step::Rewound { leaves: none, .. } = node.step().await else {
        panic!("rewound");
    };
    assert!(none.start <= none.end);
    node.catch_up().await;
    assert_eq!(node.sync().await.encode(), fresh.sync().await.encode());
}

#[tokio::test(flavor = "multi_thread")]
async fn refusals_name_the_state_they_were_refused_against() {
    let fixture = Fixture::load();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut node = TestNode::start_with(
        config(dir.path(), &fixture, Duration::from_secs(2)),
        FakeChain::new(
            fixture.pool,
            fixture.first_block,
            fixture.logs.clone(),
            fixture.head,
        ),
    );
    node.catch_up().await;
    let past = fixture.leaf_count + 1;
    for path in [
        format!("/howl/v1/prefixes?since={past}"),
        "/howl/v1/upper?since=1".to_owned(),
        format!("/howl/v1/sync?since={past}&upper=0"),
        format!(
            "/howl/v1/block/{}",
            fixture.leaf_count.div_ceil(BLOCK_LEAVES)
        ),
    ] {
        let (status, body) = node.http.get(&path).await;
        assert_eq!(status, StatusCode::CONFLICT, "{path}");
        let answer = Answer::decode(&body).expect("a stale answer decodes");
        assert_eq!(answer.header().kind, Kind::Stale);
        assert_eq!(answer.leaf_count, fixture.leaf_count);
    }
    let (status, _) = node.http.get("/howl/v1/prefixes?since=x").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let mut reader = Reader::new(&node.http, 6).await;
    let handle = reader.register(&node.http).await;
    // Three is not a ladder step.
    let config = raven_inspire::params::ShardConfig::for_ring_dim(2048, 256, fixture.leaf_count)
        .expect("config");
    let (_, three) = reader
        .session
        .query_batch(&[1, 2, 3], &config, &mut reader.sampler)
        .expect("batch");
    let (status, _) = node
        .http
        .post(
            "/howl/v1/notes",
            support::request(&bincode::serialize(&three).expect("encode")),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    // A shard past the table.
    let wide =
        raven_inspire::params::ShardConfig::for_ring_dim(2048, 256, 3 * 2_048).expect("config");
    let (_, past_shard) = reader
        .session
        .query_batch(&[5_000], &wide, &mut reader.sampler)
        .expect("batch");
    let (status, body) = node
        .http
        .post(
            "/howl/v1/notes",
            support::request(&bincode::serialize(&past_shard).expect("encode")),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        Answer::decode(&body).expect("stale").leaf_count,
        fixture.leaf_count
    );
    // Another wire version or parameter set.
    let mut body = support::request(&bincode::serialize(&three).expect("encode"));
    body[3] = 9;
    assert_eq!(
        node.http.post("/howl/v1/notes", body.clone()).await.0,
        StatusCode::BAD_REQUEST
    );
    body[1] = 2;
    assert_eq!(
        node.http.post("/howl/v1/notes", body).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        node.http
            .post("/howl/v1/session", vec![0, 1, 0, 1, 7])
            .await
            .0,
        StatusCode::BAD_REQUEST
    );

    // A session lives while it is used and lapses a TTL after its last use.
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        reader.fetch(&node.http, &[1], fixture.leaf_count).await;
    }
    tokio::time::sleep(Duration::from_millis(2_300)).await;
    let (_, late) = reader.batch(&[1], fixture.leaf_count);
    let (status, body) = node.http.post("/howl/v1/notes", late).await;
    assert_eq!(
        status,
        StatusCode::GONE,
        "handle {handle}: {}",
        String::from_utf8_lossy(&body)
    );
}

/// The fixture, then chain A: `blocks` blocks of `per_block` notes. Chain B keeps A below
/// `fork` and replaces block `fork` on with `b_blocks` blocks of `b_per_block` other notes.
struct Forked {
    logs_a: Vec<RawLog>,
    leaves_a: Vec<Node>,
    a_last: u64,
    b: support::Extension,
    tree_b: support::LeanTree,
    leaves_b: Vec<Node>,
    logs_b: Vec<RawLog>,
}

fn forked(
    fixture: &Fixture,
    blocks: u64,
    per_block: u64,
    fork_after: u64,
    b_blocks: u64,
    b_per_block: u64,
) -> Forked {
    let (tree, base) = fixture_tree(fixture);
    let mut tree_a = tree.clone();
    let a = extend(
        fixture.pool,
        &mut tree_a,
        fixture.head + 1,
        blocks,
        per_block,
        0xa1,
    );
    let fork = fixture.head + 1 + fork_after;
    let kept = (fork_after * per_block) as usize;
    let mut tree_b = tree;
    let mut leaves_b = base.clone();
    for leaf in &a.leaves[..kept] {
        tree_b.insert(support::scalar(leaf));
        leaves_b.push(*leaf);
    }
    let b = extend(fixture.pool, &mut tree_b, fork, b_blocks, b_per_block, 0xb2);
    leaves_b.extend(&b.leaves);
    let mut logs_a = fixture.logs.clone();
    logs_a.extend(a.logs.iter().cloned());
    let mut logs_b = fixture.logs.clone();
    logs_b.extend(a.logs.iter().filter(|l| l.block_number < fork).cloned());
    logs_b.extend(b.logs.iter().cloned());
    let mut leaves_a = base;
    leaves_a.extend(&a.leaves);
    Forked {
        logs_a,
        leaves_a,
        a_last: a.last_block,
        b,
        tree_b,
        leaves_b,
        logs_b,
    }
}

const ROUTES: [&str; 5] = [
    "/howl/v1/sync?since=0&upper=0",
    "/howl/v1/prefixes?since=0",
    "/howl/v1/block/0",
    "/howl/v1/block/1",
    "/howl/v1/upper?since=0",
];

/// The routes and shards of `node` equal those of a node that only ever followed `logs`.
async fn same_as_fresh(node: &TestNode, fixture: &Fixture, logs: Vec<RawLog>, head: u64) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut fresh = TestNode::start(
        dir.path(),
        fixture,
        FakeChain::new(fixture.pool, fixture.first_block, logs, head),
    );
    fresh.catch_up().await;
    for path in ROUTES {
        assert_eq!(
            node.http.get(path).await,
            fresh.http.get(path).await,
            "{path}"
        );
    }
    let served = node.engine.view();
    let expected = fresh.engine.view();
    assert_eq!(served.shards.len(), expected.shards.len());
    for (a, b) in served.shards.iter().zip(&expected.shards) {
        assert_eq!(a.digest, b.digest);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reorganisation_inside_a_step_is_never_applied() {
    let fixture = Fixture::load();
    // B replaces A's last block with as many other leaves; its next block has no pool logs.
    let f = forked(&fixture, 5, 4, 4, 1, 4);
    let x = f.a_last;
    let chain = FakeChain::new(fixture.pool, fixture.first_block, f.logs_a.clone(), x);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut node = TestNode::start(dir.path(), &fixture, chain.clone());
    node.catch_up().await;
    assert_eq!(node.sync().await.root, root_of(&f.leaves_a));

    // The fork lands after the step's first look at the newest mark.
    chain.fork_on_next_head(x, f.b.logs.clone(), x + 1);
    let step = node.step().await;
    let served = node.sync().await;
    assert!(
        !(served.block > x && served.root == root_of(&f.leaves_a)),
        "{step:?} served the abandoned chain's leaves under block {}",
        served.block
    );
    node.catch_up().await;
    let served = node.sync().await;
    assert_eq!(
        (served.leaf_count, served.block),
        (f.leaves_b.len() as u64, x + 1)
    );
    assert_eq!(served.root, root_of(&f.leaves_b));

    // And it keeps following B.
    let mut tree_b = f.tree_b.clone();
    let more = extend(fixture.pool, &mut tree_b, x + 2, 1, 3, 0xc3);
    chain.fork(x + 2, more.logs.clone());
    chain.set_head(x + 2);
    node.catch_up().await;
    let mut leaves = f.leaves_b.clone();
    leaves.extend(&more.leaves);
    assert_eq!(node.sync().await.root, root_of(&leaves));
    let mut logs = f.logs_b.clone();
    logs.extend(more.logs);
    same_as_fresh(&node, &fixture, logs, x + 2).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn rows_that_disagree_with_the_chain_are_walked_back_past_marks_that_still_match() {
    let fixture = Fixture::load();
    let f = forked(&fixture, 5, 4, 4, 1, 4);
    let x = f.a_last;
    let chain = FakeChain::new(fixture.pool, fixture.first_block, f.logs_a.clone(), x);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut node = TestNode::start(dir.path(), &fixture, chain.clone());
    node.catch_up().await;

    // A backend that keeps answering the replaced block's old hash hides the fork, so a mark
    // is written over A's rows under B's next block.
    chain.freeze_hash(x);
    chain.fork(x, f.b.logs.clone());
    chain.set_head(x + 1);
    node.catch_up().await;
    chain.thaw();

    // B's next leaf no longer continues the table's root.
    let mut tree_b = f.tree_b.clone();
    let more = extend(fixture.pool, &mut tree_b, x + 2, 1, 3, 0xc3);
    chain.fork(x + 2, more.logs.clone());
    chain.set_head(x + 2);
    let steps = node.catch_up().await;
    assert!(
        steps.iter().any(|s| matches!(s, Step::Rewound { .. })),
        "{steps:?}"
    );
    let mut leaves = f.leaves_b.clone();
    leaves.extend(&more.leaves);
    assert_eq!(node.sync().await.root, root_of(&leaves));
    let mut logs = f.logs_b.clone();
    logs.extend(more.logs);
    same_as_fresh(&node, &fixture, logs, x + 2).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_backend_behind_the_table_is_waited_for_and_a_shorter_chain_is_not() {
    let fixture = Fixture::load();
    let (logs, leaves, last) = long_chain(&fixture, 30, 9, 0x1a6);
    let chain = FakeChain::new(fixture.pool, fixture.first_block, logs, last);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut node = TestNode::start(dir.path(), &fixture, chain.clone());
    node.catch_up().await;
    let at_tip = node.sync().await;
    let encodes = node.engine.encodes();

    // A replica a few blocks behind: the table stays served and nothing is re-encoded.
    chain.set_head(last - 3);
    for _ in 0..3 {
        assert_eq!(node.step().await, Step::Moved);
        assert_eq!(node.sync().await, at_tip);
    }
    chain.set_head(last);
    assert!(matches!(node.step().await, Step::Idle { .. }));
    assert_eq!(node.sync().await, at_tip);
    assert_eq!(node.engine.encodes(), encodes);

    // A chain that stays shorter is followed after a bounded wait.
    chain.set_head(last - 3);
    let mut moved = 0;
    let rewound = loop {
        match node.step().await {
            Step::Moved => moved += 1,
            step => break step,
        }
        assert!(moved <= 64, "the shorter chain is never followed");
    };
    assert!(matches!(rewound, Step::Rewound { .. }), "{rewound:?}");
    node.catch_up().await;
    let shorter = node.sync().await;
    let count = shorter.leaf_count as usize;
    assert!(count < leaves.len() && shorter.block <= last - 3);
    assert_eq!(shorter.root, root_of(&leaves[..count]));
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_publishes_carry_nothing_from_the_view_they_were_to_replace() {
    let fixture = Fixture::load();
    // The fork keeps a full block, so a refresh without upper nodes refuses.
    let f = forked(&fixture, 200, 17, 80, 200, 70);
    let chain = FakeChain::new(
        fixture.pool,
        fixture.first_block,
        f.logs_a.clone(),
        f.a_last,
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let mut node = TestNode::start(dir.path(), &fixture, chain.clone());
    node.catch_up().await;

    chain.fork(fixture.head + 81, f.b.logs.clone());
    chain.set_head(f.b.last_block);
    // Two publishes fail, then the rest succeed.
    for _ in 0..2 {
        let step = node.follower.step().await.expect("step");
        let (Step::Rewound { leaves, .. } | Step::Read { leaves, .. }) = step else {
            panic!("{step:?}");
        };
        assert!(leaves.start >= BLOCK_LEAVES);
        assert!(node
            .engine
            .refresh(node.follower.store(), &[], leaves.start)
            .is_err());
    }
    node.catch_up().await;
    assert_eq!(node.sync().await.root, root_of(&f.leaves_b));
    same_as_fresh(&node, &fixture, f.logs_b.clone(), f.b.last_block).await;

    // A failed publish at the head is retried by the next idle step.
    let mut tree_b = f.tree_b.clone();
    let more = extend(fixture.pool, &mut tree_b, f.b.last_block + 1, 1, 5, 0xc4);
    chain.fork(f.b.last_block + 1, more.logs.clone());
    chain.set_head(f.b.last_block + 1);
    let Step::Read { leaves, .. } = node.follower.step().await.expect("step") else {
        panic!("read");
    };
    assert!(node
        .engine
        .refresh(node.follower.store(), &[], leaves.start)
        .is_err());
    assert!(node.sync().await.leaf_count < leaves.end);
    assert!(matches!(node.step().await, Step::Idle { .. }));
    let mut logs = f.logs_b.clone();
    logs.extend(more.logs);
    same_as_fresh(&node, &fixture, logs, f.b.last_block + 1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sync_skips_the_newest_leaves_the_wallet_holds() {
    let fixture = Fixture::load();
    let (logs, _, last) = long_chain(&fixture, 80, 17, 0x5e1d);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut node = TestNode::start(
        dir.path(),
        &fixture,
        FakeChain::new(fixture.pool, fixture.first_block, logs, last),
    );
    node.catch_up().await;
    let full = node.sync().await;
    let n = full.leaf_count;
    let Body::Sync { newest, .. } = &full.body else {
        panic!("sync");
    };
    let start = u64::from(newest.block_index) * BLOCK_LEAVES;
    assert!(n - start > 5);

    // Nothing new: the header and three empty runs.
    let idle_path = format!(
        "/howl/v1/sync?since={n}&upper={}&held={n}",
        n / BLOCK_LEAVES
    );
    let (status, idle) = node.http.get(&idle_path).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(idle.len(), 56 + 16 + 16 + 8);
    // Part of the newest block held: only the rest comes.
    for held in [n - 5, start + 1, start, start.saturating_sub(7), 0] {
        let answer = node
            .http
            .answer(&format!("/howl/v1/sync?since=0&upper=0&held={held}"))
            .await;
        let Body::Sync { newest: part, .. } = answer.body else {
            panic!("sync");
        };
        let skip = (held.max(start) - start) as usize * 32;
        assert_eq!(part.block_index, newest.block_index);
        assert_eq!(part.leaves, newest.leaves[skip..], "held {held}");
    }
    // Holding more than the node: the state it holds.
    let (status, body) = node
        .http
        .get(&format!("/howl/v1/sync?since=0&upper=0&held={}", n + 1))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(Answer::decode(&body).expect("stale").leaf_count, n);
}
