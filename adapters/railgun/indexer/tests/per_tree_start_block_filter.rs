//! Per-tree `start_block` filter regression: the indexer worker scans
//! from `start_block` but drops events whose tree's floor is HIGHER
//! than the event's block height.
//!
//! Without this, a 3-instance deployment at `{25M, 24M, 23M}` would
//! either rescan `[23M..25M]` for tree 0 (the MAX strategy) or miss
//! events in `(24M, 25M]` for trees 1+2 (the naive single-floor
//! strategy).

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::needless_continue,
    clippy::match_same_arms,
    clippy::cast_possible_truncation
)]

use async_trait::async_trait;
use raven_railgun_core::{CommitmentLeaf, RailgunEvent};
use raven_railgun_indexer::{
    ChainSource, IndexerError, IndexerMessage, IndexerWorker, IndexerWorkerConfig, Result,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Debug, Default)]
struct PerTreeMockSource {
    inner: Mutex<MockInner>,
}

#[derive(Debug, Default)]
struct MockInner {
    chain: BTreeMap<u64, [u8; 32]>,
    events: BTreeMap<u64, Vec<RailgunEvent>>,
    latest: u64,
}

impl PerTreeMockSource {
    fn new() -> Self {
        Self::default()
    }
    fn add_block(&self, n: u64, hash: [u8; 32]) {
        let mut g = self.inner.lock().expect("lock");
        g.chain.insert(n, hash);
        g.latest = g.latest.max(n);
    }
    fn add_event(&self, n: u64, ev: RailgunEvent) {
        let mut g = self.inner.lock().expect("lock");
        g.events.entry(n).or_default().push(ev);
    }
}

#[async_trait]
impl ChainSource for PerTreeMockSource {
    async fn latest_block(&self) -> Result<u64> {
        Ok(self.inner.lock().expect("lock").latest)
    }
    async fn events_in_range(&self, from: u64, to: u64) -> Result<Vec<RailgunEvent>> {
        let g = self.inner.lock().expect("lock");
        let mut out = Vec::new();
        for (_, evs) in g.events.range(from..=to) {
            for e in evs {
                out.push(e.clone());
            }
        }
        Ok(out)
    }
    async fn root_history(
        &self,
        _t: u32,
        _r: [u8; 32],
        _at: Option<alloy::eips::BlockId>,
    ) -> Result<bool> {
        Ok(true)
    }
    async fn block_hash(&self, n: u64) -> Result<[u8; 32]> {
        self.inner
            .lock()
            .expect("lock")
            .chain
            .get(&n)
            .copied()
            .ok_or_else(|| IndexerError::Rpc(format!("block {n} not in mock chain")))
    }
    async fn merkle_root(&self, _at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        Err(IndexerError::Rpc("not used".into()))
    }
    async fn active_tree_number(&self, _at: Option<alloy::eips::BlockId>) -> Result<u32> {
        Err(IndexerError::Rpc("not used".into()))
    }
}

fn shield(tree: u32, block: u64, leaf: u32) -> RailgunEvent {
    RailgunEvent::Shield {
        block_number: block,
        tx_hash: [u8::try_from(block & 0xff).expect("byte"); 32],
        tree_number: tree,
        start_position: leaf,
        leaves: vec![CommitmentLeaf {
            tree_number: tree,
            leaf_index: leaf,
            commitment_hash: [0xab; 32],
            ciphertext: Vec::new(),
        }],
    }
}

fn unshield(block: u64) -> RailgunEvent {
    RailgunEvent::Unshield {
        block_number: block,
        tx_hash: [u8::try_from(block & 0xff).expect("byte"); 32],
        to: [0u8; 20],
        token: [0u8; 32],
        amount: 0,
        fee: 0,
    }
}

/// Three instances at heights `{25, 24, 23}` (compressed) each receive
/// ONLY the events at or above their per-tree floor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_instance_chain_indexer_routes_events_to_correct_tree_from_per_tree_cursor() {
    let src = Arc::new(PerTreeMockSource::new());
    let last_block = 30u64;
    for n in 0..=last_block {
        src.add_block(n, [u8::try_from(n & 0xff).expect("byte"); 32]);
    }
    for b in 23..=27u64 {
        src.add_event(b, shield(0, b, u32::try_from(b - 23).expect("u32")));
    }
    for b in 24..=27u64 {
        src.add_event(b, shield(1, b, u32::try_from(b - 24).expect("u32")));
    }
    for b in 25..=27u64 {
        src.add_event(b, shield(2, b, u32::try_from(b - 25).expect("u32")));
    }

    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(256);
    let worker = IndexerWorker::new(Arc::clone(&src), tx);

    let mut per_tree_start: BTreeMap<u32, u64> = BTreeMap::new();
    per_tree_start.insert(0, 23);
    per_tree_start.insert(1, 24);
    per_tree_start.insert(2, 25);

    let cfg = IndexerWorkerConfig {
        start_block: 22, // = min(per-tree) - 1; first scan span = (23..)
        poll_interval_secs: 1,
        chunk_blocks: 50,
        per_tree_start_blocks: per_tree_start,
        ..IndexerWorkerConfig::default()
    };

    let join = tokio::spawn(async move { worker.run(cfg).await });

    let mut received: Vec<(u32, u64)> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        match tokio::time::timeout(Duration::from_millis(1500), rx.recv()).await {
            Ok(Some(IndexerMessage::Event { event, .. })) => {
                let pair = match event {
                    RailgunEvent::Shield {
                        tree_number,
                        block_number,
                        ..
                    } => (tree_number, block_number),
                    _ => continue,
                };
                received.push(pair);
                if received.len() >= 12 {
                    break;
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;

    let tree0: Vec<u64> = received
        .iter()
        .filter(|(t, _)| *t == 0)
        .map(|(_, b)| *b)
        .collect();
    let tree1: Vec<u64> = received
        .iter()
        .filter(|(t, _)| *t == 1)
        .map(|(_, b)| *b)
        .collect();
    let tree2: Vec<u64> = received
        .iter()
        .filter(|(t, _)| *t == 2)
        .map(|(_, b)| *b)
        .collect();

    assert_eq!(
        tree0,
        vec![23, 24, 25, 26, 27],
        "tree 0 must receive all events >= floor 23"
    );
    assert_eq!(
        tree1,
        vec![24, 25, 26, 27],
        "tree 1 must receive only events >= floor 24"
    );
    assert_eq!(
        tree2,
        vec![25, 26, 27],
        "tree 2 must receive only events >= floor 25"
    );
}

// Skip/existence semantics (a tree with floor=H receives nothing below H) live
// in the floor property below, which was proven RED under both a disabled
// filter and a boundary off-by-one; the routes test above holds the boundary
// but its fixture feeds trees 1-2 only above-floor events, so it cannot see a
// disabled filter.

/// One generated event: `tree: None` is an Unshield (no tree number, never
/// filtered); heights and floors are drawn from the same small range so the
/// `height == floor` boundary is hit often.
#[derive(Debug, Clone)]
struct GenEvent {
    tree: Option<u32>,
    height: u64,
}

/// The filter law over ARBITRARY floor maps and event sets: the worker delivers
/// exactly the input events minus tree-carrying events whose tree has a floor
/// above their height, in source order. A sentinel Unshield at a height past
/// every generated event is delivered unconditionally, so its arrival proves
/// the scan completed — no sleep is used as synchronization.
mod floor_property {
    use super::*;
    use proptest::prelude::*;

    const MAX_H: u64 = 12;
    const SENTINEL_H: u64 = MAX_H + 1;

    fn runtime() -> &'static tokio::runtime::Runtime {
        static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
        RT.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime")
        })
    }

    async fn run_case(
        floors: BTreeMap<u32, u64>,
        events: Vec<GenEvent>,
    ) -> Vec<(Option<u32>, u64)> {
        let src = Arc::new(PerTreeMockSource::new());
        for n in 0..=SENTINEL_H {
            src.add_block(n, [u8::try_from(n & 0xff).expect("byte"); 32]);
        }
        for (i, ev) in events.iter().enumerate() {
            match ev.tree {
                Some(t) => src.add_event(
                    ev.height,
                    shield(t, ev.height, u32::try_from(i).expect("u32")),
                ),
                None => src.add_event(ev.height, unshield(ev.height)),
            }
        }
        src.add_event(SENTINEL_H, unshield(SENTINEL_H));

        let (tx, mut rx) = mpsc::channel::<IndexerMessage>(256);
        let worker = IndexerWorker::new(Arc::clone(&src), tx);
        let cfg = IndexerWorkerConfig {
            start_block: 0,
            poll_interval_secs: 1,
            chunk_blocks: 50,
            per_tree_start_blocks: floors,
            ..IndexerWorkerConfig::default()
        };
        let join = tokio::spawn(async move { worker.run(cfg).await });

        let mut received: Vec<(Option<u32>, u64)> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        'collect: loop {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            match tokio::time::timeout(Duration::from_millis(1500), rx.recv()).await {
                Ok(Some(IndexerMessage::Event { event, .. })) => {
                    let pair = match event {
                        RailgunEvent::Shield {
                            tree_number,
                            block_number,
                            ..
                        } => (Some(tree_number), block_number),
                        RailgunEvent::Unshield { block_number, .. } => (None, block_number),
                        _ => continue,
                    };
                    if pair == (None, SENTINEL_H) {
                        break 'collect;
                    }
                    received.push(pair);
                }
                Ok(Some(_)) => continue,
                Ok(None) => break,
                Err(_) => continue,
            }
        }
        drop(rx);
        let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
        received
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn per_tree_floor_filter_delivers_exactly_the_at_or_above_floor_events(
            floors in proptest::collection::btree_map(0u32..4, 0u64..MAX_H, 0..4),
            // Heights start at 1: the worker's first span is (start_block..],
            // so with start_block = 0 a height-0 event is out of window by design.
            events in proptest::collection::vec(
                (proptest::option::of(0u32..4), 1u64..MAX_H)
                    .prop_map(|(tree, height)| GenEvent { tree, height }),
                0..12,
            ),
        ) {
            // Force the boundary class for every mapped tree: an off-by-one in
            // the floor comparison survived a purely random draw once, so
            // floor-1 / floor / floor+1 events are injected deterministically.
            let mut events = events;
            for (t, f) in &floors {
                for h in [f.saturating_sub(1), *f, f.saturating_add(1)] {
                    if (1..=MAX_H).contains(&h) {
                        events.push(GenEvent {
                            tree: Some(*t),
                            height: h,
                        });
                    }
                }
            }

            // Independent statement of the law, per-event; source order is
            // height-major then insertion order, matching the mock's BTreeMap.
            let mut expected: Vec<(Option<u32>, u64)> = Vec::new();
            let mut by_height: BTreeMap<u64, Vec<(usize, &GenEvent)>> = BTreeMap::new();
            for (i, ev) in events.iter().enumerate() {
                by_height.entry(ev.height).or_default().push((i, ev));
            }
            for evs in by_height.values() {
                for (_, ev) in evs {
                    let keep = match ev.tree {
                        None => true,
                        Some(t) => floors.get(&t).is_none_or(|f| ev.height >= *f),
                    };
                    if keep {
                        expected.push((ev.tree, ev.height));
                    }
                }
            }

            let received = runtime().block_on(run_case(floors.clone(), events.clone()));
            prop_assert_eq!(
                received,
                expected,
                "floors={:?} events={:?}",
                floors,
                events
            );
        }
    }
}

/// Trees NOT in the map (e.g. tree=3 with a per_tree_start_blocks map
/// only covering trees {0,1,2}) pass through unfiltered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indexer_passes_through_trees_not_in_per_tree_map() {
    let src = Arc::new(PerTreeMockSource::new());
    for n in 0..=10u64 {
        src.add_block(n, [u8::try_from(n & 0xff).expect("byte"); 32]);
    }
    src.add_event(2, shield(3, 2, 0));
    src.add_event(7, shield(3, 7, 1));

    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(64);
    let worker = IndexerWorker::new(Arc::clone(&src), tx);

    let mut per_tree_start: BTreeMap<u32, u64> = BTreeMap::new();
    per_tree_start.insert(0, 5);
    per_tree_start.insert(1, 5);

    let cfg = IndexerWorkerConfig {
        start_block: 0,
        poll_interval_secs: 1,
        chunk_blocks: 50,
        per_tree_start_blocks: per_tree_start,
        ..IndexerWorkerConfig::default()
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let mut received_blocks: Vec<u64> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    loop {
        if tokio::time::Instant::now() >= deadline || received_blocks.len() >= 2 {
            break;
        }
        match tokio::time::timeout(Duration::from_millis(1500), rx.recv()).await {
            Ok(Some(IndexerMessage::Event { event, .. })) => {
                if let RailgunEvent::Shield { block_number, .. } = event {
                    received_blocks.push(block_number);
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;

    assert_eq!(
        received_blocks,
        vec![2, 7],
        "tree 3 (not in floor map) must pass through every event; got {received_blocks:?}"
    );
}

/// Unshield events carry no `tree_number` and MUST pass through
/// regardless of `per_tree_start_blocks` content.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indexer_passes_through_unshield_events_unconditionally() {
    let src = Arc::new(PerTreeMockSource::new());
    for n in 0..=10u64 {
        src.add_block(n, [u8::try_from(n & 0xff).expect("byte"); 32]);
    }
    src.add_event(1, unshield(1));
    src.add_event(6, unshield(6));

    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(64);
    let worker = IndexerWorker::new(Arc::clone(&src), tx);

    let mut per_tree_start: BTreeMap<u32, u64> = BTreeMap::new();
    // High floors for every tree id that *could* match; Unshield has
    // no tree_number so the map is irrelevant.
    per_tree_start.insert(0, 1_000_000);
    per_tree_start.insert(1, 1_000_000);

    let cfg = IndexerWorkerConfig {
        start_block: 0,
        poll_interval_secs: 1,
        chunk_blocks: 50,
        per_tree_start_blocks: per_tree_start,
        ..IndexerWorkerConfig::default()
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let mut received_blocks: Vec<u64> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    loop {
        if tokio::time::Instant::now() >= deadline || received_blocks.len() >= 2 {
            break;
        }
        match tokio::time::timeout(Duration::from_millis(1500), rx.recv()).await {
            Ok(Some(IndexerMessage::Event { event, .. })) => {
                if let RailgunEvent::Unshield { block_number, .. } = event {
                    received_blocks.push(block_number);
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;

    assert_eq!(
        received_blocks,
        vec![1, 6],
        "Unshield events must pass through; got {received_blocks:?}"
    );
}
