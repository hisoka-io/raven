//! The Layer 1 reorg window must stay usable at production chunk spans.
//!
//! Three invariants: retention is bounded by ENTRY COUNT (not block
//! distance, which a 499-block tick collapses to a single entry); the scan
//! cursor never advances past a block whose hash could not be cached; and a
//! window miss fails closed instead of masquerading as a divergence.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::needless_continue,
    clippy::match_same_arms
)]

use async_trait::async_trait;
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use raven_railgun_core::RailgunEvent;
use raven_railgun_indexer::{
    detect_reorg_layer1, ChainSource, IndexerError, IndexerMessage, IndexerWorker,
    IndexerWorkerConfig, Result,
};
use raven_railgun_indexer::{encode_reorg_window, MAX_REORG_BLOCKS};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::mpsc;

fn snap() -> &'static Snapshotter {
    static SNAP: OnceLock<Snapshotter> = OnceLock::new();
    SNAP.get_or_init(|| {
        let recorder = DebuggingRecorder::new();
        let s = recorder.snapshotter();
        let _ = metrics::set_global_recorder(recorder);
        s
    })
}

const TIP_HASH_FAILED: &str = "raven_railgun_indexer_reorg_window_tip_hash_failed_total";

fn counter_by_name(snap: &Snapshotter, name: &str) -> u64 {
    for (composite_key, _, _, value) in snap.snapshot().into_vec() {
        if format!("{composite_key:?}").contains(name) {
            if let DebugValue::Counter(v) = value {
                return v;
            }
        }
    }
    0
}

#[derive(Debug, Default)]
struct WindowSource {
    inner: Mutex<WindowInner>,
}

#[derive(Debug, Default)]
struct WindowInner {
    chain: BTreeMap<u64, [u8; 32]>,
    events: BTreeMap<u64, Vec<RailgunEvent>>,
    latest: u64,
    block_hash_denied_at: Option<u64>,
    lowest_block_hash_queried: Option<u64>,
}

impl WindowSource {
    fn with_chain(through: u64) -> Self {
        let src = Self::default();
        for n in 0..=through {
            src.set_block(n, canonical_hash(n));
        }
        src
    }
    fn set_block(&self, n: u64, hash: [u8; 32]) {
        let mut g = self.inner.lock().expect("lock");
        g.chain.insert(n, hash);
        g.latest = g.latest.max(n);
    }
    fn add_unshield_at(&self, n: u64) {
        let mut g = self.inner.lock().expect("lock");
        g.events.entry(n).or_default().push(unshield_at(n));
    }
    fn reorg(&self, from: u64, to: u64, new_hash: [u8; 32]) {
        let mut g = self.inner.lock().expect("lock");
        for n in from..=to {
            g.chain.insert(n, new_hash);
        }
    }
    fn deny_block_hash_at(&self, n: u64) {
        self.inner.lock().expect("lock").block_hash_denied_at = Some(n);
    }
    fn allow_block_hash_everywhere(&self) {
        self.inner.lock().expect("lock").block_hash_denied_at = None;
    }
    fn lowest_block_hash_queried(&self) -> Option<u64> {
        self.inner.lock().expect("lock").lowest_block_hash_queried
    }
}

/// Tree-less so the per-tree floor cannot suppress it; the height is the identity.
fn unshield_at(block_number: u64) -> RailgunEvent {
    RailgunEvent::Unshield {
        block_number,
        tx_hash: canonical_hash(block_number),
        to: [0x11; 20],
        token: [0x22; 32],
        amount: 1,
        fee: 0,
    }
}

fn unshield_height(event: &RailgunEvent) -> u64 {
    match event {
        RailgunEvent::Unshield { block_number, .. } => *block_number,
        other => panic!("fixture emits only Unshield; got {other:?}"),
    }
}

fn canonical_hash(n: u64) -> [u8; 32] {
    let mut h = [0xaa_u8; 32];
    h[..8].copy_from_slice(&n.to_le_bytes());
    h
}

#[async_trait]
impl ChainSource for WindowSource {
    async fn latest_block(&self) -> Result<u64> {
        Ok(self.inner.lock().expect("lock").latest)
    }
    async fn events_in_range(&self, from: u64, to: u64) -> Result<Vec<RailgunEvent>> {
        let g = self.inner.lock().expect("lock");
        Ok(g.events
            .range(from..=to)
            .flat_map(|(_, evs)| evs.iter().cloned())
            .collect())
    }
    async fn root_history(
        &self,
        _tree: u32,
        _root: [u8; 32],
        _at: Option<alloy::eips::BlockId>,
    ) -> Result<bool> {
        Ok(true)
    }
    async fn block_hash(&self, n: u64) -> Result<[u8; 32]> {
        let mut g = self.inner.lock().expect("lock");
        g.lowest_block_hash_queried = Some(g.lowest_block_hash_queried.map_or(n, |low| low.min(n)));
        if g.block_hash_denied_at == Some(n) {
            return Err(IndexerError::Rpc(format!(
                "WindowSource: block_hash({n}) denied"
            )));
        }
        g.chain
            .get(&n)
            .copied()
            .ok_or_else(|| IndexerError::Rpc(format!("block {n} not in mock chain")))
    }
    async fn merkle_root(&self, _at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        Err(IndexerError::Rpc(
            "WindowSource: merkle_root not used by these tests".into(),
        ))
    }
    async fn active_tree_number(&self, _at: Option<alloy::eips::BlockId>) -> Result<u32> {
        Err(IndexerError::Rpc(
            "WindowSource: active_tree_number not used by these tests".into(),
        ))
    }
}

/// Ticks advance a whole chunk, so a window capped at 3 ENTRIES must retain
/// the last three chunk boundaries. Capping by block distance leaves one
/// entry and every later divergence surfaces as `ReorgTooDeep`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn window_retains_entries_when_chunk_span_exceeds_window_depth() {
    let src = Arc::new(WindowSource::with_chain(120));
    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(64);
    let worker = IndexerWorker::new(Arc::clone(&src), tx);
    let cfg = IndexerWorkerConfig {
        start_block: 0,
        poll_interval_secs: 1,
        chunk_blocks: 30,
        reorg_window_entries: 3,
        ..IndexerWorkerConfig::default()
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut caught_up = false;
    while tokio::time::Instant::now() < deadline && !caught_up {
        match tokio::time::timeout(Duration::from_millis(1500), rx.recv()).await {
            Ok(Some(IndexerMessage::Heartbeat {
                scanned_through_block,
                ..
            })) => caught_up = scanned_through_block == 120,
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    assert!(
        caught_up,
        "worker must reach the chain tip before the reorg"
    );

    src.reorg(91, 120, [0xff; 32]);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut got_reorg = None;
    while tokio::time::Instant::now() < deadline && got_reorg.is_none() {
        match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
            Ok(Some(IndexerMessage::Reorg { height })) => got_reorg = Some(height),
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;

    assert_eq!(
        got_reorg,
        Some(90),
        "three retained chunk boundaries (60, 90, 120) must let the walk-back \
         land on the surviving tip 90"
    );
}

/// An uncacheable tip hash leaves a hole the reorg walk-back can never
/// cross, so the cursor must not step over it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cursor_holds_when_tip_hash_is_uncacheable() {
    let s = snap();
    let before = counter_by_name(s, TIP_HASH_FAILED);

    let src = Arc::new(WindowSource::with_chain(120));
    src.deny_block_hash_at(30);
    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(64);
    let worker = IndexerWorker::new(Arc::clone(&src), tx);
    let cfg = IndexerWorkerConfig {
        start_block: 0,
        poll_interval_secs: 1,
        chunk_blocks: 30,
        ..IndexerWorkerConfig::default()
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut watermarks = Vec::new();
    while tokio::time::Instant::now() < deadline && watermarks.len() < 3 {
        match tokio::time::timeout(Duration::from_millis(1500), rx.recv()).await {
            Ok(Some(IndexerMessage::Heartbeat {
                scanned_through_block,
                ..
            })) => watermarks.push(scanned_through_block),
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;

    assert!(
        watermarks.len() >= 3,
        "worker must keep heartbeating while it is stuck; got {watermarks:?}"
    );
    assert!(
        watermarks.iter().all(|&w| w == 0),
        "the scan watermark must not pass block 30 while its hash is uncacheable; \
         got {watermarks:?}"
    );
    let after = counter_by_name(s, TIP_HASH_FAILED);
    assert!(
        after > before,
        "the held tick must be counted; before={before} after={after}"
    );
}

/// Collect until `want_heartbeats` watermarks arrive or the deadline expires,
/// returning every event seen alongside those watermarks.
async fn drain_until_heartbeats(
    rx: &mut mpsc::Receiver<IndexerMessage>,
    want_heartbeats: usize,
    budget: Duration,
) -> (Vec<RailgunEvent>, Vec<u64>) {
    let deadline = tokio::time::Instant::now() + budget;
    let mut events = Vec::new();
    let mut watermarks = Vec::new();
    while tokio::time::Instant::now() < deadline && watermarks.len() < want_heartbeats {
        match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
            Ok(Some(IndexerMessage::Event { event, .. })) => events.push(event),
            Ok(Some(IndexerMessage::Heartbeat {
                scanned_through_block,
                ..
            })) => watermarks.push(scanned_through_block),
            Ok(Some(IndexerMessage::Reorg { height })) => {
                panic!("no reorg expected in this fixture; got Reorg({height})")
            }
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    (events, watermarks)
}

/// Delivery must follow the tip-hash cache, not precede it: a chunk emitted
/// before the hold is replayed in full on every held tick.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_chunk_delivers_its_events_exactly_once_once_the_tip_hash_returns() {
    let src = Arc::new(WindowSource::with_chain(60));
    src.add_unshield_at(5);
    src.add_unshield_at(20);
    src.deny_block_hash_at(30);

    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(256);
    let worker = IndexerWorker::new(Arc::clone(&src), tx);
    let cfg = IndexerWorkerConfig {
        start_block: 0,
        poll_interval_secs: 1,
        chunk_blocks: 30,
        ..IndexerWorkerConfig::default()
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let (held_events, held_marks) =
        drain_until_heartbeats(&mut rx, 3, Duration::from_secs(15)).await;
    assert!(
        held_marks.len() >= 3,
        "worker must keep heartbeating while it is stuck; got {held_marks:?}"
    );
    assert!(
        held_marks.iter().all(|&w| w == 0),
        "the watermark must not pass block 30 while its hash is uncacheable; got {held_marks:?}"
    );
    assert!(
        held_events.is_empty(),
        "a chunk whose tip hash is uncacheable must not be delivered; got {:?}",
        held_events.iter().map(unshield_height).collect::<Vec<_>>()
    );

    src.allow_block_hash_everywhere();

    let (released_events, released_marks) =
        drain_until_heartbeats(&mut rx, 4, Duration::from_secs(15)).await;
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;

    let delivered: Vec<u64> = held_events
        .iter()
        .chain(released_events.iter())
        .map(unshield_height)
        .collect();
    assert_eq!(
        delivered,
        vec![5, 20],
        "both chunk events must land exactly once after the hold clears; \
         watermarks={released_marks:?}"
    );
    assert!(
        released_marks.iter().any(|&w| w >= 30),
        "the watermark must advance past the chunk once its hash is cacheable; \
         got {released_marks:?}"
    );
}

/// Entry retention and reorg depth are different units. A window capped at N
/// ENTRIES spans N chunks of blocks, so an unbounded walk-back can return a
/// surviving tip thousands of blocks below the cursor and truncate that far.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn walk_back_refuses_a_surviving_tip_beyond_the_block_depth_bound() {
    let src = WindowSource::with_chain(2_996);
    let mut cache = BTreeMap::new();
    // Chunk boundaries at the production span: 5 entries, 1_996 blocks apart end to end.
    for n in [1_000_u64, 1_499, 1_998, 2_497, 2_996] {
        cache.insert(n, canonical_hash(n));
    }
    src.reorg(1_500, 2_996, [0xff; 32]);

    let outcome = detect_reorg_layer1(&src, &cache, 2_996, MAX_REORG_BLOCKS).await;

    match outcome {
        Err(IndexerError::ReorgTooDeep(at)) => assert_eq!(at, 2_996),
        Ok(Some(height)) => panic!(
            "walk-back returned surviving tip {height}, {} blocks below cursor 2996; \
             MAX_REORG_BLOCKS={MAX_REORG_BLOCKS} must bound it",
            2_996 - height
        ),
        Ok(None) => panic!("the chain diverged at the cursor; Ok(None) is wrong"),
        Err(other) => panic!("expected ReorgTooDeep; got {other:?}"),
    }
}

/// The entry cap and the depth bound move independently: a window holding
/// entries inside the bound still resolves its surviving tip.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn walk_back_accepts_a_surviving_tip_inside_the_block_depth_bound() {
    let src = WindowSource::with_chain(2_996);
    let mut cache = BTreeMap::new();
    for n in [2_996_u64 - MAX_REORG_BLOCKS, 2_900, 2_996] {
        cache.insert(n, canonical_hash(n));
    }
    src.reorg(2_901, 2_996, [0xff; 32]);

    let outcome = detect_reorg_layer1(&src, &cache, 2_996, MAX_REORG_BLOCKS).await;

    assert_eq!(
        outcome.expect("a divergence inside the bound must resolve"),
        Some(2_900),
        "the newest cached height still canonical is the surviving tip"
    );
}

/// The worker must be able to REACH the window miss. Guarding the walk-back on
/// `contains_key(cursor)` skips the check exactly when the window cannot vouch
/// for the cursor, so a reorg-while-down above the window top is scanned across
/// in silence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_rewinds_to_the_newest_verifiable_height_on_a_window_miss() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("window_miss.bin");
    let seeded: BTreeMap<u64, [u8; 32]> = [30_u64, 60, 90]
        .into_iter()
        .map(|n| (n, canonical_hash(n)))
        .collect();
    std::fs::write(&path, encode_reorg_window(&seeded)).expect("seed sidecar");

    let src = Arc::new(WindowSource::with_chain(200));
    // Reorged while down, entirely above the window top, so the restart
    // stale-check on height 90 still matches and no rebuild fires.
    src.reorg(91, 200, [0xff; 32]);

    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(256);
    let worker = IndexerWorker::new(Arc::clone(&src), tx);
    let cfg = IndexerWorkerConfig {
        // Engine watermark ahead of every cached boundary: the hole.
        start_block: 100,
        poll_interval_secs: 1,
        chunk_blocks: 30,
        reorg_window_path: Some(path.clone()),
        ..IndexerWorkerConfig::default()
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut got_reorg = None;
    let mut marks_after_reorg = Vec::new();
    while tokio::time::Instant::now() < deadline && marks_after_reorg.len() < 3 {
        match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
            Ok(Some(IndexerMessage::Reorg { height })) => got_reorg = Some(height),
            Ok(Some(IndexerMessage::Heartbeat {
                scanned_through_block,
                ..
            })) => {
                if got_reorg.is_some() {
                    marks_after_reorg.push(scanned_through_block);
                }
            }
            Ok(Some(IndexerMessage::Event { event, .. })) => {
                panic!("fixture has no events; got {event:?}")
            }
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;

    assert_eq!(
        got_reorg,
        Some(90),
        "a cursor the window cannot vouch for must rewind to the newest cached \
         height below it, not scan across the gap"
    );
    assert!(
        marks_after_reorg.iter().any(|&w| w > 90),
        "the rewind must not jam the scan; got {marks_after_reorg:?}"
    );
}

/// The restart rebuild walks one entry per block, so it is bounded by BOTH the
/// depth bound and the entry cap. Spending the depth bound in RPC calls when the
/// cap will evict all but a handful is restart amplification against the node.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_rebuild_never_reaches_below_the_entry_cap() {
    const ENTRY_CAP: usize = 4;
    const TOP: u64 = 1_000;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rebuild_span.bin");
    // Stale top hash: forces the restart rebuild.
    let seeded: BTreeMap<u64, [u8; 32]> = [(TOP, [0x01_u8; 32])].into_iter().collect();
    std::fs::write(&path, encode_reorg_window(&seeded)).expect("seed sidecar");

    let src = Arc::new(WindowSource::with_chain(1_100));
    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(256);
    let worker = IndexerWorker::new(Arc::clone(&src), tx);
    let cfg = IndexerWorkerConfig {
        start_block: TOP,
        poll_interval_secs: 1,
        chunk_blocks: 30,
        reorg_window_path: Some(path),
        reorg_window_entries: ENTRY_CAP,
        reorg_max_depth_blocks: 64,
        ..IndexerWorkerConfig::default()
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut heartbeats = 0_u32;
    while tokio::time::Instant::now() < deadline && heartbeats < 2 {
        match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
            Ok(Some(IndexerMessage::Heartbeat { .. })) => heartbeats += 1,
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;

    assert!(heartbeats >= 2, "worker must run past the restart rebuild");
    let floor = TOP - ENTRY_CAP as u64;
    assert_eq!(
        src.lowest_block_hash_queried(),
        Some(floor),
        "the rebuild must stop at the entry cap ({ENTRY_CAP} entries below {TOP}), \
         not spend the {}-block depth bound on hashes the cap evicts",
        64
    );
}

/// A window miss and a divergence are indistinguishable from the walk-back's
/// point of view, so substituting a zero hash turns a miss into a leaf-deleting
/// `Reorg`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detect_reorg_layer1_fails_closed_on_window_miss() {
    let src = WindowSource::with_chain(105);
    let mut cache = BTreeMap::new();
    for n in 100..=104u64 {
        cache.insert(n, canonical_hash(n));
    }

    let outcome = detect_reorg_layer1(&src, &cache, 105, MAX_REORG_BLOCKS).await;

    let err = match outcome {
        Err(e) => e,
        Ok(other) => panic!("a window miss must fail closed; got Ok({other:?})"),
    };
    match err {
        IndexerError::ReorgWindowMiss {
            cursor,
            window_len,
            window_oldest,
            window_newest,
        } => {
            assert_eq!(cursor, 105);
            assert_eq!(window_len, 5);
            assert_eq!(window_oldest, Some(100));
            assert_eq!(window_newest, Some(104));
        }
        other => panic!("expected ReorgWindowMiss; got {other:?}"),
    }
}
