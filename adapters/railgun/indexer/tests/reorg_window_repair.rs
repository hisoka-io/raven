//! The Layer 1 reorg window must stay usable at production chunk spans.
//!
//! Retention is bounded by ENTRY COUNT (not block distance, which a 499-block
//! tick collapses to a single entry) while the walk-back is bounded by BLOCK
//! DISTANCE; the scan cursor never advances past a block whose hash could not
//! be cached; a window miss fails closed instead of masquerading as a
//! divergence, and an ordinary restart is not a miss; and a check the worker
//! cannot resolve still heartbeats rather than freezing the lag gauge.

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
use raven_railgun_indexer::{
    encode_reorg_window, load_reorg_window, MAX_REORG_BLOCKS, SCAN_CHUNK_BLOCKS,
};
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
const REORG_CHECK_FAILED: &str = "raven_railgun_indexer_reorg_check_failed_total";

/// Reads once: `snapshot()` consumes what it reports, so a second call returns
/// the increments since the first, not the running total.
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
    events_denied: bool,
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
    fn deny_events(&self) {
        self.inner.lock().expect("lock").events_denied = true;
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
        if g.events_denied {
            return Err(IndexerError::Rpc(format!(
                "WindowSource: events_in_range({from}, {to}) denied"
            )));
        }
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
    let cursor = SCAN_CHUNK_BLOCKS * 6;
    let src = WindowSource::with_chain(cursor);
    let mut cache = BTreeMap::new();
    // Chunk boundaries at the production span, reaching further back than the bound.
    for chunk in 0..=6 {
        let n = SCAN_CHUNK_BLOCKS * chunk;
        cache.insert(n, canonical_hash(n));
    }
    // Surviving tip one block below the oldest entry still inside the bound.
    let diverged_from = cursor - MAX_REORG_BLOCKS - SCAN_CHUNK_BLOCKS + 1;
    src.reorg(diverged_from, cursor, [0xff; 32]);

    let outcome = detect_reorg_layer1(&src, &cache, cursor, MAX_REORG_BLOCKS).await;

    match outcome {
        Err(IndexerError::ReorgTooDeep(at)) => assert_eq!(at, cursor),
        Ok(Some(height)) => panic!(
            "walk-back returned surviving tip {height}, {} blocks below cursor {cursor}; \
             MAX_REORG_BLOCKS={MAX_REORG_BLOCKS} must bound it",
            cursor - height
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

#[derive(Debug, Default)]
struct Traffic {
    reorgs: Vec<u64>,
    watermarks: Vec<u64>,
    events: usize,
}

/// Drain until `stop` observes what the caller is waiting for, or the budget
/// expires. The 100ms recv timeout re-evaluates `stop` on a silent channel, so a
/// stop condition reading a metrics counter still makes progress.
async fn drain_while(
    rx: &mut mpsc::Receiver<IndexerMessage>,
    budget: Duration,
    mut stop: impl FnMut(&Traffic) -> bool,
) -> Traffic {
    let deadline = tokio::time::Instant::now() + budget;
    let mut seen = Traffic::default();
    while tokio::time::Instant::now() < deadline {
        if stop(&seen) {
            break;
        }
        match tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
            Ok(Some(IndexerMessage::Reorg { height })) => seen.reorgs.push(height),
            Ok(Some(IndexerMessage::Heartbeat {
                scanned_through_block,
                ..
            })) => seen.watermarks.push(scanned_through_block),
            Ok(Some(IndexerMessage::Event { .. })) => seen.events += 1,
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    seen
}

/// The window caches chunk tips; the resume cursor is the consumer's applied
/// height, which is not a chunk boundary. Reading its absence as a divergence
/// makes every ordinary restart truncate leaves it should have kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn benign_restart_below_the_window_top_emits_no_reorg() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("benign_restart.bin");
    let tips: BTreeMap<u64, [u8; 32]> = [
        SCAN_CHUNK_BLOCKS,
        SCAN_CHUNK_BLOCKS * 2,
        SCAN_CHUNK_BLOCKS * 3,
    ]
    .into_iter()
    .map(|n| (n, canonical_hash(n)))
    .collect();
    std::fs::write(&path, encode_reorg_window(&tips)).expect("seed sidecar");

    // Mid-chunk resume cursor: the chain is exactly what the prior run scanned.
    let resume_cursor = SCAN_CHUNK_BLOCKS * 2 + 236;
    let src = Arc::new(WindowSource::with_chain(SCAN_CHUNK_BLOCKS * 4));
    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(256);
    let worker = IndexerWorker::new(Arc::clone(&src), tx);
    let cfg = IndexerWorkerConfig {
        start_block: resume_cursor,
        poll_interval_secs: 1,
        reorg_window_path: Some(path),
        ..IndexerWorkerConfig::default()
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let seen = drain_while(&mut rx, Duration::from_secs(15), |t| {
        !t.reorgs.is_empty() || t.watermarks.iter().any(|&w| w > resume_cursor)
    })
    .await;
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;

    assert!(
        seen.reorgs.is_empty(),
        "an unchanged chain must not look like a reorg on restart; got {:?}",
        seen.reorgs
    );
    assert!(
        seen.watermarks.iter().any(|&w| w > resume_cursor),
        "the scan must advance past the resume cursor {resume_cursor}; got {:?}",
        seen.watermarks
    );
}

/// A divergence past the walk-back bound is unresolvable, but the worker still
/// owns the liveness signal: without a heartbeat the lag gauge holds its last
/// healthy value while ingestion has permanently stopped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_divergence_past_the_walk_back_bound_keeps_heartbeating_and_counts() {
    let s = snap();
    let top = SCAN_CHUNK_BLOCKS * 6;
    let src = Arc::new(WindowSource::with_chain(top));
    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(256);
    let worker = IndexerWorker::new(Arc::clone(&src), tx);
    let cfg = IndexerWorkerConfig {
        start_block: 0,
        poll_interval_secs: 1,
        ..IndexerWorkerConfig::default()
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let caught_up = drain_while(&mut rx, Duration::from_secs(30), |t| {
        t.watermarks.contains(&top)
    })
    .await;
    assert!(
        caught_up.watermarks.contains(&top),
        "worker must reach the chain tip before the divergence; got {:?}",
        caught_up.watermarks
    );

    let before = counter_by_name(s, REORG_CHECK_FAILED);
    // Surviving tip further below the cursor than the bound allows, so no cached
    // entry within the bound can be the answer.
    src.reorg(top - MAX_REORG_BLOCKS - SCAN_CHUNK_BLOCKS, top, [0xff; 32]);

    let mut after = before;
    let refused = drain_while(&mut rx, Duration::from_secs(15), |_| {
        after = after.max(counter_by_name(s, REORG_CHECK_FAILED));
        after > before
    })
    .await;
    assert!(
        after > before,
        "an unresolvable divergence must be counted; before={before} after={after}"
    );

    let still_live = drain_while(&mut rx, Duration::from_secs(15), |t| {
        t.watermarks.len() >= 2
    })
    .await;
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;

    assert!(
        still_live.watermarks.len() >= 2,
        "the worker must keep heartbeating while it cannot resolve the divergence; \
         got {:?} after the refusal (and {:?} before it)",
        still_live.watermarks,
        refused.watermarks
    );
    assert!(
        refused.reorgs.is_empty() && still_live.reorgs.is_empty(),
        "no surviving height is derivable, so no Reorg may be emitted; got {:?} / {:?}",
        refused.reorgs,
        still_live.reorgs
    );
}

/// Second instance of the same liveness defect: an events fetch that keeps
/// failing must still beat, or the lag gauge holds its last healthy value while
/// nothing is being ingested.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_events_fetch_keeps_heartbeating_against_a_held_cursor() {
    let src = Arc::new(WindowSource::with_chain(120));
    src.deny_events();
    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(256);
    let worker = IndexerWorker::new(Arc::clone(&src), tx);
    let cfg = IndexerWorkerConfig {
        start_block: 0,
        poll_interval_secs: 1,
        chunk_blocks: 30,
        ..IndexerWorkerConfig::default()
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let seen = drain_while(&mut rx, Duration::from_secs(15), |t| {
        t.watermarks.len() >= 3
    })
    .await;
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;

    assert!(
        seen.watermarks.len() >= 3,
        "the worker must keep heartbeating while every events fetch fails; got {:?}",
        seen.watermarks
    );
    assert!(
        seen.watermarks.iter().all(|&w| w == 0),
        "the cursor must hold while no chunk can be fetched; got {:?}",
        seen.watermarks
    );
    assert_eq!(
        seen.events, 0,
        "a failed fetch must deliver nothing; got {} events",
        seen.events
    );
}

/// The same catch-all swallows an RPC failure inside the reorg check, which is
/// the mundane way production reaches it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_rpc_failure_in_the_reorg_check_keeps_heartbeating_and_counts() {
    let s = snap();
    let src = Arc::new(WindowSource::with_chain(120));
    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(256);
    let worker = IndexerWorker::new(Arc::clone(&src), tx);
    let cfg = IndexerWorkerConfig {
        start_block: 0,
        poll_interval_secs: 1,
        chunk_blocks: 30,
        ..IndexerWorkerConfig::default()
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let caught_up = drain_while(&mut rx, Duration::from_secs(15), |t| {
        t.watermarks.contains(&120)
    })
    .await;
    assert!(
        caught_up.watermarks.contains(&120),
        "worker must reach the chain tip first; got {:?}",
        caught_up.watermarks
    );

    let before = counter_by_name(s, REORG_CHECK_FAILED);
    src.deny_block_hash_at(120);

    let mut after = before;
    let denied = drain_while(&mut rx, Duration::from_secs(15), |_| {
        after = after.max(counter_by_name(s, REORG_CHECK_FAILED));
        after > before
    })
    .await;
    assert!(
        after > before,
        "a failed reorg check must be counted; before={before} after={after}"
    );

    let still_live = drain_while(&mut rx, Duration::from_secs(15), |t| {
        t.watermarks.len() >= 2
    })
    .await;
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;

    assert!(
        still_live.watermarks.len() >= 2,
        "the worker must keep heartbeating while the cursor hash is unavailable; \
         got {:?} after the failure (and {:?} before it)",
        still_live.watermarks,
        denied.watermarks
    );
}

/// Clearing the window on an unresolvable miss disables Layer 1 detection until
/// a fresh tip is cached, and persists that blind state. Refill it instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_window_miss_with_nothing_below_the_cursor_refills_the_window() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("miss_refill.bin");
    // Every cached tip sits ABOVE the resume cursor, so no verifiable height
    // exists below it.
    let tips: BTreeMap<u64, [u8; 32]> = [1_500_u64, 1_999]
        .into_iter()
        .map(|n| (n, canonical_hash(n)))
        .collect();
    std::fs::write(&path, encode_reorg_window(&tips)).expect("seed sidecar");

    let resume_cursor = 1_000_u64;
    let src = Arc::new(WindowSource::with_chain(2_500));
    // Denies the startup seed for the cursor, which is what leaves the miss
    // reachable at all.
    src.deny_block_hash_at(resume_cursor);
    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(256);
    let worker = IndexerWorker::new(Arc::clone(&src), tx);
    let entry_cap = 256_usize;
    let cfg = IndexerWorkerConfig {
        start_block: resume_cursor,
        poll_interval_secs: 1,
        reorg_window_path: Some(path.clone()),
        reorg_window_entries: entry_cap,
        ..IndexerWorkerConfig::default()
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });

    let seen = drain_while(&mut rx, Duration::from_secs(20), |t| {
        !t.reorgs.is_empty() || t.watermarks.iter().any(|&w| w > resume_cursor)
    })
    .await;
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;

    assert!(
        seen.reorgs.is_empty(),
        "no verifiable height exists, so no Reorg may be emitted; got {:?}",
        seen.reorgs
    );
    let span = u64::try_from(entry_cap).expect("entry cap fits u64");
    assert_eq!(
        src.lowest_block_hash_queried(),
        Some(resume_cursor - span),
        "the window must be refilled from RPC below the cursor, not cleared"
    );
    let persisted = load_reorg_window(&path).expect("sidecar loads");
    assert!(
        persisted.keys().any(|&h| h < resume_cursor),
        "the refilled window must reach below the cursor on disk; got {:?}",
        persisted.keys().collect::<Vec<_>>()
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
