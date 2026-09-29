//! Waits that fail only when what they watch stops moving.
//!
//! A fixed window reds a correct run on a loaded box: a commit is fsync-bound and slows with every
//! other process writing. Progress is what separates a slow run from a stuck one.

// `#[path]`-included by several targets; each uses a different subset.
#![allow(dead_code, unreachable_pub, clippy::panic)]

use std::fmt::Debug;
use std::future::Future;
use std::path::Path;
use std::time::{Duration, SystemTime};

use raven_railgun_engine::orchestrator::PerInstanceHandles;
use raven_railgun_engine::persistence::{ConsumerEvent, ConsumerMetrics, InspirePersistence};

/// How long nothing a test watches may stay unchanged before the test fails.
pub const STALL: Duration = Duration::from_secs(120);

const POLL: Duration = Duration::from_millis(25);

/// Polls `probe` until it returns a result. Fails only once the progress it reports alongside
/// has not changed for [`STALL`], naming what stalled and where it stood.
pub async fn until_done_or_stalled<P, T>(what: &str, mut probe: impl FnMut() -> (P, Option<T>)) -> T
where
    P: PartialEq + Debug,
{
    let mut last: Option<P> = None;
    let mut unchanged_since = tokio::time::Instant::now();
    loop {
        let (progress, done) = probe();
        if let Some(done) = done {
            return done;
        }
        if last.as_ref() == Some(&progress) {
            assert!(
                unchanged_since.elapsed() < STALL,
                "{what}: stalled, nothing moved for {STALL:?}; last seen {progress:?}"
            );
        } else {
            last = Some(progress);
            unchanged_since = tokio::time::Instant::now();
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Awaits `fut` for as long as `progress` keeps changing; fails once it has not for [`STALL`].
/// A future with nothing of its own to show passes `|| ()` and gets the whole [`STALL`].
pub async fn await_or_stalled<F, P>(
    what: &str,
    fut: F,
    mut progress: impl FnMut() -> P,
) -> F::Output
where
    F: Future,
    P: PartialEq + Debug,
{
    tokio::pin!(fut);
    let mut last = progress();
    let mut unchanged_since = tokio::time::Instant::now();
    loop {
        if let Ok(out) = tokio::time::timeout(POLL, fut.as_mut()).await {
            return out;
        }
        let now = progress();
        if now == last {
            assert!(
                unchanged_since.elapsed() < STALL,
                "{what}: stalled, nothing moved for {STALL:?}; last seen {now:?}"
            );
        } else {
            last = now;
            unchanged_since = tokio::time::Instant::now();
        }
    }
}

/// Joins `task` as [`await_or_stalled`] does, failing if it panicked or was cancelled.
pub async fn join_or_stalled<T, P>(
    what: &str,
    task: tokio::task::JoinHandle<T>,
    progress: impl FnMut() -> P,
) -> T
where
    P: PartialEq + Debug,
{
    await_or_stalled(what, task, progress)
        .await
        .unwrap_or_else(|e| panic!("{what}: task did not run to completion: {e}"))
}

/// What a consumer shows while it works: its counters and the files it writes. The files are
/// what move during a commit, which changes no counter until it lands.
#[derive(Debug, PartialEq, Eq)]
pub struct ConsumerMotion {
    // Every field is a plain counter, so the rendering is a faithful key that names them all.
    metrics: String,
    files: DirMotion,
}

pub fn consumer_motion(
    metrics: &parking_lot::Mutex<ConsumerMetrics>,
    persistence: &InspirePersistence,
) -> ConsumerMotion {
    let m = *metrics.lock();
    ConsumerMotion {
        metrics: format!("{m:?}"),
        files: dir_motion(persistence.layout().root()),
    }
}

/// [`consumer_motion`] of every instance of a multi-instance boot.
pub fn fleet_motion(instances: &[PerInstanceHandles]) -> Vec<ConsumerMotion> {
    instances
        .iter()
        .map(|h| consumer_motion(&h.metrics, &h.persistence))
        .collect()
}

/// Joins a consumer task and returns what it returned.
pub async fn join_consumer<T>(
    what: &str,
    consumer: tokio::task::JoinHandle<T>,
    metrics: &parking_lot::Mutex<ConsumerMetrics>,
    persistence: &InspirePersistence,
) -> T {
    join_or_stalled(what, consumer, || consumer_motion(metrics, persistence)).await
}

/// Returns once the consumer has finished every event sent before this call, verifier and
/// deferred publish included. It takes events one at a time, and a heartbeat sets only the
/// chain-head and scan gauges, so the heartbeat landing is the barrier.
pub async fn drained(
    what: &str,
    sender: &tokio::sync::mpsc::Sender<ConsumerEvent>,
    metrics: &parking_lot::Mutex<ConsumerMetrics>,
    persistence: &InspirePersistence,
) {
    let (marker, scanned) = {
        let m = metrics.lock();
        (
            m.last_known_chain_head.wrapping_add(1),
            m.last_scanned_block,
        )
    };
    sender
        .send(ConsumerEvent::Heartbeat {
            chain_head: marker,
            scanned_through: scanned,
        })
        .await
        .unwrap_or_else(|_| panic!("{what}: consumer channel closed"));
    until_done_or_stalled(what, || {
        (
            consumer_motion(metrics, persistence),
            (metrics.lock().last_known_chain_head == marker).then_some(()),
        )
    })
    .await;
}

/// Aborts a consumer and waits for it to exit: abort lands at its next await, so a commit
/// already running still writes the data dir until then.
pub async fn abort_consumer<T>(
    what: &str,
    consumer: &mut tokio::task::JoinHandle<T>,
    metrics: &parking_lot::Mutex<ConsumerMetrics>,
    persistence: &InspirePersistence,
) {
    consumer.abort();
    let _cancelled_or_done =
        await_or_stalled(what, consumer, || consumer_motion(metrics, persistence)).await;
}

/// File count, total bytes and newest mtime under a directory.
#[derive(Debug, PartialEq, Eq, Default)]
pub struct DirMotion {
    files: u64,
    bytes: u64,
    newest: Option<SystemTime>,
}

pub fn dir_motion(root: &Path) -> DirMotion {
    let mut motion = DirMotion::default();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        // A commit renames and deletes as it goes, so an entry can vanish mid-walk.
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                pending.push(entry.path());
            } else {
                motion.files += 1;
                motion.bytes += meta.len();
                motion.newest = motion.newest.max(meta.modified().ok());
            }
        }
    }
    motion
}
