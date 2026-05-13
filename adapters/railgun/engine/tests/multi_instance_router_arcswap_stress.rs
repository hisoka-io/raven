//! Concurrency stress on the multi-instance router's chain-tree
//! routing table (`ChainTreeRoutes = Arc<ArcSwap<Vec<...>>>`).
//!
//! Exercises three invariants under contention: reads see consistent
//! snapshots, concurrent `rcu` writers don't drop appends, and 50
//! readers don't deadlock under write pressure.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use raven_railgun_engine::orchestrator::ChainTreeRoutes;
use raven_railgun_engine::persistence::ConsumerEvent;
use tokio::sync::mpsc;

fn build_initial_routes(n: u32) -> (ChainTreeRoutes, Vec<mpsc::Receiver<ConsumerEvent>>) {
    let mut entries: Vec<(u32, mpsc::Sender<ConsumerEvent>)> = Vec::with_capacity(n as usize);
    let mut receivers: Vec<mpsc::Receiver<ConsumerEvent>> = Vec::with_capacity(n as usize);
    for tn in 0..n {
        let (tx, rx) = mpsc::channel::<ConsumerEvent>(16);
        entries.push((tn, tx));
        receivers.push(rx);
    }
    let cell = Arc::new(arc_swap::ArcSwap::from_pointee(entries));
    (cell, receivers)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn arcswap_routes_no_torn_reads_no_dropped_writes_under_50_readers_10_writers() {
    const N_INITIAL_ROUTES: u32 = 4;
    const N_READERS: usize = 50;
    const N_WRITERS: usize = 10;
    const APPENDS_PER_WRITER: usize = 25;
    const TEST_DEADLINE: Duration = Duration::from_secs(10);

    let (routes, _receivers) = build_initial_routes(N_INITIAL_ROUTES);

    let total_reads = Arc::new(AtomicU64::new(0));
    let torn_reads = Arc::new(AtomicU64::new(0));
    let stop_readers = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let mut reader_handles = Vec::with_capacity(N_READERS);
    for _ in 0..N_READERS {
        let routes = Arc::clone(&routes);
        let total_reads = Arc::clone(&total_reads);
        let torn_reads = Arc::clone(&torn_reads);
        let stop = Arc::clone(&stop_readers);
        reader_handles.push(tokio::spawn(async move {
            while !stop.load(Ordering::Acquire) {
                let snap = routes.load();
                let len = snap.len();
                if len < N_INITIAL_ROUTES as usize {
                    torn_reads.fetch_add(1, Ordering::Relaxed);
                }
                for i in 0..len {
                    let _ = snap.get(i).expect("snapshot index in range");
                }
                total_reads.fetch_add(1, Ordering::Relaxed);
                tokio::task::yield_now().await;
            }
        }));
    }

    let mut writer_handles = Vec::with_capacity(N_WRITERS);
    for w in 0..N_WRITERS {
        let routes = Arc::clone(&routes);
        writer_handles.push(tokio::spawn(async move {
            for i in 0..APPENDS_PER_WRITER {
                let tree_number = N_INITIAL_ROUTES + (w as u32) * 10_000 + (i as u32);
                let (tx, _rx) = mpsc::channel::<ConsumerEvent>(8);
                routes.rcu(|cur| {
                    let mut next: Vec<(u32, mpsc::Sender<ConsumerEvent>)> = (**cur).clone();
                    next.push((tree_number, tx.clone()));
                    next
                });
                tokio::task::yield_now().await;
            }
        }));
    }

    let writers_started = Instant::now();
    for h in writer_handles {
        let remaining = TEST_DEADLINE
            .checked_sub(writers_started.elapsed())
            .unwrap_or(Duration::from_millis(100));
        tokio::time::timeout(remaining, h)
            .await
            .expect("writer did not finish within deadline (deadlock?)")
            .expect("writer panicked");
    }

    stop_readers.store(true, Ordering::Release);
    for h in reader_handles {
        tokio::time::timeout(Duration::from_secs(2), h)
            .await
            .expect("reader did not finish within deadline (deadlock?)")
            .expect("reader panicked");
    }

    let final_snap = routes.load();
    let expected_final_len = N_INITIAL_ROUTES as usize + N_WRITERS * APPENDS_PER_WRITER;
    assert_eq!(
        final_snap.len(),
        expected_final_len,
        "final route count must reflect every concurrent write \
         (initial={N_INITIAL_ROUTES} + {N_WRITERS}*{APPENDS_PER_WRITER}={expected_final_len}); \
         a regression that dropped writes would surface as a smaller len"
    );

    // Sanity: every reader executed at least once. The two load-
    // bearing correctness invariants below (final_snap.len ==
    // expected_final_len for no-dropped-writes + torn == 0 for
    // no-torn-reads) are the actual correctness signals. The
    // earlier reads-count perf floor was host-dependent: under
    // nextest's parallel-test-binary scheduler the test runs
    // alongside 100+ concurrent processes and the read throughput
    // drops below any uniform floor we could pick. Starvation-by-
    // exclusive-lock would surface as `reads == 0` for many readers
    // (long blocking on lock contention) — the `> 0` floor is a
    // smoke test on that pathology.
    let reads = total_reads.load(Ordering::Relaxed);
    assert!(
        reads > 0,
        "expected at least one read across the readers; got {reads}. \
         A regression that introduced an exclusive lock on `load()` \
         would surface here as zero reads (every reader blocked on \
         a write-held lock for the test window)."
    );

    let torn = torn_reads.load(Ordering::Relaxed);
    assert_eq!(
        torn, 0,
        "ArcSwap snapshots are point-in-time consistent; observed {torn} torn reads. \
         A regression that re-introduced a non-Arc layer would surface as a \
         half-applied swap visible to readers."
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn arcswap_routes_read_only_baseline_completes_quickly() {
    const N_INITIAL_ROUTES: u32 = 4;
    const N_READERS: usize = 32;
    const READS_PER_READER: usize = 100;

    let (routes, _receivers) = build_initial_routes(N_INITIAL_ROUTES);
    let mut handles = Vec::with_capacity(N_READERS);
    for _ in 0..N_READERS {
        let routes = Arc::clone(&routes);
        handles.push(tokio::spawn(async move {
            for _ in 0..READS_PER_READER {
                let snap = routes.load();
                assert_eq!(snap.len(), N_INITIAL_ROUTES as usize);
            }
        }));
    }
    let started = Instant::now();
    for h in handles {
        h.await.expect("reader joined");
    }
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "read-only baseline should complete well under 5s; took {:?}",
        started.elapsed()
    );
}
