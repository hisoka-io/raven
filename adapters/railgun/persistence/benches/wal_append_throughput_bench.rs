//! WAL append throughput bench (`#[ignore]`-gated).
//!
//! Synced `append` against `append_deferred` plus one `sync` per batch of 1, 64 and
//! 1,024 frames, each over the same 1,024 `AppendLeaf` frames (3-seed median).
//! Run: `cargo test --release -p raven-railgun-persistence --bench wal_append_throughput_bench -- --ignored --nocapture`

#![allow(
    clippy::expect_used,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing
)]

use std::time::{Duration, Instant};

use raven_railgun_persistence::{StoreLayout, Wal, WalEntryPayload};

const FRAMES: usize = 1_024;
const SEEDS: usize = 3;
const BATCHES: &[usize] = &[1, 64, 1_024];

fn payload_for(i: usize) -> WalEntryPayload {
    let leaf_index = (i % 65_536) as u32;
    let mut commitment = [0u8; 32];
    commitment[28..32].copy_from_slice(&leaf_index.to_be_bytes());
    WalEntryPayload::AppendLeaf {
        tree_number: 0,
        leaf_index,
        commitment,
    }
}

/// `batch == None` is one synced `append` per frame.
fn timed_run(batch: Option<usize>) -> Duration {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let wal = Wal::open(&layout, None).expect("open");
    let started = Instant::now();
    for i in 0..FRAMES {
        let marker = 100 + i as u64;
        match batch {
            None => {
                wal.append(&payload_for(i), marker).expect("append");
            }
            Some(b) => {
                wal.append_deferred(&payload_for(i), marker)
                    .expect("append_deferred");
                if (i + 1) % b == 0 {
                    wal.sync().expect("sync");
                }
            }
        }
    }
    wal.sync().expect("final sync");
    let elapsed = started.elapsed();
    assert_eq!(wal.next_seq(), FRAMES as u64);
    elapsed
}

fn median_of(batch: Option<usize>) -> Duration {
    let mut timings: Vec<Duration> = (0..SEEDS).map(|_| timed_run(batch)).collect();
    timings.sort();
    timings[SEEDS / 2]
}

fn report(mode: &str, med: Duration) -> f64 {
    let rate = FRAMES as f64 / med.as_secs_f64();
    eprintln!(
        "wal_append: mode={mode} frames={FRAMES} 3-seed-median={med:?} rate={rate:.0}/s \
         per-frame={:.1}us",
        med.as_secs_f64() * 1e6 / FRAMES as f64
    );
    rate
}

#[test]
#[ignore = "10-20 s in release at load 17-19, nearly all of it the fsyncs of the synced and \
            batch-1 modes; fsync latency makes it noisy, so it is run by hand, not per push. \
            Trigger: changing Wal::append, Wal::append_deferred, Wal::sync or the WAL frame \
            layout."]
fn wal_append_synced_vs_deferred_at_batch_1_64_1024() {
    let synced = report("synced", median_of(None));
    for &b in BATCHES {
        let rate = report(&format!("deferred-batch-{b}"), median_of(Some(b)));
        eprintln!(
            "wal_append: deferred-batch-{b} / synced = {:.1}x",
            rate / synced
        );
    }
}
