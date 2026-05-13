//! WAL replay scaling bench (`#[ignore]`-gated).
//!
//! Measures `Wal::replay()` wall-clock at 1k/10k/100k entries (3-seed median).
//! Run: `cargo test --release -p raven-railgun-persistence --test wal_replay_scaling_bench -- --ignored --nocapture`

#![allow(
    clippy::expect_used,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::indexing_slicing,
    clippy::uninlined_format_args
)]

use std::time::{Duration, Instant};

use raven_railgun_persistence::{StoreLayout, Wal, WalEntryPayload};

const SEEDS: usize = 3;
const ENTRY_COUNTS: &[usize] = &[1_000, 10_000, 100_000];

fn payload_for(seq: usize) -> WalEntryPayload {
    let leaf_index = (seq % 65_536) as u32;
    let mut commitment = [0u8; 32];
    commitment[28..32].copy_from_slice(&leaf_index.to_be_bytes());
    commitment[31] |= 1;
    WalEntryPayload::AppendLeaf {
        tree_number: 0,
        leaf_index,
        commitment,
    }
}

fn seed_wal(layout: &StoreLayout, n_entries: usize) {
    let wal = Wal::open(layout, None).expect("wal open");
    for i in 0..n_entries {
        let payload = payload_for(i);
        wal.append(&payload, 100 + i as u64).expect("wal append");
    }
}

fn measured_replay(layout: &StoreLayout) -> (Duration, usize) {
    let wal = Wal::open(layout, None).expect("wal reopen");
    let started = Instant::now();
    let replay = wal.replay().expect("wal replay");
    let elapsed = started.elapsed();
    (elapsed, replay.entries.len())
}

fn median(timings: &mut [Duration]) -> Duration {
    timings.sort();
    timings[timings.len() / 2]
}

#[test]
#[ignore = "WAL replay scaling sweep; ~10s wall at 100k entries x 3 seeds"]
fn wal_replay_scales_linearly_at_1k_10k_100k() {
    eprintln!(
        "wal_replay_scaling: SEEDS={} ENTRY_COUNTS={:?}",
        SEEDS, ENTRY_COUNTS
    );

    for &n in ENTRY_COUNTS {
        let mut timings: Vec<Duration> = Vec::with_capacity(SEEDS);
        let mut last_count = 0usize;

        for seed in 0..SEEDS {
            let dir = tempfile::tempdir().expect("tempdir");
            let layout = StoreLayout::open(dir.path()).expect("layout");

            let seed_start = Instant::now();
            seed_wal(&layout, n);
            let seed_elapsed = seed_start.elapsed();

            let (replay_elapsed, count) = measured_replay(&layout);
            assert_eq!(count, n, "replay must surface every appended entry");
            last_count = count;

            eprintln!(
                "wal_replay_scaling: n={n} seed={seed} seed-wall={:?} replay-wall={:?}",
                seed_elapsed, replay_elapsed
            );
            timings.push(replay_elapsed);
        }

        let med = median(&mut timings);
        let per_entry_ns = med.as_nanos() as f64 / n as f64;
        eprintln!(
            "wal_replay_scaling: n={n} entries={last_count} 3-seed-median={:?} \
             (per-entry {:.0} ns)",
            med, per_entry_ns
        );
    }
}
