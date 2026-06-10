//! Layer B WAL chaos: forks `wal_chaos_child`, SIGKILLs at varying delays, asserts recovery.
//! Complements Layer A (`wal_model_check.rs`) by exercising the real fsync + kernel page-cache path.
//! Run: `cargo test -p raven-railgun-persistence --features chaos-tests --test wal_chaos_layer_b -- --nocapture`

#![cfg(feature = "chaos-tests")]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::cast_possible_truncation
)]

use raven_railgun_persistence::{StoreLayout, Wal, WalEntryPayload};
use std::process::{Command, Stdio};
use std::time::Duration;

fn canonical_payload(seed: u64, i: usize) -> (WalEntryPayload, u64) {
    let h = seed
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(i as u64);
    let block_height = 100u64.saturating_add(i as u64);
    let variant = (h as usize) % 5;
    let payload = match variant {
        0 => WalEntryPayload::AppendLeaf {
            tree_number: (h % 4) as u32,
            leaf_index: ((h >> 4) % 65_536) as u32,
            commitment: {
                let mut a = [0u8; 32];
                for (j, byte) in a.iter_mut().enumerate() {
                    *byte = (h.wrapping_add(j as u64) & 0xff) as u8;
                }
                a
            },
        },
        1 => WalEntryPayload::PpoiStatus {
            list_key: {
                let mut a = [0u8; 32];
                a[0] = (h & 0xff) as u8;
                a
            },
            blinded_commitment: {
                let mut a = [0u8; 32];
                a[0] = ((h >> 8) & 0xff) as u8;
                a
            },
            status: ((h >> 16) % 4) as u8,
        },
        2 => WalEntryPayload::Reorg {
            height: block_height,
        },
        3 => WalEntryPayload::PpoiListLeafAdded {
            list_key: {
                let mut a = [0u8; 32];
                a[0] = (h & 0xff) as u8;
                a
            },
            list_index: ((h >> 4) % 65_536) as u32,
            blinded_commitment: {
                let mut a = [0u8; 32];
                a[0] = ((h >> 8) & 0xff) as u8;
                a
            },
            status: ((h >> 16) % 4) as u8,
        },
        _ => WalEntryPayload::Heartbeat {
            wallclock_unix_ms: h,
        },
    };
    (payload, block_height)
}

fn one_chaos_round(seed: u64, kill_delay: Duration) -> usize {
    let dir = tempfile::tempdir().expect("tempdir");
    let child_bin = env!("CARGO_BIN_EXE_wal_chaos_child");
    let mut child = Command::new(child_bin)
        .arg("--data-dir")
        .arg(dir.path())
        .arg("--seed")
        .arg(seed.to_string())
        .arg("--max")
        .arg("1000")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn child");

    std::thread::sleep(kill_delay);

    let _ = child.kill();
    let _ = child.wait();

    let layout = StoreLayout::open(dir.path()).expect("layout");
    let wal = Wal::open(&layout, None).expect("wal");
    let replay = wal.replay().expect("replay");

    for (idx, recovered) in replay.entries.iter().enumerate() {
        let (canonical_payload_value, canonical_height) = canonical_payload(seed, idx);
        assert_eq!(
            recovered.marker, canonical_height,
            "entry {idx}: marker mismatch (seed={seed}, kill_delay={kill_delay:?})"
        );
        let decoded: WalEntryPayload = bincode::deserialize(&recovered.payload)
            .expect("recovered payload must be valid bincode");
        assert_eq!(
            decoded, canonical_payload_value,
            "entry {idx}: payload mismatch (seed={seed}, kill_delay={kill_delay:?})"
        );
    }
    replay.entries.len()
}

#[test]
fn chaos_kill_at_random_offsets_recovers_clean_prefix() {
    for (trial, delay_ms) in [(1u64, 10u64), (2, 30), (3, 60), (4, 120), (5, 250)] {
        let recovered = one_chaos_round(trial, Duration::from_millis(delay_ms));
        eprintln!(
            "Layer B chaos trial {trial} (delay={delay_ms}ms): \
             recovered {recovered} entries"
        );
    }
}

#[test]
fn chaos_zero_delay_kill_recovers_zero_or_more_entries() {
    let recovered = one_chaos_round(99, Duration::from_millis(0));
    eprintln!("Layer B chaos zero-delay: recovered {recovered} entries");
}
