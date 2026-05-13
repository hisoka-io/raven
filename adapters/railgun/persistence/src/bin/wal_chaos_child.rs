//! Child binary for the Layer B WAL chaos harness (`tests/wal_chaos_layer_b.rs`).
//!
//! Writes a deterministic `--seed`-derived sequence of WAL entries; the parent SIGKILLs
//! it at a random delay and asserts replay returns a clean prefix of the canonical sequence.

#![allow(
    clippy::expect_used,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::cast_possible_truncation,
    clippy::panic
)]

use raven_railgun_persistence::{StoreLayout, Wal, WalEntryPayload};

fn parse_args() -> (std::path::PathBuf, u64, usize) {
    let mut args = std::env::args().skip(1);
    let mut data_dir = None;
    let mut seed = 0u64;
    let mut max_entries = 1000usize;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--data-dir" => {
                data_dir = Some(std::path::PathBuf::from(
                    args.next().expect("--data-dir requires value"),
                ));
            }
            "--seed" => {
                seed = args
                    .next()
                    .expect("--seed requires value")
                    .parse()
                    .expect("seed must be u64");
            }
            "--max" => {
                max_entries = args
                    .next()
                    .expect("--max requires value")
                    .parse()
                    .expect("max must be usize");
            }
            other => panic!("unknown flag {other}"),
        }
    }
    (data_dir.expect("--data-dir required"), seed, max_entries)
}

/// Deterministic payload generator; parent mirrors this to verify recovered entries.
pub fn canonical_payload(seed: u64, i: usize) -> (WalEntryPayload, u64) {
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

fn main() {
    let (data_dir, seed, max_entries) = parse_args();
    eprintln!(
        "wal_chaos_child: data_dir={} seed={} max_entries={}",
        data_dir.display(),
        seed,
        max_entries
    );
    std::fs::create_dir_all(&data_dir).expect("mkdir data_dir");
    let layout = StoreLayout::open(&data_dir).expect("open layout");
    let wal = Wal::open(&layout, None).expect("wal open");

    for i in 0..max_entries {
        let (payload, block_height) = canonical_payload(seed, i);
        let _seq = wal.append(&payload, block_height).expect("append");
        if i % 50 == 0 {
            println!("wrote {i}");
        }
    }
    eprintln!("wal_chaos_child: completed {max_entries} entries cleanly");
}
