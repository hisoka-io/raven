//! Codec bench: bincode vs bitcode on 32k `AppendLeaf` entries (~1.6 MiB).
//! Borsh absent: requires derive traits not on `WalEntryPayload` (structural blocker).
//!
//! Run: cargo test --release -p raven-railgun-persistence --test snapshot_codec_bench -- --ignored --nocapture

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

use raven_railgun_persistence::WalEntryPayload;

const SEEDS: usize = 3;
const PAYLOAD_COUNT: usize = 32_768;

fn build_payload_set(salt: u64) -> Vec<WalEntryPayload> {
    (0..PAYLOAD_COUNT)
        .map(|i| {
            let leaf_index = (i as u32).wrapping_add(salt as u32);
            let mut commitment = [0u8; 32];
            commitment[24..32]
                .copy_from_slice(&(salt.wrapping_mul(7919).wrapping_add(i as u64)).to_be_bytes());
            commitment[31] |= 1;
            WalEntryPayload::AppendLeaf {
                tree_number: 0,
                leaf_index,
                commitment,
            }
        })
        .collect()
}

fn median(timings: &mut [Duration]) -> Duration {
    timings.sort();
    timings[timings.len() / 2]
}

#[test]
#[ignore = "snapshot codec sweep; ~2-3s wall total"]
fn snapshot_codec_bench_bincode_vs_bitcode() {
    eprintln!(
        "snapshot_codec: SEEDS={} PAYLOAD_COUNT={}",
        SEEDS, PAYLOAD_COUNT
    );

    let mut bincode_ser_t: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut bincode_de_t: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut bincode_bytes_out: usize = 0;

    let mut bitcode_ser_t: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut bitcode_de_t: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut bitcode_bytes_out: usize = 0;

    for seed in 0..SEEDS {
        let payloads = build_payload_set(seed as u64 + 1);

        let bs = Instant::now();
        let bincoded: Vec<u8> = bincode::serialize(&payloads).expect("bincode ser");
        let bincode_ser = bs.elapsed();
        bincode_bytes_out = bincoded.len();
        bincode_ser_t.push(bincode_ser);

        let bd = Instant::now();
        let _round: Vec<WalEntryPayload> = bincode::deserialize(&bincoded).expect("bincode de");
        let bincode_de = bd.elapsed();
        bincode_de_t.push(bincode_de);

        let bts = Instant::now();
        let bitcoded: Vec<u8> = bitcode::serialize(&payloads).expect("bitcode ser");
        let bitcode_ser = bts.elapsed();
        bitcode_bytes_out = bitcoded.len();
        bitcode_ser_t.push(bitcode_ser);

        let btd = Instant::now();
        let _round: Vec<WalEntryPayload> = bitcode::deserialize(&bitcoded).expect("bitcode de");
        let bitcode_de = btd.elapsed();
        bitcode_de_t.push(bitcode_de);

        eprintln!(
            "snapshot_codec: seed={seed} bincode ser={:?} de={:?} bytes={} \
             bitcode ser={:?} de={:?} bytes={}",
            bincode_ser,
            bincode_de,
            bincoded.len(),
            bitcode_ser,
            bitcode_de,
            bitcoded.len()
        );
    }

    let bincode_ser_med = median(&mut bincode_ser_t);
    let bincode_de_med = median(&mut bincode_de_t);
    let bitcode_ser_med = median(&mut bitcode_ser_t);
    let bitcode_de_med = median(&mut bitcode_de_t);

    let bytes_ratio = bitcode_bytes_out as f64 / bincode_bytes_out as f64;
    let ser_ratio = bitcode_ser_med.as_secs_f64() / bincode_ser_med.as_secs_f64();
    let de_ratio = bitcode_de_med.as_secs_f64() / bincode_de_med.as_secs_f64();

    eprintln!(
        "snapshot_codec: bincode 3-seed-median ser={:?} de={:?} bytes={}",
        bincode_ser_med, bincode_de_med, bincode_bytes_out
    );
    eprintln!(
        "snapshot_codec: bitcode 3-seed-median ser={:?} de={:?} bytes={}",
        bitcode_ser_med, bitcode_de_med, bitcode_bytes_out
    );
    eprintln!(
        "snapshot_codec: ratios bitcode/bincode bytes={:.3} ser={:.3} de={:.3} \
         (borsh: structural blocker; not benched)",
        bytes_ratio, ser_ratio, de_ratio
    );
}
