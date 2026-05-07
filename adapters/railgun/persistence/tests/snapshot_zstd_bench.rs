//! Snapshot zstd-l3 wrap bench (`#[ignore]`-gated).
//!
//! 3-seed median per (codec, op) at the production ~170 MiB payload shape.
//! Run: `cargo test --release -p raven-railgun-persistence --test snapshot_zstd_bench -- --ignored --nocapture`

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

const SEEDS: usize = 3;

fn build_payload(seed: u64) -> Vec<u8> {
    const TOTAL: usize = 170 * 1024 * 1024;
    let mut out: Vec<u8> = Vec::with_capacity(TOTAL);
    let mut rng: u64 = 0xDEAD_BEEF_CAFE_F00D_u64 ^ seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);

    while out.len() + 64 <= TOTAL {
        out.extend_from_slice(&[
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        for _ in 0..8 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            out.push((rng & 0xFF) as u8);
        }
    }
    while out.len() < TOTAL {
        out.push(0);
    }
    out
}

fn median(timings: &mut [Duration]) -> Duration {
    timings.sort();
    timings[timings.len() / 2]
}

#[test]
#[ignore = "snapshot zstd bench; ~3-6s wall total at 170 MiB x 3 seeds"]
fn snapshot_zstd_bench_bincode_vs_zstd_l3() {
    eprintln!("snapshot_zstd_bench: SEEDS={} TOTAL_BYTES~170MiB", SEEDS);

    let mut bincode_ser_t: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut bincode_de_t: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut bincode_bytes_out: usize = 0;

    let mut zstd_ser_t: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut zstd_de_t: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut zstd_bytes_out: usize = 0;

    for seed in 0..SEEDS {
        let payload = build_payload(seed as u64 + 1);
        let input_len = payload.len();

        let bs = Instant::now();
        let bincoded: Vec<u8> = bincode::serialize(&payload).expect("bincode ser");
        let bincode_ser = bs.elapsed();
        bincode_bytes_out = bincoded.len();
        bincode_ser_t.push(bincode_ser);

        let bd = Instant::now();
        let _round: Vec<u8> = bincode::deserialize(&bincoded).expect("bincode de");
        let bincode_de = bd.elapsed();
        bincode_de_t.push(bincode_de);

        let zs = Instant::now();
        let bincoded_2: Vec<u8> = bincode::serialize(&payload).expect("bincode ser pre-zstd");
        let zstd_wrapped: Vec<u8> = zstd::bulk::compress(&bincoded_2, 3).expect("zstd compress");
        let zstd_ser = zs.elapsed();
        zstd_bytes_out = zstd_wrapped.len();
        zstd_ser_t.push(zstd_ser);

        let zd = Instant::now();
        let zstd_unwrapped: Vec<u8> =
            zstd::bulk::decompress(&zstd_wrapped, 4 * 1024 * 1024 * 1024).expect("zstd decompress");
        let _round2: Vec<u8> = bincode::deserialize(&zstd_unwrapped).expect("bincode de post-zstd");
        let zstd_de = zd.elapsed();
        zstd_de_t.push(zstd_de);

        eprintln!(
            "snapshot_zstd_bench: seed={seed} input={input_len} \
             bincode ser={:?} de={:?} bytes={} \
             zstd-l3 ser={:?} de={:?} bytes={}",
            bincode_ser,
            bincode_de,
            bincoded.len(),
            zstd_ser,
            zstd_de,
            zstd_wrapped.len(),
        );
    }

    let bincode_ser_med = median(&mut bincode_ser_t);
    let bincode_de_med = median(&mut bincode_de_t);
    let zstd_ser_med = median(&mut zstd_ser_t);
    let zstd_de_med = median(&mut zstd_de_t);

    let bytes_ratio = zstd_bytes_out as f64 / bincode_bytes_out as f64;
    let ser_delta_ms = zstd_ser_med.as_secs_f64() * 1000.0 - bincode_ser_med.as_secs_f64() * 1000.0;
    let de_delta_ms = zstd_de_med.as_secs_f64() * 1000.0 - bincode_de_med.as_secs_f64() * 1000.0;

    eprintln!(
        "snapshot_zstd_bench: bincode-only 3-seed-median ser={:?} de={:?} bytes={}",
        bincode_ser_med, bincode_de_med, bincode_bytes_out,
    );
    eprintln!(
        "snapshot_zstd_bench: zstd-l3 3-seed-median ser={:?} de={:?} bytes={}",
        zstd_ser_med, zstd_de_med, zstd_bytes_out,
    );
    eprintln!(
        "snapshot_zstd_bench: bytes_ratio={:.4} ser_delta={:+.2}ms de_delta={:+.2}ms",
        bytes_ratio, ser_delta_ms, de_delta_ms,
    );
}
