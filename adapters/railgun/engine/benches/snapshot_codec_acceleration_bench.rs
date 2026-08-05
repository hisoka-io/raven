//! Snapshot codec acceleration bench (`#[ignore]`-gated): compares
//! bincode, bitcode, and zstd-on-bincode at the production cell, 3-seed
//! median per (codec, op). borsh is absent: no serde auto-derive for the upstream types.

#![allow(
    clippy::expect_used,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::indexing_slicing,
    clippy::uninlined_format_args,
    clippy::items_after_statements,
    clippy::too_many_lines
)]

use std::io::Write;
use std::time::{Duration, Instant};

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::ServerInspiringCache;
use raven_railgun_engine::inspire::{
    restore_inspire_state, setup_state, snapshot_inspire_state, PersistedInspireState,
};

const ENTRIES_LOG2: usize = 16;
const ENTRY_BYTES: usize = 512;
const SEEDS: usize = 3;
const ZSTD_LEVEL: i32 = 3;

fn build_synthetic_db(n_entries: usize, entry_bytes: usize, salt: u64) -> Vec<u8> {
    (0..n_entries)
        .flat_map(|i| {
            let salted = (i as u64).wrapping_add(salt).wrapping_mul(31);
            (0..entry_bytes)
                .map(move |j| (salted.wrapping_add(j as u64).wrapping_mul(17) % 251) as u8)
        })
        .collect()
}

fn median(timings: &mut [Duration]) -> Duration {
    timings.sort();
    timings[timings.len() / 2]
}

fn fmt_us(d: Duration) -> String {
    format!("{:.3} ms", d.as_secs_f64() * 1000.0)
}

#[test]
#[ignore = "production-cell setup is heavy (~12 s/seed); snapshot codec acceleration sweep"]
fn snapshot_codec_acceleration_at_production_cell() {
    eprintln!(
        "snapshot_codec_acceleration: cell=65536x{} SEEDS={} variant=TwoPacking d=2048 zstd_level={}",
        ENTRY_BYTES, SEEDS, ZSTD_LEVEL
    );

    let mut bincode_ser_t: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut bincode_de_pure_t: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut bincode_de_with_cache_t: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut cache_rebuild_t: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut bincode_bytes: usize = 0;

    let mut bitcode_ser_t: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut bitcode_de_t: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut bitcode_bytes: usize = 0;

    let mut zstd_compress_t: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut zstd_decompress_t: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut zstd_bytes: usize = 0;

    let params = InspireParams::secure_128_d2048();
    let entries = 1usize << ENTRIES_LOG2;

    for seed in 0..SEEDS {
        let setup_start = Instant::now();
        let db = build_synthetic_db(entries, ENTRY_BYTES, seed as u64 + 1);
        let (server_state, _secret_key) =
            setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking)
                .expect("setup_state");
        let setup_elapsed = setup_start.elapsed();
        eprintln!(
            "snapshot_codec_acceleration: seed={} setup={}",
            seed,
            fmt_us(setup_elapsed)
        );

        // time a fresh ser inside the window to measure clean serialization, not setup overhead
        let bs = Instant::now();
        let bincoded = snapshot_inspire_state(&server_state).expect("bincode ser");
        let bincode_ser = bs.elapsed();
        bincode_bytes = bincoded.len();
        bincode_ser_t.push(bincode_ser);

        // restore is deserialize + cache rebuild; time them separately to attribute cost
        let bd_pure = Instant::now();
        let bundle_for_restore: PersistedInspireState =
            bincode::deserialize(&bincoded).expect("bincode de pure");
        let bincode_de_pure = bd_pure.elapsed();
        bincode_de_pure_t.push(bincode_de_pure);

        let cache_start = Instant::now();
        let restored = restore_inspire_state(&bincoded).expect("bincode de full");
        let bincode_de_with_cache = cache_start.elapsed() + bincode_de_pure;
        bincode_de_with_cache_t.push(bincode_de_with_cache);
        cache_rebuild_t.push(cache_start.elapsed());

        let recanonical = snapshot_inspire_state(&restored).expect("bincode resnap");
        assert_eq!(
            recanonical.len(),
            bincoded.len(),
            "bincode round-trip length must match"
        );
        assert_eq!(
            recanonical, bincoded,
            "bincode round-trip must be byte-identical"
        );

        drop(restored);
        drop(bundle_for_restore);

        let cache_only_start = Instant::now();
        let _cache = ServerInspiringCache::new(&server_state.crs, &server_state.encoded_db)
            .expect("standalone cache rebuild");
        let cache_only = cache_only_start.elapsed();

        // deserialize outside the window so bitcode ser measures pure codec cost on the same value
        let bundle: raven_railgun_engine::inspire::PersistedInspireState =
            bincode::deserialize(&bincoded).expect("bincode de for bitcode-input");
        let bts = Instant::now();
        let bitcoded: Vec<u8> = bitcode::serialize(&bundle).expect("bitcode ser");
        let bitcode_ser = bts.elapsed();
        bitcode_bytes = bitcoded.len();
        bitcode_ser_t.push(bitcode_ser);

        let btd = Instant::now();
        let bundle_back: raven_railgun_engine::inspire::PersistedInspireState =
            bitcode::deserialize(&bitcoded).expect("bitcode de");
        let bitcode_de = btd.elapsed();
        bitcode_de_t.push(bitcode_de);

        // re-serialize via bincode to prove bitcode preserved every on-disk-format field
        let recanonical_via_bitcode =
            bincode::serialize(&bundle_back).expect("bincode reser via bitcode round-trip");
        assert_eq!(
            recanonical_via_bitcode, bincoded,
            "bitcode round-trip must preserve canonical bincode bytes"
        );

        drop(bundle);
        drop(bundle_back);

        let zs = Instant::now();
        let mut compressed = Vec::with_capacity(bincoded.len() / 2);
        {
            let mut enc = zstd::Encoder::new(&mut compressed, ZSTD_LEVEL).expect("zstd enc");
            enc.write_all(&bincoded).expect("zstd write");
            enc.finish().expect("zstd finish");
        }
        let zstd_compress = zs.elapsed();
        zstd_bytes = compressed.len();
        zstd_compress_t.push(zstd_compress);

        let zd = Instant::now();
        let mut decompressed = Vec::with_capacity(bincoded.len());
        {
            let mut dec = zstd::Decoder::new(&compressed[..]).expect("zstd dec");
            std::io::copy(&mut dec, &mut decompressed).expect("zstd copy");
        }
        let zstd_decompress = zd.elapsed();
        zstd_decompress_t.push(zstd_decompress);

        assert_eq!(
            decompressed, bincoded,
            "zstd round-trip must be byte-identical"
        );

        eprintln!(
            "snapshot_codec_acceleration: seed={} bincode ser={} de_pure={} de_with_cache={} cache_only={} bytes={} \
             | bitcode ser={} de={} bytes={} \
             | zstd_l3 compress={} decompress={} bytes={}",
            seed,
            fmt_us(bincode_ser),
            fmt_us(bincode_de_pure),
            fmt_us(bincode_de_with_cache),
            fmt_us(cache_only),
            bincode_bytes,
            fmt_us(bitcode_ser),
            fmt_us(bitcode_de),
            bitcode_bytes,
            fmt_us(zstd_compress),
            fmt_us(zstd_decompress),
            zstd_bytes,
        );

        drop(server_state);
    }

    let bincode_ser_med = median(&mut bincode_ser_t);
    let bincode_de_pure_med = median(&mut bincode_de_pure_t);
    let bincode_de_with_cache_med = median(&mut bincode_de_with_cache_t);
    let cache_rebuild_med = median(&mut cache_rebuild_t);
    let bitcode_ser_med = median(&mut bitcode_ser_t);
    let bitcode_de_med = median(&mut bitcode_de_t);
    let zstd_compress_med = median(&mut zstd_compress_t);
    let zstd_decompress_med = median(&mut zstd_decompress_t);

    eprintln!("snapshot_codec_acceleration: ====== 3-SEED MEDIANS ======");
    eprintln!(
        "snapshot_codec_acceleration: bincode  median ser={} de_pure={} de_with_cache={} cache_rebuild={} bytes={}",
        fmt_us(bincode_ser_med),
        fmt_us(bincode_de_pure_med),
        fmt_us(bincode_de_with_cache_med),
        fmt_us(cache_rebuild_med),
        bincode_bytes
    );
    eprintln!(
        "snapshot_codec_acceleration: bitcode  median ser={} de={} bytes={}",
        fmt_us(bitcode_ser_med),
        fmt_us(bitcode_de_med),
        bitcode_bytes
    );
    eprintln!(
        "snapshot_codec_acceleration: zstd_l3  median compress={} decompress={} bytes={} \
         (on top of bincode)",
        fmt_us(zstd_compress_med),
        fmt_us(zstd_decompress_med),
        zstd_bytes
    );

    let bytes_ratio_bitcode = bitcode_bytes as f64 / bincode_bytes as f64;
    let ser_ratio_bitcode = bitcode_ser_med.as_secs_f64() / bincode_ser_med.as_secs_f64();
    let de_ratio_bitcode = bitcode_de_med.as_secs_f64() / bincode_de_pure_med.as_secs_f64();

    let bytes_ratio_zstd = zstd_bytes as f64 / bincode_bytes as f64;

    eprintln!(
        "snapshot_codec_acceleration: ratios bitcode/bincode bytes={:.4} ser={:.3} de={:.3}",
        bytes_ratio_bitcode, ser_ratio_bitcode, de_ratio_bitcode
    );
    eprintln!(
        "snapshot_codec_acceleration: ratios zstd_l3/bincode bytes={:.4} \
         compress_overhead_ms={:.3}",
        bytes_ratio_zstd,
        zstd_compress_med.as_secs_f64() * 1000.0
    );
}
