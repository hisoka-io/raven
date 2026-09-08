//! Offline-packing-key cache cold-vs-warm at the production cell, 3-seed median.
//! Gated, stderr-only.
//!
//! This is a bench by construction: it exists to publish a speedup number, and its only
//! assertion (`warm_med < cold_med`) holds for any working cache at any magnitude. The
//! cache semantics it looks like it guards are guarded at the toy cell inside the
//! per-commit lane by `tests/offline_packing_keys_cache.rs` — including the
//! `panic!("build_fresh must not run on warm load")` closure, which lives there too, so
//! moving this out of the test lane retains that invariant.

#![allow(clippy::expect_used, clippy::panic, clippy::print_stderr)]

use std::time::{Duration, Instant};

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_engine::inspire;
use raven_railgun_engine::offline_packing_keys_cache::{CellShape, OfflinePackingKeysCache};

const PROD_ENTRIES: usize = 65_536;
const PROD_ENTRY_BYTES: usize = 512;
const SCHEME_TAG: &[u8] = b"raven-inspire-twopacking-wp3-v1";
const PACKING_PARAM_ID: &[u8] = b"InspireParams::secure_128_d2048";

fn synthetic_db(entries: usize, entry_bytes: usize) -> Vec<u8> {
    #[allow(clippy::cast_possible_truncation)]
    (0..entries)
        .flat_map(|i| (0..entry_bytes).map(move |j| ((i * 31 + j * 17) % 251) as u8))
        .collect()
}

fn median_of(durs: &[Duration]) -> Duration {
    let mut sorted = durs.to_vec();
    sorted.sort();
    *sorted.get(sorted.len() / 2).expect("non-empty timings")
}

#[test]
#[ignore = "production-cell offline phase is heavy (~12 s per seed x 3 seeds = ~36 s); run with \
            --release. Trigger: changing OfflinePackingKeys generation or its disk-backed cache."]
fn production_cell_three_seed_cold_vs_warm() {
    eprintln!(
        "offline_packing_keys_cache: production-cell bench cell={PROD_ENTRIES} entries × {PROD_ENTRY_BYTES} B"
    );
    let params = InspireParams::secure_128_d2048();
    let mut cold_timings: Vec<Duration> = Vec::with_capacity(3);
    let mut warm_timings: Vec<Duration> = Vec::with_capacity(3);
    let mut cache_size_bytes: u64 = 0;

    for seed in 0..3u8 {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = OfflinePackingKeysCache::new(dir.path());
        let cell = CellShape {
            scheme_tag: SCHEME_TAG.to_vec(),
            entries: PROD_ENTRIES as u64,
            entry_bytes: PROD_ENTRY_BYTES as u64,
            packing_param_id: format!("{}-seed{seed}", String::from_utf8_lossy(PACKING_PARAM_ID))
                .into_bytes(),
        };

        let setup_start = Instant::now();
        let db = synthetic_db(PROD_ENTRIES, PROD_ENTRY_BYTES);
        let (state, _sk) =
            inspire::setup_state(&params, &db, PROD_ENTRY_BYTES, InspireVariant::TwoPacking)
                .expect("production-cell setup_state");
        let pp = state.cache.pack_params().clone();
        let ok = state.cache.offline_keys().clone();
        let setup_elapsed = setup_start.elapsed();

        let store_start = Instant::now();
        cache.store(&cell, &pp, &ok).expect("store");
        let store_elapsed = store_start.elapsed();
        let cold_total = setup_elapsed + store_elapsed;
        cold_timings.push(cold_total);
        eprintln!(
            "offline_packing_keys_cache: seed={seed} cold setup={setup_elapsed:?} \
             store={store_elapsed:?} total={cold_total:?}"
        );

        let warm_start = Instant::now();
        let (warm_cache, hit) = cache
            .load_or_build(&cell, || -> Result<_, std::convert::Infallible> {
                panic!("build_fresh must not run on warm load")
            })
            .expect("warm load_or_build");
        let warm_elapsed = warm_start.elapsed();
        assert!(hit, "warm load must hit");
        drop(warm_cache);
        warm_timings.push(warm_elapsed);
        eprintln!("offline_packing_keys_cache: seed={seed} warm load={warm_elapsed:?}");

        if cache_size_bytes == 0 {
            cache_size_bytes = std::fs::metadata(cache.path()).expect("cache stat").len();
        }
    }

    let cold_med = median_of(&cold_timings);
    let warm_med = median_of(&warm_timings);
    let speedup = cold_med.as_secs_f64() / warm_med.as_secs_f64().max(1e-9);
    let cold_ms: Vec<f64> = cold_timings
        .iter()
        .map(|d| d.as_secs_f64() * 1000.0)
        .collect();
    let warm_ms: Vec<f64> = warm_timings
        .iter()
        .map(|d| d.as_secs_f64() * 1000.0)
        .collect();

    let render = |xs: &[f64]| {
        xs.iter()
            .map(|x| format!("{x:.1}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    eprintln!(
        "cold_offline_phase_ms_seed=[{}] | 3-seed-median={:.1} ms",
        render(&cold_ms),
        cold_med.as_secs_f64() * 1000.0
    );
    eprintln!(
        "warm_load_ms_seed=[{}] | 3-seed-median={:.1} ms",
        render(&warm_ms),
        warm_med.as_secs_f64() * 1000.0
    );
    #[allow(clippy::cast_precision_loss)]
    let cache_mb = cache_size_bytes as f64 / (1024.0 * 1024.0);
    eprintln!("speedup={speedup:.1}x | cache_file_size={cache_mb:.2} MB");

    assert!(
        warm_med < cold_med,
        "warm median must be smaller than cold median; cold={cold_med:?} warm={warm_med:?}"
    );
}
