//! Disk-backed cache tests for InspiRING offline packing keys.
//!
//! Shared `(PackParams, OfflinePackingKeys)` built once per process at
//! the smallest viable cell shape; all tests clone from it to avoid
//! paying the `O(d^3)` automorph-table cost repeatedly.

#![allow(clippy::expect_used, clippy::panic, clippy::print_stderr)]

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use raven_inspire::inspiring::{OfflinePackingKeys, PackParams};
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::ServerInspiringCache;
use raven_railgun_engine::inspire;
use raven_railgun_engine::offline_packing_keys_cache::{
    CacheBuildError, CacheLoad, CellShape, OfflinePackingKeysCache, OfflinePackingKeysCacheError,
};

const TEST_ENTRIES: usize = 256;
const TEST_ENTRY_BYTES: usize = 32;
const PROD_ENTRIES: usize = 65_536;
const PROD_ENTRY_BYTES: usize = 512;
const SCHEME_TAG: &[u8] = b"raven-inspire-twopacking-wp3-v1";
const PACKING_PARAM_ID: &[u8] = b"InspireParams::secure_128_d2048";

fn shared_parts() -> &'static (PackParams, OfflinePackingKeys) {
    static PARTS: OnceLock<(PackParams, OfflinePackingKeys)> = OnceLock::new();
    PARTS.get_or_init(|| {
        let params = InspireParams::secure_128_d2048();
        let db = synthetic_db(TEST_ENTRIES, TEST_ENTRY_BYTES);
        let (state, _sk) =
            inspire::setup_state(&params, &db, TEST_ENTRY_BYTES, InspireVariant::TwoPacking)
                .expect("offline_packing_keys_cache: setup_state");
        // The cache exposes `pack_params()` / `offline_keys()`
        // borrows; clone them out for repeated use across tests.
        let pp = state.cache.pack_params().clone();
        let ok = state.cache.offline_keys().clone();
        (pp, ok)
    })
}

fn synthetic_db(entries: usize, entry_bytes: usize) -> Vec<u8> {
    #[allow(clippy::cast_possible_truncation)]
    (0..entries)
        .flat_map(|i| (0..entry_bytes).map(move |j| ((i * 31 + j * 17) % 251) as u8))
        .collect()
}

fn test_cell() -> CellShape {
    CellShape {
        scheme_tag: SCHEME_TAG.to_vec(),
        entries: TEST_ENTRIES as u64,
        entry_bytes: TEST_ENTRY_BYTES as u64,
        packing_param_id: PACKING_PARAM_ID.to_vec(),
    }
}

fn median_of(durs: &[Duration]) -> Duration {
    let mut sorted = durs.to_vec();
    sorted.sort();
    *sorted.get(sorted.len() / 2).expect("non-empty timings")
}

#[test]
fn cold_load_writes_cache_then_warm_load_skips_offline_phase() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = OfflinePackingKeysCache::new(dir.path());
    let cell = test_cell();
    let parts = shared_parts();

    let cold_start = Instant::now();
    let (server_cache, hit) = cache
        .load_or_build(&cell, || -> Result<_, std::convert::Infallible> {
            Ok((parts.0.clone(), parts.1.clone()))
        })
        .expect("cold load_or_build");
    let cold_elapsed = cold_start.elapsed();
    assert!(!hit, "cold load must not report a hit");
    drop(server_cache);
    assert!(cache.path().exists(), "cache file must exist after store");

    let warm_start = Instant::now();
    let (warm_cache, warm_hit) = cache
        .load_or_build(&cell, || -> Result<_, std::convert::Infallible> {
            panic!("build_fresh must not run on warm load");
        })
        .expect("warm load_or_build");
    let warm_elapsed = warm_start.elapsed();
    assert!(warm_hit, "warm load must report a hit");

    assert_eq!(
        warm_cache.pack_params().num_to_pack,
        parts.0.num_to_pack,
        "warm cache pack_params must round-trip"
    );

    eprintln!(
        "offline_packing_keys_cache: cold={cold_elapsed:?} warm={warm_elapsed:?} \
         ratio={:.4}",
        warm_elapsed.as_secs_f64() / cold_elapsed.as_secs_f64().max(1e-9)
    );
    assert!(
        warm_elapsed.as_nanos() * 20 <= cold_elapsed.as_nanos().saturating_mul(1),
        "warm load not under 5% of cold: cold={cold_elapsed:?} warm={warm_elapsed:?}"
    );
}

#[test]
fn scheme_tag_mismatch_falls_through_to_offline_phase_and_overwrites_cache() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = OfflinePackingKeysCache::new(dir.path());
    let parts = shared_parts();

    let cell_a = CellShape {
        scheme_tag: b"first".to_vec(),
        ..test_cell()
    };
    cache
        .store(&cell_a, &parts.0, &parts.1)
        .expect("initial store");

    let cell_b = CellShape {
        scheme_tag: b"second".to_vec(),
        ..test_cell()
    };
    match cache.load(&cell_b) {
        CacheLoad::Miss(OfflinePackingKeysCacheError::SchemeMismatch { expected, found }) => {
            assert_eq!(expected, b"second");
            assert_eq!(found, b"first");
        }
        other => panic!("expected SchemeMismatch, got {other:?}"),
    }

    let mut build_calls = 0;
    let (server_cache, hit) = cache
        .load_or_build(&cell_b, || -> Result<_, std::convert::Infallible> {
            build_calls += 1;
            Ok((parts.0.clone(), parts.1.clone()))
        })
        .expect("scheme-mismatch load_or_build");
    assert!(!hit);
    assert_eq!(build_calls, 1, "build_fresh must run exactly once");
    drop(server_cache);

    match cache.load(&cell_b) {
        CacheLoad::Hit(_) => {}
        CacheLoad::Miss(err) => panic!("expected Hit after overwrite, got Miss({err:?})"),
    }
    match cache.load(&cell_a) {
        CacheLoad::Miss(OfflinePackingKeysCacheError::SchemeMismatch { .. }) => {}
        CacheLoad::Miss(other) => {
            panic!("expected SchemeMismatch on old scheme after overwrite, got Miss({other:?})")
        }
        CacheLoad::Hit(_) => {
            panic!("expected SchemeMismatch on old scheme after overwrite, got Hit")
        }
    }
}

#[test]
fn cell_shape_change_invalidates_cache() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = OfflinePackingKeysCache::new(dir.path());
    let parts = shared_parts();

    let baseline = test_cell();
    cache
        .store(&baseline, &parts.0, &parts.1)
        .expect("baseline store");

    let entries_changed = CellShape {
        entries: baseline.entries + 1,
        ..baseline.clone()
    };
    match cache.load(&entries_changed) {
        CacheLoad::Miss(OfflinePackingKeysCacheError::HashMismatch { expected, found }) => {
            assert_ne!(expected, found, "fingerprints must differ");
        }
        CacheLoad::Miss(other) => {
            panic!("expected HashMismatch on entries change, got Miss({other:?})")
        }
        CacheLoad::Hit(_) => panic!("expected HashMismatch on entries change, got Hit"),
    }

    let entry_bytes_changed = CellShape {
        entry_bytes: baseline.entry_bytes * 2,
        ..baseline.clone()
    };
    match cache.load(&entry_bytes_changed) {
        CacheLoad::Miss(OfflinePackingKeysCacheError::HashMismatch { .. }) => {}
        CacheLoad::Miss(other) => {
            panic!("expected HashMismatch on entry_bytes change, got Miss({other:?})")
        }
        CacheLoad::Hit(_) => panic!("expected HashMismatch on entry_bytes change, got Hit"),
    }

    // Original cell still hits.
    match cache.load(&baseline) {
        CacheLoad::Hit(_) => {}
        CacheLoad::Miss(err) => panic!("expected Hit on baseline, got Miss({err:?})"),
    }
}

// ============================================================================
// Test 4: corrupt cache file falls through cleanly + overwrites
// ============================================================================
#[test]
fn corrupt_cache_file_falls_through_cleanly_then_overwrites() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = OfflinePackingKeysCache::new(dir.path());
    let cell = test_cell();
    let parts = shared_parts();

    // Write garbage bytes at the canonical path.
    if let Some(parent) = cache.path().parent() {
        std::fs::create_dir_all(parent).expect("mkdir cache dir");
    }
    std::fs::write(cache.path(), b"garbage-not-a-valid-bincode-payload").expect("write garbage");

    // Direct load: must Miss with Serialization (or BadMagic if the
    // garbage happens to deserialise to a CacheFile-shaped struct,
    // which is astronomically unlikely for this payload).
    let load_result = cache.load(&cell);
    match load_result {
        CacheLoad::Miss(
            OfflinePackingKeysCacheError::Serialization(_)
            | OfflinePackingKeysCacheError::BadMagic { .. },
        ) => {}
        CacheLoad::Miss(other) => {
            panic!("expected Serialization or BadMagic miss, got Miss({other:?})")
        }
        CacheLoad::Hit(_) => panic!("expected Serialization or BadMagic miss, got Hit"),
    }

    // load_or_build runs build_fresh and overwrites.
    let (server_cache, hit) = cache
        .load_or_build(&cell, || -> Result<_, std::convert::Infallible> {
            Ok((parts.0.clone(), parts.1.clone()))
        })
        .expect("post-corrupt load_or_build");
    assert!(!hit, "corrupt-fall-through must not report a hit");
    drop(server_cache);

    // Subsequent load now hits cleanly.
    match cache.load(&cell) {
        CacheLoad::Hit(_) => {}
        CacheLoad::Miss(err) => panic!("expected Hit after overwrite, got Miss({err:?})"),
    }
}

// ============================================================================
// Test 5: concurrent writes safe via atomic rename
// ============================================================================
#[test]
fn concurrent_writes_safe_via_atomic_rename() {
    const WRITERS: usize = 8;
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = OfflinePackingKeysCache::new(dir.path());
    let cell = test_cell();
    let parts = shared_parts();

    // Spawn N writer threads racing to store the same payload at the
    // same path. Atomic rename guarantees that no thread sees a
    // partially-written file at the canonical path; the loser of the
    // rename simply overwrites the winner's file with byte-identical
    // content (same `cell` + same `parts`).
    let cell_arc = std::sync::Arc::new(cell.clone());
    let parts_arc = std::sync::Arc::new(parts.clone());
    let cache_arc = std::sync::Arc::new(cache.clone());
    let mut handles = Vec::with_capacity(WRITERS);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(WRITERS));
    for _ in 0..WRITERS {
        let c = std::sync::Arc::clone(&cache_arc);
        let cell = std::sync::Arc::clone(&cell_arc);
        let parts = std::sync::Arc::clone(&parts_arc);
        let b = std::sync::Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            b.wait();
            c.store(&cell, &parts.0, &parts.1)
        }));
    }
    for h in handles {
        let r = h.join().expect("writer join");
        assert!(r.is_ok(), "concurrent store must succeed: {:?}", r.err());
    }

    // After the dust settles: the canonical file is a complete,
    // valid cache that loads cleanly.
    match cache.load(&cell) {
        CacheLoad::Hit(parts_box) => {
            assert_eq!(parts_box.pack_params.num_to_pack, parts.0.num_to_pack);
        }
        CacheLoad::Miss(err) => {
            panic!("expected Hit after concurrent writes, got Miss({err:?})")
        }
    }

    // No `.tmp.*` files should remain (each writer cleans up via
    // atomic rename consuming its own tmp). We tolerate a stray tmp
    // if a thread crashed mid-fsync, but in this test all writers
    // succeed.
    let stray: Vec<_> = std::fs::read_dir(cache.path().parent().expect("parent"))
        .expect("readdir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains(".tmp."))
        })
        .collect();
    assert!(
        stray.is_empty(),
        "no .tmp.* files should remain after successful writes; found: {stray:?}"
    );
}

// ============================================================================
// Production-cell 3-seed bench (#[ignore]-gated)
// ============================================================================

#[test]
#[ignore = "production-cell offline phase is heavy (~12s per seed × 3 seeds = ~36s); run with --release"]
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

        // Cold: do a real production-cell setup_state once, then
        // hand the parts to the cache via load_or_build (the
        // build_fresh closure clones out of the freshly-built
        // server cache).
        let setup_start = Instant::now();
        let db = synthetic_db(PROD_ENTRIES, PROD_ENTRY_BYTES);
        let (state, _sk) =
            inspire::setup_state(&params, &db, PROD_ENTRY_BYTES, InspireVariant::TwoPacking)
                .expect("production-cell setup_state");
        let pp = state.cache.pack_params().clone();
        let ok = state.cache.offline_keys().clone();
        let setup_elapsed = setup_start.elapsed();

        // Pre-populate via store so warm-load timing isolates the
        // bincode-deserialise + SHA-256 path (no clone overhead).
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

// Suppress unused-import warnings when only a subset of items are
// referenced under specific cfg paths.
#[allow(dead_code)]
fn _unused_imports_anchor(_: ServerInspiringCache, _: CacheBuildError<std::convert::Infallible>) {}
