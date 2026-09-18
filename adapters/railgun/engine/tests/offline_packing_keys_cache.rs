//! Disk-backed offline-packing-key cache. One `(PackParams, OfflinePackingKeys)` per PROCESS,
//! cloned per test.
//!
//! That does NOT pay the build once, which this header used to claim. `cargo nextest` runs every
//! test in its own process, so a per-process `OnceLock` amortises only within a single test - this
//! binary pays the build once per test, not once. Measured 2026-08-31.

#![allow(clippy::expect_used, clippy::panic, clippy::print_stderr)]

use std::sync::OnceLock;
use std::time::Instant;

use raven_inspire::inspiring::{OfflinePackingKeys, PackParams};
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_engine::inspire;
use raven_railgun_engine::offline_packing_keys_cache::{
    CacheLoad, CellShape, OfflinePackingKeysCache, OfflinePackingKeysCacheError,
};

const TEST_ENTRIES: usize = 256;
const TEST_ENTRY_BYTES: usize = 32;
const SCHEME_TAG: &[u8] = b"raven-inspire-twopacking-wp3-v1";
const PACKING_PARAM_ID: &[u8] = b"InspireParams::secure_128_d2048";

fn shared_parts() -> &'static (PackParams, OfflinePackingKeys, bool) {
    static PARTS: OnceLock<(PackParams, OfflinePackingKeys, bool)> = OnceLock::new();
    PARTS.get_or_init(|| {
        let params = InspireParams::secure_128_d2048();
        let db = synthetic_db(TEST_ENTRIES, TEST_ENTRY_BYTES);
        let (state, _sk) =
            inspire::setup_state(&params, &db, TEST_ENTRY_BYTES, InspireVariant::TwoPacking)
                .expect("offline_packing_keys_cache: setup_state");
        let pp = state.cache.pack_params().clone();
        let ok = state.cache.offline_keys().clone();
        let setup_fields_consumed =
            state.crs.inspiring_pack_params.is_none() && state.crs.inspiring_packing_key.is_none();
        (pp, ok, setup_fields_consumed)
    })
}

#[test]
fn production_setup_consumes_the_setup_cache_parts() {
    assert!(
        shared_parts().2,
        "setup_state rebuilt the cache instead of consuming setup output"
    );
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

#[test]
fn inspiring_seed_change_invalidates_the_cache_identity() {
    let params = InspireParams::secure_128_d2048();
    let first = CellShape::for_inspiring(&params, 16, [1; 32]);
    let second = CellShape::for_inspiring(&params, 16, [2; 32]);
    assert_ne!(first.fingerprint(), second.fingerprint());
}

#[test]
fn cache_uses_v3_magic_and_refuses_v2_before_body_decode() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = OfflinePackingKeysCache::new(dir.path());
    let cell = test_cell();
    let parts = shared_parts();
    cache.store(&cell, &parts.0, &parts.1).expect("store");

    let mut bytes = std::fs::read(cache.path()).expect("new cache bytes");
    assert_eq!(bytes.get(..8), Some(b"RVN_OPK3".as_slice()));
    bytes
        .get_mut(..8)
        .expect("magic prefix")
        .copy_from_slice(b"RVN_OPK2");
    std::fs::write(cache.path(), bytes).expect("write old epoch");
    match cache.load(&cell) {
        CacheLoad::Miss(OfflinePackingKeysCacheError::BadMagic { expected, found }) => {
            assert_eq!(expected, *b"RVN_OPK3");
            assert_eq!(found, *b"RVN_OPK2");
        }
        other => panic!("expected v2 BadMagic miss, got {other:?}"),
    }
}

#[test]
fn bad_magic_is_a_typed_miss() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = OfflinePackingKeysCache::new(dir.path());
    let cell = test_cell();
    let parts = shared_parts();
    cache.store(&cell, &parts.0, &parts.1).expect("store");
    let mut bytes = std::fs::read(cache.path()).expect("cache bytes");
    *bytes.first_mut().expect("magic byte") ^= 1;
    std::fs::write(cache.path(), bytes).expect("mutate magic");

    match cache.load(&cell) {
        CacheLoad::Miss(OfflinePackingKeysCacheError::BadMagic { expected, found }) => {
            assert_eq!(expected, *b"RVN_OPK3");
            assert_ne!(found, expected);
        }
        other => panic!("expected BadMagic miss, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn cache_store_is_owner_only_and_ignores_legacy_tmp_collision() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let cache = OfflinePackingKeysCache::new(dir.path());
    let cell = test_cell();
    let parts = shared_parts();
    let legacy_tmp = cache.path().with_extension("tmp");
    std::fs::create_dir_all(legacy_tmp.parent().expect("parent")).expect("cache dir");
    std::fs::write(&legacy_tmp, b"collision").expect("legacy collision");

    cache.store(&cell, &parts.0, &parts.1).expect("store");

    assert_eq!(
        std::fs::read(legacy_tmp).expect("collision survives"),
        b"collision"
    );
    let mode = std::fs::metadata(cache.path())
        .expect("cache metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
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
    assert_eq!(
        bincode::serialize(warm_cache.pack_params()).expect("serialize warm params"),
        bincode::serialize(&parts.0).expect("serialize source params")
    );
    assert_eq!(
        bincode::serialize(warm_cache.offline_keys()).expect("serialize warm keys"),
        bincode::serialize(&parts.1).expect("serialize source keys")
    );

    eprintln!(
        "offline_packing_keys_cache: cold={cold_elapsed:?} warm={warm_elapsed:?} \
         ratio={:.4}",
        warm_elapsed.as_secs_f64() / cold_elapsed.as_secs_f64().max(1e-9)
    );
    // Enforced by the warm-path panic closure, not by a wall-clock floor.
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

    match cache.load(&baseline) {
        CacheLoad::Hit(_) => {}
        CacheLoad::Miss(err) => panic!("expected Hit on baseline, got Miss({err:?})"),
    }
}

#[test]
fn corrupt_cache_file_falls_through_cleanly_then_overwrites() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = OfflinePackingKeysCache::new(dir.path());
    let cell = test_cell();
    let parts = shared_parts();

    if let Some(parent) = cache.path().parent() {
        std::fs::create_dir_all(parent).expect("mkdir cache dir");
    }
    std::fs::write(cache.path(), b"garbage-not-a-valid-bincode-payload").expect("write garbage");

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

    let (server_cache, hit) = cache
        .load_or_build(&cell, || -> Result<_, std::convert::Infallible> {
            Ok((parts.0.clone(), parts.1.clone()))
        })
        .expect("post-corrupt load_or_build");
    assert!(!hit, "corrupt-fall-through must not report a hit");
    drop(server_cache);

    match cache.load(&cell) {
        CacheLoad::Hit(_) => {}
        CacheLoad::Miss(err) => panic!("expected Hit after overwrite, got Miss({err:?})"),
    }
}

#[test]
fn body_hash_rejects_a_validly_decoded_mutation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = OfflinePackingKeysCache::new(dir.path());
    let cell = test_cell();
    let parts = shared_parts();
    cache.store(&cell, &parts.0, &parts.1).expect("store");
    let mut bytes = std::fs::read(cache.path()).expect("read cache");
    let last = bytes.last_mut().expect("non-empty cache");
    *last ^= 1;
    std::fs::write(cache.path(), bytes).expect("write mutation");

    match cache.load(&cell) {
        CacheLoad::Miss(OfflinePackingKeysCacheError::BodyHashMismatch { .. }) => {}
        other => panic!("expected BodyHashMismatch, got {other:?}"),
    }
}

#[test]
fn concurrent_writes_safe_via_atomic_rename() {
    const WRITERS: usize = 8;
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = OfflinePackingKeysCache::new(dir.path());
    let cell = test_cell();
    let parts = shared_parts();

    // Atomic rename: no reader sees a partial file, and losing writers overwrite
    // with byte-identical content.
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

    match cache.load(&cell) {
        CacheLoad::Hit(parts_box) => {
            assert_eq!(parts_box.pack_params.num_to_pack, parts.0.num_to_pack);
        }
        CacheLoad::Miss(err) => {
            panic!("expected Hit after concurrent writes, got Miss({err:?})")
        }
    }

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
