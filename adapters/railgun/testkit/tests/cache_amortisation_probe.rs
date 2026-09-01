//! Pins what the process-level cache does and does not buy.
//!
//! This exists because the claim "one build per process" is technically true and practically
//! false under `cargo nextest`, which runs every test in its own process. That misreading
//! already shipped once, in `engine/tests/offline_packing_keys_cache.rs`'s header. This test
//! asserts the property rather than describing it, so a future change to the cache's shape
//! cannot quietly restore the false version.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::time::Instant;

use raven_railgun_testkit::cached_toy_state;

/// The cache amortises WITHIN one test and the second call is effectively free.
///
/// The threshold is deliberately loose: a real build measured ~7.6 s, a cache hit ~0 ms, so
/// anything under a second is unambiguously a hit and the test does not become a wall-clock
/// budget that reds on a slow runner.
#[test]
fn a_second_build_at_the_same_record_size_inside_one_test_is_a_cache_hit() {
    let first = Instant::now();
    let a = cached_toy_state(32);
    let first_ms = first.elapsed().as_millis();

    let second = Instant::now();
    let b = cached_toy_state(32);
    let second_ms = second.elapsed().as_millis();

    assert!(
        std::ptr::eq(
            std::sync::Arc::as_ptr(&a.encoded_db),
            std::sync::Arc::as_ptr(&b.encoded_db)
        ),
        "the second call must reuse the cached allocation"
    );
    assert!(
        second_ms < 1_000,
        "second build took {second_ms} ms after a {first_ms} ms first build; \
         that is not a cache hit, so the within-test amortisation is broken"
    );
}

/// A different record size is a different cache slot and pays its own build.
///
/// Asserted because the opposite - one slot serving every width - is the silent-wrong-bytes
/// failure this codebase is most prone to: a 32-byte fixture handed to a 256-byte test does not
/// error, it decrypts to the wrong bytes.
#[test]
fn a_different_record_size_does_not_reuse_the_other_slot() {
    let narrow = cached_toy_state(32);
    let wide = cached_toy_state(256);
    assert!(
        !std::ptr::eq(
            std::sync::Arc::as_ptr(&narrow.encoded_db),
            std::sync::Arc::as_ptr(&wide.encoded_db)
        ),
        "32 B and 256 B must never share an encoded database"
    );
    assert_eq!(narrow.shard_config().entry_size_bytes, 32);
    assert_eq!(wide.shard_config().entry_size_bytes, 256);
}
