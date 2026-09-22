//! A counter must still render its true total after the registry's map has grown.
//!
//! `metrics` 0.24.5 shipped a `Key` whose `Hash` impl disagreed with `Key::get_hash()`.
//! `metrics_util::Registry` looks entries up by `get_hash()` through
//! `raw_entry_mut().from_key_hashed_nocheck(..)`, which bypasses the `BuildHasher` — but a
//! hashbrown **resize** cannot bypass it and rehashes every stored key through `KeyHasher`.
//! The two disagreed, so a grown shard relocated entries where the next lookup would never
//! probe, and each further `counter!` re-registered the key. The scrape then rendered one of
//! the duplicates arbitrarily and an incremented counter could read low, or zero.
//!
//! It bit here: two `mirror_preflight_boot` tests asserting a counter on `/metrics` passed
//! locally and failed in CI, because CI's key population crossed the resize point and a dev
//! box's did not. Fixed upstream in 0.24.6 (metrics-rs #694).
//!
//! This test exists so a future `cargo update` cannot walk the lockfile back into it. It
//! forces the resize rather than hoping for one, which is the whole point: the defect is
//! invisible below the growth threshold.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

/// Enough distinct keys to grow every shard past its initial capacity several times over.
const KEYS_FORCING_RESIZE: usize = 512;

#[test]
fn a_counter_still_renders_its_total_after_the_registry_map_grows() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    metrics::with_local_recorder(&recorder, || {
        // Registered BEFORE the growth, so the resize has something of ours to relocate.
        metrics::counter!("raven_resize_probe", "phase" => "before").increment(3);

        for i in 0..KEYS_FORCING_RESIZE {
            metrics::counter!("raven_resize_filler", "i" => i.to_string()).increment(1);
        }

        // Re-resolved from scratch after the growth: this is the lookup that missed.
        metrics::counter!("raven_resize_probe", "phase" => "before").increment(4);
    });

    let rendered = handle.render();
    let line = rendered
        .lines()
        .find(|l| l.starts_with("raven_resize_probe{"))
        .unwrap_or_else(|| {
            panic!("the probe counter is absent from the scrape entirely:\n{rendered}")
        });

    let value: u64 = line
        .rsplit(' ')
        .next()
        .expect("a rendered counter line ends in its value")
        .parse()
        .unwrap_or_else(|e| panic!("could not parse {line:?}: {e}"));

    assert_eq!(
        value, 7,
        "a counter incremented by 3 then 4 across a registry resize must render 7, got {value}; \
         a low or zero value means the registry is bucketing keys by a hash that disagrees with \
         Key::get_hash() -- check that the lockfile has not moved metrics below 0.24.6"
    );

    // One key means one entry. Duplicates are the defect's signature and render arbitrarily.
    let occurrences = rendered
        .lines()
        .filter(|l| l.starts_with("raven_resize_probe{"))
        .count();
    assert_eq!(
        occurrences, 1,
        "the probe key must appear exactly once; {occurrences} lines means the registry holds \
         duplicate entries for one key:\n{rendered}"
    );
}
