//! Operator-trust regression: every multi-instance restart must respect
//! the per-tree recovered manifest floor so the indexer does not silently
//! re-emit events the consumer task has already applied (toml = 0 case),
//! and does not silently SKIP events for lower-height instances when an
//! operator picks a global `start_block` (toml = max-recovered case).
//!
//! Three behaviours covered:
//!
//! 1. [`compute_effective_start_block`] — global MAX fallback used by
//!    the single-instance serve path. Locks the `max(toml, recovered)`
//!    invariant against future drift.
//!
//! 2. [`compute_effective_start_block_per_tree`] — per-tree MAX
//!    fallback used by the multi-instance serve path. Locks the
//!    per-tree map shape so a 3-instance deployment at heterogeneous
//!    heights does not collapse to a single global floor.
//!
//! 3. [`InspirePersistence::manifest_block_height`] — the build-site
//!    accessor that surfaces the recovered height to the CLI. Pre-fix
//!    this accessor did not exist on raven and the CLI built
//!    `IndexerWorkerConfig` with `per_tree_start_blocks = BTreeMap::new()`,
//!    making the indexer's already-tested per-tree drop site
//!    (`indexer/src/lib.rs:746`) unreachable in production.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_cli::serve_production_multi::{
    compute_effective_start_block, compute_effective_start_block_per_tree,
};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{setup_state, LogicalLeafStore};
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_persistence::StoreLayout;

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-start-block-fallback";
const ENTRIES_PER_SHARD: u32 = 2048;
const ENTRY_BYTES: usize = 32;

fn encoder() -> Arc<dyn PirTableEncoder> {
    EncoderKind::PerLeafBc
        .build(ENTRY_BYTES, ENTRIES_PER_SHARD)
        .expect("build encoder")
}

#[test]
fn indexer_resume_uses_manifest_block_height_when_higher_than_toml_start_block() {
    let recovered = [100u64];
    assert_eq!(compute_effective_start_block(50, &recovered), 100);
}

#[test]
fn indexer_fresh_bootstrap_uses_toml_start_block_when_no_manifest() {
    let recovered: Vec<u64> = Vec::new();
    assert_eq!(
        compute_effective_start_block(25_030_578, &recovered),
        25_030_578
    );
    let zero_recovered = [0u64, 0u64, 0u64];
    assert_eq!(
        compute_effective_start_block(25_030_578, &zero_recovered),
        25_030_578
    );
}

#[test]
fn indexer_resume_uses_toml_start_block_when_higher_than_manifest_height() {
    // Operator manually advanced the floor past the recovered baseline
    // (e.g. fast-forwarded after restoring from a snapshot). The
    // indexer must honour that override and not silently slip back to
    // the recovered height.
    let recovered = [50u64, 75u64];
    assert_eq!(compute_effective_start_block(100, &recovered), 100);
}

#[test]
fn effective_start_block_takes_max_across_instances() {
    let recovered = [10u64, 200u64, 50u64];
    assert_eq!(compute_effective_start_block(0, &recovered), 200);
}

#[test]
fn effective_start_block_per_tree_uses_max_of_toml_and_recovered_per_instance() {
    let mut recovered: BTreeMap<u32, u64> = BTreeMap::new();
    recovered.insert(0, 25_000_000);
    recovered.insert(1, 24_000_000);
    recovered.insert(2, 23_000_000);
    let result = compute_effective_start_block_per_tree(0, &recovered);
    assert_eq!(result.get(&0), Some(&25_000_000));
    assert_eq!(result.get(&1), Some(&24_000_000));
    assert_eq!(result.get(&2), Some(&23_000_000));

    let toml_above = compute_effective_start_block_per_tree(25_500_000, &recovered);
    assert_eq!(toml_above.get(&0), Some(&25_500_000));
    assert_eq!(toml_above.get(&1), Some(&25_500_000));
    assert_eq!(toml_above.get(&2), Some(&25_500_000));
}

#[test]
fn effective_start_block_per_tree_falls_back_to_toml_when_no_recovered_height() {
    let mut recovered: BTreeMap<u32, u64> = BTreeMap::new();
    recovered.insert(0, 0);
    recovered.insert(1, 0);
    let result = compute_effective_start_block_per_tree(25_030_578, &recovered);
    assert_eq!(result.get(&0), Some(&25_030_578));
    assert_eq!(result.get(&1), Some(&25_030_578));

    let empty: BTreeMap<u32, u64> = BTreeMap::new();
    let result_empty = compute_effective_start_block_per_tree(100, &empty);
    assert!(result_empty.is_empty());
}

/// End-to-end accessor wire-up: after a successful `commit_v6` at block
/// height H, reopening the persistence and reading
/// `manifest_block_height()` must return H. The multi-instance CLI
/// build site at `serve_production_multi.rs` consumes this accessor to
/// populate `per_tree_start_blocks`; if the accessor reverts to a stub
/// returning 0 (or is removed), the indexer cursor silently drops back
/// to `opts.start_block` and every restart re-scans the prefix below
/// the recovered floor.
#[test]
fn manifest_block_height_reflects_committed_height_after_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let params = InspireParams::secure_128_d2048();
    let db: Vec<u8> = (0..(ENTRIES_PER_SHARD as usize) * ENTRY_BYTES)
        .map(|i| u8::try_from(i & 0xff).expect("byte"))
        .collect();
    let (state, _sk) =
        setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("setup_state");
    let store = LogicalLeafStore::new();

    // Phase 1: fresh open, commit at height 12_345.
    {
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("manifest-height-test"),
            SnapshotPolicy::default(),
            encoder(),
        )
        .expect("fresh open");
        assert_eq!(
            opened.persistence.manifest_block_height(),
            0,
            "fresh bootstrap baseline must be 0 before the first commit"
        );
        opened
            .persistence
            .commit_v6(&state, &store, 12_345)
            .expect("commit_v6 at 12345");
        assert_eq!(
            opened.persistence.manifest_block_height(),
            12_345,
            "post-commit accessor must reflect the committed height"
        );
    }

    // Phase 2: reopen; the manifest_block_height must survive the
    // round-trip and surface the committed height before any new commit
    // lands.
    let layout = StoreLayout::open(dir.path()).expect("layout reopen");
    let opened = InspirePersistence::open(
        layout,
        SCHEME_TAG,
        InstanceId::new("manifest-height-test"),
        SnapshotPolicy::default(),
        encoder(),
    )
    .expect("reopen");
    assert_eq!(
        opened.persistence.manifest_block_height(),
        12_345,
        "manifest_block_height must survive reopen so the CLI's \
         per_tree_recovered build sees the committed floor"
    );
}

/// Heterogeneous-height multi-instance scenario at the CLI build-site
/// level: two persistence handles committed at distinct block heights
/// produce distinct entries in the per-tree map, and
/// `compute_effective_start_block_per_tree(0, &map)` preserves the
/// per-tree distinction. Locks the read path that
/// `serve_production_multi::run` walks on bootstrap.
#[test]
fn two_instances_at_different_heights_yield_per_tree_distinct_floors() {
    let dir_a = tempfile::tempdir().expect("tempdir A");
    let dir_b = tempfile::tempdir().expect("tempdir B");
    let params = InspireParams::secure_128_d2048();
    let db: Vec<u8> = (0..(ENTRIES_PER_SHARD as usize) * ENTRY_BYTES)
        .map(|i| u8::try_from(i & 0xff).expect("byte"))
        .collect();
    let (state, _sk) =
        setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("setup_state");
    let store = LogicalLeafStore::new();

    let layout_a = StoreLayout::open(dir_a.path()).expect("layout A");
    let opened_a = InspirePersistence::open(
        layout_a,
        SCHEME_TAG,
        InstanceId::new("tree-0-instance"),
        SnapshotPolicy::default(),
        encoder(),
    )
    .expect("open A");
    opened_a
        .persistence
        .commit_v6(&state, &store, 25_000_000)
        .expect("commit A");

    let layout_b = StoreLayout::open(dir_b.path()).expect("layout B");
    let opened_b = InspirePersistence::open(
        layout_b,
        SCHEME_TAG,
        InstanceId::new("tree-1-instance"),
        SnapshotPolicy::default(),
        encoder(),
    )
    .expect("open B");
    opened_b
        .persistence
        .commit_v6(&state, &store, 23_000_000)
        .expect("commit B");

    let mut per_tree_recovered: BTreeMap<u32, u64> = BTreeMap::new();
    per_tree_recovered.insert(0u32, opened_a.persistence.manifest_block_height());
    per_tree_recovered.insert(1u32, opened_b.persistence.manifest_block_height());

    assert_eq!(
        per_tree_recovered.get(&0),
        Some(&25_000_000),
        "tree-0 recovered floor must reflect committed height A"
    );
    assert_eq!(
        per_tree_recovered.get(&1),
        Some(&23_000_000),
        "tree-1 recovered floor must reflect committed height B"
    );

    let floors = compute_effective_start_block_per_tree(0, &per_tree_recovered);
    assert_eq!(
        floors.get(&0),
        Some(&25_000_000),
        "tree-0 effective floor preserves the higher recovered height"
    );
    assert_eq!(
        floors.get(&1),
        Some(&23_000_000),
        "tree-1 effective floor preserves the lower recovered height; \
         a regression that collapsed the per-tree map to a global floor \
         would either replay events in (23M, 25M] against tree-1 (toml=0) \
         or silently skip them (toml=25M)"
    );
}
