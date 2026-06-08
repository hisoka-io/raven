//! Restart must honour the per-tree recovered manifest floor: the indexer
//! must neither re-emit already-applied events (toml=0) nor skip events for
//! lower-height instances under a global `start_block` (toml=max-recovered).
//! Covers `compute_effective_start_block` (global max), its per-tree variant,
//! and `manifest_block_height` (the accessor that feeds the CLI build site).

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
    // operator-advanced floor past the recovered baseline must win
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

/// `manifest_block_height()` must return the committed height after reopen;
/// a stub returning 0 drops the indexer cursor back to `opts.start_block`.
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

/// Two instances committed at distinct heights must yield distinct per-tree
/// floors, not collapse to a single global floor.
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
