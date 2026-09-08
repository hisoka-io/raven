//! Restart must honour the per-tree recovered manifest floor: the indexer
//! must neither re-emit already-applied events (toml=0) nor skip events for
//! lower-height instances under a global `start_block` (toml=max-recovered).
//! Covers `compute_effective_start_block` (global max), its per-tree variant,
//! and `manifest_block_height` (the accessor that feeds the CLI build site).

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::Arc;

use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_cli::serve_production_multi::{
    compute_effective_start_block, compute_effective_start_block_per_tree,
    per_tree_recovered_floors,
};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{setup_state, LogicalLeafStore};
use raven_railgun_engine::orchestrator::{InstanceConfig, PerInstanceHandles};
use raven_railgun_engine::persistence::{
    ConsumerEvent, ConsumerMetrics, InspirePersistence, SnapshotPolicy,
};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_engine::{InstanceRole, PirInstance};
use raven_railgun_persistence::{StoreLayout, WalEntryPayload};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-start-block-fallback";
const ENTRIES_PER_SHARD: u32 = 2048;
const ENTRY_BYTES: usize = 32;

fn encoder() -> Arc<dyn PirTableEncoder> {
    EncoderKind::PerLeafBc { tree_number: 0 }
        .build(ENTRY_BYTES, ENTRIES_PER_SHARD)
        .expect("build encoder")
}

/// Independent oracle for the global floor: an explicit scan, not the subject's
/// `max().unwrap_or(0).max()` restated. The empty slice needs no special case
/// here, which is what makes it an oracle for the fresh-bootstrap arm rather
/// than a copy of the code under test.
fn expected_global_floor(toml_start_block: u64, recovered: &[u64]) -> u64 {
    let mut floor = toml_start_block;
    for &height in recovered {
        if height > floor {
            floor = height;
        }
    }
    floor
}

fn check_global_floor(toml_start_block: u64, recovered: &[u64]) -> Result<(), TestCaseError> {
    prop_assert_eq!(
        compute_effective_start_block(toml_start_block, recovered),
        expected_global_floor(toml_start_block, recovered),
        "global floor for toml={} recovered={:?}",
        toml_start_block,
        recovered
    );
    Ok(())
}

fn check_per_tree_floor(
    toml_start_block: u64,
    recovered: &BTreeMap<u32, u64>,
) -> Result<(), TestCaseError> {
    let got = compute_effective_start_block_per_tree(toml_start_block, recovered);
    // Key set, not just length: a map that dropped a tree and invented another
    // would keep the count.
    prop_assert!(
        got.keys().eq(recovered.keys()),
        "per-tree floors must cover exactly the recovered trees; got {:?} for {:?}",
        got.keys().collect::<Vec<_>>(),
        recovered.keys().collect::<Vec<_>>()
    );
    for (&tree, &recovered_height) in recovered {
        let Some(&floor) = got.get(&tree) else {
            return Err(TestCaseError::fail(format!(
                "tree {tree} missing from the floors map"
            )));
        };
        // "at least both, and equal to one of them" characterises max without
        // restating it, so a global collapse (every key the same value) fails
        // the second half on any tree whose own height is not that value.
        prop_assert!(
            floor >= toml_start_block && floor >= recovered_height,
            "tree {} floor {} must not sit below toml {} or recovered {}",
            tree,
            floor,
            toml_start_block,
            recovered_height
        );
        prop_assert!(
            floor == toml_start_block || floor == recovered_height,
            "tree {} floor {} must be one of toml {} / recovered {}, not a derived value",
            tree,
            floor,
            toml_start_block,
            recovered_height
        );
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Replaces four hand-written examples: recovered-above-toml, toml-above-recovered,
    /// max-across-instances, and the fresh-bootstrap pair (no manifest / all-zero
    /// manifests). The last two are not left to the generator - every case re-runs the
    /// drawn `toml` against the empty slice and against an all-zero slice.
    #[test]
    fn effective_start_block_is_the_highest_of_toml_and_every_recovered_height(
        toml_start_block in prop_oneof![
            Just(0u64),
            Just(25_030_578u64),
            Just(u64::MAX),
            any::<u64>(),
        ],
        recovered in prop::collection::vec(
            prop_oneof![Just(0u64), Just(u64::MAX), 0u64..30_000_000, any::<u64>()],
            0..8,
        ),
    ) {
        check_global_floor(toml_start_block, &recovered)?;
        check_global_floor(toml_start_block, &[])?;
        check_global_floor(toml_start_block, &vec![0u64; recovered.len()])?;
    }

    /// Replaces the two per-tree examples. Same deterministic boundary treatment:
    /// the empty map and the all-zero map are re-checked in every case.
    #[test]
    fn effective_start_block_per_tree_lifts_each_tree_to_its_own_floor(
        toml_start_block in prop_oneof![
            Just(0u64),
            Just(25_030_578u64),
            Just(u64::MAX),
            any::<u64>(),
        ],
        recovered in prop::collection::btree_map(
            0u32..6,
            prop_oneof![Just(0u64), Just(u64::MAX), 0u64..30_000_000, any::<u64>()],
            0..6,
        ),
    ) {
        check_per_tree_floor(toml_start_block, &recovered)?;
        check_per_tree_floor(toml_start_block, &BTreeMap::new())?;
        let zeroed: BTreeMap<u32, u64> = recovered.keys().map(|&t| (t, 0u64)).collect();
        check_per_tree_floor(toml_start_block, &zeroed)?;
    }
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

fn canonical_leaf(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&v.to_be_bytes());
    out
}

fn append_leaf(tree_number: u32, leaf_index: u32) -> WalEntryPayload {
    WalEntryPayload::AppendLeaf {
        tree_number,
        leaf_index,
        commitment: canonical_leaf(u64::from(leaf_index) + 1),
    }
}

/// A reorg lowers the committed manifest marker but `LogicalLeafStore::
/// last_block_height` is monotone, so a floor that folded the store height in
/// would resume above the rollback and never re-index the unwound blocks.
#[tokio::test]
async fn per_tree_floor_follows_the_manifest_after_a_reorg_rollback() {
    let dir = tempfile::tempdir().expect("tempdir");
    let params = InspireParams::secure_128_d2048();
    let db: Vec<u8> = (0..(ENTRIES_PER_SHARD as usize) * ENTRY_BYTES)
        .map(|i| u8::try_from(i & 0xff).expect("byte"))
        .collect();
    let (state, _sk) =
        setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("setup_state");

    let enc = encoder();
    let mut store = LogicalLeafStore::new();
    store
        .apply(&append_leaf(0, 0), 400, enc.as_ref())
        .expect("leaf 0 at block 400");
    store
        .apply(&append_leaf(0, 1), 500, enc.as_ref())
        .expect("leaf 1 at block 500");
    store
        .apply(&WalEntryPayload::Reorg { height: 450 }, 450, enc.as_ref())
        .expect("reorg to 450");
    assert_eq!(
        store.last_block_height(),
        500,
        "store height is monotone: the reorg must not lower it, else this test \
         proves nothing about the floor"
    );

    let layout = StoreLayout::open(dir.path()).expect("layout");
    let opened = InspirePersistence::open(
        layout,
        SCHEME_TAG,
        InstanceId::new("reorg-floor-tree-0"),
        SnapshotPolicy::default(),
        encoder(),
    )
    .expect("open");
    let persistence = Arc::new(opened.persistence);
    persistence
        .commit_v6(&state, &store, 450)
        .expect("post-reorg commit at the rolled-back height");
    assert_eq!(persistence.manifest_block_height(), 450);

    let (sender, _rx) = tokio::sync::mpsc::channel::<ConsumerEvent>(1);
    let handles = vec![PerInstanceHandles {
        config: InstanceConfig::commit_tree(
            "reorg-floor-tree-0",
            dir.path().to_path_buf(),
            0,
            InstanceRole::Live,
        ),
        instance: Arc::new(PirInstance::new(
            InstanceId::new("reorg-floor-tree-0"),
            InstanceRole::Live,
            state,
        )),
        persistence: Arc::clone(&persistence),
        consumer: tokio::spawn(async { Ok(()) }),
        sender,
        metrics: Arc::new(parking_lot::Mutex::new(ConsumerMetrics::default())),
        logical_store: Arc::new(parking_lot::Mutex::new(store)),
    }];

    let floors = per_tree_recovered_floors(&handles);
    assert_eq!(
        floors.get(&0),
        Some(&450),
        "the manifest marker is authoritative after a reorg; folding in the \
         monotone store height (500) would skip blocks 451..=500 and leave the \
         tree permanently one leaf short of chain state"
    );
}
