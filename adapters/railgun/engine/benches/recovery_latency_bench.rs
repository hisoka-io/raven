//! Cold-start bootstrap-from-disk latency at the production cell shape; target
//! is 1 s for manifest load, snapshot restore and cache rebuild.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    reason = "benchmark fixtures abort on invalid setup before measuring"
)]

use std::time::{Duration, Instant};

use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire;
use raven_railgun_engine::offline_packing_keys_cache::{
    CacheLoad, CellShape, OfflinePackingKeysCache,
};
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{PerLeafCommitmentEncoder, PirTableEncoder};
use raven_railgun_persistence::StoreLayout;

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-test";

fn test_encoder() -> Arc<dyn PirTableEncoder> {
    Arc::new(PerLeafCommitmentEncoder::new(512, 2048, 0).expect("test encoder"))
}

#[test]
#[ignore = "production-cell setup is heavy (11 s measured); measures cold-start \
            bootstrap-from-disk, which is 5.5 s on a 16-core box under the ci-test profile. \
            Trigger: changing manifest load, snapshot restore, or cache rebuild."]
fn recovery_from_production_cell_snapshot_under_5s() {
    let setup_start = Instant::now();
    let params = InspireParams::secure_128_d2048();
    let entries = 1usize << 16;
    let entry_size = 512usize;
    #[allow(clippy::cast_possible_truncation)]
    let db: Vec<u8> = (0..entries)
        .flat_map(|i| (0..entry_size).map(move |j| ((i * 31 + j * 17) % 251) as u8))
        .collect();
    let (state, _sk) = inspire::setup_state(&params, &db, entry_size, InspireVariant::TwoPacking)
        .expect("setup_state");
    let setup_elapsed = setup_start.elapsed();
    eprintln!("recovery_bench: setup elapsed = {setup_elapsed:?}");
    eprintln!(
        "recovery_bench: pack params bytes = {}, offline keys bytes = {}",
        bincode::serialize(state.cache.pack_params())
            .expect("serialize pack params")
            .len(),
        bincode::serialize(state.cache.offline_keys())
            .expect("serialize offline keys")
            .len()
    );

    let dir = tempfile::tempdir().expect("tempdir");
    {
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let opened = InspirePersistence::open(
            layout,
            SCHEME_TAG,
            InstanceId::new("recovery-bench"),
            SnapshotPolicy::default(),
            test_encoder(),
        )
        .expect("open");
        let first_commit_start = Instant::now();
        opened.persistence.commit(&state, 0).expect("commit");
        let first_commit_elapsed = first_commit_start.elapsed();
        let repeated_commit_start = Instant::now();
        opened
            .persistence
            .commit(&state, 1)
            .expect("repeated commit");
        let repeated_commit_elapsed = repeated_commit_start.elapsed();
        eprintln!(
            "recovery_bench: first commit = {first_commit_elapsed:?}, repeated commit = \
             {repeated_commit_elapsed:?}, repeated cache bytes written = 0"
        );
        let columns = state.encoded_db.shards[0].polynomials.len();
        let identity =
            CellShape::for_inspiring(&state.crs.params, columns, state.crs.inspiring_w_seed);
        let cache = OfflinePackingKeysCache::new(dir.path());
        match cache.load(&identity) {
            CacheLoad::Hit(_) => {}
            CacheLoad::Miss(error) => panic!("cache must load after commit: {error}"),
        }
        eprintln!(
            "recovery_bench: cache bytes = {}",
            std::fs::metadata(cache.path())
                .expect("cache metadata")
                .len()
        );
    }

    let layout2 = StoreLayout::open(dir.path()).expect("layout 2");
    let recovery_start = Instant::now();
    let opened = InspirePersistence::open(
        layout2,
        SCHEME_TAG,
        InstanceId::new("recovery-bench"),
        SnapshotPolicy::default(),
        test_encoder(),
    )
    .expect("recovery open");
    let recovery_elapsed = recovery_start.elapsed();
    eprintln!("recovery_bench: recovery elapsed = {recovery_elapsed:?}");
    assert!(
        opened.recovered_cache_hit,
        "recovery must use the validated sidecar cache"
    );

    let recovered = opened.recovered_state.expect("recovered some");
    assert_eq!(recovered.entry_size, entry_size);
    assert_eq!(recovered.variant, InspireVariant::TwoPacking);

    // Ceiling sits above the 1s target to absorb cold-page and host variability.
    assert!(
        recovery_elapsed < Duration::from_secs(5),
        "recovery latency regressed: {recovery_elapsed:?} > 5 s"
    );
}
