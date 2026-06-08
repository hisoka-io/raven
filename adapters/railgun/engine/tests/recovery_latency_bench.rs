//! Recovery latency bench (`#[ignore]`-gated): cold-start latency for
//! the bootstrap-from-disk path at the production cell shape
//! (65,536 x 512 B). Target <= 1 s for manifest-load + snapshot-restore
//! + cache rebuild.

#![allow(clippy::expect_used, clippy::print_stderr)]

use std::time::{Duration, Instant};

use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire;
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{PerLeafCommitmentEncoder, PirTableEncoder};
use raven_railgun_persistence::StoreLayout;

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-test";

fn test_encoder() -> Arc<dyn PirTableEncoder> {
    Arc::new(PerLeafCommitmentEncoder::new(512, 2048).expect("test encoder"))
}

#[test]
#[ignore = "production-cell setup is heavy (~12s); cold-start measurement"]
// asserts < 5s; the < 1s target needs cache-carry-across-swaps, not yet implemented
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
        opened.persistence.commit(&state, 0).expect("commit");
    }

    // cold start: manifest-load + snapshot-load + deserialize + cache rebuild; WAL replay is empty
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

    let recovered = opened.recovered_state.expect("recovered some");
    assert_eq!(recovered.entry_size, entry_size);
    assert_eq!(recovered.variant, InspireVariant::TwoPacking);

    // 5s floor (target is 1s): absorbs first-cold-page noise and contended-host variability
    assert!(
        recovery_elapsed < Duration::from_secs(5),
        "recovery latency regressed: {recovery_elapsed:?} > 5 s"
    );
}
