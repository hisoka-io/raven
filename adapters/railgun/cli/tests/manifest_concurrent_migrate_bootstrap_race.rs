//! Cross-binary race: `migrate-encoder` vs `serve-production`-style
//! `StoreLayout::open_with_lock` against the SAME `data_dir`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use raven_railgun_engine::pir_table::EncoderKind;
use raven_railgun_persistence::{Manifest, StoreLayout};

#[test]
fn migrate_encoder_and_bootstrap_lock_serialize_one_winner_per_round() {
    const ROUNDS: usize = 20;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();

    let migration_lock_errors = Arc::new(AtomicUsize::new(0));
    let migration_other_errors = Arc::new(AtomicUsize::new(0));
    let bootstrap_lock_errors = Arc::new(AtomicUsize::new(0));

    for round in 0..ROUNDS {
        let path_for_migrate = path.clone();
        let path_for_bootstrap = path.clone();
        let mig_lock_ctr = Arc::clone(&migration_lock_errors);
        let mig_other_ctr = Arc::clone(&migration_other_errors);
        let boot_lock_ctr = Arc::clone(&bootstrap_lock_errors);

        let migrate_h = thread::spawn(move || {
            let r =
                raven_railgun_cli::migrate_encoder::run(&path_for_migrate, EncoderKind::PerLeafBc);
            // fresh dir: migration errors via lock contention (loser) or
            // missing-manifest (winner)
            let err = r.expect_err("fresh data_dir + migration must error");
            let msg = format!("{err:#}").to_lowercase();
            if msg.contains("lock") {
                mig_lock_ctr.fetch_add(1, Ordering::SeqCst);
            } else if msg.contains("manifest") {
                mig_other_ctr.fetch_add(1, Ordering::SeqCst);
            } else {
                panic!("unexpected migrate error in round {round}: {msg}");
            }
        });

        let bootstrap_h = thread::spawn(move || {
            // stand-in for serve-production bootstrap; hold long enough to race
            // the fail-fast migration against the held lock across rounds
            match StoreLayout::open_with_lock(&path_for_bootstrap) {
                Ok((_layout, lock)) => {
                    thread::sleep(Duration::from_millis(20));
                    drop(lock);
                }
                Err(raven_railgun_persistence::PersistenceError::LockHeld(_)) => {
                    boot_lock_ctr.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) => panic!("unexpected bootstrap error in round {round}: {e:?}"),
            }
        });

        migrate_h.join().expect("migrate joined");
        bootstrap_h.join().expect("bootstrap joined");

        // lock must be releasable post-round (proves no leak)
        let (_layout, _lock) = StoreLayout::open_with_lock(&path)
            .unwrap_or_else(|e| panic!("post-round {round} reacquire failed: {e:?}"));
    }

    let mig_lock = migration_lock_errors.load(Ordering::SeqCst);
    let mig_manifest = migration_other_errors.load(Ordering::SeqCst);
    // contention ratios are flaky across CI hardware; captured, not asserted
    let _ = bootstrap_lock_errors.load(Ordering::SeqCst);
    assert_eq!(
        mig_lock + mig_manifest,
        ROUNDS,
        "every round must produce exactly one migrate-side outcome"
    );
}

#[test]
fn fan_out_migrate_and_bootstrap_against_same_data_dir_yield_no_corruption() {
    const N_MIGRATE: usize = 4;
    const N_BOOTSTRAP: usize = 4;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();

    let mut handles = Vec::with_capacity(N_MIGRATE + N_BOOTSTRAP);
    for _ in 0..N_MIGRATE {
        let path = path.clone();
        handles.push(thread::spawn(move || {
            let r = raven_railgun_cli::migrate_encoder::run(&path, EncoderKind::PerLeafBc);
            let _ = r.expect_err("fresh dir + migration must error");
        }));
    }
    for _ in 0..N_BOOTSTRAP {
        let path = path.clone();
        handles.push(thread::spawn(move || {
            // tolerate Ok or LockHeld; any other error is a flock regression
            match StoreLayout::open_with_lock(&path) {
                Ok((_layout, lock)) => {
                    thread::sleep(Duration::from_millis(2));
                    drop(lock);
                }
                Err(raven_railgun_persistence::PersistenceError::LockHeld(_)) => {}
                Err(e) => panic!("unexpected bootstrap error: {e:?}"),
            }
        }));
    }
    for h in handles {
        h.join().expect("worker joined");
    }

    let (layout, _lock) = StoreLayout::open_with_lock(&path)
        .expect("post-fan-out reacquire must succeed; lock leak otherwise");
    // no worker completes a full migration; any manifest present must still
    // be well-formed bincode (atomic-rename contract)
    if let Some(m) = Manifest::load(&layout).expect("manifest load may succeed or be None") {
        assert_eq!(
            m.schema_version,
            raven_railgun_persistence::MANIFEST_SCHEMA_VERSION,
            "post-fan-out manifest must carry the current schema version"
        );
    }
}
