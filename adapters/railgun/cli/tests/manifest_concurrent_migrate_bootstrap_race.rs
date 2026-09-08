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
use raven_railgun_persistence::StoreLayout;

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
            let r = raven_railgun_cli::migrate_encoder::run(
                &path_for_migrate,
                EncoderKind::PerLeafBc { tree_number: 0 },
            );
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
            // Held long enough to race the fail-fast migration across rounds.
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

        // Releasable post-round, proving no leak.
        let (_layout, _lock) = StoreLayout::open_with_lock(&path)
            .unwrap_or_else(|e| panic!("post-round {round} reacquire failed: {e:?}"));
    }

    // Contention ratios are flaky across CI hardware, so these are captured for the
    // failure message and not asserted. The sum that used to be asserted here could
    // not fail: the migrate thread either increments one of the two counters or
    // panics, and the panic fails join().expect above first. Mutation-proved -
    // deleting the 20 ms hold above removes the contention window entirely and the
    // old assertion stayed green (0.466 s -> 0.013 s).
    let mig_lock = migration_lock_errors.load(Ordering::SeqCst);
    let mig_manifest = migration_other_errors.load(Ordering::SeqCst);
    let boot_lock = bootstrap_lock_errors.load(Ordering::SeqCst);

    // The racing rounds cannot promise WHICH side wins, so none of them observes
    // exclusion. This round forces it: the lock is held here across the migration,
    // so a migration that is refused for any reason OTHER than the lock proves the
    // flock stopped serializing.
    let (_held_layout, held) =
        StoreLayout::open_with_lock(&path).expect("hold for the forced round");
    let forced =
        raven_railgun_cli::migrate_encoder::run(&path, EncoderKind::PerLeafBc { tree_number: 0 });
    drop(held);
    let forced_msg = format!(
        "{:#}",
        forced.expect_err("migration against a held data_dir lock must error")
    )
    .to_lowercase();
    assert!(
        forced_msg.contains("lock"),
        "a migration started while the data_dir lock is held must fail ON THE LOCK, not on the \
         missing manifest it would reach past an unheld one; got {forced_msg:?} \
         (racing rounds: {mig_lock} lock / {mig_manifest} manifest / {boot_lock} bootstrap-lock)"
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
            let r = raven_railgun_cli::migrate_encoder::run(
                &path,
                EncoderKind::PerLeafBc { tree_number: 0 },
            );
            let msg =
                format!("{:#}", r.expect_err("fresh dir + migration must error")).to_lowercase();
            // Same two-outcome classification test 1 makes; discarding the error here
            // let any new failure mode pass as "it errored, good".
            assert!(
                msg.contains("lock") || msg.contains("manifest"),
                "fan-out migrate must fail on the lock or the missing manifest; got {msg:?}"
            );
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

    let (_layout, _lock) = StoreLayout::open_with_lock(&path)
        .expect("post-fan-out reacquire must succeed; lock leak otherwise");
    // A schema_version check used to sit here. It was unreachable: migrate_encoder::run
    // bails before writing anything and open_with_lock writes no manifest, so on a fresh
    // tempdir Manifest::load is always None. Mutation-proved - a panic! planted inside
    // that branch never fired.
}
