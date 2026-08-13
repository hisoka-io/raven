//! `migrate-encoder` must serialize against a live `serve-production` holding the
//! same `data_dir` lock, and release the gate on Err return.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use raven_railgun_engine::pir_table::EncoderKind;
use raven_railgun_persistence::StoreLayout;

#[test]
fn migrate_encoder_refuses_while_serve_production_holds_data_dir_lock() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().to_path_buf();

    // Reproduces contention without a full server boot.
    let (_layout, server_lock) =
        StoreLayout::open_with_lock(&data_dir).expect("server-side lock acquire");

    let result = raven_railgun_cli::migrate_encoder::run(
        &data_dir,
        EncoderKind::PerLeafBc { tree_number: 0 },
    );
    let err = result.expect_err("migrate-encoder must refuse while server holds the lock");
    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("lock"),
        "error message should mention the lock contention so operator grep \
         finds the path immediately; got: {msg}"
    );

    // A released gate flips the error from "lock" to "manifest" on a fresh data_dir.
    drop(server_lock);

    let result_after = raven_railgun_cli::migrate_encoder::run(
        &data_dir,
        EncoderKind::PerLeafBc { tree_number: 0 },
    );
    let err_after = result_after
        .expect_err("fresh data_dir has no manifest; migration must error past the lock gate");
    let msg_after = format!("{err_after:#}");
    assert!(
        msg_after.to_lowercase().contains("manifest"),
        "after lock release the error should be about the missing manifest, \
         not the lock; got: {msg_after}"
    );
}

#[test]
fn migrate_encoder_lock_release_permits_a_second_migration_invocation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().to_path_buf();

    let r1 = raven_railgun_cli::migrate_encoder::run(
        &data_dir,
        EncoderKind::PerLeafBc { tree_number: 0 },
    );
    assert!(r1.is_err(), "fresh data_dir must error on missing manifest");

    let r2 = raven_railgun_cli::migrate_encoder::run(
        &data_dir,
        EncoderKind::PerLeafBc { tree_number: 0 },
    );
    let err2 = r2.expect_err("second invocation also errors on missing manifest");
    let msg2 = format!("{err2:#}");
    assert!(
        !msg2.to_lowercase().contains("lock"),
        "second invocation must reach past the lock gate (proving the first \
         call released its lock on Err return); got: {msg2}"
    );
}
