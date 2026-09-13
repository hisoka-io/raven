//! A data_dir stored at one row width must not reopen under an encoder emitting
//! a different width; `encoder_label` is stable across operator-supplied widths,
//! so the label check alone cannot see it.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::{AdapterError, InstanceId};
use raven_railgun_engine::inspire::{setup_state, LogicalLeafStore};
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_persistence::{Manifest, ManifestShape, StoreLayout, MANIFEST_SCHEMA_VERSION};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-cell-shape-guard";
const ENTRIES_PER_SHARD: u32 = 2048;
const STORED_WIDTH: usize = 512;
const NARROW_WIDTH: usize = 32;
const CELL_ROWS: usize = 64;

fn encoder_at(width: usize) -> Arc<dyn PirTableEncoder> {
    encoder_with_rows(width, ENTRIES_PER_SHARD)
}

fn encoder_with_rows(width: usize, entries_per_shard: u32) -> Arc<dyn PirTableEncoder> {
    EncoderKind::PerLeafBc { tree_number: 0 }
        .build(width, entries_per_shard)
        .expect("build per-leaf-bc encoder")
}

fn seed_data_dir(dir: &std::path::Path, instance: &str, stored_width: usize) {
    let layout = StoreLayout::open(dir).expect("layout");
    let opened = InspirePersistence::open(
        layout,
        SCHEME_TAG,
        InstanceId::new(instance),
        SnapshotPolicy::default(),
        encoder_at(stored_width),
    )
    .expect("fresh open");

    let params = InspireParams::secure_128_d2048();
    let db = raven_railgun_testkit::toy_db(CELL_ROWS, stored_width);
    let (state, _sk) =
        setup_state(&params, &db, stored_width, InspireVariant::TwoPacking).expect("setup_state");
    assert_eq!(state.shard_config().entry_size_bytes, stored_width);

    opened
        .persistence
        .commit_v6(&state, &LogicalLeafStore::new(), 100)
        .expect("commit_v6");
}

fn reopen(dir: &std::path::Path, instance: &str, width: usize) -> Result<(), AdapterError> {
    let layout = StoreLayout::open(dir).expect("layout reopen");
    InspirePersistence::open(
        layout,
        SCHEME_TAG,
        InstanceId::new(instance),
        SnapshotPolicy::default(),
        encoder_at(width),
    )
    .map(|_| ())
}

#[test]
fn narrower_encoder_than_stored_cell_is_refused_on_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed_data_dir(dir.path(), "narrow-vs-stored", STORED_WIDTH);

    let Err(err) = reopen(dir.path(), "narrow-vs-stored", NARROW_WIDTH) else {
        panic!(
            "SILENT WRONG: a data_dir stored at {STORED_WIDTH}-byte rows reopened under an \
             encoder emitting {NARROW_WIDTH}-byte rows. encoder_label is identical for both \
             (per-leaf-bc), so nothing downstream can tell: every re-encoded shard would pack \
             {ratio} narrow rows into one stored row and serve unrelated bytes with no \
             query-path error",
            ratio = STORED_WIDTH / NARROW_WIDTH,
        );
    };

    let msg = format!("{err}");
    for needle in [
        &STORED_WIDTH.to_string(),
        &NARROW_WIDTH.to_string(),
        "per-leaf-bc",
        "re-bootstrapped",
    ] {
        assert!(
            msg.contains(needle),
            "error must name {needle:?} to be actionable; got: {msg}"
        );
    }
    assert!(
        matches!(err, AdapterError::Internal(_)),
        "must be a typed Internal error, matching the sibling manifest-mismatch \
         rejections; got {err:?}"
    );
}

#[test]
fn wider_encoder_than_stored_cell_is_refused_on_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed_data_dir(dir.path(), "wide-vs-stored", NARROW_WIDTH);

    let Err(err) = reopen(dir.path(), "wide-vs-stored", STORED_WIDTH) else {
        panic!(
            "SILENT WRONG: a data_dir stored at {NARROW_WIDTH}-byte rows reopened under an \
             encoder emitting {STORED_WIDTH}-byte rows"
        );
    };
    assert!(matches!(err, AdapterError::Internal(_)), "got {err:?}");
}

#[test]
fn matching_width_still_reopens() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed_data_dir(dir.path(), "healthy-round-trip", STORED_WIDTH);

    let layout = StoreLayout::open(dir.path()).expect("layout reopen");
    let opened = InspirePersistence::open(
        layout,
        SCHEME_TAG,
        InstanceId::new("healthy-round-trip"),
        SnapshotPolicy::default(),
        encoder_at(STORED_WIDTH),
    )
    .expect("a data_dir reopened at its own stored width must still open");

    let recovered = opened
        .recovered_state
        .expect("post-commit reopen must surface recovered_state");
    assert_eq!(recovered.shard_config().entry_size_bytes, STORED_WIDTH);
}

#[test]
fn mismatched_rows_per_shard_are_refused_during_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed_data_dir(dir.path(), "row-mismatch", STORED_WIDTH);

    let layout = StoreLayout::open(dir.path()).expect("layout reopen");
    let error = InspirePersistence::open(
        layout,
        SCHEME_TAG,
        InstanceId::new("row-mismatch"),
        SnapshotPolicy::default(),
        encoder_with_rows(STORED_WIDTH, ENTRIES_PER_SHARD / 2),
    )
    .expect_err("recovery must not continue with a different row window");

    let message = error.to_string();
    for needle in ["per-leaf-bc", "2048", "1024", "re-bootstrapped"] {
        assert!(message.contains(needle), "missing {needle}: {message}");
    }
}

#[test]
fn legacy_v6_manifest_migrates_shape_from_its_snapshot() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed_data_dir(dir.path(), "legacy-shape-migration", STORED_WIDTH);
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let mut manifest = Manifest::load(&layout)
        .expect("manifest load")
        .expect("manifest present");
    manifest.schema_version = 6;
    manifest.entry_size_bytes = None;
    manifest.rows_per_shard = None;
    manifest.save(&layout).expect("save exact legacy shape");

    reopen(dir.path(), "legacy-shape-migration", STORED_WIDTH)
        .expect("snapshot-derived legacy migration");

    let migrated = Manifest::load(&layout)
        .expect("migrated manifest load")
        .expect("migrated manifest present");
    assert_eq!(migrated.schema_version, MANIFEST_SCHEMA_VERSION);
    assert_eq!(
        migrated.require_shape().expect("migrated shape"),
        ManifestShape {
            entry_size_bytes: STORED_WIDTH,
            rows_per_shard: u64::from(ENTRIES_PER_SHARD),
        }
    );
}

#[test]
fn legacy_manifest_without_a_snapshot_refuses_instead_of_inventing_shape() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let opened = InspirePersistence::open(
        layout.clone(),
        SCHEME_TAG,
        InstanceId::new("legacy-no-snapshot"),
        SnapshotPolicy::default(),
        encoder_at(STORED_WIDTH),
    )
    .expect("fresh open");
    drop(opened);
    let mut manifest = Manifest::load(&layout)
        .expect("manifest load")
        .expect("manifest present");
    manifest.schema_version = 6;
    manifest.entry_size_bytes = None;
    manifest.rows_per_shard = None;
    manifest.save(&layout).expect("save legacy manifest");

    let error = reopen(dir.path(), "legacy-no-snapshot", STORED_WIDTH)
        .expect_err("no persisted bytes can establish geometry");
    let message = error.to_string();
    assert!(message.contains("no cell shape"), "{message}");
    assert!(message.contains("snapshot"), "{message}");
    assert!(message.contains("re-bootstrap"), "{message}");
}

#[test]
fn fresh_manifest_refuses_a_different_configured_shape_without_a_snapshot() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let opened = InspirePersistence::open(
        layout,
        SCHEME_TAG,
        InstanceId::new("fresh-config-mismatch"),
        SnapshotPolicy::default(),
        encoder_at(STORED_WIDTH),
    )
    .expect("fresh open");
    drop(opened);

    let error = reopen(dir.path(), "fresh-config-mismatch", NARROW_WIDTH)
        .expect_err("manifest shape is authoritative before the first snapshot");
    let message = error.to_string();
    for needle in ["manifest cell shape mismatch", "32", "512", "per-leaf-bc"] {
        assert!(message.contains(needle), "missing {needle}: {message}");
    }
}

#[test]
fn manifest_shape_that_disagrees_with_snapshot_refuses() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed_data_dir(dir.path(), "manifest-vs-snapshot", STORED_WIDTH);
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let mut manifest = Manifest::load(&layout)
        .expect("manifest load")
        .expect("manifest present");
    manifest.entry_size_bytes = Some(NARROW_WIDTH);
    manifest.save(&layout).expect("save forged shape");

    let error = reopen(dir.path(), "manifest-vs-snapshot", NARROW_WIDTH)
        .expect_err("manifest and recovered snapshot must agree");
    let message = error.to_string();
    for needle in ["manifest cell shape mismatch", "32", "512", "re-bootstrap"] {
        assert!(message.contains(needle), "missing {needle}: {message}");
    }
}

#[test]
fn commit_refuses_a_state_that_disagrees_with_the_manifest_shape() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let opened = InspirePersistence::open(
        layout.clone(),
        SCHEME_TAG,
        InstanceId::new("commit-shape-mismatch"),
        SnapshotPolicy::default(),
        encoder_at(NARROW_WIDTH),
    )
    .expect("fresh open");
    let params = InspireParams::secure_128_d2048();
    let database = raven_railgun_testkit::toy_db(CELL_ROWS, STORED_WIDTH);
    let (wrong_state, _secret) =
        setup_state(&params, &database, STORED_WIDTH, InspireVariant::TwoPacking)
            .expect("wrong-width state");

    let error = opened
        .persistence
        .commit_v6(&wrong_state, &LogicalLeafStore::new(), 100)
        .expect_err("commit must not publish a snapshot at another shape");
    let message = error.to_string();
    for needle in [
        "manifest cell shape mismatch",
        "32",
        "512",
        "re-bootstrapped",
    ] {
        assert!(message.contains(needle), "missing {needle}: {message}");
    }
    let manifest = Manifest::load(&layout)
        .expect("manifest load")
        .expect("manifest present");
    assert_eq!(
        manifest.current_snapshot_id,
        raven_railgun_persistence::SnapshotId(0),
        "a refused shape must not advance the persisted snapshot"
    );
}
