#![allow(clippy::expect_used, clippy::panic)]

use std::path::Path;

use proptest::prelude::*;
use raven_storage::{
    Manifest, ManifestShape, PersistenceError, StoreLayout, MANIFEST_SCHEMA_VERSION,
};

const V5_BYTES: &[u8] = br#"{
  "schema_version": 5,
  "scheme_tag": "shape-test",
  "instance_id": "primary",
  "current_snapshot_id": 7,
  "current_snapshot_seq": 19,
  "current_block_height": 23,
  "encoder_label": "flat",
  "prev_encoder_label": null
}"#;

const V6_BYTES: &[u8] = br#"{
  "schema_version": 6,
  "scheme_tag": "shape-test",
  "instance_id": "primary",
  "current_snapshot_id": 7,
  "current_snapshot_seq": 19,
  "current_block_height": 23,
  "encoder_label": "flat",
  "prev_encoder_label": null
}"#;

const V7_WITHOUT_SHAPE_BYTES: &[u8] = br#"{
  "schema_version": 7,
  "scheme_tag": "shape-test",
  "instance_id": "primary",
  "current_snapshot_id": 7,
  "current_snapshot_seq": 19,
  "current_block_height": 23,
  "encoder_label": "flat",
  "prev_encoder_label": null
}"#;

const V7_BYTES: &[u8] = br#"{
  "schema_version": 7,
  "scheme_tag": "shape-test",
  "instance_id": "primary",
  "current_snapshot_id": 7,
  "current_snapshot_seq": 19,
  "current_block_height": 23,
  "encoder_label": "flat",
  "prev_encoder_label": null,
  "entry_size_bytes": 32,
  "rows_per_shard": 2048
}"#;

fn write_manifest(path: &Path, bytes: &[u8]) {
    std::fs::write(path.join("manifest.json"), bytes).expect("write manifest fixture");
}

fn load_fixture(bytes: &[u8]) -> (tempfile::TempDir, StoreLayout, Manifest) {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    write_manifest(dir.path(), bytes);
    let manifest = Manifest::load(&layout)
        .expect("fixture must load")
        .expect("fixture present");
    (dir, layout, manifest)
}

fn production_shape() -> ManifestShape {
    ManifestShape {
        entry_size_bytes: 32,
        rows_per_shard: 2048,
    }
}

#[test]
fn exact_v7_bytes_load_with_required_shape_and_round_trip() {
    assert_eq!(MANIFEST_SCHEMA_VERSION, 7);
    let (_dir, layout, manifest) = load_fixture(V7_BYTES);

    assert_eq!(
        manifest.require_shape().expect("v7 shape"),
        production_shape()
    );
    manifest.save(&layout).expect("save v7");
    assert_eq!(
        std::fs::read(layout.manifest_path()).expect("read saved v7"),
        V7_BYTES,
        "the current manifest fixture is the exact persisted contract"
    );
}

#[test]
fn exact_v5_and_v6_bytes_load_without_inventing_shape_then_upgrade_from_snapshot() {
    for fixture in [V5_BYTES, V6_BYTES] {
        let (_dir, layout, mut manifest) = load_fixture(fixture);
        assert_eq!(
            manifest.cell_shape().expect("legacy shape state"),
            None,
            "legacy absence must not become configured geometry during decode"
        );
        assert!(
            manifest
                .migrate_shape_from_snapshot(production_shape())
                .expect("snapshot-derived migration"),
            "legacy schema must report an in-memory upgrade"
        );
        manifest.save(&layout).expect("save upgraded manifest");
        assert_eq!(
            std::fs::read(layout.manifest_path()).expect("read upgraded manifest"),
            V7_BYTES,
            "v5 and v6 must converge on the exact v7 bytes"
        );
    }
}

#[test]
fn current_manifest_without_shape_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    write_manifest(dir.path(), V7_WITHOUT_SHAPE_BYTES);

    let error = Manifest::load(&layout).expect_err("v7 without shape must fail closed");
    assert!(
        matches!(
            error,
            PersistenceError::ManifestShapeMissing { schema_version: 7 }
        ),
        "got {error:?}"
    );
}

#[test]
fn partial_or_zero_shape_is_refused() {
    let cases = [
        serde_json::json!({
            "schema_version": 6,
            "scheme_tag": "shape-test",
            "instance_id": "primary",
            "current_snapshot_id": 7,
            "current_snapshot_seq": 19,
            "current_block_height": 23,
            "encoder_label": "flat",
            "entry_size_bytes": 32
        }),
        serde_json::json!({
            "schema_version": 7,
            "scheme_tag": "shape-test",
            "instance_id": "primary",
            "current_snapshot_id": 7,
            "current_snapshot_seq": 19,
            "current_block_height": 23,
            "encoder_label": "flat",
            "entry_size_bytes": 0,
            "rows_per_shard": 2048
        }),
    ];
    for value in cases {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        write_manifest(
            dir.path(),
            &serde_json::to_vec_pretty(&value).expect("fixture encode"),
        );
        let error = Manifest::load(&layout).expect_err("invalid shape must fail closed");
        assert!(
            matches!(error, PersistenceError::ManifestShapeInvalid { .. }),
            "got {error:?}"
        );
    }
}

#[test]
fn stored_shape_mismatch_is_typed_and_actionable() {
    let (_dir, _layout, manifest) = load_fixture(V7_BYTES);
    let error = manifest
        .validate_shape(ManifestShape {
            entry_size_bytes: 512,
            rows_per_shard: 1024,
        })
        .expect_err("both shape fields differ");
    assert!(
        matches!(
            error,
            PersistenceError::ManifestShapeMismatch {
                stored_entry_size_bytes: 32,
                stored_rows_per_shard: 2048,
                configured_entry_size_bytes: 512,
                configured_rows_per_shard: 1024,
            }
        ),
        "got {error:?}"
    );
    let message = error.to_string();
    for needle in ["32", "2048", "512", "1024", "re-bootstrap"] {
        assert!(message.contains(needle), "missing {needle}: {message}");
    }
}

proptest! {
    #[test]
    fn every_nonzero_shape_survives_json_round_trip(
        entry_size_bytes in 1usize..=1_048_576,
        rows_per_shard in 1u64..=u64::from(u32::MAX),
    ) {
        let (_dir, layout, mut manifest) = load_fixture(V6_BYTES);
        let shape = ManifestShape { entry_size_bytes, rows_per_shard };
        manifest.migrate_shape_from_snapshot(shape).expect("migrate shape");
        manifest.save(&layout).expect("save shape");
        let recovered = Manifest::load(&layout).expect("load shape").expect("present");
        prop_assert_eq!(recovered.require_shape().expect("required shape"), shape);
    }
}
