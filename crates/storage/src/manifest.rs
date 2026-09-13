//! Single source of truth for the current snapshot. Atomic-renamed on every
//! bump, so a crash before rename leaves the prior snapshot live.

use crate::{atomic_write, PersistenceError, Result, SnapshotId, StoreLayout};
use serde::{Deserialize, Serialize};

/// Current schema. V7 binds the manifest to the snapshot's cell shape.
pub const MANIFEST_SCHEMA_VERSION: u32 = 7;

/// Oldest readable schema; V5/V6 require snapshot-derived shape migration.
pub const MIN_READABLE_MANIFEST_SCHEMA_VERSION: u32 = 5;

/// Persisted PIR cell geometry, matching the server's state-shape vocabulary.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestShape {
    /// Bytes per record.
    pub entry_size_bytes: usize,
    /// Rows per shard.
    pub rows_per_shard: u64,
}

/// On-disk manifest; JSON-serialized for human-readable forensics.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    /// Accepted range `[MIN_READABLE_MANIFEST_SCHEMA_VERSION, MANIFEST_SCHEMA_VERSION]`.
    pub schema_version: u32,
    /// Scheme identity checked by [`Manifest::load_validated`].
    pub scheme_tag: String,
    /// Operator-defined identity checked by [`Manifest::load_validated`].
    pub instance_id: String,
    /// Currently-live snapshot id.
    pub current_snapshot_id: SnapshotId,
    /// First WAL seq the replayer must consume (`last_seq_in_snapshot + 1`).
    pub current_snapshot_seq: u64,
    /// Caller-supplied monotonic marker; on-disk key stays
    /// `current_block_height` for format stability.
    #[serde(rename = "current_block_height")]
    pub current_marker: u64,
    /// Encoder discriminator checked by [`Manifest::load_validated`].
    pub encoder_label: String,
    /// Source encoder from the most recent completed migration.
    #[serde(default)]
    pub prev_encoder_label: Option<String>,
    /// Bytes per record. Absent only while reading a legacy V5/V6 manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_size_bytes: Option<usize>,
    /// Rows per shard. Absent only while reading a legacy V5/V6 manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows_per_shard: Option<u64>,
}

impl Manifest {
    /// Loads schema-valid contents without checking caller-supplied identity.
    ///
    /// Returns `Ok(None)` when the file is missing.
    pub fn load(layout: &StoreLayout) -> Result<Option<Self>> {
        let path = layout.manifest_path();
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(PersistenceError::Io(e)),
        };
        let manifest: Manifest = serde_json::from_slice(&bytes)
            .map_err(|e| PersistenceError::ManifestMissing(format!("manifest.json parse: {e}")))?;
        if manifest.schema_version < MIN_READABLE_MANIFEST_SCHEMA_VERSION
            || manifest.schema_version > MANIFEST_SCHEMA_VERSION
        {
            return Err(PersistenceError::ManifestMissing(format!(
                "manifest schema_version {} outside supported range [{}..={}]",
                manifest.schema_version,
                MIN_READABLE_MANIFEST_SCHEMA_VERSION,
                MANIFEST_SCHEMA_VERSION
            )));
        }
        let shape = manifest.cell_shape()?;
        if manifest.schema_version == MANIFEST_SCHEMA_VERSION && shape.is_none() {
            return Err(PersistenceError::ManifestShapeMissing {
                schema_version: manifest.schema_version,
            });
        }
        Ok(Some(manifest))
    }

    /// Loads a manifest only when all configured identity fields match.
    ///
    /// Returns `Ok(None)` when the file is missing.
    ///
    /// # Errors
    ///
    /// Returns [`PersistenceError::Invariant`] for an identity mismatch, or the
    /// same parse, schema, and I/O errors as [`Manifest::load`].
    ///
    /// # Examples
    ///
    /// ```
    /// use raven_storage::{Manifest, SnapshotId, StoreLayout, MANIFEST_SCHEMA_VERSION};
    ///
    /// let dir = tempfile::tempdir()?;
    /// let layout = StoreLayout::open(dir.path())?;
    /// let manifest = Manifest {
    ///     schema_version: MANIFEST_SCHEMA_VERSION,
    ///     scheme_tag: "scheme-v1".into(),
    ///     instance_id: "main".into(),
    ///     current_snapshot_id: SnapshotId(0),
    ///     current_snapshot_seq: 0,
    ///     current_marker: 0,
    ///     encoder_label: "flat".into(),
    ///     prev_encoder_label: None,
    ///     entry_size_bytes: Some(32),
    ///     rows_per_shard: Some(2048),
    /// };
    /// manifest.save(&layout)?;
    /// let loaded = Manifest::load_validated(&layout, "scheme-v1", "main", "flat")?;
    /// assert_eq!(loaded, Some(manifest));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn load_validated(
        layout: &StoreLayout,
        scheme_tag: &str,
        instance_id: &str,
        encoder_label: &str,
    ) -> Result<Option<Self>> {
        let Some(manifest) = Self::load(layout)? else {
            return Ok(None);
        };
        manifest.validate_identity(scheme_tag, instance_id, encoder_label)?;
        Ok(Some(manifest))
    }

    /// Require all persisted identity fields to match configured values.
    ///
    /// # Errors
    ///
    /// Returns [`PersistenceError::Invariant`] naming the mismatched field.
    pub fn validate_identity(
        &self,
        scheme_tag: &str,
        instance_id: &str,
        encoder_label: &str,
    ) -> Result<()> {
        validate_identity_field("scheme_tag", &self.scheme_tag, scheme_tag)?;
        validate_identity_field("instance_id", &self.instance_id, instance_id)?;
        validate_identity_field("encoder_label", &self.encoder_label, encoder_label)
    }

    /// Return the stored shape, preserving legacy absence as `None`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistenceError::ManifestShapeInvalid`] when only one field
    /// is present or either value is zero.
    pub fn cell_shape(&self) -> Result<Option<ManifestShape>> {
        match (self.entry_size_bytes, self.rows_per_shard) {
            (None, None) => Ok(None),
            (Some(entry_size_bytes), Some(rows_per_shard))
                if entry_size_bytes > 0 && rows_per_shard > 0 =>
            {
                Ok(Some(ManifestShape {
                    entry_size_bytes,
                    rows_per_shard,
                }))
            }
            (entry_size_bytes, rows_per_shard) => Err(PersistenceError::ManifestShapeInvalid {
                schema_version: self.schema_version,
                entry_size_bytes,
                rows_per_shard,
            }),
        }
    }

    /// Return the required current shape.
    ///
    /// # Errors
    ///
    /// Returns [`PersistenceError::ManifestShapeMissing`] for legacy bytes
    /// that have not been migrated, or the validation error from
    /// [`Manifest::cell_shape`].
    pub fn require_shape(&self) -> Result<ManifestShape> {
        self.cell_shape()?
            .ok_or(PersistenceError::ManifestShapeMissing {
                schema_version: self.schema_version,
            })
    }

    /// Require the persisted and configured shapes to agree exactly.
    ///
    /// # Errors
    ///
    /// Returns a typed missing, invalid, or mismatch error naming both shapes.
    pub fn validate_shape(&self, configured: ManifestShape) -> Result<()> {
        validate_shape_value(self.schema_version, configured)?;
        let stored = self.require_shape()?;
        if stored == configured {
            return Ok(());
        }
        Err(PersistenceError::ManifestShapeMismatch {
            stored_entry_size_bytes: stored.entry_size_bytes,
            stored_rows_per_shard: stored.rows_per_shard,
            configured_entry_size_bytes: configured.entry_size_bytes,
            configured_rows_per_shard: configured.rows_per_shard,
        })
    }

    /// Upgrade a readable legacy manifest from shape recovered from its snapshot.
    ///
    /// Returns `true` when the manifest changed and must be saved. An existing
    /// shape is validated rather than overwritten.
    ///
    /// # Errors
    ///
    /// Returns a typed shape error when recovered geometry is invalid, current
    /// bytes omit shape, or stored and recovered shapes disagree.
    pub fn migrate_shape_from_snapshot(&mut self, recovered: ManifestShape) -> Result<bool> {
        validate_shape_value(self.schema_version, recovered)?;
        if let Some(stored) = self.cell_shape()? {
            if stored != recovered {
                return Err(PersistenceError::ManifestShapeMismatch {
                    stored_entry_size_bytes: stored.entry_size_bytes,
                    stored_rows_per_shard: stored.rows_per_shard,
                    configured_entry_size_bytes: recovered.entry_size_bytes,
                    configured_rows_per_shard: recovered.rows_per_shard,
                });
            }
            if self.schema_version == MANIFEST_SCHEMA_VERSION {
                return Ok(false);
            }
        } else if self.schema_version == MANIFEST_SCHEMA_VERSION {
            return Err(PersistenceError::ManifestShapeMissing {
                schema_version: self.schema_version,
            });
        }
        self.entry_size_bytes = Some(recovered.entry_size_bytes);
        self.rows_per_shard = Some(recovered.rows_per_shard);
        self.schema_version = MANIFEST_SCHEMA_VERSION;
        Ok(true)
    }

    /// Atomically write the manifest.
    pub fn save(&self, layout: &StoreLayout) -> Result<()> {
        if self.schema_version == MANIFEST_SCHEMA_VERSION {
            self.require_shape()?;
        } else {
            self.cell_shape()?;
        }
        let bytes = serde_json::to_vec_pretty(self)?;
        Ok(atomic_write(&layout.manifest_path(), &bytes)?)
    }

    /// Serialize into an arbitrary writer, skipping the atomic-rename pipeline,
    /// so fault injection can force a write error without a real tmpfs.
    pub fn save_to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        if self.schema_version == MANIFEST_SCHEMA_VERSION {
            self.require_shape()?;
        } else {
            self.cell_shape()?;
        }
        let bytes = serde_json::to_vec_pretty(self)?;
        writer.write_all(&bytes).map_err(PersistenceError::Io)
    }
}

fn validate_shape_value(schema_version: u32, shape: ManifestShape) -> Result<()> {
    if shape.entry_size_bytes > 0 && shape.rows_per_shard > 0 {
        return Ok(());
    }
    Err(PersistenceError::ManifestShapeInvalid {
        schema_version,
        entry_size_bytes: Some(shape.entry_size_bytes),
        rows_per_shard: Some(shape.rows_per_shard),
    })
}

fn validate_identity_field(field: &str, stored: &str, configured: &str) -> Result<()> {
    if stored == configured {
        return Ok(());
    }
    Err(PersistenceError::Invariant(format!(
        "manifest {field} mismatch: stored {stored:?} != configured {configured:?}; restore the \
         configuration that owns this data_dir, migrate it with the owning tool, or choose a \
         different data_dir"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        Manifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            scheme_tag: "test-scheme-v1".to_owned(),
            instance_id: "test-instance".to_owned(),
            current_snapshot_id: SnapshotId(7),
            current_snapshot_seq: 100_000,
            current_marker: 24_978_046,
            encoder_label: "test-encoder".to_owned(),
            prev_encoder_label: None,
            entry_size_bytes: Some(32),
            rows_per_shard: Some(2048),
        }
    }

    #[test]
    fn load_when_missing_returns_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        assert_eq!(Manifest::load(&layout).expect("load"), None);
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let m = sample();
        m.save(&layout).expect("save");
        let back = Manifest::load(&layout).expect("load").expect("present");
        assert_eq!(back, m);
    }

    #[test]
    fn load_validated_accepts_exact_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let manifest = sample();
        manifest.save(&layout).expect("save");

        let loaded = Manifest::load_validated(
            &layout,
            &manifest.scheme_tag,
            &manifest.instance_id,
            &manifest.encoder_label,
        )
        .expect("validated load")
        .expect("present");

        assert_eq!(loaded, manifest);
    }

    #[test]
    fn load_validated_rejects_each_identity_mismatch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let manifest = sample();
        manifest.save(&layout).expect("save");

        let cases = [
            (
                "wrong-scheme",
                manifest.instance_id.as_str(),
                manifest.encoder_label.as_str(),
                "scheme_tag",
            ),
            (
                manifest.scheme_tag.as_str(),
                "wrong-instance",
                manifest.encoder_label.as_str(),
                "instance_id",
            ),
            (
                manifest.scheme_tag.as_str(),
                manifest.instance_id.as_str(),
                "wrong-encoder",
                "encoder_label",
            ),
        ];
        for (scheme_tag, instance_id, encoder_label, expected_field) in cases {
            let err = Manifest::load_validated(&layout, scheme_tag, instance_id, encoder_label)
                .expect_err("identity mismatch must fail closed");
            match err {
                PersistenceError::Invariant(message) => assert!(
                    message.contains(expected_field),
                    "identity error must name {expected_field}: {message}"
                ),
                other => panic!("expected Invariant, got {other:?}"),
            }
        }
    }

    #[test]
    fn save_atomic_rename_overwrites_previous() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let mut m = sample();
        m.save(&layout).expect("save 1");
        m.current_snapshot_id = SnapshotId(8);
        m.current_snapshot_seq = 200_000;
        m.save(&layout).expect("save 2");
        let back = Manifest::load(&layout).expect("load").expect("present");
        assert_eq!(back.current_snapshot_id, SnapshotId(8));
        assert_eq!(back.current_snapshot_seq, 200_000);
    }

    #[test]
    fn schema_version_mismatch_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let mut m = sample();
        m.schema_version = 999;
        m.save(&layout).expect("save");
        let err = Manifest::load(&layout).expect_err("should fail");
        assert!(matches!(err, PersistenceError::ManifestMissing(_)));
    }

    #[test]
    fn legacy_min_readable_manifest_loads_for_backward_compat() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let mut m = sample();
        m.schema_version = MIN_READABLE_MANIFEST_SCHEMA_VERSION;
        m.save(&layout).expect("save legacy");
        let back = Manifest::load(&layout)
            .expect("load legacy")
            .expect("present");
        assert_eq!(back.schema_version, MIN_READABLE_MANIFEST_SCHEMA_VERSION);
    }

    #[test]
    fn below_min_readable_manifest_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let mut m = sample();
        m.schema_version = MIN_READABLE_MANIFEST_SCHEMA_VERSION - 1;
        m.save(&layout).expect("save");
        let err = Manifest::load(&layout).expect_err("must be rejected");
        assert!(matches!(err, PersistenceError::ManifestMissing(_)));
    }

    #[test]
    fn corrupt_json_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        std::fs::write(layout.manifest_path(), b"{ not valid json").expect("write");
        let err = Manifest::load(&layout).expect_err("should fail");
        assert!(matches!(err, PersistenceError::ManifestMissing(_)));
    }

    #[test]
    fn manifest_without_prev_encoder_label_reads_with_default_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let json = serde_json::json!({
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "scheme_tag": "test-scheme-v1",
            "instance_id": "compat",
            "current_snapshot_id": 3,
            "current_snapshot_seq": 7,
            "current_block_height": 24_000_000u64,
            "encoder_label": "test-encoder",
            "entry_size_bytes": 32,
            "rows_per_shard": 2048
        });
        std::fs::write(
            layout.manifest_path(),
            serde_json::to_vec_pretty(&json).expect("ser"),
        )
        .expect("write");
        let loaded = Manifest::load(&layout).expect("load").expect("present");
        assert_eq!(loaded.prev_encoder_label, None);
        assert_eq!(loaded.encoder_label, "test-encoder");
        assert_eq!(loaded.instance_id, "compat");
    }

    #[test]
    fn manifest_with_prev_encoder_label_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let mut m = sample();
        m.encoder_label = "encoder-b".to_owned();
        m.prev_encoder_label = Some("encoder-a".to_owned());
        m.save(&layout).expect("save");
        let back = Manifest::load(&layout).expect("load").expect("present");
        assert_eq!(back.encoder_label, "encoder-b");
        assert_eq!(back.prev_encoder_label, Some("encoder-a".to_owned()));
        assert_eq!(back, m);
    }
}
