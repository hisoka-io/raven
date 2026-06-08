//! Manifest: single source of truth for the current snapshot.
//! Atomic-renamed on every bump; crash before rename leaves the prior snapshot live.

use crate::{atomic_write, PersistenceError, Result, SnapshotId, StoreLayout};
use serde::{Deserialize, Serialize};

/// Schema version of the manifest; versions outside the
/// `[MIN_READABLE_MANIFEST_SCHEMA_VERSION, MANIFEST_SCHEMA_VERSION]`
/// window are rejected at load time. V6 signals the snapshot binary
/// embeds the leaf store; V5 snapshots rebuild it from WAL replay.
pub const MANIFEST_SCHEMA_VERSION: u32 = 6;

/// Oldest manifest schema version this build can read; anything older
/// is rejected. V5 is read-only legacy: decoded, rebuilt from WAL on
/// open, upgraded to V6 on the next commit.
pub const MIN_READABLE_MANIFEST_SCHEMA_VERSION: u32 = 5;

/// On-disk manifest; JSON-serialized for human-readable forensics.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    /// Must equal [`MANIFEST_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Scheme tag; bootstrap rejects a scheme mismatch against the configured engine.
    pub scheme_tag: String,
    /// Operator-defined instance id.
    pub instance_id: String,
    /// Currently-live snapshot id.
    pub current_snapshot_id: SnapshotId,
    /// First WAL seq the replayer must consume (`last_seq_in_snapshot + 1`).
    pub current_snapshot_seq: u64,
    /// Chain block height covered by the current snapshot.
    pub current_block_height: u64,
    /// Encoder discriminator; bootstrap rejects a label mismatch.
    pub encoder_label: String,
    /// Set only during an in-flight encoder migration; `None` at steady state.
    /// Allows recovery to detect a partially completed migration.
    #[serde(default)]
    pub prev_encoder_label: Option<String>,
}

impl Manifest {
    /// Load the manifest. Returns `Ok(None)` if the file is missing (caller bootstraps fresh).
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
        Ok(Some(manifest))
    }

    /// Atomically write the manifest.
    pub fn save(&self, layout: &StoreLayout) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        atomic_write(&layout.manifest_path(), &bytes)
    }

    /// Serialize the manifest into an arbitrary writer without the atomic-rename pipeline.
    ///
    /// Used by fault-injection tests (`tests/enospc_propagation.rs`) to force a
    /// `StorageFull` error through the JSON-encode → `write_all` boundary that
    /// the production path traverses, without needing a real tmpfs.
    pub fn save_to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        writer.write_all(&bytes).map_err(PersistenceError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        Manifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            scheme_tag: "raven-inspire-twopacking-inspiring-wp3".to_owned(),
            instance_id: "ppoi-paths-ofac".to_owned(),
            current_snapshot_id: SnapshotId(7),
            current_snapshot_seq: 100_000,
            current_block_height: 24_978_046,
            encoder_label: "per-leaf-bc".to_owned(),
            prev_encoder_label: None,
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
    fn legacy_v5_manifest_loads_for_backward_compat() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let mut m = sample();
        m.schema_version = 5;
        m.save(&layout).expect("save v5");
        let back = Manifest::load(&layout).expect("load v5").expect("present");
        assert_eq!(back.schema_version, 5);
    }

    #[test]
    fn pre_v5_manifest_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let mut m = sample();
        m.schema_version = 4;
        m.save(&layout).expect("save v4");
        let err = Manifest::load(&layout).expect_err("v4 must be rejected");
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
    fn v4_manifest_without_prev_encoder_label_reads_into_v5_struct_with_default_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let v4_json = serde_json::json!({
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "scheme_tag": "raven-inspire-twopacking-inspiring-wp3",
            "instance_id": "v4-compat",
            "current_snapshot_id": 3,
            "current_snapshot_seq": 7,
            "current_block_height": 24_000_000u64,
            "encoder_label": "per-leaf-bc"
        });
        std::fs::write(
            layout.manifest_path(),
            serde_json::to_vec_pretty(&v4_json).expect("ser"),
        )
        .expect("write");
        let loaded = Manifest::load(&layout).expect("load").expect("present");
        assert_eq!(loaded.prev_encoder_label, None);
        assert_eq!(loaded.encoder_label, "per-leaf-bc");
        assert_eq!(loaded.instance_id, "v4-compat");
    }

    #[test]
    fn v5_manifest_with_prev_encoder_label_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let mut m = sample();
        m.encoder_label = "per-node".to_owned();
        m.prev_encoder_label = Some("per-leaf-bc".to_owned());
        m.save(&layout).expect("save");
        let back = Manifest::load(&layout).expect("load").expect("present");
        assert_eq!(back.encoder_label, "per-node");
        assert_eq!(back.prev_encoder_label, Some("per-leaf-bc".to_owned()));
        assert_eq!(back, m);
    }
}
