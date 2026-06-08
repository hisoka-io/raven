//! Snapshot files: magic header + SHA-256 checksum + bincode payload, written atomically.

use crate::{atomic_write, fsync_parent_dir, PersistenceError, Result, StoreLayout};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Monotonic snapshot identifier within a [`StoreLayout`].
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SnapshotId(pub u64);

impl SnapshotId {
    /// Successor id. Saturates at `u64::MAX`.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// 16-byte magic + SHA-256 checksum + payload length stored alongside the bincode payload.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotHeader {
    /// ASCII magic bytes (`RAVEN_RAILGUN_01`).
    pub magic: [u8; 16],
    /// SHA-256 of the uncompressed bincode payload, hex-encoded.
    pub data_sha256_hex: String,
    /// Length of the uncompressed bincode payload.
    pub data_len: u64,
}

/// Expected magic bytes.
pub const SNAPSHOT_MAGIC: [u8; 16] = *b"RAVEN_RAILGUN_01";

/// zstd frame magic (RFC 8878 §3.1.1). `Snapshot::load` sniffs these bytes to dispatch
/// between zstd-wrapped (new) and bare-bincode (legacy) payloads. SHA-256 covers the
/// uncompressed payload in both paths so no manifest schema bump is needed.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// zstd level 3: ~3-4x size reduction on bincode-shaped state, single-digit-percent CPU overhead.
#[cfg(feature = "zstd-compression")]
const ZSTD_LEVEL: i32 = 3;

/// Opaque snapshot payload. The persistence crate treats the bytes as a black box;
/// callers serialize their scheme-specific state and hand it in.
#[derive(Clone, Debug)]
pub struct Snapshot {
    /// Header metadata.
    pub header: SnapshotHeader,
    /// Bincode-serialized state payload.
    pub data: Vec<u8>,
}

impl Snapshot {
    /// Build a snapshot, computing the header checksum from `data`.
    pub fn build(data: Vec<u8>) -> Self {
        let digest = Sha256::digest(&data);
        let hex = bytes_to_hex(&digest);
        let data_len = u64::try_from(data.len()).unwrap_or(u64::MAX);
        Self {
            header: SnapshotHeader {
                magic: SNAPSHOT_MAGIC,
                data_sha256_hex: hex,
                data_len,
            },
            data,
        }
    }

    /// Persist the snapshot under `layout.snapshot_dir(id)`.
    ///
    /// Two-rename idiom for crash-atomicity: (1) rename existing
    /// `final_dir` to `.old.tmp`, (2) rename `tmp_dir` to `final_dir`,
    /// (3) remove `.old.tmp`. A kill between steps leaves recoverable
    /// state that [`Snapshot::load`] handles. Idempotent under retry
    /// with the same `id`.
    pub fn save(&self, layout: &StoreLayout, id: SnapshotId) -> Result<()> {
        let final_dir = layout.snapshot_dir(id);
        let tmp_dir = final_dir.with_extension("tmp");
        let final_old_tmp = final_dir.with_extension("old.tmp");

        let _ = std::fs::remove_dir_all(&tmp_dir);
        let _ = std::fs::remove_dir_all(&final_old_tmp);
        std::fs::create_dir_all(&tmp_dir)?;

        let header_bytes = bincode::serialize(&self.header)?;
        atomic_write(&tmp_dir.join("header.bin"), &header_bytes)?;
        let body = wrap_for_disk(&self.data)?;
        atomic_write(&tmp_dir.join("data.bincode"), &body)?;

        let had_final = final_dir.exists();
        if had_final {
            if let Err(e) = std::fs::rename(&final_dir, &final_old_tmp) {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(PersistenceError::Io(e));
            }
            if let Some(parent) = final_dir.parent() {
                fsync_parent_dir(parent)?;
            }
        }

        if let Err(e) = std::fs::rename(&tmp_dir, &final_dir) {
            if had_final {
                if let Err(rollback_err) = std::fs::rename(&final_old_tmp, &final_dir) {
                    tracing::error!(
                        target: "raven::persistence::snapshot",
                        rollback_err = %rollback_err,
                        save_err = %e,
                        snap_id = id.0,
                        "snapshot save failed AND rollback rename failed; \
                         operator must manually rename `.old.tmp` back to \
                         the snapshot dir before restart"
                    );
                }
            }
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(PersistenceError::Io(e));
        }
        if let Some(parent) = final_dir.parent() {
            fsync_parent_dir(parent)?;
        }

        // best-effort reclaim; load recovery handles leaks
        if had_final {
            if let Err(e) = std::fs::remove_dir_all(&final_old_tmp) {
                tracing::warn!(
                    target: "raven::persistence::snapshot",
                    err = %e,
                    snap_id = id.0,
                    "snapshot save: failed to remove displaced `.old.tmp`; \
                     load-time recovery will reclaim it"
                );
            }
        }
        Ok(())
    }

    /// Load a snapshot, verifying magic and SHA-256.
    ///
    /// Sniffs the leading 4 bytes for the zstd frame magic to dispatch between
    /// compressed and legacy bare-bincode payloads. Handles the three crash-recovery
    /// states left by `save`'s two-rename pipeline: `.old.tmp` alone (promotes it back),
    /// both present (`final_dir` wins, `.old.tmp` cleaned up), or only `final_dir`.
    pub fn load(layout: &StoreLayout, id: SnapshotId) -> Result<Self> {
        let dir = layout.snapshot_dir(id);
        let old_tmp = dir.with_extension("old.tmp");
        let dir_exists = dir.is_dir();
        let old_exists = old_tmp.is_dir();

        match (dir_exists, old_exists) {
            (true, true) => {
                if let Err(e) = std::fs::remove_dir_all(&old_tmp) {
                    tracing::warn!(
                        target: "raven::persistence::snapshot",
                        err = %e,
                        snap_id = id.0,
                        "snapshot load: failed to clean obsolete `.old.tmp`; \
                         leaking bytes but no correctness impact"
                    );
                }
            }
            (false, true) => {
                std::fs::rename(&old_tmp, &dir)?;
                if let Some(parent) = dir.parent() {
                    fsync_parent_dir(parent)?;
                }
                tracing::info!(
                    target: "raven::persistence::snapshot",
                    snap_id = id.0,
                    "snapshot load: recovered from `.old.tmp` left by \
                     interrupted save"
                );
            }
            (false, false) => {
                return Err(PersistenceError::SnapshotNotFound(id));
            }
            (true, false) => {}
        }

        if !dir.is_dir() {
            return Err(PersistenceError::SnapshotNotFound(id));
        }
        let header_bytes = std::fs::read(dir.join("header.bin"))?;
        let header: SnapshotHeader = bincode::deserialize(&header_bytes)?;
        if header.magic != SNAPSHOT_MAGIC {
            return Err(PersistenceError::SnapshotCorrupt(format!(
                "snap-{:06}: magic mismatch",
                id.0
            )));
        }
        let raw = std::fs::read(dir.join("data.bincode"))?;
        let data = unwrap_from_disk(&raw, id)?;
        if u64::try_from(data.len()).unwrap_or(u64::MAX) != header.data_len {
            return Err(PersistenceError::SnapshotCorrupt(format!(
                "snap-{:06}: data_len {} != header.data_len {}",
                id.0,
                data.len(),
                header.data_len
            )));
        }
        let digest = Sha256::digest(&data);
        let hex = bytes_to_hex(&digest);
        if hex != header.data_sha256_hex {
            return Err(PersistenceError::SnapshotCorrupt(format!(
                "snap-{:06}: SHA-256 mismatch",
                id.0
            )));
        }
        Ok(Self { header, data })
    }
}

#[cfg(feature = "zstd-compression")]
fn wrap_for_disk(payload: &[u8]) -> Result<Vec<u8>> {
    zstd::bulk::compress(payload, ZSTD_LEVEL)
        .map_err(|e| PersistenceError::SnapshotCorrupt(format!("zstd compress: {e}")))
}

#[cfg(not(feature = "zstd-compression"))]
fn wrap_for_disk(payload: &[u8]) -> Result<Vec<u8>> {
    Ok(payload.to_vec())
}

fn unwrap_from_disk(raw: &[u8], id: SnapshotId) -> Result<Vec<u8>> {
    if raw.len() >= ZSTD_MAGIC.len() && raw.get(..ZSTD_MAGIC.len()) == Some(&ZSTD_MAGIC) {
        decompress_zstd_body(raw, id)
    } else {
        Ok(raw.to_vec())
    }
}

#[cfg(feature = "zstd-compression")]
fn decompress_zstd_body(raw: &[u8], id: SnapshotId) -> Result<Vec<u8>> {
    // 4 GiB cap prevents heap exhaustion from a hostile/corrupt frame;
    // production payloads are ~170 MiB so this stays well clear of valid bodies.
    const MAX_DECOMPRESSED: usize = 4 * 1024 * 1024 * 1024;
    zstd::bulk::decompress(raw, MAX_DECOMPRESSED).map_err(|e| {
        PersistenceError::SnapshotCorrupt(format!("snap-{:06}: zstd decompress: {e}", id.0))
    })
}

#[cfg(not(feature = "zstd-compression"))]
fn decompress_zstd_body(_raw: &[u8], id: SnapshotId) -> Result<Vec<u8>> {
    Err(PersistenceError::SnapshotCorrupt(format!(
        "snap-{:06}: zstd-wrapped body but build has no zstd-compression feature",
        id.0
    )))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let hi = HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0');
        let lo = HEX.get(usize::from(b & 0x0F)).copied().unwrap_or(b'0');
        out.push(hi as char);
        out.push(lo as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_id_next_saturates() {
        assert_eq!(SnapshotId(0).next(), SnapshotId(1));
        assert_eq!(SnapshotId(u64::MAX).next(), SnapshotId(u64::MAX));
    }

    #[test]
    fn build_round_trips_via_save_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let payload = b"hello inspire snapshot".to_vec();
        let snap = Snapshot::build(payload.clone());
        snap.save(&layout, SnapshotId(1)).expect("save");
        let back = Snapshot::load(&layout, SnapshotId(1)).expect("load");
        assert_eq!(back.data, payload);
        assert_eq!(back.header.magic, SNAPSHOT_MAGIC);
    }

    #[test]
    fn missing_snapshot_returns_not_found() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let err = Snapshot::load(&layout, SnapshotId(99)).expect_err("missing");
        assert!(matches!(err, PersistenceError::SnapshotNotFound(_)));
    }

    #[test]
    fn corrupt_data_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let snap = Snapshot::build(b"original".to_vec());
        snap.save(&layout, SnapshotId(1)).expect("save");
        std::fs::write(
            layout.snapshot_dir(SnapshotId(1)).join("data.bincode"),
            b"tampered",
        )
        .expect("write");
        let err = Snapshot::load(&layout, SnapshotId(1)).expect_err("corrupt");
        assert!(matches!(err, PersistenceError::SnapshotCorrupt(_)));
    }

    #[test]
    fn wrong_magic_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let mut snap = Snapshot::build(b"x".to_vec());
        snap.header.magic = *b"WRONG_MAGIC_HERE";
        let header_bytes = bincode::serialize(&snap.header).expect("ser");
        let final_dir = layout.snapshot_dir(SnapshotId(1));
        std::fs::create_dir_all(&final_dir).expect("mkdir");
        std::fs::write(final_dir.join("header.bin"), &header_bytes).expect("write h");
        std::fs::write(final_dir.join("data.bincode"), &snap.data).expect("write d");
        let err = Snapshot::load(&layout, SnapshotId(1)).expect_err("magic");
        assert!(matches!(err, PersistenceError::SnapshotCorrupt(_)));
    }

    // re-saving the same id must not fail with ENOTEMPTY
    #[test]
    fn save_is_idempotent_under_existing_final_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");

        let snap_a = Snapshot::build(b"first commit attempt".to_vec());
        snap_a
            .save(&layout, SnapshotId(1))
            .expect("first save succeeds");

        let snap_b = Snapshot::build(b"retry commit attempt".to_vec());
        snap_b
            .save(&layout, SnapshotId(1))
            .expect("retry save must NOT fail with ENOTEMPTY");

        let loaded = Snapshot::load(&layout, SnapshotId(1)).expect("load post-retry");
        assert_eq!(loaded.data, b"retry commit attempt");
    }

    // only `final_dir`, no `.old.tmp`: loads with no migration step
    #[test]
    fn load_handles_pre_c8_snapshot_with_only_final_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let payload = b"pre-c8 deployment payload".to_vec();
        let snap = Snapshot::build(payload.clone());
        snap.save(&layout, SnapshotId(7)).expect("save");
        let old_tmp = layout.snapshot_dir(SnapshotId(7)).with_extension("old.tmp");
        assert!(!old_tmp.exists());
        let loaded = Snapshot::load(&layout, SnapshotId(7)).expect("load pre-c8 layout");
        assert_eq!(loaded.data, payload);
    }

    // kill after final_dir was displaced to `.old.tmp`: load promotes it back
    #[test]
    fn load_recovers_when_only_old_tmp_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");
        let payload = b"prior good snapshot bytes".to_vec();
        let snap = Snapshot::build(payload.clone());
        snap.save(&layout, SnapshotId(3)).expect("save");

        let final_dir = layout.snapshot_dir(SnapshotId(3));
        let old_tmp = final_dir.with_extension("old.tmp");
        std::fs::rename(&final_dir, &old_tmp).expect("simulated step-1 displacement");

        let loaded = Snapshot::load(&layout, SnapshotId(3)).expect("load with recovery");
        assert_eq!(loaded.data, payload);
        assert!(final_dir.is_dir());
        assert!(!old_tmp.exists());
    }

    // kill with both dirs present: `final_dir` wins, `.old.tmp` cleaned up
    #[test]
    fn load_prefers_final_dir_when_both_present_and_cleans_up_old_tmp() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");

        let prev = Snapshot::build(b"previous payload".to_vec());
        prev.save(&layout, SnapshotId(2)).expect("save prev");
        let final_dir = layout.snapshot_dir(SnapshotId(2));
        let old_tmp = final_dir.with_extension("old.tmp");
        std::fs::rename(&final_dir, &old_tmp).expect("displace prev");

        let new_payload = b"new winning payload".to_vec();
        let new_snap = Snapshot::build(new_payload.clone());
        std::fs::create_dir_all(&final_dir).expect("mkdir final_dir");
        let header_bytes = bincode::serialize(&new_snap.header).expect("ser header");
        atomic_write(&final_dir.join("header.bin"), &header_bytes).expect("header");
        let body = wrap_for_disk(&new_snap.data).expect("wrap");
        atomic_write(&final_dir.join("data.bincode"), &body).expect("data");

        let loaded = Snapshot::load(&layout, SnapshotId(2)).expect("load with both present");
        assert_eq!(loaded.data, new_payload);
        assert!(!old_tmp.exists());
    }
}
