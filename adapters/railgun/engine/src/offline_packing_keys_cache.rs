//! Disk-backed cache for InspiRING `(PackParams, OfflinePackingKeys)`.
//!
//! `ServerInspiringCache::new` runs O(d^3) automorph-table search plus rotation
//! work; both depend only on `(crs.params, num_columns, inspiring_w_seed)`.
//! Persisting once and reloading via `from_parts` skips the offline phase on
//! restart. Atomic-rename writes; cell-shape fingerprint guards against reuse
//! against a different CRS.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use raven_inspire::inspiring::{OfflinePackingKeys, PackParams};
use raven_inspire::ServerInspiringCache;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CACHE_MAGIC: [u8; 8] = *b"RVN_OPK1";

/// Standard relative path under `<data_dir>`.
pub const CACHE_RELATIVE_PATH: &str = "cache/offline_packing_keys.bin";

/// Errors produced by [`OfflinePackingKeysCache`].
#[derive(Debug, thiserror::Error)]
pub enum OfflinePackingKeysCacheError {
    /// I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    /// bincode encode/decode error.
    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    /// On-disk magic bytes did not match.
    #[error("bad magic: expected {expected:?}, found {found:?}")]
    BadMagic {
        /// Expected magic bytes.
        expected: [u8; 8],
        /// On-disk magic bytes.
        found: [u8; 8],
    },
    /// Stale cache — fingerprint mismatch.
    #[error("hash mismatch: expected {expected}, found {found}")]
    HashMismatch {
        /// Hex of expected fingerprint.
        expected: String,
        /// Hex of on-disk fingerprint.
        found: String,
    },
    /// Cache was produced by a different scheme.
    #[error("scheme mismatch: expected {expected:?}, found {found:?}")]
    SchemeMismatch {
        /// Expected scheme tag.
        expected: Vec<u8>,
        /// On-disk scheme tag.
        found: Vec<u8>,
    },
}

/// Cell-shape fingerprint identifying a `(PackParams, OfflinePackingKeys)` pair.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CellShape {
    /// Scheme tag (e.g. `b"raven-inspire-twopacking-wp3"`). Rejects caches
    /// from sibling schemes that picked the same cell dimensions.
    pub scheme_tag: Vec<u8>,
    /// Number of database entries.
    pub entries: u64,
    /// Bytes per entry.
    pub entry_bytes: u64,
    /// Stable identifier for the InspiRING packing parameters; caller derives
    /// from a serialised view of `InspireParams`.
    pub packing_param_id: Vec<u8>,
}

impl CellShape {
    /// SHA-256 fingerprint of this cell shape.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.scheme_tag);
        hasher.update(self.entries.to_le_bytes());
        hasher.update(self.entry_bytes.to_le_bytes());
        hasher.update(&self.packing_param_id);
        hasher.finalize().into()
    }

    /// Hex-encoded fingerprint.
    #[must_use]
    pub fn fingerprint_hex(&self) -> String {
        hex_encode(&self.fingerprint())
    }
}

/// On-disk envelope.
#[derive(Serialize, Deserialize)]
struct CacheFile {
    magic: [u8; 8],
    fingerprint: [u8; 32],
    scheme_tag: Vec<u8>,
    entries: u64,
    entry_bytes: u64,
    pack_params: PackParams,
    offline_keys: OfflinePackingKeys,
}

/// Boxed inside [`CacheLoad::Hit`] (clippy `large_enum_variant`).
#[derive(Debug)]
pub struct CacheParts {
    /// Cached pack parameters.
    pub pack_params: PackParams,
    /// Cached offline packing keys.
    pub offline_keys: OfflinePackingKeys,
}

/// Result of a `load` attempt.
#[derive(Debug)]
pub enum CacheLoad {
    /// Cache matched.
    Hit(Box<CacheParts>),
    /// Cache miss; caller falls through to the offline phase.
    Miss(OfflinePackingKeysCacheError),
}

/// Disk-backed cache for InspiRING offline keys.
#[derive(Clone, Debug)]
pub struct OfflinePackingKeysCache {
    path: PathBuf,
}

impl OfflinePackingKeysCache {
    /// Pin to `<data_dir>/cache/offline_packing_keys.bin`.
    #[must_use]
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        Self {
            path: data_dir.as_ref().join(CACHE_RELATIVE_PATH),
        }
    }

    /// Pin to a caller-supplied path. Used by tests.
    #[must_use]
    pub fn at_path(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Resolved on-disk path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Try to load. `Miss` carries a typed reason; returns no `Result` so the
    /// caller is forced to handle the miss inline.
    #[must_use]
    pub fn load(&self, cell: &CellShape) -> CacheLoad {
        match self.try_load(cell) {
            Ok(parts) => parts,
            Err(err) => CacheLoad::Miss(err),
        }
    }

    fn try_load(&self, cell: &CellShape) -> Result<CacheLoad, OfflinePackingKeysCacheError> {
        let bytes = fs::read(&self.path)?;
        let file: CacheFile = bincode::deserialize(&bytes)?;
        if file.magic != CACHE_MAGIC {
            return Err(OfflinePackingKeysCacheError::BadMagic {
                expected: CACHE_MAGIC,
                found: file.magic,
            });
        }
        if file.scheme_tag != cell.scheme_tag {
            return Err(OfflinePackingKeysCacheError::SchemeMismatch {
                expected: cell.scheme_tag.clone(),
                found: file.scheme_tag,
            });
        }
        let runtime = cell.fingerprint();
        if file.fingerprint != runtime
            || file.entries != cell.entries
            || file.entry_bytes != cell.entry_bytes
        {
            return Err(OfflinePackingKeysCacheError::HashMismatch {
                expected: hex_encode(&runtime),
                found: hex_encode(&file.fingerprint),
            });
        }
        Ok(CacheLoad::Hit(Box::new(CacheParts {
            pack_params: file.pack_params,
            offline_keys: file.offline_keys,
        })))
    }

    /// Persist via atomic rename (`path.tmp` + fsync + rename + parent fsync).
    pub fn store(
        &self,
        cell: &CellShape,
        pack_params: &PackParams,
        offline_keys: &OfflinePackingKeys,
    ) -> Result<(), OfflinePackingKeysCacheError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = CacheFile {
            magic: CACHE_MAGIC,
            fingerprint: cell.fingerprint(),
            scheme_tag: cell.scheme_tag.clone(),
            entries: cell.entries,
            entry_bytes: cell.entry_bytes,
            pack_params: pack_params.clone(),
            offline_keys: offline_keys.clone(),
        };
        let bytes = bincode::serialize(&file)?;
        atomic_write(&self.path, &bytes)
    }

    /// Try the cache; on miss run `build_fresh` and persist. Returns the cache
    /// paired with `true` for a disk hit, `false` if the offline phase ran.
    pub fn load_or_build<F, E>(
        &self,
        cell: &CellShape,
        build_fresh: F,
    ) -> Result<(ServerInspiringCache, bool), CacheBuildError<E>>
    where
        F: FnOnce() -> Result<(PackParams, OfflinePackingKeys), E>,
    {
        match self.load(cell) {
            CacheLoad::Hit(parts) => {
                let CacheParts {
                    pack_params,
                    offline_keys,
                } = *parts;
                Ok((
                    ServerInspiringCache::from_parts(pack_params, offline_keys),
                    true,
                ))
            }
            CacheLoad::Miss(_) => {
                let (pack_params, offline_keys) = build_fresh().map_err(CacheBuildError::Build)?;
                self.store(cell, &pack_params, &offline_keys)
                    .map_err(CacheBuildError::Cache)?;
                Ok((
                    ServerInspiringCache::from_parts(pack_params, offline_keys),
                    false,
                ))
            }
        }
    }
}

/// Composite error from [`OfflinePackingKeysCache::load_or_build`].
#[derive(Debug, thiserror::Error)]
pub enum CacheBuildError<E> {
    /// `build_fresh` closure failed.
    #[error("offline-phase build failed: {0}")]
    Build(E),
    /// Cache layer (load or store) failed.
    #[error(transparent)]
    Cache(#[from] OfflinePackingKeysCacheError),
}

// Atomic write: tmp + fsync + rename + parent fsync. Mirrors the helper in
// raven-railgun-persistence so this module stays self-contained.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), OfflinePackingKeysCacheError> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "cache path has no parent"))?;
    fs::create_dir_all(parent)?;
    let mut tmp = path.to_path_buf();
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "cache path has no file name")
    })?;
    // Suffix with pid+seq so concurrent writers don't stomp each other's tmp.
    let mut tmp_name = file_name.to_owned();
    tmp_name.push(format!(".tmp.{:x}.{}", std::process::id(), next_tmp_seq()));
    tmp.set_file_name(tmp_name);
    {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    fsync_parent(parent)?;
    Ok(())
}

fn fsync_parent(parent: &Path) -> Result<(), OfflinePackingKeysCacheError> {
    match File::open(parent) {
        Ok(dir) => match dir.sync_all() {
            Ok(()) => Ok(()),
            Err(err) if err.raw_os_error() == Some(libc_einval()) => Ok(()),
            Err(err) => Err(OfflinePackingKeysCacheError::Io(err)),
        },
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => Ok(()),
        Err(err) => Err(OfflinePackingKeysCacheError::Io(err)),
    }
}

#[cfg(target_os = "linux")]
const fn libc_einval() -> i32 {
    22
}
#[cfg(not(target_os = "linux"))]
const fn libc_einval() -> i32 {
    22
}

fn next_tmp_seq() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_changes_with_entries() {
        let a = CellShape {
            scheme_tag: b"x".to_vec(),
            entries: 1,
            entry_bytes: 32,
            packing_param_id: b"p".to_vec(),
        };
        let mut b = a.clone();
        b.entries = 2;
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn fingerprint_changes_with_entry_bytes() {
        let a = CellShape {
            scheme_tag: b"x".to_vec(),
            entries: 1,
            entry_bytes: 32,
            packing_param_id: b"p".to_vec(),
        };
        let mut b = a.clone();
        b.entry_bytes = 33;
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn fingerprint_changes_with_scheme_tag() {
        let a = CellShape {
            scheme_tag: b"x".to_vec(),
            entries: 1,
            entry_bytes: 32,
            packing_param_id: b"p".to_vec(),
        };
        let mut b = a.clone();
        b.scheme_tag = b"y".to_vec();
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn missing_file_is_miss() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = OfflinePackingKeysCache::new(dir.path());
        let cell = CellShape {
            scheme_tag: b"raven".to_vec(),
            entries: 256,
            entry_bytes: 32,
            packing_param_id: b"id".to_vec(),
        };
        match cache.load(&cell) {
            CacheLoad::Miss(OfflinePackingKeysCacheError::Io(err)) => {
                assert_eq!(err.kind(), io::ErrorKind::NotFound);
            }
            other => panic!("expected NotFound miss, got {other:?}"),
        }
    }
}
