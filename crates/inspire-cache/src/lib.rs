//! Crash-consistent disk cache for query-independent InsPIRe server packing keys.
//!
//! The cache identity binds the complete public parameter set, encoded-database width, and CRS
//! seed. A miss is explicit and lets the caller rebuild safely; detected corruption never becomes
//! server state.
//!
//! ```
//! use raven_inspire_cache::{CellShape, OfflinePackingKeysCache};
//!
//! let cache = OfflinePackingKeysCache::new("server-state");
//! let shape = CellShape {
//!     scheme_tag: b"my-inspire-deployment".to_vec(),
//!     entries: 2048,
//!     entry_bytes: 32,
//!     packing_param_id: b"public-parameter-id".to_vec(),
//! };
//! assert_ne!(shape.fingerprint(), [0; 32]);
//! assert!(cache.path().ends_with("cache/offline_packing_keys.bin"));
//! ```
#![deny(missing_docs)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use raven_inspire::inspiring::{OfflinePackingKeys, PackParams};
use raven_inspire::ServerInspiringCache;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CACHE_MAGIC: [u8; 8] = *b"RVN_OPK2";
const MAX_CACHE_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Standard relative path under a caller-owned data directory.
pub const CACHE_RELATIVE_PATH: &str = "cache/offline_packing_keys.bin";

/// Errors produced by [`OfflinePackingKeysCache`].
#[derive(Debug, thiserror::Error)]
pub enum OfflinePackingKeysCacheError {
    /// I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    /// Bincode encode/decode error.
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
    /// Stale cache fingerprint.
    #[error("hash mismatch: expected {expected}, found {found}")]
    HashMismatch {
        /// Hex-encoded expected fingerprint.
        expected: String,
        /// Hex-encoded on-disk fingerprint.
        found: String,
    },
    /// Decoded cache parts do not match their stored digest.
    #[error("body hash mismatch: expected {expected}, found {found}")]
    BodyHashMismatch {
        /// Digest stored beside the body.
        expected: String,
        /// Digest recomputed from the decoded body.
        found: String,
    },
    /// Cache file exceeds the allocation bound.
    #[error("cache file too large: {actual} bytes exceeds {limit} byte limit")]
    TooLarge {
        /// Observed or encoded file size.
        actual: u64,
        /// Maximum accepted cache size.
        limit: u64,
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
    /// Scheme tag; rejects sibling schemes that picked the same cell shape.
    pub scheme_tag: Vec<u8>,
    /// Number of database entries.
    pub entries: u64,
    /// Bytes per entry.
    pub entry_bytes: u64,
    /// Stable identifier for the packing parameters.
    pub packing_param_id: Vec<u8>,
}

impl CellShape {
    /// Build the exact InspiRING cache identity from parameters, packing width, and public seed.
    #[must_use]
    pub fn for_inspiring(
        params: &raven_inspire::params::InspireParams,
        num_columns: usize,
        inspiring_w_seed: [u8; 32],
    ) -> Self {
        let mut identity = Vec::new();
        identity.extend_from_slice(&(params.ring_dim as u64).to_le_bytes());
        identity.extend_from_slice(&params.q.to_le_bytes());
        identity.extend_from_slice(&params.p.to_le_bytes());
        identity.extend_from_slice(&params.sigma.to_bits().to_le_bytes());
        identity.extend_from_slice(&params.gadget_base.to_le_bytes());
        identity.extend_from_slice(&(params.gadget_len as u64).to_le_bytes());
        identity.push(match params.security_level {
            raven_inspire::params::SecurityLevel::Bits128 => 0,
            raven_inspire::params::SecurityLevel::Bits256 => 1,
        });
        identity.extend_from_slice(&(params.crt_moduli.len() as u64).to_le_bytes());
        for modulus in &params.crt_moduli {
            identity.extend_from_slice(&modulus.to_le_bytes());
        }
        identity.extend_from_slice(&(num_columns as u64).to_le_bytes());
        identity.extend_from_slice(&inspiring_w_seed);
        Self {
            scheme_tag: b"raven-inspire-cache-v2".to_vec(),
            entries: 0,
            entry_bytes: 0,
            packing_param_id: identity,
        }
    }

    /// Return the SHA-256 fingerprint of this cell shape.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.scheme_tag);
        hasher.update(self.entries.to_le_bytes());
        hasher.update(self.entry_bytes.to_le_bytes());
        hasher.update(&self.packing_param_id);
        hasher.finalize().into()
    }

    /// Return the hex-encoded fingerprint.
    #[must_use]
    pub fn fingerprint_hex(&self) -> String {
        hex_encode(&self.fingerprint())
    }
}

#[derive(Serialize, Deserialize)]
struct CacheFile {
    magic: [u8; 8],
    fingerprint: [u8; 32],
    scheme_tag: Vec<u8>,
    entries: u64,
    entry_bytes: u64,
    body_hash: [u8; 32],
    pack_params: PackParams,
    offline_keys: OfflinePackingKeys,
}

/// Deserialized query-independent cache parts.
#[derive(Debug)]
pub struct CacheParts {
    /// Cached pack parameters.
    pub pack_params: PackParams,
    /// Cached offline packing keys.
    pub offline_keys: OfflinePackingKeys,
}

/// Result of a cache load attempt.
#[derive(Debug)]
pub enum CacheLoad {
    /// Cache matched the requested identity and body digest.
    Hit(Box<CacheParts>),
    /// Cache did not match; the caller must rebuild the offline phase.
    Miss(OfflinePackingKeysCacheError),
}

/// Disk-backed cache for InspiRING offline keys.
#[derive(Clone, Debug)]
pub struct OfflinePackingKeysCache {
    path: PathBuf,
}

impl OfflinePackingKeysCache {
    /// Pin the cache to [`CACHE_RELATIVE_PATH`] under `data_dir`.
    #[must_use]
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        Self {
            path: data_dir.as_ref().join(CACHE_RELATIVE_PATH),
        }
    }

    /// Pin the cache to a caller-supplied path.
    #[must_use]
    pub fn at_path(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Return the resolved on-disk path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Try to load the cache, returning a typed miss instead of silently rebuilding.
    #[must_use]
    pub fn load(&self, cell: &CellShape) -> CacheLoad {
        match self.try_load(cell) {
            Ok(parts) => parts,
            Err(err) => CacheLoad::Miss(err),
        }
    }

    fn try_load(&self, cell: &CellShape) -> Result<CacheLoad, OfflinePackingKeysCacheError> {
        let file_len = fs::metadata(&self.path)?.len();
        if file_len > MAX_CACHE_FILE_BYTES {
            return Err(OfflinePackingKeysCacheError::TooLarge {
                actual: file_len,
                limit: MAX_CACHE_FILE_BYTES,
            });
        }
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
        let observed_body_hash = cache_body_hash(&file.pack_params, &file.offline_keys)?;
        if file.body_hash != observed_body_hash {
            return Err(OfflinePackingKeysCacheError::BodyHashMismatch {
                expected: hex_encode(&file.body_hash),
                found: hex_encode(&observed_body_hash),
            });
        }
        Ok(CacheLoad::Hit(Box::new(CacheParts {
            pack_params: file.pack_params,
            offline_keys: file.offline_keys,
        })))
    }

    /// Persist the cache with an atomic write, file fsync, rename, and parent-directory fsync.
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
            body_hash: cache_body_hash(pack_params, offline_keys)?,
            pack_params: pack_params.clone(),
            offline_keys: offline_keys.clone(),
        };
        let bytes = bincode::serialize(&file)?;
        if bytes.len() as u64 > MAX_CACHE_FILE_BYTES {
            return Err(OfflinePackingKeysCacheError::TooLarge {
                actual: bytes.len() as u64,
                limit: MAX_CACHE_FILE_BYTES,
            });
        }
        raven_storage::atomic_write(&self.path, &bytes)?;
        Ok(())
    }

    /// Load the cache or build and persist fresh query-independent cache parts.
    ///
    /// The returned flag is `true` only for a disk hit. The closure must not include
    /// query-derived `packing_offline` work.
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

fn cache_body_hash(
    pack_params: &PackParams,
    offline_keys: &OfflinePackingKeys,
) -> Result<[u8; 32], OfflinePackingKeysCacheError> {
    let bytes = bincode::serialize(&(pack_params, offline_keys))?;
    Ok(Sha256::digest(bytes).into())
}

/// Composite error from [`OfflinePackingKeysCache::load_or_build`].
#[derive(Debug, thiserror::Error)]
pub enum CacheBuildError<E> {
    /// The caller's offline-phase build failed.
    #[error("offline-phase build failed: {0}")]
    Build(E),
    /// The cache layer failed.
    #[error(transparent)]
    Cache(#[from] OfflinePackingKeysCacheError),
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = std::fmt::Write::write_fmt(&mut encoded, format_args!("{byte:02x}"));
    }
    encoded
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use raven_inspire::params::{InspireParams, SecurityLevel};

    fn shape() -> CellShape {
        CellShape {
            scheme_tag: b"scheme".to_vec(),
            entries: 1,
            entry_bytes: 32,
            packing_param_id: b"params".to_vec(),
        }
    }

    #[test]
    fn fingerprint_binds_every_shape_component() {
        let baseline = shape();
        let mut changed = baseline.clone();
        changed.scheme_tag = b"other".to_vec();
        assert_ne!(baseline.fingerprint(), changed.fingerprint());
        changed = baseline.clone();
        changed.entries += 1;
        assert_ne!(baseline.fingerprint(), changed.fingerprint());
        changed = baseline.clone();
        changed.entry_bytes += 1;
        assert_ne!(baseline.fingerprint(), changed.fingerprint());
        changed = baseline.clone();
        changed.packing_param_id.push(0);
        assert_ne!(baseline.fingerprint(), changed.fingerprint());
    }

    #[test]
    fn missing_file_is_typed_miss() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = OfflinePackingKeysCache::new(dir.path());
        match cache.load(&shape()) {
            CacheLoad::Miss(OfflinePackingKeysCacheError::Io(error)) => {
                assert_eq!(error.kind(), io::ErrorKind::NotFound);
            }
            other => panic!("expected NotFound miss, got {other:?}"),
        }
    }

    #[test]
    fn sparse_oversize_file_is_refused_before_allocation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = OfflinePackingKeysCache::new(dir.path());
        fs::create_dir_all(cache.path().parent().expect("parent")).expect("cache dir");
        let file = fs::File::create(cache.path()).expect("cache file");
        file.set_len(MAX_CACHE_FILE_BYTES + 1)
            .expect("sparse length");
        match cache.load(&shape()) {
            CacheLoad::Miss(OfflinePackingKeysCacheError::TooLarge { actual, limit }) => {
                assert_eq!(actual, 256 * 1024 * 1024 + 1);
                assert_eq!(limit, 256 * 1024 * 1024);
            }
            other => panic!("expected TooLarge miss, got {other:?}"),
        }
    }

    #[test]
    fn inspiring_identity_binds_every_declared_input() {
        let baseline_params = InspireParams::secure_128_d2048();
        let baseline = CellShape::for_inspiring(&baseline_params, 16, [7; 32]);

        let assert_params_change = |params: &InspireParams| {
            assert_ne!(
                CellShape::for_inspiring(params, 16, [7; 32]).packing_param_id,
                baseline.packing_param_id
            );
        };
        let mut changed = baseline_params.clone();
        changed.ring_dim += 1;
        assert_params_change(&changed);
        changed = baseline_params.clone();
        changed.q += 1;
        assert_params_change(&changed);
        changed = baseline_params.clone();
        changed.p += 1;
        assert_params_change(&changed);
        changed = baseline_params.clone();
        changed.sigma = f64::from_bits(changed.sigma.to_bits() + 1);
        assert_params_change(&changed);
        changed = baseline_params.clone();
        changed.gadget_base += 1;
        assert_params_change(&changed);
        changed = baseline_params.clone();
        changed.gadget_len += 1;
        assert_params_change(&changed);
        changed = baseline_params.clone();
        changed.security_level = SecurityLevel::Bits256;
        assert_params_change(&changed);
        changed = baseline_params.clone();
        changed.crt_moduli.push(17);
        assert_params_change(&changed);

        assert_ne!(
            CellShape::for_inspiring(&baseline_params, 17, [7; 32]).packing_param_id,
            baseline.packing_param_id
        );
        assert_ne!(
            CellShape::for_inspiring(&baseline_params, 16, [8; 32]).packing_param_id,
            baseline.packing_param_id
        );
    }

    proptest! {
        #[test]
        fn fingerprint_changes_for_any_distinct_entry_count(
            entries in any::<u64>(),
            other in any::<u64>(),
        ) {
            prop_assume!(entries != other);
            let mut baseline = shape();
            baseline.entries = entries;
            let mut changed = baseline.clone();
            changed.entries = other;
            prop_assert_ne!(baseline.fingerprint(), changed.fingerprint());
        }
    }
}
