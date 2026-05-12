//! Operator snapshot export / import.
//!
//! Export: walks instance data_dirs, builds a zstd tarball with `EXPORT_MANIFEST.json`.
//! Import: verifies signature + checksums before any disk write, then atomic-renames staging into
//! place. `wal/current.log` is excluded by default (unsafe to read from a live writer).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use raven_railgun_persistence::{Manifest, MANIFEST_SCHEMA_VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SnapshotPortError {
    #[error("signature verification failed: {detail}")]
    SignatureVerificationFailed { detail: String },
    #[error("detached signature public_key_hex does not match supplied verifying key")]
    SignaturePublicKeyMismatch,
    #[error("detached signature content_hash_hex does not match tarball manifest")]
    SignatureContentHashMismatch,
    #[error("signature length {actual} != expected {expected}")]
    SignatureLengthInvalid { actual: usize, expected: usize },
    #[error("checksum mismatch: {detail}")]
    ChecksumMismatch { detail: String },
    #[error("export top-level content_hash_hex mismatch (manifest tampered)")]
    ContentHashMismatch,
    #[error("schema version mismatch: {kind} observed={observed} expected={expected}")]
    SchemaVersionMismatch {
        kind: &'static str,
        observed: u32,
        expected: u32,
    },
    #[error("export kind {observed:?} != expected {expected:?}")]
    KindMismatch {
        observed: String,
        expected: &'static str,
    },
    #[error(
        "destination root already contains instance data_dirs; \
         pass --allow-overwrite to back them up to <root>.pre-import.<ts>/"
    )]
    DestinationPopulated,
    #[error("parse tarball: {detail}")]
    TarballParse { detail: String },
    #[error(
        "import-snapshot requires Ed25519 verification: pass `verifying_key = Some(_)` or \
         explicitly set `unsafe_no_verify = true` (an attacker who replaces the tarball \
         can swap your entire data_dir)"
    )]
    SignatureRequired,
}

const EXPORT_MANIFEST_NAME: &str = "EXPORT_MANIFEST.json";
const EXPORT_SCHEMA_VERSION: u32 = 1;
const EXPORT_KIND: &str = "raven-railgun-export/v1";
const SHARED_CRS_DIR: &str = "shared/crs/";
const INSTANCES_PREFIX: &str = "instances/";
const PER_INSTANCE_MANIFEST: &str = "manifest.json";
const SNAPSHOTS_DIR: &str = "snapshots";
const WAL_DIR: &str = "wal";
const WAL_ARCHIVED_DIR: &str = "archived";
const WAL_CURRENT_FILE: &str = "current.log";
const STAGING_PREFIX: &str = ".staging.";
const BACKUP_PREFIX: &str = ".pre-import.";
const ED25519_SEED_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct ExportOptions {
    pub data_dir: PathBuf,
    pub output: PathBuf,
    pub signing_key: Option<PathBuf>,
    pub include_current_wal: bool,
    /// Retain only the N newest `*.tar.zst` tarballs in the parent
    /// directory of `output` after a successful write. `0` disables.
    /// Operator CLI default is 3; tests typically pass `0`.
    pub keep_snapshots: usize,
}

/// Options for the standalone `PruneSnapshots` subcommand.
///
/// Cron / systemd-timer friendly: the entry point is idempotent, never
/// touches the live `data_dir` itself, and only inspects `*.tar.zst`
/// files (plus paired `.sig` sidecars) in the configured directory.
#[derive(Debug, Clone)]
pub struct PruneOptions {
    /// Directory containing `*.tar.zst` export tarballs.
    pub data_dir: PathBuf,
    /// Retention floor: keep the N newest tarballs (plus paired `.sig`
    /// sidecars). `0` disables; `1` keeps only the newest.
    pub keep_snapshots: usize,
}

#[derive(Debug, Clone)]
pub struct ImportOptions {
    pub input: PathBuf,
    pub data_dir: PathBuf,
    pub verifying_key: Option<PathBuf>,
    pub allow_overwrite: bool,
    /// When `verifying_key` is `None`, `run_import` returns `SignatureRequired` unless this is set.
    pub unsafe_no_verify: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExportManifest {
    pub schema_version: u32,
    pub kind: String,
    pub exported_at_unix_ms: u64,
    pub instance_count: u32,
    pub persistence_manifest_version: u32,
    pub instances: Vec<ExportInstance>,
    pub shared_crs: Vec<SharedCrsRef>,
    pub content_hash_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExportInstance {
    pub id: String,
    pub encoder_label: String,
    pub scheme_tag: String,
    pub shared_crs_hash: String,
    pub data_size_bytes: u64,
    pub content_hash_hex: String,
    pub files: Vec<ExportFile>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExportFile {
    pub rel_path: String,
    pub byte_len: u64,
    pub sha256_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedCrsRef {
    pub hash: String,
    pub rel_path: String,
    pub byte_len: u64,
    pub scheme_tag: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedCrsBlob {
    pub kind: String,
    pub scheme_tag: String,
    pub persistence_manifest_version: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetachedSignature {
    pub kind: String,
    pub signature_hex: String,
    pub content_hash_hex: String,
    pub public_key_hex: String,
}

#[allow(clippy::too_many_lines)]
pub fn run_export(opts: ExportOptions) -> anyhow::Result<()> {
    let instances = discover_instances(&opts.data_dir).with_context(|| {
        format!(
            "discover instance data_dirs under {}",
            opts.data_dir.display()
        )
    })?;
    if instances.is_empty() {
        bail!(
            "no instance data_dirs found under {} (expected at least one child with manifest.json)",
            opts.data_dir.display()
        );
    }

    let mut planned: Vec<PlannedInstance> = Vec::with_capacity(instances.len());
    for entry in instances {
        let plan = plan_instance(&entry, opts.include_current_wal)
            .with_context(|| format!("plan export for instance at {}", entry.dir.display()))?;
        planned.push(plan);
    }

    let mut shared_crs_table: BTreeMap<String, (SharedCrsBlob, Vec<u8>, String)> = BTreeMap::new();
    for plan in &planned {
        let blob = SharedCrsBlob {
            kind: "raven-railgun-shared-crs/v1".to_owned(),
            scheme_tag: plan.manifest.scheme_tag.clone(),
            persistence_manifest_version: plan.manifest.schema_version,
        };
        let bytes = serde_json::to_vec(&blob).context("serialize shared CRS blob")?;
        let hash = sha256_hex(&bytes);
        let rel = format!("{SHARED_CRS_DIR}{hash}.json");
        shared_crs_table.entry(hash).or_insert((blob, bytes, rel));
    }

    let exported_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));

    let mut export_instances: Vec<ExportInstance> = Vec::with_capacity(planned.len());
    let mut all_content_hashes: Vec<u8> = Vec::new();
    for plan in &planned {
        let scheme_blob = SharedCrsBlob {
            kind: "raven-railgun-shared-crs/v1".to_owned(),
            scheme_tag: plan.manifest.scheme_tag.clone(),
            persistence_manifest_version: plan.manifest.schema_version,
        };
        let scheme_bytes = serde_json::to_vec(&scheme_blob)?;
        let scheme_hash = sha256_hex(&scheme_bytes);
        let mut hasher = Sha256::new();
        let mut total: u64 = 0;
        let mut files: Vec<ExportFile> = Vec::with_capacity(plan.files.len());
        for f in &plan.files {
            hasher.update(f.rel_path.as_bytes());
            hasher.update(b":");
            hasher.update(f.sha256_hex.as_bytes());
            hasher.update(b"\n");
            total = total.saturating_add(f.byte_len);
            files.push(ExportFile {
                rel_path: f.rel_path.clone(),
                byte_len: f.byte_len,
                sha256_hex: f.sha256_hex.clone(),
            });
        }
        let content_hash = bytes_to_hex(&hasher.finalize());
        all_content_hashes.extend_from_slice(plan.id.as_bytes());
        all_content_hashes.extend_from_slice(b":");
        all_content_hashes.extend_from_slice(content_hash.as_bytes());
        all_content_hashes.push(b'\n');
        export_instances.push(ExportInstance {
            id: plan.id.clone(),
            encoder_label: plan.manifest.encoder_label.clone(),
            scheme_tag: plan.manifest.scheme_tag.clone(),
            shared_crs_hash: scheme_hash,
            data_size_bytes: total,
            content_hash_hex: content_hash,
            files,
        });
    }
    let global_content_hash = sha256_hex(&all_content_hashes);

    let mut shared_crs_entries: Vec<SharedCrsRef> = shared_crs_table
        .iter()
        .map(|(hash, (blob, bytes, rel))| SharedCrsRef {
            hash: hash.clone(),
            rel_path: rel.clone(),
            byte_len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            scheme_tag: blob.scheme_tag.clone(),
        })
        .collect();
    shared_crs_entries.sort_by(|a, b| a.hash.cmp(&b.hash));

    let manifest = ExportManifest {
        schema_version: EXPORT_SCHEMA_VERSION,
        kind: EXPORT_KIND.to_owned(),
        exported_at_unix_ms: exported_at,
        instance_count: u32::try_from(planned.len()).unwrap_or(u32::MAX),
        persistence_manifest_version: MANIFEST_SCHEMA_VERSION,
        instances: export_instances,
        shared_crs: shared_crs_entries,
        content_hash_hex: global_content_hash.clone(),
    };

    write_tarball(&opts.output, &manifest, &planned, &shared_crs_table)?;
    fsync_file(&opts.output)?;
    if let Some(parent) = opts.output.parent() {
        if !parent.as_os_str().is_empty() {
            fsync_dir(parent)?;
        }
    }

    if let Some(key_path) = opts.signing_key.as_ref() {
        let signing_key = load_signing_key(key_path)?;
        let signature = signing_key.sign(global_content_hash.as_bytes());
        let public = signing_key.verifying_key();
        let detached = DetachedSignature {
            kind: "raven-railgun-export-sig/v1".to_owned(),
            signature_hex: hex::encode(signature.to_bytes()),
            content_hash_hex: global_content_hash,
            public_key_hex: hex::encode(public.to_bytes()),
        };
        let bytes = serde_json::to_vec_pretty(&detached)?;
        let sig_path = sig_sidecar_path(&opts.output);
        atomic_write_file(&sig_path, &bytes)?;
        fsync_file(&sig_path)?;
        if let Some(parent) = sig_path.parent() {
            if !parent.as_os_str().is_empty() {
                fsync_dir(parent)?;
            }
        }
    }

    // Opportunistic retention pass: trim the parent directory to the
    // configured floor. Best-effort -- a prune failure must NOT fail
    // the export itself; the operator still has a fresh tarball on
    // disk. Per-entry failures inside the pruner are warn-logged.
    if opts.keep_snapshots > 0 {
        if let Some(parent) = opts.output.parent() {
            if !parent.as_os_str().is_empty() {
                match prune_old_export_tarballs(parent, opts.keep_snapshots) {
                    Ok(removed) => {
                        if removed > 0 {
                            tracing::info!(
                                directory = %parent.display(),
                                removed,
                                keep_snapshots = opts.keep_snapshots,
                                "pruned stale export tarballs"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            directory = %parent.display(),
                            error = %e,
                            "post-export prune failed; tarball already written"
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

/// Trim the directory to the `keep_last_n` newest `*.tar.zst` files by
/// modification time. Paired `.sig` sidecars are removed alongside the
/// tarball they protect. Per-entry failures are logged at `warn` and
/// do not abort the prune.
///
/// `keep_last_n = 0` is a no-op (returns `Ok(0)`). A non-existent
/// `snapshots_dir` is also a no-op (cron-friendly: the pruner can race
/// the directory's creation). Returns the count of tarballs removed
/// (excluding `.sig` sidecars).
pub fn prune_old_export_tarballs(snapshots_dir: &Path, keep_last_n: usize) -> anyhow::Result<usize> {
    if keep_last_n == 0 {
        return Ok(0);
    }
    if !snapshots_dir.exists() {
        return Ok(0);
    }
    let read = match std::fs::read_dir(snapshots_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => {
            return Err(anyhow::Error::new(e).context(format!(
                "read_dir snapshots directory {}",
                snapshots_dir.display()
            )));
        }
    };
    let mut entries: Vec<(PathBuf, SystemTime)> = Vec::new();
    for ent in read {
        let Ok(ent) = ent else {
            continue;
        };
        let path = ent.path();
        if !path.is_file() {
            continue;
        }
        let is_tarball = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|s| s.ends_with(".tar.zst"));
        if !is_tarball {
            continue;
        }
        let mtime = match ent.metadata().and_then(|m| m.modified()) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "prune: skipping entry; metadata/mtime unreadable"
                );
                continue;
            }
        };
        entries.push((path, mtime));
    }
    // Sort newest-first by mtime; tie-break on filename for determinism.
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.cmp(&a.0)));
    let mut removed = 0usize;
    for (path, _) in entries.iter().skip(keep_last_n) {
        let sig = sig_sidecar_path(path);
        if let Err(e) = std::fs::remove_file(path) {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "prune: failed to remove tarball; skipping"
            );
            continue;
        }
        removed = removed.saturating_add(1);
        // Best-effort .sig sidecar removal -- absent or transient is fine.
        match std::fs::remove_file(&sig) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(
                    path = %sig.display(),
                    error = %e,
                    "prune: failed to remove .sig sidecar"
                );
            }
        }
    }
    Ok(removed)
}

/// Standalone prune entry point. Suitable for cron / systemd-timer
/// invocation between exports. Idempotent.
pub fn run_prune(opts: PruneOptions) -> anyhow::Result<()> {
    let removed = prune_old_export_tarballs(&opts.data_dir, opts.keep_snapshots)?;
    tracing::info!(
        directory = %opts.data_dir.display(),
        removed,
        keep_snapshots = opts.keep_snapshots,
        "run_prune complete"
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub fn run_import(opts: ImportOptions) -> anyhow::Result<()> {
    if opts.verifying_key.is_none() && !opts.unsafe_no_verify {
        return Err(anyhow::Error::new(SnapshotPortError::SignatureRequired));
    }
    let raw = fs::read(&opts.input)
        .with_context(|| format!("open input tarball {}", opts.input.display()))?;

    if let Some(key_path) = opts.verifying_key.as_ref() {
        let public = load_verifying_key(key_path)?;
        let sig_path = sig_sidecar_path(&opts.input);
        let sig_bytes = fs::read(&sig_path)
            .with_context(|| format!("open signature sidecar {}", sig_path.display()))?;
        let detached: DetachedSignature =
            serde_json::from_slice(&sig_bytes).context("parse signature sidecar")?;
        let sig_raw = hex::decode(&detached.signature_hex).context("hex-decode signature")?;
        if sig_raw.len() != Signature::BYTE_SIZE {
            return Err(anyhow::Error::new(
                SnapshotPortError::SignatureLengthInvalid {
                    actual: sig_raw.len(),
                    expected: Signature::BYTE_SIZE,
                },
            ));
        }
        let mut sig_arr = [0u8; Signature::BYTE_SIZE];
        sig_arr.copy_from_slice(&sig_raw);
        let signature = Signature::from_bytes(&sig_arr);
        public
            .verify(detached.content_hash_hex.as_bytes(), &signature)
            .map_err(|e| {
                anyhow::Error::new(SnapshotPortError::SignatureVerificationFailed {
                    detail: e.to_string(),
                })
            })?;
    }

    let parsed = parse_tarball(&raw).map_err(|e| {
        anyhow::Error::new(SnapshotPortError::TarballParse {
            detail: format!("{e:#}"),
        })
    })?;
    let manifest = parsed.manifest.clone();

    if manifest.schema_version != EXPORT_SCHEMA_VERSION {
        return Err(anyhow::Error::new(
            SnapshotPortError::SchemaVersionMismatch {
                kind: "export",
                observed: manifest.schema_version,
                expected: EXPORT_SCHEMA_VERSION,
            },
        ));
    }
    if manifest.kind != EXPORT_KIND {
        return Err(anyhow::Error::new(SnapshotPortError::KindMismatch {
            observed: manifest.kind.clone(),
            expected: EXPORT_KIND,
        }));
    }
    if manifest.persistence_manifest_version != MANIFEST_SCHEMA_VERSION {
        return Err(anyhow::Error::new(
            SnapshotPortError::SchemaVersionMismatch {
                kind: "persistence",
                observed: manifest.persistence_manifest_version,
                expected: MANIFEST_SCHEMA_VERSION,
            },
        ));
    }
    if manifest.content_hash_hex != recompute_content_hash(&manifest) {
        return Err(anyhow::Error::new(SnapshotPortError::ContentHashMismatch));
    }
    if let Some(key_path) = opts.verifying_key.as_ref() {
        let public = load_verifying_key(key_path)?;
        let sig_bytes = fs::read(sig_sidecar_path(&opts.input))?;
        let detached: DetachedSignature = serde_json::from_slice(&sig_bytes)?;
        if detached.content_hash_hex != manifest.content_hash_hex {
            return Err(anyhow::Error::new(
                SnapshotPortError::SignatureContentHashMismatch,
            ));
        }
        let pk_bytes = hex::decode(&detached.public_key_hex)?;
        if pk_bytes != public.to_bytes() {
            return Err(anyhow::Error::new(
                SnapshotPortError::SignaturePublicKeyMismatch,
            ));
        }
    }

    verify_payload_checksums(&parsed)?;

    let dest_root = opts.data_dir.clone();
    let dest_exists_populated = root_has_instances(&dest_root)?;
    if dest_exists_populated && !opts.allow_overwrite {
        return Err(anyhow::Error::new(SnapshotPortError::DestinationPopulated)).with_context(
            || format!("destination root {} already populated", dest_root.display()),
        );
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));

    let staging = sibling_with_suffix(&dest_root, &format!("{STAGING_PREFIX}{ts}"))?;
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    fs::create_dir_all(&staging)?;

    extract_instances(&parsed, &staging)?;

    let backup = if dest_exists_populated {
        let path = sibling_with_suffix(&dest_root, &format!("{BACKUP_PREFIX}{ts}"))?;
        fs::rename(&dest_root, &path).with_context(|| {
            format!(
                "back up existing root {} -> {}",
                dest_root.display(),
                path.display()
            )
        })?;
        if let Some(parent) = dest_root.parent() {
            if !parent.as_os_str().is_empty() {
                fsync_dir(parent)?;
            }
        }
        Some(path)
    } else if dest_root.exists() {
        fs::remove_dir_all(&dest_root)?;
        None
    } else {
        None
    };

    if let Err(e) = fs::rename(&staging, &dest_root) {
        if let Some(b) = backup.as_ref() {
            let _ = fs::rename(b, &dest_root);
        }
        let _ = fs::remove_dir_all(&staging);
        return Err(anyhow!(
            "atomic rename {} -> {} failed: {e}",
            staging.display(),
            dest_root.display()
        ));
    }
    if let Some(parent) = dest_root.parent() {
        if !parent.as_os_str().is_empty() {
            fsync_dir(parent)?;
        }
    }

    let mut imported_ids: BTreeSet<String> = BTreeSet::new();
    for inst in &manifest.instances {
        let dir = dest_root.join(&inst.id);
        let manifest_path = dir.join(PER_INSTANCE_MANIFEST);
        let bytes = fs::read(&manifest_path).with_context(|| {
            format!(
                "post-import: read recovered manifest at {}",
                manifest_path.display()
            )
        })?;
        let m: Manifest = serde_json::from_slice(&bytes).map_err(|e| {
            anyhow!(
                "post-import: parse recovered manifest at {}: {e}",
                manifest_path.display()
            )
        })?;
        if m.encoder_label != inst.encoder_label {
            bail!(
                "post-import sanity: instance {} encoder_label {:?} != export entry {:?}",
                inst.id,
                m.encoder_label,
                inst.encoder_label
            );
        }
        if m.scheme_tag != inst.scheme_tag {
            bail!(
                "post-import sanity: instance {} scheme_tag {:?} != export entry {:?}",
                inst.id,
                m.scheme_tag,
                inst.scheme_tag
            );
        }
        imported_ids.insert(inst.id.clone());
    }

    drop(imported_ids);
    Ok(())
}

#[derive(Debug, Clone)]
struct DiscoveredInstance {
    id: String,
    dir: PathBuf,
}

fn discover_instances(root: &Path) -> anyhow::Result<Vec<DiscoveredInstance>> {
    if !root.is_dir() {
        bail!("data_dir {} is not a directory", root.display());
    }
    let mut out: Vec<DiscoveredInstance> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    if root.join(PER_INSTANCE_MANIFEST).is_file() {
        let id = root
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("root path has no UTF-8 file name: {}", root.display()))?
            .to_owned();
        seen.insert(id.clone());
        out.push(DiscoveredInstance {
            id,
            dir: root.to_path_buf(),
        });
        return Ok(out);
    }
    for child in fs::read_dir(root)? {
        let entry = child?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if !path.join(PER_INSTANCE_MANIFEST).is_file() {
            continue;
        }
        let id = entry
            .file_name()
            .into_string()
            .map_err(|os| anyhow!("non-UTF-8 instance dir name: {os:?}"))?;
        if !seen.insert(id.clone()) {
            bail!("duplicate instance id: {id}");
        }
        out.push(DiscoveredInstance { id, dir: path });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

#[derive(Debug, Clone)]
struct PlannedInstance {
    id: String,
    manifest: Manifest,
    files: Vec<PlannedFile>,
}

#[derive(Debug, Clone)]
struct PlannedFile {
    rel_path: String,
    abs_path: PathBuf,
    byte_len: u64,
    sha256_hex: String,
}

fn plan_instance(
    entry: &DiscoveredInstance,
    include_current_wal: bool,
) -> anyhow::Result<PlannedInstance> {
    let manifest_bytes = fs::read(entry.dir.join(PER_INSTANCE_MANIFEST))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| anyhow!("parse manifest for {}: {e}", entry.id))?;
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        bail!(
            "instance {}: manifest schema_version {} != supported {}",
            entry.id,
            manifest.schema_version,
            MANIFEST_SCHEMA_VERSION
        );
    }

    let mut files: Vec<PlannedFile> = Vec::new();
    push_file(&mut files, entry, PER_INSTANCE_MANIFEST.to_owned())?;

    let snap_dir = entry
        .dir
        .join(SNAPSHOTS_DIR)
        .join(format!("snap-{:06}", manifest.current_snapshot_id.0));
    if snap_dir.is_dir() {
        let header = snap_dir.join("header.bin");
        if header.is_file() {
            let rel = format!(
                "{SNAPSHOTS_DIR}/snap-{:06}/header.bin",
                manifest.current_snapshot_id.0
            );
            push_file(&mut files, entry, rel)?;
        }
        let data = snap_dir.join("data.bincode");
        if data.is_file() {
            let rel = format!(
                "{SNAPSHOTS_DIR}/snap-{:06}/data.bincode",
                manifest.current_snapshot_id.0
            );
            push_file(&mut files, entry, rel)?;
        }
    }

    if include_current_wal {
        let current = entry.dir.join(WAL_DIR).join(WAL_CURRENT_FILE);
        if current.is_file() {
            let rel = format!("{WAL_DIR}/{WAL_CURRENT_FILE}");
            push_file(&mut files, entry, rel)?;
        }
    }

    let archived_dir = entry.dir.join(WAL_DIR).join(WAL_ARCHIVED_DIR);
    if archived_dir.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(&archived_dir)?
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().is_file())
            .collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for e in entries {
            let name = e
                .file_name()
                .into_string()
                .map_err(|os| anyhow!("non-UTF-8 archived WAL filename: {os:?}"))?;
            let rel = format!("{WAL_DIR}/{WAL_ARCHIVED_DIR}/{name}");
            push_file(&mut files, entry, rel)?;
        }
    }

    files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    Ok(PlannedInstance {
        id: entry.id.clone(),
        manifest,
        files,
    })
}

fn push_file(
    out: &mut Vec<PlannedFile>,
    entry: &DiscoveredInstance,
    rel: String,
) -> anyhow::Result<()> {
    let abs = entry.dir.join(&rel);
    let bytes =
        fs::read(&abs).with_context(|| format!("read planned file {} for {}", rel, entry.id))?;
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let sha = sha256_hex(&bytes);
    out.push(PlannedFile {
        rel_path: rel,
        abs_path: abs,
        byte_len: len,
        sha256_hex: sha,
    });
    Ok(())
}

fn write_tarball(
    output: &Path,
    manifest: &ExportManifest,
    planned: &[PlannedInstance],
    shared_crs_table: &BTreeMap<String, (SharedCrsBlob, Vec<u8>, String)>,
) -> anyhow::Result<()> {
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let tmp = output.with_extension("tmp");
    if tmp.exists() {
        fs::remove_file(&tmp)?;
    }
    let raw = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)?;
    let zstd_writer = zstd::stream::write::Encoder::new(raw, 3).context("init zstd encoder")?;
    let mut zstd_writer = zstd_writer.auto_finish();
    {
        let mut tar_writer = tar::Builder::new(&mut zstd_writer);
        tar_writer.mode(tar::HeaderMode::Deterministic);

        let manifest_bytes = serde_json::to_vec_pretty(manifest)?;
        append_bytes(&mut tar_writer, EXPORT_MANIFEST_NAME, &manifest_bytes)?;

        for (_, bytes, rel) in shared_crs_table.values() {
            append_bytes(&mut tar_writer, rel, bytes)?;
        }

        for plan in planned {
            for f in &plan.files {
                let rel = format!("{INSTANCES_PREFIX}{}/{}", plan.id, f.rel_path);
                let bytes = fs::read(&f.abs_path)?;
                append_bytes(&mut tar_writer, &rel, &bytes)?;
            }
        }
        tar_writer.finish()?;
    }

    fs::rename(&tmp, output)?;
    Ok(())
}

fn append_bytes<W: Write>(
    builder: &mut tar::Builder<W>,
    name: &str,
    bytes: &[u8],
) -> anyhow::Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_path(name)?;
    header.set_size(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    header.set_mode(0o600);
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_cksum();
    builder.append(&header, bytes)?;
    Ok(())
}

#[derive(Debug)]
struct ParsedTarball {
    manifest: ExportManifest,
    files: BTreeMap<String, Vec<u8>>,
}

fn parse_tarball(raw: &[u8]) -> anyhow::Result<ParsedTarball> {
    let decoder = zstd::stream::read::Decoder::with_buffer(std::io::Cursor::new(raw))?;
    let mut archive = tar::Archive::new(decoder);
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for entry_res in archive.entries()? {
        let mut entry = entry_res?;
        let path = entry.path()?.into_owned();
        let normalised = normalise_archive_path(&path)?;
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        if files.insert(normalised, buf).is_some() {
            bail!("tarball contains duplicate entry for the same logical path");
        }
    }
    let manifest_bytes = files
        .get(EXPORT_MANIFEST_NAME)
        .ok_or_else(|| anyhow!("tarball missing top-level {EXPORT_MANIFEST_NAME}"))?;
    let manifest: ExportManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|e| anyhow!("parse {EXPORT_MANIFEST_NAME}: {e}"))?;
    Ok(ParsedTarball { manifest, files })
}

fn normalise_archive_path(path: &Path) -> anyhow::Result<String> {
    let mut out = String::new();
    for comp in path.components() {
        match comp {
            Component::Normal(part) => {
                let s = part
                    .to_str()
                    .ok_or_else(|| anyhow!("non-UTF-8 archive entry: {}", path.display()))?;
                if !out.is_empty() {
                    out.push('/');
                }
                out.push_str(s);
            }
            Component::ParentDir => bail!(
                "archive entry contains parent-dir component: {}",
                path.display()
            ),
            Component::RootDir | Component::Prefix(_) => {
                bail!("archive entry contains absolute root: {}", path.display())
            }
            Component::CurDir => {}
        }
    }
    if out.is_empty() {
        bail!("empty archive entry path");
    }
    Ok(out)
}

fn verify_payload_checksums(parsed: &ParsedTarball) -> anyhow::Result<()> {
    for shared in &parsed.manifest.shared_crs {
        let bytes = parsed.files.get(&shared.rel_path).ok_or_else(|| {
            anyhow::Error::new(SnapshotPortError::ChecksumMismatch {
                detail: format!("tarball missing shared CRS {}", shared.rel_path),
            })
        })?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != shared.byte_len {
            return Err(anyhow::Error::new(SnapshotPortError::ChecksumMismatch {
                detail: format!(
                    "shared CRS {} byte_len {} != manifest {}",
                    shared.rel_path,
                    bytes.len(),
                    shared.byte_len
                ),
            }));
        }
        let actual = sha256_hex(bytes);
        if actual != shared.hash {
            return Err(anyhow::Error::new(SnapshotPortError::ChecksumMismatch {
                detail: format!(
                    "shared CRS {} sha256 mismatch (actual {} != manifest {})",
                    shared.rel_path, actual, shared.hash
                ),
            }));
        }
    }

    let mut all_content_hashes: Vec<u8> = Vec::new();
    for inst in &parsed.manifest.instances {
        let mut local_hasher = Sha256::new();
        let mut total: u64 = 0;
        for f in &inst.files {
            let key = format!("{INSTANCES_PREFIX}{}/{}", inst.id, f.rel_path);
            let bytes = parsed.files.get(&key).ok_or_else(|| {
                anyhow::Error::new(SnapshotPortError::ChecksumMismatch {
                    detail: format!("tarball missing instance file {key}"),
                })
            })?;
            if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != f.byte_len {
                return Err(anyhow::Error::new(SnapshotPortError::ChecksumMismatch {
                    detail: format!(
                        "checksum mismatch for {key}: byte_len {} != manifest {}",
                        bytes.len(),
                        f.byte_len
                    ),
                }));
            }
            let actual = sha256_hex(bytes);
            if actual != f.sha256_hex {
                return Err(anyhow::Error::new(SnapshotPortError::ChecksumMismatch {
                    detail: format!(
                        "checksum mismatch for {key}: sha256 {} != manifest {}",
                        actual, f.sha256_hex
                    ),
                }));
            }
            local_hasher.update(f.rel_path.as_bytes());
            local_hasher.update(b":");
            local_hasher.update(f.sha256_hex.as_bytes());
            local_hasher.update(b"\n");
            total = total.saturating_add(f.byte_len);
        }
        if total != inst.data_size_bytes {
            return Err(anyhow::Error::new(SnapshotPortError::ChecksumMismatch {
                detail: format!(
                    "instance {}: total bytes {} != manifest data_size_bytes {}",
                    inst.id, total, inst.data_size_bytes
                ),
            }));
        }
        let local_hash = bytes_to_hex(&local_hasher.finalize());
        if local_hash != inst.content_hash_hex {
            return Err(anyhow::Error::new(SnapshotPortError::ChecksumMismatch {
                detail: format!(
                    "instance {}: per-instance content_hash_hex mismatch ({} != {})",
                    inst.id, local_hash, inst.content_hash_hex
                ),
            }));
        }
        all_content_hashes.extend_from_slice(inst.id.as_bytes());
        all_content_hashes.extend_from_slice(b":");
        all_content_hashes.extend_from_slice(inst.content_hash_hex.as_bytes());
        all_content_hashes.push(b'\n');
    }
    let global = sha256_hex(&all_content_hashes);
    if global != parsed.manifest.content_hash_hex {
        return Err(anyhow::Error::new(SnapshotPortError::ChecksumMismatch {
            detail: format!(
                "global content_hash_hex mismatch ({} != {})",
                global, parsed.manifest.content_hash_hex
            ),
        }));
    }
    Ok(())
}

fn recompute_content_hash(manifest: &ExportManifest) -> String {
    let mut buf: Vec<u8> = Vec::new();
    for inst in &manifest.instances {
        buf.extend_from_slice(inst.id.as_bytes());
        buf.extend_from_slice(b":");
        buf.extend_from_slice(inst.content_hash_hex.as_bytes());
        buf.push(b'\n');
    }
    sha256_hex(&buf)
}

fn extract_instances(parsed: &ParsedTarball, staging_root: &Path) -> anyhow::Result<()> {
    for inst in &parsed.manifest.instances {
        let inst_root = staging_root.join(&inst.id);
        for f in &inst.files {
            let rel = Path::new(&f.rel_path);
            for comp in rel.components() {
                match comp {
                    Component::Normal(_) => {}
                    _ => bail!(
                        "refused to extract path with non-normal component: {}",
                        f.rel_path
                    ),
                }
            }
            let dst = inst_root.join(rel);
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent)?;
            }
            let key = format!("{INSTANCES_PREFIX}{}/{}", inst.id, f.rel_path);
            let bytes = parsed
                .files
                .get(&key)
                .ok_or_else(|| anyhow!("missing tarball entry {key}"))?;
            atomic_write_file(&dst, bytes)?;
        }
        let snap_dir = inst_root.join(SNAPSHOTS_DIR);
        if !snap_dir.is_dir() {
            fs::create_dir_all(&snap_dir)?;
        }
        let wal_archived = inst_root.join(WAL_DIR).join(WAL_ARCHIVED_DIR);
        if !wal_archived.is_dir() {
            fs::create_dir_all(&wal_archived)?;
        }
    }
    Ok(())
}

fn root_has_instances(root: &Path) -> anyhow::Result<bool> {
    if !root.exists() {
        return Ok(false);
    }
    if !root.is_dir() {
        bail!(
            "destination data_dir {} exists and is not a directory",
            root.display()
        );
    }
    if root.join(PER_INSTANCE_MANIFEST).is_file() {
        return Ok(true);
    }
    for child in fs::read_dir(root)? {
        let entry = child?;
        if entry.path().join(PER_INSTANCE_MANIFEST).is_file() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn sibling_with_suffix(dest: &Path, suffix: &str) -> anyhow::Result<PathBuf> {
    let parent = dest
        .parent()
        .ok_or_else(|| anyhow!("destination {} has no parent", dest.display()))?;
    let name = dest
        .file_name()
        .ok_or_else(|| anyhow!("destination {} has no file name", dest.display()))?;
    let mut new_name = name.to_owned();
    new_name.push(suffix);
    Ok(parent.join(new_name))
}

fn atomic_write_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("import-tmp");
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        fsync_dir(parent)?;
    }
    Ok(())
}

/// Tolerates EINVAL (dirs that disallow fsync), `Unsupported` (WSL2/virtio-fs), and
/// `PermissionDenied` (sandboxed envs). All other errors propagate so ENOSPC/EIO surface.
fn fsync_dir(parent: &Path) -> anyhow::Result<()> {
    match fs::File::open(parent) {
        Ok(dir) => match dir.sync_all() {
            Ok(()) => Ok(()),
            Err(e)
                if matches!(e.raw_os_error(), Some(22))
                    || matches!(e.kind(), std::io::ErrorKind::Unsupported) =>
            {
                Ok(())
            }
            Err(e) => Err(anyhow::Error::from(e))
                .with_context(|| format!("fsync directory {}", parent.display())),
        },
        Err(e) if matches!(e.kind(), std::io::ErrorKind::PermissionDenied) => Ok(()),
        Err(e) => Err(anyhow::Error::from(e))
            .with_context(|| format!("open directory {} for fsync", parent.display())),
    }
}

fn fsync_file(path: &Path) -> anyhow::Result<()> {
    let f = fs::File::open(path).with_context(|| format!("open {} for fsync", path.display()))?;
    f.sync_all()
        .with_context(|| format!("fsync file {}", path.display()))?;
    Ok(())
}

fn load_signing_key(path: &Path) -> anyhow::Result<SigningKey> {
    let bytes = fs::read(path).with_context(|| format!("read signing key {}", path.display()))?;
    let seed = decode_key_bytes(&bytes, ED25519_SEED_LEN, "signing-key")?;
    let mut arr = [0u8; ED25519_SEED_LEN];
    arr.copy_from_slice(&seed);
    Ok(SigningKey::from_bytes(&arr))
}

fn load_verifying_key(path: &Path) -> anyhow::Result<VerifyingKey> {
    let bytes = fs::read(path).with_context(|| format!("read verifying key {}", path.display()))?;
    let raw = decode_key_bytes(&bytes, ED25519_SEED_LEN, "verifying-key")?;
    let mut arr = [0u8; ED25519_SEED_LEN];
    arr.copy_from_slice(&raw);
    VerifyingKey::from_bytes(&arr).map_err(|e| anyhow!("verifying key: {e}"))
}

fn decode_key_bytes(bytes: &[u8], expect_len: usize, label: &str) -> anyhow::Result<Vec<u8>> {
    if bytes.len() == expect_len {
        return Ok(bytes.to_vec());
    }
    let trimmed: Vec<u8> = bytes
        .iter()
        .copied()
        .filter(|b| !matches!(*b, b' ' | b'\n' | b'\r' | b'\t'))
        .collect();
    if trimmed.len() == expect_len * 2 {
        let s = std::str::from_utf8(&trimmed)
            .map_err(|e| anyhow!("{label}: hex decode failed: {e}"))?;
        let raw = hex::decode(s).map_err(|e| anyhow!("{label}: hex decode failed: {e}"))?;
        if raw.len() == expect_len {
            return Ok(raw);
        }
    }
    bail!(
        "{label}: expected {} raw bytes or {}-char hex, got {} bytes",
        expect_len,
        expect_len * 2,
        bytes.len()
    )
}

fn sig_sidecar_path(tarball: &Path) -> PathBuf {
    let mut s = tarball.as_os_str().to_owned();
    s.push(".sig");
    PathBuf::from(s)
}

fn sha256_hex(bytes: &[u8]) -> String {
    bytes_to_hex(&Sha256::digest(bytes))
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
