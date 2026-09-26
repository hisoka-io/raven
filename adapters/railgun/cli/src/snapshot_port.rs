//! Operator snapshot export / import.
//!
//! Export captures every instance data_dir, `wal/current.log` included, recovers each capture
//! through the node's own recovery path, and records what it recovered to in
//! `EXPORT_MANIFEST.json`. The content hash covers that whole manifest and is what gets signed.
//! Import checks the signature and an operator-pinned content hash before any disk write,
//! recovers the staged copy the same way, and swaps it in only when both recoveries agree.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::imt::Imt;
use raven_railgun_engine::inspire::{InspireServerState, LogicalLeafStore};
use raven_railgun_engine::persistence::{
    wal_replay_skipped_instances, InspirePersistence, SnapshotPolicy,
};
use raven_railgun_engine::pir_table::{labels, EncoderKind, PirTableEncoder};
use raven_railgun_persistence::{
    atomic_write, decode_no_trailing, fsync_parent_dir, Manifest, PpoiEventMetadata, StoreLayout,
    Wal, WalEntryPayload, MANIFEST_SCHEMA_VERSION,
};
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
    #[error("signature sidecar kind {observed:?} != expected {expected:?}")]
    SignatureKindMismatch {
        observed: String,
        expected: &'static str,
    },
    #[error(
        "export is not the pinned one: --expect-content-hash is {expected} but the signed export \
         carries {found}. An older or different export was supplied; take the hash from the \
         export-snapshot output recorded for this deploy, never from the .sig sidecar"
    )]
    ExpectedContentHashMismatch { expected: String, found: String },
    #[error("--expect-content-hash {value:?} is not 64 hex characters")]
    ExpectedContentHashInvalid { value: String },
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
    #[error("export declares instance_count {declared} but lists {listed} instances")]
    InstanceCountMismatch { declared: u32, listed: usize },
    #[error("export instance id {id:?} is not a single path component")]
    InstanceIdInvalid { id: String },
    #[error(
        "destination root is not empty; pass --allow-overwrite to move what it holds to \
         <root>.pre-import.<ts>/"
    )]
    DestinationPopulated,
    #[error("parse tarball: {detail}")]
    TarballParse { detail: String },
    #[error(
        "instance {instance}: manifest.json changed while its files were being captured (a \
         commit ran during the export); re-run export-snapshot, or stop the node first"
    )]
    CaptureRaced { instance: String },
    #[error("instance {instance}: recovery through the node's open path failed: {detail}")]
    RecoveryFailed { instance: String, detail: String },
    #[error(
        "instance {instance}: WAL replay skipped entries it could not apply, or this process had \
         already recorded a skip for its instance id, so this data_dir is not proven to recover \
         to a contiguous state; repair or re-sync it before transplanting"
    )]
    ReplaySkipped { instance: String },
    #[error(
        "instance {instance}: the imported data recovers to a different state than the signed \
         export recorded ({detail}); the data_dir was not swapped in"
    )]
    RecoveredStateMismatch { instance: String, detail: String },
}

const EXPORT_MANIFEST_NAME: &str = "EXPORT_MANIFEST.json";
const EXPORT_SCHEMA_VERSION: u32 = 2;
const EXPORT_KIND: &str = "raven-railgun-export/v2";
const SIGNATURE_KIND: &str = "raven-railgun-export-sig/v2";
const IDENTITY_DOMAIN: &[u8] = b"raven-railgun-export-identity/v2\0";
const SIGNATURE_DOMAIN: &[u8] = b"raven-railgun-export-sig/v2\0";
const STORE_DIGEST_DOMAIN: &[u8] = b"raven-railgun-recovered-store/v1\0";
const SHARED_CRS_DIR: &str = "shared/crs/";
const INSTANCES_PREFIX: &str = "instances/";
const STAGING_PREFIX: &str = ".staging.";
const VERIFY_PREFIX: &str = ".verify.";
const BACKUP_PREFIX: &str = ".pre-import.";
const ED25519_SEED_LEN: usize = 32;
/// The engine re-marks an instance divergent on open while this file exists, so dropping it
/// would transplant an unrepaired tree as clean.
const LAYER2_DIVERGENT_MARKER: &str = "layer2-divergent";
/// A node refuses to boot an instance whose manifest exists without its session-handle floor,
/// since it could then reissue a handle a client still holds. The witness is the floor's own
/// regression check.
const SESSION_HANDLE_WITNESS: &str = "session-handle-issuance-v1.bin";
const SESSION_HANDLE_FLOOR: &str = "session-handle-floor-v1.bin";
const CONTENT_HASH_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct ExportOptions {
    pub data_dir: PathBuf,
    pub output: PathBuf,
    pub signing_key: Option<PathBuf>,
    /// Retain the N newest `*.tar.zst` tarballs beside `output`; `0` disables.
    pub keep_snapshots: usize,
}

/// Idempotent; touches only `*.tar.zst` files and paired `.sig` sidecars.
#[derive(Debug, Clone)]
pub struct PruneOptions {
    pub data_dir: PathBuf,
    pub keep_snapshots: usize,
}

#[derive(Debug, Clone)]
pub struct ImportOptions {
    pub input: PathBuf,
    pub data_dir: PathBuf,
    pub verifying_key: PathBuf,
    /// The content hash export-snapshot printed for the export this deploy means to install.
    pub expected_content_hash: String,
    pub allow_overwrite: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct ExportInstance {
    pub id: String,
    pub encoder_label: String,
    pub scheme_tag: String,
    pub shared_crs_hash: String,
    pub data_size_bytes: u64,
    pub content_hash_hex: String,
    pub files: Vec<ExportFile>,
    pub recovered: RecoveredState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportFile {
    pub rel_path: String,
    pub byte_len: u64,
    pub sha256_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct DetachedSignature {
    pub kind: String,
    pub signature_hex: String,
    pub content_hash_hex: String,
    pub public_key_hex: String,
}

/// What one instance's files recover to through [`InspirePersistence::open`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredState {
    pub leaf_count: u64,
    pub ppoi_row_count: u64,
    pub last_block_height: u64,
    pub trees: Vec<RecoveredTree>,
    pub lists: Vec<RecoveredList>,
    /// Every leaf-store field except dirty-shard bookkeeping, in canonical order.
    pub store_sha256: String,
    /// The decoded PIR table; `None` when the manifest names no snapshot.
    pub encoded_db_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredTree {
    pub tree_number: u32,
    pub leaf_count: u64,
    pub root_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredList {
    pub list_key_hex: String,
    pub leaf_count: u64,
    pub root_hex: String,
}

#[derive(Clone, Debug)]
pub struct ExportReceipt {
    pub output: PathBuf,
    pub content_hash_hex: String,
    pub exported_at_unix_ms: u64,
    pub public_key_hex: Option<String>,
    pub instances: Vec<(String, RecoveredState)>,
}

#[derive(Clone, Debug)]
pub struct ImportReceipt {
    pub data_dir: PathBuf,
    pub content_hash_hex: String,
    pub exported_at_unix_ms: u64,
    pub instances: Vec<(String, RecoveredState)>,
}

impl fmt::Display for RecoveredState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "leaves={} ppoi_rows={} last_block={} store_sha256={}",
            self.leaf_count, self.ppoi_row_count, self.last_block_height, self.store_sha256
        )?;
        for t in &self.trees {
            write!(
                f,
                "\n    tree {}: leaves={} root={}",
                t.tree_number, t.leaf_count, t.root_hex
            )?;
        }
        for l in &self.lists {
            write!(
                f,
                "\n    list {}: leaves={} root={}",
                l.list_key_hex, l.leaf_count, l.root_hex
            )?;
        }
        Ok(())
    }
}

impl fmt::Display for ExportReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "exported {} instance(s) to {}",
            self.instances.len(),
            self.output.display()
        )?;
        writeln!(f, "content_hash_hex = {}", self.content_hash_hex)?;
        writeln!(f, "exported_at_unix_ms = {}", self.exported_at_unix_ms)?;
        match &self.public_key_hex {
            Some(pk) => writeln!(f, "public_key_hex = {pk}")?,
            None => writeln!(
                f,
                "unsigned: import-snapshot refuses a tarball without a .sig sidecar"
            )?,
        }
        for (id, state) in &self.instances {
            writeln!(f, "  instance {id}: {state}")?;
        }
        write!(
            f,
            "record content_hash_hex in the deploy record; import-snapshot requires it as \
             --expect-content-hash"
        )
    }
}

impl fmt::Display for ImportReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "imported {} instance(s) into {}",
            self.instances.len(),
            self.data_dir.display()
        )?;
        writeln!(f, "content_hash_hex = {}", self.content_hash_hex)?;
        write!(f, "exported_at_unix_ms = {}", self.exported_at_unix_ms)?;
        for (id, state) in &self.instances {
            write!(f, "\n  instance {id}: {state}")?;
        }
        Ok(())
    }
}

/// Canonical content hash of `manifest`: every field except `content_hash_hex` itself.
pub fn export_content_hash(manifest: &ExportManifest) -> anyhow::Result<String> {
    #[derive(Serialize)]
    struct Identity<'a> {
        schema_version: u32,
        kind: &'a str,
        exported_at_unix_ms: u64,
        instance_count: u32,
        persistence_manifest_version: u32,
        instances: &'a [ExportInstance],
        shared_crs: &'a [SharedCrsRef],
    }
    let body = bincode::serialize(&Identity {
        schema_version: manifest.schema_version,
        kind: &manifest.kind,
        exported_at_unix_ms: manifest.exported_at_unix_ms,
        instance_count: manifest.instance_count,
        persistence_manifest_version: manifest.persistence_manifest_version,
        instances: &manifest.instances,
        shared_crs: &manifest.shared_crs,
    })
    .context("encode export identity")?;
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_DOMAIN);
    hasher.update(&body);
    Ok(bytes_to_hex(&hasher.finalize()))
}

/// Per-instance hash over its file list, as recorded in [`ExportInstance::content_hash_hex`].
pub fn instance_files_hash(files: &[ExportFile]) -> String {
    let mut hasher = Sha256::new();
    for f in files {
        hasher.update(f.rel_path.as_bytes());
        hasher.update(b":");
        hasher.update(f.sha256_hex.as_bytes());
        hasher.update(b"\n");
    }
    bytes_to_hex(&hasher.finalize())
}

/// Bytes an export signature covers for `content_hash_hex`.
pub fn signature_message(content_hash_hex: &str) -> Result<Vec<u8>, SnapshotPortError> {
    let raw = hex::decode(content_hash_hex)
        .ok()
        .filter(|raw| raw.len() == CONTENT_HASH_LEN)
        .ok_or_else(|| SnapshotPortError::SignatureVerificationFailed {
            detail: format!("content_hash_hex {content_hash_hex:?} is not a 32-byte hex digest"),
        })?;
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + raw.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&raw);
    Ok(message)
}

#[allow(clippy::too_many_lines)]
pub fn run_export(opts: ExportOptions) -> anyhow::Result<ExportReceipt> {
    // Before any recovery runs or anything is published: a bad key costs nothing.
    let signing_key = opts
        .signing_key
        .as_deref()
        .map(load_signing_key)
        .transpose()?;
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

    let exported_at = now_unix_ms();
    let mut tarball = TarballWriter::create(&opts.output)?;
    let scratch = ScratchDir::new(sibling_with_suffix(
        &opts.output,
        &format!("{VERIFY_PREFIX}{}.{exported_at}", std::process::id()),
    )?)?;
    let mut shared_crs_table: BTreeMap<String, (SharedCrsBlob, Vec<u8>, String)> = BTreeMap::new();
    let mut export_instances: Vec<ExportInstance> = Vec::with_capacity(instances.len());
    // One instance at a time, one file at a time: the export runs beside a serving node.
    for entry in &instances {
        let copy = ScratchDir::new(scratch.path().join(&entry.id))?;
        let capture = capture_instance(entry, &mut |rel, bytes| {
            tarball.append(&format!("{INSTANCES_PREFIX}{}/{rel}", entry.id), bytes)?;
            stage_file(copy.path(), rel, bytes)
        })
        .with_context(|| format!("capture instance at {}", entry.dir.display()))?;
        let recovered = recover_dir(&capture.id, copy.path())?;
        drop(copy);

        let blob = SharedCrsBlob {
            kind: "raven-railgun-shared-crs/v1".to_owned(),
            scheme_tag: capture.manifest.scheme_tag.clone(),
            persistence_manifest_version: capture.manifest.schema_version,
        };
        let bytes = serde_json::to_vec(&blob).context("serialize shared CRS blob")?;
        let scheme_hash = sha256_hex(&bytes);
        let rel = format!("{SHARED_CRS_DIR}{scheme_hash}.json");
        shared_crs_table
            .entry(scheme_hash.clone())
            .or_insert((blob, bytes, rel));

        export_instances.push(ExportInstance {
            id: capture.id,
            encoder_label: capture.manifest.encoder_label,
            scheme_tag: capture.manifest.scheme_tag,
            shared_crs_hash: scheme_hash,
            data_size_bytes: capture
                .files
                .iter()
                .fold(0u64, |acc, f| acc.saturating_add(f.byte_len)),
            content_hash_hex: instance_files_hash(&capture.files),
            files: capture.files,
            recovered,
        });
    }
    drop(scratch);

    let mut shared_crs_entries: Vec<SharedCrsRef> = shared_crs_table
        .iter()
        .map(|(hash, (blob, bytes, rel))| SharedCrsRef {
            hash: hash.clone(),
            rel_path: rel.clone(),
            byte_len: byte_len(bytes),
            scheme_tag: blob.scheme_tag.clone(),
        })
        .collect();
    shared_crs_entries.sort_by(|a, b| a.hash.cmp(&b.hash));

    let mut manifest = ExportManifest {
        schema_version: EXPORT_SCHEMA_VERSION,
        kind: EXPORT_KIND.to_owned(),
        exported_at_unix_ms: exported_at,
        instance_count: u32::try_from(export_instances.len()).unwrap_or(u32::MAX),
        persistence_manifest_version: MANIFEST_SCHEMA_VERSION,
        instances: export_instances,
        shared_crs: shared_crs_entries,
        content_hash_hex: String::new(),
    };
    manifest.content_hash_hex = export_content_hash(&manifest)?;

    for (_, bytes, rel) in shared_crs_table.values() {
        tarball.append(rel, bytes)?;
    }
    // Last, since it records what every instance recovered to.
    tarball.append(
        EXPORT_MANIFEST_NAME,
        &serde_json::to_vec_pretty(&manifest).context("serialize export manifest")?,
    )?;
    tarball.finish(&opts.output)?;
    // A sidecar already at this name signed the tarball just replaced.
    let sig_path = sig_sidecar_path(&opts.output);
    match fs::remove_file(&sig_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(anyhow::Error::new(e)
                .context(format!("remove stale signature {}", sig_path.display())));
        }
    }
    if let Some(parent) = opts.output.parent() {
        if !parent.as_os_str().is_empty() {
            fsync_parent_dir(parent)
                .with_context(|| format!("fsync export directory {}", parent.display()))?;
        }
    }

    let mut public_key_hex = None;
    if let Some(signing_key) = signing_key.as_ref() {
        let signature = signing_key.sign(&signature_message(&manifest.content_hash_hex)?);
        let public = hex::encode(signing_key.verifying_key().to_bytes());
        let detached = DetachedSignature {
            kind: SIGNATURE_KIND.to_owned(),
            signature_hex: hex::encode(signature.to_bytes()),
            content_hash_hex: manifest.content_hash_hex.clone(),
            public_key_hex: public.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&detached)?;
        atomic_write(&sig_path, &bytes)
            .with_context(|| format!("write signature sidecar {}", sig_path.display()))?;
        fsync_file(&sig_path)?;
        if let Some(parent) = sig_path.parent() {
            if !parent.as_os_str().is_empty() {
                fsync_parent_dir(parent)
                    .with_context(|| format!("fsync signature directory {}", parent.display()))?;
            }
        }
        public_key_hex = Some(public);
    }

    // Best-effort: a prune failure must not fail the export itself.
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

    Ok(ExportReceipt {
        output: opts.output,
        content_hash_hex: manifest.content_hash_hex,
        exported_at_unix_ms: manifest.exported_at_unix_ms,
        public_key_hex,
        instances: manifest
            .instances
            .into_iter()
            .map(|i| (i.id, i.recovered))
            .collect(),
    })
}

/// Keep the `keep_last_n` newest `*.tar.zst` by mtime plus their `.sig` sidecars;
/// returns tarballs removed. Per-entry failures are warn-logged, not fatal.
pub fn prune_old_export_tarballs(
    snapshots_dir: &Path,
    keep_last_n: usize,
) -> anyhow::Result<usize> {
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
    // newest-first; filename tie-break for determinism.
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

/// Standalone prune entry point; idempotent.
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
pub fn run_import(opts: ImportOptions) -> anyhow::Result<ImportReceipt> {
    let expected = normalise_expected_hash(&opts.expected_content_hash)?;
    let public = load_verifying_key(&opts.verifying_key)?;
    let sig_path = sig_sidecar_path(&opts.input);
    let sig_bytes = fs::read(&sig_path)
        .with_context(|| format!("open signature sidecar {}", sig_path.display()))?;
    let detached: DetachedSignature = serde_json::from_slice(&sig_bytes).map_err(|e| {
        anyhow::Error::new(SnapshotPortError::SignatureVerificationFailed {
            detail: format!(
                "signature sidecar {} does not parse: {e}",
                sig_path.display()
            ),
        })
    })?;
    if detached.kind != SIGNATURE_KIND {
        return Err(anyhow::Error::new(
            SnapshotPortError::SignatureKindMismatch {
                observed: detached.kind.clone(),
                expected: SIGNATURE_KIND,
            },
        ));
    }
    let sig_raw = hex::decode(&detached.signature_hex).map_err(|e| {
        anyhow::Error::new(SnapshotPortError::SignatureVerificationFailed {
            detail: format!("signature_hex is not hex: {e}"),
        })
    })?;
    let sig_arr: [u8; Signature::BYTE_SIZE] = sig_raw.as_slice().try_into().map_err(|_| {
        anyhow::Error::new(SnapshotPortError::SignatureLengthInvalid {
            actual: sig_raw.len(),
            expected: Signature::BYTE_SIZE,
        })
    })?;
    public
        .verify(
            &signature_message(&detached.content_hash_hex)?,
            &Signature::from_bytes(&sig_arr),
        )
        .map_err(|e| {
            anyhow::Error::new(SnapshotPortError::SignatureVerificationFailed {
                detail: e.to_string(),
            })
        })?;
    if hex::decode(&detached.public_key_hex).ok().as_deref() != Some(public.as_bytes().as_slice()) {
        return Err(anyhow::Error::new(
            SnapshotPortError::SignaturePublicKeyMismatch,
        ));
    }
    let signed_hash = detached.content_hash_hex;
    // A genuine older export verifies; only the operator's pin names the current one.
    if signed_hash != expected {
        return Err(anyhow::Error::new(
            SnapshotPortError::ExpectedContentHashMismatch {
                expected,
                found: signed_hash,
            },
        ));
    }

    let raw = fs::read(&opts.input)
        .with_context(|| format!("open input tarball {}", opts.input.display()))?;
    let mut parsed = parse_tarball(&raw).map_err(|e| {
        anyhow::Error::new(SnapshotPortError::TarballParse {
            detail: format!("{e:#}"),
        })
    })?;
    drop(raw);
    let manifest = &parsed.manifest;

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
    if manifest.content_hash_hex != export_content_hash(manifest)? {
        return Err(anyhow::Error::new(SnapshotPortError::ContentHashMismatch));
    }
    if manifest.content_hash_hex != signed_hash {
        return Err(anyhow::Error::new(
            SnapshotPortError::SignatureContentHashMismatch,
        ));
    }
    if usize::try_from(manifest.instance_count).ok() != Some(manifest.instances.len()) {
        return Err(anyhow::Error::new(
            SnapshotPortError::InstanceCountMismatch {
                declared: manifest.instance_count,
                listed: manifest.instances.len(),
            },
        ));
    }
    for inst in &manifest.instances {
        validate_instance_id(&inst.id)?;
    }

    verify_payload_checksums(&parsed)?;

    let dest_root = opts.data_dir.clone();
    let dest_occupied = root_is_occupied(&dest_root)?;
    if dest_occupied && !opts.allow_overwrite {
        return Err(anyhow::Error::new(SnapshotPortError::DestinationPopulated))
            .with_context(|| format!("destination root {} is not empty", dest_root.display()));
    }

    let ts = now_unix_ms();
    let staging = ScratchDir::new(sibling_with_suffix(
        &dest_root,
        &format!("{STAGING_PREFIX}{ts}"),
    )?)?;
    extract_instances(&parsed, staging.path())?;
    // Staged on disk now; recovery below needs that memory for the PIR table.
    parsed.files.clear();

    let mut recovered: Vec<(String, RecoveredState)> = Vec::with_capacity(manifest.instances.len());
    for inst in &manifest.instances {
        let dir = staging.path().join(&inst.id);
        check_staged_labels(inst, &dir)?;
        let state = recover_dir(&inst.id, &dir)?;
        if let Some(detail) = describe_state_difference(&inst.recovered, &state) {
            return Err(anyhow::Error::new(
                SnapshotPortError::RecoveredStateMismatch {
                    instance: inst.id.clone(),
                    detail,
                },
            ));
        }
        recovered.push((inst.id.clone(), state));
    }

    let backup = if dest_occupied {
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
                fsync_parent_dir(parent)
                    .with_context(|| format!("fsync backup directory {}", parent.display()))?;
            }
        }
        Some(path)
    } else if dest_root.exists() {
        fs::remove_dir(&dest_root)
            .with_context(|| format!("remove empty destination {}", dest_root.display()))?;
        None
    } else {
        None
    };

    if let Err(e) = fs::rename(staging.path(), &dest_root) {
        if let Some(b) = backup.as_ref() {
            let _ = fs::rename(b, &dest_root);
        }
        return Err(anyhow!(
            "atomic rename {} -> {} failed: {e}",
            staging.path().display(),
            dest_root.display()
        ));
    }
    if let Some(parent) = dest_root.parent() {
        if !parent.as_os_str().is_empty() {
            fsync_parent_dir(parent)
                .with_context(|| format!("fsync import directory {}", parent.display()))?;
        }
    }

    Ok(ImportReceipt {
        data_dir: dest_root,
        content_hash_hex: manifest.content_hash_hex.clone(),
        exported_at_unix_ms: manifest.exported_at_unix_ms,
        instances: recovered,
    })
}

fn normalise_expected_hash(value: &str) -> anyhow::Result<String> {
    let trimmed = value.trim();
    let bare = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if bare.len() != CONTENT_HASH_LEN * 2 || !bare.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow::Error::new(
            SnapshotPortError::ExpectedContentHashInvalid {
                value: value.to_owned(),
            },
        ));
    }
    Ok(bare.to_ascii_lowercase())
}

fn validate_instance_id(id: &str) -> anyhow::Result<()> {
    let mut components = Path::new(id).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err(anyhow::Error::new(SnapshotPortError::InstanceIdInvalid {
            id: id.to_owned(),
        })),
    }
}

fn check_staged_labels(inst: &ExportInstance, dir: &Path) -> anyhow::Result<()> {
    let manifest = Manifest::load(&StoreLayout::inspect(dir))
        .map_err(|e| anyhow!("post-import: read staged manifest for {}: {e}", inst.id))?
        .ok_or_else(|| anyhow!("post-import: instance {} has no manifest.json", inst.id))?;
    if manifest.encoder_label != inst.encoder_label {
        bail!(
            "post-import sanity: instance {} encoder_label {:?} != export entry {:?}",
            inst.id,
            manifest.encoder_label,
            inst.encoder_label
        );
    }
    if manifest.scheme_tag != inst.scheme_tag {
        bail!(
            "post-import sanity: instance {} scheme_tag {:?} != export entry {:?}",
            inst.id,
            manifest.scheme_tag,
            inst.scheme_tag
        );
    }
    Ok(())
}

fn describe_state_difference(
    recorded: &RecoveredState,
    recovered: &RecoveredState,
) -> Option<String> {
    if recorded == recovered {
        return None;
    }
    let field = |name: &str, a: &dyn fmt::Debug, b: &dyn fmt::Debug| {
        format!("{name}: recorded {a:?}, recovered {b:?}")
    };
    Some(if recorded.leaf_count != recovered.leaf_count {
        field("leaf_count", &recorded.leaf_count, &recovered.leaf_count)
    } else if recorded.ppoi_row_count != recovered.ppoi_row_count {
        field(
            "ppoi_row_count",
            &recorded.ppoi_row_count,
            &recovered.ppoi_row_count,
        )
    } else if recorded.lists != recovered.lists {
        field("lists", &recorded.lists, &recovered.lists)
    } else if recorded.trees != recovered.trees {
        field("trees", &recorded.trees, &recovered.trees)
    } else if recorded.last_block_height != recovered.last_block_height {
        field(
            "last_block_height",
            &recorded.last_block_height,
            &recovered.last_block_height,
        )
    } else if recorded.encoded_db_sha256 != recovered.encoded_db_sha256 {
        field(
            "encoded_db_sha256",
            &recorded.encoded_db_sha256,
            &recovered.encoded_db_sha256,
        )
    } else {
        field(
            "store_sha256",
            &recorded.store_sha256,
            &recovered.store_sha256,
        )
    })
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
    if StoreLayout::inspect(root).manifest_path().is_file() {
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
        if !StoreLayout::inspect(&path).manifest_path().is_file() {
            continue;
        }
        let id = entry
            .file_name()
            .into_string()
            .map_err(|os| anyhow!("non-UTF-8 instance dir name: {}", os.display()))?;
        if !seen.insert(id.clone()) {
            bail!("duplicate instance id: {id}");
        }
        out.push(DiscoveredInstance { id, dir: path });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

#[derive(Debug)]
struct CapturedInstance {
    id: String,
    manifest: Manifest,
    files: Vec<ExportFile>,
}

/// Each file is read once and handed to `emit` as read, so the tarball carries exactly the bytes
/// that were hashed and recovered, and no more than one file is held at a time.
fn capture_instance(
    entry: &DiscoveredInstance,
    emit: &mut dyn FnMut(&str, &[u8]) -> anyhow::Result<()>,
) -> anyhow::Result<CapturedInstance> {
    let layout = StoreLayout::inspect(&entry.dir);
    let mut files: Vec<ExportFile> = Vec::new();
    let manifest_bytes = capture_file(&mut files, entry, layout.manifest_path(), emit)?;
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

    for path in [
        layout.snapshot_header_path(manifest.current_snapshot_id),
        layout.snapshot_data_path(manifest.current_snapshot_id),
        layout.wal_current_path(),
        entry.dir.join(LAYER2_DIVERGENT_MARKER),
        // The floor is rewritten before the witness, so reading the witness first can never pair
        // a newer witness with an older floor.
        entry.dir.join(SESSION_HANDLE_WITNESS),
        entry.dir.join(SESSION_HANDLE_FLOOR),
    ] {
        if path.is_file() {
            capture_file(&mut files, entry, path, emit)?;
        }
    }

    let archived_dir = layout.archived_wals_dir();
    if archived_dir.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(&archived_dir)?
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().is_file())
            .collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for e in entries {
            capture_file(&mut files, entry, e.path(), emit)?;
        }
    }

    // A commit rewrites manifest.json before it archives the log, so an unchanged manifest
    // means every file above belongs to one generation.
    let after = fs::read(layout.manifest_path())
        .with_context(|| format!("re-read manifest for {}", entry.id))?;
    if after != manifest_bytes {
        return Err(anyhow::Error::new(SnapshotPortError::CaptureRaced {
            instance: entry.id.clone(),
        }));
    }

    files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    Ok(CapturedInstance {
        id: entry.id.clone(),
        manifest,
        files,
    })
}

fn capture_file(
    out: &mut Vec<ExportFile>,
    entry: &DiscoveredInstance,
    abs: PathBuf,
    emit: &mut dyn FnMut(&str, &[u8]) -> anyhow::Result<()>,
) -> anyhow::Result<Vec<u8>> {
    let relative = abs.strip_prefix(&entry.dir).map_err(|error| {
        anyhow!(
            "planned path {} escapes instance {}: {error}",
            abs.display(),
            entry.id
        )
    })?;
    let rel = relative
        .components()
        .map(|component| component.as_os_str().to_str())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| anyhow!("non-UTF-8 planned path: {}", abs.display()))?
        .join("/");
    let bytes =
        fs::read(&abs).with_context(|| format!("read planned file {} for {}", rel, entry.id))?;
    emit(&rel, &bytes)?;
    out.push(ExportFile {
        byte_len: byte_len(&bytes),
        sha256_hex: sha256_hex(&bytes),
        rel_path: rel,
    });
    Ok(bytes)
}

fn stage_file(dir: &Path, rel: &str, bytes: &[u8]) -> anyhow::Result<()> {
    let dst = dir.join(rel);
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&dst, bytes).with_context(|| format!("stage {} for recovery", dst.display()))
}

/// Recover `dir` exactly as a booting node does, then summarise what it served.
fn recover_dir(id: &str, dir: &Path) -> anyhow::Result<RecoveredState> {
    let failed = |detail: String| {
        anyhow::Error::new(SnapshotPortError::RecoveryFailed {
            instance: id.to_owned(),
            detail,
        })
    };
    let layout = StoreLayout::open(dir).map_err(|e| failed(format!("layout: {e}")))?;
    let manifest = Manifest::load(&layout)
        .map_err(|e| failed(format!("manifest: {e}")))?
        .ok_or_else(|| failed("manifest.json missing".to_owned()))?;
    let encoder = recovery_encoder(&layout, &manifest).map_err(|e| failed(format!("{e:#}")))?;
    let opened = InspirePersistence::open(
        layout,
        manifest.scheme_tag.clone(),
        InstanceId::new(manifest.instance_id.clone()),
        SnapshotPolicy::static_default(),
        encoder,
    )
    .map_err(|e| failed(e.to_string()))?;
    // The skip record is per process and never cleared on this path, so a mark it already held
    // counts against this replay too: that mark could be hiding one this replay added.
    if replay_skipped(&manifest.instance_id) {
        return Err(anyhow::Error::new(SnapshotPortError::ReplaySkipped {
            instance: id.to_owned(),
        }));
    }
    summarise(
        &opened.recovered_logical_store,
        opened.recovered_state.as_ref(),
    )
    .map_err(|e| failed(format!("{e:#}")))
}

fn replay_skipped(instance_id: &str) -> bool {
    wal_replay_skipped_instances()
        .iter()
        .any(|id| id == instance_id)
}

/// The manifest records only the encoder's label. Its tree or list pin is config, and it
/// decides dirty-shard bookkeeping alone, which [`RecoveredState`] leaves out. Pinning to what
/// the replayed log carries keeps a correct replay from logging a foreign-list warning per row.
fn recovery_encoder(
    layout: &StoreLayout,
    manifest: &Manifest,
) -> anyhow::Result<Arc<dyn PirTableEncoder>> {
    let (tree_number, list_key) = replayed_pin(layout, manifest)?;
    let kind = match manifest.encoder_label.as_str() {
        labels::PER_LEAF_BC => EncoderKind::PerLeafBc { tree_number },
        labels::PER_LEAF_PATH => EncoderKind::PerLeafPath { tree_number },
        labels::PER_NODE => EncoderKind::PerNode { tree_number },
        labels::PER_LIST_STATUS => EncoderKind::PerListStatus { list_key },
        labels::PER_LIST_PATH => EncoderKind::PerListPath { list_key },
        labels::PER_LIST_PATH10 => EncoderKind::PerListPath10 { list_key },
        labels::PER_LIST_NODE => EncoderKind::PerListNode { list_key },
        other => bail!("unknown encoder_label {other:?}"),
    };
    let shape = manifest
        .require_shape()
        .map_err(|e| anyhow!("manifest cell shape: {e}"))?;
    let rows = u32::try_from(shape.rows_per_shard)
        .map_err(|_| anyhow!("rows_per_shard {} exceeds u32", shape.rows_per_shard))?;
    kind.build(shape.entry_size_bytes, rows)
        .map_err(|e| anyhow!("build {} encoder: {e}", manifest.encoder_label))
}

fn replayed_pin(layout: &StoreLayout, manifest: &Manifest) -> anyhow::Result<(u32, [u8; 32])> {
    let floor = manifest.current_snapshot_seq;
    let wal = Wal::open(layout, floor.checked_sub(1)).map_err(|e| anyhow!("wal open: {e}"))?;
    let replay = wal.replay().map_err(|e| anyhow!("wal scan: {e}"))?;
    let (mut tree, mut list) = (None, None);
    for entry in replay.entries.iter().filter(|e| e.seq >= floor) {
        match decode_no_trailing::<WalEntryPayload>(&entry.payload) {
            Ok(WalEntryPayload::AppendLeaf { tree_number, .. }) => {
                tree.get_or_insert(tree_number);
            }
            Ok(
                WalEntryPayload::PpoiListLeafAdded { list_key, .. }
                | WalEntryPayload::PpoiStatus { list_key, .. },
            ) => {
                list.get_or_insert(list_key);
            }
            _ => {}
        }
        if tree.is_some() && list.is_some() {
            break;
        }
    }
    Ok((tree.unwrap_or(0), list.unwrap_or([0; 32])))
}

/// `LogicalLeafStore`'s serde shape, which V7 snapshots also carry, with its two hash maps read
/// as ordered pairs: bincode writes a map and a sequence of pairs identically.
#[derive(Deserialize)]
struct StoreWire {
    leaves: BTreeMap<(u32, u32), [u8; 32]>,
    ppoi_status: BTreeMap<([u8; 32], [u8; 32]), u8>,
    _dirty_shards: BTreeSet<u32>,
    last_block_height: u64,
    leaf_block_height: BTreeMap<(u32, u32), u64>,
    ppoi_block_height: BTreeMap<([u8; 32], [u8; 32]), u64>,
    imts: Vec<(u32, Imt)>,
    ppoi_imts: Vec<([u8; 32], Imt)>,
    ppoi_bc_indices: BTreeSet<([u8; 32], [u8; 32], u32)>,
    ppoi_index_bc: BTreeMap<([u8; 32], u32), [u8; 32]>,
    ppoi_event_metadata: BTreeMap<([u8; 32], u32), PpoiEventMetadata>,
    ppoi_list_leaf_block_height: BTreeMap<([u8; 32], u32), u64>,
}

fn summarise(
    store: &LogicalLeafStore,
    state: Option<&InspireServerState>,
) -> anyhow::Result<RecoveredState> {
    #[derive(Serialize)]
    struct Canonical<'a> {
        leaves: &'a BTreeMap<(u32, u32), [u8; 32]>,
        ppoi_status: &'a BTreeMap<([u8; 32], [u8; 32]), u8>,
        last_block_height: u64,
        leaf_block_height: &'a BTreeMap<(u32, u32), u64>,
        ppoi_block_height: &'a BTreeMap<([u8; 32], [u8; 32]), u64>,
        trees: &'a [RecoveredTree],
        lists: &'a [RecoveredList],
        ppoi_bc_indices: &'a BTreeSet<([u8; 32], [u8; 32], u32)>,
        ppoi_index_bc: &'a BTreeMap<([u8; 32], u32), [u8; 32]>,
        ppoi_event_metadata: &'a BTreeMap<([u8; 32], u32), PpoiEventMetadata>,
        ppoi_list_leaf_block_height: &'a BTreeMap<([u8; 32], u32), u64>,
    }

    let wire_bytes = bincode::serialize(store).context("encode recovered leaf store")?;
    let wire: StoreWire = decode_no_trailing(&wire_bytes).map_err(|e| {
        anyhow!(
            "read recovered leaf store: {e}; this build's LogicalLeafStore no longer has the \
             shape the export digest reads"
        )
    })?;
    let mut trees: Vec<RecoveredTree> = wire
        .imts
        .iter()
        .map(|(tree_number, imt)| RecoveredTree {
            tree_number: *tree_number,
            leaf_count: u64::try_from(imt.leaf_count()).unwrap_or(u64::MAX),
            root_hex: hex::encode(imt.root()),
        })
        .collect();
    trees.sort_by_key(|t| t.tree_number);
    let mut lists: Vec<RecoveredList> = wire
        .ppoi_imts
        .iter()
        .map(|(key, imt)| RecoveredList {
            list_key_hex: hex::encode(key),
            leaf_count: u64::try_from(imt.leaf_count()).unwrap_or(u64::MAX),
            root_hex: hex::encode(imt.root()),
        })
        .collect();
    lists.sort_by(|a, b| a.list_key_hex.cmp(&b.list_key_hex));

    let canonical = bincode::serialize(&Canonical {
        leaves: &wire.leaves,
        ppoi_status: &wire.ppoi_status,
        last_block_height: wire.last_block_height,
        leaf_block_height: &wire.leaf_block_height,
        ppoi_block_height: &wire.ppoi_block_height,
        trees: &trees,
        lists: &lists,
        ppoi_bc_indices: &wire.ppoi_bc_indices,
        ppoi_index_bc: &wire.ppoi_index_bc,
        ppoi_event_metadata: &wire.ppoi_event_metadata,
        ppoi_list_leaf_block_height: &wire.ppoi_list_leaf_block_height,
    })
    .context("encode canonical leaf store")?;
    let mut hasher = Sha256::new();
    hasher.update(STORE_DIGEST_DOMAIN);
    hasher.update(&canonical);

    let encoded_db_sha256 = match state {
        Some(state) => {
            let mut db_hasher = HashWriter(Sha256::new());
            bincode::serialize_into(&mut db_hasher, &*state.encoded_db)
                .context("digest recovered PIR table")?;
            Some(bytes_to_hex(&db_hasher.0.finalize()))
        }
        None => None,
    };

    Ok(RecoveredState {
        leaf_count: u64::try_from(store.leaf_count()).unwrap_or(u64::MAX),
        ppoi_row_count: u64::try_from(store.ppoi_count()).unwrap_or(u64::MAX),
        last_block_height: store.last_block_height(),
        trees,
        lists,
        store_sha256: bytes_to_hex(&hasher.finalize()),
        encoded_db_sha256,
    })
}

struct HashWriter(Sha256);

impl Write for HashWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Removed on drop; a successful import renames it away first, which makes the drop a no-op.
#[derive(Debug)]
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(path: PathBuf) -> anyhow::Result<Self> {
        if path.exists() {
            fs::remove_dir_all(&path)
                .with_context(|| format!("clear stale scratch {}", path.display()))?;
        }
        fs::create_dir_all(&path).with_context(|| format!("create scratch {}", path.display()))?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Written beside `output` and renamed onto it by [`TarballWriter::finish`]; removed if dropped
/// before then, so a refused export leaves no partial archive behind.
struct TarballWriter {
    tmp: PathBuf,
    builder: Option<tar::Builder<zstd::stream::write::Encoder<'static, fs::File>>>,
    armed: bool,
}

impl TarballWriter {
    fn create(output: &Path) -> anyhow::Result<Self> {
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
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        let encoder = zstd::stream::write::Encoder::new(raw, 3).context("init zstd encoder")?;
        let mut builder = tar::Builder::new(encoder);
        builder.mode(tar::HeaderMode::Deterministic);
        Ok(Self {
            tmp,
            builder: Some(builder),
            armed: true,
        })
    }

    fn append(&mut self, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
        let builder = self
            .builder
            .as_mut()
            .ok_or_else(|| anyhow!("tarball {} already sealed", self.tmp.display()))?;
        append_bytes(builder, name, bytes)
    }

    fn finish(mut self, output: &Path) -> anyhow::Result<()> {
        let builder = self
            .builder
            .take()
            .ok_or_else(|| anyhow!("tarball {} already sealed", self.tmp.display()))?;
        let encoder = builder.into_inner().context("seal tar stream")?;
        let file = encoder.finish().context("seal zstd stream")?;
        file.sync_all()
            .with_context(|| format!("fsync {}", self.tmp.display()))?;
        drop(file);
        fs::rename(&self.tmp, output)
            .with_context(|| format!("publish {} -> {}", self.tmp.display(), output.display()))?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for TarballWriter {
    fn drop(&mut self) {
        if self.armed {
            drop(self.builder.take());
            let _ = fs::remove_file(&self.tmp);
        }
    }
}

fn append_bytes<W: Write>(
    builder: &mut tar::Builder<W>,
    name: &str,
    bytes: &[u8],
) -> anyhow::Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_path(name)?;
    header.set_size(byte_len(bytes));
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
        if byte_len(bytes) != shared.byte_len {
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

    for inst in &parsed.manifest.instances {
        let mut total: u64 = 0;
        for f in &inst.files {
            let key = format!("{INSTANCES_PREFIX}{}/{}", inst.id, f.rel_path);
            let bytes = parsed.files.get(&key).ok_or_else(|| {
                anyhow::Error::new(SnapshotPortError::ChecksumMismatch {
                    detail: format!("tarball missing instance file {key}"),
                })
            })?;
            if byte_len(bytes) != f.byte_len {
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
        let local_hash = instance_files_hash(&inst.files);
        if local_hash != inst.content_hash_hex {
            return Err(anyhow::Error::new(SnapshotPortError::ChecksumMismatch {
                detail: format!(
                    "instance {}: per-instance content_hash_hex mismatch ({} != {})",
                    inst.id, local_hash, inst.content_hash_hex
                ),
            }));
        }
    }
    Ok(())
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
            atomic_write(&dst, bytes)
                .with_context(|| format!("extract tarball entry {key} to {}", dst.display()))?;
        }
        let layout = StoreLayout::inspect(&inst_root);
        let snap_dir = layout.snapshots_dir();
        if !snap_dir.is_dir() {
            fs::create_dir_all(&snap_dir)?;
        }
        let wal_archived = layout.archived_wals_dir();
        if !wal_archived.is_dir() {
            fs::create_dir_all(&wal_archived)?;
        }
    }
    Ok(())
}

/// Whatever a root holds may be the operator's, not an instance, so it is moved aside and never
/// deleted.
fn root_is_occupied(root: &Path) -> anyhow::Result<bool> {
    if !root.exists() {
        return Ok(false);
    }
    if !root.is_dir() {
        bail!(
            "destination data_dir {} exists and is not a directory",
            root.display()
        );
    }
    Ok(fs::read_dir(root)?.next().is_some())
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

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn byte_len(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use raven_railgun_engine::inspire::apply_wal_entry;
    use raven_railgun_persistence::PpoiEventType;

    const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-cache-session";
    const RECORD_SIZE: usize = 256;
    const LIST: [u8; 32] = [0x0c; 32];

    fn row(list_index: u32) -> WalEntryPayload {
        let mut blinded_commitment = [0u8; 32];
        blinded_commitment[28..].copy_from_slice(&(list_index + 1).to_be_bytes());
        WalEntryPayload::PpoiListLeafAdded {
            list_key: LIST,
            list_index,
            blinded_commitment,
            status: 1,
            event_type: PpoiEventType::Shield,
            signature: vec![0; 64],
            validated_merkleroot: [0; 32],
        }
    }

    /// A commit landing while the files are read would pair a log from one generation with a
    /// manifest from another; the export refuses rather than ship it.
    #[test]
    fn a_commit_during_the_capture_refuses_it() {
        let scratch = tempfile::tempdir().expect("scratch");
        let dir = scratch.path().join("alpha");
        let encoder = EncoderKind::PerListStatus { list_key: LIST }
            .build(RECORD_SIZE, 2048)
            .expect("encoder");
        let opened = InspirePersistence::open(
            StoreLayout::open(&dir).expect("layout"),
            SCHEME_TAG,
            InstanceId::new("alpha"),
            SnapshotPolicy::static_default(),
            Arc::clone(&encoder),
        )
        .expect("open");
        let state = raven_railgun_testkit::cached_toy_state(RECORD_SIZE);
        opened
            .persistence
            .commit_v6(&state, &LogicalLeafStore::default(), 0)
            .expect("first commit");
        let mut store = LogicalLeafStore::default();
        for (block, index) in (100u64..).zip(0..3u32) {
            let payload = row(index);
            opened
                .persistence
                .apply_event(&payload, block)
                .expect("append");
            apply_wal_entry(&mut store, &payload, block, encoder.as_ref()).expect("apply");
        }
        let entry = DiscoveredInstance {
            id: "alpha".to_owned(),
            dir,
        };

        let quiet = capture_instance(&entry, &mut |_, _| Ok(())).expect("a quiet capture");
        assert!(
            quiet.files.iter().any(|f| f.rel_path == "wal/current.log"),
            "{:?}",
            quiet.files
        );

        let raced = capture_instance(&entry, &mut |rel, _| {
            if rel == "wal/current.log" {
                opened
                    .persistence
                    .commit_v6(&state, &store, 102)
                    .map_err(|e| anyhow!("racing commit: {e}"))?;
            }
            Ok(())
        })
        .expect_err("a commit during the capture must refuse it");
        assert!(
            matches!(
                raced.downcast_ref::<SnapshotPortError>(),
                Some(SnapshotPortError::CaptureRaced { instance }) if instance == "alpha"
            ),
            "{raced:?}"
        );
    }
}
