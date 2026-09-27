//! Real instance data_dirs for the snapshot export / import tests.
//!
//! An export recovers every instance through the node's open path, so a fixture must be a
//! data_dir a node could boot. Two shapes are:
//! - [`wal_only_instance`]: `manifest.json` at snapshot id 0 plus the live log. Recovery replays
//!   the whole log and builds no PIR state, so an export or import of it takes milliseconds.
//! - [`synced_instance`]: what a static PPOI instance holds right after a sync, one committed
//!   snapshot of an empty store and every row only in the live log. Each recovery of it rebuilds
//!   the packing cache, so only tests whose property is the snapshot bytes or this synced shape
//!   use it.

// `#[path]`-included by several targets; each uses a different subset.
#![allow(dead_code, unreachable_pub)]
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    clippy::missing_panics_doc
)]

use std::collections::BTreeMap;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use raven_railgun_cli::snapshot_port::{
    export_content_hash, instance_files_hash, run_export, run_import, signature_message,
    DetachedSignature, ExportManifest, ExportOptions, ExportReceipt, ImportOptions, ImportReceipt,
};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::persistence::{InspirePersistence, OpenedInstance, SnapshotPolicy};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_persistence::{PpoiEventType, StoreLayout, WalEntryPayload};
use sha2::{Digest, Sha256};

pub const SCHEME_TAG_A: &str = "raven-inspire-twopacking-inspiring-wp3-cache-session";
pub const SCHEME_TAG_B: &str = "raven-inspire-twopacking-inspiring-wp3-cache-session-alt";
pub const RECORD_SIZE: usize = 256;
pub const ENTRIES_PER_SHARD: u32 = 2048;
pub const LIST_A: [u8; 32] = [0x0a; 32];
pub const LIST_B: [u8; 32] = [0x0b; 32];
pub const FIRST_BLOCK: u64 = 100;
pub const MANIFEST_ENTRY: &str = "EXPORT_MANIFEST.json";

pub fn encoder(list_key: [u8; 32]) -> Arc<dyn PirTableEncoder> {
    EncoderKind::PerListStatus { list_key }
        .build(RECORD_SIZE, ENTRIES_PER_SHARD)
        .expect("per-list-status encoder")
}

pub fn list_leaf(list_key: [u8; 32], list_index: u32) -> WalEntryPayload {
    let mut blinded_commitment = [0u8; 32];
    blinded_commitment[1] = list_key[0];
    blinded_commitment[28..].copy_from_slice(&(list_index + 1).to_be_bytes());
    WalEntryPayload::PpoiListLeafAdded {
        list_key,
        list_index,
        blinded_commitment,
        status: 1,
        event_type: PpoiEventType::Shield,
        signature: vec![u8::try_from(list_index % 251).expect("< 251"); 64],
        validated_merkleroot: [0; 32],
    }
}

pub fn open(dir: &Path, id: &str, scheme_tag: &str, list_key: [u8; 32]) -> OpenedInstance {
    InspirePersistence::open(
        StoreLayout::open(dir).expect("layout"),
        scheme_tag,
        InstanceId::new(id),
        SnapshotPolicy::static_default(),
        encoder(list_key),
    )
    .expect("open through the node's recovery path")
}

/// An instance that never committed: `rows` rows in the live log and no snapshot.
pub fn wal_only_instance(
    root: &Path,
    id: &str,
    scheme_tag: &str,
    list_key: [u8; 32],
    rows: u32,
) -> PathBuf {
    wal_only_instance_of(root, id, scheme_tag, list_key, &list_rows(list_key, rows))
}

/// A synced static instance: an empty committed snapshot and `rows` rows in the live log.
pub fn synced_instance(
    root: &Path,
    id: &str,
    scheme_tag: &str,
    list_key: [u8; 32],
    rows: u32,
) -> PathBuf {
    instance_of(
        root,
        id,
        scheme_tag,
        list_key,
        &list_rows(list_key, rows),
        true,
    )
}

pub fn list_rows(list_key: [u8; 32], rows: u32) -> Vec<WalEntryPayload> {
    (0..rows).map(|i| list_leaf(list_key, i)).collect()
}

/// As [`wal_only_instance`], holding exactly `rows`, row `i` at block `FIRST_BLOCK + i`.
pub fn wal_only_instance_of(
    root: &Path,
    id: &str,
    scheme_tag: &str,
    list_key: [u8; 32],
    rows: &[WalEntryPayload],
) -> PathBuf {
    instance_of(root, id, scheme_tag, list_key, rows, false)
}

fn instance_of(
    root: &Path,
    id: &str,
    scheme_tag: &str,
    list_key: [u8; 32],
    rows: &[WalEntryPayload],
    commit_empty_snapshot: bool,
) -> PathBuf {
    let dir = root.join(id);
    let opened = open(&dir, id, scheme_tag, list_key);
    assert!(
        opened.recovered_state.is_none(),
        "fixture wants a fresh data_dir"
    );
    if commit_empty_snapshot {
        opened
            .persistence
            .commit_v6(
                &raven_railgun_testkit::cached_toy_state(RECORD_SIZE),
                &LogicalLeafStore::default(),
                0,
            )
            .expect("empty first commit");
    }
    for (i, row) in (0u64..).zip(rows) {
        let (_, trigger) = opened
            .persistence
            .apply_event(row, FIRST_BLOCK + i)
            .expect("wal append");
        assert!(!trigger, "a static policy never commits during a sync");
    }
    dir
}

/// Reopen `dir` and append `rows` to its live log, as a resumed sync does.
pub fn sync_more(dir: &Path, id: &str, scheme_tag: &str, list_key: [u8; 32], rows: Range<u32>) {
    let opened = open(dir, id, scheme_tag, list_key);
    append_rows(&opened.persistence, list_key, rows);
}

pub fn append_rows(persistence: &InspirePersistence, list_key: [u8; 32], rows: Range<u32>) {
    for i in rows {
        let (_, trigger) = persistence
            .apply_event(&list_leaf(list_key, i), FIRST_BLOCK + u64::from(i))
            .expect("wal append");
        assert!(!trigger, "a static policy never commits during a sync");
    }
}

/// The store a node holding `rows` rows serves from, built by applying them directly.
pub fn expected_store(list_key: [u8; 32], rows: u32) -> LogicalLeafStore {
    store_of(list_key, &list_rows(list_key, rows))
}

pub fn store_of(list_key: [u8; 32], rows: &[WalEntryPayload]) -> LogicalLeafStore {
    let enc = encoder(list_key);
    let mut store = LogicalLeafStore::new();
    for (i, row) in (0u64..).zip(rows) {
        apply_wal_entry(&mut store, row, FIRST_BLOCK + i, enc.as_ref()).expect("apply");
    }
    store
}

#[derive(Debug)]
pub struct Keys {
    pub key: SigningKey,
    pub signing: PathBuf,
    pub verifying: PathBuf,
}

pub fn keys(dir: &Path, seed: u8) -> Keys {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = seed.wrapping_add(u8::try_from(i).expect("< 32"));
    }
    let key = SigningKey::from_bytes(&bytes);
    let signing = dir.join(format!("signing-{seed}.key"));
    let verifying = dir.join(format!("verifying-{seed}.pub"));
    std::fs::write(&signing, key.to_bytes()).expect("write signing key");
    std::fs::write(&verifying, key.verifying_key().to_bytes()).expect("write verifying key");
    Keys {
        key,
        signing,
        verifying,
    }
}

pub fn export(src: &Path, output: &Path, keys: &Keys) -> ExportReceipt {
    run_export(ExportOptions {
        data_dir: src.to_path_buf(),
        output: output.to_path_buf(),
        signing_key: Some(keys.signing.clone()),
        keep_snapshots: 0,
    })
    .expect("export")
}

pub fn import(
    input: &Path,
    dst: &Path,
    keys: &Keys,
    expected_content_hash: &str,
) -> anyhow::Result<ImportReceipt> {
    run_import(ImportOptions {
        input: input.to_path_buf(),
        data_dir: dst.to_path_buf(),
        verifying_key: keys.verifying.clone(),
        expected_content_hash: expected_content_hash.to_owned(),
        allow_overwrite: false,
    })
}

pub fn sig_path(tarball: &Path) -> PathBuf {
    let mut s = tarball.as_os_str().to_owned();
    s.push(".sig");
    PathBuf::from(s)
}

pub fn read_tarball(tarball: &Path) -> (ExportManifest, BTreeMap<String, Vec<u8>>) {
    let raw = std::fs::read(tarball).expect("read tarball");
    let dec = zstd::stream::read::Decoder::with_buffer(std::io::Cursor::new(raw)).expect("zstd");
    let mut archive = tar::Archive::new(dec);
    let mut files = BTreeMap::new();
    for entry in archive.entries().expect("entries") {
        let mut entry = entry.expect("entry");
        let name = entry.path().expect("path").to_string_lossy().into_owned();
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut buf).expect("read entry");
        files.insert(name, buf);
    }
    let manifest = serde_json::from_slice(&files[MANIFEST_ENTRY]).expect("parse manifest");
    (manifest, files)
}

pub fn write_tarball(tarball: &Path, manifest: &ExportManifest, files: &BTreeMap<String, Vec<u8>>) {
    let f = std::fs::File::create(tarball).expect("create tarball");
    let enc = zstd::stream::write::Encoder::new(f, 3)
        .expect("zstd")
        .auto_finish();
    let mut tar_writer = tar::Builder::new(enc);
    let manifest_bytes = serde_json::to_vec_pretty(manifest).expect("manifest json");
    let entries = std::iter::once((MANIFEST_ENTRY, manifest_bytes.as_slice())).chain(
        files
            .iter()
            .filter(|(name, _)| name.as_str() != MANIFEST_ENTRY)
            .map(|(name, bytes)| (name.as_str(), bytes.as_slice())),
    );
    for (name, bytes) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_path(name).expect("set_path");
        header.set_size(u64::try_from(bytes.len()).expect("size"));
        header.set_mode(0o600);
        header.set_mtime(0);
        header.set_cksum();
        tar_writer.append(&header, bytes).expect("append");
    }
    tar_writer.finish().expect("finish");
}

pub fn write_signature(tarball: &Path, key: &SigningKey, content_hash_hex: &str, message: &[u8]) {
    let detached = DetachedSignature {
        kind: "raven-railgun-export-sig/v2".to_owned(),
        signature_hex: hex::encode(key.sign(message).to_bytes()),
        content_hash_hex: content_hash_hex.to_owned(),
        public_key_hex: hex::encode(key.verifying_key().to_bytes()),
    };
    std::fs::write(
        sig_path(tarball),
        serde_json::to_vec_pretty(&detached).expect("sig json"),
    )
    .expect("write sig");
}

/// Apply `edit`, then re-derive every checksum and the content hash and re-sign with `key`:
/// the result is byte-perfect and genuinely signed, whatever it now carries. Returns its hash.
pub fn reforge(
    tarball: &Path,
    key: &SigningKey,
    edit: impl FnOnce(&mut ExportManifest, &mut BTreeMap<String, Vec<u8>>),
) -> String {
    let hash = restitch(tarball, edit);
    let message = signature_message(&hash).expect("message");
    write_signature(tarball, key, &hash, &message);
    hash
}

/// As [`reforge`], but the sidecar is left as it was: consistent throughout, and not re-signed.
pub fn restitch(
    tarball: &Path,
    edit: impl FnOnce(&mut ExportManifest, &mut BTreeMap<String, Vec<u8>>),
) -> String {
    let (mut manifest, mut files) = read_tarball(tarball);
    edit(&mut manifest, &mut files);
    for inst in &mut manifest.instances {
        let prefix = format!("instances/{}/", inst.id);
        inst.files
            .retain(|f| files.contains_key(&format!("{prefix}{}", f.rel_path)));
        for f in &mut inst.files {
            let bytes = &files[&format!("{prefix}{}", f.rel_path)];
            f.byte_len = u64::try_from(bytes.len()).expect("len");
            f.sha256_hex = hex::encode(Sha256::digest(bytes));
        }
        inst.data_size_bytes = inst.files.iter().map(|f| f.byte_len).sum();
        inst.content_hash_hex = instance_files_hash(&inst.files);
    }
    manifest.content_hash_hex = export_content_hash(&manifest).expect("content hash");
    write_tarball(tarball, &manifest, &files);
    manifest.content_hash_hex
}

/// Rewrite the manifest only, leaving the sidecar and every other entry untouched.
pub fn rewrite_manifest(tarball: &Path, edit: impl FnOnce(&mut ExportManifest)) {
    let (mut manifest, files) = read_tarball(tarball);
    edit(&mut manifest);
    write_tarball(tarball, &manifest, &files);
}

pub fn is_empty_or_absent(dir: &Path) -> bool {
    !dir.exists() || std::fs::read_dir(dir).map_or(0, Iterator::count) == 0
}

/// Names under `parent` that start with `prefix`, e.g. leftover `dst.staging.*` dirs.
pub fn siblings_with_prefix(parent: &Path, prefix: &str) -> Vec<String> {
    std::fs::read_dir(parent)
        .expect("read_dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(prefix))
        .collect()
}
