//! Integration tests for the operator snapshot export / import path.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]
#![cfg(test)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use raven_railgun_cli::snapshot_port::{
    run_export, run_import, ExportManifest, ExportOptions, ImportOptions, SnapshotPortError,
};
use raven_railgun_persistence::{
    Manifest, Snapshot, SnapshotId, StoreLayout, Wal, WalEntryPayload, MANIFEST_SCHEMA_VERSION,
    SNAPSHOT_MAGIC,
};

const SCHEME_TAG_A: &str = "raven-inspire-twopacking-inspiring-wp3-cache-session";
const SCHEME_TAG_B: &str = "raven-inspire-twopacking-inspiring-wp3-cache-session-alt";

fn bootstrap_instance(
    root: &Path,
    instance_id: &str,
    encoder_label: &str,
    scheme_tag: &str,
    snapshot_payload: &[u8],
    wal_events: usize,
) -> PathBuf {
    let inst_dir = root.join(instance_id);
    let layout = StoreLayout::open(&inst_dir).expect("StoreLayout::open");
    let snap = Snapshot::build(snapshot_payload.to_vec(), SNAPSHOT_MAGIC);
    let snap_id = SnapshotId(7);
    snap.save(&layout, snap_id).expect("snapshot save");
    let wal = Wal::open(&layout, Some(0)).expect("wal open");
    for i in 0..wal_events {
        let payload = WalEntryPayload::AppendLeaf {
            tree_number: 0,
            leaf_index: u32::try_from(i).expect("leaf_index fits u32"),
            commitment: {
                let mut a = [0u8; 32];
                a[0] = u8::try_from(i & 0xFF).expect("byte fits");
                a
            },
        };
        wal.append(&payload, 100 + u64::try_from(i).expect("fits"))
            .expect("wal append");
    }
    let manifest = Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        scheme_tag: scheme_tag.to_owned(),
        instance_id: instance_id.to_owned(),
        current_snapshot_id: snap_id,
        current_snapshot_seq: 1,
        current_marker: 12_345_678,
        encoder_label: encoder_label.to_owned(),
        prev_encoder_label: None,
        entry_size_bytes: Some(32),
        rows_per_shard: Some(2048),
    };
    manifest.save(&layout).expect("manifest save");
    inst_dir
}

fn collect_dir_bytes(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    visit(dir, dir, &mut out);
    out
}

fn visit(root: &Path, current: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
    let Ok(entries) = std::fs::read_dir(current) else {
        return;
    };
    for e in entries {
        let entry = e.expect("entry");
        let path = entry.path();
        let name = entry.file_name();
        let lossy = name.to_string_lossy().into_owned();
        if lossy == ".lock" {
            continue;
        }
        if path.is_dir() {
            visit(root, &path, out);
        } else if path.is_file() {
            let rel = path
                .strip_prefix(root)
                .expect("strip")
                .to_string_lossy()
                .into_owned();
            let bytes = std::fs::read(&path).expect("read");
            out.insert(rel, bytes);
        }
    }
}

fn read_export_manifest(tarball: &Path) -> ExportManifest {
    let raw = std::fs::read(tarball).expect("read tarball");
    let dec = zstd::stream::read::Decoder::with_buffer(std::io::Cursor::new(raw)).expect("zstd");
    let mut archive = tar::Archive::new(dec);
    for entry_res in archive.entries().expect("entries") {
        let mut entry = entry_res.expect("entry");
        let path = entry.path().expect("path").into_owned();
        if path.to_string_lossy() == "EXPORT_MANIFEST.json" {
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut buf).expect("read manifest");
            return serde_json::from_slice(&buf).expect("parse manifest");
        }
    }
    panic!("EXPORT_MANIFEST.json not found in tarball");
}

fn count_tarball_entries_matching(tarball: &Path, prefix: &str) -> usize {
    let raw = std::fs::read(tarball).expect("read");
    let dec = zstd::stream::read::Decoder::with_buffer(std::io::Cursor::new(raw)).expect("zstd");
    let mut archive = tar::Archive::new(dec);
    let mut count = 0usize;
    for entry_res in archive.entries().expect("entries") {
        let entry = entry_res.expect("entry");
        let path = entry.path().expect("path").into_owned();
        if path.to_string_lossy().starts_with(prefix) {
            count += 1;
        }
    }
    count
}

fn deterministic_signing_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = seed.wrapping_add(u8::try_from(i & 0xFF).expect("byte"));
    }
    SigningKey::from_bytes(&bytes)
}

fn write_signing_key(path: &Path, key: &SigningKey) {
    std::fs::write(path, key.to_bytes()).expect("write signing key");
}

fn write_verifying_key(path: &Path, key: &SigningKey) {
    let pub_bytes = key.verifying_key().to_bytes();
    std::fs::write(path, pub_bytes).expect("write verifying key");
}

#[test]
fn export_then_import_round_trip_preserves_byte_identity() {
    let scratch = tempfile::tempdir().expect("scratch");
    let src_root = scratch.path().join("src");
    std::fs::create_dir_all(&src_root).expect("mkdir src");
    let payload_a: Vec<u8> = (0..1024)
        .map(|i| u8::try_from(i & 0xFF).expect("byte"))
        .collect();
    let payload_b: Vec<u8> = (0..2048)
        .map(|i| u8::try_from((i * 3) & 0xFF).expect("byte"))
        .collect();
    bootstrap_instance(
        &src_root,
        "alpha",
        "per-leaf-bc",
        SCHEME_TAG_A,
        &payload_a,
        4,
    );
    bootstrap_instance(
        &src_root,
        "beta",
        "per-leaf-path",
        SCHEME_TAG_A,
        &payload_b,
        8,
    );

    // `wal/current.log` is skipped without `--include-current-wal`,
    // so compare only files the export captures by default.
    let original_alpha = collect_capturable_bytes(&src_root.join("alpha"));
    let original_beta = collect_capturable_bytes(&src_root.join("beta"));

    let tarball = scratch.path().join("export.tar.zst");
    run_export(ExportOptions {
        data_dir: src_root.clone(),
        output: tarball.clone(),
        signing_key: None,
        include_current_wal: false,
        keep_snapshots: 0,
    })
    .expect("export");

    let dst_root = scratch.path().join("dst");
    run_import(ImportOptions {
        input: tarball,
        data_dir: dst_root.clone(),
        verifying_key: None,
        allow_overwrite: false,
        unsafe_no_verify: true,
    })
    .expect("import");

    let restored_alpha = collect_capturable_bytes(&dst_root.join("alpha"));
    let restored_beta = collect_capturable_bytes(&dst_root.join("beta"));
    assert_eq!(restored_alpha, original_alpha, "alpha byte-identity");
    assert_eq!(restored_beta, original_beta, "beta byte-identity");
}

#[test]
fn export_inspection_does_not_create_layout_under_non_instance_candidates() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let root = scratch.path().join("instances");
    std::fs::create_dir_all(&root).expect("root");
    bootstrap_instance(&root, "live", "per-leaf-bc", SCHEME_TAG_A, b"snapshot", 0);
    let candidate = root.join("candidate");
    std::fs::create_dir(&candidate).expect("candidate");
    let tarball = scratch.path().join("export.tar.zst");

    run_export(ExportOptions {
        data_dir: root,
        output: tarball,
        signing_key: None,
        include_current_wal: false,
        keep_snapshots: 0,
    })
    .expect("export");

    assert_eq!(
        std::fs::read_dir(&candidate)
            .expect("candidate read")
            .count(),
        0,
        "read-only candidate inspection must not create manifest, snapshots, or WAL paths"
    );
}

#[test]
fn signed_export_ignores_legacy_fixed_tmp_collision() {
    let scratch = tempfile::tempdir().expect("scratch");
    let src_root = scratch.path().join("src");
    std::fs::create_dir_all(&src_root).expect("mkdir src");
    bootstrap_instance(
        &src_root,
        "alpha",
        "per-leaf-bc",
        SCHEME_TAG_A,
        b"snapshot payload",
        1,
    );

    let signing_path = scratch.path().join("signing.key");
    write_signing_key(&signing_path, &deterministic_signing_key(41));
    let tarball = scratch.path().join("export.tar.zst");
    let mut sig_name = tarball.as_os_str().to_owned();
    sig_name.push(".sig");
    let sig_path = PathBuf::from(sig_name);
    let fixed_tmp = sig_path.with_extension("import-tmp");
    std::fs::create_dir(&fixed_tmp).expect("reserve legacy fixed tmp path");

    run_export(ExportOptions {
        data_dir: src_root,
        output: tarball,
        signing_key: Some(signing_path),
        include_current_wal: false,
        keep_snapshots: 0,
    })
    .expect("shared atomic write must ignore legacy fixed tmp collision");

    assert!(sig_path.is_file(), "signature sidecar must be published");
    assert!(fixed_tmp.is_dir(), "legacy tmp sentinel must be untouched");
}

fn collect_capturable_bytes(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut all = collect_dir_bytes(dir);
    all.remove("wal/current.log");
    all
}

/// Tamper-refusal TOTALITY: for ANY offset past the zstd frame header and ANY
/// non-zero xor mask, import must refuse with a TYPED error and leave no
/// partial data dir. Replaces the two former single-offset examples (mid-file
/// and offset-256): two lucky offsets usually land in the zstd entropy stream
/// and prove only that zstd notices, while a flip inside a stored (raw) block
/// of high-entropy CRS bytes decompresses cleanly and reaches the manifest
/// checksum layer — the layer that actually guards silent-wrong-bytes.
#[test]
fn tamper_refusal_is_total_over_the_byte_range() {
    use proptest::prelude::{Strategy, TestCaseError};
    use proptest::test_runner::{Config as PropConfig, TestRunner};

    let scratch = tempfile::tempdir().expect("scratch");
    let src_root = scratch.path().join("src");
    std::fs::create_dir_all(&src_root).expect("mkdir");
    let payload: Vec<u8> = (0..16_384u32)
        .map(|i| u8::try_from(i & 0xFF).expect("byte"))
        .collect();
    bootstrap_instance(&src_root, "alpha", "per-leaf-bc", SCHEME_TAG_A, &payload, 4);

    // Export ONCE; every case copies and tampers these bytes.
    let tarball = scratch.path().join("export.tar.zst");
    run_export(ExportOptions {
        data_dir: src_root,
        output: tarball.clone(),
        signing_key: None,
        include_current_wal: false,
        keep_snapshots: 0,
    })
    .expect("export");
    let pristine = std::fs::read(&tarball).expect("read pristine tarball");
    let len = pristine.len();
    assert!(
        len > 64,
        "tarball ({len} bytes) too small to tamper past the header"
    );

    let mut runner = TestRunner::new(PropConfig {
        cases: 32,
        failure_persistence: None,
        ..PropConfig::default()
    });
    let case_no = std::cell::Cell::new(0usize);
    runner
        .run(
            &(64..len, 1u8..=255u8).prop_map(|(o, m)| (o, m)),
            |(offset, mask)| {
                let i = case_no.get();
                case_no.set(i + 1);

                let mut bytes = pristine.clone();
                bytes[offset] ^= mask;
                let tampered = scratch.path().join(format!("tampered-{i}.tar.zst"));
                std::fs::write(&tampered, &bytes)
                    .map_err(|e| TestCaseError::fail(format!("write tampered copy: {e}")))?;

                let dst_root = scratch.path().join(format!("dst-{i}"));
                let result = run_import(ImportOptions {
                    input: tampered,
                    data_dir: dst_root.clone(),
                    verifying_key: None,
                    allow_overwrite: false,
                    unsafe_no_verify: true,
                });
                let Err(err) = result else {
                    return Err(TestCaseError::fail(format!(
                        "flip at offset {offset} mask {mask:#04x} imported CLEANLY"
                    )));
                };
                let Some(typed) = err.downcast_ref::<SnapshotPortError>() else {
                    return Err(TestCaseError::fail(format!(
                        "flip at offset {offset} mask {mask:#04x}: untyped error {err:?}"
                    )));
                };
                if !matches!(
                    typed,
                    SnapshotPortError::TarballParse { .. }
                        | SnapshotPortError::ChecksumMismatch { .. }
                        | SnapshotPortError::ContentHashMismatch
                ) {
                    return Err(TestCaseError::fail(format!(
                        "flip at offset {offset} mask {mask:#04x}: wrong error class {typed:?}"
                    )));
                }
                let dst_populated = dst_root.exists()
                    && std::fs::read_dir(&dst_root).map_or(0, std::iter::Iterator::count) > 0;
                if dst_populated {
                    return Err(TestCaseError::fail(format!(
                        "flip at offset {offset} mask {mask:#04x}: partial data dir left behind"
                    )));
                }
                Ok(())
            },
        )
        .expect("tamper-refusal property");
}

#[test]
fn cross_version_v_minus_one_export_refused() {
    let scratch = tempfile::tempdir().expect("scratch");
    let src_root = scratch.path().join("src");
    std::fs::create_dir_all(&src_root).expect("mkdir");
    bootstrap_instance(
        &src_root,
        "alpha",
        "per-leaf-bc",
        SCHEME_TAG_A,
        b"payload",
        1,
    );

    let tarball = scratch.path().join("export.tar.zst");
    run_export(ExportOptions {
        data_dir: src_root,
        output: tarball.clone(),
        signing_key: None,
        include_current_wal: false,
        keep_snapshots: 0,
    })
    .expect("export");

    let mut manifest = read_export_manifest(&tarball);
    let bumped_persistence = MANIFEST_SCHEMA_VERSION.saturating_sub(1).max(1);
    manifest.persistence_manifest_version = bumped_persistence;

    rewrite_export_manifest(&tarball, &manifest);

    let dst_root = scratch.path().join("dst");
    let err = run_import(ImportOptions {
        input: tarball,
        data_dir: dst_root,
        verifying_key: None,
        allow_overwrite: false,
        unsafe_no_verify: true,
    })
    .expect_err("cross-version import must refuse");
    let typed = err
        .downcast_ref::<SnapshotPortError>()
        .expect("typed SnapshotPortError");
    assert!(
        matches!(
            typed,
            SnapshotPortError::SchemaVersionMismatch {
                kind: "persistence",
                ..
            } | SnapshotPortError::ContentHashMismatch
        ),
        "expected SchemaVersionMismatch(persistence) or ContentHashMismatch, got: {typed:?}"
    );
}

fn rewrite_export_manifest(tarball: &Path, manifest: &ExportManifest) {
    let raw = std::fs::read(tarball).expect("read");
    let dec = zstd::stream::read::Decoder::with_buffer(std::io::Cursor::new(raw)).expect("zstd");
    let mut archive = tar::Archive::new(dec);
    let mut new_entries: Vec<(String, Vec<u8>)> = Vec::new();
    for entry_res in archive.entries().expect("entries") {
        let mut entry = entry_res.expect("entry");
        let path = entry.path().expect("path").into_owned();
        let name = path.to_string_lossy().into_owned();
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut buf).expect("read entry");
        if name == "EXPORT_MANIFEST.json" {
            buf = serde_json::to_vec_pretty(manifest).expect("ser manifest");
        }
        new_entries.push((name, buf));
    }
    let tmp = tarball.with_extension("tmp.repack");
    {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .expect("open tmp");
        let enc = zstd::stream::write::Encoder::new(f, 3)
            .expect("zstd enc")
            .auto_finish();
        let mut tar_writer = tar::Builder::new(enc);
        for (name, bytes) in &new_entries {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).expect("set_path");
            header.set_size(u64::try_from(bytes.len()).expect("size"));
            header.set_mode(0o600);
            header.set_mtime(0);
            header.set_uid(0);
            header.set_gid(0);
            header.set_cksum();
            tar_writer
                .append(&header, bytes.as_slice())
                .expect("append");
        }
        tar_writer.finish().expect("finish");
    }
    std::fs::rename(&tmp, tarball).expect("rename");
}

#[test]
fn signed_export_verifies_with_correct_pubkey() {
    let scratch = tempfile::tempdir().expect("scratch");
    let src_root = scratch.path().join("src");
    std::fs::create_dir_all(&src_root).expect("mkdir");
    bootstrap_instance(
        &src_root,
        "alpha",
        "per-leaf-bc",
        SCHEME_TAG_A,
        b"payload",
        2,
    );

    let tarball = scratch.path().join("export.tar.zst");
    let signing = deterministic_signing_key(0x42);
    let signing_path = scratch.path().join("ed25519.seed");
    let verifying_path = scratch.path().join("ed25519.pub");
    write_signing_key(&signing_path, &signing);
    write_verifying_key(&verifying_path, &signing);

    run_export(ExportOptions {
        data_dir: src_root,
        output: tarball.clone(),
        signing_key: Some(signing_path),
        include_current_wal: false,
        keep_snapshots: 0,
    })
    .expect("export");

    let dst_root = scratch.path().join("dst");
    run_import(ImportOptions {
        input: tarball,
        data_dir: dst_root,
        verifying_key: Some(verifying_path),
        allow_overwrite: false,
        unsafe_no_verify: false,
    })
    .expect("import with matching pubkey");
}

#[test]
fn signed_export_refused_with_wrong_pubkey() {
    let scratch = tempfile::tempdir().expect("scratch");
    let src_root = scratch.path().join("src");
    std::fs::create_dir_all(&src_root).expect("mkdir");
    bootstrap_instance(
        &src_root,
        "alpha",
        "per-leaf-bc",
        SCHEME_TAG_A,
        b"payload",
        2,
    );

    let tarball = scratch.path().join("export.tar.zst");
    let signing = deterministic_signing_key(0x42);
    let other = deterministic_signing_key(0x99);
    let signing_path = scratch.path().join("ed25519.seed");
    let wrong_pub = scratch.path().join("wrong.pub");
    write_signing_key(&signing_path, &signing);
    write_verifying_key(&wrong_pub, &other);

    run_export(ExportOptions {
        data_dir: src_root,
        output: tarball.clone(),
        signing_key: Some(signing_path),
        include_current_wal: false,
        keep_snapshots: 0,
    })
    .expect("export");

    let dst_root = scratch.path().join("dst");
    let err = run_import(ImportOptions {
        input: tarball,
        data_dir: dst_root,
        verifying_key: Some(wrong_pub),
        allow_overwrite: false,
        unsafe_no_verify: false,
    })
    .expect_err("wrong pubkey must refuse");
    let typed = err
        .downcast_ref::<SnapshotPortError>()
        .expect("typed SnapshotPortError");
    assert!(
        matches!(
            typed,
            SnapshotPortError::SignatureVerificationFailed { .. }
                | SnapshotPortError::SignaturePublicKeyMismatch
        ),
        "expected SignatureVerificationFailed or SignaturePublicKeyMismatch, got: {typed:?}"
    );
}

#[test]
fn import_into_existing_data_dir_refused_without_allow_overwrite() {
    let scratch = tempfile::tempdir().expect("scratch");
    let src_root = scratch.path().join("src");
    std::fs::create_dir_all(&src_root).expect("mkdir");
    bootstrap_instance(
        &src_root,
        "alpha",
        "per-leaf-bc",
        SCHEME_TAG_A,
        b"payload",
        1,
    );

    let tarball = scratch.path().join("export.tar.zst");
    run_export(ExportOptions {
        data_dir: src_root,
        output: tarball.clone(),
        signing_key: None,
        include_current_wal: false,
        keep_snapshots: 0,
    })
    .expect("export");

    let dst_root = scratch.path().join("dst");
    bootstrap_instance(
        &dst_root,
        "preexisting",
        "per-leaf-bc",
        SCHEME_TAG_A,
        b"prior",
        1,
    );
    let pre_existing_marker = dst_root.join("preexisting").join("manifest.json");
    assert!(pre_existing_marker.is_file(), "pre-existing marker present");

    let err = run_import(ImportOptions {
        input: tarball.clone(),
        data_dir: dst_root.clone(),
        verifying_key: None,
        allow_overwrite: false,
        unsafe_no_verify: true,
    })
    .expect_err("populated root must refuse without --allow-overwrite");
    let typed = err
        .downcast_ref::<SnapshotPortError>()
        .expect("typed SnapshotPortError");
    assert!(
        matches!(typed, SnapshotPortError::DestinationPopulated),
        "expected DestinationPopulated, got: {typed:?}"
    );

    run_import(ImportOptions {
        input: tarball,
        data_dir: dst_root.clone(),
        verifying_key: None,
        allow_overwrite: true,
        unsafe_no_verify: true,
    })
    .expect("import with --allow-overwrite");

    let parent = dst_root.parent().expect("parent");
    let backups: Vec<_> = std::fs::read_dir(parent)
        .expect("readdir")
        .filter_map(std::result::Result::ok)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("dst.pre-import.")
        })
        .collect();
    assert!(
        !backups.is_empty(),
        "expected at least one .pre-import backup directory"
    );
    let restored_alpha = dst_root.join("alpha").join("manifest.json");
    assert!(
        restored_alpha.is_file(),
        "imported instance must have replaced the root"
    );
}

#[test]
fn dedup_shared_crs_appears_once_in_tarball() {
    let scratch = tempfile::tempdir().expect("scratch");
    let src_root = scratch.path().join("src");
    std::fs::create_dir_all(&src_root).expect("mkdir");
    bootstrap_instance(
        &src_root,
        "alpha",
        "per-leaf-bc",
        SCHEME_TAG_A,
        b"payload-a",
        1,
    );
    bootstrap_instance(
        &src_root,
        "beta",
        "per-leaf-path",
        SCHEME_TAG_A,
        b"payload-b",
        1,
    );

    let tarball = scratch.path().join("export.tar.zst");
    run_export(ExportOptions {
        data_dir: src_root,
        output: tarball.clone(),
        signing_key: None,
        include_current_wal: false,
        keep_snapshots: 0,
    })
    .expect("export");

    let manifest = read_export_manifest(&tarball);
    assert_eq!(
        manifest.shared_crs.len(),
        1,
        "two instances sharing scheme_tag must dedup to one shared CRS entry"
    );
    let crs_count = count_tarball_entries_matching(&tarball, "shared/crs/");
    assert_eq!(
        crs_count, 1,
        "tarball must contain exactly one shared/crs/ payload"
    );
    assert_eq!(
        manifest.instances[0].shared_crs_hash, manifest.instances[1].shared_crs_hash,
        "both instances must reference the same CRS hash"
    );
}

#[test]
fn distinct_scheme_tags_get_distinct_shared_crs_entries() {
    let scratch = tempfile::tempdir().expect("scratch");
    let src_root = scratch.path().join("src");
    std::fs::create_dir_all(&src_root).expect("mkdir");
    bootstrap_instance(
        &src_root,
        "alpha",
        "per-leaf-bc",
        SCHEME_TAG_A,
        b"payload-a",
        1,
    );
    bootstrap_instance(
        &src_root,
        "beta",
        "per-leaf-bc",
        SCHEME_TAG_B,
        b"payload-b",
        1,
    );

    let tarball = scratch.path().join("export.tar.zst");
    run_export(ExportOptions {
        data_dir: src_root,
        output: tarball.clone(),
        signing_key: None,
        include_current_wal: false,
        keep_snapshots: 0,
    })
    .expect("export");

    let manifest = read_export_manifest(&tarball);
    assert_eq!(
        manifest.shared_crs.len(),
        2,
        "distinct scheme_tags must allocate distinct shared CRS slots"
    );
    let crs_count = count_tarball_entries_matching(&tarball, "shared/crs/");
    assert_eq!(crs_count, 2, "tarball must contain two shared CRS payloads");
    assert_ne!(
        manifest.instances[0].shared_crs_hash, manifest.instances[1].shared_crs_hash,
        "distinct scheme_tags must produce distinct CRS hashes"
    );
}

#[test]
fn import_refuses_tampered_signature_file_with_actionable_error() {
    let scratch = tempfile::tempdir().expect("scratch");
    let src_root = scratch.path().join("src");
    std::fs::create_dir_all(&src_root).expect("mkdir");
    bootstrap_instance(
        &src_root,
        "alpha",
        "per-leaf-bc",
        SCHEME_TAG_A,
        b"signed-payload",
        2,
    );

    let tarball = scratch.path().join("export.tar.zst");
    let signing = deterministic_signing_key(0x77);
    let signing_path = scratch.path().join("ed25519.seed");
    let verifying_path = scratch.path().join("ed25519.pub");
    write_signing_key(&signing_path, &signing);
    write_verifying_key(&verifying_path, &signing);

    run_export(ExportOptions {
        data_dir: src_root,
        output: tarball.clone(),
        signing_key: Some(signing_path),
        include_current_wal: false,
        keep_snapshots: 0,
    })
    .expect("export");

    let sig_path = {
        let mut p = tarball.as_os_str().to_owned();
        p.push(".sig");
        std::path::PathBuf::from(p)
    };
    let mut sig_bytes = std::fs::read(&sig_path).expect("read sig");
    let sig_str = std::str::from_utf8(&sig_bytes).expect("sig is utf8 json");
    let needle = "\"signature_hex\":";
    let key_idx = sig_str.find(needle).expect("signature_hex field present");
    let after_open_quote = sig_str[key_idx + needle.len()..]
        .find('"')
        .map(|o| key_idx + needle.len() + o + 1)
        .expect("opening quote of signature_hex value");
    let original = sig_bytes[after_open_quote];
    let flipped = match original {
        b'0' => b'1',
        b'a'..=b'f' | b'A'..=b'F' => original - 1,
        _ => b'0',
    };
    assert_ne!(original, flipped, "must actually mutate sig hex char");
    sig_bytes[after_open_quote] = flipped;
    std::fs::write(&sig_path, &sig_bytes).expect("write tampered sig");

    let dst_root = scratch.path().join("dst");
    let err = run_import(ImportOptions {
        input: tarball,
        data_dir: dst_root.clone(),
        verifying_key: Some(verifying_path),
        allow_overwrite: false,
        unsafe_no_verify: false,
    })
    .expect_err("tampered signature must refuse with mandatory verification");
    let typed = err
        .downcast_ref::<SnapshotPortError>()
        .expect("typed SnapshotPortError");
    assert!(
        matches!(
            typed,
            SnapshotPortError::SignatureVerificationFailed { .. }
                | SnapshotPortError::SignatureLengthInvalid { .. }
        ),
        "expected SignatureVerificationFailed or SignatureLengthInvalid, got: {typed:?}"
    );
    assert!(
        !dst_root.exists()
            || std::fs::read_dir(&dst_root).map_or(0, std::iter::Iterator::count) == 0,
        "destination must remain empty when signature tampering is detected"
    );
}
