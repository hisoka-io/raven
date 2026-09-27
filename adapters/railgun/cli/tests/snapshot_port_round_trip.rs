//! Integration tests for the operator snapshot export / import path.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]
#![cfg(test)]

#[path = "support/snapshot_fixture.rs"]
mod snapshot_fixture;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use raven_railgun_cli::snapshot_port::{
    run_export, run_import, DetachedSignature, ExportManifest, ExportOptions, ImportOptions,
    SnapshotPortError,
};
use raven_railgun_persistence::MANIFEST_SCHEMA_VERSION;
use sha2::Digest;
use snapshot_fixture::{
    export, import, is_empty_or_absent, keys, read_tarball, rewrite_manifest, sig_path,
    synced_instance, wal_only_instance, LIST_A, LIST_B, SCHEME_TAG_A, SCHEME_TAG_B,
};

/// The decoded archive, or `None` if zstd refuses the stream.
fn inflate(compressed: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut dec =
        zstd::stream::read::Decoder::with_buffer(std::io::Cursor::new(compressed)).ok()?;
    std::io::Read::read_to_end(&mut dec, &mut out).ok()?;
    Some(out)
}

fn read_export_manifest(tarball: &Path) -> ExportManifest {
    read_tarball(tarball).0
}

fn count_tarball_entries_matching(tarball: &Path, prefix: &str) -> usize {
    read_tarball(tarball)
        .1
        .keys()
        .filter(|name| name.starts_with(prefix))
        .count()
}

/// Every file the export lists for `id`, read from `root/id`.
fn exported_files(manifest: &ExportManifest, id: &str, root: &Path) -> BTreeMap<String, Vec<u8>> {
    let inst = manifest
        .instances
        .iter()
        .find(|i| i.id == id)
        .expect("instance listed");
    inst.files
        .iter()
        .map(|f| {
            let bytes = std::fs::read(root.join(id).join(&f.rel_path)).expect("read listed file");
            (f.rel_path.clone(), bytes)
        })
        .collect()
}

fn typed(err: &anyhow::Error) -> &SnapshotPortError {
    err.downcast_ref::<SnapshotPortError>()
        .unwrap_or_else(|| panic!("untyped error: {err:?}"))
}

/// Alpha carries a committed snapshot, whose bytes are the point; beta shares its scheme tag, so
/// the one export also proves the shared CRS entry is deduplicated.
#[test]
fn export_then_import_round_trip_preserves_byte_identity() {
    let scratch = tempfile::tempdir().expect("scratch");
    let src_root = scratch.path().join("src");
    synced_instance(&src_root, "alpha", SCHEME_TAG_A, LIST_A, 40);
    wal_only_instance(&src_root, "beta", SCHEME_TAG_A, LIST_B, 24);
    let keys = keys(scratch.path(), 0x42);

    let tarball = scratch.path().join("export.tar.zst");
    let receipt = export(&src_root, &tarball, &keys);
    let manifest = read_export_manifest(&tarball);
    let original_alpha = exported_files(&manifest, "alpha", &src_root);
    let original_beta = exported_files(&manifest, "beta", &src_root);
    assert!(
        original_alpha.contains_key("wal/current.log"),
        "the live log is part of every export"
    );
    assert!(
        original_alpha
            .keys()
            .any(|rel| rel.starts_with("snapshots/")),
        "alpha must carry snapshot bytes for the byte-identity check to cover them: {:?}",
        original_alpha.keys()
    );

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

    let dst_root = scratch.path().join("dst");
    let imported = import(&tarball, &dst_root, &keys, &receipt.content_hash_hex).expect("import");
    assert_eq!(
        imported.instances, receipt.instances,
        "the import recovers what the export recorded"
    );

    assert_eq!(
        exported_files(&manifest, "alpha", &dst_root),
        original_alpha,
        "alpha byte-identity"
    );
    assert_eq!(
        exported_files(&manifest, "beta", &dst_root),
        original_beta,
        "beta byte-identity"
    );
}

#[test]
fn export_inspection_does_not_create_layout_under_non_instance_candidates() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let root = scratch.path().join("instances");
    wal_only_instance(&root, "live", SCHEME_TAG_A, LIST_A, 0);
    let candidate = root.join("candidate");
    std::fs::create_dir(&candidate).expect("candidate");
    let tarball = scratch.path().join("export.tar.zst");

    run_export(ExportOptions {
        data_dir: root,
        output: tarball,
        signing_key: None,
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

/// Tamper-refusal TOTALITY: for ANY offset past the zstd frame header and ANY
/// non-zero xor mask, import must refuse with a TYPED error and leave no
/// partial data dir. Replaces the two former single-offset examples (mid-file
/// and offset-256): two lucky offsets usually land in the zstd entropy stream
/// and prove only that zstd notices, while a flip inside a stored (raw) block
/// of high-entropy bytes decompresses cleanly and reaches the manifest
/// checksum layer -- the layer that actually guards silent-wrong-bytes.
#[test]
fn tamper_refusal_is_total_over_the_byte_range() {
    use proptest::prelude::{Strategy, TestCaseError};
    use proptest::test_runner::{Config as PropConfig, TestRunner};

    let scratch = tempfile::tempdir().expect("scratch");
    let src_root = scratch.path().join("src");
    let alpha = wal_only_instance(&src_root, "alpha", SCHEME_TAG_A, LIST_A, 64);
    // The raw blocks: export carries a sealed segment and recovery never reads one, so these
    // bytes cost no replay. A multiple of 512 leaves no tar padding inside them.
    let incompressible: Vec<u8> = (0u32..8192)
        .flat_map(|i| sha2::Sha256::digest(i.to_le_bytes()))
        .collect();
    std::fs::write(
        alpha.join("wal/archived/seq-00000000000000000000-00000000000000000000.log"),
        &incompressible,
    )
    .expect("sealed segment");
    let keys = keys(scratch.path(), 0x51);

    // Export ONCE; every case copies and tampers these bytes, beside the untouched sidecar.
    let tarball = scratch.path().join("export.tar.zst");
    let receipt = export(&src_root, &tarball, &keys);
    let pristine = std::fs::read(&tarball).expect("read pristine tarball");
    let pristine_sig = std::fs::read(sig_path(&tarball)).expect("read pristine sidecar");
    let len = pristine.len();
    let plain = inflate(&pristine).expect("pristine export must inflate");

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
                // A zstd bitstream has don't-care bits: a flip that decodes to the identical
                // archive has tampered nothing, and accepting it is correct. Measured at
                // compressed offset 1122, masks 0x08 and 0x18 leave all 7,680 decoded bytes
                // unchanged while 0x01 trips the decoder. The totality property is over flips
                // that CHANGE the decoded archive; a no-op flip is not a tamper.
                if inflate(&bytes).as_deref() == Some(plain.as_slice()) {
                    return Ok(());
                }
                let tampered = scratch.path().join(format!("tampered-{i}.tar.zst"));
                std::fs::write(&tampered, &bytes)
                    .map_err(|e| TestCaseError::fail(format!("write tampered copy: {e}")))?;
                std::fs::write(sig_path(&tampered), &pristine_sig)
                    .map_err(|e| TestCaseError::fail(format!("write sidecar copy: {e}")))?;

                let dst_root = scratch.path().join(format!("dst-{i}"));
                let result = import(&tampered, &dst_root, &keys, &receipt.content_hash_hex);
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
                // A flip on a version digit refuses at the version gate, which runs before the
                // hash gate so that an old export names its version rather than a hash.
                if !matches!(
                    typed,
                    SnapshotPortError::TarballParse { .. }
                        | SnapshotPortError::ChecksumMismatch { .. }
                        | SnapshotPortError::ContentHashMismatch
                        | SnapshotPortError::KindMismatch { .. }
                        | SnapshotPortError::SchemaVersionMismatch { .. }
                ) {
                    return Err(TestCaseError::fail(format!(
                        "flip at offset {offset} mask {mask:#04x}: wrong error class {typed:?}"
                    )));
                }
                if !is_empty_or_absent(&dst_root) {
                    return Err(TestCaseError::fail(format!(
                        "flip at offset {offset} mask {mask:#04x}: partial data dir left behind"
                    )));
                }
                Ok(())
            },
        )
        .expect("tamper-refusal property");
}

/// The stored `kind` field must refuse as a TYPED `KindMismatch`, not as whatever byte happens to
/// live at a fixed offset.
///
/// This assertion used to ride inside the tamper proptest as a hand-picked flip at **compressed**
/// offset 222. `snapshot_port.rs` writes `SystemTime::now()` into `EXPORT_MANIFEST.json`, so the
/// zstd layout shifts on every export and offset 222 lands somewhere different each run -- the
/// assertion failed about one run in four with `TarballParse`, and the lane carrying it had not
/// executed in CI since the offset was introduced.
///
/// Tampering the FIELD instead of a byte position is deterministic. The replacement is the same
/// length, so every tar header and its checksum are untouched and the import reaches the kind check.
#[test]
fn a_stored_kind_field_flip_refuses_as_a_typed_kind_mismatch() {
    const KIND: &[u8] = b"raven-railgun-export/v2";
    /// Same length as KIND, so every tar header and checksum is untouched.
    const FLIPPED: &[u8] = b"raven-railgun-export/v0";

    let scratch = tempfile::tempdir().expect("scratch");
    let src_root = scratch.path().join("src");
    wal_only_instance(&src_root, "alpha", SCHEME_TAG_A, LIST_A, 4);
    let keys = keys(scratch.path(), 0x61);

    let tarball = scratch.path().join("export.tar.zst");
    let receipt = export(&src_root, &tarball, &keys);

    let compressed = std::fs::read(&tarball).expect("read tarball");
    let mut plain = inflate(&compressed).expect("inflate");
    let at = plain
        .windows(KIND.len())
        .position(|w| w == KIND)
        .expect("the export kind literal must be present in the tarball");
    plain[at..at + KIND.len()].copy_from_slice(FLIPPED);

    let tampered = scratch.path().join("tampered.tar.zst");
    std::fs::write(
        &tampered,
        zstd::stream::encode_all(std::io::Cursor::new(&plain), 3).expect("zstd encode"),
    )
    .expect("write tampered");
    std::fs::copy(sig_path(&tarball), sig_path(&tampered)).expect("copy sidecar");

    let dst_root = scratch.path().join("dst");
    let err = import(&tampered, &dst_root, &keys, &receipt.content_hash_hex)
        .expect_err("a wrong export kind must refuse");
    assert!(
        matches!(typed(&err), SnapshotPortError::KindMismatch { .. }),
        "a stored kind-field flip must be a typed KindMismatch, got {err:?}"
    );
    assert!(
        is_empty_or_absent(&dst_root),
        "a refused import must leave no partial data dir"
    );
}

#[test]
fn cross_version_v_minus_one_export_refused() {
    let scratch = tempfile::tempdir().expect("scratch");
    let src_root = scratch.path().join("src");
    wal_only_instance(&src_root, "alpha", SCHEME_TAG_A, LIST_A, 1);
    let keys = keys(scratch.path(), 0x71);

    let tarball = scratch.path().join("export.tar.zst");
    let receipt = export(&src_root, &tarball, &keys);
    rewrite_manifest(&tarball, |m| {
        m.persistence_manifest_version = MANIFEST_SCHEMA_VERSION.saturating_sub(1).max(1);
    });

    let dst_root = scratch.path().join("dst");
    let err = import(&tarball, &dst_root, &keys, &receipt.content_hash_hex)
        .expect_err("cross-version import must refuse");
    assert!(
        matches!(
            typed(&err),
            SnapshotPortError::SchemaVersionMismatch {
                kind: "persistence",
                ..
            }
        ),
        "expected SchemaVersionMismatch(persistence), got: {err:?}"
    );
}

#[test]
fn signed_export_refused_with_wrong_pubkey() {
    let scratch = tempfile::tempdir().expect("scratch");
    let src_root = scratch.path().join("src");
    wal_only_instance(&src_root, "alpha", SCHEME_TAG_A, LIST_A, 2);
    let signer = keys(scratch.path(), 0x42);
    let other = keys(scratch.path(), 0x99);

    let tarball = scratch.path().join("export.tar.zst");
    let receipt = export(&src_root, &tarball, &signer);

    let dst_root = scratch.path().join("dst");
    let err = import(&tarball, &dst_root, &other, &receipt.content_hash_hex)
        .expect_err("wrong pubkey must refuse");
    assert!(
        matches!(
            typed(&err),
            SnapshotPortError::SignatureVerificationFailed { .. }
        ),
        "expected SignatureVerificationFailed, got: {err:?}"
    );
}

/// A root that holds no instance is still the operator's, e.g. the parent of the real one; a
/// root that holds an instance is refused the same way.
#[test]
fn import_never_deletes_what_the_destination_already_holds() {
    let scratch = tempfile::tempdir().expect("scratch");
    let src_root = scratch.path().join("src");
    wal_only_instance(&src_root, "alpha", SCHEME_TAG_A, LIST_A, 1);
    let keys = keys(scratch.path(), 0x43);
    let tarball = scratch.path().join("export.tar.zst");
    let receipt = export(&src_root, &tarball, &keys);
    let pin = receipt.content_hash_hex.as_str();

    let dst_root = scratch.path().join("dst");
    let kept = Path::new("secrets").join("operator.toml");
    std::fs::create_dir_all(dst_root.join("secrets")).expect("mkdir");
    std::fs::write(dst_root.join(&kept), b"not an instance").expect("operator file");

    let err = import(&tarball, &dst_root, &keys, pin)
        .expect_err("a root holding no instance must still refuse without --allow-overwrite");
    assert!(
        matches!(typed(&err), SnapshotPortError::DestinationPopulated),
        "expected DestinationPopulated for a no-instance root, got: {err:?}"
    );
    assert_eq!(
        std::fs::read(dst_root.join(&kept)).expect("operator file survives the refusal"),
        b"not an instance"
    );

    let pre_existing_marker: PathBuf = Path::new("preexisting").join("manifest.json");
    std::fs::create_dir_all(dst_root.join("preexisting")).expect("mkdir");
    std::fs::write(dst_root.join(&pre_existing_marker), b"{}").expect("marker");

    let err = import(&tarball, &dst_root, &keys, pin)
        .expect_err("a root holding an instance must refuse without --allow-overwrite");
    assert!(
        matches!(typed(&err), SnapshotPortError::DestinationPopulated),
        "expected DestinationPopulated for a root holding an instance, got: {err:?}"
    );
    assert_eq!(
        std::fs::read(dst_root.join(&kept)).expect("operator file survives the refusal"),
        b"not an instance"
    );
    assert_eq!(
        std::fs::read(dst_root.join(&pre_existing_marker))
            .expect("pre-existing instance manifest survives the refusal"),
        b"{}"
    );

    run_import(ImportOptions {
        input: tarball.clone(),
        data_dir: dst_root.clone(),
        verifying_key: keys.verifying.clone(),
        expected_content_hash: pin.to_owned(),
        allow_overwrite: true,
    })
    .expect("import with --allow-overwrite");
    let backups = snapshot_fixture::siblings_with_prefix(scratch.path(), "dst.pre-import.");
    assert_eq!(backups.len(), 1, "{backups:?}");
    assert_eq!(
        std::fs::read(scratch.path().join(&backups[0]).join(&kept))
            .expect("operator file moved aside, not deleted"),
        b"not an instance"
    );
    assert_eq!(
        std::fs::read(scratch.path().join(&backups[0]).join(&pre_existing_marker))
            .expect("pre-existing instance moved aside, not deleted"),
        b"{}"
    );
    assert!(
        dst_root.join("alpha").join("manifest.json").is_file()
            && !dst_root.join("preexisting").exists(),
        "imported instance must have replaced the root"
    );

    let empty_root = scratch.path().join("empty");
    std::fs::create_dir(&empty_root).expect("mkdir");
    import(&tarball, &empty_root, &keys, pin).expect("an empty root holds nothing to keep");
    assert!(empty_root.join("alpha").join("manifest.json").is_file());
    assert!(
        snapshot_fixture::siblings_with_prefix(scratch.path(), "empty.pre-import.").is_empty(),
        "nothing to back up"
    );
}

#[test]
fn distinct_scheme_tags_get_distinct_shared_crs_entries() {
    let scratch = tempfile::tempdir().expect("scratch");
    let src_root = scratch.path().join("src");
    wal_only_instance(&src_root, "alpha", SCHEME_TAG_A, LIST_A, 1);
    wal_only_instance(&src_root, "beta", SCHEME_TAG_B, LIST_B, 1);

    let tarball = scratch.path().join("export.tar.zst");
    run_export(ExportOptions {
        data_dir: src_root,
        output: tarball.clone(),
        signing_key: None,
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

/// The signature carries the export time, so its leading character differs per export. Every
/// replacement is tried, hex and not, so the outcome cannot depend on which one it started with.
#[test]
fn import_refuses_tampered_signature_file_with_actionable_error() {
    let scratch = tempfile::tempdir().expect("scratch");
    let src_root = scratch.path().join("src");
    wal_only_instance(&src_root, "alpha", SCHEME_TAG_A, LIST_A, 2);
    let keys = keys(scratch.path(), 0x77);

    let tarball = scratch.path().join("export.tar.zst");
    let receipt = export(&src_root, &tarball, &keys);
    let sig = sig_path(&tarball);
    let pristine: DetachedSignature =
        serde_json::from_slice(&std::fs::read(&sig).expect("read sig")).expect("sig json");
    let original = pristine.signature_hex.as_bytes()[0];

    let mut tampered_sidecars: Vec<(String, Vec<u8>)> = b"0123456789abcdef`gG"
        .iter()
        .filter(|c| **c != original)
        .map(|c| {
            let mut tampered = pristine.clone();
            tampered
                .signature_hex
                .replace_range(0..1, char::from(*c).encode_utf8(&mut [0; 4]));
            (
                format!("leading {:?}", char::from(*c)),
                serde_json::to_vec_pretty(&tampered).expect("sig json"),
            )
        })
        .collect();
    tampered_sidecars.push(("not json".to_owned(), b"{\"kind\":".to_vec()));
    assert_eq!(
        tampered_sidecars.len(),
        19,
        "18 replacements and one torn sidecar"
    );

    for (i, (label, bytes)) in tampered_sidecars.into_iter().enumerate() {
        std::fs::write(&sig, &bytes).expect("write tampered sig");
        let dst_root = scratch.path().join(format!("dst-{i}"));
        let err = import(&tarball, &dst_root, &keys, &receipt.content_hash_hex)
            .expect_err("a tampered signature must refuse");
        assert!(
            matches!(
                typed(&err),
                SnapshotPortError::SignatureVerificationFailed { .. }
            ),
            "{label}: expected SignatureVerificationFailed, got: {err:?}"
        );
        assert!(
            is_empty_or_absent(&dst_root),
            "{label}: destination must remain empty when signature tampering is detected"
        );
    }
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The key is checked before any instance is recovered, so a refusal leaves whatever already
/// sits at the output name exactly as it was.
#[test]
fn an_unusable_signing_key_refuses_before_the_export_publishes_anything() {
    let scratch = tempfile::tempdir().expect("scratch");
    let src_root = scratch.path().join("src");
    wal_only_instance(&src_root, "alpha", SCHEME_TAG_A, LIST_A, 2);
    let out_dir = scratch.path().join("out");
    std::fs::create_dir(&out_dir).expect("output dir");
    let tarball = out_dir.join("export.tar.zst");
    let sig = sig_path(&tarball);
    std::fs::write(&tarball, b"previous export").expect("previous tarball");
    std::fs::write(&sig, b"previous sidecar").expect("previous sidecar");
    let malformed = scratch.path().join("malformed.key");
    std::fs::write(&malformed, b"not a key").expect("malformed key");

    for key in [malformed, scratch.path().join("absent.key")] {
        let err = run_export(ExportOptions {
            data_dir: src_root.clone(),
            output: tarball.clone(),
            signing_key: Some(key.clone()),
            keep_snapshots: 0,
        })
        .expect_err("a key that cannot sign must refuse the export");
        assert!(
            format!("{err:#}").contains("signing"),
            "{}: {err:#}",
            key.display()
        );
        assert!(
            std::fs::read(&tarball).expect("tarball") == b"previous export",
            "{}: the previous export was replaced",
            key.display()
        );
        assert_eq!(std::fs::read(&sig).expect("sidecar"), b"previous sidecar");
        assert_eq!(
            names_in(&out_dir),
            ["export.tar.zst", "export.tar.zst.sig"],
            "{}",
            key.display()
        );
    }
}

#[test]
fn an_export_removes_the_sidecar_of_the_tarball_it_replaces() {
    let scratch = tempfile::tempdir().expect("scratch");
    let src_root = scratch.path().join("src");
    wal_only_instance(&src_root, "alpha", SCHEME_TAG_A, LIST_A, 2);
    let tarball = scratch.path().join("export.tar.zst");
    let sig = sig_path(&tarball);
    std::fs::write(&tarball, b"previous export").expect("previous tarball");
    std::fs::write(&sig, b"previous sidecar").expect("previous sidecar");

    let receipt = run_export(ExportOptions {
        data_dir: src_root,
        output: tarball.clone(),
        signing_key: None,
        keep_snapshots: 0,
    })
    .expect("unsigned export");

    assert!(receipt.public_key_hex.is_none());
    assert_ne!(
        std::fs::read(&tarball).expect("tarball"),
        b"previous export"
    );
    assert!(
        !sig.exists(),
        "a sidecar left beside the new tarball signs the one it replaced"
    );
}
