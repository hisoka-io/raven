//! A transplant carries the state the source data_dir holds, proves it on the destination with
//! only the shipped binary, and is bound to the one export the deploy record names.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]
#![cfg(test)]

#[path = "support/snapshot_fixture.rs"]
mod snapshot_fixture;

use std::path::Path;
use std::process::{Command, Output};

use raven_railgun_cli::snapshot_port::{
    run_export, ExportOptions, ExportReceipt, SnapshotPortError,
};
use raven_railgun_engine::imt::Imt;
use raven_railgun_engine::persistence::{
    clear_layer2_divergent, clear_wal_replay_skipped, layer2_divergent_instances,
    mark_wal_replay_skipped,
};
use raven_railgun_persistence::WalEntryPayload;
use snapshot_fixture::{
    encoder, expected_store, export, import, is_empty_or_absent, keys, list_rows, open,
    read_tarball, reforge, restitch, rewrite_manifest, siblings_with_prefix, sig_path, store_of,
    sync_more, synced_instance, wal_only_instance, wal_only_instance_of, write_signature,
    ENTRIES_PER_SHARD, LIST_A, SCHEME_TAG_A,
};

const LIVE_LOG: &str = "instances/alpha/wal/current.log";

fn typed(err: &anyhow::Error) -> &SnapshotPortError {
    err.downcast_ref::<SnapshotPortError>()
        .unwrap_or_else(|| panic!("untyped error: {err:?}"))
}

fn copy_export(from: &Path, to: &Path) {
    std::fs::copy(from, to).expect("copy tarball");
    std::fs::copy(sig_path(from), sig_path(to)).expect("copy sidecar");
}

/// Two genuine signed exports of one instance: `older` at `first` rows, `current` at `total`.
fn two_exports(scratch: &Path, first: u32, total: u32) -> (ExportReceipt, ExportReceipt) {
    let src = scratch.join("src");
    let alpha = wal_only_instance(&src, "alpha", SCHEME_TAG_A, LIST_A, first);
    let keys = keys(scratch, 0x33);
    let older = export(&src, &scratch.join("older.tar.zst"), &keys);
    sync_more(&alpha, "alpha", SCHEME_TAG_A, LIST_A, first..total);
    let current = export(&src, &scratch.join("current.tar.zst"), &keys);
    assert_ne!(older.content_hash_hex, current.content_hash_hex);
    (older, current)
}

/// One genuine signed export of one instance holding `rows`.
fn one_export(scratch: &Path, rows: u32) -> ExportReceipt {
    let src = scratch.join("src");
    wal_only_instance(&src, "alpha", SCHEME_TAG_A, LIST_A, rows);
    export(&src, &scratch.join("current.tar.zst"), &keys(scratch, 0x33))
}

#[test]
fn an_export_right_after_a_sync_carries_the_live_log_and_the_import_serves_the_same_rows() {
    // Every row lands in shard 0 either way; the property is the shape, not the row count.
    const ROWS: u32 = 20;
    let scratch = tempfile::tempdir().expect("scratch");
    let src = scratch.path().join("src");
    let alpha = synced_instance(&src, "alpha", SCHEME_TAG_A, LIST_A, ROWS);

    // The shape a synced static instance has on disk: nothing archived, every row live.
    let live_len = std::fs::metadata(alpha.join("wal/current.log"))
        .expect("live log")
        .len();
    assert!(live_len > 0, "the sync wrote its rows to the live log");
    let archived: u64 = std::fs::read_dir(alpha.join("wal/archived"))
        .expect("archived dir")
        .map(|e| e.expect("entry").metadata().expect("meta").len())
        .sum();
    assert_eq!(archived, 0, "the sync committed none of its rows");

    let keys = keys(scratch.path(), 0x21);
    let tarball = scratch.path().join("export.tar.zst");
    let receipt = export(&src, &tarball, &keys);
    let (manifest, files) = read_tarball(&tarball);
    let listed = manifest.instances[0]
        .files
        .iter()
        .find(|f| f.rel_path == "wal/current.log")
        .expect("the default export lists the live log");
    assert_eq!(listed.byte_len, live_len);
    assert_eq!(u64::try_from(files[LIVE_LOG].len()).expect("len"), live_len);

    let dst = scratch.path().join("dst");
    let imported = import(&tarball, &dst, &keys, &receipt.content_hash_hex).expect("import");
    assert_eq!(imported.instances, receipt.instances);

    let expected = expected_store(LIST_A, ROWS);
    let restored = open(&dst.join("alpha"), "alpha", SCHEME_TAG_A, LIST_A);
    let store = &restored.recovered_logical_store;
    let rows = usize::try_from(ROWS).expect("rows");
    assert_eq!(store.ppoi_imt(&LIST_A).map(Imt::leaf_count), Some(rows));
    assert_eq!(
        store.ppoi_imt_root(&LIST_A),
        expected.ppoi_imt_root(&LIST_A)
    );
    for i in 0..ROWS {
        assert_eq!(
            store.ppoi_bc_at(&LIST_A, i),
            expected.ppoi_bc_at(&LIST_A, i)
        );
        assert_eq!(
            store.ppoi_status_at(&LIST_A, i),
            expected.ppoi_status_at(&LIST_A, i)
        );
    }
    let enc = encoder(LIST_A);
    for shard in 0..=ROWS / ENTRIES_PER_SHARD {
        assert_eq!(
            enc.materialize_shard(shard, store),
            enc.materialize_shard(shard, &expected),
            "shard {shard} rows served after the transplant"
        );
    }
}

#[test]
fn an_older_genuine_export_is_refused_against_the_pinned_hash() {
    let scratch = tempfile::tempdir().expect("scratch");
    let (older, current) = two_exports(scratch.path(), 20, 50);
    let keys = keys(scratch.path(), 0x33);

    let dst = scratch.path().join("dst");
    let err = import(&older.output, &dst, &keys, &current.content_hash_hex)
        .expect_err("a genuine but older export must not install");
    match typed(&err) {
        SnapshotPortError::ExpectedContentHashMismatch { expected, found } => {
            assert_eq!(expected, &current.content_hash_hex);
            assert_eq!(found, &older.content_hash_hex);
        }
        other => panic!("expected ExpectedContentHashMismatch, got {other:?}"),
    }
    assert!(
        is_empty_or_absent(&dst),
        "nothing written for a stale export"
    );

    let imported = import(&current.output, &dst, &keys, &current.content_hash_hex)
        .expect("the pinned export installs");
    assert_eq!(imported.instances, current.instances);
    assert_eq!(imported.instances[0].1.lists[0].leaf_count, 50);
}

#[test]
fn a_byte_perfect_signed_export_that_recovers_to_other_rows_fails_the_post_import_check() {
    let scratch = tempfile::tempdir().expect("scratch");
    let src = scratch.path().join("src");
    let alpha = wal_only_instance(&src, "alpha", SCHEME_TAG_A, LIST_A, 20);
    // The bytes an export taken now would carry as its live log.
    let older_log = std::fs::read(alpha.join("wal/current.log")).expect("live log at 20 rows");
    sync_more(&alpha, "alpha", SCHEME_TAG_A, LIST_A, 20..50);
    let keys = keys(scratch.path(), 0x33);
    let current = export(&src, &scratch.path().join("current.tar.zst"), &keys);

    // The live log dropped from an otherwise intact, re-signed export: the old default.
    let dropped = scratch.path().join("dropped.tar.zst");
    copy_export(&current.output, &dropped);
    let dropped_hash = reforge(&dropped, &keys.key, |_, files| {
        files.remove(LIVE_LOG).expect("live log present");
    });
    // A genuine older log under the newer manifest.
    let swapped = scratch.path().join("swapped.tar.zst");
    copy_export(&current.output, &swapped);
    let swapped_hash = reforge(&swapped, &keys.key, |_, files| {
        files.insert(LIVE_LOG.to_owned(), older_log);
    });

    for (label, tarball, hash) in [
        ("dropped", &dropped, &dropped_hash),
        ("swapped", &swapped, &swapped_hash),
    ] {
        let dst = scratch.path().join(format!("dst-{label}"));
        let err = import(tarball, &dst, &keys, hash)
            .expect_err("data that recovers to other rows must not install");
        match typed(&err) {
            SnapshotPortError::RecoveredStateMismatch { instance, detail } => {
                assert_eq!(instance, "alpha", "{label}");
                assert!(detail.contains("ppoi_row_count"), "{label}: {detail}");
            }
            other => panic!("{label}: expected RecoveredStateMismatch, got {other:?}"),
        }
        assert!(is_empty_or_absent(&dst), "{label}: destination untouched");
        assert!(
            siblings_with_prefix(scratch.path(), &format!("dst-{label}.staging.")).is_empty(),
            "{label}: staging removed"
        );
    }
}

type RowEdit = fn(&mut WalEntryPayload);

#[test]
fn a_signed_export_with_the_same_row_count_but_other_rows_fails_the_post_import_check() {
    const ROWS: u32 = 50;
    const ROW: u32 = 17;
    let scratch = tempfile::tempdir().expect("scratch");
    let current = one_export(scratch.path(), ROWS);
    let keys = keys(scratch.path(), 0x33);
    let expected = expected_store(LIST_A, ROWS);

    let cases: [(&str, RowEdit); 2] = [
        ("status", |row| {
            if let WalEntryPayload::PpoiListLeafAdded { status, .. } = row {
                *status = 2;
            }
        }),
        ("commitment", |row| {
            if let WalEntryPayload::PpoiListLeafAdded {
                blinded_commitment, ..
            } = row
            {
                blinded_commitment[2] = 0x5a;
            }
        }),
    ];
    for (label, edit) in cases {
        let mut rows = list_rows(LIST_A, ROWS);
        edit(&mut rows[usize::try_from(ROW).expect("row")]);
        let forged = store_of(LIST_A, &rows);
        assert_eq!(forged.ppoi_count(), expected.ppoi_count(), "{label}");
        assert_eq!(
            forged.ppoi_imt(&LIST_A).map(Imt::leaf_count),
            expected.ppoi_imt(&LIST_A).map(Imt::leaf_count),
            "{label}"
        );
        assert_ne!(
            (
                forged.ppoi_bc_at(&LIST_A, ROW),
                forged.ppoi_status_at(&LIST_A, ROW)
            ),
            (
                expected.ppoi_bc_at(&LIST_A, ROW),
                expected.ppoi_status_at(&LIST_A, ROW)
            ),
            "{label}: the forged rows hold other content at row {ROW}"
        );
        let forged_dir = wal_only_instance_of(
            &scratch.path().join(format!("forged-{label}")),
            "alpha",
            SCHEME_TAG_A,
            LIST_A,
            &rows,
        );
        let log = std::fs::read(forged_dir.join("wal/current.log")).expect("forged live log");

        let tarball = scratch.path().join(format!("forged-{label}.tar.zst"));
        copy_export(&current.output, &tarball);
        let hash = reforge(&tarball, &keys.key, |_, files| {
            files.insert(LIVE_LOG.to_owned(), log);
        });
        let dst = scratch.path().join(format!("dst-{label}"));
        let err = import(&tarball, &dst, &keys, &hash)
            .expect_err("rows other than the recorded ones must not install");
        match typed(&err) {
            SnapshotPortError::RecoveredStateMismatch { instance, detail } => {
                assert_eq!(instance, "alpha", "{label}");
                assert!(
                    !detail.starts_with("leaf_count") && !detail.starts_with("ppoi_row_count"),
                    "{label}: the counts agree, so the refusal must name content: {detail}"
                );
            }
            other => panic!("{label}: expected RecoveredStateMismatch, got {other:?}"),
        }
        assert!(is_empty_or_absent(&dst), "{label}: destination untouched");
        assert!(
            siblings_with_prefix(scratch.path(), &format!("dst-{label}.staging.")).is_empty(),
            "{label}: staging removed"
        );
    }
}

/// Each edit is consistent with itself and rehashed, and the genuine sidecar is kept. The same
/// edit left unrehashed is refused earlier, by the manifest's own hash.
#[test]
fn every_identity_field_class_is_inside_the_signature() {
    let scratch = tempfile::tempdir().expect("scratch");
    let (older, current) = two_exports(scratch.path(), 20, 50);
    let keys = keys(scratch.path(), 0x33);
    let (older_manifest, older_files) = read_tarball(&older.output);

    let stale_field = scratch.path().join("stale-field.tar.zst");
    copy_export(&current.output, &stale_field);
    rewrite_manifest(&stale_field, |m| m.exported_at_unix_ms += 1);
    let dst = scratch.path().join("dst-stale-field");
    let err = import(&stale_field, &dst, &keys, &current.content_hash_hex)
        .expect_err("an edited export time must not verify");
    assert!(
        matches!(typed(&err), SnapshotPortError::ContentHashMismatch),
        "unrehashed exported_at: {err:?}"
    );
    assert!(
        is_empty_or_absent(&dst),
        "unrehashed exported_at: destination untouched"
    );

    for label in ["instance_count", "shared_crs", "instances", "exported_at"] {
        let tarball = scratch.path().join(format!("{label}.tar.zst"));
        copy_export(&current.output, &tarball);
        let rehashed = restitch(&tarball, |m, files| match label {
            "instance_count" => m.instance_count += 1,
            "shared_crs" => m.shared_crs[0].scheme_tag.push('x'),
            "exported_at" => m.exported_at_unix_ms += 1,
            "instances" => {
                m.instances.clone_from(&older_manifest.instances);
                files.retain(|name, _| !name.starts_with("instances/"));
                files.extend(
                    older_files
                        .iter()
                        .filter(|(name, _)| name.starts_with("instances/"))
                        .map(|(name, bytes)| (name.clone(), bytes.clone())),
                );
            }
            other => unreachable!("no edit for {other}"),
        });
        let dst = scratch.path().join(format!("dst-{label}"));
        let err = import(&tarball, &dst, &keys, &current.content_hash_hex)
            .expect_err("an edit the signer never saw must not install");
        assert!(
            matches!(typed(&err), SnapshotPortError::SignatureContentHashMismatch),
            "{label}: {err:?}"
        );
        assert!(is_empty_or_absent(&dst), "{label}: destination untouched");
        assert_ne!(rehashed, current.content_hash_hex, "{label}");
    }
}

#[test]
fn a_signature_without_the_domain_tag_or_with_the_old_sidecar_kind_does_not_verify() {
    let scratch = tempfile::tempdir().expect("scratch");
    let src = scratch.path().join("src");
    wal_only_instance(&src, "alpha", SCHEME_TAG_A, LIST_A, 4);
    let keys = keys(scratch.path(), 0x55);
    let receipt = export(&src, &scratch.path().join("export.tar.zst"), &keys);
    let hash = receipt.content_hash_hex.clone();
    let raw_hash = hex::decode(&hash).expect("hex");

    for (label, message) in [("raw", raw_hash.as_slice()), ("hex", hash.as_bytes())] {
        write_signature(&receipt.output, &keys.key, &hash, message);
        let err = import(
            &receipt.output,
            &scratch.path().join(format!("dst-{label}")),
            &keys,
            &hash,
        )
        .expect_err("an undomained signature must not verify");
        assert!(
            matches!(
                typed(&err),
                SnapshotPortError::SignatureVerificationFailed { .. }
            ),
            "{label}: {err:?}"
        );
    }

    let message =
        raven_railgun_cli::snapshot_port::signature_message(&hash).expect("domained message");
    write_signature(&receipt.output, &keys.key, &hash, &message);
    let sig = sig_path(&receipt.output);
    let mut detached: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&sig).expect("read sig")).expect("sig json");
    detached["kind"] = serde_json::Value::from("raven-railgun-export-sig/v1");
    std::fs::write(&sig, serde_json::to_vec(&detached).expect("json")).expect("write sig");
    let err = import(
        &receipt.output,
        &scratch.path().join("dst-kind"),
        &keys,
        &hash,
    )
    .expect_err("an old sidecar kind must not verify");
    assert!(
        matches!(typed(&err), SnapshotPortError::SignatureKindMismatch { .. }),
        "{err:?}"
    );
}

#[test]
fn an_export_whose_replay_skips_a_row_is_refused() {
    let scratch = tempfile::tempdir().expect("scratch");
    let src = scratch.path().join("src");
    // Its own id: the skip record is per process, and "alpha" is recovered by other tests.
    let gapped = wal_only_instance(&src, "gapped", SCHEME_TAG_A, LIST_A, 10);
    // `apply_event` is the raw WAL append; the consumer's contiguity screen is not in front of it.
    let opened = open(&gapped, "gapped", SCHEME_TAG_A, LIST_A);
    opened
        .persistence
        .apply_event(&snapshot_fixture::list_leaf(LIST_A, 12), 500)
        .expect("append a gapped row");
    drop(opened);

    let tarball = scratch.path().join("export.tar.zst");
    let err = run_export(ExportOptions {
        data_dir: src,
        output: tarball.clone(),
        signing_key: None,
        keep_snapshots: 0,
    })
    .expect_err("a data_dir that recovers only by skipping rows must not export");
    assert!(
        matches!(typed(&err), SnapshotPortError::ReplaySkipped { instance } if instance == "gapped"),
        "{err:?}"
    );
    assert!(!tarball.exists(), "no tarball for a refused export");
    let left: Vec<String> = std::fs::read_dir(scratch.path())
        .expect("read scratch")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|name| name != "src")
        .collect();
    assert!(
        left.is_empty(),
        "a refused export leaves no partial archive or recovery scratch: {left:?}"
    );
}

#[test]
fn a_replay_skip_this_process_already_recorded_fails_closed() {
    const ID: &str = "marked";
    let scratch = tempfile::tempdir().expect("scratch");
    let src = scratch.path().join("src");
    wal_only_instance(&src, ID, SCHEME_TAG_A, LIST_A, 4);
    let tarball = scratch.path().join("export.tar.zst");

    mark_wal_replay_skipped(ID);
    let result = run_export(ExportOptions {
        data_dir: src,
        output: tarball.clone(),
        signing_key: None,
        keep_snapshots: 0,
    });
    clear_wal_replay_skipped(ID);
    let err = result.expect_err("a replay this process cannot prove clean must not export");
    assert!(
        matches!(typed(&err), SnapshotPortError::ReplaySkipped { instance } if instance == ID),
        "{err:?}"
    );
    assert!(!tarball.exists(), "no tarball for a refused export");
}

#[test]
fn a_divergence_marker_travels_with_the_instance() {
    const ID: &str = "diverged";
    let scratch = tempfile::tempdir().expect("scratch");
    let src = scratch.path().join("src");
    let dir = wal_only_instance(&src, ID, SCHEME_TAG_A, LIST_A, 4);
    open(&dir, ID, SCHEME_TAG_A, LIST_A)
        .persistence
        .mark_layer2_divergent()
        .expect("mark the tree divergent");
    let keys = keys(scratch.path(), 0x7a);
    let tarball = scratch.path().join("export.tar.zst");
    let receipt = export(&src, &tarball, &keys);
    let dst = scratch.path().join("dst");
    import(&tarball, &dst, &keys, &receipt.content_hash_hex).expect("import");

    // Both recoveries re-marked it in this process; only the destination's own files may now.
    clear_layer2_divergent(ID);
    drop(open(&dst.join(ID), ID, SCHEME_TAG_A, LIST_A));
    let marked = layer2_divergent_instances().iter().any(|id| id == ID);
    clear_layer2_divergent(ID);
    assert!(
        marked,
        "the destination must still report the unrepaired tree"
    );
}

fn binary(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_raven-railgun"))
        .args(args)
        .output()
        .expect("run raven-railgun")
}

fn content_hash_line(stdout: &[u8]) -> String {
    let out = text(stdout);
    let found = out
        .lines()
        .find_map(|l| l.strip_prefix("content_hash_hex = "));
    found
        .unwrap_or_else(|| panic!("no content hash in {out}"))
        .to_owned()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn the_shipped_binary_alone_refuses_a_stale_export_and_installs_the_current_one() {
    let scratch = tempfile::tempdir().expect("scratch");
    let src = scratch.path().join("src");
    let alpha = wal_only_instance(&src, "alpha", SCHEME_TAG_A, LIST_A, 20);
    let keys = keys(scratch.path(), 0x66);
    let path = |p: &Path| p.to_str().expect("utf8 path").to_owned();
    let export_to = |name: &str| {
        let out = binary(&[
            "export-snapshot",
            "--data-dir",
            &path(&src),
            "--output",
            &path(&scratch.path().join(name)),
            "--sign",
            "--signing-key",
            &path(&keys.signing),
            "--keep-snapshots",
            "0",
        ]);
        assert!(out.status.success(), "export: {}", text(&out.stderr));
        content_hash_line(&out.stdout)
    };
    let older = export_to("older.tar.zst");
    sync_more(&alpha, "alpha", SCHEME_TAG_A, LIST_A, 20..50);
    let current = export_to("current.tar.zst");
    let import_from = |name: &str, dst: &str| {
        binary(&[
            "import-snapshot",
            "--input",
            &path(&scratch.path().join(name)),
            "--data-dir",
            &path(&scratch.path().join(dst)),
            "--verifying-key",
            &path(&keys.verifying),
            "--expect-content-hash",
            &current,
        ])
    };

    let stale = import_from("older.tar.zst", "dst-stale");
    assert!(!stale.status.success(), "a stale export must be refused");
    let stderr = text(&stale.stderr);
    assert!(
        stderr.contains(&older) && stderr.contains(&current),
        "{stderr}"
    );
    assert!(is_empty_or_absent(&scratch.path().join("dst-stale")));

    let installed = import_from("current.tar.zst", "dst");
    assert!(installed.status.success(), "{}", text(&installed.stderr));
    let stdout = text(&installed.stdout);
    assert!(stdout.contains(&current), "{stdout}");
    assert!(stdout.contains("leaves=50"), "{stdout}");
}

#[test]
fn the_binary_offers_no_flag_that_skips_verification_or_drops_the_live_log() {
    let pin = "00".repeat(32);
    for (args, flag) in [
        (
            vec![
                "import-snapshot",
                "--input",
                "x.tar.zst",
                "--data-dir",
                "d",
                "--verifying-key",
                "k",
                "--expect-content-hash",
                pin.as_str(),
                "--unsafe-no-verify",
            ],
            "--unsafe-no-verify",
        ),
        (
            vec![
                "import-snapshot",
                "--input",
                "x.tar.zst",
                "--data-dir",
                "d",
                "--expect-content-hash",
                pin.as_str(),
            ],
            "--verifying-key",
        ),
        (
            vec![
                "import-snapshot",
                "--input",
                "x.tar.zst",
                "--data-dir",
                "d",
                "--verifying-key",
                "k",
            ],
            "--expect-content-hash",
        ),
        (
            vec![
                "export-snapshot",
                "--data-dir",
                "d",
                "--output",
                "x.tar.zst",
                "--include-current-wal",
            ],
            "--include-current-wal",
        ),
    ] {
        let out = binary(&args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?}: {}",
            text(&out.stderr)
        );
        assert!(
            text(&out.stderr).contains(flag),
            "{args:?}: {}",
            text(&out.stderr)
        );
    }
}
