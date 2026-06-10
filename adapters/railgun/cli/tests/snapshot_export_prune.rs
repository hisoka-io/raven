//! Snapshot export-tarball pruning: `prune_old_export_tarballs` keeps the
//! `keep_last_n` newest `*.tar.zst` by mtime, dropping paired `.sig` sidecars,
//! and `run_export` invokes it after each successful write.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]
#![cfg(test)]

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use raven_railgun_cli::snapshot_port::{
    prune_old_export_tarballs, run_export, run_prune, ExportOptions, PruneOptions,
};
use raven_railgun_persistence::{
    Manifest, Snapshot, SnapshotId, StoreLayout, MANIFEST_SCHEMA_VERSION, SNAPSHOT_MAGIC,
};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-cache-session";

/// Minimal manifest+snapshot data_dir so `run_export` has one instance to walk.
fn bootstrap_minimal_instance(root: &Path, instance_id: &str, payload: &[u8]) {
    let inst_dir = root.join(instance_id);
    let layout = StoreLayout::open(&inst_dir).expect("StoreLayout::open");
    let snap = Snapshot::build(payload.to_vec(), SNAPSHOT_MAGIC);
    let snap_id = SnapshotId(7);
    snap.save(&layout, snap_id).expect("snapshot save");
    let manifest = Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        scheme_tag: SCHEME_TAG.to_owned(),
        instance_id: instance_id.to_owned(),
        current_snapshot_id: snap_id,
        current_snapshot_seq: 1,
        current_marker: 100,
        encoder_label: "per-leaf-bc".to_owned(),
        prev_encoder_label: None,
    };
    manifest.save(&layout).expect("manifest save");
}

/// Write `bytes` and stamp `mtime` deterministically.
fn write_with_mtime(path: &Path, bytes: &[u8], mtime: SystemTime) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::write(path, bytes).expect("write");
    let f = std::fs::File::options()
        .write(true)
        .open(path)
        .expect("open for set_modified");
    f.set_modified(mtime).expect("set_modified");
}

fn list_tarballs(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(dir)
        .expect("read_dir")
        .filter_map(Result::ok)
        .filter_map(|e| {
            let p = e.path();
            if p.is_file()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|s| s.ends_with(".tar.zst"))
            {
                p.file_name().and_then(|n| n.to_str()).map(str::to_owned)
            } else {
                None
            }
        })
        .collect();
    out.sort();
    out
}

#[test]
fn prune_old_export_tarballs_keeps_last_3_by_mtime() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let dir = scratch.path();
    let now = SystemTime::now();
    for (i, name) in [
        "e0.tar.zst",
        "e1.tar.zst",
        "e2.tar.zst",
        "e3.tar.zst",
        "e4.tar.zst",
    ]
    .iter()
    .enumerate()
    {
        let mtime = now - Duration::from_secs(u64::try_from((4 - i) * 10).unwrap());
        write_with_mtime(&dir.join(name), b"dummy-tarball-payload", mtime);
    }

    let removed = prune_old_export_tarballs(dir, 3).expect("prune");
    assert_eq!(removed, 2, "expected 2 oldest tarballs removed");
    let remaining = list_tarballs(dir);
    assert_eq!(remaining, vec!["e2.tar.zst", "e3.tar.zst", "e4.tar.zst"]);
}

#[test]
fn prune_old_export_tarballs_removes_paired_sig_sidecar_with_tarball() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let dir = scratch.path();
    let now = SystemTime::now();
    let names = ["a.tar.zst", "b.tar.zst", "c.tar.zst", "d.tar.zst"];
    for (i, n) in names.iter().enumerate() {
        let mtime = now - Duration::from_secs(u64::try_from((3 - i) * 10).unwrap());
        let tar = dir.join(n);
        write_with_mtime(&tar, b"tarball", mtime);
        let mut sig_path = tar.as_os_str().to_owned();
        sig_path.push(".sig");
        write_with_mtime(&PathBuf::from(sig_path), b"sig", mtime);
    }

    let removed = prune_old_export_tarballs(dir, 2).expect("prune");
    assert_eq!(removed, 2);
    assert!(!dir.join("a.tar.zst").exists());
    assert!(
        !dir.join("a.tar.zst.sig").exists(),
        "paired .sig must be pruned"
    );
    assert!(!dir.join("b.tar.zst").exists());
    assert!(
        !dir.join("b.tar.zst.sig").exists(),
        "paired .sig must be pruned"
    );
    assert!(dir.join("c.tar.zst").exists());
    assert!(dir.join("c.tar.zst.sig").exists());
    assert!(dir.join("d.tar.zst").exists());
    assert!(dir.join("d.tar.zst.sig").exists());
}

#[test]
fn prune_old_export_tarballs_zero_when_count_below_keep() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let dir = scratch.path();
    let now = SystemTime::now();
    write_with_mtime(&dir.join("only.tar.zst"), b"x", now);

    let removed = prune_old_export_tarballs(dir, 3).expect("prune");
    assert_eq!(removed, 0);
    assert!(dir.join("only.tar.zst").exists());

    // keep=0 disables pruning
    for i in 0..5 {
        write_with_mtime(
            &dir.join(format!("k{i}.tar.zst")),
            b"y",
            now - Duration::from_secs(u64::try_from(i).unwrap()),
        );
    }
    let removed_disabled = prune_old_export_tarballs(dir, 0).expect("prune disabled");
    assert_eq!(removed_disabled, 0);
}

#[test]
fn prune_snapshots_subcommand_removes_oldest_tarballs() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let dir = scratch.path();
    let now = SystemTime::now();
    let names = [
        "x0.tar.zst",
        "x1.tar.zst",
        "x2.tar.zst",
        "x3.tar.zst",
        "x4.tar.zst",
    ];
    for (i, n) in names.iter().enumerate() {
        let mtime = now - Duration::from_secs(u64::try_from((4 - i) * 30).unwrap());
        write_with_mtime(&dir.join(n), b"tarball-payload", mtime);
    }

    run_prune(PruneOptions {
        data_dir: dir.to_path_buf(),
        keep_snapshots: 2,
    })
    .expect("run_prune");

    let remaining = list_tarballs(dir);
    assert_eq!(
        remaining,
        vec!["x3.tar.zst", "x4.tar.zst"],
        "expected only 2 newest tarballs to survive prune-snapshots subcommand"
    );
}

#[test]
fn prune_snapshots_keeps_paired_sig_sidecars_with_kept_tarballs() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let dir = scratch.path();
    let now = SystemTime::now();
    let names = ["a.tar.zst", "b.tar.zst", "c.tar.zst"];
    for (i, n) in names.iter().enumerate() {
        let mtime = now - Duration::from_secs(u64::try_from((2 - i) * 60).unwrap());
        let tar = dir.join(n);
        write_with_mtime(&tar, b"tarball", mtime);
        let mut sig_path = tar.as_os_str().to_owned();
        sig_path.push(".sig");
        write_with_mtime(&PathBuf::from(sig_path), b"sig", mtime);
    }

    run_prune(PruneOptions {
        data_dir: dir.to_path_buf(),
        keep_snapshots: 2,
    })
    .expect("run_prune");

    assert!(
        !dir.join("a.tar.zst").exists(),
        "oldest tarball must be pruned"
    );
    assert!(
        !dir.join("a.tar.zst.sig").exists(),
        "oldest tarball's paired .sig sidecar must be pruned"
    );
    assert!(dir.join("b.tar.zst").exists());
    assert!(
        dir.join("b.tar.zst.sig").exists(),
        "kept tarball's paired .sig sidecar must survive"
    );
    assert!(dir.join("c.tar.zst").exists());
    assert!(
        dir.join("c.tar.zst.sig").exists(),
        "kept tarball's paired .sig sidecar must survive"
    );
}

#[test]
fn prune_snapshots_zero_when_count_below_keep() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let dir = scratch.path();
    let now = SystemTime::now();
    write_with_mtime(&dir.join("only.tar.zst"), b"x", now);

    run_prune(PruneOptions {
        data_dir: dir.to_path_buf(),
        keep_snapshots: 5,
    })
    .expect("run_prune below-keep");
    assert!(
        dir.join("only.tar.zst").exists(),
        "single tarball must survive when count < --keep"
    );

    // keep=0 disables pruning
    for i in 0..3 {
        write_with_mtime(
            &dir.join(format!("z{i}.tar.zst")),
            b"y",
            now - Duration::from_secs(u64::try_from(i + 1).unwrap()),
        );
    }
    let pre = list_tarballs(dir).len();
    run_prune(PruneOptions {
        data_dir: dir.to_path_buf(),
        keep_snapshots: 0,
    })
    .expect("run_prune disabled");
    assert_eq!(
        list_tarballs(dir).len(),
        pre,
        "keep_snapshots=0 must be a no-op even when many tarballs are present"
    );

    // missing dir must not error
    let missing = scratch.path().join("does-not-exist");
    run_prune(PruneOptions {
        data_dir: missing,
        keep_snapshots: 3,
    })
    .expect("run_prune missing-dir");
}

#[test]
fn export_snapshot_invokes_pruner_after_write() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let src_root = scratch.path().join("src");
    std::fs::create_dir_all(&src_root).expect("mkdir src");
    bootstrap_minimal_instance(&src_root, "alpha", b"deadbeef-payload");

    // pre-seed stale tarballs the export must prune
    let parent = scratch.path().join("snapshots");
    std::fs::create_dir_all(&parent).expect("mkdir snapshots");
    let now = SystemTime::now();
    for i in 0..4 {
        write_with_mtime(
            &parent.join(format!("stale-{i:02}.tar.zst")),
            b"stale",
            now - Duration::from_secs(u64::try_from((4 - i) * 60).unwrap()),
        );
    }
    let pre_count = list_tarballs(&parent).len();
    assert_eq!(pre_count, 4);

    let fresh = parent.join("fresh.tar.zst");
    run_export(ExportOptions {
        data_dir: src_root,
        output: fresh.clone(),
        signing_key: None,
        include_current_wal: false,
        keep_snapshots: 2,
    })
    .expect("run_export");

    let post = list_tarballs(&parent);
    assert!(
        post.contains(&"fresh.tar.zst".to_owned()),
        "fresh tarball must remain after prune; got: {post:?}"
    );
    assert_eq!(
        post.len(),
        2,
        "expected 2 tarballs (keep_snapshots=2) after run_export prune; got: {post:?}"
    );
}
