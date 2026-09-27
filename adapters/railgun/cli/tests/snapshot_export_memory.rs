//! Export memory against the instance count.
//!
//! Its own target, so its one test is alone in its process under `cargo test` as under nextest:
//! `VmHWM` is per process, and a sibling test running beside it would move the peak it reads.

#![allow(clippy::expect_used, clippy::panic)]
#![cfg(target_os = "linux")]

#[path = "support/snapshot_fixture.rs"]
mod snapshot_fixture;

use std::path::Path;

use raven_railgun_cli::snapshot_port::{run_export, ExportOptions};
use snapshot_fixture::{wal_only_instance, LIST_A, SCHEME_TAG_A};

/// Peak resident set of this process so far.
fn peak_rss_bytes() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
    let kib: u64 = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|value| value.trim().strip_suffix("kB"))
        .and_then(|kib| kib.trim().parse().ok())
        .unwrap_or_else(|| panic!("no VmHWM in /proc/self/status: {status}"));
    kib * 1024
}

/// An export runs on the box that serves, beside the node's own memory, so it holds one
/// instance's bytes at a time: four instances need no more than one does.
#[test]
fn export_memory_does_not_grow_with_the_instance_count() {
    const PAYLOAD: u64 = 32 << 20;
    let scratch = tempfile::tempdir().expect("scratch");
    let heavy = |root: &Path, id: &str| {
        let dir = wal_only_instance(root, id, SCHEME_TAG_A, LIST_A, 1);
        // Recovery never reads a sealed segment, so this adds bytes to carry and no replay work.
        let sealed = dir.join("wal/archived/seq-00000000000000000000-00000000000000000000.log");
        std::fs::File::create(&sealed)
            .and_then(|f| f.set_len(PAYLOAD))
            .expect("sealed segment");
    };
    let one = scratch.path().join("one");
    heavy(&one, "solo");
    let four = scratch.path().join("four");
    for i in 0..4 {
        heavy(&four, &format!("inst-{i}"));
    }
    let export_unsigned = |root: &Path, name: &str| {
        run_export(ExportOptions {
            data_dir: root.to_path_buf(),
            output: scratch.path().join(name),
            signing_key: None,
            keep_snapshots: 0,
        })
        .expect("export")
    };

    export_unsigned(&one, "one.tar.zst");
    let after_one = peak_rss_bytes();
    let receipt = export_unsigned(&four, "four.tar.zst");
    let after_four = peak_rss_bytes();

    assert_eq!(receipt.instances.len(), 4);
    let growth = after_four.saturating_sub(after_one);
    assert!(
        growth < PAYLOAD,
        "exporting four instances of {PAYLOAD} B raised the peak by {growth} B over exporting one \
         (peak {after_one} B, then {after_four} B)"
    );
}
