//! Chaos coverage for `Snapshot::save`'s two-rename pipeline.
//!
//! Forks `snapshot_chaos_child`, SIGKILLs at deterministic step windows, then asserts
//! `Snapshot::load` recovers the correct payload without torn state.
//! Exercises the real fsync + kernel rename path that in-process synthetic tests cannot reach.
//!
//! Run via:
//!   cargo test --manifest-path adapters/railgun/Cargo.toml \
//!     -p raven-railgun-persistence --features chaos-tests \
//!     --test snapshot_chaos_save_two_rename -- --nocapture

#![cfg(feature = "chaos-tests")]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::cast_possible_truncation
)]

use raven_railgun_persistence::{Snapshot, SnapshotId, StoreLayout, SNAPSHOT_MAGIC};
use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

const BASE_PAYLOAD: &[u8] = b"raven c8 chaos: base prior-good payload";
const NEW_PAYLOAD: &[u8] = b"raven c8 chaos: new winning payload";
const SNAP_ID: u64 = 5;
const PAUSE_MS: u64 = 250;
const MARKER_TIMEOUT: Duration = Duration::from_secs(20);

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let hi = HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0');
        let lo = HEX.get(usize::from(b & 0x0f)).copied().unwrap_or(b'0');
        out.push(hi as char);
        out.push(lo as char);
    }
    out
}

fn spawn_child(data_dir: &std::path::Path) -> (Child, BufReader<ChildStdout>) {
    let bin = env!("CARGO_BIN_EXE_snapshot_chaos_child");
    let mut child = Command::new(bin)
        .arg("--data-dir")
        .arg(data_dir)
        .arg("--pause-ms")
        .arg(PAUSE_MS.to_string())
        .arg("--base-payload")
        .arg(to_hex(BASE_PAYLOAD))
        .arg("--new-payload")
        .arg(to_hex(NEW_PAYLOAD))
        .arg("--id")
        .arg(SNAP_ID.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn snapshot_chaos_child");
    let stdout = child.stdout.take().expect("child stdout");
    (child, BufReader::new(stdout))
}

fn wait_for_marker(reader: &mut BufReader<ChildStdout>, target: &str) -> Result<(), String> {
    let deadline = Instant::now() + MARKER_TIMEOUT;
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => return Err(format!("child stdout EOF before `{target}`")),
            Ok(_) => {
                let trimmed = line.trim_end();
                eprintln!("child> {trimmed}");
                if trimmed == target {
                    return Ok(());
                }
            }
            Err(e) => return Err(format!("read child stdout: {e}")),
        }
    }
    Err(format!("timeout waiting for marker `{target}`"))
}

#[test]
fn kill_between_step_1_and_step_2_load_recovers_base_payload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut child, mut reader) = spawn_child(dir.path());

    wait_for_marker(&mut reader, "AFTER_STEP_1").expect("AFTER_STEP_1");
    let _ = child.kill();
    let _ = child.wait();

    let layout = StoreLayout::open(dir.path()).expect("open layout");
    let final_dir = layout.snapshot_dir(SnapshotId(SNAP_ID));
    let old_tmp = final_dir.with_extension("old.tmp");
    assert!(old_tmp.is_dir(), "post-kill: `.old.tmp` must exist");
    assert!(!final_dir.is_dir(), "post-kill: `final_dir` must be absent");

    let loaded =
        Snapshot::load(&layout, SnapshotId(SNAP_ID), SNAPSHOT_MAGIC).expect("load with recovery");
    assert_eq!(loaded.data, BASE_PAYLOAD);
    assert!(final_dir.is_dir());
    assert!(!old_tmp.exists());
}

#[test]
fn kill_between_step_2_and_step_3_load_picks_final_dir_and_cleans_up() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut child, mut reader) = spawn_child(dir.path());

    wait_for_marker(&mut reader, "AFTER_STEP_2").expect("AFTER_STEP_2");
    let _ = child.kill();
    let _ = child.wait();

    let layout = StoreLayout::open(dir.path()).expect("open layout");
    let final_dir = layout.snapshot_dir(SnapshotId(SNAP_ID));
    let old_tmp = final_dir.with_extension("old.tmp");
    assert!(final_dir.is_dir(), "post-kill: `final_dir` must exist");
    assert!(
        old_tmp.is_dir(),
        "post-kill: `.old.tmp` must still be present"
    );

    let loaded = Snapshot::load(&layout, SnapshotId(SNAP_ID), SNAPSHOT_MAGIC)
        .expect("load with both present");
    assert_eq!(loaded.data, NEW_PAYLOAD);
    assert!(!old_tmp.exists());
}

#[test]
fn round_trip_save_kill_load_never_loses_data_at_any_step() {
    let kill_targets = [
        "READY_FOR_CHAOS",
        "STAGED_TMP",
        "AFTER_STEP_1",
        "AFTER_STEP_2",
        "AFTER_STEP_3",
    ];
    for target in kill_targets {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut child, mut reader) = spawn_child(dir.path());

        wait_for_marker(&mut reader, target).unwrap_or_else(|e| {
            panic!("waiting for marker `{target}` failed: {e}");
        });
        let _ = child.kill();
        let _ = child.wait();

        let layout = StoreLayout::open(dir.path()).expect("open layout");
        let loaded = Snapshot::load(&layout, SnapshotId(SNAP_ID), SNAPSHOT_MAGIC).unwrap_or_else(|e| {
            panic!("post-kill load at marker `{target}` must succeed; got {e:?}")
        });
        assert!(
            loaded.data == BASE_PAYLOAD || loaded.data == NEW_PAYLOAD,
            "post-kill at `{target}`: unexpected payload ({} bytes)",
            loaded.data.len(),
        );

        match target {
            "READY_FOR_CHAOS" | "STAGED_TMP" | "AFTER_STEP_1" => {
                assert_eq!(
                    loaded.data, BASE_PAYLOAD,
                    "kill at `{target}` must recover BASE"
                );
            }
            "AFTER_STEP_2" | "AFTER_STEP_3" => {
                assert_eq!(
                    loaded.data, NEW_PAYLOAD,
                    "kill at `{target}` must surface NEW"
                );
            }
            _ => unreachable!(),
        }

        let final_dir = layout.snapshot_dir(SnapshotId(SNAP_ID));
        let old_tmp = final_dir.with_extension("old.tmp");
        assert!(
            !old_tmp.exists(),
            "post-load at `{target}`: `.old.tmp` must be cleaned up"
        );
        assert!(
            final_dir.is_dir(),
            "post-load at `{target}`: `final_dir` must exist"
        );
    }
}
