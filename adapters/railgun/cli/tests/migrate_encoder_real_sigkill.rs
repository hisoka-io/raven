//! Real-SIGKILL closure for the offline `migrate-encoder` tool.
//! Spawns migration as a fork+exec'd subprocess, parks at a named
//! checkpoint, then SIGKILLs and asserts the documented disk-state contract.

#![cfg(unix)]
#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used,
        clippy::too_many_lines,
        clippy::assigning_clones,
        clippy::single_match_else
    )
)]

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{setup_state, InspireServerState};
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_persistence::{
    Manifest, Snapshot, SnapshotId, StoreLayout, WalEntryPayload, SNAPSHOT_MAGIC,
};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-real-sigkill-migration";
const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_SIZE: usize = 32;
const ENTRIES_PER_SHARD: u32 = 256;
const SEED_LEAF_COUNT: u32 = 32;
const SENTINEL_TIMEOUT: Duration = Duration::from_secs(60);
const POST_KILL_WAIT: Duration = Duration::from_secs(10);

fn canonical(seed: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = seed.max(1);
    b
}

fn build_toy_state() -> InspireServerState {
    let params = InspireParams::secure_128_d2048();
    let db: Vec<u8> = (0..TOY_ENTRIES)
        .flat_map(|i| (0..TOY_ENTRY_SIZE).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
        .collect();
    let (state, _sk) =
        setup_state(&params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking).expect("setup_state");
    state
}

fn encoder_arc(kind: EncoderKind) -> Arc<dyn PirTableEncoder> {
    kind.build(TOY_ENTRY_SIZE, ENTRIES_PER_SHARD)
        .expect("build encoder")
}

fn seed_dir(dir_path: &Path, encoder_kind: EncoderKind) {
    let layout = StoreLayout::open(dir_path).expect("layout");
    let opened = InspirePersistence::open(
        layout,
        SCHEME_TAG,
        InstanceId::new("real-sigkill-migrate"),
        SnapshotPolicy::default(),
        encoder_arc(encoder_kind),
    )
    .expect("fresh open");

    let state = build_toy_state();
    opened
        .persistence
        .commit(&state, 0)
        .expect("initial commit");

    for i in 0..SEED_LEAF_COUNT {
        let payload = WalEntryPayload::AppendLeaf {
            tree_number: 0,
            leaf_index: i,
            commitment: canonical(u8::try_from(i).unwrap_or(0).saturating_add(1)),
        };
        opened
            .persistence
            .apply_event(&payload, 100 + u64::from(i))
            .expect("apply_event");
    }
}

fn read_manifest(dir_path: &Path) -> Manifest {
    let layout = StoreLayout::open(dir_path).expect("layout");
    Manifest::load(&layout)
        .expect("manifest load")
        .expect("manifest present")
}

fn manifest_bytes(dir_path: &Path) -> Vec<u8> {
    let layout = StoreLayout::open(dir_path).expect("layout");
    std::fs::read(layout.manifest_path()).expect("read manifest bytes")
}

fn snapshot_bytes(dir_path: &Path, id: SnapshotId) -> Vec<u8> {
    let layout = StoreLayout::open(dir_path).expect("layout");
    let snap = Snapshot::load(&layout, id, SNAPSHOT_MAGIC).expect("load snap");
    snap.data
}

/// Spawn the chaos child paused at `checkpoint`, then SIGKILL it once its
/// stdout sentinel confirms it reached that point.
fn spawn_park_kill(dir_path: &Path, target: &str, checkpoint: &str) -> String {
    let bin = env!("CARGO_BIN_EXE_migrate_chaos_child");
    let mut child: Child = Command::new(bin)
        .arg("--data-dir")
        .arg(dir_path)
        .arg("--target")
        .arg(target)
        .arg("--pause-at")
        .arg(checkpoint)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn migrate_chaos_child");

    let stdout = child.stdout.take().expect("captured stdout");
    let mut reader = BufReader::new(stdout);

    let deadline = Instant::now() + SENTINEL_TIMEOUT;
    let mut found = String::new();
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        let n = reader.read_line(&mut line).expect("read child stdout");
        if n == 0 {
            break; // EOF before sentinel: child exited unexpectedly
        }
        let trimmed = line.trim();
        if trimmed.contains("\"checkpoint\"") {
            found = trimmed.to_owned();
            break;
        }
    }

    assert!(
        !found.is_empty(),
        "child did not emit checkpoint sentinel within {SENTINEL_TIMEOUT:?} for checkpoint={checkpoint}"
    );
    let expected_fragment = format!("\"checkpoint\":\"{checkpoint}\"");
    assert!(
        found.contains(&expected_fragment),
        "sentinel must name the requested checkpoint; got: {found}"
    );

    child.kill().expect("SIGKILL child");
    let status = wait_with_timeout(&mut child, POST_KILL_WAIT);
    assert!(
        !status.success(),
        "child exited cleanly after SIGKILL; status={status:?}"
    );
    found
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => return status,
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    return child.wait().expect("blocking wait after timeout");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn assert_old_encoder_recovers(dir_path: &Path) {
    let layout = StoreLayout::open(dir_path).expect("layout");
    let opened = InspirePersistence::open(
        layout,
        SCHEME_TAG,
        InstanceId::new("real-sigkill-migrate"),
        SnapshotPolicy::default(),
        encoder_arc(EncoderKind::PerLeafBc),
    )
    .expect("reopen with prior encoder must succeed after kill");
    assert_eq!(
        opened.recovered_logical_store.imt_leaf_count_for(0),
        SEED_LEAF_COUNT as usize,
        "WAL replay must restore all seeded leaves after SIGKILL"
    );
    drop(opened);
}

#[test]
#[ignore = "slow: cold-start PIR keygen; run with --ignored"]
fn real_sigkill_at_pre_re_encode_no_disk_mutation_then_resume_succeeds() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed_dir(dir.path(), EncoderKind::PerLeafBc);

    let manifest_pre = read_manifest(dir.path());
    let pre_manifest_raw = manifest_bytes(dir.path());
    let pre_snap_bytes = snapshot_bytes(dir.path(), manifest_pre.current_snapshot_id);

    spawn_park_kill(dir.path(), "per-node", "pre-re-encode");

    assert_eq!(
        manifest_bytes(dir.path()),
        pre_manifest_raw,
        "pre-re-encode kill must leave manifest bytes pristine"
    );
    assert_eq!(
        snapshot_bytes(dir.path(), manifest_pre.current_snapshot_id),
        pre_snap_bytes,
        "pre-re-encode kill must leave snapshot bytes pristine"
    );

    assert_old_encoder_recovers(dir.path());

    raven_railgun_cli::migrate_encoder::run(dir.path(), EncoderKind::PerNode { tree_number: 0 })
        .expect("resumed migration must succeed");

    let manifest_after = read_manifest(dir.path());
    assert_eq!(manifest_after.encoder_label, "per-node");
    assert_eq!(
        manifest_after.prev_encoder_label,
        Some("per-leaf-bc".to_owned())
    );
    assert_eq!(
        manifest_after.current_snapshot_id,
        manifest_pre.current_snapshot_id.next()
    );
}

#[test]
#[ignore = "slow: cold-start PIR keygen; run with --ignored"]
fn real_sigkill_at_post_re_encode_no_disk_mutation_then_resume_succeeds() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed_dir(dir.path(), EncoderKind::PerLeafBc);

    let manifest_pre = read_manifest(dir.path());
    let pre_manifest_raw = manifest_bytes(dir.path());
    let pre_snap_bytes = snapshot_bytes(dir.path(), manifest_pre.current_snapshot_id);

    spawn_park_kill(dir.path(), "per-node", "post-re-encode");

    assert_eq!(
        manifest_bytes(dir.path()),
        pre_manifest_raw,
        "post-re-encode kill must not have written any new manifest"
    );
    assert_eq!(
        snapshot_bytes(dir.path(), manifest_pre.current_snapshot_id),
        pre_snap_bytes,
        "post-re-encode kill must leave snapshot bytes pristine"
    );

    assert_old_encoder_recovers(dir.path());

    raven_railgun_cli::migrate_encoder::run(dir.path(), EncoderKind::PerNode { tree_number: 0 })
        .expect("resumed migration must succeed");

    let manifest_after = read_manifest(dir.path());
    assert_eq!(manifest_after.encoder_label, "per-node");
    assert_eq!(
        manifest_after.prev_encoder_label,
        Some("per-leaf-bc".to_owned())
    );
    assert_eq!(
        manifest_after.current_snapshot_id,
        manifest_pre.current_snapshot_id.next()
    );
}

#[test]
#[ignore = "slow: cold-start PIR keygen; run with --ignored"]
fn real_sigkill_at_pre_snapshot_no_disk_mutation_then_resume_succeeds() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed_dir(dir.path(), EncoderKind::PerLeafBc);

    let manifest_pre = read_manifest(dir.path());
    let pre_manifest_raw = manifest_bytes(dir.path());

    spawn_park_kill(dir.path(), "per-node", "pre-snapshot");

    assert_eq!(
        manifest_bytes(dir.path()),
        pre_manifest_raw,
        "pre-snapshot kill must leave manifest bytes pristine"
    );

    assert_old_encoder_recovers(dir.path());

    raven_railgun_cli::migrate_encoder::run(dir.path(), EncoderKind::PerNode { tree_number: 0 })
        .expect("resumed migration must succeed");

    let manifest_after = read_manifest(dir.path());
    assert_eq!(manifest_after.encoder_label, "per-node");
    assert_eq!(
        manifest_after.current_snapshot_id,
        manifest_pre.current_snapshot_id.next()
    );
}

#[test]
#[ignore = "slow: cold-start PIR keygen; run with --ignored"]
fn real_sigkill_at_post_snapshot_keeps_old_manifest_then_resume_succeeds() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed_dir(dir.path(), EncoderKind::PerLeafBc);

    let manifest_pre = read_manifest(dir.path());
    let pre_manifest_raw = manifest_bytes(dir.path());

    spawn_park_kill(dir.path(), "per-node", "post-snapshot");

    // snapshot id+1 is on disk but the manifest still points at the old id (no rename fired)
    let manifest_post_kill = read_manifest(dir.path());
    assert_eq!(
        manifest_bytes(dir.path()),
        pre_manifest_raw,
        "post-snapshot kill must leave manifest bytes pristine (no atomic-rename fired)"
    );
    assert_eq!(
        manifest_post_kill.current_snapshot_id, manifest_pre.current_snapshot_id,
        "manifest must still reference pre-migration snapshot id"
    );
    assert_eq!(manifest_post_kill.encoder_label, "per-leaf-bc");
    assert_eq!(manifest_post_kill.prev_encoder_label, None);

    assert_old_encoder_recovers(dir.path());

    raven_railgun_cli::migrate_encoder::run(dir.path(), EncoderKind::PerNode { tree_number: 0 })
        .expect("resumed migration must succeed");

    let manifest_after = read_manifest(dir.path());
    assert_eq!(manifest_after.encoder_label, "per-node");
    assert_eq!(
        manifest_after.prev_encoder_label,
        Some("per-leaf-bc".to_owned())
    );
}

#[test]
#[ignore = "slow: cold-start PIR keygen; run with --ignored"]
fn real_sigkill_at_pre_manifest_bump_keeps_old_manifest_then_resume_succeeds() {
    // pre-manifest-bump aliases post-snapshot (identical on-disk shape); kept distinct for intent
    let dir = tempfile::tempdir().expect("tempdir");
    seed_dir(dir.path(), EncoderKind::PerLeafBc);

    let manifest_pre = read_manifest(dir.path());
    let pre_manifest_raw = manifest_bytes(dir.path());

    spawn_park_kill(dir.path(), "per-node", "pre-manifest-bump");

    assert_eq!(
        manifest_bytes(dir.path()),
        pre_manifest_raw,
        "pre-manifest-bump kill must leave manifest bytes pristine"
    );
    assert_old_encoder_recovers(dir.path());

    raven_railgun_cli::migrate_encoder::run(dir.path(), EncoderKind::PerNode { tree_number: 0 })
        .expect("resumed migration must succeed");

    let manifest_after = read_manifest(dir.path());
    assert_eq!(manifest_after.encoder_label, "per-node");
    assert_eq!(
        manifest_after.prev_encoder_label,
        Some("per-leaf-bc".to_owned())
    );
    assert_eq!(
        manifest_after.current_snapshot_id,
        manifest_pre.current_snapshot_id.next()
    );
}

#[test]
#[ignore = "slow: cold-start PIR keygen; run with --ignored"]
fn real_sigkill_at_post_manifest_bump_yields_fully_migrated_state() {
    // migration completes before the kill; re-running must hit the idempotency guard, not touch disk
    let dir = tempfile::tempdir().expect("tempdir");
    seed_dir(dir.path(), EncoderKind::PerLeafBc);

    let manifest_pre = read_manifest(dir.path());

    spawn_park_kill(dir.path(), "per-node", "post-manifest-bump");

    let manifest_post_kill = read_manifest(dir.path());
    assert_eq!(manifest_post_kill.encoder_label, "per-node");
    assert_eq!(
        manifest_post_kill.prev_encoder_label,
        Some("per-leaf-bc".to_owned())
    );
    assert_eq!(
        manifest_post_kill.current_snapshot_id,
        manifest_pre.current_snapshot_id.next(),
        "snapshot id must be bumped by one"
    );

    let err = raven_railgun_cli::migrate_encoder::run(
        dir.path(),
        EncoderKind::PerNode { tree_number: 0 },
    )
    .expect_err("post-manifest-bump migrate must be rejected as already-on-target");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("already") || msg.contains("nothing to migrate"),
        "error must surface idempotency guard; got: {msg}"
    );

    let manifest_after_attempt = read_manifest(dir.path());
    assert_eq!(
        manifest_after_attempt, manifest_post_kill,
        "refused attempt must not mutate manifest"
    );

    let layout = StoreLayout::open(dir.path()).expect("layout");
    let opened = InspirePersistence::open(
        layout,
        SCHEME_TAG,
        InstanceId::new("real-sigkill-migrate"),
        SnapshotPolicy::default(),
        encoder_arc(EncoderKind::PerNode { tree_number: 0 }),
    )
    .expect("reopen with migrated encoder must succeed");
    assert_eq!(
        opened.recovered_logical_store.imt_leaf_count_for(0),
        SEED_LEAF_COUNT as usize,
        "WAL replay must restore all leaves after post-bump SIGKILL"
    );
}
