//! Can THIS binary reopen THAT data_dir? Point the probe at one and find out, before a
//! deploy rather than after it.
//!
//! A snapshot's on-disk layout can drift out from under the reader silently: bincode is
//! positional, so a field inserted mid-struct anywhere inside
//! `PersistedInspireState` -- including inside the InsPIRe submodule types it embeds --
//! shifts every field after it. A real data_dir is the only oracle for that: an in-tree
//! fixture could be minted for the submodule half too, but only the operator has bytes an
//! older build actually wrote, and those are what a deploy meets.
//!
//! ```text
//! RAVEN_PROBE_DATA_DIR=/srv/raven/data/ppoi-paths-ofac cargo test \
//!   --manifest-path adapters/railgun/Cargo.toml -p raven-railgun-engine \
//!   --test data_dir_reopen_probe -- --ignored
//! ```
//!
//! `--manifest-path` is not optional: this is a detached workspace, so `-p` alone resolves to
//! no package from the repo root.
//!
//! LIMITS, stated because the pitch is "before a deploy rather than after it". It reports
//! success on a successful DECODE, not a correct one — a shift that happens to decode into
//! well-formed values passes green. And it opens the snapshot alone: it does not replay the
//! WAL and does not build the recovery cache, so a failure confined to either is invisible
//! to it. Production boots through `restore_inspire_state_v6_cached`, which does build that
//! cache; this calls its uncached twin, and the two share only the byte decode.
//!
//! Read-only: `StoreLayout::inspect` neither creates nor writes, and the probe opens the
//! snapshot file alone -- not the WAL, which would take the lock a running node holds.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_railgun_engine::inspire::{
    restore_inspire_state_v6, snapshot_inspire_state_v7, LogicalLeafStore,
};
use raven_railgun_persistence::{
    Manifest, Snapshot, SnapshotId, StoreLayout, MANIFEST_SCHEMA_VERSION, SNAPSHOT_MAGIC,
};

/// `Err` carries the operator-facing verdict; `Ok` carries which arm read it, so a green run
/// still says whether the V5, V6 or V7 path was exercised.
fn probe(dir: &std::path::Path) -> Result<&'static str, String> {
    let layout = StoreLayout::inspect(dir);
    let manifest = match Manifest::load(&layout) {
        Ok(Some(m)) => m,
        Ok(None) => return Err(format!("{}: no manifest.json", dir.display())),
        Err(e) => return Err(format!("{}: manifest unreadable: {e}", dir.display())),
    };
    let schema = manifest.schema_version;
    let id = manifest.current_snapshot_id;
    if id == SnapshotId(0) {
        return Err(format!(
            "{}: manifest schema_version {schema} names no snapshot yet",
            dir.display()
        ));
    }
    let snap = Snapshot::load(&layout, id, SNAPSHOT_MAGIC).map_err(|e| {
        format!(
            "{}: snapshot {id:?} would not load at all: {e}",
            dir.display()
        )
    })?;

    // The magic prefix, not the manifest number, picks the read arm. Reporting both stops a
    // reader concluding that "schema_version 5" means the V5 path was taken.
    let arm = match snap.data.get(..4) {
        Some(b"RV7\0") => "V7",
        Some(b"RV6\0") => "V6",
        _ => "V5 (no magic prefix)",
    };

    restore_inspire_state_v6(&snap.data).map_err(|e| {
        format!(
            "{}: THIS BINARY CANNOT REOPEN THIS DATA_DIR.\n  \
             manifest schema_version: {schema}\n  snapshot arm by magic: {arm}\n  error: {e}\n  \
             Deploying this build over that data_dir fails at boot.",
            dir.display()
        )
    })?;
    Ok(arm)
}

#[test]
#[ignore = "trigger: run by hand before a deploy, with RAVEN_PROBE_DATA_DIR set to a real \
            data_dir. It needs an operator's filesystem, so it can belong to no lane."]
fn the_data_dir_named_by_the_environment_reopens_under_this_binary() {
    let Ok(dir) = std::env::var("RAVEN_PROBE_DATA_DIR") else {
        panic!("set RAVEN_PROBE_DATA_DIR to the instance data_dir to probe");
    };
    if let Err(verdict) = probe(std::path::Path::new(&dir)) {
        panic!("{verdict}");
    }
}

/// Verifies the INSTRUMENT. Until this existed the probe had only ever been seen to fail, and
/// a check that cannot go green is indistinguishable from one that is simply broken.
#[test]
fn the_probe_reports_green_on_a_data_dir_this_binary_just_wrote() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let state = raven_railgun_testkit::toy_state(32);
    let payload =
        snapshot_inspire_state_v7(&state, &LogicalLeafStore::new()).expect("v7 serialize");

    let id = SnapshotId(1);
    Snapshot::build(payload, SNAPSHOT_MAGIC)
        .save(&layout, id)
        .expect("save snapshot");
    Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        scheme_tag: "raven-inspire-twopacking-inspiring-wp3-reopen-probe".to_owned(),
        instance_id: "reopen-probe".to_owned(),
        current_snapshot_id: id,
        current_snapshot_seq: 0,
        current_marker: 0,
        encoder_label: "per-node".to_owned(),
        prev_encoder_label: None,
        entry_size_bytes: Some(32),
        rows_per_shard: Some(2048),
    }
    .save(&layout)
    .expect("save manifest");

    assert_eq!(
        probe(dir.path()).expect("a data_dir this binary just wrote must reopen"),
        "V7"
    );
}

/// ...and that it goes RED for the reason it claims. A byte flipped inside the embedded
/// InsPIRe types is the shape of the real failure: the header still validates, the arm is
/// still V7, and the decode fails anyway.
#[test]
fn the_probe_reports_red_when_the_snapshot_body_does_not_match_this_binary() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let state = raven_railgun_testkit::toy_state(32);
    let mut payload =
        snapshot_inspire_state_v7(&state, &LogicalLeafStore::new()).expect("v7 serialize");

    // Splice out eight bytes just past the magic: exactly what a removed `usize` field does
    // to every byte after it.
    payload.drain(8..16);

    let id = SnapshotId(1);
    Snapshot::build(payload, SNAPSHOT_MAGIC)
        .save(&layout, id)
        .expect("save snapshot");
    Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        scheme_tag: "raven-inspire-twopacking-inspiring-wp3-reopen-probe".to_owned(),
        instance_id: "reopen-probe".to_owned(),
        current_snapshot_id: id,
        current_snapshot_seq: 0,
        current_marker: 0,
        encoder_label: "per-node".to_owned(),
        prev_encoder_label: None,
        entry_size_bytes: Some(32),
        rows_per_shard: Some(2048),
    }
    .save(&layout)
    .expect("save manifest");

    let verdict = probe(dir.path()).expect_err("a shifted body must not reopen");
    assert!(verdict.contains("CANNOT REOPEN"), "{verdict}");
    assert!(verdict.contains("snapshot arm by magic: V7"), "{verdict}");
    assert!(
        verdict.contains("no in-place migration exists"),
        "{verdict}"
    );
}
