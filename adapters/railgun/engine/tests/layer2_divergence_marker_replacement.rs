//! The divergence marker is REPLACED, never written through in place.
//!
//! That the mark survives a restart is already gated in `layer2_divergence_gate.rs`, and a
//! bare `fs::write` passes that test - it creates the same file. What atomic replacement
//! buys is a durable DIRECTORY ENTRY: write a tmp file, fsync it, rename it over the target,
//! fsync the parent. A power cut can otherwise lose an entry that was reported as written.
//!
//! The fsync half needs crash injection and is not gated here. The replacement half has one
//! deterministic consequence that does not: a rename over a target needs permission on the
//! DIRECTORY, not on the file, so replacing the marker cannot depend on the old marker being
//! writable. A revert to `fs::write` fails this with a permission error.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use raven_railgun_core::InstanceId;
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_persistence::StoreLayout;

const SCHEME_TAG: &str = "raven-inspire-twopacking-divergence-marker-replacement";
const INSTANCE: &str = "divergence-marker-replacement";
/// On-disk contract, mirrored from the writer. If the writer renames it, this fails loudly,
/// which is correct: the filename is what a restart looks for.
const MARKER: &str = "layer2-divergent";

fn encoder() -> Arc<dyn PirTableEncoder> {
    EncoderKind::PerLeafBc { tree_number: 0 }
        .build(32, 2048)
        .expect("build encoder")
}

#[cfg(unix)]
#[test]
fn re_marking_replaces_a_read_only_marker_rather_than_writing_through_it() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let opened = InspirePersistence::open(
        layout,
        SCHEME_TAG,
        InstanceId::new(INSTANCE),
        SnapshotPolicy::default(),
        encoder(),
    )
    .expect("fresh open");
    let persistence = opened.persistence;

    persistence
        .mark_layer2_divergent()
        .expect("first mark writes the marker");
    let marker = dir.path().join(MARKER);
    assert!(marker.is_file(), "the marker must be a file at {MARKER}");

    // A marker left read-only by a restore, an operator, or a stricter umask.
    let mut perms = std::fs::metadata(&marker).expect("metadata").permissions();
    perms.set_mode(0o444);
    std::fs::set_permissions(&marker, perms).expect("chmod 444");
    assert!(
        std::fs::OpenOptions::new()
            .write(true)
            .open(&marker)
            .is_err(),
        "precondition: the marker really is not writable in place"
    );

    persistence
        .mark_layer2_divergent()
        .expect("replacing the marker must not require the old file to be writable");

    let contents = std::fs::read(&marker).expect("read marker");
    assert_eq!(
        contents,
        INSTANCE.as_bytes(),
        "the replacement must carry the instance id a restart reads back"
    );

    // Replacement renames its scratch file away; a leftover tmp beside the marker means the
    // rename did not happen and something wrote in place.
    let strays: Vec<String> = std::fs::read_dir(dir.path())
        .expect("read store root")
        .filter_map(std::result::Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(MARKER) && n != MARKER)
        .collect();
    assert!(
        strays.is_empty(),
        "replacement must leave no scratch file behind; found {strays:?}"
    );
}
