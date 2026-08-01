//! Recovery-time cell-shape guard: a data_dir stored at one row width must not
//! reopen under an encoder emitting a different width. `encoder_label` alone is
//! label-stable across the operator-supplied widths (`PerLeafBc`,
//! `PerListStatus`), so the label check cannot see this.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::{AdapterError, InstanceId};
use raven_railgun_engine::inspire::{setup_state, LogicalLeafStore};
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_persistence::StoreLayout;

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-cell-shape-guard";
const ENTRIES_PER_SHARD: u32 = 2048;
const STORED_WIDTH: usize = 512;
const NARROW_WIDTH: usize = 32;
const CELL_ROWS: usize = 64;

fn encoder_at(width: usize) -> Arc<dyn PirTableEncoder> {
    EncoderKind::PerLeafBc
        .build(width, ENTRIES_PER_SHARD)
        .expect("build per-leaf-bc encoder")
}

fn seed_data_dir(dir: &std::path::Path, instance: &str, stored_width: usize) {
    let layout = StoreLayout::open(dir).expect("layout");
    let opened = InspirePersistence::open(
        layout,
        SCHEME_TAG,
        InstanceId::new(instance),
        SnapshotPolicy::default(),
        encoder_at(stored_width),
    )
    .expect("fresh open");

    let params = InspireParams::secure_128_d2048();
    let db: Vec<u8> = (0..CELL_ROWS)
        .flat_map(|i| (0..stored_width).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
        .collect();
    let (state, _sk) =
        setup_state(&params, &db, stored_width, InspireVariant::TwoPacking).expect("setup_state");
    assert_eq!(state.shard_config().entry_size_bytes, stored_width);

    opened
        .persistence
        .commit_v6(&state, &LogicalLeafStore::new(), 100)
        .expect("commit_v6");
}

fn reopen(dir: &std::path::Path, instance: &str, width: usize) -> Result<(), AdapterError> {
    let layout = StoreLayout::open(dir).expect("layout reopen");
    InspirePersistence::open(
        layout,
        SCHEME_TAG,
        InstanceId::new(instance),
        SnapshotPolicy::default(),
        encoder_at(width),
    )
    .map(|_| ())
}

#[test]
fn narrower_encoder_than_stored_cell_is_refused_on_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed_data_dir(dir.path(), "narrow-vs-stored", STORED_WIDTH);

    let Err(err) = reopen(dir.path(), "narrow-vs-stored", NARROW_WIDTH) else {
        panic!(
            "SILENT WRONG: a data_dir stored at {STORED_WIDTH}-byte rows reopened under an \
             encoder emitting {NARROW_WIDTH}-byte rows. encoder_label is identical for both \
             (per-leaf-bc), so nothing downstream can tell: every re-encoded shard would pack \
             {ratio} narrow rows into one stored row and serve unrelated bytes with no \
             query-path error",
            ratio = STORED_WIDTH / NARROW_WIDTH,
        );
    };

    let msg = format!("{err}");
    for needle in [
        &STORED_WIDTH.to_string(),
        &NARROW_WIDTH.to_string(),
        "per-leaf-bc",
        "re-bootstrapped",
    ] {
        assert!(
            msg.contains(needle),
            "error must name {needle:?} to be actionable; got: {msg}"
        );
    }
    assert!(
        matches!(err, AdapterError::Internal(_)),
        "must be a typed Internal error, matching the sibling manifest-mismatch \
         rejections; got {err:?}"
    );
}

#[test]
fn wider_encoder_than_stored_cell_is_refused_on_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed_data_dir(dir.path(), "wide-vs-stored", NARROW_WIDTH);

    let Err(err) = reopen(dir.path(), "wide-vs-stored", STORED_WIDTH) else {
        panic!(
            "SILENT WRONG: a data_dir stored at {NARROW_WIDTH}-byte rows reopened under an \
             encoder emitting {STORED_WIDTH}-byte rows"
        );
    };
    assert!(matches!(err, AdapterError::Internal(_)), "got {err:?}");
}

#[test]
fn matching_width_still_reopens() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed_data_dir(dir.path(), "healthy-round-trip", STORED_WIDTH);

    let layout = StoreLayout::open(dir.path()).expect("layout reopen");
    let opened = InspirePersistence::open(
        layout,
        SCHEME_TAG,
        InstanceId::new("healthy-round-trip"),
        SnapshotPolicy::default(),
        encoder_at(STORED_WIDTH),
    )
    .expect("a data_dir reopened at its own stored width must still open");

    let recovered = opened
        .recovered_state
        .expect("post-commit reopen must surface recovered_state");
    assert_eq!(recovered.shard_config().entry_size_bytes, STORED_WIDTH);
}
