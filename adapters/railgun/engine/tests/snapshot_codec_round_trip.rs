//! Byte identity of the on-disk snapshot: canonical across a restore.
//!
//! These assertions were carried only by `benches/snapshot_codec_acceleration_bench.rs`.
//! That target is `#[ignore]`-gated and no lane passes `--run-ignored`, so they executed
//! nowhere. The bench still measures the codecs at the production cell; the restore
//! canonicality check runs here at a toy cell, where a per-commit lane executes it.

#![allow(clippy::expect_used)]

use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_engine::inspire::{
    restore_inspire_state, setup_state, snapshot_inspire_state, InspireServerState,
};

const ENTRIES: usize = 256;
const ENTRY_BYTES: usize = 32;

/// Compare without printing the operands: a snapshot is hundreds of KiB and a plain
/// `assert_eq!` on two of them buries the run log under megabytes of decimal bytes.
fn assert_same_bytes(got: &[u8], want: &[u8], what: &str) {
    let first_diff = got.iter().zip(want.iter()).position(|(a, b)| a != b);
    assert!(
        got == want,
        "{what}: got {} bytes, want {} bytes; first differing byte at {first_diff:?}",
        got.len(),
        want.len()
    );
}

/// Every stored field must survive a restore and re-serialize to the same bytes. A restore
/// that normalises or hardcodes one of them rewrites every later snapshot while failing
/// nothing. `variant` is exercised under two values for that reason: a hardcoded restore
/// reads as correct at whichever variant the rest of the suite happens to use. It is only a
/// stored field, so both values share one setup.
#[test]
fn snapshot_bytes_are_canonical_across_a_restore_under_both_variants() {
    let params = InspireParams::secure_128_d2048();
    let db = raven_railgun_testkit::toy_db(ENTRIES, ENTRY_BYTES);
    let (base, _sk) =
        setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("setup_state");

    for variant in [InspireVariant::TwoPacking, InspireVariant::NoPacking] {
        let state = InspireServerState {
            crs: Arc::clone(&base.crs),
            encoded_db: Arc::clone(&base.encoded_db),
            cache: Arc::clone(&base.cache),
            session_store: Arc::clone(&base.session_store),
            variant,
            entry_size: base.entry_size,
        };
        let canonical = snapshot_inspire_state(&state).expect("snapshot");
        let restored = restore_inspire_state(&canonical).expect("restore");
        let resnapshot = snapshot_inspire_state(&restored).expect("resnapshot");
        assert_same_bytes(
            &resnapshot,
            &canonical,
            &format!("{variant:?}: snapshot is not canonical across a restore"),
        );
    }
}
