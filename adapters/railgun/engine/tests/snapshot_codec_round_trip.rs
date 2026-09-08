//! Byte identity of the on-disk snapshot: canonical across a restore, and stable under a
//! codec swap or a compression wrap.
//!
//! These assertions were carried only by `benches/snapshot_codec_acceleration_bench.rs`.
//! That target is `#[ignore]`-gated and no lane passes `--run-ignored`, so they executed
//! nowhere. The bench still measures the codecs at the production cell; the correctness
//! half runs here at a toy cell, where a per-commit lane executes it.

#![allow(clippy::expect_used)]

use std::io::Write;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_engine::inspire::{
    restore_inspire_state, setup_state, snapshot_inspire_state, PersistedInspireState,
};

const ENTRIES: usize = 256;
const ENTRY_BYTES: usize = 32;
const ZSTD_LEVEL: i32 = 3;

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
/// reads as correct at whichever variant the rest of the suite happens to use.
fn assert_snapshot_bytes_survive_every_hop(variant: InspireVariant) {
    let params = InspireParams::secure_128_d2048();
    let db = raven_railgun_testkit::toy_db(ENTRIES, ENTRY_BYTES);
    let (state, _sk) = setup_state(&params, &db, ENTRY_BYTES, variant).expect("setup_state");

    let canonical = snapshot_inspire_state(&state).expect("snapshot");
    let restored = restore_inspire_state(&canonical).expect("restore");
    let resnapshot = snapshot_inspire_state(&restored).expect("resnapshot");
    assert_same_bytes(
        &resnapshot,
        &canonical,
        &format!("{variant:?}: snapshot is not canonical across a restore"),
    );

    // A codec swap is only safe if the serde shape carries every field the on-disk format
    // holds; re-emitting bincode after a bitcode round-trip is what proves it.
    let bundle: PersistedInspireState =
        bincode::deserialize(&canonical).expect("bincode deserialize");
    let bitcoded = bitcode::serialize(&bundle).expect("bitcode serialize");
    let back: PersistedInspireState = bitcode::deserialize(&bitcoded).expect("bitcode deserialize");
    let via_bitcode = bincode::serialize(&back).expect("bincode re-serialize");
    assert_same_bytes(
        &via_bitcode,
        &canonical,
        &format!("{variant:?}: a bitcode round-trip lost a snapshot field"),
    );

    let mut compressed = Vec::with_capacity(canonical.len() / 2);
    {
        let mut enc = zstd::Encoder::new(&mut compressed, ZSTD_LEVEL).expect("zstd encoder");
        enc.write_all(&canonical).expect("zstd write");
        enc.finish().expect("zstd finish");
    }
    let mut decompressed = Vec::with_capacity(canonical.len());
    {
        let mut dec = zstd::Decoder::new(&compressed[..]).expect("zstd decoder");
        std::io::copy(&mut dec, &mut decompressed).expect("zstd copy");
    }
    assert_same_bytes(
        &decompressed,
        &canonical,
        &format!("{variant:?}: the zstd wrap is not byte-transparent over a snapshot"),
    );
}

#[test]
fn snapshot_bytes_survive_every_hop_two_packing() {
    assert_snapshot_bytes_survive_every_hop(InspireVariant::TwoPacking);
}

#[test]
fn snapshot_bytes_survive_every_hop_no_packing() {
    assert_snapshot_bytes_survive_every_hop(InspireVariant::NoPacking);
}
