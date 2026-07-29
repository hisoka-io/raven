//! Legal InsPIRe cell widths at production parameters.
//!
//! A record width is legal only if the InspiRING column count it induces,
//! `num_columns = ceil(entry_size / 2)` (`crates/inspire/src/pir/setup.rs`,
//! `crates/inspire/src/pir/encode_db.rs`), is a power of two no larger than
//! `ring_dim / 2`.
//!
//! Mechanism: the packing generator is `2n / gamma + 1` for `gamma < n` and `5`
//! otherwise (`crates/inspire/src/inspiring/inspiring2.rs:114-119`). The division
//! is integer, so a `gamma` that does not divide `2n` silently yields the wrong
//! generator, the wrong automorphism, and plaintext that decrypts to unrelated
//! bytes. Nothing on the path returns an error.
//!
//! Measured outside the law, at `ring_dim = 2048`:
//!
//! | entry_size | num_columns | outcome |
//! |---|---|---|
//! | 328 | 164 | every byte wrong, no error |
//! | 640 | 320 | every byte wrong, no error |
//! | 4096 | 2048 | every byte wrong, no error |
//! | 4098 and above | 2049 and above | panic, `inspiring2.rs:509` / `:1027`, index out of bounds |
//!
//! `production_cell_width_ladder_is_empirically_correct` reproduces the first three
//! rows. Widths at or above 4098 are excluded from it because they abort the process.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_engine::inspire::{
    build_client_session, build_seeded_query, extract_response, register_client_session,
    setup_state,
};
use raven_railgun_engine::pir_table::{NODE_HASH_BYTES, PATH_RECORD_BYTES};
use raven_railgun_engine::PirScheme;

/// The DB1 note record: 32 commitment + 8 leaf index + 32 ephemeral public key
/// + 32 wrapped content key + 7 x 32 ciphertext.
const NOTE_RECORD_BYTES: usize = 328;

/// Column count a record width induces in the InspiRING packing.
fn num_columns(entry_size: usize) -> usize {
    entry_size.div_ceil(2).max(1)
}

/// Whether `entry_size` is a legal cell width at `ring_dim`.
fn is_legal_cell_width(entry_size: usize, ring_dim: usize) -> bool {
    let cols = num_columns(entry_size);
    entry_size > 0 && cols.is_power_of_two() && cols <= ring_dim / 2
}

/// Widths proven correct by the empirical ladder below.
const LEGAL_WIDTHS: [usize; 7] = [32, 64, 128, 256, 512, 1024, 2048];

/// Widths that produce wrong bytes with no error. 328 is the DB1 note record and
/// 32768 is the DB2 block; both are named cell shapes in the read-path design.
const ILLEGAL_WIDTHS: [usize; 5] = [328, 640, 4096, 8192, 32768];

#[test]
fn legal_widths_are_accepted_and_named_illegal_widths_are_rejected() {
    let ring_dim = InspireParams::secure_128_d2048().ring_dim;
    assert_eq!(ring_dim, 2048, "production ring dimension changed");

    for width in LEGAL_WIDTHS {
        assert!(
            is_legal_cell_width(width, ring_dim),
            "entry_size {width} (num_columns {}) must be a legal cell width",
            num_columns(width)
        );
    }
    for width in ILLEGAL_WIDTHS {
        assert!(
            !is_legal_cell_width(width, ring_dim),
            "entry_size {width} (num_columns {}) must be rejected: the InspiRING \
             generator 2n/gamma+1 is exact only when gamma divides 2 * ring_dim \
             and gamma < ring_dim",
            num_columns(width)
        );
    }
}

#[test]
fn shipped_railgun_cell_widths_are_legal() {
    let ring_dim = InspireParams::secure_128_d2048().ring_dim;
    for (label, width) in [
        ("per-leaf-path / per-list-path", PATH_RECORD_BYTES),
        ("per-node / per-list-node", NODE_HASH_BYTES),
    ] {
        assert!(
            is_legal_cell_width(width, ring_dim),
            "shipped encoder {label} uses entry_size {width} (num_columns {}), \
             which is not a legal cell width at ring_dim {ring_dim}",
            num_columns(width)
        );
    }
}

#[test]
fn db1_note_record_does_not_fit_a_raw_cell_and_needs_the_next_legal_width() {
    let ring_dim = InspireParams::secure_128_d2048().ring_dim;
    assert!(
        !is_legal_cell_width(NOTE_RECORD_BYTES, ring_dim),
        "the 328-byte note record must not be served at its raw width"
    );
    let smallest_legal = LEGAL_WIDTHS
        .iter()
        .copied()
        .find(|&w| w >= NOTE_RECORD_BYTES)
        .expect("a legal width at or above 328 exists");
    assert_eq!(
        smallest_legal, 512,
        "the note record must be padded to the 512-byte cell"
    );
}

/// Full PIR round trip at one width; returns the worst per-entry mismatched-byte count.
fn worst_mismatch_at_width(entry_size: usize) -> usize {
    let params = InspireParams::secure_128_d2048();
    let entries = 8usize;
    let mut db = vec![0u8; entries * entry_size];
    for (i, byte) in db.iter_mut().enumerate() {
        *byte = u8::try_from(i % 251).unwrap_or(0);
    }
    let (state, secret_key) =
        setup_state(&params, &db, entry_size, InspireVariant::TwoPacking).expect("setup_state");
    let mut client_session =
        build_client_session((*state.crs).clone(), secret_key, &params).expect("client session");
    register_client_session(&mut client_session, &state).expect("register session");

    let mut worst = 0usize;
    for entry in 0..entries {
        let (client_state, query) =
            build_seeded_query(&client_session, state.shard_config(), entry as u64, &params)
                .expect("build_seeded_query");
        let response = <raven_railgun_engine::inspire::RavenInspireScheme as PirScheme>::respond(
            &state, &query,
        )
        .expect("respond");
        let plaintext =
            extract_response(&state.crs, &client_state, &response, entry_size).expect("extract");
        let expected = db
            .get(entry * entry_size..(entry + 1) * entry_size)
            .expect("expected entry slice");
        let recovered = plaintext.get(..entry_size).expect("recovered entry slice");
        worst = worst.max(
            recovered
                .iter()
                .zip(expected.iter())
                .filter(|(a, b)| a != b)
                .count(),
        );
    }
    worst
}

/// Evidence for the law. Ten full production-parameter setups, several minutes of
/// wall time, so it runs in the nightly production-cell lane rather than on every
/// commit. The cheap tests above encode its result and run everywhere.
#[test]
#[ignore = "ten production-parameter PIR setups (~4 min); nightly production-cell lane runs it with --run-ignored all"]
fn production_cell_width_ladder_is_empirically_correct() {
    for width in LEGAL_WIDTHS {
        let worst = worst_mismatch_at_width(width);
        assert_eq!(
            worst,
            0,
            "entry_size {width} (num_columns {}) is declared legal but round-tripped \
             {worst} wrong bytes",
            num_columns(width)
        );
    }
    // 8192 and 32768 are excluded: num_columns exceeds ring_dim and the packing
    // panics on an out-of-bounds generator-power lookup rather than returning bytes.
    for width in [328usize, 640, 4096] {
        let worst = worst_mismatch_at_width(width);
        assert!(
            worst > 0,
            "entry_size {width} (num_columns {}) round-tripped cleanly. The width law \
             is derived from this failing; if the InspiRING packing now supports \
             non-power-of-two or gamma == ring_dim widths, re-derive is_legal_cell_width \
             from the current generator formula before relaxing anything",
            num_columns(width)
        );
    }
}
