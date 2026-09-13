//! The boot-path cell-width gate: the legal-width ladder, the rejection messages an
//! operator reads, and the empirical sweep that shows the ladder is the real one.
//!
//! `EncoderKind` width parity moved to `encoder_label_audit.rs` as a property over every
//! variant; the two examples that lived here tested one requested width, 512.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_inspire::inspiring::PackParams;
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_engine::inspire::{
    build_client_session, build_seeded_query, extract_response, register_client_session,
    setup_state,
};
use raven_railgun_engine::pir_table::{
    is_legal_cell_width, next_legal_cell_width, pir_cell_columns, validate_cell_shape,
    validate_cell_width, validate_rows_per_shard, EncoderKind, LEAVES_PER_TREE, NODE_HASH_BYTES,
    PATH_RECORD_BYTES, PER_NODE_TOTAL_NODES,
};
use raven_railgun_engine::PirScheme;

const LEGAL_WIDTHS: [usize; 7] = [32, 64, 128, 256, 512, 1024, 2048];
const ILLEGAL_WIDTHS: [usize; 5] = [328, 640, 4096, 8192, 32768];
const NOTE_RECORD_BYTES: usize = 328;

fn ring_dim() -> usize {
    InspireParams::secure_128_d2048().ring_dim
}

#[test]
fn adapter_width_predicate_matches_inspire_for_every_ring_shape() {
    for ring_dim in 0usize..=4096 {
        for columns in (0..=11).map(|shift| 1usize << shift) {
            let entry_size = columns * 2;
            assert_eq!(
                is_legal_cell_width(entry_size, ring_dim),
                PackParams::is_legal_width(ring_dim, columns),
                "predicate drift at ring_dim {ring_dim}, entry_size {entry_size}"
            );
        }
    }
}

#[test]
fn runtime_gate_agrees_with_the_pinned_ladder() {
    let ring_dim = ring_dim();
    assert_eq!(ring_dim, 2048, "production ring dimension changed");
    for width in LEGAL_WIDTHS {
        assert!(
            is_legal_cell_width(width, ring_dim),
            "width {width} (num_columns {}) is pinned legal by the empirical ladder",
            pir_cell_columns(width)
        );
        validate_cell_width(width, ring_dim)
            .unwrap_or_else(|e| panic!("pinned-legal width {width} must validate: {e}"));
    }
    for width in ILLEGAL_WIDTHS {
        assert!(
            !is_legal_cell_width(width, ring_dim),
            "width {width} (num_columns {}) is pinned illegal by the empirical ladder",
            pir_cell_columns(width)
        );
        assert!(
            validate_cell_width(width, ring_dim).is_err(),
            "pinned-illegal width {width} must be rejected at runtime, not only in a test"
        );
    }
}

#[test]
fn note_record_rejection_names_width_columns_and_the_next_legal_width() {
    let err = validate_cell_width(NOTE_RECORD_BYTES, ring_dim())
        .expect_err("328 must be rejected")
        .to_string();
    for needle in ["328", "164", "512"] {
        assert!(
            err.contains(needle),
            "rejection must name {needle} (offending width, induced columns, next legal width): {err}"
        );
    }
}

#[test]
fn zero_width_is_rejected_with_its_own_reason() {
    let err = validate_cell_width(0, ring_dim())
        .expect_err("zero width must be rejected")
        .to_string();
    assert!(
        err.contains("must be > 0"),
        "zero width needs its own reason, not a column-count one: {err}"
    );
}

#[test]
fn odd_entry_widths_round_up_before_the_law_is_checked() {
    assert_eq!(pir_cell_columns(3), 2);
    assert!(is_legal_cell_width(3, ring_dim()));
    assert_eq!(pir_cell_columns(5), 3);
    assert!(!is_legal_cell_width(5, ring_dim()));
}

#[test]
fn widths_past_the_ring_dim_ceiling_have_no_legal_successor() {
    let ring_dim = ring_dim();
    assert_eq!(
        next_legal_cell_width(NOTE_RECORD_BYTES, ring_dim),
        Some(512)
    );
    assert_eq!(next_legal_cell_width(640, ring_dim), Some(1024));
    assert_eq!(next_legal_cell_width(2048, ring_dim), Some(2048));
    assert_eq!(next_legal_cell_width(4096, ring_dim), None);
    let err = validate_cell_width(4096, ring_dim)
        .expect_err("4096 must be rejected")
        .to_string();
    assert!(
        err.contains("2048"),
        "past the ceiling the operator needs the maximum legal width: {err}"
    );
}

#[test]
fn next_legal_width_rounds_onto_the_ladder_not_onto_the_predicate() {
    let ring_dim = ring_dim();
    assert_eq!(
        next_legal_cell_width(0, ring_dim),
        None,
        "zero is not a width, so it has no successor to offer as a remedy"
    );
    for width in [63usize, 511] {
        assert!(
            is_legal_cell_width(width, ring_dim),
            "width {width} satisfies the column-count predicate on its own"
        );
        let next = next_legal_cell_width(width, ring_dim).expect("successor below the ceiling");
        assert!(
            next > width && LEGAL_WIDTHS.contains(&next),
            "next_legal_cell_width({width}) must round up onto a measured ladder width, got {next}"
        );
    }
}

#[test]
fn per_node_rejects_a_record_size_its_layout_will_not_honor() {
    let ring_dim = ring_dim();
    let kind = EncoderKind::PerNode { tree_number: 0 };
    let err = validate_cell_shape(&kind, PER_NODE_TOTAL_NODES as usize + 1, 512, ring_dim)
        .expect_err("per-node with a 512-byte request must be rejected, not silently downgraded")
        .to_string();
    assert!(err.contains("512"), "must name the requested width: {err}");
    assert!(err.contains("32"), "must name the canonical width: {err}");
    validate_cell_shape(
        &kind,
        PER_NODE_TOTAL_NODES as usize + 1,
        NODE_HASH_BYTES,
        ring_dim,
    )
    .expect("per-node at its canonical width must validate");
}

#[test]
fn shipped_cell_shapes_pass_the_runtime_gate() {
    let ring_dim = ring_dim();
    let leaves = LEAVES_PER_TREE as usize;
    let nodes = PER_NODE_TOTAL_NODES as usize + 1;
    validate_cell_shape(
        &EncoderKind::PerLeafBc { tree_number: 0 },
        leaves,
        512,
        ring_dim,
    )
    .expect("per-leaf-bc 512");
    validate_cell_shape(
        &EncoderKind::PerLeafPath { tree_number: 0 },
        leaves,
        PATH_RECORD_BYTES,
        ring_dim,
    )
    .expect("per-leaf-path 512");
    validate_cell_shape(
        &EncoderKind::PerNode { tree_number: 0 },
        nodes,
        NODE_HASH_BYTES,
        ring_dim,
    )
    .expect("per-node 32");
    validate_cell_shape(
        &EncoderKind::PerListStatus { list_key: [0; 32] },
        leaves,
        512,
        ring_dim,
    )
    .expect("per-list-status 512");
}

#[test]
fn rows_per_shard_must_equal_ring_dim_in_both_directions() {
    let ring_dim = ring_dim();
    validate_rows_per_shard(2048, ring_dim).expect("the shipped rows-per-shard must validate");
    for supplied in [1u32, 256, 1024, 2047, 2049, 4096, 131_070] {
        assert!(
            validate_rows_per_shard(supplied, ring_dim).is_err(),
            "rows per shard {supplied} != ring_dim {ring_dim} must be rejected at boot"
        );
    }
}

#[test]
fn under_width_rows_per_shard_rejection_names_supplied_required_and_reason() {
    let err = validate_rows_per_shard(1024, ring_dim())
        .expect_err("1024 rows per shard must be rejected")
        .to_string();
    for needle in ["1024", "2048", "ring_dim", "entry_size"] {
        assert!(
            err.contains(needle),
            "rejection must name {needle} (supplied, required, the requirement, its source): {err}"
        );
    }
}

#[test]
fn cell_shape_still_enforces_the_total_entries_floor() {
    let kind = EncoderKind::PerNode { tree_number: 0 };
    let err = validate_cell_shape(&kind, 65_536, NODE_HASH_BYTES, ring_dim())
        .expect_err("an undersized per-node cell must still be rejected")
        .to_string();
    assert!(err.contains("131071"), "must cite the entry floor: {err}");
}

// ---------------------------------------------------------------------------
// The empirical ladder, moved here from pir_cell_width_law.rs so the width
// table has ONE home. The InspiRING generator `2n / gamma + 1` divides
// integrally, so an off-law gamma picks the wrong automorphism and decrypts to
// unrelated bytes; setup refuses an off-law width up front, so the ladder
// asserts refusal rather than the wrong bytes it used to measure. The cheap
// tests above encode its result.
// ---------------------------------------------------------------------------

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

/// `Some(error)` when setup refuses the width, `None` when it accepts.
fn setup_rejection_at_width(entry_size: usize) -> Option<String> {
    let params = InspireParams::secure_128_d2048();
    let db = vec![0u8; 8 * entry_size];
    setup_state(&params, &db, entry_size, InspireVariant::TwoPacking)
        .err()
        .map(|e| e.to_string())
}

/// Evidence for the law. Seven production-parameter round trips plus five early
/// refusals take minutes, so the cheap tests above encode the result.
#[test]
#[ignore = "seven production-parameter setups at d=2048 (~7 s each), plus five widths that setup \
            refuses before it builds the packing table; ~150 s in CI. Trigger: changing \
            is_legal_cell_width, the InspiRING generator, or a shipped encoder record width. The \
            nightly production-cell-closure job runs it with --run-ignored all."]
fn production_cell_width_ladder_is_empirically_correct() {
    for width in LEGAL_WIDTHS {
        let worst = worst_mismatch_at_width(width);
        assert_eq!(
            worst,
            0,
            "entry_size {width} (num_columns {}) is declared legal but round-tripped \
             {worst} wrong bytes",
            pir_cell_columns(width)
        );
    }
    for width in ILLEGAL_WIDTHS {
        let err = setup_rejection_at_width(width).unwrap_or_else(|| {
            panic!(
                "entry_size {width} (num_columns {}) was accepted by setup. The width law is \
                 derived from this being refused; if the InspiRING packing now supports \
                 non-power-of-two or gamma >= ring_dim widths, re-derive is_legal_cell_width \
                 from the current generator formula before relaxing anything",
                pir_cell_columns(width)
            )
        });
        assert!(
            err.contains(&width.to_string()),
            "entry_size {width} was refused, but the error never names the width: {err}"
        );
    }
}
