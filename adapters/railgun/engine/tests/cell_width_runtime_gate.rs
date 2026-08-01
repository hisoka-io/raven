//! Runtime twin of the cell-width law: the boot-path gate, not the test-only predicate.
//!
//! The ladder re-asserted below is the one measured in `pir_cell_width_law.rs`. Both
//! suites pin the same table, so a change to either predicate breaks one of them.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_inspire::params::InspireParams;
use raven_railgun_engine::pir_table::{
    is_legal_cell_width, next_legal_cell_width, pir_cell_columns, validate_cell_shape,
    validate_cell_width, validate_rows_per_shard, EncoderKind, LEAVES_PER_TREE, NODE_HASH_BYTES,
    PATH_RECORD_BYTES, PER_NODE_TOTAL_NODES,
};

const LEGAL_WIDTHS: [usize; 7] = [32, 64, 128, 256, 512, 1024, 2048];
const ILLEGAL_WIDTHS: [usize; 5] = [328, 640, 4096, 8192, 32768];
const NOTE_RECORD_BYTES: usize = 328;

fn ring_dim() -> usize {
    InspireParams::secure_128_d2048().ring_dim
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
fn effective_record_size_predicts_what_build_returns() {
    let requested = 512usize;
    for kind in [
        EncoderKind::PerLeafBc,
        EncoderKind::PerLeafPath { tree_number: 0 },
        EncoderKind::PerNode { tree_number: 0 },
        EncoderKind::PerListStatus { list_key: [0; 32] },
        EncoderKind::PerListPath { list_key: [0; 32] },
        EncoderKind::PerListNode { list_key: [0; 32] },
    ] {
        let built = kind.build(requested, 2048).expect("build").record_size();
        assert_eq!(
            kind.effective_record_size(requested),
            built,
            "encoder {} must be able to report the width it will actually use before build",
            kind.label()
        );
    }
}

#[test]
fn fixed_layout_variants_report_their_canonical_width() {
    assert_eq!(EncoderKind::PerLeafBc.fixed_record_size(), None);
    assert_eq!(
        EncoderKind::PerListStatus { list_key: [0; 32] }.fixed_record_size(),
        None
    );
    assert_eq!(
        EncoderKind::PerLeafPath { tree_number: 0 }.fixed_record_size(),
        Some(PATH_RECORD_BYTES)
    );
    assert_eq!(
        EncoderKind::PerListPath { list_key: [0; 32] }.fixed_record_size(),
        Some(PATH_RECORD_BYTES)
    );
    assert_eq!(
        EncoderKind::PerNode { tree_number: 0 }.fixed_record_size(),
        Some(NODE_HASH_BYTES)
    );
    assert_eq!(
        EncoderKind::PerListNode { list_key: [0; 32] }.fixed_record_size(),
        Some(NODE_HASH_BYTES)
    );
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
    validate_cell_shape(&EncoderKind::PerLeafBc, leaves, 512, ring_dim).expect("per-leaf-bc 512");
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
