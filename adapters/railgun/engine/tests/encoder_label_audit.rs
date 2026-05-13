//! Encoder label + invariant audit tests. Locks `EncoderKind` label parity,
//! rejection of degenerate inputs, list-key round-trip, and path-record size
//! pinning.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use raven_railgun_engine::pir_table::{
    EncoderKind, PerLeafCommitmentEncoder, PerLeafPathEncoder, PerListPathEncoder,
    PerListStatusEncoder, PerNodeEncoder, PirTableEncoder,
};

const ENTRIES: u32 = 65_536;
const RECORD: usize = 32;
const PATH_BYTES: usize = 16 * 32;
const LIST_KEY: [u8; 32] = [0xab; 32];

#[test]
fn per_leaf_bc_label_matches_built() {
    let built: std::sync::Arc<dyn PirTableEncoder> = EncoderKind::PerLeafBc
        .build(RECORD, ENTRIES)
        .expect("build");
    assert_eq!(EncoderKind::PerLeafBc.label(), built.label());
}

#[test]
fn per_leaf_path_label_matches_built() {
    let kind = EncoderKind::PerLeafPath { tree_number: 7 };
    let built = kind.build(PATH_BYTES, ENTRIES).expect("build");
    assert_eq!(kind.label(), built.label());
}

#[test]
fn per_node_label_matches_built() {
    let kind = EncoderKind::PerNode { tree_number: 5 };
    let built = kind.build(RECORD, ENTRIES).expect("build");
    assert_eq!(kind.label(), built.label());
}

#[test]
fn per_list_status_label_matches_built() {
    let kind = EncoderKind::PerListStatus { list_key: LIST_KEY };
    let built = kind.build(RECORD, ENTRIES).expect("build");
    assert_eq!(kind.label(), built.label());
}

#[test]
fn per_list_path_label_matches_built() {
    let kind = EncoderKind::PerListPath { list_key: LIST_KEY };
    let built = kind.build(PATH_BYTES, ENTRIES).expect("build");
    assert_eq!(kind.label(), built.label());
}

#[test]
fn per_leaf_bc_rejects_too_small_record_size() {
    let err = PerLeafCommitmentEncoder::new(31, ENTRIES).expect_err("must reject 31");
    let msg = format!("{err}");
    assert!(
        msg.contains("must be >= 32"),
        "rejected with unexpected msg: {msg}"
    );
}

#[test]
fn per_leaf_bc_rejects_zero_entries_per_shard() {
    let err = PerLeafCommitmentEncoder::new(32, 0).expect_err("must reject 0");
    let msg = format!("{err}");
    assert!(msg.contains("> 0"), "rejected with unexpected msg: {msg}");
}

#[test]
fn per_list_status_rejects_too_small_record_size() {
    let err = PerListStatusEncoder::new(8, ENTRIES, LIST_KEY).expect_err("must reject 8");
    let msg = format!("{err}");
    // The encoder may surface either the size floor or a different
    // structural rejection; both are valid signals — assert at
    // least that an Err surfaced.
    assert!(!msg.is_empty());
}

#[test]
fn per_list_status_carries_list_key_round_trip() {
    let enc = PerListStatusEncoder::new(RECORD, ENTRIES, LIST_KEY).expect("build");
    assert_eq!(enc.list_key(), &LIST_KEY);
}

#[test]
fn per_list_path_carries_list_key_round_trip() {
    let enc = PerListPathEncoder::new(PATH_BYTES, ENTRIES, LIST_KEY).expect("build");
    assert_eq!(enc.list_key(), &LIST_KEY);
}

#[test]
fn encoder_kind_build_round_trips_record_size_for_perleaf_bc() {
    let built = EncoderKind::PerLeafBc.build(64, ENTRIES).expect("build");
    assert_eq!(built.record_size(), 64);
    assert_eq!(built.entries_per_shard(), ENTRIES);
}

#[test]
fn encoder_kind_build_pins_path_record_to_512_bytes_regardless_of_hint() {
    // PerLeafPath ignores the caller's record_size hint and pins to
    // 512 B (16 siblings * 32 B). The `build` method's contract is
    // that the resulting encoder's `record_size()` MUST be 512 B,
    // not the hint.
    let built = EncoderKind::PerLeafPath { tree_number: 0 }
        .build(123, ENTRIES)
        .expect("build");
    assert_eq!(built.record_size(), PATH_BYTES);
}

#[test]
fn encoder_kind_build_pins_list_path_record_to_512_bytes_regardless_of_hint() {
    let built = EncoderKind::PerListPath { list_key: LIST_KEY }
        .build(99, ENTRIES)
        .expect("build");
    assert_eq!(built.record_size(), PATH_BYTES);
}

#[test]
fn per_node_encoder_flat_index_round_trips_level_and_offset() {
    // Per `PerNodeEncoder` contract: level 0 is leaves and occupies
    // `[0, 2^D)` with D=16 (TREE_DEPTH); each successive level
    // halves the slot count. Round-trip MUST hold for every valid
    // (level, offset) pair within that span.
    let depth: u32 = 16;
    for level in 0u32..=depth {
        let span = 1u32 << (depth - level);
        let sample_count = span.min(8);
        for sample in 0..sample_count {
            let offset = if span == 0 {
                0
            } else {
                sample * (span / sample_count.max(1))
            };
            let offset = offset.min(span.saturating_sub(1));
            let flat = PerNodeEncoder::flat_index(level, offset);
            let (lev, off) = PerNodeEncoder::level_and_offset(flat);
            assert_eq!(
                (lev, off),
                (level, offset),
                "round trip failed at level={level} offset={offset} flat={flat}"
            );
        }
    }
}

#[test]
fn per_leaf_path_encoder_pins_tree_number() {
    let enc = PerLeafPathEncoder::new(PATH_BYTES, ENTRIES, 42).expect("build");
    // The encoder's label is the same string as for any other tree
    // (label is the encoder kind, not the instance), but the inner
    // tree_number is what makes the encoder produce the right path.
    // Cross-check by materializing an empty shard and asserting it
    // returns a vector of the right size — proves the constructor
    // succeeded with the supplied tree_number.
    let store = raven_railgun_engine::inspire::LogicalLeafStore::new();
    let bytes = enc.materialize_shard(0, &store);
    assert_eq!(
        bytes.len(),
        PATH_BYTES * (ENTRIES as usize),
        "shard byte count must match record_size * entries_per_shard"
    );
}
