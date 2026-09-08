//! `EncoderKind` parity with what `build` returns — label, row width, and the per-node
//! flat-index round trip — plus degenerate-input rejection, list-key carry, and the
//! record-width constants those parity properties deliberately cannot pin.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::{
    EncoderKind, PerLeafCommitmentEncoder, PerLeafPathEncoder, PerListPathEncoder,
    PerListStatusEncoder, PerNodeEncoder, PirTableEncoder, MIN_RECORD_SIZE, NODE_HASH_BYTES,
    PATH_RECORD_BYTES,
};
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_testkit::canonical;

const ENTRIES: u32 = 65_536;
const RECORD: usize = 32;
const PATH_BYTES: usize = 16 * 32;
const LIST_KEY: [u8; 32] = [0xab; 32];
const TREE_DEPTH: u32 = 16;

/// Every variant, with the pin drawn rather than fixed: a parity law that holds only for
/// `tree_number: 0` or one hard-coded list key is not the law the boot path relies on.
fn any_encoder_kind() -> impl Strategy<Value = EncoderKind> {
    prop_oneof![
        any::<u32>().prop_map(|tree_number| EncoderKind::PerLeafBc { tree_number }),
        any::<u32>().prop_map(|tree_number| EncoderKind::PerLeafPath { tree_number }),
        any::<u32>().prop_map(|tree_number| EncoderKind::PerNode { tree_number }),
        any::<[u8; 32]>().prop_map(|list_key| EncoderKind::PerListStatus { list_key }),
        any::<[u8; 32]>().prop_map(|list_key| EncoderKind::PerListPath { list_key }),
        any::<[u8; 32]>().prop_map(|list_key| EncoderKind::PerListNode { list_key }),
    ]
}

fn any_entries() -> impl Strategy<Value = u32> {
    prop::sample::select(vec![64u32, 2048, 65_536])
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// `/v1/status` and every log line report `kind.label()` while the rows are produced by
    /// `kind.build(..)`. If those two ever disagree an operator reads the wrong encoder name
    /// off a live instance, which is how a mis-encoded cell stays invisible.
    #[test]
    fn encoder_kind_label_survives_build(
        kind in any_encoder_kind(),
        hint in MIN_RECORD_SIZE..2048usize,
        entries in any_entries(),
    ) {
        let built = kind
            .build(hint, entries)
            .map_err(|e| TestCaseError::fail(format!("build({hint}, {entries}): {e}")))?;
        prop_assert_eq!(
            kind.label(),
            built.label(),
            "kind {:?} reports a label its own build does not",
            kind
        );
    }

    /// The boot path gates on `effective_record_size` BEFORE building, so a variant whose
    /// prediction and construction disagree passes the width gate and then lays out rows at
    /// another width. Fixed-layout variants must additionally build at any hint at all —
    /// that is what "ignores the hint" has to mean for the gate to be sound.
    #[test]
    fn effective_record_size_predicts_build_and_fixed_layouts_ignore_the_hint(
        kind in any_encoder_kind(),
        hint in 1usize..2048,
        entries in any_entries(),
    ) {
        let predicted = kind.effective_record_size(hint);
        match kind.build(hint, entries) {
            Ok(built) => {
                prop_assert_eq!(
                    built.record_size(),
                    predicted,
                    "kind {:?} predicted {} at hint {} and built {}",
                    kind,
                    predicted,
                    hint,
                    built.record_size()
                );
                if let Some(fixed) = kind.fixed_record_size() {
                    prop_assert_eq!(predicted, fixed, "a fixed layout must predict its own width");
                    prop_assert_eq!(
                        built.record_size(),
                        fixed,
                        "kind {:?} let hint {} move a width its layout pins",
                        kind,
                        hint
                    );
                }
            }
            Err(err) => {
                prop_assert!(
                    kind.fixed_record_size().is_none(),
                    "kind {:?} has a canonical width and must build at any hint, including {}: {}",
                    kind,
                    hint,
                    err
                );
                prop_assert!(
                    hint < MIN_RECORD_SIZE,
                    "kind {:?} refused hint {}, which is at or above the {} floor: {}",
                    kind,
                    hint,
                    MIN_RECORD_SIZE,
                    err
                );
            }
        }
    }

    /// Every level gets a fresh uniform offset on every case, so no level is sampled on a
    /// stride. A flat index that survives the round trip at level L for even offsets and
    /// not odd ones is a real mis-encoding, and a strided walk cannot see it.
    #[test]
    fn per_node_flat_index_round_trips_at_every_level(
        draws in prop::collection::vec(any::<u32>(), (TREE_DEPTH as usize) + 1),
    ) {
        for (level, draw) in draws.iter().enumerate() {
            let level = u32::try_from(level).expect("level fits u32");
            let span = 1u32 << (TREE_DEPTH - level);
            let offset = draw % span;
            let flat = PerNodeEncoder::flat_index(level, offset);
            prop_assert_eq!(
                PerNodeEncoder::level_and_offset(flat),
                (level, offset),
                "flat index {} did not round trip",
                flat
            );
        }
    }
}

/// Pinned against literals on purpose. The parity property above asserts only that
/// prediction and construction MOVE TOGETHER, so a change to both at once — the exact shape
/// of a silent wire-format break — satisfies it. These two numbers are the wire.
#[test]
fn record_size_constants_are_pinned() {
    assert_eq!(
        PATH_RECORD_BYTES, 512,
        "a path record is 16 siblings x 32 B; changing it changes the served row width"
    );
    assert_eq!(
        NODE_HASH_BYTES, 32,
        "a node record is one Poseidon output; changing it changes the served row width"
    );
}

#[test]
fn per_leaf_bc_rejects_too_small_record_size() {
    let err = PerLeafCommitmentEncoder::new(31, ENTRIES, 0).expect_err("must reject 31");
    let msg = format!("{err}");
    assert!(
        msg.contains("must be >= 32"),
        "rejected with unexpected msg: {msg}"
    );
}

#[test]
fn per_leaf_bc_rejects_zero_entries_per_shard() {
    let err = PerLeafCommitmentEncoder::new(32, 0, 0).expect_err("must reject 0");
    let msg = format!("{err}");
    assert!(msg.contains("> 0"), "rejected with unexpected msg: {msg}");
}

#[test]
fn per_list_status_rejects_too_small_record_size() {
    let err = PerListStatusEncoder::new(8, ENTRIES, LIST_KEY).expect_err("must reject 8");
    let msg = format!("{err}");
    assert!(
        msg.contains("record_size 8") && msg.contains("must be >= 32"),
        "rejection must name the supplied width and the floor: {msg}"
    );
}

// The two list-key carries below are NOT folded into the parity properties above:
// `build` returns `Arc<dyn PirTableEncoder>` and `list_key()` is not on that trait, so no
// property phrased over build's return value can reach the pin at all.
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

/// The pin selects which tree's auth paths a shard carries. An empty store returns the
/// right number of zero bytes whatever the pin is, so the row contents are the only
/// assertion that can tell a mis-pinned encoder from a correct one.
#[test]
fn per_leaf_path_encoder_pins_tree_number() {
    const EPS: u32 = 8;
    const LEAVES: u32 = 5;
    const PINNED_TREE: u32 = 42;

    let seed_encoder = PerLeafPathEncoder::new(PATH_BYTES, EPS, 0).expect("build");
    let mut store = LogicalLeafStore::new();
    for (tree, base) in [(0u32, 1u8), (PINNED_TREE, 100u8)] {
        for leaf_index in 0..LEAVES {
            apply_wal_entry(
                &mut store,
                &WalEntryPayload::AppendLeaf {
                    tree_number: tree,
                    leaf_index,
                    commitment: canonical(
                        base.saturating_add(u8::try_from(leaf_index).expect("< 5")),
                    ),
                },
                100 + u64::from(leaf_index),
                &seed_encoder,
            )
            .expect("leaf applies");
        }
    }

    let pinned = PerLeafPathEncoder::new(PATH_BYTES, EPS, PINNED_TREE).expect("build");
    let bytes = pinned.materialize_shard(0, &store);
    assert_eq!(
        bytes.len(),
        PATH_BYTES * (EPS as usize),
        "shard byte count must match record_size * entries_per_shard"
    );

    let imt = store.imt(PINNED_TREE).expect("pinned tree present");
    for leaf_index in 0..LEAVES {
        let proof = imt
            .merkle_proof(leaf_index as usize)
            .expect("proof for an appended leaf");
        let row_start = leaf_index as usize * PATH_BYTES;
        for (sib_idx, sibling) in proof.elements.iter().enumerate() {
            let start = row_start + sib_idx * 32;
            assert_eq!(
                bytes
                    .get(start..start + 32)
                    .expect("sibling slice in range"),
                &sibling[..],
                "row {leaf_index} sibling {sib_idx} must byte-equal tree {PINNED_TREE}'s proof"
            );
        }
    }

    // Rows past the tip are filler. Non-zero filler reconstructs to some root, which a
    // client cannot tell from a real path for an index the tree does not hold yet.
    for row in LEAVES..EPS {
        let start = row as usize * PATH_BYTES;
        assert!(
            bytes
                .get(start..start + PATH_BYTES)
                .expect("row slice in range")
                .iter()
                .all(|b| *b == 0),
            "row {row} is past the tip and must be all zero, not a path-shaped value"
        );
    }

    let unpinned = PerLeafPathEncoder::new(PATH_BYTES, EPS, 0).expect("build");
    assert_ne!(
        unpinned.materialize_shard(0, &store),
        bytes,
        "the same store under a different pin must serve that tree's paths instead"
    );
}
