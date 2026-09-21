//! The pre-WAL screen relates a `PpoiListLeafAdded` to the upstream root it carries.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use proptest::prelude::*;
use raven_railgun_engine::imt::Imt;
use raven_railgun_engine::inspire::{apply_wal_entry, validate_apply, LogicalLeafStore};
use raven_railgun_engine::pir_table::PerListStatusEncoder;
use raven_railgun_engine::ppoi_root::PpoiRootDivergence;
use raven_railgun_persistence::WalEntryPayload;

const LIST_KEY: [u8; 32] = [0x5c; 32];

fn encoder() -> PerListStatusEncoder {
    PerListStatusEncoder::new(64, 2048, LIST_KEY).expect("encoder")
}

fn list_leaf(list_index: u32, leaf: [u8; 32], validated_merkleroot: [u8; 32]) -> WalEntryPayload {
    WalEntryPayload::PpoiListLeafAdded {
        list_key: LIST_KEY,
        list_index,
        blinded_commitment: leaf,
        status: 0,
        event_type: raven_railgun_persistence::PpoiEventType::Shield,
        signature: vec![0; 64],
        validated_merkleroot,
    }
}

/// A store holding `leaves`, plus the root a feed would publish for `next` appended after
/// them. The root comes from a tree grown here, never from the store under test.
fn store_and_next_root(leaves: &[[u8; 32]], next: [u8; 32]) -> (LogicalLeafStore, [u8; 32]) {
    let mut reference = Imt::new().expect("reference imt");
    let mut store = LogicalLeafStore::new();
    for (i, leaf) in leaves.iter().enumerate() {
        reference
            .insert_leaves(i, &[*leaf])
            .expect("reference insert");
        let row = list_leaf(u32::try_from(i).expect("small"), *leaf, reference.root());
        apply_wal_entry(&mut store, &row, 0, &encoder()).expect("seed row");
    }
    reference
        .insert_leaves(leaves.len(), &[next])
        .expect("reference insert of next");
    (store, reference.root())
}

#[test]
fn a_root_that_is_not_the_post_append_root_is_refused_without_mutating() {
    let seeded = [
        raven_railgun_testkit::canonical(1),
        raven_railgun_testkit::canonical(2),
    ];
    let next = raven_railgun_testkit::canonical(3);
    let (store, upstream_root) = store_and_next_root(&seeded, next);
    let root_before = store.ppoi_imt_root(&LIST_KEY);

    validate_apply(&store, &list_leaf(2, next, upstream_root))
        .expect("the row carrying its own post-append root passes the screen");

    // The root BEFORE the append is the nearest wrong answer a confused producer could send.
    let stale_root = root_before.expect("two leaves seeded");
    let refusal = validate_apply(&store, &list_leaf(2, next, stale_root))
        .expect_err("a pre-append root is not the root this append produces");
    let message = refusal.to_string();
    for needle in [
        "5c5c5c5c".to_owned(),
        "list_index 2".to_owned(),
        hex(&stale_root),
        hex(&upstream_root),
    ] {
        assert!(
            message.contains(&needle),
            "refusal must name {needle}: {message}"
        );
    }
    assert_eq!(store.ppoi_imt_root(&LIST_KEY), root_before);
}

#[test]
fn the_first_row_of_a_list_is_held_to_its_root_too() {
    let first = raven_railgun_testkit::canonical(9);
    let (store, upstream_root) = store_and_next_root(&[], first);
    validate_apply(&store, &list_leaf(0, first, upstream_root)).expect("row 0 with its own root");
    let mut wrong = upstream_root;
    wrong[0] ^= 0x80;
    validate_apply(&store, &list_leaf(0, first, wrong))
        .expect_err("no tree exists yet, and the root is still checked");
}

fn counted(snapshotter: &Snapshotter, name: &str) -> u64 {
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(composite, _, _, value)| match value {
            DebugValue::Counter(count) if composite.key().name() == name => Some(count),
            _ => None,
        })
        .sum()
}

#[test]
fn a_divergence_is_typed_with_both_roots_and_counted_once() {
    let seeded = [raven_railgun_testkit::canonical(1)];
    let next = raven_railgun_testkit::canonical(2);
    let (store, upstream_root) = store_and_next_root(&seeded, next);
    let mut published = upstream_root;
    published[17] ^= 0x04;

    assert_eq!(
        store
            .ppoi_root_divergence(&LIST_KEY, &next, &upstream_root)
            .expect("hashable leaf"),
        None
    );
    assert_eq!(
        store
            .ppoi_root_divergence(&LIST_KEY, &next, &published)
            .expect("hashable leaf"),
        Some(PpoiRootDivergence {
            list_key: LIST_KEY,
            list_index: 1,
            local_root: upstream_root,
            upstream_root: published,
        })
    );

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        validate_apply(&store, &list_leaf(1, next, upstream_root)).expect("own root passes");
        validate_apply(&store, &list_leaf(1, next, published)).expect_err("divergent root");
    });
    assert_eq!(
        counted(&snapshotter, "raven_railgun_ppoi_root_divergence_total"),
        1
    );
    assert_eq!(
        counted(&snapshotter, "raven_railgun_ppoi_root_unasserted_total"),
        0
    );
}

// Upstream serves a stored tree root with every row or omits the row, so an all-zero root is
// never upstream's. It is what in-process producers with no root to assert write, and the
// screen lets it through UNCOMPARED. This pins that the bypass is counted, and that the
// comparison itself has no such exemption.
#[test]
fn an_all_zero_root_is_applied_uncompared_and_counted_as_unasserted() {
    let first = raven_railgun_testkit::canonical(5);
    let (store, _) = store_and_next_root(&[], first);

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        validate_apply(&store, &list_leaf(0, first, [0; 32])).expect("zero root is not compared");
    });
    assert_eq!(
        counted(&snapshotter, "raven_railgun_ppoi_root_unasserted_total"),
        1
    );
    assert_eq!(
        counted(&snapshotter, "raven_railgun_ppoi_root_divergence_total"),
        0
    );

    let strict = store
        .ppoi_root_divergence(&LIST_KEY, &first, &[0; 32])
        .expect("hashable leaf")
        .expect("zero is not the root of any tree");
    assert_eq!(strict.upstream_root, [0; 32]);
}

fn canonical_leaf() -> impl Strategy<Value = [u8; 32]> {
    // High byte zero keeps the value below the BN254 scalar modulus.
    any::<[u8; 31]>().prop_map(|tail| {
        let mut leaf = [0u8; 32];
        leaf[1..].copy_from_slice(&tail);
        leaf
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn the_screen_passes_exactly_the_post_append_root(
        seeded in proptest::collection::vec(canonical_leaf(), 0..6),
        next in canonical_leaf(),
        flipped_bit in proptest::option::of(0usize..256),
    ) {
        let (store, upstream_root) = store_and_next_root(&seeded, next);
        let mut published = upstream_root;
        if let Some(bit) = flipped_bit {
            let byte = published.get_mut(bit / 8).expect("bit index below 256");
            *byte ^= 1 << (bit % 8);
        }
        let index = u32::try_from(seeded.len()).expect("small");
        let outcome = validate_apply(&store, &list_leaf(index, next, published));
        prop_assert_eq!(outcome.is_ok(), flipped_bit.is_none(), "{:?}", outcome);
    }

    #[test]
    fn the_previewed_root_is_the_root_the_append_produces(
        leaves in proptest::collection::vec(canonical_leaf(), 1..10),
        keep in 0usize..10,
    ) {
        let mut tree = Imt::new().expect("imt");
        let (last, prefix) = leaves.split_last().expect("at least one leaf");
        tree.insert_leaves(0, prefix).expect("prefix");
        // A rewind must not leave a node behind that the preview then reads.
        tree.truncate_to(keep.min(prefix.len()));
        let (root_before, count_before) = (tree.root(), tree.leaf_count());
        let previewed = tree.root_after_append(*last).expect("preview");
        prop_assert_eq!((tree.root(), tree.leaf_count()), (root_before, count_before));
        tree.insert_leaves(tree.leaf_count(), &[*last]).expect("append");
        prop_assert_eq!(previewed, tree.root());
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}
