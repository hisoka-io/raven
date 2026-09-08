//! The ACCEPT half of the capacity bound.
//!
//! `insert_rejects_overflow_past_capacity` (in-src, `#[ignore]`d, reachable only
//! through the engine-ignored CI lane) asserts that leaf `TREE_MAX_ITEMS` is refused.
//! Nothing asserted that the leaf BEFORE it is accepted, so tightening the comparison
//! by one wedges every tree a leaf early and the whole suite stays green under a
//! developer's default `cargo test`. This file is that missing direction, non-ignored.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use raven_railgun_engine::imt::{Imt, TREE_DEPTH, TREE_MAX_ITEMS};

fn leaf(i: usize) -> [u8; 32] {
    // High byte zero keeps every leaf a canonical BN254 Fr, which merkle_node requires.
    let mut buf = [0u8; 32];
    buf[24..].copy_from_slice(&u64::try_from(i).expect("index fits u64").to_be_bytes());
    buf
}

#[test]
fn a_tree_accepts_exactly_tree_max_items_leaves() {
    let mut tree = Imt::new().expect("imt build");

    // One leaf short of capacity, then the last one: both must be accepted, and the
    // boundary insert is the case a `>=` comparison would refuse.
    let bulk: Vec<[u8; 32]> = (0..TREE_MAX_ITEMS - 1).map(leaf).collect();
    tree.insert_leaves(0, &bulk).expect("fill to capacity - 1");
    assert_eq!(tree.leaf_count(), TREE_MAX_ITEMS - 1);

    tree.insert_leaves(TREE_MAX_ITEMS - 1, &[leaf(TREE_MAX_ITEMS - 1)])
        .expect("the LAST legal leaf must be accepted");
    assert_eq!(
        tree.leaf_count(),
        TREE_MAX_ITEMS,
        "a depth-{TREE_DEPTH} tree holds exactly {TREE_MAX_ITEMS} leaves"
    );

    // The full tree still serves a proof for its rightmost leaf; a capacity guard that
    // accepted the insert but left the path unhashed would pass the count assert alone.
    let proof = tree
        .merkle_proof(TREE_MAX_ITEMS - 1)
        .expect("proof for the last leaf");
    assert_eq!(proof.root, tree.root());
    assert_eq!(
        usize::from(proof.indices),
        TREE_MAX_ITEMS - 1,
        "indices must carry the full depth-{TREE_DEPTH} path; a narrower field truncates it"
    );

    // And the reject direction still holds one past the end.
    tree.insert_leaves(TREE_MAX_ITEMS, &[leaf(0)])
        .expect_err("one past capacity must be refused");
}
