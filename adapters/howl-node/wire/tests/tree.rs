//! The tree arithmetic against a from-scratch fold and against the pool's own insert walk.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use howl_wire::tree::{block_node, fold, Node, TreeError, TreeView, BLOCK_LEAVES, TREE_DEPTH};

fn bytes(value: Fr) -> Node {
    let be = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

fn leaves(count: u64) -> Vec<Node> {
    (1..=count).map(|i| bytes(Fr::from(i * 7919 + 3))).collect()
}

/// The root of `leaves`, pairs hashed with their level, a lone node carried.
fn naive_root(leaves: &[Node]) -> Node {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut nodes: Vec<Fr> = leaves
        .iter()
        .map(|l| Fr::from_be_bytes_mod_order(l))
        .collect();
    let mut level = 0u64;
    while nodes.len() > 1 {
        nodes = nodes
            .chunks(2)
            .map(|pair| match pair {
                [l, r] => howl_poseidon2::hash(&[*l, *r, Fr::from(level)]),
                _ => pair[0],
            })
            .collect();
        level += 1;
    }
    bytes(nodes[0])
}

fn upper(all: &[Node]) -> Vec<Node> {
    all.chunks(BLOCK_LEAVES as usize)
        .filter(|block| block.len() == BLOCK_LEAVES as usize)
        .map(|block| block_node(block).expect("block node"))
        .collect()
}

fn view<'a>(all: &'a [Node], upper: &'a [Node], n: u64) -> TreeView<'a> {
    let tail_start = (n.saturating_sub(1) / BLOCK_LEAVES * BLOCK_LEAVES) as usize;
    TreeView {
        n,
        upper,
        tail: &all[tail_start..],
    }
}

fn block_of(all: &[Node], index: u64) -> &[Node] {
    let start = (index / BLOCK_LEAVES * BLOCK_LEAVES) as usize;
    &all[start..(start + BLOCK_LEAVES as usize).min(all.len())]
}

const COUNTS: [u64; 14] = [
    0, 1, 2, 3, 1_023, 1_024, 1_025, 2_047, 2_048, 2_049, 3_071, 3_072, 4_100, 5_000,
];

#[test]
fn the_root_at_any_count_is_the_from_scratch_fold() {
    let all = leaves(5_000);
    let upper = upper(&all);
    for n in COUNTS {
        assert_eq!(
            view(&all, &upper, n).root().expect("root"),
            naive_root(&all[..n as usize]),
            "n = {n}"
        );
    }
}

#[test]
fn every_path_folds_to_the_root_of_its_count_and_no_other() {
    let all = leaves(5_000);
    let upper = upper(&all);
    let mut state = 0x1234_5678u64;
    let mut next = |bound: u64| {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        (state >> 33) % bound
    };
    for n in COUNTS.into_iter().filter(|n| *n > 0) {
        let root = naive_root(&all[..n as usize]);
        let mut indices = vec![0, n - 1, n / 2];
        indices.extend((0..6).map(|_| next(n)));
        for index in indices {
            let path = view(&all, &upper, n)
                .path(index, block_of(&all, index))
                .expect("path");
            assert_eq!(path.root, root);
            assert_eq!(
                fold(&all[index as usize], index, &path.siblings),
                Ok(root),
                "{index} at {n}"
            );
            if n > 1 {
                let other = (index + 1) % n;
                assert_ne!(fold(&all[other as usize], index, &path.siblings), Ok(root));
            }
        }
    }
}

#[test]
fn the_newest_leaf_is_a_carried_right_edge_and_the_circuit_rule_holds() {
    let all = leaves(5);
    let path = view(&all, &[], 5).path(4, &all).expect("path");
    // Leaf 4 of five has no sibling at levels 0 and 1, and the subtree of four at level 2.
    assert_eq!(path.siblings[0], [0u8; 32]);
    assert_eq!(path.siblings[1], [0u8; 32]);
    assert_ne!(path.siblings[2], [0u8; 32]);
    assert!(path.siblings[3..].iter().all(|s| *s == [0u8; 32]));
    // Claiming leaf 5 with the same siblings makes it a right child at an empty level.
    assert_eq!(
        fold(&all[4], 5, &path.siblings),
        Err(TreeError::NonCanonicalIndex { index: 5, level: 0 })
    );
}

/// The pool's insert walk over a frontier: an even position parks its node, an odd one
/// hashes with the parked node.
fn insert(side: &mut [Fr; TREE_DEPTH], count: &mut u64, leaf: Fr) -> Node {
    let mut node = leaf;
    let mut index = *count;
    for (level, slot) in side.iter_mut().enumerate() {
        if index & 1 == 0 {
            *slot = node;
            if index == 0 {
                break;
            }
        } else {
            node = howl_poseidon2::hash(&[*slot, node, Fr::from(level as u64)]);
        }
        index >>= 1;
    }
    *count += 1;
    bytes(node)
}

#[test]
fn a_frontier_continues_the_tree_exactly() {
    let all = leaves(5_000);
    let upper = upper(&all);
    for n in [0u64, 1, 2, 1_023, 1_024, 1_025, 2_048, 3_000, 4_095] {
        let (side, root) = view(&all, &upper, n).frontier().expect("frontier");
        assert_eq!(root, naive_root(&all[..n as usize]));
        let mut nodes = [Fr::from(0u64); TREE_DEPTH];
        for (slot, node) in nodes.iter_mut().zip(&side) {
            *slot = Fr::from_be_bytes_mod_order(node);
        }
        let mut count = n;
        for next in n..(n + 70).min(5_000) {
            let root = insert(
                &mut nodes,
                &mut count,
                Fr::from_be_bytes_mod_order(&all[next as usize]),
            );
            assert_eq!(
                root,
                naive_root(&all[..=next as usize]),
                "from {n}, leaf {next}"
            );
        }
    }
}

#[test]
fn short_inputs_are_refused() {
    let all = leaves(3_000);
    let upper = upper(&all);
    assert!(matches!(
        TreeView {
            n: 3_000,
            upper: &upper[..1],
            tail: &all[2_048..]
        }
        .root(),
        Err(TreeError::Missing { .. })
    ));
    assert!(matches!(
        TreeView {
            n: 3_000,
            upper: &upper,
            tail: &all[2_048..2_100]
        }
        .root(),
        Err(TreeError::Missing { .. })
    ));
    assert_eq!(
        view(&all, &upper, 3_000).path(3_000, block_of(&all, 2_999)),
        Err(TreeError::OutOfRange {
            index: 3_000,
            n: 3_000
        })
    );
    assert!(block_node(&[]).is_err());
    assert!(block_node(&all[..1_025]).is_err());
}

/// Roots of `leaves` at chosen counts, and one path, from the pool wallet's own
/// `LeanIMT` (TypeScript), so the levels above a block are checked against Howl's code.
const WALLET_TREE_ROOTS: [(u64, &str); 12] = [
    (
        1_023,
        "079ff6da732322bc09a5ea24d4496802a243abeb67f3d3d8e8a487446c0c8ca3",
    ),
    (
        1_024,
        "2d75423ef73853b0fc452aba8ad665e2ae39cb936541ce45a0c9a89477066c02",
    ),
    (
        1_025,
        "176f0285e6de4cbd403d52184bd52236140e79a6dcfd82896d3f7e1b6c568b85",
    ),
    (
        2_047,
        "0ef2fe575fe0cff6f4611a091623ba597132918c72e526a4bd19e5d493beb949",
    ),
    (
        2_048,
        "2e5199a46a5120021fb1be950f93e2c92a80542614614278484e23b696d26d52",
    ),
    (
        2_049,
        "17e12a0f7e0d0812893db71a06c9a6354be9980069a9499fe24cc7d919f948dc",
    ),
    (
        3_071,
        "0bf2ccf2bfca2be976ee5d190beb22d62b8e46f00fad9d70d13c39c831b6eca6",
    ),
    (
        3_073,
        "1c18598fd94a84b730dde7d7f8f1c067812fb864370a1de05d338d046279d4ff",
    ),
    (
        4_096,
        "0101d08b53a28338306845e82bd3fab74995b0c6046c01186d8d7aebfc0d130a",
    ),
    (
        4_097,
        "2a3d7cfc8fe9184ea824e40f9109d1c3ddba039c4fc09842a16b968984570f40",
    ),
    (
        5_000,
        "1f6d606ef5f65a89af333369ac5d164bad86fdbbcc99ebc61562476ecdc9fe03",
    ),
    (
        6_145,
        "149e0e6c645aac695da7f28d0b1110c83db35efdd5ca2dac64124bc753d81ea6",
    ),
];
const WALLET_TREE_PATH: (u64, u64, [&str; 32]) = (
    6_145,
    4_100,
    [
        "0000000000000000000000000000000000000000000000000000000001efa99d",
        "004f2753f7994826e4c17caf3e18d73967723c5fb5f41755aa474b85ee8bd853",
        "0426ee73b621edb07916e07a9cc8d29414044e5551730c35d46a733a41e42424",
        "06ff8dac73428d7d81b8261d2bafefa24f16da1a59bcdcf60552fcc8ab396629",
        "0992208f22022c09e07e5ed5bd4e1e8fce00a4cfe3955daa2d62d3cc3508bd23",
        "05791a9a3d3ae3973920b89de3290091c4d8b68d6b86ece0f72177b70212f700",
        "0dcda8a0696653b37799462e8dfdb4234af88375b28cb1e95303edbd5b852c26",
        "14f008747a1b10e9cd642437972ae89251645d302c511c6d8df302e9f72073c6",
        "29cf4b26a214945f3d3622e2f034bcd13dda713c85281d87901bf92ec16a3b5c",
        "22179c7ee73ac0acf24bdff6ce1ee3ff7e2f85a99909aef7a26cd03423579b02",
        "147a2a7418c47c5e37434984e6b30fbe5b523c2f50c36231da013f6c18ea7a05",
        "0000000000000000000000000000000000000000000000000000000002e686f2",
        "0101d08b53a28338306845e82bd3fab74995b0c6046c01186d8d7aebfc0d130a",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
    ],
);

fn node_hex(text: &str) -> Node {
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16).expect("hex");
    }
    out
}

#[test]
fn roots_and_a_path_above_a_block_match_the_wallets_own_tree() {
    let all = leaves(6_145);
    let upper = upper(&all);
    for (n, root) in WALLET_TREE_ROOTS {
        assert_eq!(
            view(&all, &upper, n).root().expect("root"),
            node_hex(root),
            "{n}"
        );
    }
    let (n, index, siblings) = WALLET_TREE_PATH;
    let path = view(&all, &upper, n)
        .path(index, block_of(&all, index))
        .expect("path");
    assert_eq!(path.siblings, siblings.map(node_hex));
    assert_eq!(
        fold(&all[index as usize], index, &path.siblings).expect("fold"),
        node_hex(WALLET_TREE_ROOTS[WALLET_TREE_ROOTS.len() - 1].1)
    );
}
