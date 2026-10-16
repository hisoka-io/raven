//! The pool's lean Merkle tree, at any leaf count a caller chooses.
//!
//! A level pairs its nodes left to right and hashes each pair with the level of the children;
//! a node left without a right sibling is carried up unhashed. The root of the first `n`
//! leaves therefore depends on `n`, and every root the tree ever had stays valid on chain, so
//! a wallet builds a path at the count its proof needs: two notes of one join under one root,
//! or a root another party fixed earlier.
//!
//! The node serves the leaves in blocks of [`BLOCK_LEAVES`] and, for every full block, its
//! node at level [`BLOCK_LEVEL`]. Those nodes never change once the block is full. With them
//! and the leaves of two blocks (the note's, and the one holding leaf `n - 1`) [`path_at`]
//! builds the full path at any `n`, and [`fold`] checks it by the circuit's own rule.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

/// Depth of the pool's tree.
pub const TREE_DEPTH: usize = 32;

/// Level of the node a full block contributes to the upper list.
pub const BLOCK_LEVEL: usize = 10;

/// Leaves in one block.
pub const BLOCK_LEAVES: u64 = 1 << BLOCK_LEVEL;

/// A tree node or leaf: a BN254 scalar, 32 bytes big-endian.
pub type Node = [u8; 32];

/// Why a path could not be built or checked.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum TreeError {
    /// The leaf is not in the tree of the first `n` leaves.
    #[error("leaf {index} is not below the leaf count {n}")]
    OutOfRange {
        /// Leaf asked for.
        index: u64,
        /// Leaf count asked for.
        n: u64,
    },
    /// A count beyond the tree's capacity.
    #[error("leaf count {n} exceeds the tree's capacity")]
    TooLarge {
        /// Leaf count asked for.
        n: u64,
    },
    /// Fewer leaves or upper nodes were given than the count needs.
    #[error("{what}: {given} given, {needed} needed")]
    Missing {
        /// Which input fell short.
        what: &'static str,
        /// Entries given.
        given: u64,
        /// Entries needed.
        needed: u64,
    },
    /// A value at or above the scalar modulus.
    #[error("a node is not a canonical BN254 scalar")]
    NonCanonical,
    /// A path whose index has a right child at a level the path says is empty, which the
    /// circuit refuses.
    #[error("leaf index {index} is a right child at empty level {level}")]
    NonCanonicalIndex {
        /// Leaf index of the path.
        index: u64,
        /// Level of the empty sibling.
        level: usize,
    },
}

fn scalar(bytes: &Node) -> Result<Fr, TreeError> {
    let fr = Fr::from_be_bytes_mod_order(bytes);
    if to_bytes(fr) == *bytes {
        Ok(fr)
    } else {
        Err(TreeError::NonCanonical)
    }
}

fn to_bytes(value: Fr) -> Node {
    let be = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let start = out.len().saturating_sub(be.len());
    if let Some(slot) = out.get_mut(start..) {
        if let Some(src) = be.get(be.len().saturating_sub(32)..) {
            slot.copy_from_slice(src);
        }
    }
    out
}

fn hash(left: Fr, right: Fr, level: usize) -> Fr {
    howl_poseidon2::hash(&[left, right, Fr::from(level as u64)])
}

/// The parent of two nodes at `level`: the pool's node hash, for callers that keep their own
/// levels.
///
/// # Errors
/// [`TreeError::NonCanonical`] for a value that is not a scalar.
pub fn parent(left: &Node, right: &Node, level: usize) -> Result<Node, TreeError> {
    Ok(to_bytes(hash(scalar(left)?, scalar(right)?, level)))
}

/// The level above `nodes`, which sit at `level`.
fn parents(nodes: &[Fr], level: usize) -> Vec<Fr> {
    nodes
        .chunks(2)
        .filter_map(|pair| match pair {
            [left, right] => Some(hash(*left, *right, level)),
            [lone] => Some(*lone),
            _ => None,
        })
        .collect()
}

/// Every level from `level` up to the root, starting with `nodes`.
fn levels_from(nodes: Vec<Fr>, level: usize) -> Vec<Vec<Fr>> {
    let mut out = vec![nodes];
    for at in level..TREE_DEPTH {
        let next = out
            .last()
            .map(|below| parents(below, at))
            .unwrap_or_default();
        out.push(next);
    }
    out
}

fn scalars(leaves: &[Node]) -> Result<Vec<Fr>, TreeError> {
    leaves.iter().map(scalar).collect()
}

/// The level-[`BLOCK_LEVEL`] node of a run of at most [`BLOCK_LEAVES`] leaves that starts at
/// a block boundary: the subtree root of a full block, the carried value of a partial one.
///
/// # Errors
/// [`TreeError::Missing`] for more than one block of leaves or none, and
/// [`TreeError::NonCanonical`] for a leaf that is not a scalar.
pub fn block_node(leaves: &[Node]) -> Result<Node, TreeError> {
    if leaves.is_empty() || leaves.len() as u64 > BLOCK_LEAVES {
        return Err(TreeError::Missing {
            what: "leaves of one block",
            given: leaves.len() as u64,
            needed: BLOCK_LEAVES,
        });
    }
    let mut nodes = scalars(leaves)?;
    for level in 0..BLOCK_LEVEL {
        nodes = parents(&nodes, level);
    }
    nodes
        .first()
        .copied()
        .map(to_bytes)
        .ok_or(TreeError::NonCanonical)
}

/// The inputs a path or a root at leaf count `n` is built from.
#[derive(Debug, Clone, Copy)]
pub struct TreeView<'a> {
    /// Leaf count the tree is taken at.
    pub n: u64,
    /// Level-[`BLOCK_LEVEL`] nodes of the full blocks, from block 0; at least `n / 1024`.
    pub upper: &'a [Node],
    /// Leaves of the block holding leaf `n - 1`, from its first leaf; at least up to that
    /// leaf. Unused when `n` is a multiple of [`BLOCK_LEAVES`].
    pub tail: &'a [Node],
}

impl TreeView<'_> {
    fn full_blocks(&self) -> u64 {
        self.n / BLOCK_LEAVES
    }

    fn tail_len(&self) -> u64 {
        self.n % BLOCK_LEAVES
    }

    fn check(&self) -> Result<(), TreeError> {
        if self.n > 1u64 << TREE_DEPTH {
            return Err(TreeError::TooLarge { n: self.n });
        }
        if (self.upper.len() as u64) < self.full_blocks() {
            return Err(TreeError::Missing {
                what: "upper nodes",
                given: self.upper.len() as u64,
                needed: self.full_blocks(),
            });
        }
        if (self.tail.len() as u64) < self.tail_len() {
            return Err(TreeError::Missing {
                what: "leaves of the newest block",
                given: self.tail.len() as u64,
                needed: self.tail_len(),
            });
        }
        Ok(())
    }

    /// Level-10 nodes at count `n`: the full blocks', then the newest partial block's.
    fn level_nodes(&self) -> Result<Vec<Fr>, TreeError> {
        let full = usize::try_from(self.full_blocks()).unwrap_or(usize::MAX);
        let mut nodes = scalars(self.upper.get(..full).unwrap_or_default())?;
        let tail = usize::try_from(self.tail_len()).unwrap_or(usize::MAX);
        if tail > 0 {
            nodes.push(scalar(&block_node(
                self.tail.get(..tail).unwrap_or_default(),
            )?)?);
        }
        Ok(nodes)
    }

    fn upper_levels(&self) -> Result<Vec<Vec<Fr>>, TreeError> {
        Ok(levels_from(self.level_nodes()?, BLOCK_LEVEL))
    }

    /// Levels 0 to [`BLOCK_LEVEL`] of block `block`, truncated at `n`.
    fn block_levels(&self, block: u64, leaves: &[Node]) -> Result<Vec<Vec<Fr>>, TreeError> {
        let start = block * BLOCK_LEAVES;
        let present = self.n.saturating_sub(start).min(BLOCK_LEAVES);
        if (leaves.len() as u64) < present {
            return Err(TreeError::Missing {
                what: "leaves of the note's block",
                given: leaves.len() as u64,
                needed: present,
            });
        }
        let present = usize::try_from(present).unwrap_or(usize::MAX);
        let mut levels = vec![scalars(leaves.get(..present).unwrap_or_default())?];
        for level in 0..BLOCK_LEVEL {
            let next = levels
                .last()
                .map(|below| parents(below, level))
                .unwrap_or_default();
            levels.push(next);
        }
        Ok(levels)
    }

    /// The root of the first `n` leaves; zero for an empty tree.
    ///
    /// # Errors
    /// [`TreeError::Missing`] when the inputs do not cover `n`.
    pub fn root(&self) -> Result<Node, TreeError> {
        self.check()?;
        let levels = self.upper_levels()?;
        Ok(levels
            .last()
            .and_then(|top| top.first())
            .copied()
            .map_or([0u8; 32], to_bytes))
    }

    /// The path of leaf `index`, whose block's leaves are `block_leaves`, in the tree of the
    /// first `n` leaves.
    ///
    /// # Errors
    /// [`TreeError::OutOfRange`] unless `index < n`, and [`TreeError::Missing`] when the
    /// inputs do not cover `n` or the note's block.
    pub fn path(&self, index: u64, block_leaves: &[Node]) -> Result<Path, TreeError> {
        self.check()?;
        if index >= self.n {
            return Err(TreeError::OutOfRange { index, n: self.n });
        }
        let block = index / BLOCK_LEAVES;
        let low = self.block_levels(block, block_leaves)?;
        let high = self.upper_levels()?;
        let mut siblings = [[0u8; 32]; TREE_DEPTH];
        for (level, slot) in siblings.iter_mut().enumerate() {
            let (nodes, position) = if level < BLOCK_LEVEL {
                (low.get(level), (index % BLOCK_LEAVES) >> level)
            } else {
                (high.get(level - BLOCK_LEVEL), index >> level)
            };
            let sibling = usize::try_from(position ^ 1)
                .ok()
                .and_then(|at| nodes.and_then(|nodes| nodes.get(at)));
            if let Some(node) = sibling {
                *slot = to_bytes(*node);
            }
        }
        let root = high
            .last()
            .and_then(|top| top.first())
            .copied()
            .map_or([0u8; 32], to_bytes);
        Ok(Path {
            index,
            siblings,
            root,
        })
    }

    /// The pending left node of every level whose bit is set in `n`, and the root: what an
    /// indexer needs to continue the tree from `n`. Levels whose bit is clear are zero.
    ///
    /// # Errors
    /// [`TreeError::Missing`] when the inputs do not cover `n`.
    pub fn frontier(&self) -> Result<(Vec<Node>, Node), TreeError> {
        self.check()?;
        let high = self.upper_levels()?;
        let tail_block = self.n.saturating_sub(1) / BLOCK_LEAVES;
        let low = self.block_levels(tail_block, self.tail)?;
        let mut side = vec![[0u8; 32]; TREE_DEPTH];
        for (level, slot) in side.iter_mut().enumerate() {
            if (self.n >> level) & 1 == 0 {
                continue;
            }
            let last = (self.n >> level) - 1;
            let node = if level < BLOCK_LEVEL {
                let offset = last - ((tail_block * BLOCK_LEAVES) >> level);
                usize::try_from(offset)
                    .ok()
                    .and_then(|at| low.get(level).and_then(|nodes| nodes.get(at)))
            } else {
                usize::try_from(last).ok().and_then(|at| {
                    high.get(level - BLOCK_LEVEL)
                        .and_then(|nodes| nodes.get(at))
                })
            };
            *slot = node.copied().map(to_bytes).ok_or(TreeError::Missing {
                what: "a frontier node",
                given: 0,
                needed: 1,
            })?;
        }
        let root = self.root()?;
        Ok((side, root))
    }
}

/// A leaf's path in the tree of a chosen leaf count, and the root it proves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    /// The leaf.
    pub index: u64,
    /// Sibling per level, zero where the level has no sibling at that count.
    pub siblings: [Node; TREE_DEPTH],
    /// Root of the tree at that count.
    pub root: Node,
}

/// The root a path proves for `leaf` at `index`, by the circuit's rule: a zero sibling means
/// the node is carried up unhashed, and is refused when the index says the node is a right
/// child there.
///
/// # Errors
/// [`TreeError::NonCanonicalIndex`] for a right child at an empty level, and
/// [`TreeError::NonCanonical`] for a value that is not a scalar.
pub fn fold(leaf: &Node, index: u64, siblings: &[Node; TREE_DEPTH]) -> Result<Node, TreeError> {
    let mut current = scalar(leaf)?;
    for (level, sibling) in siblings.iter().enumerate() {
        let right_child = (index >> level) & 1 == 1;
        if *sibling == [0u8; 32] {
            if right_child {
                return Err(TreeError::NonCanonicalIndex { index, level });
            }
            continue;
        }
        let sibling = scalar(sibling)?;
        current = if right_child {
            hash(sibling, current, level)
        } else {
            hash(current, sibling, level)
        };
    }
    Ok(to_bytes(current))
}
