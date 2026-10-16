//! The pool's lean tree kept level by level, so that appending hashes only what is new and a
//! root or a sibling at any earlier count costs one walk down the right edge.
//!
//! Only complete nodes are kept: level `k` holds node `j` once the base nodes
//! `[j << k, (j + 1) << k)` are all present. A node on the right edge of a shorter count is
//! rebuilt from the complete nodes below it, carrying a lone left child up unhashed as the
//! circuit does.

use howl_wire::tree::{self, Node, TreeError, BLOCK_LEAVES, BLOCK_LEVEL, TREE_DEPTH};

/// A run of nodes appended at `base_level`, and every complete node above it up to `top`.
#[derive(Debug, Clone)]
pub(crate) struct Levels {
    base_level: usize,
    levels: Vec<Vec<Node>>,
}

impl Levels {
    /// Levels from `base_level` up to `top` (the level of the single root).
    pub(crate) fn new(base_level: usize, top: usize) -> Self {
        Self {
            base_level,
            levels: vec![Vec::new(); top - base_level + 1],
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.levels.first().map_or(0, Vec::len)
    }

    pub(crate) fn base(&self) -> &[Node] {
        self.levels.first().map_or(&[], Vec::as_slice)
    }

    /// Append one base node; hashes each node it completes.
    pub(crate) fn push(&mut self, node: Node) -> Result<(), TreeError> {
        let depth = self.levels.len();
        let Some(base) = self.levels.first_mut() else {
            return Ok(());
        };
        base.push(node);
        let len = base.len();
        for k in 1..depth {
            if len % (1usize << k) != 0 {
                break;
            }
            let (below, above) = self.levels.split_at_mut(k);
            let (Some(below), Some(above)) = (below.last(), above.first_mut()) else {
                break;
            };
            let j = above.len();
            let (Some(left), Some(right)) = (below.get(2 * j), below.get(2 * j + 1)) else {
                break;
            };
            above.push(tree::parent(left, right, self.base_level + k - 1)?);
        }
        Ok(())
    }

    /// Keep the first `m` base nodes.
    pub(crate) fn truncate(&mut self, m: usize) {
        for (k, level) in self.levels.iter_mut().enumerate() {
            level.truncate(m >> k);
        }
    }

    /// Node `j` at relative level `k` of the tree of the first `m` base nodes, with `extra`
    /// standing at base index `m` when given (a node not kept here); `None` past the end.
    pub(crate) fn node(
        &self,
        k: usize,
        j: usize,
        m: usize,
        extra: Option<&Node>,
    ) -> Result<Option<Node>, TreeError> {
        let present = m + usize::from(extra.is_some());
        let start = j << k;
        if start >= present {
            return Ok(None);
        }
        if (j + 1) << k <= m {
            if let Some(node) = self.levels.get(k).and_then(|level| level.get(j)) {
                return Ok(Some(*node));
            }
        }
        if k == 0 {
            return Ok(if j == m {
                extra.copied()
            } else {
                self.base().get(j).copied()
            });
        }
        let left = self.node(k - 1, 2 * j, m, extra)?;
        let right = self.node(k - 1, 2 * j + 1, m, extra)?;
        Ok(match (left, right) {
            (Some(left), Some(right)) => {
                Some(tree::parent(&left, &right, self.base_level + k - 1)?)
            }
            (left, None) => left,
            (None, Some(_)) => None,
        })
    }

    /// The single node at the top level for the first `m` base nodes (and `extra`).
    pub(crate) fn top(&self, m: usize, extra: Option<&Node>) -> Result<Option<Node>, TreeError> {
        self.node(self.levels.len() - 1, 0, m, extra)
    }
}

/// The level-10 nodes of the full blocks, the newest block's leaves, and any other full block
/// a path needed, each kept as [`Levels`].
#[derive(Debug, Clone)]
pub(crate) struct Tree {
    upper: Levels,
    newest_index: u64,
    newest: Levels,
    blocks: Vec<(u64, Levels)>,
}

const MAX_HELD_BLOCKS: usize = 8;

fn missing(what: &'static str, given: u64, needed: u64) -> TreeError {
    TreeError::Missing {
        what,
        given,
        needed,
    }
}

impl Default for Tree {
    fn default() -> Self {
        Self {
            upper: Levels::new(BLOCK_LEVEL, TREE_DEPTH),
            newest_index: 0,
            newest: Levels::new(0, BLOCK_LEVEL),
            blocks: Vec::new(),
        }
    }
}

impl Tree {
    pub(crate) fn full_blocks(&self) -> u64 {
        self.upper.len() as u64
    }

    pub(crate) fn upper_nodes(&self) -> &[Node] {
        self.upper.base()
    }

    pub(crate) fn newest_index(&self) -> u64 {
        self.newest_index
    }

    pub(crate) fn newest_leaves(&self) -> &[Node] {
        self.newest.base()
    }

    pub(crate) fn append_upper(&mut self, nodes: &[Node]) -> Result<(), TreeError> {
        for node in nodes {
            self.upper.push(*node)?;
        }
        Ok(())
    }

    /// Hold `leaves` as block `index`'s leaves; only leaves past a held prefix are hashed.
    pub(crate) fn set_newest(&mut self, index: u64, leaves: &[Node]) -> Result<(), TreeError> {
        if leaves.len() as u64 > BLOCK_LEAVES {
            return Err(missing(
                "leaves of one block",
                leaves.len() as u64,
                BLOCK_LEAVES,
            ));
        }
        let held = self.newest.base();
        let shared = held.iter().zip(leaves).take_while(|(a, b)| a == b).count();
        if index != self.newest_index {
            self.newest = Levels::new(0, BLOCK_LEVEL);
            self.newest_index = index;
        } else {
            self.newest.truncate(shared);
        }
        for leaf in leaves.get(self.newest.len()..).unwrap_or_default() {
            self.newest.push(*leaf)?;
        }
        Ok(())
    }

    /// Keep a full block's leaves after checking they hash to its held upper node.
    pub(crate) fn add_block(&mut self, index: u64, leaves: &[Node]) -> Result<(), TreeError> {
        if leaves.len() as u64 != BLOCK_LEAVES {
            return Err(missing(
                "leaves of a full block",
                leaves.len() as u64,
                BLOCK_LEAVES,
            ));
        }
        let held = usize::try_from(index)
            .ok()
            .and_then(|i| self.upper.base().get(i))
            .copied()
            .ok_or(missing("upper nodes", self.full_blocks(), index + 1))?;
        let mut levels = Levels::new(0, BLOCK_LEVEL);
        for leaf in leaves {
            levels.push(*leaf)?;
        }
        if levels.top(leaves.len(), None)? != Some(held) {
            return Err(TreeError::NonCanonical);
        }
        self.blocks.retain(|(b, _)| *b != index);
        if self.blocks.len() >= MAX_HELD_BLOCKS {
            self.blocks.remove(0);
        }
        self.blocks.push((index, levels));
        Ok(())
    }

    /// Leaf `index`, from the newest block or a held full block.
    pub(crate) fn leaf(&self, index: u64) -> Option<Node> {
        let (levels, _) = self.block(index / BLOCK_LEAVES, index + 1).ok()?;
        levels
            .base()
            .get(usize::try_from(index % BLOCK_LEAVES).ok()?)
            .copied()
    }

    /// Whether block `b`'s leaves are held (the newest block, or a full block kept for paths).
    pub(crate) fn holds(&self, b: u64) -> bool {
        b == self.newest_index || self.blocks.iter().any(|(i, _)| *i == b)
    }

    /// Drop every leaf from `n` on.
    pub(crate) fn truncate(&mut self, n: u64) {
        let full = usize::try_from(n / BLOCK_LEAVES).unwrap_or(usize::MAX);
        self.upper.truncate(full);
        self.blocks.retain(|(b, _)| *b < n / BLOCK_LEAVES);
        if self.newest_index > n / BLOCK_LEAVES || n.is_multiple_of(BLOCK_LEAVES) {
            self.newest = Levels::new(0, BLOCK_LEVEL);
            self.newest_index = n / BLOCK_LEAVES;
        } else {
            self.newest
                .truncate(usize::try_from(n % BLOCK_LEAVES).unwrap_or(usize::MAX));
        }
    }

    /// Block `b`'s levels, if held, with the leaves present at `n`.
    fn block(&self, b: u64, n: u64) -> Result<(&Levels, usize), TreeError> {
        let present = n.saturating_sub(b * BLOCK_LEAVES).min(BLOCK_LEAVES);
        let levels = if b == self.newest_index {
            Some(&self.newest)
        } else {
            self.blocks.iter().find(|(i, _)| *i == b).map(|(_, l)| l)
        };
        match levels {
            Some(levels) if levels.len() as u64 >= present => {
                Ok((levels, usize::try_from(present).unwrap_or(usize::MAX)))
            }
            _ => Err(missing("leaves of a block not held", 0, present)),
        }
    }

    /// The level-10 node of the partial block holding leaf `n - 1`, if that block is partial.
    fn tail_node(&self, n: u64) -> Result<Option<Node>, TreeError> {
        if n.is_multiple_of(BLOCK_LEAVES) {
            return Ok(None);
        }
        let (levels, present) = self.block(n / BLOCK_LEAVES, n)?;
        levels.top(present, None)
    }

    fn check(&self, n: u64) -> Result<usize, TreeError> {
        if n > 1u64 << TREE_DEPTH {
            return Err(TreeError::TooLarge { n });
        }
        if n / BLOCK_LEAVES > self.full_blocks() {
            return Err(missing("upper nodes", self.full_blocks(), n / BLOCK_LEAVES));
        }
        Ok(usize::try_from(n / BLOCK_LEAVES).unwrap_or(usize::MAX))
    }

    /// The root of the first `n` leaves; zero for an empty tree.
    pub(crate) fn root(&self, n: u64) -> Result<Node, TreeError> {
        let full = self.check(n)?;
        let tail = self.tail_node(n)?;
        Ok(self.upper.top(full, tail.as_ref())?.unwrap_or([0u8; 32]))
    }

    /// Siblings of leaf `index` from level 0 up, and the root, at count `n`.
    pub(crate) fn path(&self, index: u64, n: u64) -> Result<([Node; TREE_DEPTH], Node), TreeError> {
        let full = self.check(n)?;
        if index >= n {
            return Err(TreeError::OutOfRange { index, n });
        }
        let tail = self.tail_node(n)?;
        let (own, present) = self.block(index / BLOCK_LEAVES, n)?;
        let mut siblings = [[0u8; 32]; TREE_DEPTH];
        for (level, slot) in siblings.iter_mut().enumerate() {
            let at = usize::try_from((index >> level) ^ 1).unwrap_or(usize::MAX);
            let node = if level < BLOCK_LEVEL {
                let within = (index % BLOCK_LEAVES) >> level;
                own.node(
                    level,
                    usize::try_from(within ^ 1).unwrap_or(usize::MAX),
                    present,
                    None,
                )?
            } else {
                self.upper
                    .node(level - BLOCK_LEVEL, at, full, tail.as_ref())?
            };
            if let Some(node) = node {
                *slot = node;
            }
        }
        let root = self.upper.top(full, tail.as_ref())?.unwrap_or([0u8; 32]);
        Ok((siblings, root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use howl_wire::tree::TreeView;

    fn leaf(seed: u64) -> Node {
        let mut out = [0u8; 32];
        let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0xdead_beef;
        for byte in out.iter_mut().skip(1) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *byte = (x & 0xff) as u8;
        }
        out[1] &= 0x0f;
        out
    }

    fn reference(leaves: &[Node], n: u64) -> (Vec<Node>, Vec<Node>) {
        let full = (n / BLOCK_LEAVES) as usize;
        let upper: Vec<Node> = (0..full)
            .map(|b| tree::block_node(&leaves[b * 1024..(b + 1) * 1024]).expect("node"))
            .collect();
        let tail = leaves[full * 1024..n as usize].to_vec();
        (upper, tail)
    }

    /// Feeds a tree the way a wallet does: upper deltas and the newest block, sync by sync.
    fn grown(leaves: &[Node], counts: &[u64]) -> Tree {
        let mut t = Tree::default();
        for &n in counts {
            let (upper, tail) = reference(leaves, n);
            t.append_upper(&upper[t.full_blocks() as usize..])
                .expect("upper");
            t.set_newest(n / BLOCK_LEAVES, &tail).expect("newest");
        }
        t
    }

    #[test]
    fn roots_and_paths_match_the_tree_built_from_scratch() {
        let leaves: Vec<Node> = (0..3_300).map(leaf).collect();
        let t = grown(
            &leaves,
            &[1, 5, 700, 1_024, 1_100, 2_047, 2_048, 2_049, 3_300],
        );
        let mut t = t;
        for b in 0..3 {
            t.add_block(b, &leaves[b as usize * 1024..(b as usize + 1) * 1024])
                .expect("block");
        }
        let mut checked = 0;
        for n in [
            3_300u64, 3_072, 3_073, 2_049, 2_048, 1_025, 1_024, 1_023, 2, 1,
        ] {
            let (upper, tail) = reference(&leaves, n);
            let view = TreeView {
                n,
                upper: &upper,
                tail: &tail,
            };
            // a prefix count inside a block that is not held cannot be served
            if t.root(n).is_err() {
                assert!(n % 1024 != 0 && n / 1024 >= 3, "{n}");
                continue;
            }
            assert_eq!(
                t.root(n).expect("root"),
                view.root().expect("ref"),
                "root at {n}"
            );
            for index in [0, 1, n / 2, n.saturating_sub(2), n - 1]
                .into_iter()
                .filter(|i| *i < n)
            {
                let b = (index / 1024) as usize;
                let block = &leaves[b * 1024..((b + 1) * 1024).min(leaves.len())];
                let want = view.path(index, block).expect("ref path");
                let (siblings, root) = t.path(index, n).expect("path");
                assert_eq!(
                    (siblings, root),
                    (want.siblings, want.root),
                    "{index} at {n}"
                );
                checked += 1;
            }
        }
        assert!(checked > 30);
    }

    #[test]
    fn appending_hashes_only_what_is_new_and_truncation_rewinds() {
        let leaves: Vec<Node> = (0..2_500).map(|i| leaf(i + 7)).collect();
        let mut t = grown(&leaves, &[2_500]);
        let (upper, tail) = reference(&leaves, 2_500);
        let full = TreeView {
            n: 2_500,
            upper: &upper,
            tail: &tail,
        };
        assert_eq!(t.root(2_500).expect("root"), full.root().expect("ref"));
        t.truncate(1_500);
        assert_eq!(t.full_blocks(), 1);
        assert_eq!(
            t.newest_leaves().len(),
            0,
            "the newest block was past the cut"
        );
        // regrow on a different chain from the cut
        let mut other = leaves[..1_500].to_vec();
        other.extend((0..900).map(|i| leaf(i + 99_999)));
        let (upper, tail) = reference(&other, 2_400);
        t.append_upper(&upper[1..]).expect("upper");
        t.set_newest(2, &tail).expect("newest");
        let view = TreeView {
            n: 2_400,
            upper: &upper,
            tail: &tail,
        };
        assert_eq!(t.root(2_400).expect("root"), view.root().expect("ref"));
        // a newest block whose held prefix changed is rebuilt from the change
        let mut changed = tail.clone();
        changed[3] = leaf(5);
        t.set_newest(2, &changed).expect("newest");
        let view = TreeView {
            n: 2_400,
            upper: &upper,
            tail: &changed,
        };
        assert_eq!(t.root(2_400).expect("root"), view.root().expect("ref"));
    }

    #[test]
    fn a_block_that_does_not_hash_to_its_upper_node_is_refused() {
        let leaves: Vec<Node> = (0..2_048).map(leaf).collect();
        let mut t = grown(&leaves, &[2_048]);
        assert!(t.add_block(0, &leaves[..1024]).is_ok());
        assert!(t.add_block(1, &leaves[..1024]).is_err());
        assert!(t.add_block(2, &leaves[..1024]).is_err());
    }
}
