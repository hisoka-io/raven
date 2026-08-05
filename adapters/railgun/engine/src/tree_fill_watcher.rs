//! Signals when a new tree number warrants a new PIR instance. Pure and sync;
//! callers own the spawn.

/// Highest commitment-tree number seen on chain. A crossing means the previous
/// tree is sealed and `tree_number` needs its own instance.
#[derive(Debug, Clone)]
pub struct TreeFillWatcher {
    last_known_tree: u32,
}

impl TreeFillWatcher {
    /// Seed at the highest tree number with a running instance.
    pub fn new(initial_tree: u32) -> Self {
        Self {
            last_known_tree: initial_tree,
        }
    }

    /// Feed a tree number; `Some` only when it exceeds the highest seen.
    pub fn observe_tree_number(&mut self, tree_number: u32) -> Option<u32> {
        if tree_number > self.last_known_tree {
            self.last_known_tree = tree_number;
            Some(tree_number)
        } else {
            None
        }
    }

    /// The highest tree number seen so far.
    pub fn last_known(&self) -> u32 {
        self.last_known_tree
    }
}
