//! Watches chain events for new tree numbers and signals when a new PIR
//! instance should be spawned. Pure and sync; callers handle the spawn.

/// Tracks the highest commitment-tree number seen on chain.
///
/// A boundary crossing (`tree_number > last_known_tree`) means tree
/// `last_known_tree` is sealed at `TREE_MAX_ITEMS` leaves and a new instance
/// is required for `tree_number`.
#[derive(Debug, Clone)]
pub struct TreeFillWatcher {
    last_known_tree: u32,
}

impl TreeFillWatcher {
    /// Seed at `initial_tree`, the highest tree number with a running instance at startup.
    pub fn new(initial_tree: u32) -> Self {
        Self {
            last_known_tree: initial_tree,
        }
    }

    /// Feed a tree number from a decoded chain event. Returns `Some(tree_number)`
    /// when strictly greater than `last_known_tree`; `None` otherwise.
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
