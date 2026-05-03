//! Unit tests for [`TreeFillWatcher`].

use raven_railgun_engine::tree_fill_watcher::TreeFillWatcher;

#[test]
fn watcher_fires_on_new_tree_number() {
    let mut w = TreeFillWatcher::new(0);
    assert_eq!(w.observe_tree_number(0), None);
    assert_eq!(w.observe_tree_number(1), Some(1));
    assert_eq!(w.observe_tree_number(1), None);
    assert_eq!(w.last_known(), 1);
}

#[test]
fn watcher_tracks_multiple_increments() {
    let mut w = TreeFillWatcher::new(0);
    assert_eq!(w.observe_tree_number(0), None);
    assert_eq!(w.observe_tree_number(1), Some(1));
    assert_eq!(w.observe_tree_number(2), Some(2));
    assert_eq!(w.observe_tree_number(3), Some(3));
    assert_eq!(w.last_known(), 3);
}

#[test]
fn watcher_ignores_same_or_lower() {
    let mut w = TreeFillWatcher::new(5);
    assert_eq!(w.observe_tree_number(5), None);
    assert_eq!(w.observe_tree_number(3), None);
    assert_eq!(w.observe_tree_number(5), None);
    assert_eq!(w.last_known(), 5);
}

#[test]
fn watcher_skips_gap_correctly() {
    // A chain event may report tree 3 after tree 0 if trees 1 and 2
    // were filled before we started watching.
    let mut w = TreeFillWatcher::new(0);
    assert_eq!(w.observe_tree_number(3), Some(3));
    assert_eq!(w.observe_tree_number(3), None);
    assert_eq!(w.observe_tree_number(4), Some(4));
    assert_eq!(w.last_known(), 4);
}
