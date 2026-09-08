//! [`TreeFillWatcher`] — the mechanism whose absence caused the tree-4 outage:
//! a crossing to a higher tree number MUST fire exactly once, with that number.

use proptest::prelude::*;
use raven_railgun_engine::tree_fill_watcher::TreeFillWatcher;

/// The outage shape, pinned as a plain example: a watcher seeded at tree 0 must
/// fire when tree 1 appears, and not again for the same number.
#[test]
fn watcher_fires_on_new_tree_number() {
    let mut w = TreeFillWatcher::new(0);
    assert_eq!(w.observe_tree_number(0), None);
    assert_eq!(w.observe_tree_number(1), Some(1));
    assert_eq!(w.observe_tree_number(1), None);
    assert_eq!(w.last_known(), 1);
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        ..ProptestConfig::default()
    })]

    /// Model: the watcher is a running maximum. `Some(t)` exactly when `t` exceeds
    /// every number seen so far (including the seed); `last_known` tracks that
    /// maximum. Covers the retired examples' classes in one walk: increments
    /// (consecutive maxima), same-or-lower silence, and gap-skips (a chain event
    /// may report tree 3 after tree 0 if trees 1 and 2 filled before we watched).
    #[test]
    fn watcher_is_a_running_maximum_that_fires_exactly_on_crossings(
        initial in 0u32..1_000,
        observations in proptest::collection::vec(0u32..1_000, 1..40),
    ) {
        let mut w = TreeFillWatcher::new(initial);
        let mut model_max = initial;
        for &t in &observations {
            let fired = w.observe_tree_number(t);
            if t > model_max {
                prop_assert_eq!(
                    fired,
                    Some(t),
                    "crossing to {} above max {} must fire with the new tree number",
                    t,
                    model_max
                );
                model_max = t;
            } else {
                prop_assert_eq!(
                    fired,
                    None,
                    "observation {} at or below max {} must not fire (a re-fire \
                     would re-spawn an instance that already exists)",
                    t,
                    model_max
                );
            }
            prop_assert_eq!(w.last_known(), model_max, "last_known must track the maximum");
        }
    }
}
