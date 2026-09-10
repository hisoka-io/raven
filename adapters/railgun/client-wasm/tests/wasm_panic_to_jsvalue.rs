//! Every export must surface bad input as a typed error or a caught panic, never a
//! WASM trap or native abort.
//!
//! Only the path-index exports are covered here: the query/extract/decode surface is
//! `pub use raven_client::*` (src/lib.rs), so its panic-safety tests live with the
//! function bodies in `crates/client/tests/panic_safety.rs`, which CI actually runs.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#![cfg(not(target_arch = "wasm32"))]

use std::panic::{self, AssertUnwindSafe};

use proptest::prelude::*;
use raven_inspire_client_wasm::{path_indices_for_leaf_rust, path_indices_for_per_list_leaf_rust};

const TREE_DEPTH: u32 = 16;
const LEAVES_PER_TREE: u32 = 1u32 << TREE_DEPTH;

fn expected_path_indices(idx: u32) -> Vec<u32> {
    (0..TREE_DEPTH)
        .map(|level| {
            let sibling_idx = (idx >> level) ^ 1;
            let level_offset = (1u32 << (TREE_DEPTH + 1)) - (1u32 << (TREE_DEPTH + 1 - level));
            level_offset + sibling_idx
        })
        .collect()
}

fn list_key_classes() -> impl Strategy<Value = (Vec<u8>, Vec<u8>, Vec<u8>)> {
    (
        prop::collection::vec(any::<u8>(), 32),
        prop::collection::vec(any::<u8>(), 0..32),
        prop::collection::vec(any::<u8>(), 33..64),
    )
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn path_indices_are_total(
        tree_number in any::<u32>(),
        (valid_key, short_key, long_key) in list_key_classes(),
        idx in prop_oneof![
            0u32..LEAVES_PER_TREE,
            Just(LEAVES_PER_TREE),
            Just(u32::MAX),
            65_530u32..65_545u32,
        ],
    ) {
        let leaf_outcome = panic::catch_unwind(AssertUnwindSafe(|| {
            path_indices_for_leaf_rust(tree_number, idx)
        }));
        let Ok(leaf_result) = leaf_outcome else {
            return Err(TestCaseError::fail(format!(
                "path_indices_for_leaf_rust panicked for leaf_idx {idx}"
            )));
        };

        if idx < LEAVES_PER_TREE {
            match leaf_result {
                Ok(indices) => {
                    prop_assert_eq!(indices.len(), TREE_DEPTH as usize);
                    prop_assert_eq!(indices, expected_path_indices(idx));
                }
                Err(err) => prop_assert!(false, "valid leaf_idx {idx} returned {err}"),
            }
        } else {
            match leaf_result {
                Ok(indices) => prop_assert!(
                    false,
                    "invalid leaf_idx {idx} returned {} indices",
                    indices.len()
                ),
                Err(err) => {
                    let index_needle = format!("leaf_idx {idx}");
                    prop_assert!(err.contains(&index_needle), "got {err}");
                    prop_assert!(err.contains(">= 2^TREE_DEPTH"), "got {err}");
                }
            }
        }

        for list_key in [valid_key, short_key, long_key] {
            let per_list_outcome = panic::catch_unwind(AssertUnwindSafe(|| {
                path_indices_for_per_list_leaf_rust(&list_key, idx)
            }));
            let Ok(per_list_result) = per_list_outcome else {
                return Err(TestCaseError::fail(format!(
                    "path_indices_for_per_list_leaf_rust panicked for key length {} and idx {idx}",
                    list_key.len()
                )));
            };

            if list_key.len() == 32 && idx < LEAVES_PER_TREE {
                match per_list_result {
                    Ok(indices) => {
                        prop_assert_eq!(indices.len(), TREE_DEPTH as usize);
                        prop_assert_eq!(indices, expected_path_indices(idx));
                    }
                    Err(err) => prop_assert!(false, "valid key and idx {idx} returned {err}"),
                }
            } else {
                match per_list_result {
                    Ok(indices) => prop_assert!(
                        false,
                        "invalid key length {} or idx {idx} returned {} indices",
                        list_key.len(),
                        indices.len()
                    ),
                    Err(err) if list_key.len() != 32 => {
                        let length_needle = format!("list_key length {} must be 32", list_key.len());
                        prop_assert!(err.contains(&length_needle), "got {err}");
                    }
                    Err(err) => {
                        let index_needle = format!("idx {idx}");
                        prop_assert!(err.contains(&index_needle), "got {err}");
                        prop_assert!(err.contains(">= 2^TREE_DEPTH"), "got {err}");
                    }
                }
            }
        }
    }
}
