//! WASM client surface: `raven-client`'s PIR query/extract exports (byte-stable
//! through the re-export) plus the commitment-tree auth-path helper.

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use wasm_bindgen::prelude::*;

pub use raven_client::*;

// The published wasm must refuse a served parameter set below the floors.
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(
    raven_client::PARAMETER_FLOORS_ENFORCED,
    "raven-client was built with unfloored-test-params"
);

// Must match raven-railgun-engine::imt::TREE_DEPTH; duplicated to keep this crate
// a leaf in the WASM dep graph.
const PATH_INDEX_TREE_DEPTH: u32 = 16;
const PATH_INDEX_LEAVES_PER_TREE: u32 = 1u32 << PATH_INDEX_TREE_DEPTH;
const PATH_INDICES_LEN: usize = PATH_INDEX_TREE_DEPTH as usize;

/// 16 flat-global row indices for the auth path of `leaf_idx` under the
/// `PerNodeEncoder` layout; one PIR query per index, reconstructed client-side.
#[wasm_bindgen]
pub fn path_indices_for_leaf(tree_number: u32, leaf_idx: u32) -> Result<Vec<u32>, JsValue> {
    path_indices_for_leaf_impl(tree_number, leaf_idx).map_err(|error| JsValue::from_str(&error))
}

fn path_indices(operation: &str, index_name: &str, idx: u32) -> Result<Vec<u32>, String> {
    if idx >= PATH_INDEX_LEAVES_PER_TREE {
        return Err(format!(
            "{operation}: {index_name} {idx} >= 2^TREE_DEPTH ({PATH_INDEX_LEAVES_PER_TREE})"
        ));
    }
    let mut indices = Vec::with_capacity(PATH_INDICES_LEN);
    let mut walk = idx;
    for level in 0..PATH_INDEX_TREE_DEPTH {
        let sibling_idx = walk ^ 1;
        indices.push(raven_railgun_core::tree_layout::flat_index(
            PATH_INDEX_TREE_DEPTH,
            level,
            sibling_idx,
        ));
        walk >>= 1;
    }
    Ok(indices)
}

fn path_indices_for_leaf_impl(tree_number: u32, leaf_idx: u32) -> Result<Vec<u32>, String> {
    let _ = tree_number;
    path_indices("path_indices_for_leaf", "leaf_idx", leaf_idx)
}

/// Rust-native mirror of [`path_indices_for_leaf`].
pub fn path_indices_for_leaf_rust(tree_number: u32, leaf_idx: u32) -> Result<Vec<u32>, String> {
    path_indices_for_leaf_impl(tree_number, leaf_idx)
}

#[cfg(test)]
mod path_indices_tests {
    use super::*;

    #[test]
    fn path_indices_for_leaf_zero_matches_per_node_encoder_layout() {
        let out = path_indices_for_leaf_rust(0, 0).expect("leaf 0 ok");
        assert_eq!(out[0], 1);
        assert_eq!(out[1], 65537);
    }

    #[test]
    fn flat_index_root_is_total_minus_two() {
        let depth = PATH_INDEX_TREE_DEPTH;
        let total = 1u32 << (depth + 1);
        let root = raven_railgun_core::tree_layout::flat_index(depth, depth, 0);
        assert_eq!(root, total - 2);
    }
}
