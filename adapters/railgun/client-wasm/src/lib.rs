//! WASM client surface for the Raven Railgun adapter.
//!
//! Re-exports the generic PIR query/extract surface from `raven-client` (the
//! wasm-bindgen ABI and Rust API stay byte-stable through the re-export) and adds
//! the Railgun commitment-tree / PPOI per-list Merkle auth-path helpers.

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use wasm_bindgen::prelude::*;

pub use raven_client::*;

// must match raven-railgun-engine::imt::TREE_DEPTH; duplicated to keep this crate a leaf in the WASM dep graph
const PATH_INDEX_TREE_DEPTH: u32 = 16;
const PATH_INDEX_LEAVES_PER_TREE: u32 = 1u32 << PATH_INDEX_TREE_DEPTH;
const PATH_INDICES_LEN: usize = PATH_INDEX_TREE_DEPTH as usize;

/// Flat-global index for `(level, idx_at_level)`: leaves in `[0, 2^D)`, root at
/// `2^(D+1) - 2`. Mirrors `PerNodeEncoder::flat_index` in `raven-railgun-engine`.
fn flat_index_for(level: u32, idx_at_level: u32) -> u32 {
    let depth = PATH_INDEX_TREE_DEPTH;
    let total = 1u32 << (depth + 1);
    let level_offset = total - (1u32 << (depth + 1 - level));
    level_offset + idx_at_level
}

/// 16 flat-global row indices for the Merkle auth path of `leaf_idx` in a
/// commit tree (`PerNodeEncoder` layout). The wallet issues one PIR query per
/// index and reconstructs the path locally.
#[wasm_bindgen]
pub fn path_indices_for_leaf(tree_number: u32, leaf_idx: u32) -> Result<Vec<u32>, JsValue> {
    let _ = tree_number;
    if leaf_idx >= PATH_INDEX_LEAVES_PER_TREE {
        return Err(JsValue::from_str(&format!(
            "path_indices_for_leaf: leaf_idx {leaf_idx} >= 2^TREE_DEPTH ({PATH_INDEX_LEAVES_PER_TREE})"
        )));
    }
    let mut out = Vec::with_capacity(PATH_INDICES_LEN);
    let mut idx = leaf_idx;
    for level in 0..PATH_INDEX_TREE_DEPTH {
        let sibling_idx = idx ^ 1;
        out.push(flat_index_for(level, sibling_idx));
        idx >>= 1;
    }
    Ok(out)
}

/// 16 flat-global row indices for the Merkle auth path of per-list PPOI leaf
/// `idx` (`PerListNodeEncoder` layout). Mirror of [`path_indices_for_leaf`]
/// keyed on `list_key` rather than `tree_number`.
#[wasm_bindgen]
pub fn path_indices_for_per_list_leaf(list_key: &[u8], idx: u32) -> Result<Vec<u32>, JsValue> {
    if list_key.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "path_indices_for_per_list_leaf: list_key length {} must be 32",
            list_key.len()
        )));
    }
    if idx >= PATH_INDEX_LEAVES_PER_TREE {
        return Err(JsValue::from_str(&format!(
            "path_indices_for_per_list_leaf: idx {idx} >= 2^TREE_DEPTH ({PATH_INDEX_LEAVES_PER_TREE})"
        )));
    }
    let mut out = Vec::with_capacity(PATH_INDICES_LEN);
    let mut walk = idx;
    for level in 0..PATH_INDEX_TREE_DEPTH {
        let sibling_idx = walk ^ 1;
        out.push(flat_index_for(level, sibling_idx));
        walk >>= 1;
    }
    Ok(out)
}

/// Rust-native mirror of [`path_indices_for_leaf`].
pub fn path_indices_for_leaf_rust(tree_number: u32, leaf_idx: u32) -> Result<Vec<u32>, String> {
    let _ = tree_number;
    if leaf_idx >= PATH_INDEX_LEAVES_PER_TREE {
        return Err(format!(
            "path_indices_for_leaf: leaf_idx {leaf_idx} >= 2^TREE_DEPTH ({PATH_INDEX_LEAVES_PER_TREE})"
        ));
    }
    let mut out = Vec::with_capacity(PATH_INDICES_LEN);
    let mut idx = leaf_idx;
    for level in 0..PATH_INDEX_TREE_DEPTH {
        let sibling_idx = idx ^ 1;
        out.push(flat_index_for(level, sibling_idx));
        idx >>= 1;
    }
    Ok(out)
}

/// Rust-native mirror of [`path_indices_for_per_list_leaf`].
pub fn path_indices_for_per_list_leaf_rust(list_key: &[u8], idx: u32) -> Result<Vec<u32>, String> {
    if list_key.len() != 32 {
        return Err(format!(
            "path_indices_for_per_list_leaf: list_key length {} must be 32",
            list_key.len()
        ));
    }
    if idx >= PATH_INDEX_LEAVES_PER_TREE {
        return Err(format!(
            "path_indices_for_per_list_leaf: idx {idx} >= 2^TREE_DEPTH ({PATH_INDEX_LEAVES_PER_TREE})"
        ));
    }
    let mut out = Vec::with_capacity(PATH_INDICES_LEN);
    let mut walk = idx;
    for level in 0..PATH_INDEX_TREE_DEPTH {
        let sibling_idx = walk ^ 1;
        out.push(flat_index_for(level, sibling_idx));
        walk >>= 1;
    }
    Ok(out)
}

#[cfg(test)]
mod path_indices_tests {
    use super::*;

    #[test]
    fn path_indices_for_leaf_zero_matches_per_node_encoder_layout() {
        // leaf 0: sibling flat_index(0,1)=1, then flat_index(1,1)=2^16+1=65537
        let out = path_indices_for_leaf_rust(0, 0).expect("leaf 0 ok");
        assert_eq!(out[0], 1);
        assert_eq!(out[1], 65537);
    }

    #[test]
    fn path_indices_for_per_list_returns_same_layout_as_per_node_encoder() {
        // per-list and commit-tree share the flat layout: identical for the same index
        let key = [7u8; 32];
        let a = path_indices_for_leaf_rust(0, 1234).expect("leaf 1234 ok");
        let b = path_indices_for_per_list_leaf_rust(&key, 1234).expect("per-list 1234 ok");
        assert_eq!(a, b);
    }

    #[test]
    fn flat_index_root_is_total_minus_two() {
        let depth = PATH_INDEX_TREE_DEPTH;
        let total = 1u32 << (depth + 1);
        let root = flat_index_for(depth, 0);
        assert_eq!(root, total - 2);
    }
}
