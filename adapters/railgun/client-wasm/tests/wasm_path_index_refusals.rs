//! The path-index exports refuse bad input through their `JsValue` error arm, carrying their
//! `_rust` mirror's message. wasm32 only: on any other target `JsValue::from_str` aborts the
//! process, which is why `wasm_panic_to_jsvalue.rs` can drive only the mirrors.

#![cfg(target_arch = "wasm32")]
#![allow(clippy::expect_used)]

use raven_inspire_client_wasm::{
    path_indices_for_leaf, path_indices_for_leaf_rust, path_indices_for_per_list_leaf,
    path_indices_for_per_list_leaf_rust,
};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

const LEAVES_PER_TREE: u32 = 1 << 16;
const LIST_KEY: [u8; 32] = [7; 32];

fn assert_same_refusal(export: Result<Vec<u32>, JsValue>, mirror: Result<Vec<u32>, String>) {
    let refusal = export.expect_err("the export must refuse");
    let reason = mirror.expect_err("the mirror must refuse");
    assert_eq!(refusal.as_string(), Some(reason));
}

#[wasm_bindgen_test]
fn leaf_index_past_the_tree_is_refused() {
    for leaf_idx in [LEAVES_PER_TREE, u32::MAX] {
        assert_same_refusal(
            path_indices_for_leaf(0, leaf_idx),
            path_indices_for_leaf_rust(0, leaf_idx),
        );
    }
}

#[wasm_bindgen_test]
fn per_list_key_of_the_wrong_length_is_refused() {
    for key in [&[][..], &LIST_KEY[..31], &[7; 33][..]] {
        assert_same_refusal(
            path_indices_for_per_list_leaf(key, 0),
            path_indices_for_per_list_leaf_rust(key, 0),
        );
    }
}

#[wasm_bindgen_test]
fn per_list_index_past_the_tree_is_refused() {
    assert_same_refusal(
        path_indices_for_per_list_leaf(&LIST_KEY, LEAVES_PER_TREE),
        path_indices_for_per_list_leaf_rust(&LIST_KEY, LEAVES_PER_TREE),
    );
}

#[wasm_bindgen_test]
fn in_range_input_is_not_refused() {
    let last = LEAVES_PER_TREE - 1;
    let leaf = path_indices_for_leaf(0, last).expect("the last leaf is in range");
    assert_eq!(Some(leaf), path_indices_for_leaf_rust(0, last).ok());
    let per_list = path_indices_for_per_list_leaf(&LIST_KEY, 0).expect("leaf 0 is in range");
    assert_eq!(
        Some(per_list),
        path_indices_for_per_list_leaf_rust(&LIST_KEY, 0).ok()
    );
}
