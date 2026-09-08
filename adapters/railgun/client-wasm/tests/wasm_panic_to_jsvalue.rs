//! Every export must surface bad input as a typed error or a caught panic, never a
//! WASM trap or native abort.
//!
//! Only the path-index exports are covered here: the query/extract/decode surface is
//! `pub use raven_client::*` (src/lib.rs), so its panic-safety tests live with the
//! function bodies in `crates/client/tests/panic_safety.rs`, which CI actually runs.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::panic::{self, AssertUnwindSafe};

use raven_inspire_client_wasm::{path_indices_for_leaf_rust, path_indices_for_per_list_leaf_rust};

const TREE_DEPTH: u32 = 16;
const LEAVES_PER_TREE: u32 = 1u32 << TREE_DEPTH;

#[test]
fn path_indices_for_leaf_overflow_returns_typed_err_no_panic() {
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        path_indices_for_leaf_rust(0, LEAVES_PER_TREE)
    }));
    let inner = outcome.expect(
        "path_indices_for_leaf_rust must NOT panic on overflow input; \
         the wasm-bindgen surface returns Result<_, JsValue> for this case",
    );
    let err = inner.expect_err("leaf_idx == 2^TREE_DEPTH must Err");
    assert!(
        err.contains(">= 2^TREE_DEPTH"),
        "error message must surface the overflow detail; got {err}"
    );
}

#[test]
fn path_indices_for_leaf_negative_via_u32_max_cast_returns_typed_err() {
    // Models a JS negative-i32-to-u32 cast.
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| path_indices_for_leaf_rust(0, u32::MAX)));
    let inner = outcome.expect("u32::MAX leaf_idx must NOT panic");
    let err = inner.expect_err("u32::MAX must Err");
    assert!(err.contains(">= 2^TREE_DEPTH"), "got {err}");
}

#[test]
fn path_indices_for_leaf_max_valid_leaf_succeeds_with_16_indices() {
    // Last valid leaf; locks the bound against a `>=`/`>` flip.
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        path_indices_for_leaf_rust(0, LEAVES_PER_TREE - 1)
    }));
    let inner = outcome.expect("max-valid leaf must NOT panic");
    let indices = inner.expect("max-valid leaf must Ok");
    assert_eq!(indices.len(), 16);
}

#[test]
fn path_indices_for_per_list_leaf_short_list_key_returns_typed_err() {
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        path_indices_for_per_list_leaf_rust(&[0u8; 31], 0)
    }));
    let inner = outcome.expect("short list_key must NOT panic");
    let err = inner.expect_err("31-byte list_key must Err");
    assert!(err.contains("list_key length 31 must be 32"), "got {err}");
}

#[test]
fn path_indices_for_per_list_leaf_long_list_key_returns_typed_err() {
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        path_indices_for_per_list_leaf_rust(&[0u8; 33], 0)
    }));
    let inner = outcome.expect("long list_key must NOT panic");
    let err = inner.expect_err("33-byte list_key must Err");
    assert!(err.contains("list_key length 33 must be 32"), "got {err}");
}

#[test]
fn path_indices_for_per_list_leaf_empty_list_key_returns_typed_err() {
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        path_indices_for_per_list_leaf_rust(&[], 0)
    }));
    let inner = outcome.expect("empty list_key must NOT panic");
    let err = inner.expect_err("0-byte list_key must Err");
    assert!(err.contains("list_key length 0 must be 32"), "got {err}");
}

#[test]
fn path_indices_for_per_list_leaf_overflow_returns_typed_err() {
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        path_indices_for_per_list_leaf_rust(&[0xA7u8; 32], LEAVES_PER_TREE)
    }));
    let inner = outcome.expect("overflow idx must NOT panic");
    let err = inner.expect_err("idx == 2^TREE_DEPTH must Err");
    assert!(err.contains(">= 2^TREE_DEPTH"), "got {err}");
}

#[test]
fn path_indices_for_per_list_leaf_negative_via_u32_max_returns_typed_err() {
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        path_indices_for_per_list_leaf_rust(&[0xA7u8; 32], u32::MAX)
    }));
    let inner = outcome.expect("u32::MAX idx must NOT panic");
    let err = inner.expect_err("u32::MAX idx must Err");
    assert!(err.contains(">= 2^TREE_DEPTH"), "got {err}");
}
