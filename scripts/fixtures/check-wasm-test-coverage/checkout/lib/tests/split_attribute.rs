#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown", not(feature = "a-feature-long-enough-to-wrap")),
    wasm_bindgen_test
)]
fn fixture() {}
