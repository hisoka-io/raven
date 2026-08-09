#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Spelling gate over the Gaussian sampler, NOT a timing proof. It pins the
//! branch-free form of the secret-dependent steps so a rewrite back to a
//! secret-indexed load or a secret-conditioned jump has to be deliberate.
//! Nothing here observes timing, and codegen inspection cannot substitute:
//! `crates/inspire/tests/constant_time_codegen_gate.rs` records why. Renaming
//! the scan helper escapes the gate, which is the accepted limit of the form.

const QUERY_SRC: &str = include_str!("../src/query.rs");

fn item_source(header: &str) -> &'static str {
    let start = QUERY_SRC
        .find(header)
        .unwrap_or_else(|| panic!("`{header}` must be present in src/query.rs"));
    let rest = &QUERY_SRC[start..];
    let end = rest.find("\n}\n").map_or(rest.len(), |i| i + 2);
    &rest[..end]
}

fn sampler_source() -> &'static str {
    item_source("pub fn gauss_sample_sigma_6_4")
}

#[test]
fn sampler_does_not_address_the_cdf_table_by_the_drawn_value() {
    let body = sampler_source();
    for indexed in ["CDF_TABLE_SIGMA_6_4[", "CDF_TABLE_SIGMA_6_4.get("] {
        assert!(
            !body.contains(indexed),
            "sampler addresses the CDF table via `{indexed}`; the drawn value is \
             secret, so the table must be scanned and selected instead:\n{body}"
        );
    }
    assert!(
        body.contains("cdf_bits_at("),
        "sampler must read the CDF table through the scanning helper:\n{body}"
    );
}

#[test]
fn cdf_table_read_scans_every_entry() {
    let body = item_source("fn cdf_bits_at");
    for indexed in ["CDF_TABLE_SIGMA_6_4[", "CDF_TABLE_SIGMA_6_4.get("] {
        assert!(
            !body.contains(indexed),
            "table read addresses memory by `{indexed}`:\n{body}"
        );
    }
    assert!(
        body.contains("CDF_TABLE_SIGMA_6_4.iter().enumerate()"),
        "table read must visit every entry:\n{body}"
    );
    assert!(
        body.contains("conditional_select"),
        "table read must select through subtle's barrier:\n{body}"
    );
}

#[test]
fn sampler_folds_the_noise_sign_without_a_source_branch() {
    let body = sampler_source();
    assert!(
        !body.contains("if sign_bit"),
        "sampler branches on the noise sign bit; fold it with \
         `i64::conditional_select` instead:\n{body}"
    );
    assert!(
        body.contains("i64::conditional_select"),
        "sampler must fold the noise sign through subtle's barrier:\n{body}"
    );
}

/// A hardware divide with a secret dividend is variable-latency on most
/// x86-64 parts, so the table modulus must reduce against a constant.
#[test]
fn sampler_reduces_against_a_compile_time_table_length() {
    let body = sampler_source();
    assert!(
        body.contains("% CDF_TABLE_LEN"),
        "sampler must reduce against a `const` divisor, not a runtime `.len()`:\n{body}"
    );
}
