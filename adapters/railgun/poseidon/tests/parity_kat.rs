//! Rust half of the cross-language Poseidon KAT.
//!
//! `tests/fixtures/poseidon_parity.txt` is the oracle for BOTH languages: this test and
//! `sdk/tests/poseidon_parity.test.ts` assert against the same bytes, and neither
//! regenerates it. A KAT that regenerates on failure re-blesses the divergence it exists
//! to catch. The TS and Rust Merkle roots must agree bit-for-bit, or a wallet verifies an
//! auth path against a root the chain never held.
//!
//! Whitespace-separated so neither side needs a parser dependency.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::format_collect,
    reason = "KAT fixture parsing; a panic here IS the failure report"
)]

use raven_railgun_poseidon::{merkle_node, railgun_merkle_zero_value};

const FIXTURE: &str = include_str!("fixtures/poseidon_parity.txt");

fn unhex(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64, "field element must be 64 hex chars, got {s:?}");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex digit");
    }
    out
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn rows(tag: &str) -> Vec<Vec<&'static str>> {
    FIXTURE
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| l.split_whitespace().collect::<Vec<_>>())
        .filter(|f| f.first() == Some(&tag))
        .collect()
}

#[test]
fn the_zero_value_matches_the_kat() {
    let z = rows("zero");
    assert_eq!(z.len(), 1, "exactly one zero_value row");
    assert_eq!(
        hex(&railgun_merkle_zero_value()),
        z[0][1],
        "the IMT zero value is keccak256(\"Railgun\") mod the SNARK prime; changing it \
         moves every empty-subtree hash and therefore every root"
    );
}

#[test]
fn every_hash_left_right_vector_matches() {
    let cases = rows("h");
    assert!(
        cases.len() >= 256,
        "expected >= 256 vectors, got {}",
        cases.len()
    );
    for (i, c) in cases.iter().enumerate() {
        let got = merkle_node(unhex(c[1]), unhex(c[2])).expect("canonical inputs hash");
        assert_eq!(
            hex(&got),
            c[3],
            "vector {i}: merkle_node diverged from the KAT"
        );
    }
}

#[test]
fn every_fold_vector_reproduces_its_root() {
    let cases = rows("f");
    assert!(
        cases.len() >= 64,
        "expected >= 64 folds, got {}",
        cases.len()
    );
    for (i, c) in cases.iter().enumerate() {
        // f <leaf> <16 siblings> <indices> <root>
        assert_eq!(c.len(), 1 + 1 + 16 + 1 + 1, "fold {i} has the wrong arity");
        let leaf = unhex(c[1]);
        let indices: u64 = c[18].parse().expect("indices");
        let mut cur = leaf;
        for level in 0..16usize {
            let sib = unhex(c[2 + level]);
            cur = if (indices >> level) & 1 == 1 {
                merkle_node(sib, cur).expect("hash")
            } else {
                merkle_node(cur, sib).expect("hash")
            };
        }
        assert_eq!(
            hex(&cur),
            c[19],
            "fold {i}: the Rust fold diverged from the KAT root"
        );
    }
}
