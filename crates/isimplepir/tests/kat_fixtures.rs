#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Byte-identity determinism KAT: each `tests/fixtures/` file pins inputs to a
//! fixed `(query, response, recovered)` triple, so any divergence flags a
//! regression in seeding, bincode layout, HKDF label, sampler, matmul, or rounding.
//!
//! These lock Raven's own wire bytes, NOT the Go `simplepir/` reference: Raven uses
//! the paper-verbatim Extract (no DB + p/2 shift) plus HKDF + ChaCha20 A-derivation.
//! See `UPSTREAM.md §kat-go scope` for the deferred cross-language KAT.

use std::fs;
use std::path::{Path, PathBuf};

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};

use raven_isimplepir::{
    db_update_row_modifications, extract, query, respond, setup, LweParams, SEED_BYTES,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Fixture {
    label: String,
    params: LweParams,
    a_seed_hex: String,
    rng_seed_hex: String,
    /// `l * m` row-major plaintext, each element in `[0, p)`.
    db_u32: Vec<u32>,
    target_idx: usize,
    expected_query_bincode_hex: String,
    expected_response_bincode_hex: String,
    expected_recovered: u32,
}

fn hex_to_seed(hex_str: &str) -> [u8; SEED_BYTES] {
    let bytes = hex::decode(hex_str).expect("fixture hex decode");
    assert_eq!(
        bytes.len(),
        SEED_BYTES,
        "seed hex must decode to {SEED_BYTES} bytes"
    );
    let mut out = [0u8; SEED_BYTES];
    out.copy_from_slice(&bytes);
    out
}

fn replay(fx: &Fixture) -> (String, String, u32) {
    let a_seed = hex_to_seed(&fx.a_seed_hex);
    let rng_seed = hex_to_seed(&fx.rng_seed_hex);

    let out = setup(&fx.db_u32, fx.params, Some(a_seed)).expect("setup");
    let mut rng = ChaCha20Rng::from_seed(rng_seed);
    let (state, client_query) = query(
        &mut rng,
        &out.server.a_seed,
        &out.server.params,
        fx.target_idx,
    )
    .expect("query");
    let server_response = respond(&out.server, &client_query.query).expect("respond");
    let recovered =
        extract(&out.server.params, &out.hint, &state, &server_response).expect("extract");

    let q_bytes: Vec<u8> = bincode::serialize(&client_query).expect("bincode query");
    let r_bytes: Vec<u8> = bincode::serialize(&server_response).expect("bincode response");

    (hex::encode(q_bytes), hex::encode(r_bytes), recovered)
}

// Inputs live in code so fixtures regenerate deterministically; the JSON only
// locks the output bytes.
fn fixture_spec_toy_4x4_p991() -> Fixture {
    let params = LweParams {
        n: 128,
        log2_q: 32,
        p: 991,
        l: 4,
        m: 4,
        bits_per_element: 9,
    };
    let db: Vec<u32> = (0..(params.l * params.m))
        .map(|i| (i as u32 * 17 + 3) % params.p)
        .collect();
    Fixture {
        label: "toy-4x4-p991-n128".to_string(),
        params,
        a_seed_hex: "00".repeat(SEED_BYTES),
        rng_seed_hex: "07".repeat(SEED_BYTES),
        db_u32: db,
        target_idx: 6,
        // filled by regeneration; the committed fixture holds the asserted bytes.
        expected_query_bincode_hex: String::new(),
        expected_response_bincode_hex: String::new(),
        expected_recovered: 0,
    }
}

fn fixture_spec_toy_8x8_p701() -> Fixture {
    let params = LweParams {
        n: 256,
        log2_q: 32,
        p: 701,
        l: 8,
        m: 8,
        bits_per_element: 9,
    };
    let db: Vec<u32> = (0..(params.l * params.m))
        .map(|i| ((i as u32).wrapping_mul(31).wrapping_add(11)) % params.p)
        .collect();
    Fixture {
        label: "toy-8x8-p701-n256".to_string(),
        params,
        a_seed_hex: "2a".repeat(SEED_BYTES),
        rng_seed_hex: "b3".repeat(SEED_BYTES),
        db_u32: db,
        target_idx: 23,
        expected_query_bincode_hex: String::new(),
        expected_response_bincode_hex: String::new(),
        expected_recovered: 0,
    }
}

fn all_fixture_specs() -> Vec<(&'static str, Fixture)> {
    vec![
        ("toy_4x4_p991.json", fixture_spec_toy_4x4_p991()),
        ("toy_8x8_p701.json", fixture_spec_toy_8x8_p701()),
    ]
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn load_fixture(name: &str) -> Fixture {
    let path = fixture_path(name);
    let bytes = fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "fixture `{}` missing at {}: {}. \
             If this is expected (new fixture), regenerate with: \
             cargo test --release --test kat_fixtures -- --ignored update_fixtures",
            name,
            path.display(),
            e
        )
    });
    serde_json::from_slice(&bytes).expect("fixture JSON decode")
}

#[test]
fn kat_toy_4x4_p991_byte_identity() {
    let committed = load_fixture("toy_4x4_p991.json");
    let (q_hex, r_hex, recovered) = replay(&committed);
    assert_eq!(
        q_hex, committed.expected_query_bincode_hex,
        "query wire bytes diverged"
    );
    assert_eq!(
        r_hex, committed.expected_response_bincode_hex,
        "response wire bytes diverged"
    );
    assert_eq!(
        recovered, committed.expected_recovered,
        "recovered plaintext diverged"
    );
    assert_eq!(
        recovered, committed.db_u32[committed.target_idx],
        "recovered plaintext does not match planted value"
    );
}

#[test]
fn kat_toy_8x8_p701_byte_identity() {
    let committed = load_fixture("toy_8x8_p701.json");
    let (q_hex, r_hex, recovered) = replay(&committed);
    assert_eq!(
        q_hex, committed.expected_query_bincode_hex,
        "query wire bytes diverged"
    );
    assert_eq!(
        r_hex, committed.expected_response_bincode_hex,
        "response wire bytes diverged"
    );
    assert_eq!(recovered, committed.expected_recovered);
    assert_eq!(recovered, committed.db_u32[committed.target_idx]);
}

/// Regenerate every fixture in place after an intentional wire-format change:
/// `cargo test --release --test kat_fixtures -- --ignored update_fixtures`.
#[test]
#[ignore = "writes files; run manually after intentional wire-format changes"]
#[allow(clippy::print_stdout)]
fn update_fixtures() {
    for (name, mut spec) in all_fixture_specs() {
        let (q_hex, r_hex, recovered) = replay(&spec);
        spec.expected_query_bincode_hex = q_hex;
        spec.expected_response_bincode_hex = r_hex;
        spec.expected_recovered = recovered;

        let path = fixture_path(name);
        let json = serde_json::to_string_pretty(&spec).expect("encode fixture");
        fs::write(&path, json.as_bytes()).expect("write fixture");
        println!("wrote {}", path.display());
    }
}

/// Every registered spec must have a committed fixture; otherwise a new entry
/// would silently skip the byte-identity check.
#[test]
fn all_specs_have_committed_fixtures() {
    for (name, _spec) in all_fixture_specs() {
        let path = fixture_path(name);
        assert!(
            path.exists(),
            "fixture `{}` is registered in all_fixture_specs() but missing on disk at {}. \
             Run: cargo test --release --test kat_fixtures -- --ignored update_fixtures",
            name,
            path.display()
        );
    }
    for (name, _spec) in all_row_update_fixture_specs() {
        let path = fixture_path(name);
        assert!(
            path.exists(),
            "row-update fixture `{}` registered but missing at {}. \
             Run: cargo test --release --test kat_fixtures -- --ignored update_fixtures",
            name,
            path.display()
        );
    }
}

/// Locks the `RowUpdate` wire bytes for the paper Fig. 2 row-aggregation delta
/// `β_edit = (i, u'_i, k)` so any change to `u'_i` order, bincode layout, or
/// version numbering surfaces as a byte mismatch.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RowUpdateFixture {
    label: String,
    params: LweParams,
    a_seed_hex: String,
    db_u32: Vec<u32>,
    target_row: usize,
    /// `(col, new_value)` edits applied in order.
    edits: Vec<(usize, u32)>,
    expected_row_update_bincode_hex: String,
}

fn replay_row_update(fx: &RowUpdateFixture) -> String {
    let a_seed = hex_to_seed(&fx.a_seed_hex);
    let out = setup(&fx.db_u32, fx.params, Some(a_seed)).expect("setup");
    let mut server = out.server;
    let delta = db_update_row_modifications(&mut server, fx.target_row, &fx.edits)
        .expect("db_update_row_modifications");
    let bytes: Vec<u8> = bincode::serialize(&delta).expect("bincode row-update");
    hex::encode(bytes)
}

fn row_update_fixture_spec_toy_4x4_p991() -> RowUpdateFixture {
    let params = LweParams {
        n: 128,
        log2_q: 32,
        p: 991,
        l: 4,
        m: 4,
        bits_per_element: 9,
    };
    let db: Vec<u32> = (0..(params.l * params.m))
        .map(|i| (i as u32 * 19 + 5) % params.p)
        .collect();
    RowUpdateFixture {
        label: "row-agg-toy-4x4-p991-n128".to_string(),
        params,
        a_seed_hex: "11".repeat(SEED_BYTES),
        db_u32: db,
        target_row: 2,
        edits: vec![(0, 7), (2, 900), (3, 42)],
        expected_row_update_bincode_hex: String::new(),
    }
}

fn all_row_update_fixture_specs() -> Vec<(&'static str, RowUpdateFixture)> {
    vec![(
        "row_update_toy_4x4_p991.json",
        row_update_fixture_spec_toy_4x4_p991(),
    )]
}

fn load_row_update_fixture(name: &str) -> RowUpdateFixture {
    let path = fixture_path(name);
    let bytes = fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "row-update fixture `{}` missing at {}: {}. \
             Regenerate with: cargo test --release --test kat_fixtures -- --ignored update_fixtures",
            name,
            path.display(),
            e,
        )
    });
    serde_json::from_slice(&bytes).expect("row-update fixture JSON decode")
}

#[test]
fn kat_row_update_toy_4x4_p991_byte_identity() {
    let committed = load_row_update_fixture("row_update_toy_4x4_p991.json");
    let hex_bytes = replay_row_update(&committed);
    assert_eq!(
        hex_bytes, committed.expected_row_update_bincode_hex,
        "RowUpdate wire bytes diverged from committed fixture"
    );
}

/// Row-update counterpart to `update_fixtures`; run alongside it on a wire change.
#[test]
#[ignore = "writes files; run manually after intentional wire-format changes"]
#[allow(clippy::print_stdout)]
fn update_row_update_fixtures() {
    for (name, mut spec) in all_row_update_fixture_specs() {
        let hex_bytes = replay_row_update(&spec);
        spec.expected_row_update_bincode_hex = hex_bytes;
        let path = fixture_path(name);
        let json = serde_json::to_string_pretty(&spec).expect("encode row-update fixture");
        fs::write(&path, json.as_bytes()).expect("write row-update fixture");
        println!("wrote {}", path.display());
    }
}
