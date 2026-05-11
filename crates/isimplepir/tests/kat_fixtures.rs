#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Byte-identity determinism KAT.
//!
//! Each fixture file under `tests/fixtures/` pins an `(a_seed,
//! rng_seed, db, target_idx)` tuple to a specific
//! `(query_bytes, response_bytes, recovered)` triple. A second
//! run of Raven against the same inputs must produce
//! byte-identical outputs; any divergence indicates a regression
//! (accidental change to ChaCha20 seeding, bincode layout, HKDF
//! label, Gaussian sampler, matmul order, or rounding formula).
//!
//! The fixtures lock *Raven's own wire bytes*; they are NOT
//! byte-identical to the Go `simplepir/` reference because Raven
//! uses the paper-verbatim Extract formulation (no DB + p/2 shift,
//! no offset correction) plus HKDF + ChaCha20 for the A-matrix
//! derivation. See `UPSTREAM.md §kat-go scope` for the deferred
//! cross-language KAT.
//!
//! ## Regenerating fixtures
//!
//! If a deliberate wire-format change lands, regenerate fixtures:
//!
//! ```bash
//! cargo test --release --test kat_fixtures -- --ignored update_fixtures
//! ```
//!
//! The regeneration test writes the fixture files in place and is
//! marked `#[ignore]` so CI does not overwrite them.

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
    /// Human-readable label (informational; not used for keying).
    label: String,
    /// Scheme parameters for this fixture. Toy cells are
    /// intentional: small `n`, `l`, `m` keep the fixture file
    /// small and the test fast while still exercising every hot
    /// path (A derivation, Gaussian sampling, matmul, rounding).
    params: LweParams,
    /// 32-byte hex-encoded master seed for the A matrix.
    a_seed_hex: String,
    /// 32-byte hex-encoded ChaCha20 seed for client-side LWE
    /// secret + Gaussian sampling.
    rng_seed_hex: String,
    /// Plaintext database laid out `l * m` row-major, each
    /// element in `[0, p)`.
    db_u32: Vec<u32>,
    /// Target linear index for the query (row-major).
    target_idx: usize,
    /// Expected bincode-serialized `ClientQuery` as hex.
    expected_query_bincode_hex: String,
    /// Expected bincode-serialized `ServerResponse` as hex.
    expected_response_bincode_hex: String,
    /// Expected recovered plaintext element (must equal
    /// `db_u32[target_idx]`).
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

/// Replay a fixture end-to-end and return the observed bytes +
/// recovered plaintext.
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

/// The set of fixtures exercised by the KAT test. Edit this list
/// when a new fixture is added; the regeneration helper iterates
/// over the same list.
///
/// Toy params live in code so the fixture JSON can be regenerated
/// deterministically if bincode layout changes. The DB and seeds
/// are also in code for the same reason. The fixture file only
/// locks the *output* bytes.
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
        // Placeholders; overwritten by regeneration + compared
        // against the committed fixture on assertion.
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
    // Sanity: recovered must equal the planted value.
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

/// Regenerate every fixture in `all_fixture_specs()` in place.
///
/// Marked `#[ignore]` so CI does not overwrite committed fixtures.
/// Run manually when a deliberate wire-format change lands:
///
/// ```bash
/// cargo test --release --test kat_fixtures -- --ignored update_fixtures
/// ```
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

/// Sanity: enumerate every spec at test-collection time, confirm
/// its committed fixture file exists on disk. Prevents the case
/// where `all_fixture_specs` gets a new entry but the regenerator
/// wasn't run. The byte-identity test would otherwise silently
/// skip the missing fixture.
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

// ---------- RowUpdate byte-identity KAT ----------

/// Fixture for the paper Fig. 2 row-aggregation delta shape
/// `β_edit = (i, u'_i, k)`. Locks the bincode wire bytes for a
/// `RowUpdate` emitted against a known DB + known edit list so any
/// future change to `u'_i` computation order, bincode layout, or
/// version-k numbering surfaces as a byte-mismatch.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RowUpdateFixture {
    label: String,
    params: LweParams,
    a_seed_hex: String,
    db_u32: Vec<u32>,
    /// Single row targeted by the aggregated modifications.
    target_row: usize,
    /// List of `(col, new_value)` edits applied in order.
    edits: Vec<(usize, u32)>,
    /// Expected bincode-serialized `RowUpdate` as hex.
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

/// Extends the primary `update_fixtures` helper with row-update
/// fixtures. Marked `#[ignore]` so CI never overwrites committed
/// bytes. Run alongside `update_fixtures` whenever a wire-format
/// change lands.
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
