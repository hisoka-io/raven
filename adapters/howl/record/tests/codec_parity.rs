//! Byte parity against Howl's committed codec.
//!
//! The vectors were produced by that codec's own offsets and field encoding. This is frozen
//! wire: an implementation on the other side of the network decodes by these offsets, so a
//! disagreement here is a note the recipient cannot read.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use howl_record::{
    commitment_prefix_matches, decode, encode, HowlNoteRecord, RecordError, CELL_BYTES,
    COMMITMENT_PREFIX_BYTES, LAYOUT_VERSION, RECORD_BYTES, RECORD_KIND_INCOMING, RECORD_KIND_SELF,
};

fn fr_from_dec(s: &str) -> Fr {
    let mut acc = Fr::from(0u64);
    for b in s.bytes() {
        assert!(b.is_ascii_digit(), "not decimal: {s}");
        acc = acc * Fr::from(10u64) + Fr::from(u64::from(b - b'0'));
    }
    acc
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

fn vectors() -> serde_json::Value {
    let raw = std::fs::read_to_string(format!(
        "{}/tests/vectors/record.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("vector file");
    serde_json::from_str(&raw).expect("parses")
}

fn record_of(v: &serde_json::Value) -> HowlNoteRecord {
    let prefix_bytes = unhex(v["commitment_prefix"].as_str().expect("prefix"));
    let mut commitment_prefix = [0u8; COMMITMENT_PREFIX_BYTES];
    commitment_prefix.copy_from_slice(&prefix_bytes);
    let kept: Vec<Fr> = v["ciphertext_kept"]
        .as_array()
        .expect("kept")
        .iter()
        .map(|w| fr_from_dec(w.as_str().expect("dec")))
        .collect();
    let mut ciphertext_kept = [Fr::from(0u64); 5];
    ciphertext_kept.copy_from_slice(&kept);
    HowlNoteRecord {
        layout_version: v["layout_version"].as_u64().expect("layout") as u8,
        record_kind: v["record_kind"].as_u64().expect("kind") as u8,
        leaf_index: v["leaf_index"].as_u64().expect("leaf") as u32,
        commitment_prefix,
        ephemeral_pk_x: fr_from_dec(v["ephemeral_pk_x"].as_str().expect("eph")),
        cek_wrap: fr_from_dec(v["cek_wrap"].as_str().expect("cek")),
        ciphertext_kept,
    }
}

#[test]
fn the_layout_constants_match_howls() {
    let doc = vectors();
    assert_eq!(doc["record_bytes"].as_u64(), Some(RECORD_BYTES as u64));
    assert_eq!(doc["cell_bytes"].as_u64(), Some(CELL_BYTES as u64));
    assert_eq!(
        doc["commitment_prefix_bytes"].as_u64(),
        Some(COMMITMENT_PREFIX_BYTES as u64)
    );
    let kept: Vec<u64> = doc["ciphertext_kept_indices"]
        .as_array()
        .expect("indices")
        .iter()
        .map(|i| i.as_u64().expect("int"))
        .collect();
    assert_eq!(kept, vec![1, 2, 3, 4, 6], "the stripped words moved");
}

#[test]
fn encode_is_byte_identical_to_howls_codec() {
    for v in vectors()["vectors"].as_array().expect("vectors") {
        let got = encode(&record_of(v));
        let want = unhex(v["cell"].as_str().expect("cell"));
        assert_eq!(
            got.to_vec(),
            want,
            "cell mismatch on {}",
            v["label"].as_str().unwrap_or("?")
        );
    }
}

#[test]
fn decode_round_trips_every_vector() {
    for v in vectors()["vectors"].as_array().expect("vectors") {
        let cell = unhex(v["cell"].as_str().expect("cell"));
        let got = decode(&cell).expect("vector decodes");
        assert_eq!(
            got,
            record_of(v),
            "round trip on {}",
            v["label"].as_str().unwrap_or("?")
        );
    }
}

/// The tail is contract, not slack. This is the check that collides with a design that wants
/// to put a field there; see `docs/OCCURRENCE-COUNT.md` in this crate.
#[test]
fn a_non_zero_tail_is_refused_at_every_pad_byte() {
    let base = unhex(vectors()["vectors"][0]["cell"].as_str().expect("cell"));
    for index in RECORD_BYTES..CELL_BYTES {
        let mut cell = base.clone();
        cell[index] = 1;
        assert_eq!(
            decode(&cell),
            Err(RecordError::NonZeroPadding { index }),
            "pad byte {index} was accepted"
        );
    }
}

#[test]
fn a_short_or_long_cell_is_refused() {
    assert_eq!(
        decode(&[0u8; CELL_BYTES - 1]),
        Err(RecordError::WrongLength {
            len: CELL_BYTES - 1
        })
    );
    assert_eq!(
        decode(&[0u8; CELL_BYTES + 1]),
        Err(RecordError::WrongLength {
            len: CELL_BYTES + 1
        })
    );
}

#[test]
fn an_unknown_layout_or_kind_is_refused_by_name() {
    let mut cell = unhex(vectors()["vectors"][0]["cell"].as_str().expect("cell"));
    cell[0] = 2;
    assert_eq!(
        decode(&cell),
        Err(RecordError::UnsupportedLayout { found: 2 })
    );
    cell[0] = LAYOUT_VERSION;
    cell[1] = 9;
    assert_eq!(decode(&cell), Err(RecordError::UnknownKind { found: 9 }));
}

/// A field slot at or above the modulus must be refused, not reduced: reduction maps two
/// distinct wire encodings onto one record.
#[test]
fn a_non_canonical_field_is_refused_rather_than_reduced() {
    let mut cell = unhex(vectors()["vectors"][0]["cell"].as_str().expect("cell"));
    let modulus = unhex("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    cell[22..54].copy_from_slice(&modulus);
    assert_eq!(
        decode(&cell),
        Err(RecordError::NonCanonicalField { offset: 22 })
    );
}

#[test]
fn both_record_kinds_decode() {
    let doc = vectors();
    let kinds: Vec<u8> = doc["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .map(|v| v["record_kind"].as_u64().expect("kind") as u8)
        .collect();
    assert!(kinds.contains(&RECORD_KIND_SELF), "no self vector");
    assert!(kinds.contains(&RECORD_KIND_INCOMING), "no incoming vector");
}

/// The prefix is the HIGH 16 bytes, so a commitment small enough to have a zero top half has
/// a zero prefix and collides with its neighbours. That is not a practical weakness - real
/// commitments are Poseidon2 outputs and near-uniform over the field - but a test built from a
/// small literal passes the accept case and cannot exercise the reject case at all.
#[test]
fn the_prefix_check_accepts_the_commitment_it_came_from_and_rejects_a_neighbour() {
    let commitment = fr_from_dec(
        "19113322687294939222907651764101372264536825748204547413233317956253656473677",
    );
    let be = commitment.into_bigint().to_bytes_be();
    let mut full = [0u8; 32];
    full[32 - be.len()..].copy_from_slice(&be);
    let mut commitment_prefix = [0u8; COMMITMENT_PREFIX_BYTES];
    commitment_prefix.copy_from_slice(&full[..COMMITMENT_PREFIX_BYTES]);
    let record = HowlNoteRecord {
        layout_version: LAYOUT_VERSION,
        record_kind: RECORD_KIND_SELF,
        leaf_index: 1,
        commitment_prefix,
        ephemeral_pk_x: Fr::from(0u64),
        cek_wrap: Fr::from(0u64),
        ciphertext_kept: [Fr::from(0u64); 5],
    };
    assert!(commitment_prefix_matches(&record, commitment));
    // The differing commitment must differ IN THE PREFIX. `commitment + 1` moves the lowest
    // byte, which this check does not read, so it would pass while proving nothing.
    let other =
        fr_from_dec("6350874878119819312338956282401532409788428879151445726012394534686998597903");
    assert_ne!(
        commitment.into_bigint().to_bytes_be()[..COMMITMENT_PREFIX_BYTES],
        other.into_bigint().to_bytes_be()[..COMMITMENT_PREFIX_BYTES],
        "fixture is wrong: the two commitments share a prefix"
    );
    assert!(
        !commitment_prefix_matches(&record, other),
        "a commitment differing in the prefix must not match"
    );
}
