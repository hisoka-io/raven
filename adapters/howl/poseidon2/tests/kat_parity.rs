//! Cross-language parity against Barretenberg, which is what Howl's generator wraps.
//!
//! The vectors in `tests/vectors/` were produced by running Aztec's own exported functions. The
//! generators are retained out of tree with the project's working notes. The sponge file is
//! cross-verified against a value the Howl repository COMMITS and calls "the published test
//! vector", so these pin the same function Howl ships against rather than one with the same
//! name.
//!
//! Two levels deliberately. The permutation vectors localise a failure to the constants or the
//! linear layers; the sponge vectors localise it to the padding, the capacity seed or the rate
//! boundary. A single end-to-end level would say only "wrong".

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use howl_poseidon2::{hash, hash_be_bytes, permutation, Poseidon2Error, STATE_WIDTH};

fn fr_from_dec(s: &str) -> Fr {
    let mut acc = Fr::from(0u64);
    let ten = Fr::from(10u64);
    for b in s.bytes() {
        assert!(b.is_ascii_digit(), "vector input is not decimal: {s}");
        acc = acc * ten + Fr::from(u64::from(b - b'0'));
    }
    acc
}

fn fr_to_hex(v: Fr) -> String {
    let be = v.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    format!(
        "0x{}",
        out.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

fn vectors(name: &str) -> serde_json::Value {
    let raw = std::fs::read_to_string(format!(
        "{}/tests/vectors/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("vector file present");
    serde_json::from_str(&raw).expect("vector file parses")
}

#[test]
fn the_permutation_matches_barretenberg_on_every_vector() {
    let doc = vectors("permutation.json");
    let cases = doc["vectors"].as_array().expect("vectors array");
    assert!(cases.len() >= 53, "corpus shrank: {} vectors", cases.len());
    for (n, case) in cases.iter().enumerate() {
        let input: Vec<Fr> = case["input"]
            .as_array()
            .expect("input array")
            .iter()
            .map(|v| fr_from_dec(v.as_str().expect("decimal string")))
            .collect();
        let mut state = [Fr::from(0u64); STATE_WIDTH];
        state.copy_from_slice(&input);
        let got = permutation(state);
        let want = case["output"].as_array().expect("output array");
        for lane in 0..STATE_WIDTH {
            assert_eq!(
                fr_to_hex(got[lane]),
                want[lane].as_str().expect("hex string"),
                "permutation vector {n}, lane {lane}"
            );
        }
    }
}

#[test]
fn the_sponge_matches_barretenberg_on_every_vector() {
    let doc = vectors("sponge.json");
    let cases = doc["vectors"].as_array().expect("vectors array");
    assert!(cases.len() >= 75, "corpus shrank: {} vectors", cases.len());
    for case in cases {
        let inputs: Vec<Fr> = case["inputs"]
            .as_array()
            .expect("inputs array")
            .iter()
            .map(|v| fr_from_dec(v.as_str().expect("decimal string")))
            .collect();
        assert_eq!(
            fr_to_hex(hash(&inputs)),
            case["output"].as_str().expect("hex string"),
            "sponge vector {}",
            case["label"].as_str().unwrap_or("?")
        );
    }
}

/// The value Howl commits as `KNOWN_HASH_2_1_2` and calls "the published test vector".
///
/// Pinned as a literal rather than read from the corpus: if the corpus were ever regenerated
/// against the wrong function, every vector would move together and every other test here
/// would still pass. This one cannot move.
#[test]
fn hash_of_one_and_two_matches_the_value_howl_publishes() {
    assert_eq!(
        fr_to_hex(hash(&[Fr::from(1u64), Fr::from(2u64)])),
        "0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383"
    );
}

/// Rate is 3, so the duplex fires on multiples of it. An implementation that mishandles the
/// boundary passes lengths 1 and 2 and fails at 3, which is why the corpus covers 3, 4, 6, 7.
#[test]
fn the_rate_boundary_is_covered_by_the_corpus() {
    let doc = vectors("sponge.json");
    let labels: Vec<String> = doc["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .filter_map(|c| c["label"].as_str().map(str::to_owned))
        .collect();
    for needed in [
        "rate_boundary_3",
        "rate_boundary_4",
        "rate_boundary_6",
        "rate_boundary_7",
    ] {
        assert!(labels.iter().any(|l| l == needed), "corpus lost {needed}");
    }
}

/// Length is bound into the capacity, so these must not collide even though one is a prefix.
#[test]
fn length_is_domain_separated() {
    let a = hash(&[Fr::from(0u64)]);
    let b = hash(&[Fr::from(0u64), Fr::from(0u64)]);
    assert_ne!(a, b, "length must change the capacity seed");
    assert_ne!(hash(&[]), a, "the empty input must not equal a single zero");
}

#[test]
fn byte_input_is_refused_rather_than_reinterpreted() {
    let mut one = [0u8; 32];
    one[31] = 1;
    assert_eq!(
        hash_be_bytes(&one).expect("canonical element"),
        {
            let mut want = [0u8; 32];
            let be = hash(&[Fr::from(1u64)]).into_bigint().to_bytes_be();
            want[32 - be.len()..].copy_from_slice(&be);
            want
        },
        "the byte entry point must agree with the field entry point"
    );
    assert_eq!(
        hash_be_bytes(&one[..31]),
        Err(Poseidon2Error::NotFieldAligned { len: 31 })
    );
    // The modulus itself is the smallest non-canonical encoding; reducing it silently would
    // make two distinct wire values hash alike.
    let modulus_be = hex_bytes("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    assert_eq!(
        hash_be_bytes(&modulus_be),
        Err(Poseidon2Error::NotCanonical { index: 0 })
    );
}

fn hex_bytes(h: &str) -> [u8; 32] {
    let padded = format!("{h:0>64}");
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&padded[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}

/// Every IV state a sponge of length 0..8 builds is in the permutation corpus, so the two levels
/// meet at the boundary rather than both testing the middle.
#[test]
fn the_permutation_corpus_covers_every_sponge_iv_state() {
    let doc = vectors("permutation.json");
    let inputs: Vec<Vec<String>> = doc["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .map(|c| {
            c["input"]
                .as_array()
                .expect("input")
                .iter()
                .map(|v| v.as_str().expect("dec").to_owned())
                .collect()
        })
        .collect();
    for n in 0u64..=8 {
        let iv = (u128::from(n) * (1u128 << 64)).to_string();
        let want = vec!["0".to_owned(), "0".to_owned(), "0".to_owned(), iv];
        assert!(
            inputs.contains(&want),
            "no permutation vector for the length-{n} capacity seed"
        );
    }
}

/// Chained vectors: a constant applied in the WRONG ROUND can survive one permutation on some
/// inputs and diverge once the state is iterated, so single-shot vectors can miss it.
#[test]
fn the_corpus_carries_chained_states() {
    let doc = vectors("permutation.json");
    let chained = doc["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .filter(|c| c.get("chained").is_some())
        .count();
    assert!(chained >= 8, "chained vectors dropped to {chained}");
}

/// Order and repetition. A sponge that lost the cache index would collide all of these.
#[test]
fn permuting_the_input_changes_the_digest() {
    let a = hash(&[Fr::from(7u64), Fr::from(9u64)]);
    let b = hash(&[Fr::from(9u64), Fr::from(7u64)]);
    assert_ne!(a, b, "order must matter");
    let three = hash(&[Fr::from(5u64); 3]);
    let four = hash(&[Fr::from(5u64); 4]);
    assert_ne!(three, four, "repetition count must matter");
}

/// Lengths bracketing every rate boundary up to 16, each distinct from its neighbours. An
/// off-by-one in the cache is invisible below 3 and again below 6.
#[test]
fn every_length_up_to_sixteen_yields_a_distinct_digest() {
    let mut seen = std::collections::BTreeSet::new();
    for n in 0..=16usize {
        let inputs: Vec<Fr> = (1..=n as u64).map(Fr::from).collect();
        assert!(
            seen.insert(fr_to_hex(hash(&inputs))),
            "length {n} collided with a shorter input"
        );
    }
}

/// The byte entry point chunks by 32 and the field entry point does not, so they can disagree
/// at the rate boundary specifically: three elements is 96 bytes and is where the duplex first
/// fires. Previously only the single-element case was pinned.
#[test]
fn the_byte_and_field_entry_points_agree_at_every_length_through_two_rate_boundaries() {
    for n in 0..=8usize {
        let fields: Vec<Fr> = (1..=n as u64).map(Fr::from).collect();
        let mut bytes = Vec::with_capacity(n * 32);
        for f in &fields {
            let be = f.into_bigint().to_bytes_be();
            let mut slot = [0u8; 32];
            slot[32 - be.len()..].copy_from_slice(&be);
            bytes.extend_from_slice(&slot);
        }
        let via_bytes = hash_be_bytes(&bytes).expect("canonical");
        let mut via_fields = [0u8; 32];
        let be = hash(&fields).into_bigint().to_bytes_be();
        via_fields[32 - be.len()..].copy_from_slice(&be);
        assert_eq!(via_bytes, via_fields, "entry points disagree at length {n}");
    }
}

/// An empty byte slice is a legal zero-element input, not an error. It is the one case where
/// the two entry points could plausibly have been given different meanings.
#[test]
fn an_empty_byte_input_is_the_empty_hash_and_not_an_error() {
    let via_bytes = hash_be_bytes(&[]).expect("empty input is legal");
    let mut via_fields = [0u8; 32];
    let be = hash(&[]).into_bigint().to_bytes_be();
    via_fields[32 - be.len()..].copy_from_slice(&be);
    assert_eq!(via_bytes, via_fields);
}

/// Extends the length-distinctness property past two further rate boundaries. The capacity is
/// seeded with the length, so every one of these must differ from every other.
#[test]
fn lengths_zero_through_forty_eight_all_yield_distinct_digests() {
    let mut seen = std::collections::BTreeMap::new();
    for n in 0..=48usize {
        let inputs: Vec<Fr> = (1..=n as u64).map(Fr::from).collect();
        let digest = fr_to_hex(hash(&inputs));
        if let Some(prev) = seen.insert(digest.clone(), n) {
            panic!("length {n} collided with length {prev}");
        }
    }
    assert_eq!(seen.len(), 49);
}

/// Domain separation is between the CAPACITY and the RATE. Feeding the capacity's own seed
/// value in as ordinary content must not reproduce another length's digest - if it did, an
/// attacker could forge a short record's digest from a longer input.
#[test]
fn capacity_seed_values_are_not_confusable_with_rate_content() {
    let two_pow_64 = Fr::from(1u128 << 64);
    let mut digests = std::collections::BTreeSet::new();
    for n in 0..=6u64 {
        // The seed a length-n sponge uses, presented as ordinary input instead.
        digests.insert(fr_to_hex(hash(&[Fr::from(n) * two_pow_64])));
    }
    // Content starts at 1, not 0: a length-1 input of [0] IS the n=0 seed presented as content,
    // so including it would report a coincidence of the fixture as a collision.
    for n in 0..=6usize {
        let inputs: Vec<Fr> = (1..=n as u64).map(Fr::from).collect();
        assert!(
            digests.insert(fr_to_hex(hash(&inputs))),
            "a length-{n} digest collided with a seed-as-content digest"
        );
    }
}

/// Corpus integrity: two vectors with different inputs must not carry the same output. A
/// duplicate would mean the file was generated wrongly, and every parity test would still pass
/// because each vector agrees with itself.
#[test]
fn no_two_distinct_sponge_vectors_share_an_output() {
    let doc = vectors("sponge.json");
    let mut by_output: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    // Keyed by INPUTS, not by label: the corpus deliberately carries one input under two names
    // (`seq_3` and `rate_boundary_3` are both [1,2,3]) and those MUST share an output. A shared
    // output for DIFFERENT inputs is the corruption this looks for.
    for case in doc["vectors"].as_array().expect("vectors") {
        let out = case["output"].as_str().expect("hex").to_owned();
        let inputs = case["inputs"].to_string();
        if let Some(prev) = by_output.insert(out.clone(), inputs.clone()) {
            assert_eq!(
                prev, inputs,
                "two DIFFERENT inputs share output {out}: {prev} and {inputs}"
            );
        }
    }
}
