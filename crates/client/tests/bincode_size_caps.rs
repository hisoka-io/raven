//! Boundary tests for the WASM bincode-deserialize size caps (64 MiB untrusted, 32 MiB trusted).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use raven_client::{
    decode_capped_for_test, decode_trusted_for_test, WASM_BINCODE_DESERIALIZE_LIMIT_BYTES,
    WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES,
};

/// The cap VALUES, pinned to literals. This is the only assertion in the tree that fails if
/// someone widens the ceiling.
///
/// Every other test in this file and in `panic_safety.rs` derives its fixture FROM the constants
/// (`LIMIT + 1`, `LIMIT - 16`), so they all follow the cap wherever it moves: raising the
/// untrusted limit to 128 MiB leaves the entire suite green while doubling how much attacker-
/// supplied input the WASM client will allocate before refusing. The boundary tests prove the
/// mechanism works AT the cap; only this one says what the cap is.
///
/// It exists because two separately-correct decisions cancelled out — one task deferred the
/// deletion of a weaker test until this pin was added, another deleted that test as a genuine
/// duplicate, and the pin was never written. Changing either number should require editing this
/// line and saying why.
#[test]
fn the_wasm_deserialize_caps_are_the_values_the_threat_model_assumes() {
    assert_eq!(
        WASM_BINCODE_DESERIALIZE_LIMIT_BYTES,
        64 * 1024 * 1024,
        "the UNTRUSTED bincode cap moved. This bounds what a hostile server can make the WASM \
         client allocate; raising it is a threat-model change, not a tuning knob."
    );
    assert_eq!(
        WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES,
        32 * 1024 * 1024,
        "the TRUSTED (self-authored session residue) cap moved; it must stay at or below the \
         untrusted cap and is deliberately half of it."
    );
}

/// The trusted cap must never exceed the untrusted one. Both sides are `const`, so this is a
/// COMPILE-time assertion rather than a runtime one: written as `assert!` inside the test above it
/// is a constant expression, which clippy correctly refuses as an assertion that cannot fail at
/// runtime — the very defect class this suite exists to remove. Violating it fails the build.
const _: () = assert!(WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES <= WASM_BINCODE_DESERIALIZE_LIMIT_BYTES);

#[test]
fn wasm_bincode_decode_rejects_payload_above_64mib_with_typed_error() {
    // contents immaterial: the length pre-check fires before bincode runs
    let bytes = vec![0u8; WASM_BINCODE_DESERIALIZE_LIMIT_BYTES + 1];

    let err = decode_capped_for_test::<Vec<u8>>(&bytes, "oversize_vec_u8")
        .expect_err("64 MiB+1 payload must be rejected by the WASM size cap");

    assert!(
        err.contains("bincode deserialize oversize_vec_u8"),
        "expected typed Decode error naming 'oversize_vec_u8', got: {err}"
    );
    assert!(
        err.contains("size limit reached"),
        "expected the cap-rejection wording 'size limit reached', got: {err}"
    );
}

#[test]
fn wasm_bincode_decode_accepts_legitimate_payload_just_under_64mib() {
    // -16 leaves room for the 8-byte length prefix; bincoded slice lands at cap-8
    let body_len = WASM_BINCODE_DESERIALIZE_LIMIT_BYTES - 16;
    let v = vec![0xa5u8; body_len];
    let bytes = bincode::serialize(&v).expect("bincode serialize legitimate");
    assert!(
        bytes.len() <= WASM_BINCODE_DESERIALIZE_LIMIT_BYTES,
        "fixture invariant: bytes={} cap={}",
        bytes.len(),
        WASM_BINCODE_DESERIALIZE_LIMIT_BYTES
    );

    let decoded: Vec<u8> = decode_capped_for_test(&bytes, "legitimate_vec_u8")
        .expect("payload at the boundary must decode cleanly");
    assert_eq!(
        decoded.len(),
        body_len,
        "decoded payload length must match the source"
    );
    assert_eq!(decoded[0], 0xa5, "decoded contents must round-trip");
}

#[test]
fn wasm_trusted_cap_rejects_payload_above_32mib_with_typed_error() {
    // scoped so the cap+1 buffer drops before the assertions run
    let err = {
        let bytes = vec![0u8; WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES + 1];
        decode_trusted_for_test::<Vec<u8>>(&bytes, "oversize_vec_u8")
            .expect_err("a cap+1 payload must be rejected by the trusted cap")
    };
    assert!(
        err.contains("bincode deserialize oversize_vec_u8"),
        "expected typed Decode error naming 'oversize_vec_u8', got: {err}"
    );
    assert!(
        err.contains("size limit reached"),
        "expected the cap-rejection wording 'size limit reached', got: {err}"
    );
}

#[test]
fn wasm_trusted_cap_admits_payload_at_32mib_boundary() {
    // at exactly the cap the length pre-check must NOT fire; a deliberately-truncated body
    // then fails the decode (not the cap), guaranteeing the Err arm - an all-zero blob
    // decodes to len 0 -> Ok, which made this assertion vacuous.
    let cap = WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES;
    let mut bytes = (cap as u64).to_le_bytes().to_vec();
    bytes.resize(cap, 0);
    let err = decode_trusted_for_test::<Vec<u8>>(&bytes, "boundary_payload")
        .expect_err("a cap-sized but truncated body must fail the decode, not the cap");
    assert!(
        !err.contains("size limit reached"),
        "the trusted cap must admit at the boundary (reject only past it); got: {err}"
    );
    assert!(
        err.contains("boundary_payload"),
        "expected the typed body-decode error for boundary_payload, got: {err}"
    );
}
