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
fn wasm_bincode_decode_accepts_oversize_payload_under_64mib_cap() {
    // oversize-payload proxy for the 64 MiB cap; an arbitrary large body under the cap
    const OVERSIZE_PAYLOAD_BYTES: usize = 35 * 1024 * 1024;
    const _: () = assert!(
        OVERSIZE_PAYLOAD_BYTES <= WASM_BINCODE_DESERIALIZE_LIMIT_BYTES,
        "fixture invariant: the oversize-payload proxy must fit under the 64 MiB cap"
    );

    let body = vec![0xc7u8; OVERSIZE_PAYLOAD_BYTES];
    let bytes = bincode::serialize(&body).expect("bincode serialize oversize payload");
    assert!(
        bytes.len() <= WASM_BINCODE_DESERIALIZE_LIMIT_BYTES,
        "the bincoded oversize Vec<u8> must fit under the WASM cap"
    );

    let decoded: Vec<u8> = decode_capped_for_test(&bytes, "oversize_payload")
        .expect("an oversize payload must decode under the 64 MiB cap");
    assert_eq!(
        decoded.len(),
        OVERSIZE_PAYLOAD_BYTES,
        "the decoded oversize payload must round-trip"
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
