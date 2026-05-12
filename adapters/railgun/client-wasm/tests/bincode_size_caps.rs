//! Boundary tests for the WASM bincode-deserialize size caps.
//!
//! The wasm-bindgen surface routes every untrusted bincode payload
//! through the crate-private `decode<T>` helper, which enforces a
//! 64 MiB ceiling matching the HTTP layer's payload cap. Self-written
//! session blobs ([`deserialize_client_session`]) route through
//! `decode_trusted<T>` which enforces the larger 256 MiB ceiling
//! covering the locked-d=2048 ClientSession (~194 MB).
//!
//! These tests exercise both caps through the public
//! `decode_capped_for_test` + `decode_trusted_for_test` mirrors so a
//! future regression that drops or weakens either cap surfaces here
//! rather than as a browser-tab OOM.
//!
//! The caps are enforced as slice-length pre-checks rather than via
//! `bincode::Options::with_limit`. Reason: bincode 1.x's slice-
//! deserialize entry point (`bincode-1.3.3` `internal.rs`
//! `deserialize_seed`) overrides any configured limit to `Infinite`,
//! so `with_limit(N)` is a no-op for `bincode::deserialize(bytes)`
//! and only takes effect on `deserialize_from(reader)`. The slice
//! pre-check bounds allocations for any payload that crosses the
//! JS->Wasm boundary.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use raven_inspire_client_wasm::{
    decode_capped_for_test, decode_trusted_for_test, WASM_BINCODE_DESERIALIZE_LIMIT_BYTES,
    WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES,
};

#[test]
fn wasm_bincode_decode_rejects_payload_above_64mib_with_typed_error() {
    // Payload one byte past the 64 MiB cap. Contents are immaterial:
    // the slice-length pre-check fires before bincode ever runs.
    let bytes = vec![0u8; WASM_BINCODE_DESERIALIZE_LIMIT_BYTES + 1];

    let err = decode_capped_for_test::<Vec<u8>>(&bytes, "oversize_vec_u8")
        .expect_err("64 MiB+1 payload must be rejected by the WASM size cap");

    // Typed-error shape: the wasm boundary surfaces failure as
    // `WasmClientError::Decode { what, detail }` formatted as
    // "bincode deserialize <what>: <detail>". Assert both halves so
    // a regression that swaps the typed surface for an opaque string
    // shows up here.
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
fn wasm_bincode_decode_accepts_35mb_server_crs_under_64mib_cap() {
    // The production-cell `ServerCrs` (d=2048, p=65537,
    // total_entries=131_072) bincodes to roughly 35 MB. The cap at
    // 64 MiB must accept it cleanly. Synthesize a Vec<u8> of the
    // shape that emulates this size and verify the cap admits it.
    //
    // We do not synthesize a real CRS here (that would require
    // running the full setup against production-cell params, which
    // is too slow for a unit test); instead we exercise the cap on
    // a Vec<u8> bincode payload of the same byte size, proving the
    // cap admits the production CRS shape end-to-end.
    const CRS_SHAPE_SIZE_BYTES: usize = 35 * 1024 * 1024;
    // Compile-time check: 35 MiB must fit under the 64 MiB cap.
    const _: () = assert!(
        CRS_SHAPE_SIZE_BYTES <= WASM_BINCODE_DESERIALIZE_LIMIT_BYTES,
        "fixture invariant: 35 MB ServerCrs shape must fit under the 64 MiB cap"
    );

    let body = vec![0xc7u8; CRS_SHAPE_SIZE_BYTES];
    let bytes = bincode::serialize(&body).expect("bincode serialize CRS-shaped vec");
    assert!(
        bytes.len() <= WASM_BINCODE_DESERIALIZE_LIMIT_BYTES,
        "bincoded 35 MB Vec<u8> must fit under the WASM cap"
    );

    let decoded: Vec<u8> = decode_capped_for_test(&bytes, "production_cell_crs_shape")
        .expect("35 MB ServerCrs-shaped payload must decode under the 64 MiB cap");
    assert_eq!(
        decoded.len(),
        CRS_SHAPE_SIZE_BYTES,
        "decoded 35 MB payload must round-trip"
    );
}

#[test]
fn wasm_bincode_decode_accepts_legitimate_payload_just_under_64mib() {
    // Build a 'just-under-cap' payload by serializing a Vec<u8> of
    // (cap - 16) bytes. The 8-byte fixint length-prefix puts the
    // bincoded slice at exactly (cap - 8); well under the cap.
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
fn wasm_trusted_cap_rejects_payload_above_256mib_with_typed_error() {
    // One byte past the trusted cap must trigger the slice-length
    // pre-check before bincode runs. Drop the buffer immediately so
    // it does not pin RSS for the rest of the test process.
    let err = {
        let bytes = vec![0u8; WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES + 1];
        decode_trusted_for_test::<Vec<u8>>(&bytes, "oversize_vec_u8")
            .expect_err("256 MiB+1 payload must be rejected by the trusted cap")
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
fn wasm_trusted_cap_admits_payload_at_256mib_boundary() {
    // Allocate a buffer of exactly the trusted-cap size. The
    // pre-check must NOT fire; the helper either decodes (the
    // bytes happen to be a valid bincode prefix for the target
    // type) or surfaces a typed bincode-decode error from the
    // body. Either outcome proves cap admission. The assertion
    // is the negative form: there must be no "size limit
    // reached" rejection.
    let outcome = {
        let bytes = vec![0u8; WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES];
        decode_trusted_for_test::<Vec<u8>>(&bytes, "boundary_payload")
    };
    if let Err(ref err) = outcome {
        assert!(
            !err.contains("size limit reached"),
            "trusted cap must admit payloads at the 256 MiB boundary; got cap rejection: {err}"
        );
        assert!(
            err.contains("bincode deserialize boundary_payload"),
            "expected the typed Decode error wording for boundary_payload, got: {err}"
        );
    }
}
