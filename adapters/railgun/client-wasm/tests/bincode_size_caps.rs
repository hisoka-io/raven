//! Boundary tests for the WASM bincode-deserialize size caps (64 MiB untrusted, 256 MiB trusted).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use raven_inspire_client_wasm::{
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
fn wasm_bincode_decode_accepts_35mb_server_crs_under_64mib_cap() {
    // proxy for the ~35 MB production-cell ServerCrs; a real one needs slow d=2048 setup
    const CRS_SHAPE_SIZE_BYTES: usize = 35 * 1024 * 1024;
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
fn wasm_trusted_cap_rejects_payload_above_256mib_with_typed_error() {
    // scoped so the 256 MiB buffer drops before the assertions run
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
    // at exactly the cap the pre-check must NOT fire; a body decode error still proves admission
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
