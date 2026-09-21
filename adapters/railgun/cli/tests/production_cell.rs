//! Production-cell BYTE IDENTITY over the full HTTP stack, at the locked T2/T3
//! cell: 65,536 entries x 512 B records (16 x 32 B Merkle siblings).
//!
//! This half carries NO wall-clock assertion. It used to: the same function
//! asserted a 300 ms single-query ceiling and a 3 s batch ceiling, and those
//! deadlines are why the durability lane excluded it by name — it measured
//! 402 ms under lane load while passing at 19.9 s standalone, i.e. it red on
//! machine speed rather than on code. The consequence was that the lane named
//! `binary(production_cell)` and ran ZERO tests from it, so the byte-identity
//! assertions — the ones that catch silent-wrong-bytes at production
//! parameters — were reachable by nobody.
//!
//! The deadlines now live in `benches/production_cell_budget_bench.rs` as an
//! SLO gate. Nothing is lost by the split: a deadline could only ever fail on
//! runner speed, and the assertions kept here are the ones that fail on wrong
//! bytes. Note that the b1 bench baseline is 2^16 x 32 B while this cell is
//! 2^16 x 512 B, so the baseline does NOT cover this shape and must not be
//! cited as if it did.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::print_stderr
)]

use raven_inspire::{SeededClientQuery, ServerResponse};
use raven_railgun_engine::inspire::WIRE_RESPONSE_MODULUS;
use serde::Deserialize;

#[path = "support/production_cell.rs"]
mod support;

use support::{ProductionCell, BATCH_WIDTH, BEARER_TOKEN, CLIENT_ID, ENTRY_BYTES};

#[derive(Deserialize)]
struct BatchCapacityEvidence {
    #[serde(rename = "serializedQueryBytes")]
    serialized_query: usize,
    #[serde(rename = "batchFrameBytes")]
    batch_frame: usize,
    #[serde(rename = "defaultBodyCapBytes")]
    default_body_cap: usize,
}

/// Bincode bytes of a packed `ServerResponse` around its two coefficient payloads: the
/// variant tag; `a`'s coefficient length, one-modulus vector, q, dim, CRT inverse and NTT
/// flag; the `b` prefix length; the retained count; the empty column vector; and
/// `Some(packing_mode)`.
const PACKED_RESPONSE_HEADER_BYTES: usize = 4 + (8 + 16 + 8 + 8 + 8 + 1) + 8 + 4 + 8 + 5;

/// The tight serializer packs `a` in full and `b`'s retained prefix at the modulus's width.
fn tight_packed_response_bytes(modulus: u64, ring_dim: usize, retained: usize) -> usize {
    let bits = usize::try_from(u64::BITS - (modulus - 1).leading_zeros()).expect("bit width");
    PACKED_RESPONSE_HEADER_BYTES + ((ring_dim + retained) * bits).div_ceil(8)
}

async fn assert_batch_capacity_boundary(
    cell: &ProductionCell,
    client: &reqwest::Client,
    target_index: u64,
) {
    let (_, handled_query) = cell.handled_query(target_index);
    let serialized_query = bincode::serialize(&handled_query).expect("serialize handled query");
    let fixture_query_bytes =
        hex::decode(include_str!("../../sdk/tests/fixtures/production_handled_query.hex").trim())
            .expect("production query fixture is hex");
    let fixture_query: SeededClientQuery =
        bincode::deserialize(&fixture_query_bytes).expect("fixture is a handled query");
    assert!(fixture_query.inspiring_packing_keys.is_none());
    assert!(fixture_query.session_handle.is_some());
    assert!(handled_query.inspiring_packing_keys.is_none());
    assert!(handled_query.session_handle.is_some());
    assert_eq!(serialized_query.len(), fixture_query_bytes.len());
    let evidence: BatchCapacityEvidence = serde_json::from_str(include_str!(
        "../../sdk/tests/fixtures/production_batch_capacity.json"
    ))
    .expect("production capacity evidence is JSON");
    let empty_batch = raven_railgun_http::write_versioned(&Vec::<SeededClientQuery>::new())
        .expect("serialize empty batch");
    let frame_bytes = empty_batch.len();
    let raw_capacity = (cell.max_body_bytes - frame_bytes) / serialized_query.len();
    assert_eq!(serialized_query.len(), evidence.serialized_query);
    assert_eq!(frame_bytes, evidence.batch_frame);
    assert_eq!(cell.max_body_bytes, evidence.default_body_cap);
    assert_eq!(serialized_query.len(), 15_491, "handled query bytes");
    assert_eq!(frame_bytes, 10, "version plus Vec length frame");
    assert_eq!(cell.max_body_bytes, 8 * 1024 * 1024, "HTTP body cap");
    assert_eq!(raw_capacity, 541, "raw query capacity");
    let admitted = raven_railgun_http::write_versioned(&vec![handled_query.clone(); raw_capacity])
        .expect("serialize admitted body");
    let refused = raven_railgun_http::write_versioned(&vec![handled_query; raw_capacity + 1])
        .expect("serialize refused body");
    assert_eq!(admitted.len(), 8_380_641);
    assert_eq!(refused.len(), 8_396_132);
    assert!(admitted.len() <= cell.max_body_bytes);
    assert!(refused.len() > cell.max_body_bytes);
    let admitted_status = client
        .post(cell.batch_url())
        .bearer_auth(BEARER_TOKEN)
        .header("x-raven-client-id", CLIENT_ID)
        .body(admitted)
        .send()
        .await
        .expect("POST body within cap")
        .status();
    assert_eq!(admitted_status, 400, "541 reaches the off-step guard");
    let refused_status = client
        .post(cell.batch_url())
        .bearer_auth(BEARER_TOKEN)
        .header("x-raven-client-id", CLIENT_ID)
        .body(refused)
        .send()
        .await
        .expect("POST body above cap")
        .status();
    assert_eq!(refused_status, 413, "542 exceeds the body cap");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "~12 s of setup_state at the 65,536 x 512 B cell plus a full HTTP round trip. Trigger: \
            changing the HTTP query or batch path, the two-packing extract, or the cell shape. \
            Runs in the durability + closure cli-ignored lane."]
async fn production_cell_round_trip_byte_identity() {
    let cell = ProductionCell::spawn().await;
    eprintln!("production_cell: setup elapsed = {:?}", cell.setup_elapsed);
    let client = ProductionCell::client();

    let target_index: u64 = 31_415;
    assert_batch_capacity_boundary(&cell, &client, target_index).await;

    let (client_state, query_bytes) = cell.seeded_query(target_index);
    let response = client
        .post(cell.query_url())
        .bearer_auth(BEARER_TOKEN)
        .header("x-raven-client-id", CLIENT_ID)
        .body(query_bytes)
        .send()
        .await
        .expect("POST query");
    assert_eq!(response.status(), 200, "HTTP status");

    let body = response.bytes().await.expect("body bytes");
    // p = 65,537 carries two record bytes per retained coefficient.
    let retained = ENTRY_BYTES.div_ceil(2);
    let switched_bytes =
        tight_packed_response_bytes(WIRE_RESPONSE_MODULUS, cell.params.ring_dim, retained);
    let unswitched_bytes =
        tight_packed_response_bytes(cell.params.q, cell.params.ring_dim, retained);
    assert_eq!(
        switched_bytes, 10_446,
        "36-bit packing over 2048 + 256 coefficients"
    );
    assert_eq!(
        unswitched_bytes, 17_358,
        "60-bit packing over the same coefficients"
    );
    assert_eq!(
        body.len(),
        raven_railgun_http::WIRE_SCHEMA_PREFIX_LEN + switched_bytes,
        "versioned switched response bytes"
    );
    let server_response: ServerResponse =
        raven_railgun_http::read_versioned(&body).expect("deserialize ServerResponse (versioned)");
    assert_eq!(
        server_response.ciphertext.modulus(),
        WIRE_RESPONSE_MODULUS,
        "every served response is mod-switched"
    );
    assert_eq!(
        server_response.packed_coefficients,
        Some(u32::try_from(retained).expect("retained fits u32")),
        "the closed form must count the prefix the server actually retained"
    );
    assert_eq!(
        server_response
            .to_binary()
            .expect("tight response body")
            .len(),
        switched_bytes,
        "the switch saves exactly {} bytes from the {unswitched_bytes}-byte unswitched body",
        unswitched_bytes - switched_bytes
    );
    let plaintext = cell.decode(&client_state, &server_response);
    assert_eq!(
        plaintext.get(..ENTRY_BYTES),
        Some(cell.planted(target_index)),
        "single-query byte equality"
    );

    let (client_states, targets, batch_bytes) = cell.seeded_batch(target_index);
    let batch_response = client
        .post(cell.batch_url())
        .bearer_auth(BEARER_TOKEN)
        .header("x-raven-client-id", CLIENT_ID)
        .body(batch_bytes)
        .send()
        .await
        .expect("POST batch");
    assert_eq!(batch_response.status(), 200, "batch HTTP status");

    let batch_body = batch_response.bytes().await.expect("batch body");
    let responses: Vec<ServerResponse> =
        raven_railgun_http::read_batch_response_versioned(&batch_body)
            .expect("deserialize batch (versioned)");
    assert_eq!(
        responses.len(),
        BATCH_WIDTH,
        "batch returned every response"
    );

    for (k, (cs, response)) in client_states.iter().zip(responses.iter()).enumerate() {
        let idx = *targets.get(k).expect("target idx in range");
        let plaintext = cell.decode(cs, response);
        assert_eq!(
            plaintext.get(..ENTRY_BYTES),
            Some(cell.planted(idx)),
            "batch byte equality at k={k}, idx={idx}"
        );
    }

    cell.shutdown().await;
}
