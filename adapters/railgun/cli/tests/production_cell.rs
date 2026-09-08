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

use raven_inspire::ServerResponse;

#[path = "support/production_cell.rs"]
mod support;

use support::{ProductionCell, BATCH_WIDTH, BEARER_TOKEN, ENTRY_BYTES};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "~12 s of setup_state at the 65,536 x 512 B cell plus a full HTTP round trip. Trigger: \
            changing the HTTP query or batch path, the two-packing extract, or the cell shape. \
            Runs in the durability + closure cli-ignored lane."]
async fn production_cell_round_trip_byte_identity() {
    let cell = ProductionCell::spawn().await;
    eprintln!("production_cell: setup elapsed = {:?}", cell.setup_elapsed);
    let client = ProductionCell::client();

    let target_index: u64 = 31_415;
    let (client_state, query_bytes) = cell.seeded_query(target_index);
    let response = client
        .post(cell.query_url())
        .bearer_auth(BEARER_TOKEN)
        .body(query_bytes)
        .send()
        .await
        .expect("POST query");
    assert_eq!(response.status(), 200, "HTTP status");

    let body = response.bytes().await.expect("body bytes");
    let server_response: ServerResponse =
        raven_railgun_http::read_versioned(&body).expect("deserialize ServerResponse (versioned)");
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
