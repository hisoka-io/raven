//! SLO GATE, not a benchmark: the production-cell latency budget.
//!
//! Both assertions here compare a wall clock against a fixed ceiling, so they
//! red on runner speed rather than on code — which is exactly why they were
//! split out of `tests/production_cell.rs`. That test's byte-identity
//! assertions now run per commit; these deadlines run where a machine-speed
//! assertion can survive.
//!
//! ROUTING, READ BEFORE MOVING THIS FILE: an SLO in `benches/` is only a gate
//! if some lane actually selects it. The railgun test matrix builds bench
//! targets (it passes `--all-targets`), but the cli lane's filter is a union of
//! named `binary(...)` terms and does not name this one — deliberately, since
//! putting a deadline back in a per-push lane recreates the flake the split
//! removed. It needs the nightly production-cell profile, whose 300 s
//! slow-timeout is the only budget a machine-speed assertion can survive.
//! A named `binary(...)` filter is NOT the only route in, which this file
//! claimed until 2026-09-22: the nightly lane selects it via `--run-ignored all`
//! without naming it, so it DOES run and the ceilings must fit that runner.
//!
//! Measured figures behind the ceilings, kept so a reader can tell a real
//! regression from runner variance. Single query: 71.9 ms on a 16-core dev box,
//! 335 ms on a 4-vCPU shared runner that spent 20.3 s on setup alone. `/batch`
//! runs its 16 queries serially (each already saturates rayon per shard, so
//! `par_iter` would thrash the global pool), giving ~1.2 s on the dev box and
//! ~5.6 s on the runner at the same 4.7x.
//!
//! The ceilings are sized for the SLOWEST host they run on, not the fastest,
//! because a ceiling the nightly lane cannot meet is a red every night and a
//! gate nobody reads. At 1 s and 12 s they catch a >10x blow-up — a lost index,
//! an accidental full scan, a re-setup per request — and nothing subtler. For a
//! real latency number, measure on a known box against the floors above; these
//! assertions are not that measurement and cannot be.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::print_stderr
)]

use std::time::{Duration, Instant};

#[path = "../tests/support/production_cell.rs"]
mod support;

use support::{ProductionCell, BEARER_TOKEN, CLIENT_ID};

/// SLO gate: single-query and batch round-trip latency at the production cell.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "SLO gate (not a bench): asserts a 1 s single-query and 12 s batch ceiling at the \
            65,536 x 512 B cell, sized for the slowest host it runs on. A wall-clock ceiling reds \
            on runner speed, so it belongs in the nightly closure lane, never per push. Trigger: a \
            >10x latency blow-up in the HTTP query or batch path at production parameters."]
async fn production_cell_latency_budget_slo() {
    let cell = ProductionCell::spawn().await;
    eprintln!("production_cell: setup elapsed = {:?}", cell.setup_elapsed);
    let client = ProductionCell::client();

    let target_index: u64 = 31_415;
    let (_client_state, query_bytes) = cell.seeded_query(target_index);
    let single_start = Instant::now();
    let response = client
        .post(cell.query_url())
        .bearer_auth(BEARER_TOKEN)
        .header("x-raven-client-id", CLIENT_ID)
        .body(query_bytes)
        .send()
        .await
        .expect("POST query");
    let status = response.status();
    let body = response.bytes().await.expect("body bytes");
    assert_eq!(
        status,
        200,
        "HTTP status; body={}",
        String::from_utf8_lossy(&body)
    );
    let single_total = single_start.elapsed();
    eprintln!("production_cell: single-query total = {single_total:?}");

    assert!(
        single_total < Duration::from_millis(1000),
        "single query total RT regressed: {single_total:?} (floors: 71.9 ms dev box, ~335 ms shared runner)"
    );

    let (_client_states, _targets, batch_bytes) = cell.seeded_batch(target_index);
    let batch_start = Instant::now();
    let batch_response = client
        .post(cell.batch_url())
        .bearer_auth(BEARER_TOKEN)
        .header("x-raven-client-id", CLIENT_ID)
        .body(batch_bytes)
        .send()
        .await
        .expect("POST batch");
    assert_eq!(batch_response.status(), 200, "batch HTTP status");
    let _ = batch_response.bytes().await.expect("batch body");
    let batch_total = batch_start.elapsed();
    eprintln!("production_cell: batch (16 queries) total = {batch_total:?}");

    assert!(
        batch_total < Duration::from_secs(12),
        "batch total RT regressed: {batch_total:?} (floors: ~1.2 s dev box, ~5.6 s shared runner)"
    );

    cell.shutdown().await;
}
