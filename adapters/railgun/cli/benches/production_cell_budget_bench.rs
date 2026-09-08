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
//! Until that lane names this binary, these two ceilings are compiled and not
//! run.
//!
//! Measured figures behind the ceilings, kept so a reader can tell a real
//! regression from runner variance: the single-query production floor is
//! 71.9 ms total and the 300 ms ceiling is that plus headroom for HTTP, serde
//! and host noise; `/batch` runs its queries serially (each already saturates
//! rayon per shard, so `par_iter` would thrash the global pool), giving a
//! 16 x ~75 ms = ~1.2 s floor under the 3 s ceiling.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::print_stderr
)]

use std::time::{Duration, Instant};

#[path = "../tests/support/production_cell.rs"]
mod support;

use support::{ProductionCell, BEARER_TOKEN};

/// SLO gate: single-query and batch round-trip latency at the production cell.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "SLO gate (not a bench): asserts a 300 ms single-query and 3 s batch ceiling at the \
            65,536 x 512 B cell. A wall-clock ceiling reds on runner speed, so it belongs in the \
            nightly closure lane, never per push. Trigger: a latency regression in the HTTP query \
            or batch path at production parameters."]
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
        .body(query_bytes)
        .send()
        .await
        .expect("POST query");
    assert_eq!(response.status(), 200, "HTTP status");
    let _ = response.bytes().await.expect("body bytes");
    let single_total = single_start.elapsed();
    eprintln!("production_cell: single-query total = {single_total:?}");

    assert!(
        single_total < Duration::from_millis(300),
        "single query total RT regressed: {single_total:?} (production floor 71.9 ms total)"
    );

    let (_client_states, _targets, batch_bytes) = cell.seeded_batch(target_index);
    let batch_start = Instant::now();
    let batch_response = client
        .post(cell.batch_url())
        .bearer_auth(BEARER_TOKEN)
        .body(batch_bytes)
        .send()
        .await
        .expect("POST batch");
    assert_eq!(batch_response.status(), 200, "batch HTTP status");
    let _ = batch_response.bytes().await.expect("batch body");
    let batch_total = batch_start.elapsed();
    eprintln!("production_cell: batch (16 queries) total = {batch_total:?}");

    assert!(
        batch_total < Duration::from_secs(3),
        "batch total RT regressed: {batch_total:?} (sequential floor ~1.2 s)"
    );

    cell.shutdown().await;
}
