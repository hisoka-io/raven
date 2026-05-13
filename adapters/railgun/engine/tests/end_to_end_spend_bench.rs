//! End-to-end spend latency bench (`#[ignore]`-gated). Measures
//! `SPEND_LEAVES * TREE_DEPTH` query sweep at the locked production cell,
//! broken down by encoder. Network RTT excluded.

#![allow(
    clippy::expect_used,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::uninlined_format_args
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::{ClientSession, ServerResponse, ServerSessionHandle};
use raven_railgun_engine::inspire::{
    build_client_session, build_seeded_query, extract_response, register_client_session,
    setup_state, RavenInspireScheme,
};
use raven_railgun_engine::PirScheme;

const ENTRIES_LOG2: usize = 16;
const SPEND_LEAVES: u64 = 16;
const TREE_DEPTH: u64 = 16;
const SEEDS: usize = 3;

fn build_synthetic_db(n_entries: usize, entry_bytes: usize) -> Vec<u8> {
    (0..n_entries)
        .flat_map(|i| (0..entry_bytes).map(move |j| ((i * 31 + j * 17) % 251) as u8))
        .collect()
}

fn median(timings: &mut [Duration]) -> Duration {
    timings.sort();
    timings[timings.len() / 2]
}

#[derive(Clone, Copy)]
struct CellShape {
    label: &'static str,
    entries_log2: usize,
    entry_bytes: usize,
}

const CELLS: &[CellShape] = &[
    CellShape {
        label: "per-leaf-path 65536x512",
        entries_log2: ENTRIES_LOG2,
        entry_bytes: 512,
    },
    CellShape {
        label: "per-node 131072x32",
        entries_log2: ENTRIES_LOG2 + 1,
        entry_bytes: 32,
    },
];

fn run_one_seed(cell: &CellShape, seed: u64) -> (Duration, Duration, Duration, Duration) {
    let entries = 1usize << cell.entries_log2;
    let params = InspireParams::secure_128_d2048();
    let db = build_synthetic_db(entries, cell.entry_bytes);
    let (state, secret_key) =
        setup_state(&params, &db, cell.entry_bytes, InspireVariant::TwoPacking)
            .expect("setup_state");
    let mut client: ClientSession =
        build_client_session((*state.crs).clone(), secret_key, &params).expect("client session");
    register_client_session(&mut client, &state).expect("register session");
    let _: ServerSessionHandle = client.session_handle().expect("session handle");

    let state_arc = Arc::new(state);
    let crs = Arc::clone(&state_arc.crs);
    let entry_size = state_arc.entry_size;
    let entries_u64 = entries as u64;

    let started_full = Instant::now();
    let mut total_build = Duration::ZERO;
    let mut total_respond = Duration::ZERO;
    let mut total_extract = Duration::ZERO;

    for spend_idx in 0..SPEND_LEAVES {
        for sibling_lvl in 0..TREE_DEPTH {
            let target = ((seed.wrapping_mul(31_415))
                .wrapping_add(spend_idx.wrapping_mul(7919))
                .wrapping_add(sibling_lvl.wrapping_mul(2017)))
                % entries_u64;

            let bs = Instant::now();
            let (cs, query) =
                build_seeded_query(&client, state_arc.shard_config(), target, &params)
                    .expect("build_seeded_query");
            total_build += bs.elapsed();

            let rs = Instant::now();
            let resp: ServerResponse =
                <RavenInspireScheme as PirScheme>::respond(state_arc.as_ref(), &query)
                    .expect("respond");
            total_respond += rs.elapsed();

            let es = Instant::now();
            let _plain = extract_response(&crs, &cs, &resp, entry_size).expect("extract");
            total_extract += es.elapsed();
        }
    }
    let total = started_full.elapsed();
    (total, total_build, total_respond, total_extract)
}

fn run_cell(cell: &CellShape) {
    let mut totals: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut builds: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut responds: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut extracts: Vec<Duration> = Vec::with_capacity(SEEDS);

    for seed in 0..SEEDS {
        let setup_start = Instant::now();
        let (total, build, respond, extract) = run_one_seed(cell, seed as u64 + 1);
        eprintln!(
            "spend_bench: cell={} seed={} total={:?} build={:?} respond={:?} extract={:?} \
             (with-setup={:?})",
            cell.label,
            seed,
            total,
            build,
            respond,
            extract,
            setup_start.elapsed()
        );
        totals.push(total);
        builds.push(build);
        responds.push(respond);
        extracts.push(extract);
    }
    let total_med = median(&mut totals);
    let build_med = median(&mut builds);
    let respond_med = median(&mut responds);
    let extract_med = median(&mut extracts);
    let sweep_count = (SPEND_LEAVES * TREE_DEPTH) as f64;
    let per_query_total = total_med.as_secs_f64() / sweep_count;
    eprintln!(
        "spend_bench: cell={} 3-seed-median total={:?} build={:?} respond={:?} extract={:?} \
         per-query-mean={:.3} ms",
        cell.label,
        total_med,
        build_med,
        respond_med,
        extract_med,
        per_query_total * 1000.0
    );
}

#[test]
#[ignore = "production-cell setup is heavy (~12s per cell x 3 seeds); 16 spend-leaves x 16 siblings sweep"]
fn end_to_end_spend_latency_per_encoder() {
    eprintln!(
        "spend_bench: SPEND_LEAVES={} TREE_DEPTH={} per-spend-queries={}",
        SPEND_LEAVES,
        TREE_DEPTH,
        SPEND_LEAVES * TREE_DEPTH
    );
    for cell in CELLS {
        run_cell(cell);
    }
}
