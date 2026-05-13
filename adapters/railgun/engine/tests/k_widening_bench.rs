//! K-dispatcher widening sweep at two cell shapes (K in {1,4,8,16}).
//! 3-seed methodology with separate server state per seed; reports per-K
//! wall-clock and speedup vs K=1.

#![allow(
    clippy::expect_used,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::format_push_string,
    clippy::uninlined_format_args
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::{ServerResponse, ServerSessionHandle};
use raven_railgun_engine::inspire::{
    build_client_session, build_seeded_query, register_client_session, setup_state,
    InspireServerState, RavenInspireScheme,
};
use raven_railgun_engine::PirScheme;

const BATCH_SIZE: usize = 16;
const K_VALUES: &[usize] = &[1, 4, 8, 16];
const SEEDS: usize = 3;
const WARMUP_ITERS: usize = 1;
const MEASURED_ITERS: usize = 3;

#[derive(Clone, Copy)]
struct CellShape {
    label: &'static str,
    entries_log2: u32,
    entry_bytes: usize,
    /// γ = ceil(entry_bytes * 8 / 16) = ceil(entry_bytes / 2)
    gamma: usize,
}

const CELLS: &[CellShape] = &[
    CellShape {
        label: "65536x512",
        entries_log2: 16,
        entry_bytes: 512,
        gamma: 256,
    },
    CellShape {
        label: "65536x32",
        entries_log2: 16,
        entry_bytes: 32,
        gamma: 16,
    },
];

fn build_synthetic_db(n_entries: usize, entry_bytes: usize) -> Vec<u8> {
    (0..n_entries)
        .flat_map(|i| (0..entry_bytes).map(move |j| ((i * 31 + j * 17) % 251) as u8))
        .collect()
}

fn median(timings: &[Duration]) -> Duration {
    let mut sorted = timings.to_vec();
    sorted.sort();
    *sorted.get(sorted.len() / 2).expect("non-empty")
}

/// Dispatch BATCH_SIZE queries against `state` at concurrency cap `k`.
/// Mirrors the production HTTP `dispatch_batch` semantics: tokio
/// `JoinSet` + `tokio::sync::Semaphore` + per-worker `spawn_blocking`.
fn dispatch_at_k(
    rt: &tokio::runtime::Runtime,
    state: &Arc<InspireServerState>,
    queries: &[raven_inspire::SeededClientQuery],
    k: usize,
) -> Vec<ServerResponse> {
    use tokio::sync::Semaphore;
    use tokio::task::JoinSet;

    let semaphore = Arc::new(Semaphore::new(k.max(1)));
    let queries_owned: Vec<_> = queries.to_vec();

    rt.block_on(async move {
        let n = queries_owned.len();
        let mut responses: Vec<Option<ServerResponse>> = (0..n).map(|_| None).collect();
        let mut join: JoinSet<(usize, ServerResponse)> = JoinSet::new();
        let mut next_idx = 0usize;
        let mut iter = queries_owned.into_iter();

        while next_idx < k.min(n) {
            let q = iter.next().expect("prime");
            let s = Arc::clone(state);
            let sem = Arc::clone(&semaphore);
            let idx = next_idx;
            join.spawn(async move {
                let _permit = sem.acquire_owned().await.expect("permit");
                let r = tokio::task::spawn_blocking(move || {
                    <RavenInspireScheme as PirScheme>::respond(s.as_ref(), &q).expect("respond")
                })
                .await
                .expect("blocking");
                (idx, r)
            });
            next_idx += 1;
        }
        while let Some(joined) = join.join_next().await {
            let (idx, r) = joined.expect("join");
            *responses.get_mut(idx).expect("idx") = Some(r);
            if let Some(q) = iter.next() {
                let s = Arc::clone(state);
                let sem = Arc::clone(&semaphore);
                let idx = next_idx;
                join.spawn(async move {
                    let _permit = sem.acquire_owned().await.expect("permit");
                    let r = tokio::task::spawn_blocking(move || {
                        <RavenInspireScheme as PirScheme>::respond(s.as_ref(), &q).expect("respond")
                    })
                    .await
                    .expect("blocking");
                    (idx, r)
                });
                next_idx += 1;
            }
        }
        responses.into_iter().map(|o| o.expect("filled")).collect()
    })
}

#[test]
#[ignore = "production-cell K-widening sweep; ~60-90s wall (heavy setup x 2 cells x 3 seeds)"]
fn k_widening_at_two_cells() {
    let cores = std::thread::available_parallelism().map_or(8, std::num::NonZeroUsize::get);
    eprintln!("k_widening: available_parallelism = {cores}");
    eprintln!("k_widening: K_VALUES = {K_VALUES:?}; BATCH_SIZE = {BATCH_SIZE}");
    eprintln!("k_widening: WARMUP_ITERS = {WARMUP_ITERS}; MEASURED_ITERS = {MEASURED_ITERS}; SEEDS = {SEEDS}");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("rt");

    for cell in CELLS {
        let entries = 1usize << cell.entries_log2;

        for seed in 0..SEEDS {
            let setup_start = Instant::now();
            let params = InspireParams::secure_128_d2048();
            let db = build_synthetic_db(entries, cell.entry_bytes);
            let (server_state, secret_key) =
                setup_state(&params, &db, cell.entry_bytes, InspireVariant::TwoPacking)
                    .expect("setup_state");

            let mut client_session =
                build_client_session((*server_state.crs).clone(), secret_key, &params)
                    .expect("client_session");
            let _: ServerSessionHandle = {
                register_client_session(&mut client_session, &server_state)
                    .expect("register session");
                client_session
                    .session_handle()
                    .expect("session_handle was set")
            };

            let state_arc = Arc::new(server_state);
            let mut queries = Vec::with_capacity(BATCH_SIZE);
            for k in 0..BATCH_SIZE as u64 {
                let idx_offset = k * 911 + (seed as u64 * 31_415);
                let idx = (37u64.wrapping_add(idx_offset)) % (entries as u64);
                let (_cs, q) =
                    build_seeded_query(&client_session, state_arc.shard_config(), idx, &params)
                        .expect("build_seeded_query");
                queries.push(q);
            }
            eprintln!(
                "k_widening: cell={} seed={} setup elapsed = {:?}",
                cell.label,
                seed,
                setup_start.elapsed()
            );

            let mut wall_per_k: Vec<(usize, Duration)> = Vec::with_capacity(K_VALUES.len());
            for &k in K_VALUES {
                for _ in 0..WARMUP_ITERS {
                    let _ = dispatch_at_k(&rt, &state_arc, &queries, k);
                }
                let mut timings = Vec::with_capacity(MEASURED_ITERS);
                for _ in 0..MEASURED_ITERS {
                    let started = Instant::now();
                    let resp = dispatch_at_k(&rt, &state_arc, &queries, k);
                    let elapsed = started.elapsed();
                    assert_eq!(resp.len(), BATCH_SIZE, "K={k} returned wrong count");
                    timings.push(elapsed);
                }
                let med = median(&timings);
                wall_per_k.push((k, med));
            }

            let mut line = format!(
                "k_widening cell={} gamma={} seed={}",
                cell.label, cell.gamma, seed
            );
            let baseline_wall = wall_per_k
                .iter()
                .find(|(k, _)| *k == 1)
                .map(|(_, w)| *w)
                .expect("K=1 measured");
            for (k, w) in &wall_per_k {
                let speedup = baseline_wall.as_secs_f64() / w.as_secs_f64();
                line.push_str(&format!(" K={k}_wall={:?}_speedup={:.2}x", w, speedup));
            }
            eprintln!("{line}");
        }
    }
}
