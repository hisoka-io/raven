//! K=4 cross-query dispatcher architecture investigation (`#[ignore]`-gated).
//! Compares four dispatch strategies (baseline JoinSet, dedicated rayon pool,
//! thread::scope, single par_iter) against the locked production cell.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation
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

type DispatchFn =
    fn(&Arc<InspireServerState>, &[raven_inspire::SeededClientQuery]) -> Vec<ServerResponse>;

const ENTRIES_LOG2: usize = 16;
const ENTRY_BYTES: usize = 512;
const BATCH_SIZE: usize = 16;
const K: usize = 4;
const WARMUP_ITERS: usize = 1;
const MEASURED_ITERS: usize = 3;

fn build_synthetic_db(n_entries: usize, entry_bytes: usize) -> Vec<u8> {
    (0..n_entries)
        .flat_map(|i| (0..entry_bytes).map(move |j| ((i * 31 + j * 17) % 251) as u8))
        .collect()
}

fn median_of_three(timings: &[Duration]) -> Duration {
    let mut sorted = timings.to_vec();
    sorted.sort();
    *sorted.get(sorted.len() / 2).expect("non-empty")
}

#[test]
#[ignore = "production-cell setup is heavy (~12s); K=4 dispatcher comparison"]
#[allow(clippy::too_many_lines)]
fn k4_dispatcher_strategy_comparison() {
    let setup_start = Instant::now();
    let params = InspireParams::secure_128_d2048();
    let entries = 1usize << ENTRIES_LOG2;
    let db = build_synthetic_db(entries, ENTRY_BYTES);
    let (server_state, secret_key) =
        setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("setup_state");
    let mut client_session = build_client_session((*server_state.crs).clone(), secret_key, &params)
        .expect("client_session");
    let _: ServerSessionHandle = {
        register_client_session(&mut client_session, &server_state).expect("register session");
        client_session
            .session_handle()
            .expect("session_handle was set")
    };

    let state_arc = Arc::new(server_state);
    let mut queries = Vec::with_capacity(BATCH_SIZE);
    for k in 0..BATCH_SIZE as u64 {
        let idx = (31_415u64.wrapping_add(k * 911)) % (entries as u64);
        let (_cs, q) = build_seeded_query(&client_session, state_arc.shard_config(), idx, &params)
            .expect("build_seeded_query");
        queries.push(q);
    }
    let setup_elapsed = setup_start.elapsed();
    eprintln!("k4_bench: setup elapsed = {setup_elapsed:?}");

    let cores = std::thread::available_parallelism().map_or(8, std::num::NonZeroUsize::get);
    eprintln!("k4_bench: available_parallelism = {cores}");
    eprintln!("k4_bench: K = {K}; BATCH_SIZE = {BATCH_SIZE}; warmup = {WARMUP_ITERS}; measured = {MEASURED_ITERS}");

    let strategies: Vec<(&str, DispatchFn)> = vec![
        ("baseline_joinset_spawnblocking", strategy_baseline),
        ("a_dedicated_rayon_pool", strategy_a_dedicated_pool),
        ("b_thread_scope", strategy_b_thread_scope),
        ("c_par_iter", strategy_c_par_iter),
    ];

    for (name, dispatch) in strategies {
        for _ in 0..WARMUP_ITERS {
            let _ = dispatch(&state_arc, &queries);
        }
        let mut timings = Vec::with_capacity(MEASURED_ITERS);
        for _ in 0..MEASURED_ITERS {
            let started = Instant::now();
            let responses = dispatch(&state_arc, &queries);
            let elapsed = started.elapsed();
            assert_eq!(responses.len(), BATCH_SIZE, "{name} returned wrong count");
            timings.push(elapsed);
        }
        let mn = timings.iter().min().expect("non-empty");
        let mx = timings.iter().max().expect("non-empty");
        let med = median_of_three(&timings);
        eprintln!("k4_bench: {name:32} min={mn:?} med={med:?} max={mx:?}  (raw: {timings:?})");
    }
}

/// Baseline mirroring production `dispatch_batch`: `JoinSet` of K
/// semaphore-gated spawn_blocking workers over the global rayon pool.
fn strategy_baseline(
    state: &Arc<InspireServerState>,
    queries: &[raven_inspire::SeededClientQuery],
) -> Vec<ServerResponse> {
    use tokio::runtime::Builder;
    use tokio::sync::Semaphore;
    use tokio::task::JoinSet;

    let rt = Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("rt");
    let semaphore = Arc::new(Semaphore::new(K));
    let queries_owned: Vec<_> = queries.to_vec();

    rt.block_on(async move {
        let n = queries_owned.len();
        let mut responses: Vec<Option<ServerResponse>> = (0..n).map(|_| None).collect();
        let mut join: JoinSet<(usize, ServerResponse)> = JoinSet::new();
        let mut next_idx = 0usize;
        let mut iter = queries_owned.into_iter();

        while next_idx < K.min(n) {
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

/// (a) K workers, each in its own `cores / K`-sized rayon pool, so
/// per-respond work does not thrash the global pool.
fn strategy_a_dedicated_pool(
    state: &Arc<InspireServerState>,
    queries: &[raven_inspire::SeededClientQuery],
) -> Vec<ServerResponse> {
    use std::thread;

    let cores = std::thread::available_parallelism().map_or(8, std::num::NonZeroUsize::get);
    let per_pool = (cores / K).max(1);

    let pools: Vec<Arc<rayon::ThreadPool>> = (0..K)
        .map(|i| {
            Arc::new(
                rayon::ThreadPoolBuilder::new()
                    .num_threads(per_pool)
                    .thread_name(move |t| format!("k4-strat-a-{i}-{t}"))
                    .build()
                    .expect("pool"),
            )
        })
        .collect();

    let n = queries.len();
    let chunk = n.div_ceil(K);
    let mut responses: Vec<Option<ServerResponse>> = (0..n).map(|_| None).collect();

    thread::scope(|s| {
        let mut handles = Vec::with_capacity(K);
        let mut chunks: Vec<Vec<(usize, raven_inspire::SeededClientQuery)>> =
            (0..K).map(|_| Vec::new()).collect();
        for (i, q) in queries.iter().enumerate() {
            let bucket = i / chunk;
            chunks
                .get_mut(bucket.min(K - 1))
                .expect("bucket")
                .push((i, q.clone()));
        }
        for (worker_idx, items) in chunks.into_iter().enumerate() {
            let pool = Arc::clone(pools.get(worker_idx).expect("pool"));
            let st = Arc::clone(state);
            handles.push(s.spawn(move || {
                pool.install(|| {
                    items
                        .into_iter()
                        .map(|(idx, q)| {
                            let r = <RavenInspireScheme as PirScheme>::respond(st.as_ref(), &q)
                                .expect("respond");
                            (idx, r)
                        })
                        .collect::<Vec<_>>()
                })
            }));
        }
        for h in handles {
            for (idx, r) in h.join().expect("worker") {
                *responses.get_mut(idx).expect("idx") = Some(r);
            }
        }
    });

    responses.into_iter().map(|o| o.expect("filled")).collect()
}

/// (b) K OS threads via `std::thread::scope`, dropping the JoinSet +
/// semaphore + per-task spawn overhead.
fn strategy_b_thread_scope(
    state: &Arc<InspireServerState>,
    queries: &[raven_inspire::SeededClientQuery],
) -> Vec<ServerResponse> {
    let n = queries.len();
    let chunk = n.div_ceil(K);
    let queries_owned: Vec<_> = queries.to_vec();
    let st = Arc::clone(state);

    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(K);
        for worker_idx in 0..K {
            let begin = worker_idx * chunk;
            let end = (begin + chunk).min(n);
            if begin >= end {
                continue;
            }
            let slice: Vec<_> = queries_owned.get(begin..end).expect("slice").to_vec();
            let s = Arc::clone(&st);
            handles.push(scope.spawn(move || {
                slice
                    .into_iter()
                    .enumerate()
                    .map(|(j, q)| {
                        let r = <RavenInspireScheme as PirScheme>::respond(s.as_ref(), &q)
                            .expect("respond");
                        (begin + j, r)
                    })
                    .collect::<Vec<_>>()
            }));
        }
        let mut responses: Vec<Option<ServerResponse>> = (0..n).map(|_| None).collect();
        for h in handles {
            for (idx, r) in h.join().expect("worker") {
                *responses.get_mut(idx).expect("idx") = Some(r);
            }
        }
        responses.into_iter().map(|o| o.expect("filled")).collect()
    })
}

/// (c) Single `rayon::par_iter` fanout: one pool handles outer + inner
/// parallelism via work-stealing.
fn strategy_c_par_iter(
    state: &Arc<InspireServerState>,
    queries: &[raven_inspire::SeededClientQuery],
) -> Vec<ServerResponse> {
    use rayon::prelude::*;
    queries
        .par_iter()
        .map(|q| <RavenInspireScheme as PirScheme>::respond(state.as_ref(), q).expect("respond"))
        .collect()
}
