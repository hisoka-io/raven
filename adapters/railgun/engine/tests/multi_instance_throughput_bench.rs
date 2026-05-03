//! Multi-instance throughput bench (`#[ignore]`-gated).
//!
//! 6 InspireServerState instances at production cell shape
//! (65,536 × 512 B, K=4), measuring aggregate QPS vs a single-instance
//! baseline.

#![allow(
    clippy::expect_used,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::uninlined_format_args
)]

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::{ClientSession, ServerResponse, ServerSessionHandle};
use raven_railgun_engine::inspire::{
    build_client_session, build_seeded_query, register_client_session, setup_state,
    InspireServerState, RavenInspireScheme,
};
use raven_railgun_engine::PirScheme;

const ENTRIES_LOG2: usize = 16;
const ENTRY_BYTES: usize = 512;
const NUM_INSTANCES: usize = 6;
const K_PER_INSTANCE: usize = 4;
const TOTAL_QUERIES: usize = 1000;
const SEEDS: usize = 3;

fn findings_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.pop();
    p.push("no-commit");
    p.push("railgun-demo");
    p.push("bench-results");
    p.push("2026-05-02-encoder-matrix");
    p.push("FINDINGS.md");
    p
}

fn append_findings_line(line: &str) {
    let path = findings_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let result = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut f| writeln!(f, "{line}"));
    if let Err(e) = result {
        eprintln!("findings: failed to append to {}: {e}", path.display());
    }
}

fn median_dur(values: &mut [Duration]) -> Duration {
    values.sort();
    values[values.len() / 2]
}

fn median_f64(values: &mut [f64]) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    values[values.len() / 2]
}

fn build_synthetic_db(n_entries: usize, entry_bytes: usize, salt: u8) -> Vec<u8> {
    (0..n_entries)
        .flat_map(|i| {
            (0..entry_bytes).map(move |j| ((i * 31 + j * 17 + usize::from(salt) * 7) % 251) as u8)
        })
        .collect()
}

struct ReadyInstance {
    state: Arc<InspireServerState>,
    client: ClientSession,
}

fn build_ready_instance(params: &InspireParams, instance_idx: usize) -> ReadyInstance {
    let entries = 1usize << ENTRIES_LOG2;
    let salt = u8::try_from(instance_idx).unwrap_or(0).saturating_add(1);
    let db = build_synthetic_db(entries, ENTRY_BYTES, salt);
    let (server_state, secret_key) =
        setup_state(params, &db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("setup_state");
    let mut client = build_client_session((*server_state.crs).clone(), secret_key, params)
        .expect("client_session");
    register_client_session(&mut client, &server_state).expect("register session");
    let _: ServerSessionHandle = client.session_handle().expect("session handle");
    ReadyInstance {
        state: Arc::new(server_state),
        client,
    }
}

#[derive(Clone, Copy, Debug)]
struct LatencyDist {
    p50: Duration,
    p95: Duration,
    p99: Duration,
    max: Duration,
    n: usize,
}

fn percentiles(samples: &mut [Duration]) -> LatencyDist {
    samples.sort();
    let n = samples.len();
    let pct = |p: f64| -> Duration {
        let idx = ((p * (n as f64 - 1.0)).round() as usize).min(n.saturating_sub(1));
        samples.get(idx).copied().unwrap_or_default()
    };
    LatencyDist {
        p50: pct(0.50),
        p95: pct(0.95),
        p99: pct(0.99),
        max: samples.last().copied().unwrap_or_default(),
        n,
    }
}

fn dispatch_sweep(
    rt: &tokio::runtime::Runtime,
    instances: &[ReadyInstance],
    queries: &[(usize, raven_inspire::SeededClientQuery)],
    k_per_instance: usize,
) -> (Duration, Vec<Vec<Duration>>) {
    use tokio::sync::Semaphore;
    use tokio::task::JoinSet;

    let n_instances = instances.len();
    let semaphores: Vec<Arc<Semaphore>> = (0..n_instances)
        .map(|_| Arc::new(Semaphore::new(k_per_instance.max(1))))
        .collect();
    let states: Vec<Arc<InspireServerState>> =
        instances.iter().map(|i| Arc::clone(&i.state)).collect();
    let queries_owned: Vec<(usize, raven_inspire::SeededClientQuery)> = queries.to_vec();

    let started = Instant::now();
    let per_instance_lat: Vec<Vec<Duration>> = rt.block_on(async move {
        let mut join: JoinSet<(usize, Duration)> = JoinSet::new();
        for (instance_idx, q) in queries_owned {
            let s = Arc::clone(&states[instance_idx]);
            let sem = Arc::clone(&semaphores[instance_idx]);
            join.spawn(async move {
                let _permit = sem.acquire_owned().await.expect("permit");
                let started_q = Instant::now();
                let _r: ServerResponse = tokio::task::spawn_blocking(move || {
                    <RavenInspireScheme as PirScheme>::respond(s.as_ref(), &q).expect("respond")
                })
                .await
                .expect("blocking");
                (instance_idx, started_q.elapsed())
            });
        }
        let mut buckets: Vec<Vec<Duration>> = (0..n_instances).map(|_| Vec::new()).collect();
        while let Some(joined) = join.join_next().await {
            let (idx, lat) = joined.expect("join");
            if let Some(bucket) = buckets.get_mut(idx) {
                bucket.push(lat);
            }
        }
        buckets
    });
    let elapsed = started.elapsed();
    (elapsed, per_instance_lat)
}

#[test]
#[ignore = "multi-instance setup is heavy (~7s x 6 = ~45s); ~120s total wall"]
fn multi_instance_throughput_at_production_cell() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("rt");
    let cores = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(8);
    eprintln!(
        "multi_instance_throughput: cores={cores} instances={NUM_INSTANCES} K={K_PER_INSTANCE} \
         total_queries={TOTAL_QUERIES}"
    );

    let params = InspireParams::secure_128_d2048();

    let setup_start = Instant::now();
    let instances: Vec<ReadyInstance> = (0..NUM_INSTANCES)
        .map(|i| {
            let started = Instant::now();
            let inst = build_ready_instance(&params, i);
            eprintln!(
                "multi_instance_throughput: instance {i} setup elapsed = {:?}",
                started.elapsed()
            );
            inst
        })
        .collect();
    eprintln!(
        "multi_instance_throughput: all-instance setup elapsed = {:?}",
        setup_start.elapsed()
    );

    let entries = 1u64 << ENTRIES_LOG2;
    let mut multi_queries: Vec<(usize, raven_inspire::SeededClientQuery)> =
        Vec::with_capacity(TOTAL_QUERIES);
    for k in 0..TOTAL_QUERIES as u64 {
        let instance_idx = (k * 911 % NUM_INSTANCES as u64) as usize;
        let inst = &instances[instance_idx];
        let target_idx = (k.wrapping_mul(7919) + 11) % entries;
        let (_cs, q) =
            build_seeded_query(&inst.client, inst.state.shard_config(), target_idx, &params)
                .expect("build_seeded_query");
        multi_queries.push((instance_idx, q));
    }

    // Reuse instances across seeds; state build (~45 s) dominates.
    let mut multi_walls: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut multi_qps_values: Vec<f64> = Vec::with_capacity(SEEDS);
    let mut last_per_instance_lat: Vec<Vec<Duration>> = Vec::new();
    for seed in 0..SEEDS {
        let (wall, lat) = dispatch_sweep(&rt, &instances, &multi_queries, K_PER_INSTANCE);
        let qps = TOTAL_QUERIES as f64 / wall.as_secs_f64();
        eprintln!(
            "multi_instance_throughput: seed={seed} 6-instance sweep wall={:?} qps={:.1}",
            wall, qps
        );
        multi_walls.push(wall);
        multi_qps_values.push(qps);
        last_per_instance_lat = lat;
    }
    let multi_wall = median_dur(&mut multi_walls.clone());
    let multi_qps = median_f64(&mut multi_qps_values.clone());
    eprintln!(
        "multi_instance_throughput: 3-seed-median 6-instance sweep wall={:?} qps={:.1} \
         (per-seed walls: {multi_walls:?})",
        multi_wall, multi_qps,
    );

    let mut all_lat: Vec<Duration> = last_per_instance_lat.iter().flatten().copied().collect();
    let agg = percentiles(&mut all_lat);
    eprintln!(
        "multi_instance_throughput: aggregate latency p50={:?} p95={:?} p99={:?} max={:?} n={}",
        agg.p50, agg.p95, agg.p99, agg.max, agg.n
    );
    for (i, mut bucket) in last_per_instance_lat.into_iter().enumerate() {
        let dist = percentiles(&mut bucket);
        eprintln!(
            "multi_instance_throughput: instance={i} latency p50={:?} p95={:?} p99={:?} max={:?} n={}",
            dist.p50, dist.p95, dist.p99, dist.max, dist.n
        );
    }

    let baseline_inst = instances.first().expect("at least one instance");
    let mut single_queries: Vec<(usize, raven_inspire::SeededClientQuery)> =
        Vec::with_capacity(TOTAL_QUERIES);
    for k in 0..TOTAL_QUERIES as u64 {
        let target_idx = (k.wrapping_mul(7919) + 11) % entries;
        let (_cs, q) = build_seeded_query(
            &baseline_inst.client,
            baseline_inst.state.shard_config(),
            target_idx,
            &params,
        )
        .expect("build_seeded_query");
        single_queries.push((0, q));
    }
    let single_slice = std::slice::from_ref(baseline_inst);
    let mut single_walls: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut single_qps_values: Vec<f64> = Vec::with_capacity(SEEDS);
    for seed in 0..SEEDS {
        let (wall, _) = dispatch_sweep(&rt, single_slice, &single_queries, K_PER_INSTANCE);
        let qps = TOTAL_QUERIES as f64 / wall.as_secs_f64();
        eprintln!(
            "multi_instance_throughput: seed={seed} single-instance K={K_PER_INSTANCE} \
             wall={:?} qps={:.1}",
            wall, qps
        );
        single_walls.push(wall);
        single_qps_values.push(qps);
    }
    let single_wall = median_dur(&mut single_walls.clone());
    let single_qps = median_f64(&mut single_qps_values.clone());

    eprintln!(
        "multi_instance_throughput: 3-seed-median single-instance K={K_PER_INSTANCE} \
         wall={:?} qps={:.1} (per-seed walls: {single_walls:?})",
        single_wall, single_qps
    );
    let speedup = single_wall.as_secs_f64() / multi_wall.as_secs_f64();
    eprintln!(
        "multi_instance_throughput: speedup_6_vs_1 = {:.2}x (qps {:.1} vs {:.1})",
        speedup, multi_qps, single_qps
    );

    append_findings_line("");
    append_findings_line(
        "## multi_instance_throughput_bench (production cell, K=4, 1000 queries, 3 seeds)",
    );
    append_findings_line("");
    append_findings_line(&format!(
        "- multi_instance | shape=`6 instances x K=4` | per-seed-walls={multi_walls:?} | \
         3-seed-median-wall={:.3}s | 3-seed-median-qps={multi_qps:.1}",
        multi_wall.as_secs_f64()
    ));
    append_findings_line(&format!(
        "- multi_instance | shape=`1 instance x K=4` | per-seed-walls={single_walls:?} | \
         3-seed-median-wall={:.3}s | 3-seed-median-qps={single_qps:.1}",
        single_wall.as_secs_f64()
    ));
    append_findings_line(&format!(
        "- multi_instance | speedup_6_vs_1={:.2}x | last-sweep aggregate p50={:?} p95={:?} \
         p99={:?} max={:?} n={}",
        speedup, agg.p50, agg.p95, agg.p99, agg.max, agg.n
    ));

    assert_eq!(agg.n, TOTAL_QUERIES, "all queries must be answered");
}
