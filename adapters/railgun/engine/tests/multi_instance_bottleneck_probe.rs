//! Multi-instance bottleneck probe (`#[ignore]`-gated).

#![allow(
    clippy::expect_used,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::uninlined_format_args,
    clippy::items_after_statements
)]

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
const TOTAL_QUERIES: usize = 240;
const SEEDS: usize = 3;

fn median_dur(values: &mut [Duration]) -> Duration {
    values.sort();
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
struct DispatchStats {
    wall: Duration,
    sum_respond_us: u128,
    n: usize,
}

impl DispatchStats {
    fn cpu_util(&self) -> f64 {
        let wall_us = self.wall.as_micros() as f64;
        if wall_us == 0.0 {
            0.0
        } else {
            (self.sum_respond_us as f64) / wall_us
        }
    }
}

fn dispatch_multi(
    rt: &tokio::runtime::Runtime,
    instances: &[ReadyInstance],
    queries: &[(usize, raven_inspire::SeededClientQuery)],
    k_per_instance: usize,
    pools: Option<&[Arc<rayon::ThreadPool>]>,
) -> DispatchStats {
    use tokio::sync::Semaphore;
    use tokio::task::JoinSet;

    let n_instances = instances.len();
    let semaphores: Vec<Arc<Semaphore>> = (0..n_instances)
        .map(|_| Arc::new(Semaphore::new(k_per_instance.max(1))))
        .collect();
    let states: Vec<Arc<InspireServerState>> =
        instances.iter().map(|i| Arc::clone(&i.state)).collect();
    let pools_owned: Option<Vec<Arc<rayon::ThreadPool>>> =
        pools.map(|p| p.iter().map(Arc::clone).collect());
    let queries_owned: Vec<(usize, raven_inspire::SeededClientQuery)> = queries.to_vec();

    let started = Instant::now();
    let total_respond_us: u128 = rt.block_on(async move {
        let mut join: JoinSet<u128> = JoinSet::new();
        for (instance_idx, q) in queries_owned {
            let s = Arc::clone(&states[instance_idx]);
            let sem = Arc::clone(&semaphores[instance_idx]);
            let pool = pools_owned.as_ref().map(|ps| Arc::clone(&ps[instance_idx]));
            join.spawn(async move {
                let _permit = sem.acquire_owned().await.expect("permit");
                let respond_us: u128 = tokio::task::spawn_blocking(move || {
                    let started_q = Instant::now();
                    if let Some(p) = pool {
                        p.install(|| {
                            let _ = <RavenInspireScheme as PirScheme>::respond(s.as_ref(), &q)
                                .expect("respond");
                        });
                    } else {
                        let _: ServerResponse =
                            <RavenInspireScheme as PirScheme>::respond(s.as_ref(), &q)
                                .expect("respond");
                    }
                    started_q.elapsed().as_micros()
                })
                .await
                .expect("blocking");
                respond_us
            });
        }
        let mut sum = 0u128;
        while let Some(joined) = join.join_next().await {
            sum = sum.saturating_add(joined.expect("join"));
        }
        sum
    });
    let wall = started.elapsed();
    DispatchStats {
        wall,
        sum_respond_us: total_respond_us,
        n: queries.len(),
    }
}

#[test]
#[ignore = "production-cell setup is heavy (~12s x 6 = ~72s); ~3 min total wall"]
fn multi_instance_bottleneck_probe() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("rt");
    let cores = std::thread::available_parallelism().map_or(8, std::num::NonZeroUsize::get);
    eprintln!(
        "BOTTLENECK_PROBE: cores={cores} instances={NUM_INSTANCES} K={K_PER_INSTANCE} \
         total_queries={TOTAL_QUERIES} seeds={SEEDS}"
    );
    eprintln!(
        "BOTTLENECK_PROBE: rayon::current_num_threads()={}",
        rayon::current_num_threads()
    );

    let params = InspireParams::secure_128_d2048();

    let setup_start = Instant::now();
    let instances: Vec<ReadyInstance> = (0..NUM_INSTANCES)
        .map(|i| {
            let s = Instant::now();
            let inst = build_ready_instance(&params, i);
            eprintln!(
                "BOTTLENECK_PROBE: instance {i} setup elapsed = {:?}",
                s.elapsed()
            );
            inst
        })
        .collect();
    eprintln!(
        "BOTTLENECK_PROBE: all-instance setup elapsed = {:?}",
        setup_start.elapsed()
    );

    let per_pool = (cores / NUM_INSTANCES).max(1);
    let dedicated_pools: Vec<Arc<rayon::ThreadPool>> = (0..NUM_INSTANCES)
        .map(|i| {
            Arc::new(
                rayon::ThreadPoolBuilder::new()
                    .num_threads(per_pool)
                    .thread_name(move |t| format!("ded-pool-{i}-{t}"))
                    .build()
                    .expect("pool"),
            )
        })
        .collect();
    eprintln!(
        "BOTTLENECK_PROBE: dedicated rayon pools per instance = {NUM_INSTANCES}, \
         per_pool_threads = {per_pool}"
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

    let single_inst_slice = std::slice::from_ref(&instances[0]);
    let mut single_queries: Vec<(usize, raven_inspire::SeededClientQuery)> =
        Vec::with_capacity(TOTAL_QUERIES);
    for k in 0..TOTAL_QUERIES as u64 {
        let target_idx = (k.wrapping_mul(7919) + 11) % entries;
        let (_cs, q) = build_seeded_query(
            &instances[0].client,
            instances[0].state.shard_config(),
            target_idx,
            &params,
        )
        .expect("build_seeded_query");
        single_queries.push((0, q));
    }

    eprintln!("BOTTLENECK_PROBE: corpus built; queries={TOTAL_QUERIES}");

    let single_pools_dummy: Vec<Arc<rayon::ThreadPool>> = vec![Arc::clone(&dedicated_pools[0])];

    type ConfigFn<'a> = Box<dyn Fn() -> DispatchStats + 'a>;
    let configs: Vec<(&str, ConfigFn<'_>)> = vec![
        (
            "single_K4_global_rayon",
            Box::new(|| {
                dispatch_multi(
                    &rt,
                    single_inst_slice,
                    &single_queries,
                    K_PER_INSTANCE,
                    None,
                )
            }) as Box<dyn Fn() -> DispatchStats + '_>,
        ),
        (
            "multi_K4_global_rayon",
            Box::new(|| dispatch_multi(&rt, &instances, &multi_queries, K_PER_INSTANCE, None)),
        ),
        (
            "multi_K4_dedicated_rayon",
            Box::new(|| {
                dispatch_multi(
                    &rt,
                    &instances,
                    &multi_queries,
                    K_PER_INSTANCE,
                    Some(&dedicated_pools),
                )
            }),
        ),
        (
            "single_K4_dedicated_rayon",
            Box::new(|| {
                dispatch_multi(
                    &rt,
                    single_inst_slice,
                    &single_queries,
                    K_PER_INSTANCE,
                    Some(&single_pools_dummy),
                )
            }),
        ),
    ];

    eprintln!("\nBOTTLENECK_PROBE: result table (3-seed median wall, qps, sum/wall ratio)");
    eprintln!(
        "{:<32}  {:>10}  {:>8}  {:>10}  {:>10}",
        "config", "med_wall_ms", "qps", "cpu_ratio", "med_per_q_us"
    );
    let mut rows: Vec<(String, Duration, f64, f64, u128)> = Vec::new();
    for (label, runner) in configs {
        let mut walls: Vec<Duration> = Vec::with_capacity(SEEDS);
        let mut ratios: Vec<f64> = Vec::with_capacity(SEEDS);
        let mut per_q: Vec<u128> = Vec::with_capacity(SEEDS);
        for seed in 0..SEEDS {
            let s = runner();
            let cpu = s.cpu_util();
            let pq = s.sum_respond_us / s.n.max(1) as u128;
            eprintln!(
                "  [{label}] seed={seed} wall={:?} sum_respond_ms={} cpu_ratio={:.2} \
                 mean_respond_us={}",
                s.wall,
                s.sum_respond_us / 1000,
                cpu,
                pq
            );
            walls.push(s.wall);
            ratios.push(cpu);
            per_q.push(pq);
        }
        let med_wall = median_dur(&mut walls.clone());
        ratios.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let med_ratio = ratios[ratios.len() / 2];
        per_q.sort_unstable();
        let med_per_q = per_q[per_q.len() / 2];
        let qps = TOTAL_QUERIES as f64 / med_wall.as_secs_f64();
        eprintln!(
            "{:<32}  {:>10.1}  {:>8.1}  {:>10.2}  {:>10}",
            label,
            med_wall.as_secs_f64() * 1000.0,
            qps,
            med_ratio,
            med_per_q,
        );
        rows.push((label.to_string(), med_wall, qps, med_ratio, med_per_q));
    }

    eprintln!("\nBOTTLENECK_PROBE: speedup analysis");
    let single_global = rows.iter().find(|r| r.0 == "single_K4_global_rayon");
    let multi_global = rows.iter().find(|r| r.0 == "multi_K4_global_rayon");
    let multi_ded = rows.iter().find(|r| r.0 == "multi_K4_dedicated_rayon");
    if let (Some(sg), Some(mg)) = (single_global, multi_global) {
        let speedup = sg.1.as_secs_f64() / mg.1.as_secs_f64();
        eprintln!(
            "  multi_global vs single_global: speedup = {:.2}x (qps {:.1} -> {:.1})",
            speedup, sg.2, mg.2
        );
    }
    if let (Some(sg), Some(md)) = (single_global, multi_ded) {
        let speedup = sg.1.as_secs_f64() / md.1.as_secs_f64();
        eprintln!(
            "  multi_dedicated vs single_global: speedup = {:.2}x (qps {:.1} -> {:.1})",
            speedup, sg.2, md.2
        );
    }
    if let (Some(mg), Some(md)) = (multi_global, multi_ded) {
        let delta = (md.1.as_secs_f64() / mg.1.as_secs_f64() - 1.0) * 100.0;
        eprintln!(
            "  multi_dedicated vs multi_global wall delta = {:+.1}% \
             (cpu_ratio multi_global={:.2}, multi_dedicated={:.2})",
            delta, mg.3, md.3
        );
    }
}
