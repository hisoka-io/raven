//! `raven-inspire` bench adapter. Emits a `BenchReport` JSON +
//! per-trial CSV. A round-trip must recover the planted plaintext
//! before any numbers are emitted.

#![allow(clippy::all)]

use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, InspireVariant, SecurityLevel, ShardConfig};
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::{
    extract_inspiring, extract_with_variant, query, respond_seeded_inspiring_cached_with_session,
    respond_with_variant, setup, ClientSession, EncodedDatabase, PackingMode,
    ServerInspiringCache, ServerSessionStore,
};

use raven_b1_bench::adaptive_params::{
    derive_medium_payload, fmt_derivation, AdaptiveInputs,
};
use raven_bench::{BenchReport, GridCell};

#[derive(Debug, Clone, Copy)]
struct RoundTrip {
    query_gen_us: u64,
    server_us: u64,
    extract_us: u64,
    total_us: u64,
    query_bytes: u64,
    response_bytes: u64,
}

fn round_trip(
    session: &ClientSession,
    server_cache: &ServerInspiringCache,
    session_store: &ServerSessionStore,
    encoded_db: &EncodedDatabase,
    sk: &RlweSecretKey,
    params: &InspireParams,
    variant: InspireVariant,
    idx: u64,
    entry_size: usize,
) -> (Vec<u8>, RoundTrip) {
    let crs = session.crs();
    let mut sampler = GaussianSampler::new(params.sigma);
    match variant {
        InspireVariant::TwoPacking => {
            let t0 = Instant::now();
            let (state, mut seeded_query) = session
                .query_seeded(idx, &encoded_db.config, &mut sampler)
                .expect("ClientSession::query_seeded");
            seeded_query.packing_mode = PackingMode::Inspiring;
            let t1 = Instant::now();
            let response = respond_seeded_inspiring_cached_with_session(
                crs,
                encoded_db,
                &seeded_query,
                server_cache,
                Some(session_store),
            )
            .expect("respond_seeded_inspiring_cached_with_session");
            let t2 = Instant::now();
            let decoded =
                extract_inspiring(crs, &state, &response, entry_size).expect("extract_inspiring");
            let t3 = Instant::now();
            let q_bytes = bincode::serialize(&seeded_query)
                .map(|v: Vec<u8>| v.len() as u64)
                .unwrap_or(0);
            let r_bytes = response
                .to_binary()
                .map(|v: Vec<u8>| v.len() as u64)
                .unwrap_or(0);
            (
                decoded,
                RoundTrip {
                    query_gen_us: micros_between(t0, t1),
                    server_us: micros_between(t1, t2),
                    extract_us: micros_between(t2, t3),
                    total_us: micros_between(t0, t3),
                    query_bytes: q_bytes,
                    response_bytes: r_bytes,
                },
            )
        }
        _ => {
            let t0 = Instant::now();
            let (state, q) =
                query(crs, idx, &encoded_db.config, sk, &mut sampler).expect("query");
            let t1 = Instant::now();
            let r = respond_with_variant(crs, encoded_db, &q, variant).expect("respond");
            let t2 = Instant::now();
            let decoded =
                extract_with_variant(crs, &state, &r, entry_size, variant).expect("extract");
            let t3 = Instant::now();
            let q_bytes = bincode::serialize(&q)
                .map(|v: Vec<u8>| v.len() as u64)
                .unwrap_or(0);
            let r_bytes = bincode::serialize(&r)
                .map(|v: Vec<u8>| v.len() as u64)
                .unwrap_or(0);
            (
                decoded,
                RoundTrip {
                    query_gen_us: micros_between(t0, t1),
                    server_us: micros_between(t1, t2),
                    extract_us: micros_between(t2, t3),
                    total_us: micros_between(t0, t3),
                    query_bytes: q_bytes,
                    response_bytes: r_bytes,
                },
            )
        }
    }
}

#[inline]
fn micros_between(start: Instant, end: Instant) -> u64 {
    u64::try_from(end.saturating_duration_since(start).as_micros()).unwrap_or(u64::MAX)
}

fn median_of(samples: &mut [u64]) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    samples.sort_unstable();
    samples[samples.len() / 2]
}

#[derive(Debug)]
struct CliArgs {
    entries_log2: u8,
    record_bytes: usize,
    warmup: u32,
    measured: u32,
    seeds: Vec<u64>,
    out_dir: PathBuf,
    smoke_only: bool,
    variant: InspireVariant,
    adaptive_params: Option<[usize; 3]>,
    derived_params_out: Option<PathBuf>,
    simulate_wire_format: bool,
    concurrent_queries: u32,
}

fn parse_variant(s: &str) -> InspireVariant {
    match s.to_ascii_lowercase().replace('-', "").replace('_', "").as_str() {
        "nopacking" => InspireVariant::NoPacking,
        "onepacking" => InspireVariant::OnePacking,
        "twopacking" => InspireVariant::TwoPacking,
        other => panic!(
            "unknown variant: {other:?} (expected no-packing | one-packing | two-packing)"
        ),
    }
}

fn variant_slug(v: InspireVariant) -> &'static str {
    match v {
        InspireVariant::NoPacking => "nopacking",
        InspireVariant::OnePacking => "onepacking",
        InspireVariant::TwoPacking => "twopacking-inspiring",
    }
}

fn parse_args() -> CliArgs {
    let mut args = std::env::args().skip(1);
    let mut cli = CliArgs {
        entries_log2: 15,
        record_bytes: 256,
        warmup: 4,
        measured: 16,
        seeds: vec![0],
        out_dir: PathBuf::from("./bench-results/inspire"),
        smoke_only: true,
        variant: InspireVariant::NoPacking,
        adaptive_params: None,
        derived_params_out: None,
        simulate_wire_format: false,
        concurrent_queries: 1,
    };
    while let Some(a) = args.next() {
        match a.as_str() {
            "--entries-log2" => cli.entries_log2 = args.next().unwrap().parse().unwrap(),
            "--record-bytes" => cli.record_bytes = args.next().unwrap().parse().unwrap(),
            "--warmup" => cli.warmup = args.next().unwrap().parse().unwrap(),
            "--measured" => cli.measured = args.next().unwrap().parse().unwrap(),
            "--seeds" => {
                cli.seeds = args
                    .next()
                    .unwrap()
                    .split(',')
                    .map(|s| s.parse().unwrap())
                    .collect();
            }
            "--out-dir" => cli.out_dir = PathBuf::from(args.next().unwrap()),
            "--adaptive-params" => {
                let spec = args.next().expect("--adaptive-params needs g0,g1,g2");
                let parts: Vec<usize> = spec
                    .split(',')
                    .map(|s| s.parse().expect("gamma values must be unsigned ints"))
                    .collect();
                assert_eq!(parts.len(), 3, "--adaptive-params expects 3 gamma values");
                cli.adaptive_params = Some([parts[0], parts[1], parts[2]]);
            }
            "--derived-params-out" => {
                cli.derived_params_out = Some(PathBuf::from(args.next().unwrap()));
            }
            "--full-bench" => cli.smoke_only = false,
            "--smoke-only" => cli.smoke_only = true,
            "--variant" => cli.variant = parse_variant(&args.next().unwrap()),
            "--simulate-wire-format" => cli.simulate_wire_format = true,
            "--concurrent-queries" => {
                let n: u32 = args
                    .next()
                    .expect("--concurrent-queries needs a positive integer")
                    .parse()
                    .expect("--concurrent-queries must be unsigned int");
                assert!(n >= 1, "--concurrent-queries must be >= 1");
                cli.concurrent_queries = n;
            }
            other => panic!("unknown arg: {other}"),
        }
    }
    cli
}

fn build_database(entries: u64, record_bytes: usize) -> Vec<u8> {
    let total_bytes = (entries as usize)
        .checked_mul(record_bytes)
        .expect("db size overflow");
    let mut db = vec![0u8; total_bytes];
    for i in 0..(entries as usize) {
        for j in 0..record_bytes {
            db[i * record_bytes + j] = ((i + j) % 251) as u8;
        }
    }
    db
}

fn expected_record(index: u64, record_bytes: usize) -> Vec<u8> {
    (0..record_bytes)
        .map(|j| (((index as usize) + j) % 251) as u8)
        .collect()
}

fn main() {
    let cli = parse_args();
    let cell = GridCell {
        entries_log2: cli.entries_log2,
        record_bytes: u32::try_from(cli.record_bytes).expect("record_bytes <= u32::MAX"),
    };
    let entries = cell.entries();

    eprintln!(
        "b1-inspire: cell = 2^{} x {} B ({} entries, {} MiB raw DB)",
        cell.entries_log2,
        cell.record_bytes,
        entries,
        (cell.raw_db_bytes() as f64) / (1024.0 * 1024.0)
    );
    eprintln!("rayon threads: {}", rayon::current_num_threads());

    let params = match &cli.adaptive_params {
        None => {
            eprintln!("params: DEFAULT_Q (q = 2^60 - 2^14 + 1, p = 65537, gadget = [2^20, 3])");
            InspireParams {
                ring_dim: 2048,
                q: 1_152_921_504_606_830_593,
                crt_moduli: vec![1_152_921_504_606_830_593],
                p: 65537,
                sigma: 6.4,
                gadget_base: 1 << 20,
                gadget_len: 3,
                security_level: SecurityLevel::Bits128,
            }
        }
        Some(gammas) => {
            let inputs = AdaptiveInputs {
                input_num_items: entries as usize,
                input_item_size_bits: cli.record_bytes * 8,
                gammas: *gammas,
                performance_factor: 1,
            };
            let derivation = derive_medium_payload(&inputs);
            let snapshot = fmt_derivation(&inputs, &derivation);
            eprintln!("{snapshot}");
            if let Some(path) = &cli.derived_params_out {
                if let Some(parent) = path.parent() {
                    create_dir_all(parent).expect("create derived-params-out parent dir");
                }
                File::create(path)
                    .and_then(|mut f| f.write_all(snapshot.as_bytes()))
                    .expect("write derived-params snapshot");
                eprintln!("derived-params snapshot written to {}", path.display());
            }
            InspireParams::for_scenario(entries as usize, cli.record_bytes, *gammas, 1)
                .expect("InspireParams::for_scenario failed")
        }
    };

    // shard_size_bytes is recomputed by upstream `setup()`; this
    // value is documentation only.
    let _shard_cfg_documentation_only: ShardConfig = ShardConfig {
        shard_size_bytes: (params.ring_dim as u64) * (cli.record_bytes as u64),
        entry_size_bytes: cli.record_bytes,
        total_entries: entries,
    };
    eprintln!("building synthetic database ...");
    let db = build_database(entries, cli.record_bytes);
    eprintln!("db bytes = {}", db.len());

    let setup_start = Instant::now();
    let mut setup_sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) = match setup(&params, &db, cli.record_bytes, &mut setup_sampler) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("inspire::setup failed: {e:?}");
            std::process::exit(2);
        }
    };
    let setup_elapsed = setup_start.elapsed();
    eprintln!("setup completed in {} ms", setup_elapsed.as_millis());

    let session_build_start = Instant::now();
    let mut session_sampler = GaussianSampler::new(params.sigma);
    let mut session =
        ClientSession::new(crs.clone(), sk.clone(), &mut session_sampler)
            .expect("ClientSession::new");
    eprintln!(
        "client session built in {} ms",
        session_build_start.elapsed().as_millis()
    );

    let server_cache_build_start = Instant::now();
    let server_cache = ServerInspiringCache::new(&crs, &encoded_db)
        .expect("ServerInspiringCache::new");
    eprintln!(
        "server cache built in {} ms",
        server_cache_build_start.elapsed().as_millis()
    );

    let session_store = ServerSessionStore::new();
    let handle = if cli.simulate_wire_format {
        eprintln!("wire-format simulation: dropping derived y_all + y_all_ntt pre-register");
        session
            .register_with_server_derivation(&session_store)
            .expect("ClientSession::register_with_server_derivation")
    } else {
        session
            .register_with(&session_store)
            .expect("ClientSession::register_with")
    };
    eprintln!(
        "session handshake: handle = {:?}, store size = {}",
        handle,
        session_store.len()
    );

    let n = entries.saturating_sub(1).max(1);
    let smoke_indices: [u64; 3] = [n / 4, n / 2, (3 * n) / 4];
    for &smoke_index in &smoke_indices {
        let (recovered, _rt) = round_trip(
            &session,
            &server_cache,
            &session_store,
            &encoded_db,
            &sk,
            &params,
            cli.variant,
            smoke_index,
            cli.record_bytes,
        );
        let expected = expected_record(smoke_index, cli.record_bytes);
        if recovered.as_slice() != expected.as_slice() {
            eprintln!(
                "CORRECTNESS FAILURE at index {smoke_index}: recovered {:?} ... expected {:?} ...",
                &recovered.iter().take(16).collect::<Vec<_>>(),
                &expected.iter().take(16).collect::<Vec<_>>()
            );
            std::process::exit(3);
        }
        eprintln!("smoke OK (index {smoke_index}, {} bytes match)", recovered.len());
    }

    if cli.smoke_only {
        eprintln!("smoke-only mode set; skipping bench loop.");
        return;
    }

    create_dir_all(&cli.out_dir).expect("create out dir");

    for &seed in &cli.seeds {
        let seed_dir = cli.out_dir.join(format!("seed-{seed}"));
        create_dir_all(&seed_dir).expect("create seed dir");

        let mut csv = File::create(seed_dir.join(format!(
            "cell-2e{}x{}.csv",
            cell.entries_log2, cell.record_bytes
        )))
        .expect("create csv");
        writeln!(
            csv,
            "trial_idx,query_idx,query_gen_us,server_us,extract_us,total_us,query_bytes,response_bytes"
        )
        .unwrap();

        let mut last_query_bytes = 0u64;
        let mut last_response_bytes = 0u64;
        let mut query_gen_times_us: Vec<u64> = Vec::new();
        let mut server_times_us: Vec<u64> = Vec::new();
        let mut extract_times_us: Vec<u64> = Vec::new();
        let mut total_times_us: Vec<u64> = Vec::new();

        let bench_total = cli.warmup + cli.measured;

        let concurrent_wall_start = Instant::now();
        let trials_completed: Vec<(u64, u64, RoundTrip)> = if cli.concurrent_queries <= 1 {
            let mut trials = Vec::with_capacity(bench_total as usize);
            for i in 0..bench_total {
                let trial = u64::from(i);
                let mut h = seed.wrapping_add(trial);
                h = (h ^ (h >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                h = (h ^ (h >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                h ^= h >> 31;
                let idx = h % entries;
                let (_decoded, rt) = round_trip(
                    &session, &server_cache, &session_store, &encoded_db, &sk,
                    &params, cli.variant, idx, cli.record_bytes,
                );
                trials.push((trial, idx, rt));
            }
            trials
        } else {
            let k = cli.concurrent_queries as usize;
            let per_thread = (bench_total as usize).div_ceil(k);
            let trials_per_thread: Vec<Vec<(u64, u64, RoundTrip)>> = std::thread::scope(|s| {
                let mut handles = Vec::with_capacity(k);
                for tid in 0..k {
                    let session_ref = &session;
                    let server_cache_ref = &server_cache;
                    let session_store_ref = &session_store;
                    let encoded_db_ref = &encoded_db;
                    let sk_ref = &sk;
                    let params_ref = &params;
                    let variant = cli.variant;
                    let record_bytes = cli.record_bytes;
                    let handle = s.spawn(move || {
                        let start = tid * per_thread;
                        let end = ((tid + 1) * per_thread).min(bench_total as usize);
                        let mut local = Vec::with_capacity(end - start);
                        for i in start..end {
                            let trial = i as u64;
                            let mut h = seed.wrapping_add(trial);
                            h = (h ^ (h >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                            h = (h ^ (h >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                            h ^= h >> 31;
                            let idx = h % entries;
                            let (_decoded, rt) = round_trip(
                                session_ref, server_cache_ref, session_store_ref,
                                encoded_db_ref, sk_ref, params_ref, variant,
                                idx, record_bytes,
                            );
                            local.push((trial, idx, rt));
                        }
                        local
                    });
                    handles.push(handle);
                }
                handles.into_iter().map(|h| h.join().expect("thread panic")).collect()
            });
            trials_per_thread.into_iter().flatten().collect()
        };
        let concurrent_wall_us =
            u64::try_from(concurrent_wall_start.elapsed().as_micros()).unwrap_or(u64::MAX);

        for (trial, idx, rt) in &trials_completed {
            last_query_bytes = rt.query_bytes;
            last_response_bytes = rt.response_bytes;

            writeln!(
                csv,
                "{trial},{idx},{},{},{},{},{},{}",
                rt.query_gen_us,
                rt.server_us,
                rt.extract_us,
                rt.total_us,
                rt.query_bytes,
                rt.response_bytes
            )
            .unwrap();

            if *trial >= u64::from(cli.warmup) {
                query_gen_times_us.push(rt.query_gen_us);
                server_times_us.push(rt.server_us);
                extract_times_us.push(rt.extract_us);
                total_times_us.push(rt.total_us);
            }
        }

        let query_gen_median_us = median_of(&mut query_gen_times_us);
        let server_median_us = median_of(&mut server_times_us);
        let extract_median_us = median_of(&mut extract_times_us);
        let total_median_us = median_of(&mut total_times_us);

        // Throughput modes: K=1 reports per-core sustained
        // (sum-of-per-trial); K>1 reports concurrent-wall.
        let measured_secs_sum = total_times_us.iter().map(|&x| x as u128).sum::<u128>() as f64
            / 1_000_000.0;
        let throughput_serial = if measured_secs_sum > 0.0 {
            total_times_us.len() as f64 / measured_secs_sum
        } else {
            0.0
        };
        let total_trials = trials_completed.len() as f64;
        let measured_trials = total_times_us.len() as f64;
        let concurrent_wall_secs = concurrent_wall_us as f64 / 1_000_000.0;
        let measured_wall_secs = if total_trials > 0.0 {
            concurrent_wall_secs * (measured_trials / total_trials)
        } else {
            0.0
        };
        let throughput_concurrent = if measured_wall_secs > 0.0 {
            measured_trials / measured_wall_secs
        } else {
            0.0
        };
        let throughput = if cli.concurrent_queries > 1 {
            throughput_concurrent
        } else {
            throughput_serial
        };

        if cli.concurrent_queries > 1 {
            eprintln!(
                "seed {seed}: K={} concurrent; serial qps {:.3}, concurrent-wall qps {:.3}, speedup {:.2}x",
                cli.concurrent_queries,
                throughput_serial,
                throughput_concurrent,
                throughput_concurrent / throughput_serial.max(1e-9)
            );
        }

        let preset_slug = match &cli.adaptive_params {
            None => "default-q".to_owned(),
            Some([g0, g1, g2]) => format!("adaptive-g{g0}-{g1}-{g2}"),
        };
        let opt_slug = "commit-e-handshake-solinas";
        let report = BenchReport {
            scheme: format!(
                "inspire-{preset_slug}-{}-{opt_slug}",
                variant_slug(cli.variant)
            ),
            cell,
            setup_ms: setup_elapsed.as_secs_f64() * 1000.0,
            hint_bytes: 0,
            query_bytes: last_query_bytes,
            response_bytes: last_response_bytes,
            query_ms_median: total_median_us as f64 / 1000.0,
            server_ms_median: Some(server_median_us as f64 / 1000.0),
            client_ms_median: Some(
                (query_gen_median_us + extract_median_us) as f64 / 1000.0,
            ),
            throughput_qps_per_core: throughput,
            measured_queries: total_times_us.len() as u64,
        };

        let json = serde_json::to_string_pretty(&report).expect("serialize");
        File::create(seed_dir.join(format!(
            "cell-2e{}x{}.json",
            cell.entries_log2, cell.record_bytes
        )))
        .expect("create json")
        .write_all(json.as_bytes())
        .expect("write json");

        eprintln!(
            "seed {seed}: total {:.3} ms (query_gen {:.3} + server {:.3} + extract {:.3}), {} qps, q={} B, r={} B",
            report.query_ms_median,
            report.client_ms_median.unwrap_or(0.0).max(0.0) - extract_median_us as f64 / 1000.0,
            report.server_ms_median.unwrap_or(0.0),
            extract_median_us as f64 / 1000.0,
            report.throughput_qps_per_core,
            last_query_bytes,
            last_response_bytes
        );
    }
}
