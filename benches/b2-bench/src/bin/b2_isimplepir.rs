//! `raven-isimplepir` bench runner. Setup once per cell, 3 seeds
//! per measurement, split timing, per-trial CSV + per-seed JSON.
//! Every query verifies against the synthetic DB; mismatch panics.

use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use raven_bench::{BenchReport, GridCell};
use raven_isimplepir::{
    extract, for_cell, query, respond, respond_packed, setup, setup_owned, squish_db, ClientHint,
    ClientQuery, ClientState, LweParams, ServerResponse, ServerState, SetupOutput,
    SquishedDatabase,
};

#[derive(Debug, Clone, Copy)]
struct RoundTrip {
    query_gen_us: u64,
    server_us: u64,
    extract_us: u64,
    total_us: u64,
    query_bytes: u64,
    response_bytes: u64,
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

// Deterministic synthetic DB: `byte = ((i + j) % 251) as u8`.
// 251 is prime so no aliasing with power-of-two record sizes;
// computing on-the-fly avoids materializing the raw byte DB.
#[inline]
fn raw_byte(entry_idx: usize, byte_offset: usize) -> u8 {
    ((entry_idx + byte_offset) % 251) as u8
}

#[inline]
fn raw_bit(bit_idx: usize, record_bytes: usize) -> u8 {
    let byte_idx = bit_idx / 8;
    let bit_in_byte = bit_idx % 8;
    let i = byte_idx / record_bytes;
    let j = byte_idx % record_bytes;
    (raw_byte(i, j) >> bit_in_byte) & 1
}

fn pack_plaintext(entries: u64, record_bytes: usize, params: &LweParams) -> Vec<u32> {
    let total_cells = params.l.saturating_mul(params.m);
    let mut out = vec![0u32; total_cells];
    let bits = params.bits_per_element as usize;
    if bits == 0 {
        return out;
    }
    let mask: u32 = (1u64 << bits).saturating_sub(1) as u32;
    let total_src_bits = (entries as usize)
        .saturating_mul(record_bytes)
        .saturating_mul(8);
    let mut src_bit = 0usize;
    for slot in out.iter_mut() {
        if src_bit >= total_src_bits {
            break;
        }
        let mut value: u32 = 0;
        for b in 0..bits {
            if src_bit >= total_src_bits {
                break;
            }
            value |= u32::from(raw_bit(src_bit, record_bytes)) << b;
            src_bit += 1;
        }
        *slot = value & mask;
        if *slot >= params.p {
            *slot %= params.p;
        }
    }
    out
}

fn expected_cell_value(
    cell_idx: usize,
    entries: u64,
    record_bytes: usize,
    params: &LweParams,
) -> u32 {
    let bits = params.bits_per_element as usize;
    let start_bit = cell_idx.saturating_mul(bits);
    let total_src_bits = (entries as usize)
        .saturating_mul(record_bytes)
        .saturating_mul(8);
    let mut value: u32 = 0;
    for b in 0..bits {
        let src_bit = start_bit + b;
        if src_bit >= total_src_bits {
            break;
        }
        value |= u32::from(raw_bit(src_bit, record_bytes)) << b;
    }
    let mask: u32 = (1u64 << bits).saturating_sub(1) as u32;
    let clamped = value & mask;
    if clamped >= params.p {
        clamped % params.p
    } else {
        clamped
    }
}

enum ServerHandle {
    Unsquished(ServerState),
    Squished {
        packed: SquishedDatabase,
        a_seed: [u8; 32],
        params: LweParams,
    },
}

impl ServerHandle {
    fn a_seed(&self) -> &[u8; 32] {
        match self {
            Self::Unsquished(s) => &s.a_seed,
            Self::Squished { a_seed, .. } => a_seed,
        }
    }

    fn params(&self) -> &LweParams {
        match self {
            Self::Unsquished(s) => &s.params,
            Self::Squished { params, .. } => params,
        }
    }
}

fn round_trip<R: RngCore>(
    rng: &mut R,
    hint: &ClientHint,
    server: &ServerHandle,
    cell_idx: usize,
) -> (u32, RoundTrip) {
    let params = server.params();
    let t0 = Instant::now();
    let (state, q): (ClientState, ClientQuery) =
        query(rng, server.a_seed(), params, cell_idx).expect("query");
    let t1 = Instant::now();
    let response: ServerResponse = match server {
        ServerHandle::Unsquished(s) => respond(s, &q.query).expect("respond"),
        ServerHandle::Squished { packed, .. } => {
            respond_packed(packed, &q.query).expect("respond_packed")
        }
    };
    let t2 = Instant::now();
    let decoded = extract(params, hint, &state, &response).expect("extract");
    let t3 = Instant::now();

    let q_bytes = bincode::serialize(&q).map(|v| v.len() as u64).unwrap_or(0);
    let r_bytes = bincode::serialize(&response)
        .map(|v| v.len() as u64)
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

#[derive(Debug)]
struct CliArgs {
    entries_log2: u8,
    record_bytes: usize,
    warmup: u32,
    measured: u32,
    seeds: Vec<u64>,
    out_dir: PathBuf,
    smoke_only: bool,
    /// Use `setup_owned` (moves the DB; halves peak memory at
    /// large cells). Default on.
    use_setup_owned: bool,
    /// Squish `ServerState.db` post-setup and use `respond_packed`.
    /// Requires `p <= 1024`. Off by default.
    use_squish: bool,
}

fn parse_args() -> CliArgs {
    let mut args = std::env::args().skip(1);
    let mut cli = CliArgs {
        entries_log2: 10,
        record_bytes: 8,
        warmup: 4,
        measured: 16,
        seeds: vec![0],
        out_dir: PathBuf::from("./bench-results/isimplepir"),
        smoke_only: true,
        use_setup_owned: true,
        use_squish: false,
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
            "--full-bench" => cli.smoke_only = false,
            "--smoke-only" => cli.smoke_only = true,
            "--use-setup-owned" => cli.use_setup_owned = true,
            "--no-setup-owned" => cli.use_setup_owned = false,
            "--use-squish" => cli.use_squish = true,
            other => panic!("unknown arg: {other}"),
        }
    }
    cli
}

fn main() {
    let cli = parse_args();
    let cell = GridCell {
        entries_log2: cli.entries_log2,
        record_bytes: u32::try_from(cli.record_bytes).expect("record_bytes <= u32::MAX"),
    };
    let entries = cell.entries();

    eprintln!(
        "b2-isimplepir: cell = 2^{} x {} B ({} entries, {:.2} MiB raw DB)",
        cell.entries_log2,
        cell.record_bytes,
        entries,
        (cell.raw_db_bytes() as f64) / (1024.0 * 1024.0)
    );
    eprintln!("rayon threads: {}", rayon::current_num_threads());

    let params = for_cell(entries, cli.record_bytes).expect("for_cell");
    eprintln!(
        "params: n = {}, log2_q = {}, p = {}, L = {}, M = {}, bits_per_element = {}",
        params.n, params.log2_q, params.p, params.l, params.m, params.bits_per_element
    );
    params.validate().expect("params validate");

    eprintln!("packing synthetic database into L*M cells ...");
    let packed = pack_plaintext(entries, cli.record_bytes, &params);
    eprintln!(
        "packed db cells = {} ({} u32s = {:.2} MiB)",
        packed.len(),
        packed.len(),
        (packed.len() * 4) as f64 / (1024.0 * 1024.0)
    );

    // Fixed `a_seed` so reruns are reproducible; per-seed query
    // RNG varies across the 3 seeds.
    let a_seed = [0u8; 32];

    let setup_start = Instant::now();
    let out: SetupOutput = if cli.use_setup_owned {
        setup_owned(packed, params, Some(a_seed)).expect("setup_owned")
    } else {
        setup(&packed, params, Some(a_seed)).expect("setup")
    };
    let setup_elapsed = setup_start.elapsed();
    eprintln!(
        "setup completed in {:.3} ms (hint: L*n = {}*{} = {} u32s = {:.2} MiB)",
        setup_elapsed.as_secs_f64() * 1000.0,
        out.hint.l,
        out.hint.n,
        out.hint.data.len(),
        (out.hint.data.len() * 4) as f64 / (1024.0 * 1024.0),
    );

    let hint_bytes_on_wire: u64 = bincode::serialize(&out.hint)
        .map(|v| v.len() as u64)
        .unwrap_or(0);
    eprintln!("hint wire bytes = {hint_bytes_on_wire}");

    let hint = out.hint;

    let server = if cli.use_squish {
        eprintln!("squish path: compressing ServerState.db ...");
        let squish_start = Instant::now();
        let packed_db = squish_db(&out.server.db, &out.server.params).expect("squish_db");
        eprintln!(
            "squish completed in {:.3} ms ({:.2}x reduction)",
            squish_start.elapsed().as_secs_f64() * 1000.0,
            (out.server.db.len() as f64) / (packed_db.data.len() as f64),
        );
        let a_seed_owned = out.server.a_seed;
        let params_owned = out.server.params;
        // Drop the unsquished DB so its allocation returns before queries.
        drop(out.server);
        ServerHandle::Squished {
            packed: packed_db,
            a_seed: a_seed_owned,
            params: params_owned,
        }
    } else {
        ServerHandle::Unsquished(out.server)
    };

    {
        let mut smoke_rng = ChaCha20Rng::from_seed([0u8; 32]);
        let expected_cell = (entries / 2) as usize;
        let expected = expected_cell_value(expected_cell, entries, cli.record_bytes, &params);
        let (decoded, _rt) = round_trip(&mut smoke_rng, &hint, &server, expected_cell);
        if decoded != expected {
            panic!("smoke fail at cell {expected_cell}: expected {expected}, got {decoded}");
        }
        eprintln!("smoke PASS at cell {expected_cell}");
    }

    if cli.smoke_only {
        eprintln!("smoke_only=true; skipping measured phase.");
        return;
    }

    for &seed in &cli.seeds {
        eprintln!("--- seed {seed} ---");
        let seed_dir = cli.out_dir.join(format!("seed-{seed}"));
        create_dir_all(&seed_dir).expect("create seed dir");

        let mut csv = File::create(seed_dir.join(format!(
            "cell-2e{}x{}.csv",
            cell.entries_log2, cell.record_bytes
        )))
        .expect("create csv");
        writeln!(
            csv,
            "trial_idx,cell_idx,query_gen_us,server_us,extract_us,total_us,query_bytes,response_bytes"
        )
        .unwrap();

        let mut rng = ChaCha20Rng::from_seed({
            let mut s = [0u8; 32];
            s[..8].copy_from_slice(&seed.to_le_bytes());
            s
        });

        let mut query_gen_us: Vec<u64> = Vec::new();
        let mut server_us_vec: Vec<u64> = Vec::new();
        let mut extract_us_vec: Vec<u64> = Vec::new();
        let mut total_us_vec: Vec<u64> = Vec::new();
        let mut last_query_bytes = 0u64;
        let mut last_response_bytes = 0u64;
        let bench_total = cli.warmup + cli.measured;

        let cell_space = params.l.saturating_mul(params.m) as u64;

        let bench_start = Instant::now();
        for i in 0..bench_total {
            let trial = u64::from(i);
            // SplitMix64 mixer; reproducible per seed.
            let mut h = seed.wrapping_add(trial);
            h = (h ^ (h >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            h = (h ^ (h >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            h ^= h >> 31;
            let cell_idx = (h % cell_space) as usize;

            let expected = expected_cell_value(cell_idx, entries, cli.record_bytes, &params);
            let (decoded, rt) = round_trip(&mut rng, &hint, &server, cell_idx);
            if decoded != expected {
                panic!(
                    "correctness fail at trial {trial} cell {cell_idx}: expected {expected}, got {decoded}"
                );
            }

            last_query_bytes = rt.query_bytes;
            last_response_bytes = rt.response_bytes;

            writeln!(
                csv,
                "{trial},{cell_idx},{},{},{},{},{},{}",
                rt.query_gen_us,
                rt.server_us,
                rt.extract_us,
                rt.total_us,
                rt.query_bytes,
                rt.response_bytes
            )
            .unwrap();

            if trial >= u64::from(cli.warmup) {
                query_gen_us.push(rt.query_gen_us);
                server_us_vec.push(rt.server_us);
                extract_us_vec.push(rt.extract_us);
                total_us_vec.push(rt.total_us);
            }
        }
        let bench_wall = bench_start.elapsed();

        let query_gen_median_us = median_of(&mut query_gen_us);
        let server_median_us = median_of(&mut server_us_vec);
        let extract_median_us = median_of(&mut extract_us_vec);
        let total_median_us = median_of(&mut total_us_vec);

        let measured_secs =
            total_us_vec.iter().map(|&x| x as u128).sum::<u128>() as f64 / 1_000_000.0;
        let throughput = if measured_secs > 0.0 {
            total_us_vec.len() as f64 / measured_secs
        } else {
            0.0
        };

        let scheme_tag = match (cli.use_setup_owned, cli.use_squish) {
            (false, false) => "isimplepir-default-q-baseline",
            (true, false) => "isimplepir-default-q-setup-owned",
            (false, true) => "isimplepir-default-q-squish",
            (true, true) => "isimplepir-default-q-setup-owned-squish",
        };
        let report = BenchReport {
            scheme: scheme_tag.to_owned(),
            cell,
            setup_ms: setup_elapsed.as_secs_f64() * 1000.0,
            hint_bytes: hint_bytes_on_wire,
            query_bytes: last_query_bytes,
            response_bytes: last_response_bytes,
            query_ms_median: total_median_us as f64 / 1000.0,
            server_ms_median: Some(server_median_us as f64 / 1000.0),
            client_ms_median: Some((query_gen_median_us + extract_median_us) as f64 / 1000.0),
            throughput_qps_per_core: throughput,
            measured_queries: total_us_vec.len() as u64,
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
            "seed {seed}: total {:.3} ms (query_gen {:.3} + server {:.3} + extract {:.3}), {:.2} qps, q={} B, r={} B; bench-wall {:.2} s",
            report.query_ms_median,
            query_gen_median_us as f64 / 1000.0,
            report.server_ms_median.unwrap_or(0.0),
            extract_median_us as f64 / 1000.0,
            report.throughput_qps_per_core,
            last_query_bytes,
            last_response_bytes,
            bench_wall.as_secs_f64(),
        );
    }
}
