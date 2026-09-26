//! Served-query latency and stage split at the deployed cell (512 B rows, 2048 a shard),
//! and a cross-build check that the kernel a build links cannot change response bytes.
//! Artifacts stamp the build as read from the build, never from a config file. Gated.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    reason = "benchmark fixtures abort on invalid setup before measuring"
)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use raven_inspire::math::mod_q::DEFAULT_Q;
use raven_inspire::math::Poly;
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::pir::mod_switch::mod_switch_response_checked;
use raven_inspire::{
    respond_seeded_inspiring_cached_with_session, ClientSession, ClientState, SeededClientQuery,
    ServerResponse,
};
use raven_railgun_engine::inspire::{
    build_client_session, build_seeded_query, extract_response, register_client_session,
    restore_inspire_state, setup_state, snapshot_inspire_state, InspireServerState,
    RavenInspireScheme, WIRE_RESPONSE_MODULUS,
};
use raven_railgun_engine::PirScheme;
use serde_json::{json, Value};

const ENTRY_BYTES: usize = 512;
const ROWS_PER_SHARD: u64 = 2048;
const DB_ROWS_LOG2: usize = 16;
const QUERY_POOL: usize = 64;
const DEFAULT_WARMUP: usize = 20;
const DEFAULT_SAMPLES: usize = 1000;
const MIN_SAMPLES: usize = 200;
const REPLAY_QUERIES: usize = 8;
const PROBE_BATCHES: usize = 400;
const PROBE_CALLS_PER_BATCH: u32 = 64;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).map_or(default, |v| {
        v.parse()
            .unwrap_or_else(|_| panic!("{name}={v} is not a count"))
    })
}

fn findings_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("RAVEN_BENCH_FINDINGS_DIR") {
        return PathBuf::from(dir);
    }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.pop();
    p.push("target");
    p.push("bench-findings");
    p
}

fn write_artifact(name: &str, value: &Value) {
    let dir = findings_dir();
    std::fs::create_dir_all(&dir).expect("findings dir");
    let path = dir.join(name);
    let body = serde_json::to_string_pretty(value).expect("serialize artifact");
    std::fs::write(&path, body).expect("write artifact");
    eprintln!("served_respond: wrote {}", path.display());
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn load_average() -> String {
    std::fs::read_to_string("/proc/loadavg").map_or_else(
        |_| "unknown".to_owned(),
        |s| s.split_whitespace().take(3).collect::<Vec<_>>().join(" "),
    )
}

fn cpu_model() -> String {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|info| {
            info.lines()
                .find_map(|l| l.strip_prefix("model name"))
                .and_then(|rest| rest.split_once(':'))
                .map(|(_, m)| m.split_whitespace().collect::<Vec<_>>().join(" "))
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

fn host_has_avx512ifma() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("avx512f") && std::is_x86_feature_detected!("avx512ifma")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|r| r.trim().to_owned())
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// The CPUID hypervisor bit as the kernel reports it. `None` where cpuinfo has no x86 flags
/// line, so a platform that cannot say is never read as bare metal.
fn under_hypervisor() -> Option<bool> {
    let info = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    let flags = info.lines().find_map(|l| l.strip_prefix("flags"))?;
    Some(flags.split_whitespace().any(|f| f == "hypervisor"))
}

fn host() -> Value {
    json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "kernel_release": kernel_release(),
        "hypervisor": under_hypervisor(),
        "cpu": cpu_model(),
        "logical_cpus": std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get),
        "avx512ifma": host_has_avx512ifma(),
    })
}

/// Cargo's precedence: the encoded variable, then `RUSTFLAGS`, then config. Config-file
/// flags never reach the compiler's environment, so that case names its source and leaves
/// the effect to `target_features`. Same contract as the root bench crate's stamp: a set
/// but empty variable reads `none`, never a blank.
fn rustflags(encoded: Option<&str>, plain: Option<&str>) -> (&'static str, String) {
    let (source, flags) = match (encoded, plain) {
        (Some(e), _) => (
            "CARGO_ENCODED_RUSTFLAGS",
            e.split('\u{1f}')
                .filter(|f| !f.is_empty())
                .collect::<Vec<_>>()
                .join(" "),
        ),
        (None, Some(p)) => (
            "RUSTFLAGS",
            p.split_whitespace().collect::<Vec<_>>().join(" "),
        ),
        (None, None) => return ("config-or-none", "unknown".to_owned()),
    };
    if flags.is_empty() {
        (source, "none".to_owned())
    } else {
        (source, flags)
    }
}

macro_rules! compiled_target_features {
    ($($feature:literal),* $(,)?) => {{
        let mut on: Vec<&'static str> = Vec::new();
        $(if cfg!(target_feature = $feature) { on.push($feature); })*
        on
    }};
}

fn target_features() -> Vec<&'static str> {
    compiled_target_features!(
        "sse4.2",
        "popcnt",
        "avx",
        "avx2",
        "fma",
        "bmi2",
        "adx",
        "avx512f",
        "avx512vl",
        "avx512ifma",
        "neon",
        "sve",
    )
}

/// The directory this executable runs from, past `deps/` or `examples/`. It names the
/// cargo profile only when the binary runs where cargo wrote it; a copy reports where it
/// was copied to.
fn profile_dir() -> String {
    let exe = std::env::current_exe().ok();
    let mut dir = exe.as_deref().and_then(Path::parent);
    if dir
        .and_then(Path::file_name)
        .is_some_and(|n| n == "deps" || n == "examples")
    {
        dir = dir.and_then(Path::parent);
    }
    dir.and_then(Path::file_name).map_or_else(
        || "unknown".to_owned(),
        |n| n.to_string_lossy().into_owned(),
    )
}

fn read_u16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn read_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn read_u64(b: &[u8], at: usize) -> Option<usize> {
    usize::try_from(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?)).ok()
}

/// Which of `needles` appear in this executable's ELF symbol-name table. `None` when there
/// is no table to read, so a stripped binary never reports a symbol as absent.
fn linked_symbols(needles: &[&str]) -> Option<Vec<bool>> {
    const SHT_SYMTAB: u32 = 2;
    let exe = std::fs::read(std::env::current_exe().ok()?).ok()?;
    if exe.get(..6)? != b"\x7fELF\x02\x01" {
        return None;
    }
    let sh_off = read_u64(&exe, 0x28)?;
    let sh_size = usize::from(read_u16(&exe, 0x3A)?);
    let sh_count = usize::from(read_u16(&exe, 0x3C)?);
    let header = |i: usize| sh_off.checked_add(i.checked_mul(sh_size)?);
    let symtab = (0..sh_count)
        .filter_map(&header)
        .find(|&h| read_u32(&exe, h + 4) == Some(SHT_SYMTAB))?;
    let strtab = header(usize::try_from(read_u32(&exe, symtab + 40)?).ok()?)?;
    let start = read_u64(&exe, strtab + 24)?;
    let names = exe.get(start..start.checked_add(read_u64(&exe, strtab + 32)?)?)?;
    Some(
        needles
            .iter()
            .map(|n| names.windows(n.len()).any(|w| w == n.as_bytes()))
            .collect(),
    )
}

/// The kernel is read as absent only when a symbol every served build links is present.
fn ifma_kernel_linked() -> Option<bool> {
    match linked_symbols(&[
        "respond_seeded_inspiring_cached_with_session",
        "solinas_mont_mul_acc_x8",
    ])?
    .as_slice()
    {
        [true, kernel] => Some(*kernel),
        _ => None,
    }
}

fn build() -> Value {
    let (source, flags) = rustflags(
        option_env!("CARGO_ENCODED_RUSTFLAGS"),
        option_env!("RUSTFLAGS"),
    );
    let exe = std::env::current_exe().ok();
    json!({
        "executable": exe.as_deref().and_then(Path::file_name).map(|n| n.to_string_lossy()),
        "profile_dir": profile_dir(),
        "debug_assertions": cfg!(debug_assertions),
        "rustflags_source": source,
        "rustflags": flags,
        "target_features": target_features(),
        "ifma_kernel_linked": ifma_kernel_linked(),
    })
}

/// Static half of the dispatch gate in `Poly::mul_acc_ntt_domain`; CPUID is the other half.
fn ifma_dispatch_preconditions(params: &InspireParams) -> bool {
    params.moduli() == [DEFAULT_Q] && params.ring_dim.is_multiple_of(8)
}

fn synthetic_db(rows: usize) -> Vec<u8> {
    (0..rows)
        .flat_map(|i| (0..ENTRY_BYTES).map(move |j| ((i * 31 + j * 17) % 251) as u8))
        .collect()
}

fn row(db: &[u8], index: u64) -> &[u8] {
    let start = usize::try_from(index).expect("index") * ENTRY_BYTES;
    db.get(start..start + ENTRY_BYTES).expect("row in range")
}

struct Fixture {
    params: InspireParams,
    db: Vec<u8>,
    state: InspireServerState,
    client: ClientSession,
}

fn fixture(rows: usize, register: bool) -> Fixture {
    let params = InspireParams::secure_128_d2048();
    let db = synthetic_db(rows);
    let started = Instant::now();
    let (state, sk) =
        setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("setup_state");
    assert_eq!(
        state.shard_config().entries_per_shard(),
        ROWS_PER_SHARD,
        "not the deployed cell"
    );
    let mut client =
        build_client_session((*state.crs).clone(), sk, &params).expect("client session");
    if register {
        register_client_session(&mut client, &state).expect("register session");
    }
    eprintln!("served_respond: setup {:?}", started.elapsed());
    Fixture {
        params,
        db,
        state,
        client,
    }
}

/// One query per shard in turn, at a different row each time round.
fn query_pool(f: &Fixture, size: usize) -> Vec<(u64, ClientState, SeededClientQuery)> {
    let rows = f.db.len() / ENTRY_BYTES;
    let shards = (rows as u64).div_ceil(ROWS_PER_SHARD);
    (0..size as u64)
        .map(|i| {
            let index = (i % shards) * ROWS_PER_SHARD + (i * 37 + 5) % ROWS_PER_SHARD;
            let (cs, q) = build_seeded_query(&f.client, f.state.shard_config(), index, &f.params)
                .expect("build_seeded_query");
            (index, cs, q)
        })
        .collect()
}

fn served(state: &InspireServerState, q: &SeededClientQuery) -> ServerResponse {
    <RavenInspireScheme as PirScheme>::respond(state, q).expect("respond")
}

fn response_bytes(r: &ServerResponse) -> Vec<u8> {
    bincode::serialize(r).expect("serialize response")
}

fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

/// Nearest-rank percentiles. `p99` is withheld when its rank is the maximum's, so a
/// small run cannot report its slowest sample as a p99.
fn summarize(samples: &[u64], unit: &str) -> Value {
    let mut s = samples.to_vec();
    s.sort_unstable();
    let n = s.len();
    let rank = |permille: usize| (permille * n).div_ceil(1000).max(1);
    let at = |permille: usize| s.get(rank(permille) - 1).copied();
    let p99_rank = rank(990);
    let mut out = serde_json::Map::new();
    out.insert("n".to_owned(), json!(n));
    for (key, value) in [
        ("min", s.first().copied()),
        ("p50", at(500)),
        ("p95", at(950)),
        ("p99", if p99_rank < n { at(990) } else { None }),
        ("max", s.last().copied()),
    ] {
        out.insert(format!("{key}_{unit}"), json!(value));
    }
    out.insert("p99_rank".to_owned(), json!(p99_rank));
    let mean = if n == 0 {
        0.0
    } else {
        s.iter().sum::<u64>() as f64 / n as f64
    };
    out.insert(format!("mean_{unit}"), json!(mean));
    Value::Object(out)
}

fn guard_env(vars: &[&str]) {
    for var in vars {
        assert!(
            std::env::var_os(var).is_none(),
            "{var} is set: it adds work to or reroutes the served path, so the figure would \
             not be the served latency"
        );
    }
}

/// `Poly::mul_acc_ntt_domain` at the served ring: the one call the IFMA kernel replaces,
/// so a build that dispatches to it reads faster here than one that does not. Batched
/// because a single call is too short for the clock.
fn mul_acc_probe(params: &InspireParams) -> Value {
    let ctx = params.ntt_context();
    let ntt_poly = || {
        let mut p = Poly::random_moduli(params.ring_dim, params.moduli());
        p.to_ntt(&ctx);
        p
    };
    let (a, b, mut acc) = (ntt_poly(), ntt_poly(), ntt_poly());
    let per_call: Vec<u64> = (0..PROBE_BATCHES)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..PROBE_CALLS_PER_BATCH {
                acc.mul_acc_ntt_domain(std::hint::black_box(&a), &b, &ctx);
            }
            u64::try_from(t.elapsed().as_nanos() / u128::from(PROBE_CALLS_PER_BATCH))
                .unwrap_or(u64::MAX)
        })
        .collect();
    std::hint::black_box(&acc);
    json!({
        "function": "Poly::mul_acc_ntt_domain",
        "ring_dim": params.ring_dim,
        "calls_per_batch": PROBE_CALLS_PER_BATCH,
        "per_call": summarize(&per_call, "ns"),
    })
}

fn run_at_concurrency(
    state: &InspireServerState,
    pool: &[(u64, ClientState, SeededClientQuery)],
    callers: usize,
    samples: usize,
) -> (Vec<u64>, Duration) {
    let per_caller = samples / callers;
    let started = Instant::now();
    let lat: Vec<u64> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..callers)
            .map(|c| {
                scope.spawn(move || {
                    (0..per_caller)
                        .map(|k| {
                            let (_, _, q) = &pool[(c * 17 + k) % pool.len()];
                            let t = Instant::now();
                            std::hint::black_box(served(state, q));
                            micros(t.elapsed())
                        })
                        .collect::<Vec<u64>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("caller thread"))
            .collect()
    });
    (lat, started.elapsed())
}

#[test]
#[ignore = "heavy: a 65,536-row state (~12 s) then ~2,000 served queries at 512 B, a few \
            minutes. Trigger: a change to the respond path, the served cell, the raven-inspire \
            features, or the build flags."]
fn served_respond_latency_at_deployed_cell() {
    guard_env(&["RAVEN_PROFILE_RESPOND", "RAVEN_FORCE_PACKING_ONLINE"]);
    let warmup = env_usize("RAVEN_BENCH_WARMUP", DEFAULT_WARMUP);
    let samples = env_usize("RAVEN_BENCH_SAMPLES", DEFAULT_SAMPLES);
    assert!(
        samples >= MIN_SAMPLES,
        "{samples} samples cannot place a p99 below the max"
    );
    let callers_list: Vec<usize> = std::env::var("RAVEN_BENCH_CONCURRENCY")
        .unwrap_or_else(|_| "1,4".to_owned())
        .split(',')
        .map(|c| {
            c.trim()
                .parse()
                .expect("RAVEN_BENCH_CONCURRENCY is a comma list")
        })
        .collect();

    let f = fixture(1 << DB_ROWS_LOG2, true);
    let pool = query_pool(&f, QUERY_POOL);
    for (index, cs, q) in pool.iter().take(4) {
        let decoded =
            extract_response(&f.state.crs, cs, &served(&f.state, q), ENTRY_BYTES).expect("extract");
        assert_eq!(
            decoded,
            row(&f.db, *index),
            "served response decodes wrong at {index}"
        );
    }
    for k in 0..warmup {
        std::hint::black_box(served(&f.state, &pool[k % pool.len()].2));
    }

    let mut results = Vec::new();
    let mut raw = serde_json::Map::new();
    for &callers in &callers_list {
        assert!(callers >= 1, "concurrency must be at least 1");
        let load_before = load_average();
        let (lat, wall) = run_at_concurrency(&f.state, &pool, callers, samples);
        let mut summary = summarize(&lat, "us");
        summary["concurrency"] = json!(callers);
        summary["wall_s"] = json!(wall.as_secs_f64());
        summary["loadavg_before"] = json!(load_before);
        summary["loadavg_after"] = json!(load_average());
        eprintln!("served_respond: concurrency={callers} {summary}");
        results.push(summary);
        raw.insert(callers.to_string(), json!(lat));
    }

    write_artifact(
        "served-respond-latency.json",
        &json!({
            "bench": "served_respond_latency_at_deployed_cell",
            "captured_at_unix": unix_now(),
            "path": "RavenInspireScheme::respond: session resolve, seeded expand, respond, \
                     mod-switch to the wire modulus. Excludes HTTP, wire serialization, \
                     admission queueing and network.",
            "cell": {
                "record_size": ENTRY_BYTES,
                "rows_per_shard": ROWS_PER_SHARD,
                "db_rows": 1u64 << DB_ROWS_LOG2,
                "params": "secure_128_d2048",
                "variant": "TwoPacking",
                "wire_response_modulus": WIRE_RESPONSE_MODULUS,
                "ifma_dispatch_preconditions": ifma_dispatch_preconditions(&f.params),
            },
            "host": host(),
            "threads": {
                "rayon": rayon::current_num_threads(),
                "concurrency": callers_list,
            },
            "method": {
                "warmup": warmup,
                "samples": samples,
                "query_pool": QUERY_POOL,
                "percentile": "nearest-rank",
                "clock": "Instant around one respond call on the caller thread",
            },
            "build": build(),
            "results": results,
            "samples_us": raw,
        }),
    );
}

#[test]
#[ignore = "heavy: a 65,536-row state (~12 s) then served queries split into timed stages. \
            Run with RAVEN_PROFILE_RESPOND=1 and stderr kept to get the in-respond split. \
            Trigger: a change to the respond path or the mod-switch."]
fn served_respond_stage_split_at_deployed_cell() {
    guard_env(&["RAVEN_FORCE_PACKING_ONLINE"]);
    let warmup = env_usize("RAVEN_BENCH_WARMUP", DEFAULT_WARMUP);
    let samples = env_usize("RAVEN_BENCH_SAMPLES", DEFAULT_SAMPLES / 4);
    let f = fixture(1 << DB_ROWS_LOG2, true);
    let pool = query_pool(&f, QUERY_POOL);
    let state = &f.state;

    let split = |q: &SeededClientQuery| -> ([u64; 3], ServerResponse) {
        let t0 = Instant::now();
        let (store, inner) = state
            .session_store
            .resolve(q.session_handle, Instant::now())
            .expect("resolve");
        let mut resolved = q.clone();
        resolved.session_handle = inner;
        let t1 = Instant::now();
        let unswitched = respond_seeded_inspiring_cached_with_session(
            state.crs.as_ref(),
            &state.encoded_db,
            &resolved,
            state.cache.as_ref(),
            Some(store.as_ref()),
        )
        .expect("respond");
        let t2 = Instant::now();
        let switched =
            mod_switch_response_checked(&state.crs.params, &unswitched, WIRE_RESPONSE_MODULUS)
                .expect("mod-switch");
        let t3 = Instant::now();
        (
            [micros(t1 - t0), micros(t2 - t1), micros(t3 - t2)],
            switched,
        )
    };

    for k in 0..warmup {
        std::hint::black_box(split(&pool[k % pool.len()].2));
    }
    let load_before = load_average();
    eprintln!("served_split: measure begin");
    let stages: Vec<[u64; 3]> = (0..samples)
        .map(|k| split(&pool[k % pool.len()].2).0)
        .collect();
    eprintln!("served_split: measure end");
    let load_after = load_average();

    for (_, _, q) in &pool {
        assert_eq!(
            response_bytes(&split(q).1),
            response_bytes(&served(state, q)),
            "the timed stages are not the served path"
        );
    }

    let column = |i: usize| stages.iter().map(|s| s[i]).collect::<Vec<u64>>();
    let total: Vec<u64> = stages.iter().map(|s| s.iter().sum()).collect();
    let kernel_probe = mul_acc_probe(&f.params);
    write_artifact(
        "served-respond-stage-split.json",
        &json!({
            "bench": "served_respond_stage_split_at_deployed_cell",
            "captured_at_unix": unix_now(),
            "stages": {
                "session_resolve": summarize(&column(0), "us"),
                "respond_seeded": summarize(&column(1), "us"),
                "mod_switch": summarize(&column(2), "us"),
                "total": summarize(&total, "us"),
            },
            "kernel_probe": kernel_probe,
            "respond_seeded_covers": "seeded expand, then the RAVEN_PROFILE regions: extprod, \
                                      extract_coeff0, bpoly, pack_offline, pack_online",
            "in_respond_split_on_stderr": std::env::var_os("RAVEN_PROFILE_RESPOND").is_some(),
            "stderr_markers": ["served_split: measure begin", "served_split: measure end"],
            "cell": {
                "record_size": ENTRY_BYTES,
                "rows_per_shard": ROWS_PER_SHARD,
                "db_rows": 1u64 << DB_ROWS_LOG2,
                "ifma_dispatch_preconditions": ifma_dispatch_preconditions(&f.params),
            },
            "host": host(),
            "threads": { "rayon": rayon::current_num_threads(), "concurrency": 1 },
            "method": { "warmup": warmup, "samples": samples, "percentile": "nearest-rank" },
            "loadavg_before": load_before,
            "loadavg_after": load_after,
            "build": build(),
            "samples_us": {
                "session_resolve": column(0),
                "respond_seeded": column(1),
                "mod_switch": column(2),
            },
        }),
    );
}

/// Query encryption draws OS entropy by design, so two builds cannot regenerate one query.
/// The first run records a snapshot, queries and served responses; a later run of another
/// build restores the same state, replays the same queries, and must produce the same bytes.
#[test]
#[ignore = "cross-build harness: needs RAVEN_BENCH_REPLAY_DIR and two builds run in turn. \
            Trigger: a change to a raven-inspire kernel feature or the multiply kernels."]
fn served_response_bytes_match_a_recorded_build() {
    let dir = PathBuf::from(
        std::env::var("RAVEN_BENCH_REPLAY_DIR").expect("RAVEN_BENCH_REPLAY_DIR names the fixture"),
    );
    let state_path = dir.join("state.bin");
    let queries_path = dir.join("queries.bin");
    let responses_path = dir.join("responses.bin");
    let recording = !state_path.exists();

    let mut decoded_ok = 0usize;
    if recording {
        std::fs::create_dir_all(&dir).expect("replay dir");
        let f = fixture(usize::try_from(ROWS_PER_SHARD).expect("rows"), false);
        std::fs::write(
            &state_path,
            snapshot_inspire_state(&f.state).expect("snapshot"),
        )
        .expect("write state");
        let pool = query_pool(&f, REPLAY_QUERIES);
        let queries: Vec<&SeededClientQuery> = pool.iter().map(|(_, _, q)| q).collect();
        std::fs::write(
            &queries_path,
            bincode::serialize(&queries).expect("queries"),
        )
        .expect("write queries");
        let restored =
            restore_inspire_state(&std::fs::read(&state_path).expect("state")).expect("restore");
        let replayed: Vec<SeededClientQuery> =
            bincode::deserialize(&std::fs::read(&queries_path).expect("queries")).expect("decode");
        let mut responses = Vec::new();
        for ((index, cs, _), q) in pool.iter().zip(&replayed) {
            let r = served(&restored, q);
            let decoded = extract_response(&restored.crs, cs, &r, ENTRY_BYTES).expect("extract");
            assert_eq!(
                decoded,
                row(&f.db, *index),
                "recorded response decodes wrong"
            );
            decoded_ok += 1;
            responses.push(r);
        }
        std::fs::write(
            &responses_path,
            bincode::serialize(&responses).expect("responses"),
        )
        .expect("write responses");
    }

    let restored =
        restore_inspire_state(&std::fs::read(&state_path).expect("state")).expect("restore");
    let queries: Vec<SeededClientQuery> =
        bincode::deserialize(&std::fs::read(&queries_path).expect("queries")).expect("decode");
    let recorded = std::fs::read(&responses_path).expect("responses");
    let first = queries
        .iter()
        .map(|q| served(&restored, q))
        .collect::<Vec<_>>();
    let again = queries
        .iter()
        .map(|q| served(&restored, q))
        .collect::<Vec<_>>();
    let bytes = bincode::serialize(&first).expect("serialize");
    assert_eq!(
        bytes,
        bincode::serialize(&again).expect("serialize"),
        "respond is not deterministic here, so a cross-build comparison would mean nothing"
    );
    let first_difference = bytes.iter().zip(&recorded).position(|(a, b)| a != b);
    assert!(
        bytes.len() == recorded.len() && first_difference.is_none(),
        "served response bytes differ from the recorded build: {} vs {} bytes, first \
         difference at {first_difference:?}",
        bytes.len(),
        recorded.len()
    );

    let mut runs: Vec<Value> = std::fs::read(dir.join("replay.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    runs.push(json!({
        "captured_at_unix": unix_now(),
        "mode": if recording { "record" } else { "verify" },
        "queries": queries.len(),
        "response_bytes": bytes.len(),
        "decoded_against_db": decoded_ok,
        "identical_to_recorded": true,
        "host": host(),
        "build": build(),
    }));
    std::fs::write(
        dir.join("replay.json"),
        serde_json::to_string_pretty(&runs).expect("serialize"),
    )
    .expect("write replay log");
}
