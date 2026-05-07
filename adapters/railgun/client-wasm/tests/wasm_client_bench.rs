//! WASM client bench, also runnable natively via the `_rust` mirror entry points.
//!
//! - WASM: `wasm-pack test --node --manifest-path adapters/railgun/client-wasm/Cargo.toml`
//! - Native: `cargo test --release ... --test wasm_client_bench -- --ignored --nocapture`

#![allow(
    clippy::expect_used,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::indexing_slicing
)]

#[cfg(target_arch = "wasm32")]
mod wasm_only {
    use raven_inspire::math::GaussianSampler;
    use raven_inspire::params::{InspireParams, SecurityLevel};
    use raven_inspire::respond_seeded_inspiring_cached_with_session;
    use raven_inspire::{
        setup as inspire_setup, ClientSession, ServerInspiringCache, ServerSessionStore,
    };
    use raven_inspire_client_wasm::{build_seeded_query_rust, extract_response_rust};
    use wasm_bindgen_test::wasm_bindgen_test;

    const SEEDS: usize = 3;

    fn small_params() -> InspireParams {
        InspireParams {
            ring_dim: 256,
            q: 1_152_921_504_606_830_593,
            crt_moduli: vec![1_152_921_504_606_830_593],
            p: 65_537,
            sigma: 6.4,
            gadget_base: 1 << 20,
            gadget_len: 3,
            security_level: SecurityLevel::Bits128,
        }
    }

    fn build_db(params: &InspireParams, entry_bytes: usize) -> Vec<u8> {
        let n = params.ring_dim;
        (0..(n * entry_bytes)).map(|i| (i % 251) as u8).collect()
    }

    fn now_ms() -> f64 {
        js_sys::Date::now()
    }

    fn median(values: &mut [f64]) -> f64 {
        values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        values[values.len() / 2]
    }

    fn run_for_entry_bytes(label: &str, entry_bytes: usize) {
        let params = small_params();
        let db = build_db(&params, entry_bytes);
        let mut setup_sampler = GaussianSampler::new(params.sigma);
        let (crs, encoded_db, sk) =
            inspire_setup(&params, &db, entry_bytes, &mut setup_sampler).expect("inspire_setup");
        let mut session_sampler = GaussianSampler::new(params.sigma);
        let session = ClientSession::new(crs.clone(), sk.clone(), &mut session_sampler)
            .expect("client session");

        let cache = ServerInspiringCache::new(&crs, &encoded_db).expect("cache");
        let store = ServerSessionStore::new();

        let mut build_t: Vec<f64> = Vec::with_capacity(SEEDS);
        let mut extract_t: Vec<f64> = Vec::with_capacity(SEEDS);

        for seed in 0..SEEDS {
            let target_idx = (seed as u64).wrapping_mul(7) % (params.ring_dim as u64);

            let bs = now_ms();
            let (state, query) =
                build_seeded_query_rust(&session, &params, &encoded_db.config, target_idx)
                    .expect("build query");
            let bend = now_ms();
            build_t.push(bend - bs);

            let response = respond_seeded_inspiring_cached_with_session(
                &crs,
                &encoded_db,
                &query,
                &cache,
                Some(&store),
            )
            .expect("respond");

            let es = now_ms();
            let _plain =
                extract_response_rust(&crs, &state, &response, entry_bytes).expect("extract");
            let eend = now_ms();
            extract_t.push(eend - es);
        }

        let build_med = median(&mut build_t);
        let extract_med = median(&mut extract_t);
        web_sys::console::log_1(
            &format!(
                "wasm_client_bench: cell={label} entry_bytes={entry_bytes} \
                 3-seed-median build={:.3}ms extract={:.3}ms",
                build_med, extract_med
            )
            .into(),
        );
    }

    #[wasm_bindgen_test]
    fn build_and_extract_per_encoder() {
        run_for_entry_bytes("bc-32B", 32);
        run_for_entry_bytes("path-512B", 512);
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use raven_inspire::math::GaussianSampler;
    use raven_inspire::params::{InspireParams, SecurityLevel};
    use raven_inspire::respond_seeded_inspiring_cached_with_session;
    use raven_inspire::{
        setup as inspire_setup, ClientSession, ServerInspiringCache, ServerSessionStore,
    };
    use raven_inspire_client_wasm::{build_seeded_query_rust, extract_response_rust};

    const SEEDS: usize = 3;

    fn small_params() -> InspireParams {
        InspireParams {
            ring_dim: 256,
            q: 1_152_921_504_606_830_593,
            crt_moduli: vec![1_152_921_504_606_830_593],
            p: 65_537,
            sigma: 6.4,
            gadget_base: 1 << 20,
            gadget_len: 3,
            security_level: SecurityLevel::Bits128,
        }
    }

    fn production_params() -> InspireParams {
        InspireParams::secure_128_d2048()
    }

    fn build_db(params: &InspireParams, entry_bytes: usize) -> Vec<u8> {
        let n = params.ring_dim;
        (0..(n * entry_bytes)).map(|i| (i % 251) as u8).collect()
    }

    fn median(values: &mut [Duration]) -> Duration {
        values.sort();
        values[values.len() / 2]
    }

    fn findings_path() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // adapters/railgun/client-wasm -> repo root
        p.pop(); // client-wasm
        p.pop(); // railgun
        p.pop(); // adapters
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

    fn bench_one(
        label: &str,
        params: &InspireParams,
        entry_bytes: usize,
    ) -> (Vec<Duration>, Vec<Duration>) {
        let db = build_db(params, entry_bytes);
        let mut setup_sampler = GaussianSampler::new(params.sigma);
        let (crs, encoded_db, sk) =
            inspire_setup(params, &db, entry_bytes, &mut setup_sampler).expect("inspire_setup");
        let mut session_sampler = GaussianSampler::new(params.sigma);
        let session = ClientSession::new(crs.clone(), sk.clone(), &mut session_sampler)
            .expect("client session");
        let cache = ServerInspiringCache::new(&crs, &encoded_db).expect("cache");
        let store = ServerSessionStore::new();

        let mut build_t: Vec<Duration> = Vec::with_capacity(SEEDS);
        let mut extract_t: Vec<Duration> = Vec::with_capacity(SEEDS);
        for seed in 0..SEEDS {
            let target_idx = (seed as u64).wrapping_mul(7) % (params.ring_dim as u64);

            let bs = Instant::now();
            let (state, query) =
                build_seeded_query_rust(&session, params, &encoded_db.config, target_idx)
                    .expect("build query");
            build_t.push(bs.elapsed());

            let response = respond_seeded_inspiring_cached_with_session(
                &crs,
                &encoded_db,
                &query,
                &cache,
                Some(&store),
            )
            .expect("respond");

            let es = Instant::now();
            let _plain =
                extract_response_rust(&crs, &state, &response, entry_bytes).expect("extract");
            extract_t.push(es.elapsed());

            eprintln!(
                "wasm_client_bench[native]: cell={label} entry_bytes={entry_bytes} seed={seed} \
                 build={:?} extract={:?}",
                build_t.last().copied().unwrap_or_default(),
                extract_t.last().copied().unwrap_or_default()
            );
        }
        (build_t, extract_t)
    }

    fn report(label: &str, build_t: &[Duration], extract_t: &[Duration]) {
        let mut b = build_t.to_vec();
        let mut e = extract_t.to_vec();
        let bm = median(&mut b);
        let em = median(&mut e);
        eprintln!(
            "wasm_client_bench[native]: cell={label} 3-seed-median build={:?} extract={:?} \
             (per-seed build={build_t:?} extract={extract_t:?})",
            bm, em
        );
        let bm_us = bm.as_secs_f64() * 1_000_000.0;
        let em_us = em.as_secs_f64() * 1_000_000.0;
        append_findings_line(&format!(
            "- wasm_client[native] | cell=`{label}` | per-seed-build={build_t:?} | \
             per-seed-extract={extract_t:?} | 3-seed-median-build={bm_us:.1} μs | \
             3-seed-median-extract={em_us:.1} μs",
        ));
    }

    #[test]
    #[ignore = "production-cell setup at d=2048 is ~12s; small + production = ~30s"]
    fn wasm_client_bench_native_per_cell() {
        append_findings_line("");
        append_findings_line(
            "## wasm_client_bench (native; pure-Rust `_rust` mirrors of wasm-bindgen wrappers; 3 seeds)",
        );
        append_findings_line("");

        let small = small_params();
        for (label, eb) in &[("bc-32B-d256", 32usize), ("path-512B-d256", 512usize)] {
            let (b, e) = bench_one(label, &small, *eb);
            report(label, &b, &e);
        }

        let prod = production_params();
        for (label, eb) in &[("bc-32B-d2048", 32usize), ("path-512B-d2048", 512usize)] {
            let (b, e) = bench_one(label, &prod, *eb);
            report(label, &b, &e);
        }
    }
}
