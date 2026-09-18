//! WASM client functional round trip: build a query and extract a response
//! through the `_rust` mirrors of the wasm-bindgen wrappers, under Node.
//!
//! Run: `wasm-pack test --node --manifest-path crates/client/Cargo.toml`
//! (the native timing half lives in `benches/wasm_client_native_bench.rs`).

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
    use raven_client::{build_seeded_query_rust, extract_response_rust};
    use raven_inspire::math::GaussianSampler;
    use raven_inspire::params::{InspireParams, SecurityLevel};
    use raven_inspire::respond_seeded_inspiring_cached_with_session;
    use raven_inspire::{
        setup as inspire_setup, ClientSession, ServerInspiringCache, ServerSessionStore,
    };
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
            query_gadget_len: 3,
            packing_gadget_len: 3,
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
                 3-seed-median build={build_med:.3}ms extract={extract_med:.3}ms"
            )
            .into(),
        );
    }

    /// Both record widths the adapter serves, at the only ring this test can afford.
    ///
    /// The wide case is 256 B, not the 512 B path record. 512 B needs ring_dim 2048: InspiRING
    /// width is `ceil(entry/2)`, which must be a power of two in `[1, 128]` at ring_dim 256, and
    /// `ceil(512/2) = 256` is outside it. This asked for 512 B until 2026-09-07 and panicked in
    /// `inspire_setup` on the first run because no CI job had invoked this wasm test target. The real
    /// 512-byte path record is covered at ring_dim 2048 by the adapter's production-cell lane.
    #[wasm_bindgen_test]
    fn build_and_extract_per_encoder() {
        run_for_entry_bytes("bc-32B", 32);
        run_for_entry_bytes("wide-256B", 256);
    }
}
