//! Cache gate. The cached InsPIRe respond path must be byte-identical to the non-cached path at
//! the SERIALIZED-response level (a stronger assertion than the existing decode/plaintext
//! equality), and must be dramatically faster at the demo's 32-byte / gamma=16 cell. Both
//! functions are exercised directly here, independent of the crate's `cached-respond` feature.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic, clippy::print_stdout, clippy::print_stderr)]


use std::time::Instant;

use eth_state::ingest::normalize_balance_be;
use eth_state::{build_flat_state, build_session, ENTRY_SIZE};
use raven_client::build_seeded_query_rust;
use raven_inspire::params::InspireParams;
use raven_inspire::{
    respond_seeded_inspiring, respond_seeded_inspiring_cached, ServerInspiringCache,
};
use serial_test::serial;

fn build_corpus(n: usize) -> Vec<u8> {
    let mut db = vec![0u8; n * ENTRY_SIZE];
    for i in 0..n {
        let bal = ((i as u128) + 1) * 1_000;
        let rec = normalize_balance_be(&bal.to_be_bytes()).expect("balance fits");
        db[i * ENTRY_SIZE..(i + 1) * ENTRY_SIZE].copy_from_slice(&rec);
    }
    db
}

#[test]
#[serial]
fn cached_respond_kat() {
    let params = InspireParams::secure_128_d2048();
    let seed = 0x0000_CA00u64;
    let db = build_corpus(8);
    let (state, sk) = build_flat_state(&params, &db, ENTRY_SIZE, seed).expect("state");
    let cache = ServerInspiringCache::new(&state.crs, &state.encoded_db).expect("cache");
    let session =
        build_session(&state.crs, sk, params.sigma, seed.wrapping_add(1)).expect("session");
    let shard_cfg = state.encoded_db.config.clone();
    let (_qs, query) = build_seeded_query_rust(&session, &params, &shard_cfg, 3).expect("query");

    let noncached =
        respond_seeded_inspiring(&state.crs, &state.encoded_db, &query).expect("noncached respond");
    let cached = respond_seeded_inspiring_cached(&state.crs, &state.encoded_db, &query, &cache)
        .expect("cached respond");

    assert_eq!(
        noncached.to_binary().expect("noncached bytes"),
        cached.to_binary().expect("cached bytes"),
        "cached and non-cached ServerResponse must be byte-identical at the serialized level"
    );
}

#[test]
#[serial]
fn cached_vs_noncached_latency() {
    let params = InspireParams::secure_128_d2048();
    let seed = 0x0000_CB00u64;
    let db = build_corpus(ENTRIES_PER_SHARD);
    let (state, sk) = build_flat_state(&params, &db, ENTRY_SIZE, seed).expect("state");
    let cache = ServerInspiringCache::new(&state.crs, &state.encoded_db).expect("cache");
    let session =
        build_session(&state.crs, sk, params.sigma, seed.wrapping_add(1)).expect("session");
    let shard_cfg = state.encoded_db.config.clone();
    let (_qs, query) =
        build_seeded_query_rust(&session, &params, &shard_cfg, 1000).expect("query");

    // Non-cached rebuilds PackParams/OfflinePackingKeys inline per call (the ~3.8s cost), so
    // sample it sparingly; the cached path reuses the prebuilt cache.
    let nc_samples = 2usize;
    let t = Instant::now();
    for _ in 0..nc_samples {
        respond_seeded_inspiring(&state.crs, &state.encoded_db, &query).expect("nc");
    }
    let noncached_ms = t.elapsed().as_secs_f64() * 1000.0 / nc_samples as f64;

    let c_samples = 20usize;
    let t = Instant::now();
    for _ in 0..c_samples {
        respond_seeded_inspiring_cached(&state.crs, &state.encoded_db, &query, &cache).expect("c");
    }
    let cached_ms = t.elapsed().as_secs_f64() * 1000.0 / c_samples as f64;

    let speedup = noncached_ms / cached_ms;
    eprintln!(
        "{{\"bench\":\"cached_vs_noncached\",\"cell\":{{\"entry_size_bytes\":{},\"gamma\":{}}},\"noncached_ms\":{:.3},\"cached_ms\":{:.3},\"speedup\":{:.1},\"cached_qps_per_core\":{:.1}}}",
        ENTRY_SIZE,
        ENTRY_SIZE / 2,
        noncached_ms,
        cached_ms,
        speedup,
        1000.0 / cached_ms
    );

    assert!(
        cached_ms < noncached_ms,
        "cached ({cached_ms:.3} ms) must be faster than non-cached ({noncached_ms:.3} ms)"
    );
    // ISOLATED single-respond micro-bench (not the end-to-end consume-both read, which is ~2 legs
    // plus query/extract). The measured win is ~300x+; a floor of 100x catches a broken/bypassed
    // cache without flaking on machine variance.
    assert!(speedup > 100.0, "cached respond speedup must be large; got {speedup:.1}x");
}

const ENTRIES_PER_SHARD: usize = 2048;
