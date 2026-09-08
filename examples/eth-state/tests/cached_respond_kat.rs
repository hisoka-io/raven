//! The cached respond path must be byte-identical to the non-cached one at the serialized
//! level, and must actually READ its cache (poisoned-cache guard below). The latency table
//! lives in `benches/`.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

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

/// Non-timing cache-use guard: a cache poisoned through the public `from_parts`
/// seam must change (or refuse) the response served through the scheme's respond.
/// The cached and uncached paths are byte-identical by design, so the ONLY way
/// poisoned bytes can equal the honest bytes is a respond that never read the
/// cache it was handed — the silent-fallback regression this test exists to catch.
#[cfg(feature = "cached-respond")]
#[test]
#[serial]
fn cached_respond_actually_uses_the_cache() {
    use std::sync::Arc;

    use eth_state::FlatBalanceScheme;
    use raven_inspire::inspiring::OfflinePackingKeys;
    use raven_server::PirScheme;

    let params = InspireParams::secure_128_d2048();
    let seed = 0x0000_CC00u64;
    let db = build_corpus(8);
    let (mut state, sk) = build_flat_state(&params, &db, ENTRY_SIZE, seed).expect("state");
    let session =
        build_session(&state.crs, sk, params.sigma, seed.wrapping_add(1)).expect("session");
    let shard_cfg = state.encoded_db.config.clone();
    let (_qs, query) = build_seeded_query_rust(&session, &params, &shard_cfg, 3).expect("query");

    let honest = respond_seeded_inspiring(&state.crs, &state.encoded_db, &query)
        .expect("noncached respond")
        .to_binary()
        .expect("honest bytes");

    let poison_seed = [0xA5u8; 32];
    assert_ne!(
        state.crs.inspiring_w_seed, poison_seed,
        "precondition: the poison seed must differ from the CRS w-seed"
    );
    let pack_params = state.cache.pack_params().clone();
    let poisoned_keys = OfflinePackingKeys::generate(&pack_params, poison_seed);
    state.cache = Arc::new(ServerInspiringCache::from_parts(pack_params, poisoned_keys));

    match FlatBalanceScheme::respond(&state, &query) {
        // Refusing a mismatched cache also proves the cache was read.
        Err(_) => {}
        Ok(resp) => {
            let bytes = resp.to_binary().expect("poisoned bytes");
            assert_ne!(
                bytes, honest,
                "a poisoned cache produced the honest bytes: the cached respond path \
                 never read the cache it was handed (silent fallback to the uncached path)"
            );
        }
    }
}

// The latency table (100x floor) lives in benches/cached_respond_latency_bench.rs;
// the cache-USE guard here is non-timing, so it holds in every lane and under load.
