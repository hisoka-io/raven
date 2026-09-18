//! SLO GATE, not a benchmark: time-to-populate-from-zero for the synthetic
//! mirror carries a 30 s numeric ceiling (asserted twice — as a live deadline
//! inside the drain loop and again on the total), so a throughput regression
//! reds it. It emits `corpus_size, wall_secs, throughput_rows_per_sec` as well,
//! which is why it reads like a harness; it is not one.
//!
//! Because it is an SLO it must never be swept into a lane that only builds
//! `benches/` opportunistically: a lane without `--all-targets` does not build
//! bench targets at all, so a filter naming it would match nothing and go
//! green. It needs a named lane with headroom — see the routing note on the
//! test below.

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use raven_railgun_core::ListKey;
use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::PerLeafCommitmentEncoder;
use raven_railgun_mock_ppoi::{
    bind_listener, list_key_from_hex, seed_from_hex, serve_on, AppState, Corpus, CorpusConfig,
    DEFAULT_CORPUS_SEED_HEX, DEFAULT_LIST_KEY_HEX,
};
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_ppoi_mirror::{MirrorConfig, UpstreamPpoiMirror};

/// SLO gate: the 30 s ceiling is a machine-speed assertion, so it belongs in a
/// lane with headroom (the nightly production-cell profile's 300 s slow-timeout),
/// never in a per-push lane where runner variance decides the verdict.
#[tokio::test]
#[ignore = "SLO gate (not a bench): asserts mirror population from zero stays under 30 s for a 1k \
            event corpus. A wall-clock ceiling reds on runner speed, so it runs in the nightly \
            closure lane, not per push. Trigger: changing the upstream mirror sync loop or the \
            synthetic corpus generator."]
async fn populate_from_zero_takes_under_30s_for_1k_events() {
    let _ = tracing_subscriber::fmt::try_init();

    let corpus_size: u32 = 1_000;
    let list_key = list_key_from_hex(DEFAULT_LIST_KEY_HEX).expect("list key");
    let seed = seed_from_hex(DEFAULT_CORPUS_SEED_HEX).expect("seed");
    let corpus = Corpus::generate(CorpusConfig {
        list_key: list_key.0,
        seed,
        size: corpus_size,
        blocked: Vec::new(),
    })
    .expect("corpus");

    let state = AppState::new(corpus);
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let (listener, local) = bind_listener(bind).await.expect("bind");
    let server_handle = tokio::spawn(async move {
        let _ = serve_on(listener, state).await;
    });

    let mirror_config = MirrorConfig {
        endpoint: format!("http://{local}"),
        chain_type: "0".into(),
        chain_id: 1,
        poll_interval_secs: 1,
        max_rows_per_fetch: 501,
        txid_version: "V2_PoseidonMerkle".into(),
    };
    let mirror = Arc::new(UpstreamPpoiMirror::new(mirror_config).expect("mirror"));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(WalEntryPayload, u64)>(2_048);

    let started = Instant::now();
    let worker_handle = tokio::spawn({
        let mirror = mirror.clone();
        let lk = ListKey::from_bytes(list_key.0);
        async move {
            let _ = mirror.run_worker(lk, 0, tx).await;
        }
    });

    let mut store = LogicalLeafStore::new();
    let encoder = PerLeafCommitmentEncoder::new(32, 65_536, 0).expect("encoder");
    let want = corpus_size as usize;
    let deadline = started + Duration::from_secs(30);
    while store.ppoi_count() < want {
        assert!(
            Instant::now() <= deadline,
            "populate exceeded 30s budget at {} of {want}",
            store.ppoi_count()
        );
        match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
            Ok(Some((payload, height))) => {
                apply_wal_entry(&mut store, &payload, height, &encoder).expect("apply");
            }
            Ok(None) => panic!("channel closed at {}", store.ppoi_count()),
            Err(_) => {}
        }
    }
    let elapsed = started.elapsed();
    #[allow(clippy::cast_precision_loss)]
    let throughput = (want as f64) / elapsed.as_secs_f64();
    tracing::info!(
        corpus_size = want,
        wall_secs = elapsed.as_secs_f64(),
        throughput_rows_per_sec = throughput,
        "mock-ppoi populate bench result",
    );
    worker_handle.abort();
    server_handle.abort();

    assert!(
        elapsed < Duration::from_secs(30),
        "populate must complete under 30s; took {:.3}s",
        elapsed.as_secs_f64()
    );
}
