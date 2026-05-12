//! Integration test wiring the adapter's `UpstreamPpoiMirror` against
//! the synthetic mock service. Asserts the engine's `LogicalLeafStore`
//! accumulates BOTH the `(list_key, bc) -> status` map (T1 status PIR)
//! AND the per-list IMT (T2 path PIR) from the mock corpus.
//!
//! Engine surface: the mirror's `run_worker` emits each
//! `/poi-events` row twice -- first as
//! [`raven_railgun_persistence::WalEntryPayload::PpoiListLeafAdded`]
//! (drives per-list IMT growth + the `(BC -> idx)` ordering oracle),
//! then as `PpoiStatus` (idempotent re-assert of the status map for
//! consumers that don't follow the IMT path). This test exercises
//! both halves: `LogicalLeafStore::ppoi_count()` reflects status-map
//! population; `ppoi_imt(&list_key).leaf_count()` reflects IMT
//! growth. Closes the gap noted in the prior incarnation of this
//! comment (the mirror previously emitted only `PpoiStatus`, leaving
//! the IMT empty even when events flowed).

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use raven_railgun_core::ListKey;
use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::PerLeafCommitmentEncoder;
use raven_railgun_mock_ppoi::{
    bind_listener, list_key_from_hex, seed_from_hex, serve_on, AppState, Corpus, CorpusConfig,
    DEFAULT_CORPUS_SEED_HEX, DEFAULT_LIST_KEY_HEX,
};
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_ppoi_mirror::{MirrorConfig, UpstreamPpoiMirror};

#[tokio::test]
async fn adapter_consumes_mock_ppoi_events_and_populates_per_list_imt() {
    let _ = tracing_subscriber::fmt::try_init();

    let list_key = list_key_from_hex(DEFAULT_LIST_KEY_HEX).expect("list key");
    let seed = seed_from_hex(DEFAULT_CORPUS_SEED_HEX).expect("seed");
    let corpus_size = 32u32;
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
        max_rows_per_fetch: corpus_size.into(),
        txid_version: "V2_PoseidonMerkle".into(),
    };
    let mirror = Arc::new(UpstreamPpoiMirror::new(mirror_config).expect("mirror"));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(WalEntryPayload, u64)>(64);
    let worker_handle = tokio::spawn({
        let mirror = mirror.clone();
        let list_for_worker = ListKey::from_bytes(list_key.0);
        async move {
            let _ = mirror.run_worker(list_for_worker, 0, tx).await;
        }
    });

    let mut store = LogicalLeafStore::new();
    let encoder = PerLeafCommitmentEncoder::new(32, 65_536).expect("encoder");
    let want = corpus_size as usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while store.ppoi_count() < want {
        assert!(
            tokio::time::Instant::now() <= deadline,
            "mirror failed to populate {want} entries within 15s (got {})",
            store.ppoi_count()
        );
        let recv_with_timeout = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await;
        match recv_with_timeout {
            Ok(Some((payload, height))) => {
                apply_wal_entry(&mut store, &payload, height, &encoder).expect("apply");
            }
            Ok(None) => panic!("mirror channel closed before reaching {want} entries"),
            Err(_) => {}
        }
    }

    assert_eq!(
        store.ppoi_count(),
        want,
        "all synthetic events surfaced via mirror",
    );

    // Per-list IMT must have grown lockstep with the status map.
    // Each mirror-emitted `/poi-events` row generates a
    // `PpoiListLeafAdded` payload that the engine apply path inserts
    // at `(list_key, list_index)` -- see
    // `raven-railgun-engine/src/lib.rs` PpoiListLeafAdded arm. T2
    // path PIR consumes this IMT; if it stays at 0, T2 returns
    // empty rows.
    let imt_leaves = store
        .ppoi_imt(&list_key.0)
        .map_or(0, raven_railgun_engine::imt::Imt::leaf_count);
    assert_eq!(
        imt_leaves, want,
        "per-list IMT must grow lockstep with status map (got {imt_leaves}, want {want})",
    );

    // Spot-check: every status emitted by the mirror is `Valid` (status
    // byte 0) because the corpus has no blocked overrides.
    let bc0 = store.ppoi_status(
        &list_key.0,
        &Corpus::generate(CorpusConfig {
            list_key: list_key.0,
            seed,
            size: corpus_size,
            blocked: Vec::new(),
        })
        .expect("regen")
        .events_view()
        .first()
        .expect("first event")
        .blinded_commitment,
    );
    assert_eq!(bc0, Some(0), "mirror reports Valid (byte 0) for seeded BC");

    worker_handle.abort();
    server_handle.abort();
}
