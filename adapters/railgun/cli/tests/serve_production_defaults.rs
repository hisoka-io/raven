//! Regression guard for the production-cell defaults the operator
//! binary ships with. Asserts the locked T2/T3 production cell shape.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use raven_railgun_cli::serve_production::{
    ProductionServeOptions, DEFAULT_PRODUCTION_ENTRIES, DEFAULT_PRODUCTION_ENTRY_BYTES,
};
use raven_railgun_engine::pir_table::EncoderKind;
use std::net::SocketAddr;

#[test]
fn production_cell_defaults_match_locked_t2_t3_shape_documentation_only() {
    assert_eq!(
        DEFAULT_PRODUCTION_ENTRIES, 65_536,
        "DEFAULT_PRODUCTION_ENTRIES must match locked T2/T3 entry count"
    );
    assert_eq!(
        DEFAULT_PRODUCTION_ENTRY_BYTES, 512,
        "DEFAULT_PRODUCTION_ENTRY_BYTES must match locked T2/T3 record width"
    );
    assert_eq!(
        DEFAULT_PRODUCTION_ENTRY_BYTES,
        16 * 32,
        "T2/T3 record = 16 × 32 B Poseidon-Merkle siblings"
    );
}

#[tokio::test]
async fn production_cell_zero_dimension_bails_regression() {
    use raven_railgun_cli::serve_production::run_with_listener;

    fn opts_with(entries: usize, entry_bytes: usize) -> ProductionServeOptions {
        ProductionServeOptions {
            bind: "127.0.0.1:0".parse::<SocketAddr>().expect("addr"),
            token: "test-token-padded-to-meet-min-length".to_owned(),
            rpc_url: "http://127.0.0.1:1".to_owned(),
            railgun_proxy: "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9".to_owned(),
            chain_id: 1,
            start_block: 0,
            mirror_endpoint: "http://127.0.0.1:1".to_owned(),
            list_key: "0".repeat(64),
            data_dir: tempfile::tempdir().expect("tempdir").keep(),
            instance_id: "test".to_owned(),
            max_concurrent_queries: 4,
            respond_timeout_secs: 30,
            entries,
            entry_bytes,
            encoder: EncoderKind::PerLeafBc,
            session_eviction_interval_secs: 0,
            metrics_public: false,
        }
    }

    for (entries, entry_bytes) in [(0, 512), (65_536, 0), (0, 0)] {
        let opts = opts_with(entries, entry_bytes);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let shutdown = std::future::pending::<()>(); // never fires
        let err = run_with_listener(opts, listener, shutdown)
            .await
            .expect_err("zero-dimension cell must bail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("production-cell shape must be non-zero"),
            "expected zero-cell bail, got: {msg}"
        );
        assert!(
            msg.contains(&format!("entries={entries}")),
            "msg should carry the rejected entries={entries}: {msg}"
        );
        assert!(
            msg.contains(&format!("entry_bytes={entry_bytes}")),
            "msg should carry the rejected entry_bytes={entry_bytes}: {msg}"
        );
    }
}
