//! Boot-path rejection of a per-list encoder pinned off the list routed to it.
//!
//! The encoder drops every event for a foreign `list_key` and materializes from its own
//! list's IMT, so the cell stays all-zero and is served at HTTP 200 forever. There is no
//! query-time error to catch, which leaves boot as the only place to refuse.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::SocketAddr;

use raven_railgun_cli::serve_production::{run_with_listener, ProductionServeOptions};
use raven_railgun_engine::pir_table::EncoderKind;

const PINNED: [u8; 32] = [0xaa; 32];
const ROUTED: [u8; 32] = [0xbb; 32];

/// `PerListStatus` leaves `record_size` free, so this shape clears `validate_cell_shape`
/// and the boot reaches the network - which is what makes the matching case a real control.
const ENTRIES: usize = 65_536;
const ENTRY_BYTES: usize = 32;

fn opts_with(list_key: [u8; 32], data_dir: std::path::PathBuf) -> ProductionServeOptions {
    ProductionServeOptions {
        bind: "127.0.0.1:0".parse::<SocketAddr>().expect("addr"),
        token: "list-key-pin-boot-gate-token-pad".to_owned(),
        rpc_url: "http://127.0.0.1:1".to_owned(),
        railgun_proxy: "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9".to_owned(),
        chain_id: 1,
        start_block: 0,
        mirror_endpoint: "http://127.0.0.1:1".to_owned(),
        list_key: hex::encode(list_key),
        data_dir,
        instance_id: "ppoi-list-pin-gate".to_owned(),
        max_concurrent_queries: 4,
        respond_timeout_secs: 30,
        entries: ENTRIES,
        entry_bytes: ENTRY_BYTES,
        encoder: EncoderKind::PerListStatus { list_key: PINNED },
        session_eviction_interval_secs: 0,
        metrics_public: false,
        enable_fanout: false,
        max_fanout_shards: 16,
    }
}

async fn boot_error(opts: ProductionServeOptions) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let err = run_with_listener(opts, listener, std::future::pending::<()>())
        .await
        .expect_err("this configuration must not reach a serving state");
    format!("{err:#}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_list_encoder_pinned_off_the_configured_list_refuses_to_boot() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let msg = boot_error(opts_with(ROUTED, tmp.path().to_path_buf())).await;
    for needle in [
        "ppoi-list-pin-gate",
        "per-list-status",
        &hex::encode(PINNED),
        &hex::encode(ROUTED),
        "--list-key",
    ] {
        assert!(
            msg.contains(needle),
            "the refusal must name {needle} (instance, encoder, both keys, the setting to \
             change): {msg}"
        );
    }
}

/// The positive control. A matching `--list-key` must pass the gate and go on to fail at
/// the FIRST thing after it - the unreachable chain RPC, which is past `validate_cell_shape`,
/// past `setup_state` and past `bootstrap_railgun_engine`. Without this, the test above is
/// satisfied by any change that breaks startup.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_matching_list_key_boots_past_the_gate() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let msg = boot_error(opts_with(PINNED, tmp.path().to_path_buf())).await;
    assert!(
        msg.contains("chain RPC unreachable"),
        "a matching list_key must reach the chain RPC, not be refused at the pin gate: {msg}"
    );
    assert!(
        !msg.contains("pins list_key"),
        "a matching list_key must not trip the pin gate: {msg}"
    );
}
