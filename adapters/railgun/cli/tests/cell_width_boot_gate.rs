//! Boot-path rejection of illegal PIR cell shapes.
//!
//! An illegal record width returns every byte wrong with no query-time error, so
//! boot is the only place it can be caught.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::path::Path;

use raven_railgun_cli::serve_production::{run_with_listener, ProductionServeOptions};
use raven_railgun_engine::pir_table::EncoderKind;

const NOTE_RECORD_BYTES: usize = 328;
/// `InspireParams::secure_128_d2048().ring_dim`, the only legal rows-per-shard.
const ROWS_PER_SHARD: u32 = 2048;

fn opts_with(
    entries: usize,
    entry_bytes: usize,
    encoder: EncoderKind,
    data_dir: std::path::PathBuf,
) -> ProductionServeOptions {
    ProductionServeOptions {
        bind: "127.0.0.1:0".parse::<SocketAddr>().expect("addr"),
        token: "cell-width-boot-gate-token-padded".to_owned(),
        rpc_url: "http://127.0.0.1:1".to_owned(),
        railgun_proxy: "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9".to_owned(),
        chain_id: 1,
        start_block: 0,
        mirror_endpoint: "http://127.0.0.1:1".to_owned(),
        list_key: "0".repeat(64),
        data_dir,
        instance_id: "cell-width-gate".to_owned(),
        max_concurrent_queries: 4,
        respond_timeout_secs: 30,
        entries,
        entry_bytes,
        encoder,
        session_eviction_interval_secs: 0,
        metrics_public: false,
    }
}

async fn boot_error(opts: ProductionServeOptions) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let err = run_with_listener(opts, listener, std::future::pending::<()>())
        .await
        .expect_err("an illegal cell shape must refuse to boot");
    format!("{err:#}")
}

#[tokio::test]
async fn serve_production_rejects_the_328_byte_note_record_width() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let msg = boot_error(opts_with(
        65_536,
        NOTE_RECORD_BYTES,
        EncoderKind::PerLeafBc,
        tmp.path().to_path_buf(),
    ))
    .await;
    for needle in ["328", "164", "512"] {
        assert!(
            msg.contains(needle),
            "boot rejection must name {needle}: {msg}"
        );
    }
}

#[tokio::test]
async fn serve_production_rejects_per_node_with_the_default_512_byte_width() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let msg = boot_error(opts_with(
        131_072,
        512,
        EncoderKind::PerNode { tree_number: 0 },
        tmp.path().to_path_buf(),
    ))
    .await;
    assert!(
        msg.contains("per-node") && msg.contains("512") && msg.contains("32"),
        "per-node must refuse a 512-byte cell instead of silently serving 32-byte rows: {msg}"
    );
}

#[tokio::test]
async fn serve_production_multi_rejects_an_illegal_global_record_size() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = write_single_instance_config(tmp.path(), NOTE_RECORD_BYTES, ROWS_PER_SHARD);
    let mut opts = raven_railgun_cli::serve_production_multi::load_options_from_toml(&config)
        .expect("parse config");
    opts.entries = 65_536;
    opts.skip_chain_workers = true;
    opts.skip_mirror_workers = true;
    for inst in &mut opts.instances {
        inst.use_flock = false;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let err = raven_railgun_cli::serve_production_multi::run_with_listener(
        opts,
        listener,
        std::future::ready(()),
    )
    .await
    .expect_err("an illegal global record_size must refuse to boot");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("328") && msg.contains("ppoi-status"),
        "multi rejection must name the width and the offending instance: {msg}"
    );
}

/// Rows-per-shard below `ring_dim` narrows every shard's row window while both the
/// re-encode and query paths still return success.
#[tokio::test]
async fn serve_production_multi_rejects_an_under_width_rows_per_shard() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = write_single_instance_config(tmp.path(), 512, ROWS_PER_SHARD / 2);
    let mut opts = raven_railgun_cli::serve_production_multi::load_options_from_toml(&config)
        .expect("parse config");
    opts.entries = 65_536;
    opts.skip_chain_workers = true;
    opts.skip_mirror_workers = true;
    for inst in &mut opts.instances {
        inst.use_flock = false;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let err = raven_railgun_cli::serve_production_multi::run_with_listener(
        opts,
        listener,
        std::future::ready(()),
    )
    .await
    .expect_err("rows per shard below ring_dim must refuse to boot");
    let msg = format!("{err:#}");
    for needle in ["1024", "2048", "ppoi-status-gate", "entries_per_shard"] {
        assert!(
            msg.contains(needle),
            "rejection must name {needle} (supplied rows, required rows, instance, config key): {msg}"
        );
    }
}

#[test]
fn migrate_encoder_refuses_a_target_whose_row_width_the_stored_cell_cannot_hold() {
    use raven_inspire::params::{InspireParams, InspireVariant};
    use raven_railgun_core::InstanceId;
    use raven_railgun_engine::inspire::{setup_state, LogicalLeafStore};
    use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
    use raven_railgun_persistence::StoreLayout;

    const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-cell-width-gate";
    const ENTRIES_PER_SHARD: u32 = 2048;
    const STORED_WIDTH: usize = 512;

    let dir = tempfile::tempdir().expect("tempdir");
    let from_encoder = EncoderKind::PerLeafBc
        .build(STORED_WIDTH, ENTRIES_PER_SHARD)
        .expect("build from encoder");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    let opened = InspirePersistence::open(
        layout,
        SCHEME_TAG,
        InstanceId::new("migrate-width-gate"),
        SnapshotPolicy::default(),
        from_encoder,
    )
    .expect("fresh open");

    let params = InspireParams::secure_128_d2048();
    let db = vec![7u8; ENTRIES_PER_SHARD as usize * STORED_WIDTH];
    let (state, _sk) =
        setup_state(&params, &db, STORED_WIDTH, InspireVariant::TwoPacking).expect("setup_state");
    opened
        .persistence
        .commit_v6(&state, &LogicalLeafStore::new(), 200)
        .expect("commit_v6");
    drop(opened);

    let err = raven_railgun_cli::migrate_encoder::run(
        dir.path(),
        EncoderKind::PerNode { tree_number: 0 },
    )
    .expect_err("migrating a 512-byte cell to a 32-byte-row encoder must be refused");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("512") && msg.contains("32"),
        "refusal must name the stored width and the encoder row width: {msg}"
    );
}

fn write_single_instance_config(
    dir: &Path,
    record_size: usize,
    entries_per_shard: u32,
) -> std::path::PathBuf {
    let list_key = "ef".repeat(32);
    let body = format!(
        r#"
[global]
bind = "127.0.0.1:0"
token = "cell-width-boot-gate-token-padded"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"
record_size = {record_size}
entries_per_shard = {entries_per_shard}
use_flock = false

[[instance]]
id = "ppoi-status-gate"
role = "live"
encoder = "per-list-status"
list_key = "{list_key}"
data_dir = "{data_dir}/ppoi-status-gate"
verification_mode = "upstream-signature"
data_source = {{ kind = "mirror", list_key = "{list_key}", what = "status" }}
"#,
        data_dir = dir.display()
    );
    let path = dir.join("config.toml");
    std::fs::write(&path, body).expect("write config");
    restrict_to_owner(&path);
    path
}

/// The parser refuses a group- or world-readable config carrying an inline token.
fn restrict_to_owner(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("fixture config must be owner-only");
    }
    #[cfg(not(unix))]
    let _ = path;
}
